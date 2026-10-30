package parallel_test

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"testing"
	"testing/fstest"
	"testing/synctest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/parallel"
	xio "github.com/aquasecurity/trivy/pkg/x/io"
)

// deniedFS fails to open the files in denied, as the OS does for a file
// the process has no permission to read.
type deniedFS struct {
	fstest.MapFS
	denied map[string]bool
}

func (d deniedFS) Open(name string) (fs.File, error) {
	if d.denied[name] {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrPermission}
	}
	return d.MapFS.Open(name)
}

func TestWalkDir_UnreadableFile(t *testing.T) {
	fsys := deniedFS{
		MapFS: fstest.MapFS{
			"app/readable.txt":   {Data: []byte("readable")},
			"app/unreadable.txt": {Data: []byte("unreadable")},
		},
		denied: map[string]bool{"app/unreadable.txt": true},
	}

	onFile := func(path string, _ fs.FileInfo, _ xio.ReadSeekerAt) (string, error) {
		return path, nil
	}
	var got []string
	onResult := func(path string) error {
		got = append(got, path)
		return nil
	}
	err := parallel.WalkDir(context.Background(), fsys, ".", 1, onFile, onResult)
	require.NoError(t, err)
	assert.Equal(t, []string{"app/readable.txt"}, got)
}

func TestWalkDir_Canceled(t *testing.T) {
	fsys := fstest.MapFS{
		"app/a.jar": {Data: []byte("a")},
		"app/b.jar": {Data: []byte("b")},
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	// The walk queues both files before the worker reaches b.jar, whose
	// parse sees the context done, as the jar parser does.
	onFile := func(path string, _ fs.FileInfo, _ xio.ReadSeekerAt) (string, error) {
		if path == "app/b.jar" {
			cancel()
			return "", ctx.Err()
		}
		return path, nil
	}
	var got []string
	onResult := func(path string) error {
		got = append(got, path)
		return nil
	}
	err := parallel.WalkDir(ctx, fsys, ".", 1, onFile, onResult)
	require.ErrorIs(t, err, context.Canceled)
	assert.Equal(t, []string{"app/a.jar"}, got)
}

func TestWalkDir_ResultError(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		fsys := fstest.MapFS{}
		for i := range 10 {
			fsys[fmt.Sprintf("app/file%d", i)] = &fstest.MapFile{Data: []byte("data")}
		}
		onFile := func(string, fs.FileInfo, xio.ReadSeekerAt) (int, error) {
			return 1, nil
		}
		errStop := errors.New("stop")
		onResult := func(int) error {
			return errStop
		}
		// A background context stays live after the test returns, unlike
		// t.Context, so a worker WalkDir leaves blocked stays blocked, and
		// synctest reports it.
		err := parallel.WalkDir(context.Background(), fsys, ".", 2, onFile, onResult)
		require.ErrorIs(t, err, errStop)
	})
}
