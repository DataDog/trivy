package parallel_test

import (
	"context"
	"io/fs"
	"testing"
	"testing/fstest"

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
