package fsutils

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCopyFile(t *testing.T) {
	type args struct {
		src string
		dst string
	}
	tests := []struct {
		name    string
		args    args
		content []byte
		want    string
		wantErr string
	}{
		{
			name:    "happy path",
			content: []byte("this is a content"),
			args:    args{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			src := tt.args.src
			if tt.args.src == "" {
				s, err := os.CreateTemp(t.TempDir(), "src")
				require.NoError(t, err, tt.name)
				_, err = s.Write(tt.content)
				require.NoError(t, err, tt.name)
				src = s.Name()
				require.NoError(t, s.Close())
			}

			dst := tt.args.dst
			if tt.args.dst == "" {
				d, err := os.CreateTemp(t.TempDir(), "dst")
				require.NoError(t, err, tt.name)
				dst = d.Name()
				require.NoError(t, d.Close(), tt.name)
			}

			_, err := CopyFile(src, dst)
			if tt.wantErr != "" {
				require.Error(t, err, tt.name)
				assert.Equal(t, tt.wantErr, err.Error(), tt.name)
			} else {
				require.NoError(t, err, tt.name)
			}
		})
	}
}

func TestDirExists(t *testing.T) {
	t.Run("invalid path", func(t *testing.T) {
		assert.False(t, DirExists("\000invalid:path"))
	})

	t.Run("valid path", func(t *testing.T) {
		assert.True(t, DirExists(t.TempDir()))
	})

	t.Run("dir not exist", func(t *testing.T) {
		assert.False(t, DirExists(filepath.Join(t.TempDir(), "tmp")))
	})

	t.Run("file path", func(t *testing.T) {
		filePath := filepath.Join(t.TempDir(), "tmp")
		f, err := os.Create(filePath)
		require.NoError(t, f.Close())
		require.NoError(t, err)
		assert.False(t, DirExists(filePath))
	})
}

func TestFileExists(t *testing.T) {
	t.Run("invalid path", func(t *testing.T) {
		assert.False(t, FileExists("\000invalid:path"))
	})

	t.Run("valid path", func(t *testing.T) {
		filePath := filepath.Join(t.TempDir(), "tmp")
		f, err := os.Create(filePath)
		require.NoError(t, f.Close())
		require.NoError(t, err)
		assert.True(t, FileExists(filePath))
	})

	t.Run("file not exist", func(t *testing.T) {
		assert.False(t, FileExists(filepath.Join(t.TempDir(), "tmp")))
	})

	t.Run("dir path", func(t *testing.T) {
		assert.False(t, FileExists(t.TempDir()))
	})
}

func TestWalkDir_Canceled(t *testing.T) {
	fsys := fstest.MapFS{
		"a.lock": {Data: []byte("a")},
		"b.lock": {Data: []byte("b")},
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	// The context ends while the last file is read, as the deadline of a
	// post-analyzer can.
	var got []string
	err := WalkDir(ctx, fsys, ".", RequiredExt(".lock"), DefaultWalkErrorCallback,
		func(path string, _ fs.DirEntry, _ io.Reader) error {
			if path == "b.lock" {
				cancel()
				return errors.New("cut short")
			}
			got = append(got, path)
			return nil
		})
	require.ErrorIs(t, err, context.Canceled)
	assert.Equal(t, []string{"a.lock"}, got)
}
