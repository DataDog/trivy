package analyzer_test

import (
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	xio "github.com/aquasecurity/trivy/pkg/x/io"
)

func TestCompositeFS_CreateLink(t *testing.T) {
	root := t.TempDir()
	for _, p := range []string{"usr/local/bin/a", "usr/local/bin/b", "opt/c"} {
		name := filepath.Join(root, filepath.FromSlash(p))
		require.NoError(t, os.MkdirAll(filepath.Dir(name), 0o700))
		require.NoError(t, os.WriteFile(name, nil, 0o600))
	}

	c, err := analyzer.NewCompositeFS()
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Cleanup() })

	link := func(types []analyzer.Type, p string) {
		require.NoError(t, c.CreateLink(types, root, p, filepath.Join(root, filepath.FromSlash(p))))
	}
	types := []analyzer.Type{analyzer.TypeGoBinary, analyzer.TypeRustBinary}
	link(types, "usr/local/bin/a")
	link(types, "usr/local/bin/b")
	link(types[:1], "opt/c")

	for _, tt := range []struct {
		typ  analyzer.Type
		want []string
	}{
		{analyzer.TypeGoBinary, []string{"opt/c", "usr/local/bin/a", "usr/local/bin/b"}},
		{analyzer.TypeRustBinary, []string{"usr/local/bin/a", "usr/local/bin/b"}},
	} {
		mfs, ok := c.Get(tt.typ)
		require.True(t, ok)
		assert.Equal(t, root, mfs.UnderlyingRoot())
		var files []string
		require.NoError(t, fs.WalkDir(mfs, ".", func(p string, d fs.DirEntry, err error) error {
			if err == nil && !d.IsDir() {
				files = append(files, p)
			}
			return err
		}))
		assert.Equal(t, tt.want, files, tt.typ)
	}
}

func TestCompositeFS_CopyFileToTemp(t *testing.T) {
	c, err := analyzer.NewCompositeFS()
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Cleanup() })

	t.Run("in memory", func(t *testing.T) {
		opener := func() (xio.ReadSeekCloserAt, error) {
			return xio.NopCloser(strings.NewReader("small")), nil
		}
		name, err := c.CopyFileToTemp(opener, nil)
		require.NoError(t, err)
		b, err := os.ReadFile(name)
		require.NoError(t, err)
		assert.Equal(t, "small", string(b))
	})

	t.Run("spilled to a temp file", func(t *testing.T) {
		// The walkers keep a large file in a temp file of their own, and
		// remove it once the walk passes the file.
		spill := filepath.Join(t.TempDir(), "cached-file")
		require.NoError(t, os.WriteFile(spill, []byte("large"), 0o600))
		opener := func() (xio.ReadSeekCloserAt, error) { return os.Open(spill) }
		name, err := c.CopyFileToTemp(opener, nil)
		require.NoError(t, err)
		src, err := os.Stat(spill)
		require.NoError(t, err)
		dst, err := os.Stat(name)
		require.NoError(t, err)
		assert.True(t, os.SameFile(src, dst), "the spilled file was copied")
		require.NoError(t, os.Remove(spill))
		b, err := os.ReadFile(name)
		require.NoError(t, err)
		assert.Equal(t, "large", string(b))
	})

	t.Run("spilled file replaced after the open", func(t *testing.T) {
		spill := filepath.Join(t.TempDir(), "cached-file")
		require.NoError(t, os.WriteFile(spill, []byte("opened"), 0o600))
		other := spill + ".other"
		require.NoError(t, os.WriteFile(other, []byte("other"), 0o600))
		opener := func() (xio.ReadSeekCloserAt, error) {
			f, err := os.Open(spill)
			if err != nil {
				return nil, err
			}
			return f, os.Rename(other, spill)
		}
		name, err := c.CopyFileToTemp(opener, nil)
		require.NoError(t, err)
		b, err := os.ReadFile(name)
		require.NoError(t, err)
		assert.Equal(t, "opened", string(b))
	})
}

// BenchmarkCompositeFS_CopyFileToTemp hands over a 128 MiB file the walker
// spilled to disk.
func BenchmarkCompositeFS_CopyFileToTemp(b *testing.B) {
	spill := filepath.Join(b.TempDir(), "cached-file")
	require.NoError(b, os.WriteFile(spill, make([]byte, 128<<20), 0o600))
	opener := func() (xio.ReadSeekCloserAt, error) { return os.Open(spill) }
	b.ReportAllocs()
	for b.Loop() {
		c, err := analyzer.NewCompositeFS()
		if err != nil {
			b.Fatal(err)
		}
		if _, err := c.CopyFileToTemp(opener, nil); err != nil {
			b.Fatal(err)
		}
		_ = c.Cleanup()
	}
}

// BenchmarkCompositeFS_CreateLink links 10,000 executables for the two
// binary analyzers, as a host walk does.
func BenchmarkCompositeFS_CreateLink(b *testing.B) {
	types := []analyzer.Type{analyzer.TypeGoBinary, analyzer.TypeRustBinary}
	var paths []string
	for i := range 10000 {
		paths = append(paths, fmt.Sprintf("opt/app%d/lib/lib%d.so", i/100, i))
	}
	b.ReportAllocs()
	for b.Loop() {
		c, err := analyzer.NewCompositeFS()
		if err != nil {
			b.Fatal(err)
		}
		for _, p := range paths {
			if err := c.CreateLink(types, "/scan", p, path.Join("/scan", p)); err != nil {
				b.Fatal(err)
			}
		}
		_ = c.Cleanup()
	}
}
