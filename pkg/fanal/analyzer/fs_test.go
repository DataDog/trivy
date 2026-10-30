package analyzer_test

import (
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
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
