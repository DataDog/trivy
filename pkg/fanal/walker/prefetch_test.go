package walker_test

import (
	"context"
	"io/fs"
	"slices"
	"sync"
	"testing"
	"testing/fstest"
	"testing/synctest"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/trivy/pkg/fanal/walker"
)

// recordFS records the directories read through it.
type recordFS struct {
	fstest.MapFS

	mu   sync.Mutex
	read []string
}

func (r *recordFS) ReadDir(name string) ([]fs.DirEntry, error) {
	r.mu.Lock()
	r.read = append(r.read, name)
	r.mu.Unlock()
	return r.MapFS.ReadDir(name)
}

func TestPrefetch(t *testing.T) {
	tree := fstest.MapFS{
		"app/a/x.txt":    {Data: []byte("x")},
		"app/b/y.txt":    {Data: []byte("y")},
		"app/.git/HEAD":  {Data: []byte("ref")},
		"proc/1/status":  {Data: []byte("status")},
		"opt/tool/z.bin": {Data: []byte("z"), Mode: 0o755},
	}
	tests := []struct {
		name string
		opt  walker.Option
		want []string
	}{
		{
			name: "skip dirs",
			opt:  walker.Option{SkipDirs: []string{"proc", "**/.git"}},
			want: []string{".", "app", "app/a", "app/b", "opt", "opt/tool"},
		},
		{
			name: "only dirs",
			opt:  walker.Option{OnlyDirs: []string{"app/a/**"}},
			want: []string{".", "app", "app/a"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fsys := &recordFS{MapFS: tree}
			walker.Prefetch(t.Context(), fsys, tt.opt, walker.PrefetchWorkers)
			slices.Sort(fsys.read)
			assert.Equal(t, tt.want, fsys.read)
		})
	}
}

// blockFS blocks reading dir until release is closed.
type blockFS struct {
	*recordFS
	dir     string
	reading chan struct{}
	release chan struct{}
}

func (b blockFS) ReadDir(name string) ([]fs.DirEntry, error) {
	if name == b.dir {
		close(b.reading)
		<-b.release
	}
	return b.recordFS.ReadDir(name)
}

// Prefetch stops reading once its context is done, and leaves no goroutine
// behind, which synctest would report.
func TestPrefetch_ContextDone(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		fsys := blockFS{
			recordFS: &recordFS{MapFS: fstest.MapFS{"a/b/c/d.txt": {Data: []byte("d")}}},
			dir:      "a",
			reading:  make(chan struct{}),
			release:  make(chan struct{}),
		}
		ctx, cancel := context.WithCancel(t.Context())
		returned := make(chan struct{})
		go func() {
			walker.Prefetch(ctx, fsys, walker.Option{}, walker.PrefetchWorkers)
			close(returned)
		}()
		<-fsys.reading
		cancel()
		synctest.Wait()
		close(fsys.release)
		<-returned
		assert.Equal(t, []string{".", "a"}, fsys.read)
	})
}
