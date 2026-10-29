package walker

import (
	"context"
	"io/fs"
	"path"
	"sync"

	"github.com/aquasecurity/trivy/pkg/fanal/utils"
)

// PrefetchWorkers is the number of directories Prefetch reads at once.
const PrefetchWorkers = 4

// Prefetch reads the directories of fsys that a walk with opt visits, and the
// metadata of their regular files, n at a time, so that a walk running
// alongside finds them in the kernel's caches. A walk reads one directory at
// a time, and on a cold cache waits on the disk for each in turn. The paths
// in opt are relative to the root of fsys, as the walkers make them.
// Prefetch returns once it has read the tree, or when ctx is done.
func Prefetch(ctx context.Context, fsys fs.FS, opt Option, n int) {
	p := &prefetcher{fsys: fsys, opt: opt, todo: []string{"."}, pending: 1}
	p.cond = sync.NewCond(&p.mu)
	stop := context.AfterFunc(ctx, func() {
		p.mu.Lock()
		p.done = true
		p.mu.Unlock()
		p.cond.Broadcast()
	})
	defer stop()

	var wg sync.WaitGroup
	for range n {
		wg.Go(p.work)
	}
	wg.Wait()
}

type prefetcher struct {
	fsys fs.FS
	opt  Option

	// mu guards todo, pending, and done, and cond signals a change to them.
	mu   sync.Mutex
	cond *sync.Cond
	// todo is the stack of directories to read, and pending counts them
	// with the directories being read.
	todo    []string
	pending int
	done    bool
}

func (p *prefetcher) work() {
	for {
		p.mu.Lock()
		for len(p.todo) == 0 && p.pending > 0 && !p.done {
			p.cond.Wait()
		}
		if p.done || p.pending == 0 {
			p.mu.Unlock()
			return
		}
		dir := p.todo[len(p.todo)-1]
		p.todo = p.todo[:len(p.todo)-1]
		p.mu.Unlock()

		subdirs := p.read(dir)

		p.mu.Lock()
		p.todo = append(p.todo, subdirs...)
		p.pending += len(subdirs) - 1
		finished := p.pending == 0
		p.mu.Unlock()
		if len(subdirs) > 0 || finished {
			p.cond.Broadcast()
		}
	}
}

// read reads dir and the metadata of its regular files, and returns the
// subdirectories a walk visits, last first, so that popping them from the
// stack follows the order of the walk.
func (p *prefetcher) read(dir string) []string {
	entries, err := fs.ReadDir(p.fsys, dir)
	if err != nil {
		return nil
	}
	var subdirs []string
	for i := len(entries) - 1; i >= 0; i-- {
		e := entries[i]
		name := path.Join(dir, e.Name())
		switch {
		case e.IsDir():
			if !utils.SkipPath(name, p.opt.SkipDirs) && !utils.OnlyPath(name, p.opt.OnlyDirs) {
				subdirs = append(subdirs, name)
			}
		case e.Type().IsRegular():
			// The walk calls Info for each file it passes to the analyzers.
			_, _ = e.Info()
		}
	}
	return subdirs
}
