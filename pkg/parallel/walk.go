package parallel

import (
	"context"
	"errors"
	"io/fs"
	"os"

	"golang.org/x/sync/errgroup"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/log"
	xio "github.com/aquasecurity/trivy/pkg/x/io"
)

const defaultParallel = 5

const (
	// aheadFiles is how far the walk runs ahead of the workers, in files.
	aheadFiles = 32
	// aheadWorkers read the files ahead, so that a worker on a cold disk
	// finds its file in the page cache rather than waiting on each read.
	aheadWorkers = 4

	// aheadHead and aheadTail are how much of the start and the end of a
	// file are read ahead.
	aheadHead = 1 << 20
	aheadTail = 64 << 10
)

// aheadFile is a file the walk passed, to read ahead.
type aheadFile struct {
	path string
	size int64
}

type onFile[T any] func(string, fs.FileInfo, xio.ReadSeekerAt) (T, error)
type onWalkResult[T any] func(T) error

// WalkDir calls onFile on each regular file under root, from parallel
// goroutines, and onResult on each result, from the calling goroutine. An
// error from onFile skips its file. WalkDir returns the first error of the
// walk or of onResult, or the error of ctx if ctx is done before the walk
// has read every file.
func WalkDir[T any](ctx context.Context, fsys fs.FS, root string, parallel int,
	onFile onFile[T], onResult onWalkResult[T]) error {
	if parallel == 0 {
		parallel = defaultParallel // Set the default value
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	g, ctx := errgroup.WithContext(ctx)
	paths := make(chan string, aheadFiles)
	ahead := make(chan aheadFile, aheadFiles)
	for range aheadWorkers {
		g.Go(func() error {
			for f := range ahead {
				prefetch(fsys, f)
			}
			return nil
		})
	}

	g.Go(func() error {
		defer close(paths)
		defer close(ahead)
		err := fs.WalkDir(fsys, root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			} else if !d.Type().IsRegular() {
				return nil
			}

			// check if file is empty
			info, err := d.Info()
			if err != nil {
				return err
			} else if info.Size() == 0 {
				log.Debug("Skip the empty file", log.FilePath(path))
				return nil
			}

			select {
			case ahead <- aheadFile{path: path, size: info.Size()}:
			default:
				// The read-ahead is behind, so leave this file to the worker.
			}
			select {
			case paths <- path:
			case <-ctx.Done():
				return ctx.Err()
			}
			return nil
		})
		if err != nil {
			return xerrors.Errorf("walk error: %w", err)
		}
		return nil
	})

	// Start a fixed number of goroutines to read and digest files.
	c := make(chan T)
	for i := 0; i < parallel; i++ {
		g.Go(func() error {
			for path := range paths {
				if err := ctx.Err(); err != nil {
					return err
				}
				if err := walk(ctx, fsys, path, c, onFile); err != nil {
					return err
				}
			}
			return nil
		})
	}
	go func() {
		_ = g.Wait()
		close(c)
	}()

	for res := range c {
		if err := onResult(res); err != nil {
			// Stop the walk and the workers blocked sending their results.
			cancel()
			_ = g.Wait()
			return err
		}
	}
	// Check whether any of the goroutines failed. Since g is accumulating the
	// errors, we don't need to send them (or check for them) in the individual
	// results sent on the channel.
	return g.Wait()
}

// prefetch starts reading f from the disk, when fsys holds it in a file.
func prefetch(fsys fs.FS, f aheadFile) {
	file, err := fsys.Open(f.path)
	if err != nil {
		return
	}
	defer file.Close()
	if osf, ok := file.(*os.File); ok {
		readAhead(osf, f.size)
	}
}

func walk[T any](ctx context.Context, fsys fs.FS, path string, c chan T, onFile onFile[T]) error {
	f, err := fsys.Open(path)
	if errors.Is(err, fs.ErrPermission) || errors.Is(err, fs.ErrNotExist) {
		log.Debug("Skip the file that cannot be opened", log.FilePath(path), log.Err(err))
		return nil
	} else if err != nil {
		return xerrors.Errorf("file open error: %w", err)
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return xerrors.Errorf("stat error: %w", err)
	}

	rsa, ok := f.(xio.ReadSeekerAt)
	if !ok {
		return xerrors.New("type assertion failed")
	}
	res, err := onFile(path, info, rsa)
	if err != nil {
		// onFile may have failed because ctx is done, and then the file
		// was cut short rather than skipped.
		if err := ctx.Err(); err != nil {
			return err
		}
		log.Debug("Walk error", log.FilePath(path), log.Err(err))
		return nil
	}

	select {
	case c <- res:
	case <-ctx.Done():
		return ctx.Err()
	}
	return nil
}
