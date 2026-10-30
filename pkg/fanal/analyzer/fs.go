package analyzer

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"path"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/mapfs"
	xos "github.com/aquasecurity/trivy/pkg/x/os"
	"github.com/aquasecurity/trivy/pkg/x/sync"
)

// CompositeFS contains multiple filesystems for post-analyzers
type CompositeFS struct {
	dir   string
	files *sync.Map[Type, *mapfs.FS]
}

func NewCompositeFS() (*CompositeFS, error) {
	tmpDir, err := xos.MkdirTemp("", "analyzer-composite-")
	if err != nil {
		return nil, xerrors.Errorf("unable to create temporary directory: %w", err)
	}

	return &CompositeFS{
		dir:   tmpDir,
		files: new(sync.Map[Type, *mapfs.FS]),
	}, nil
}

// CopyFileToTemp takes a file path and information, opens the file, copies its contents to a temporary file.
// When the opener returns a file on disk, as the walkers do for a large file they spill, it links that
// file instead.
func (c *CompositeFS) CopyFileToTemp(opener Opener, _ os.FileInfo) (string, error) {
	// Open a file in the layer
	r, err := opener()
	if err != nil {
		return "", xerrors.Errorf("file open error: %w", err)
	}
	defer r.Close()

	if src, ok := r.(*os.File); ok {
		if name, err := c.link(src); err == nil {
			return name, nil
		}
	}

	// Create a temporary file to which the file in the layer will be copied
	// so that all the files will not be loaded into memory
	f, err := xos.CreateTemp(c.dir, "analyzer-file-")
	if err != nil {
		return "", xerrors.Errorf("create temp error: %w", err)
	}
	defer f.Close()

	// Copy file content into the temporary file
	if _, err = io.Copy(f, r); err != nil {
		return "", xerrors.Errorf("copy error: %w", err)
	}

	// Use 0600 instead of file permissions to avoid errors when a file uses incorrect permissions (e.g. 0044).
	if err = os.Chmod(f.Name(), 0o600); err != nil {
		return "", xerrors.Errorf("chmod error: %w", err)
	}

	return f.Name(), nil
}

// link makes a hard link to the open file src under a new name in the
// temporary directory, which keeps the file when its walker removes src.
func (c *CompositeFS) link(src *os.File) (string, error) {
	fi, err := src.Stat()
	if err != nil {
		return "", err
	}
	f, err := xos.CreateTemp(c.dir, "analyzer-file-")
	if err != nil {
		return "", err
	}
	name := f.Name()
	_ = f.Close()
	if err := os.Remove(name); err != nil {
		return "", err
	}
	if err := os.Link(src.Name(), name); err != nil {
		return "", err
	}
	// The link goes by name, which may name another file by now.
	if li, err := os.Stat(name); err != nil || !os.SameFile(fi, li) {
		_ = os.Remove(name)
		return "", xerrors.Errorf("%s names another file", src.Name())
	}
	return name, nil
}

// CreateLink creates a link in the virtual filesystem that corresponds to a real file.
// The linked virtual file will have the same path as the real file path provided.
func (c *CompositeFS) CreateLink(analyzerTypes []Type, rootDir, virtualPath, realPath string) error {
	// Create fs.FS for each post-analyzer that wants to analyze the current file
	for _, t := range analyzerTypes {
		mfs, ok := c.files.Load(t)
		if !ok {
			// Since filesystem scanning may require access outside the specified path, (e.g. Terraform modules)
			// it allows "../" access with "WithUnderlyingRoot".
			var opts []mapfs.Option
			if rootDir != "" {
				opts = append(opts, mapfs.WithUnderlyingRoot(rootDir))
			}
			mfs, _ = c.files.LoadOrStore(t, mapfs.New(opts...))
		}
		if d := path.Dir(virtualPath); d != "." {
			if err := mfs.MkdirAll(d, os.ModePerm); err != nil && !errors.Is(err, fs.ErrExist) {
				return xerrors.Errorf("mapfs mkdir error: %w", err)
			}
		}
		if err := mfs.WriteFile(virtualPath, realPath); err != nil {
			return xerrors.Errorf("mapfs write error: %w", err)
		}
	}
	return nil
}

// Set sets the fs.FS for the specified post-analyzer
func (c *CompositeFS) Set(t Type, mfs *mapfs.FS) {
	c.files.Store(t, mfs)
}

// Get returns the fs.FS for the specified post-analyzer
func (c *CompositeFS) Get(t Type) (*mapfs.FS, bool) {
	return c.files.Load(t)
}

// Cleanup removes the temporary directory
func (c *CompositeFS) Cleanup() error {
	return os.RemoveAll(c.dir)
}
