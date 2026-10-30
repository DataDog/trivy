package mapfs

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/set"
	xsync "github.com/aquasecurity/trivy/pkg/x/sync"
)

var separator = "/"

// file represents one of them:
// - an actual file
// - a virtual file
// - a virtual dir
type file struct {
	underlyingPath string // underlying file path
	data           []byte // virtual file, only either of 'path' or 'data' has a value.
	stat           fileStat
	files          xsync.Map[string, *file]
}

func (f *file) isVirtual() bool {
	return f.underlyingPath == ""
}

func (f *file) Open(name string) (fs.File, error) {
	if name == "" || name == "." {
		return f.open()
	}

	if sub, err := f.getFile(name); err == nil {
		return sub.open()
	}

	return nil, &fs.PathError{
		Op:   "open",
		Path: name,
		Err:  fs.ErrNotExist,
	}
}

func (f *file) open() (fs.File, error) {
	switch {
	case f.stat.IsDir(): // Directory
		entries, err := f.ReadDir(".")
		if err != nil {
			return nil, xerrors.Errorf("read dir error: %w", err)
		}
		return &mapDir{
			path:     f.underlyingPath,
			fileStat: f.stat,
			entry:    entries,
		}, nil
	case f.isVirtual(): // Virtual file
		return &openMapFile{
			path:   f.stat.name,
			file:   f,
			offset: 0,
		}, nil
	default: // Real file
		return os.Open(f.underlyingPath)
	}
}

func (f *file) Remove(name string) error {
	if name == "" || name == "." {
		return nil
	}

	return f.removePath(name, false)
}

func (f *file) RemoveAll(name string) error {
	if name == "" || name == "." {
		return nil
	}

	return f.removePath(name, true)
}

func (f *file) removePath(name string, recursive bool) error {
	for {
		elem, rest, more := strings.Cut(name, separator)
		if !more {
			sub, ok := f.files.Load(name)
			if !ok {
				return fs.ErrNotExist
			}
			if sub.files.Len() != 0 && !recursive {
				return fs.ErrInvalid
			}
			f.files.Delete(name)
			return nil
		}

		sub, err := f.getFile(elem)
		if err != nil {
			return err
		} else if !sub.stat.IsDir() {
			return fs.ErrNotExist
		}
		f, name = sub, rest
	}
}

func (f *file) getFile(name string) (*file, error) {
	for name != "" && name != "." {
		elem, rest, more := strings.Cut(name, separator)
		sub, ok := f.files.Load(elem)
		if !ok || (more && !sub.stat.IsDir()) {
			return nil, fs.ErrNotExist
		}
		f, name = sub, rest
	}
	return f, nil
}

// holds reports whether the tree under f, whose path is dir, holds a file
// in paths.
func (f *file) holds(paths set.Set[string], dir string) bool {
	found := false
	f.files.Range(func(name string, sub *file) bool {
		p := joinPath(dir, name)
		if sub.stat.IsDir() {
			found = sub.holds(paths, p)
		} else {
			found = paths.Contains(p)
		}
		return !found
	})
	return found
}

// without returns a copy of the tree under f, whose path is dir, without
// the files in paths. The copy shares the file nodes, which FS never
// changes in place.
func (f *file) without(paths set.Set[string], dir string) *file {
	c := &file{
		underlyingPath: f.underlyingPath,
		data:           f.data,
		stat:           f.stat,
	}
	f.files.Range(func(name string, sub *file) bool {
		p := joinPath(dir, name)
		switch {
		case sub.stat.IsDir():
			c.files.Store(name, sub.without(paths, p))
		case !paths.Contains(p):
			c.files.Store(name, sub)
		}
		return true
	})
	return c
}

// addAll adds the tree under src to the tree under f, sharing the file
// nodes. Where both hold a name, f keeps its own.
func (f *file) addAll(src *file) {
	src.files.Range(func(name string, sub *file) bool {
		if !sub.stat.IsDir() {
			f.files.LoadOrStore(name, sub)
			return true
		}
		dir, _ := f.files.LoadOrStore(name, &file{stat: sub.stat})
		if dir.stat.IsDir() {
			dir.addAll(sub)
		}
		return true
	})
}

// eachFile calls yield with the path of each file under f, whose path is
// dir, until yield returns false. It reports whether yield never did.
func (f *file) eachFile(dir string, yield func(string) bool) bool {
	more := true
	f.files.Range(func(name string, sub *file) bool {
		p := joinPath(dir, name)
		if sub.stat.IsDir() {
			more = sub.eachFile(p, yield)
		} else {
			more = yield(p)
		}
		return more
	})
	return more
}

func joinPath(dir, name string) string {
	if dir == "" {
		return name
	}
	return dir + separator + name
}

func (f *file) ReadDir(name string) ([]fs.DirEntry, error) {
	if name == "" || name == "." {
		var entries []fs.DirEntry
		var err error
		f.files.Range(func(name string, value *file) bool {
			if value.isVirtual() {
				entries = append(entries, &value.stat)
			} else {
				fi, serr := os.Stat(value.underlyingPath)
				switch {
				case errors.Is(serr, fs.ErrNotExist), errors.Is(serr, fs.ErrPermission):
					// The file went away or became unreadable after it was
					// linked. Leave it out, as a walk of the disk would.
					return true
				case serr != nil:
					err = serr
					return false
				}
				entries = append(entries, &fileStat{
					name:    name,
					size:    fi.Size(),
					mode:    fi.Mode(),
					modTime: fi.ModTime(),
					sys:     fi.Sys(),
				})
			}
			return true
		})
		if err != nil {
			return nil, xerrors.Errorf("range error: %w", err)
		}
		sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
		return entries, nil
	}

	elem, rest, _ := strings.Cut(name, separator)
	dir, ok := f.files.Load(elem)
	if !ok || !dir.stat.IsDir() {
		return nil, fs.ErrNotExist
	}
	return dir.ReadDir(rest)
}

func (f *file) MkdirAll(path string, perm fs.FileMode) error {
	if perm&fs.ModeDir == 0 {
		perm |= fs.ModeDir
	}
	for path != "" && path != "." {
		elem, rest, _ := strings.Cut(path, separator)
		sub, loaded := f.files.Load(elem)
		if !loaded {
			// Create the directory when the key is not present
			sub, loaded = f.files.LoadOrStore(elem, &file{
				stat: fileStat{
					name:    elem,
					size:    0x100,
					modTime: time.Now(),
					mode:    perm,
				},
			})
		}
		if loaded && !sub.stat.IsDir() {
			return fs.ErrExist
		}
		f, path = sub, rest
	}
	return nil
}

func (f *file) WriteFile(path, underlyingPath string) error {
	dir, name, err := f.parent(path)
	if err != nil {
		return err
	}
	dir.files.Store(name, &file{
		underlyingPath: underlyingPath,
	})
	return nil
}

// parent returns the directory that holds path, and the last element of
// path.
func (f *file) parent(path string) (*file, string, error) {
	for {
		elem, rest, more := strings.Cut(path, separator)
		if !more {
			return f, elem, nil
		}
		dir, ok := f.files.Load(elem)
		if !ok || !dir.stat.IsDir() {
			return nil, "", fs.ErrNotExist
		}
		f, path = dir, rest
	}
}

func (f *file) WriteVirtualFile(path string, data []byte, mode fs.FileMode) error {
	if mode&fs.ModeDir != 0 {
		return xerrors.Errorf("invalid perm: %v", mode)
	}
	dir, name, err := f.parent(path)
	if err != nil {
		return err
	}
	dir.files.Store(name, &file{
		data: data,
		stat: fileStat{
			name:    name,
			size:    int64(len(data)),
			mode:    mode,
			modTime: time.Now(),
		},
	})
	return nil
}

func (f *file) glob(pattern string) ([]string, error) {
	var entries []string
	parts := strings.Split(pattern, separator)

	var err error
	f.files.Range(func(name string, sub *file) bool {
		var ok bool
		ok, err = filepath.Match(parts[0], name)
		if err != nil {
			return false
		} else if ok {
			if len(parts) == 1 {
				entries = append(entries, name)
			} else {
				var subEntries []string
				subEntries, err = sub.glob(strings.Join(parts[1:], separator))
				if err != nil {
					return false
				}
				for _, sub := range subEntries {
					entries = append(entries, name+separator+sub)
				}
			}
		}
		return true
	})
	if err != nil {
		return nil, xerrors.Errorf("range error: %w", err)
	}

	sort.Strings(entries)
	return entries, nil
}

// An openMapFile is a regular (non-directory) fs.File open for reading.
// ported from https://github.com/golang/go/blob/99bc53f5e819c2d2d49f2a56c488898085be3982/src/testing/fstest/mapfs.go
type openMapFile struct {
	path string
	*file
	offset int64
}

func (f *openMapFile) Stat() (fs.FileInfo, error) { return &f.file.stat, nil }

func (f *openMapFile) Close() error { return nil }

func (f *openMapFile) Read(b []byte) (int, error) {
	if f.offset >= int64(len(f.file.data)) {
		return 0, io.EOF
	}
	if f.offset < 0 {
		return 0, &fs.PathError{
			Op:   "read",
			Path: f.path,
			Err:  fs.ErrInvalid,
		}
	}
	n := copy(b, f.file.data[f.offset:])
	f.offset += int64(n)
	return n, nil
}

func (f *openMapFile) Seek(offset int64, whence int) (int64, error) {
	switch whence {
	case 0:
		// offset += 0
	case 1:
		offset += f.offset
	case 2:
		offset += int64(len(f.file.data))
	}
	if offset < 0 || offset > int64(len(f.file.data)) {
		return 0, &fs.PathError{
			Op:   "seek",
			Path: f.path,
			Err:  fs.ErrInvalid,
		}
	}
	f.offset = offset
	return offset, nil
}

func (f *openMapFile) ReadAt(b []byte, offset int64) (int, error) {
	if offset < 0 || offset > int64(len(f.file.data)) {
		return 0, &fs.PathError{
			Op:   "read",
			Path: f.path,
			Err:  fs.ErrInvalid,
		}
	}
	n := copy(b, f.file.data[offset:])
	if n < len(b) {
		return n, io.EOF
	}
	return n, nil
}

// A mapDir is a directory fs.File (so also fs.ReadDirFile) open for reading.
type mapDir struct {
	path string
	fileStat
	entry  []fs.DirEntry
	offset int
}

func (d *mapDir) Stat() (fs.FileInfo, error) { return &d.fileStat, nil }
func (d *mapDir) Close() error               { return nil }
func (d *mapDir) Read(_ []byte) (int, error) {
	return 0, &fs.PathError{
		Op:   "read",
		Path: d.path,
		Err:  fs.ErrInvalid,
	}
}

func (d *mapDir) ReadDir(count int) ([]fs.DirEntry, error) {
	n := len(d.entry) - d.offset
	if n == 0 && count > 0 {
		return nil, io.EOF
	}
	if count > 0 && n > count {
		n = count
	}
	list := make([]fs.DirEntry, n)
	for i := range list {
		list[i] = d.entry[d.offset+i]
	}
	d.offset += n
	return list, nil
}
