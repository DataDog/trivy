// Ported from https://github.com/golang/go/blob/b5a861782312d2b3a4f71e33d9a0c2b01a40fe5f/src/debug/buildinfo/buildinfo.go

package executable

import (
	"bytes"
	"debug/elf"
	"errors"
	"fmt"
	"io"
	"regexp"
)

var errUnrecognizedFormat = errors.New("unrecognized file format")

// chunkSize is the most FindSubmatch reads at once.
const chunkSize = 1 << 20

// An exe is a generic interface to an OS executable (ELF, Mach-O, PE, XCOFF).
type Exe interface {
	// ReadData reads and returns up to size byte starting at virtual address addr.
	ReadData(addr, size uint64) ([]byte, error)

	// DataReader returns a reader of the data from virtual address addr
	// to the end of the segment that holds it.
	DataReader(addr uint64) (*io.SectionReader, error)

	// DataStart returns the writable data segment start address.
	DataStart() (uint64, uint64)
}

// openExe opens file and returns it as an exe.
func OpenExe(r io.ReaderAt) (Exe, error) {
	ident := make([]byte, 16)
	if n, err := r.ReadAt(ident, 0); n < len(ident) || err != nil {
		return nil, errUnrecognizedFormat
	}

	switch {
	case bytes.HasPrefix(ident, []byte("\x7FELF")):
		f, err := elf.NewFile(r)
		if err != nil {
			return nil, errUnrecognizedFormat
		}
		return &elfExe{f}, nil
	default:
		return nil, errUnrecognizedFormat
	}

	return nil, errUnrecognizedFormat
}

// FindSubmatch returns the submatches of re in the first NUL-terminated
// string of the data section of x that re matches, or nil. It reads the
// section in chunks of up to 1 MB that end on a string boundary, stops at
// the first match, and skips strings too long for a chunk.
func FindSubmatch(x Exe, re *regexp.Regexp) [][]byte {
	addr, size := x.DataStart()
	r, err := x.DataReader(addr)
	if err != nil {
		return nil
	}
	size = min(size, uint64(r.Size()))
	buf := make([]byte, min(size, chunkSize))
	long := false // the chunk starts inside a string too long for a chunk
	for off := uint64(0); off < size; {
		data := buf[:min(size-off, chunkSize)]
		if _, err := r.ReadAt(data, int64(off)); err != nil {
			return nil
		}
		if off+uint64(len(data)) < size {
			// The last string may go on past the chunk.
			// Leave it for the next chunk.
			i := bytes.LastIndexByte(data, 0)
			if i < 0 {
				long = true
				off += uint64(len(data))
				continue
			}
			data = data[:i+1]
		}
		off += uint64(len(data))
		if long {
			_, data, _ = bytes.Cut(data, []byte{0})
			long = false
		}
		for len(data) > 0 {
			head, tail, _ := bytes.Cut(data, []byte{0})
			if m := re.FindSubmatch(head); m != nil {
				return m
			}
			data = tail
		}
	}
	return nil
}

// elfExe is the ELF implementation of the exe interface.
type elfExe struct {
	f *elf.File
}

func (x *elfExe) ReadData(addr, size uint64) ([]byte, error) {
	r, err := x.DataReader(addr)
	if err != nil {
		return nil, err
	}
	data := make([]byte, min(size, uint64(r.Size())))
	if _, err := r.ReadAt(data, 0); err != nil {
		return nil, err
	}
	return data, nil
}

func (x *elfExe) DataReader(addr uint64) (*io.SectionReader, error) {
	for _, prog := range x.f.Progs {
		if prog.Vaddr > addr || addr > prog.Vaddr+prog.Filesz-1 {
			continue
		}
		return io.NewSectionReader(prog, int64(addr-prog.Vaddr), int64(prog.Vaddr+prog.Filesz-addr)), nil
	}
	return nil, fmt.Errorf("address not mapped")
}

func (x *elfExe) DataStart() (uint64, uint64) {
	for _, s := range x.f.Sections {
		if s.Name == ".rodata" {
			return s.Addr, s.SectionHeader.Size
		}
	}
	return 0, 0
}
