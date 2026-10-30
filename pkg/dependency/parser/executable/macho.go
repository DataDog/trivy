package executable

import (
	"bytes"
	"debug/macho"
	"encoding/binary"
	"io"
)

// MachOSections reports an error for load commands of more than maxCmdsz
// bytes. Those of a linked file usually take a few kilobytes.
const maxCmdsz = 1 << 20

// MachOSections returns the names of the sections of the Mach-O file r,
// read from its header and load commands, where macho.NewFile reads the
// whole symbol table as well. For a fat file, it returns the sections of
// the first architecture. It returns an error for a malformed file or one
// in another format.
func MachOSections(r io.ReaderAt) ([]string, error) {
	return machoSections(MachOFirstArch(r))
}

// MachOFirstArch returns the first architecture of the fat Mach-O file r,
// the one debug/buildinfo reads, or r itself if r is not a fat file.
// buildinfo.Read decodes every architecture of a fat file, with
// macho.NewFatFile, before it reads the first.
func MachOFirstArch(r io.ReaderAt) io.ReaderAt {
	// The fat header and the fat_arch structs that follow it are big-endian.
	var b [8 + 20]byte
	if _, err := r.ReadAt(b[:], 0); err != nil {
		return r
	}
	magic, narch := binary.BigEndian.Uint32(b[:]), binary.BigEndian.Uint32(b[4:])
	if magic != macho.MagicFat || narch == 0 {
		return r
	}
	var fa macho.FatArchHeader
	if _, err := binary.Decode(b[8:], binary.BigEndian, &fa); err != nil {
		return r
	}
	return io.NewSectionReader(r, int64(fa.Offset), int64(fa.Size))
}

// machoSections returns the names of the sections of the thin Mach-O file
// r.
func machoSections(r io.ReaderAt) ([]string, error) {
	var magic [4]byte
	if _, err := r.ReadAt(magic[:], 0); err != nil {
		return nil, errUnrecognizedFormat
	}
	// Magic32 and Magic64 differ only in the bottom bit.
	var bo binary.ByteOrder
	switch macho.Magic32 &^ 1 {
	case binary.BigEndian.Uint32(magic[:]) &^ 1:
		bo = binary.BigEndian
	case binary.LittleEndian.Uint32(magic[:]) &^ 1:
		bo = binary.LittleEndian
	default:
		return nil, errUnrecognizedFormat
	}
	var hdr macho.FileHeader
	if err := binary.Read(io.NewSectionReader(r, 0, 1<<63-1), bo, &hdr); err != nil {
		return nil, errUnrecognizedFormat
	}
	off := int64(binary.Size(hdr))
	if hdr.Magic == macho.Magic64 {
		off += 4 // reserved
	}
	if hdr.Cmdsz > maxCmdsz {
		return nil, errUnrecognizedFormat
	}
	cmds := make([]byte, hdr.Cmdsz)
	if _, err := r.ReadAt(cmds, off); err != nil {
		return nil, errUnrecognizedFormat
	}

	var names []string
	for range hdr.Ncmd {
		if len(cmds) < 8 {
			return nil, errUnrecognizedFormat
		}
		cmd, size := macho.LoadCmd(bo.Uint32(cmds)), bo.Uint32(cmds[4:])
		if size < 8 || size > uint32(len(cmds)) {
			return nil, errUnrecognizedFormat
		}
		c := cmds[:size]
		cmds = cmds[size:]
		switch cmd {
		case macho.LoadCmdSegment:
			var seg macho.Segment32
			n, err := binary.Decode(c, bo, &seg)
			if err != nil {
				return nil, errUnrecognizedFormat
			}
			for c = c[n:]; seg.Nsect > 0; seg.Nsect-- {
				var s macho.Section32
				n, err := binary.Decode(c, bo, &s)
				if err != nil {
					return nil, errUnrecognizedFormat
				}
				names = append(names, cstring(s.Name[:]))
				c = c[n:]
			}
		case macho.LoadCmdSegment64:
			var seg macho.Segment64
			n, err := binary.Decode(c, bo, &seg)
			if err != nil {
				return nil, errUnrecognizedFormat
			}
			for c = c[n:]; seg.Nsect > 0; seg.Nsect-- {
				var s macho.Section64
				n, err := binary.Decode(c, bo, &s)
				if err != nil {
					return nil, errUnrecognizedFormat
				}
				names = append(names, cstring(s.Name[:]))
				c = c[n:]
			}
		}
	}
	return names, nil
}

// cstring returns the bytes of b up to the first NUL, as a string.
func cstring(b []byte) string {
	s, _, _ := bytes.Cut(b, []byte{0})
	return string(s)
}
