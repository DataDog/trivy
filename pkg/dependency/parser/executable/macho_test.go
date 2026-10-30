package executable_test

import (
	"bytes"
	"debug/macho"
	"encoding/binary"
	"io"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/dependency/parser/executable"
)

// TestMachOSections checks MachOSections against macho.NewFile.
func TestMachOSections(t *testing.T) {
	tests := []struct {
		name string
		file []byte
	}{
		{
			name: "Go",
			file: readFile(t, "../golang/binary/testdata/test.macho"),
		},
		{
			name: "Go with __DATA_CONST",
			file: readFile(t, "../golang/binary/testdata/semver-main-module-version.macho"),
		},
		{
			name: "Rust",
			file: readFile(t, "../rust/binary/testdata/test.macho"),
		},
		{
			name: "64-bit little-endian",
			file: machoFile(binary.LittleEndian, true, "__data", "__go_buildinfo"),
		},
		{
			name: "64-bit big-endian",
			file: machoFile(binary.BigEndian, true, "__data", "__go_buildinfo"),
		},
		{
			name: "32-bit little-endian",
			file: machoFile(binary.LittleEndian, false, "__data", "__go_buildinfo"),
		},
		{
			name: "32-bit big-endian",
			file: machoFile(binary.BigEndian, false, "__data", "__go_buildinfo"),
		},
		{
			name: "no sections",
			file: machoFile(binary.LittleEndian, true),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := macho.NewFile(bytes.NewReader(tt.file))
			require.NoError(t, err)
			var want []string
			for _, s := range f.Sections {
				want = append(want, s.Name)
			}
			got, err := executable.MachOSections(bytes.NewReader(tt.file))
			require.NoError(t, err)
			assert.Equal(t, want, got)
		})
	}
}

func TestMachOSectionsFat(t *testing.T) {
	le := binary.LittleEndian
	first := machoFile(le, true, "__data", "__go_buildinfo")
	second := machoFile(le, true, "__data", ".dep-v0")
	got, err := executable.MachOSections(bytes.NewReader(fatFile(first, second)))
	require.NoError(t, err)
	assert.Equal(t, []string{"__data", "__go_buildinfo"}, got)
}

func TestMachOFirstArch(t *testing.T) {
	first := machoFile(binary.LittleEndian, true, "__data")
	second := machoFile(binary.BigEndian, false, "__data")
	fat := fatFile(first, second)
	tests := []struct {
		name string
		file []byte
		want []byte
	}{
		{
			name: "fat",
			file: fat,
			want: first,
		},
		{
			name: "thin",
			file: first,
			want: first,
		},
		{
			name: "short fat header",
			file: fat[:8],
			want: fat[:8],
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := executable.MachOFirstArch(bytes.NewReader(tt.file))
			got, err := io.ReadAll(io.NewSectionReader(r, 0, 1<<62))
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestMachOSectionsError(t *testing.T) {
	le := binary.LittleEndian
	valid := machoFile(le, true, "__data")
	const (
		cmdsOff = 32           // the load commands follow the 64-bit header
		segOff  = cmdsOff + 24 // and the segment the thread command
	)
	modified := func(f func(b []byte)) []byte {
		b := bytes.Clone(valid)
		f(b)
		return b
	}
	tests := []struct {
		name string
		file []byte
	}{
		{
			name: "empty",
		},
		{
			name: "ELF",
			file: readFile(t, "../golang/binary/testdata/test.elf"),
		},
		{
			name: "short load commands",
			file: valid[:len(valid)-1],
		},
		{
			name: "large load commands",
			file: modified(func(b []byte) {
				var hdr macho.FileHeader
				_, _ = binary.Decode(b, le, &hdr)
				hdr.Cmdsz = 1<<32 - 1
				_, _ = binary.Encode(b, le, hdr)
			}),
		},
		{
			name: "short load command",
			file: modified(func(b []byte) {
				le.PutUint32(b[cmdsOff+4:], 4)
			}),
		},
		{
			name: "load command past the others",
			file: modified(func(b []byte) {
				le.PutUint32(b[cmdsOff+4:], uint32(len(b)-cmdsOff+1))
			}),
		},
		{
			name: "more sections than the segment holds",
			file: modified(func(b []byte) {
				var seg macho.Segment64
				_, _ = binary.Decode(b[segOff:], le, &seg)
				seg.Nsect++
				_, _ = binary.Encode(b[segOff:], le, seg)
			}),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := executable.MachOSections(bytes.NewReader(tt.file))
			require.Error(t, err)
		})
	}
}

func readFile(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(name)
	require.NoError(t, err)
	return b
}

// machoFile returns a thin Mach-O file in byte order bo, 64-bit if wide,
// whose load commands are a thread command and a __DATA segment holding
// sections of the given names.
func machoFile(bo binary.ByteOrder, wide bool, sects ...string) []byte {
	name := func(s string) (b [16]byte) {
		copy(b[:], s)
		return b
	}
	thread, _ := binary.Append(nil, bo, [6]uint32{uint32(macho.LoadCmdUnixThread), 24})
	var seg []byte
	if wide {
		s := macho.Segment64{Cmd: macho.LoadCmdSegment64, Name: name("__DATA"), Nsect: uint32(len(sects))}
		s.Len = uint32(binary.Size(s) + len(sects)*binary.Size(macho.Section64{}))
		seg, _ = binary.Append(nil, bo, s)
		for _, sect := range sects {
			seg, _ = binary.Append(seg, bo, macho.Section64{Name: name(sect), Seg: name("__DATA")})
		}
	} else {
		s := macho.Segment32{Cmd: macho.LoadCmdSegment, Name: name("__DATA"), Nsect: uint32(len(sects))}
		s.Len = uint32(binary.Size(s) + len(sects)*binary.Size(macho.Section32{}))
		seg, _ = binary.Append(nil, bo, s)
		for _, sect := range sects {
			seg, _ = binary.Append(seg, bo, macho.Section32{Name: name(sect), Seg: name("__DATA")})
		}
	}
	hdr := macho.FileHeader{
		Magic: macho.Magic32,
		Cpu:   macho.Cpu386,
		Type:  macho.TypeExec,
		Ncmd:  2,
		Cmdsz: uint32(len(thread) + len(seg)),
	}
	if wide {
		hdr.Magic, hdr.Cpu = macho.Magic64, macho.CpuAmd64
	}
	b, _ := binary.Append(nil, bo, hdr)
	if wide {
		b = append(b, 0, 0, 0, 0) // reserved
	}
	b = append(b, thread...)
	return append(b, seg...)
}

// fatFile returns a fat Mach-O file holding the thin files, each with a
// subtype of its own.
func fatFile(files ...[]byte) []byte {
	b := binary.BigEndian.AppendUint32(nil, macho.MagicFat)
	b = binary.BigEndian.AppendUint32(b, uint32(len(files)))
	off := len(b) + len(files)*binary.Size(macho.FatArchHeader{})
	for i, f := range files {
		b, _ = binary.Append(b, binary.BigEndian, macho.FatArchHeader{
			Cpu:    macho.CpuAmd64,
			SubCpu: uint32(i),
			Offset: uint32(off),
			Size:   uint32(len(f)),
		})
		off += len(f)
	}
	for _, f := range files {
		b = append(b, f...)
	}
	return b
}
