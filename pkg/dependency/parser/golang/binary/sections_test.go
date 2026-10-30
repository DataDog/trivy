package binary_test

import (
	"bytes"
	"debug/elf"
	"debug/macho"
	"encoding/binary"
	"os"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	gobinary "github.com/aquasecurity/trivy/pkg/dependency/parser/golang/binary"
)

// TestParseSections checks that Parse rules out a non-Go file from its
// headers alone, and parses the others in full.
func TestParseSections(t *testing.T) {
	goELF := readFile(t, "testdata/test.elf")
	goMachO := readFile(t, "testdata/test.macho")
	rustMachO := readFile(t, "../../rust/binary/testdata/test.macho")
	tests := []struct {
		name  string
		input []byte
		like  []byte // a file with the same build information, or nil
	}{
		{
			name:  "non-Go ELF",
			input: elfFile(2 << 20),
		},
		{
			name:  "non-Go Mach-O",
			input: rustMachO,
		},
		{
			name:  "non-Go fat Mach-O",
			input: fatFile(rustMachO, rustMachO),
		},
		{
			name:  "fat Mach-O",
			input: fatFile(goMachO, goMachO),
			like:  goMachO,
		},
		{
			name:  "ELF without section headers",
			input: withoutSectionHeaders(t, goELF),
			like:  goELF,
		},
		{
			name:  "ELF without section names",
			input: withoutSectionNames(t, goELF),
			like:  goELF,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &readCounter{Reader: bytes.NewReader(tt.input)}
			gotPkgs, gotDeps, err := gobinary.NewParser().Parse(t.Context(), r)
			if tt.like == nil {
				require.ErrorIs(t, err, gobinary.ErrNonGoBinary)
				assert.Less(t, r.n, 16<<10, "bytes read")
				return
			}
			require.NoError(t, err)
			wantPkgs, wantDeps, err := gobinary.NewParser().Parse(t.Context(), bytes.NewReader(tt.like))
			require.NoError(t, err)
			assert.Equal(t, wantPkgs, gotPkgs)
			assert.Equal(t, wantDeps, gotDeps)
		})
	}
}

func TestParseFatArchitectures(t *testing.T) {
	// Each of the 100 architectures of the fat file is the same Go binary,
	// under a subtype of its own.
	const (
		narch = 100
		off   = 1 << 12
	)
	goMachO := readFile(t, "testdata/test.macho")
	b := binary.BigEndian.AppendUint32(nil, macho.MagicFat)
	b = binary.BigEndian.AppendUint32(b, narch)
	for i := range narch {
		b, _ = binary.Append(b, binary.BigEndian, macho.FatArchHeader{
			Cpu:    macho.CpuAmd64,
			SubCpu: uint32(i),
			Offset: off,
			Size:   uint32(len(goMachO)),
			Align:  12,
		})
	}
	b = append(b, make([]byte, off-len(b))...)
	b = append(b, goMachO...)

	r := &readCounter{Reader: bytes.NewReader(b)}
	gotPkgs, gotDeps, err := gobinary.NewParser().Parse(t.Context(), r)
	require.NoError(t, err)
	wantPkgs, wantDeps, err := gobinary.NewParser().Parse(t.Context(), bytes.NewReader(goMachO))
	require.NoError(t, err)
	assert.Equal(t, wantPkgs, gotPkgs)
	assert.Equal(t, wantDeps, gotDeps)
	assert.Less(t, r.n, 2*len(goMachO), "bytes read")
}

func BenchmarkParse(b *testing.B) {
	benchmarks := []struct {
		name  string
		input []byte
	}{
		{
			name:  "ELF",
			input: readFile(b, "testdata/test.elf"),
		},
		{
			name:  "Mach-O",
			input: readFile(b, "testdata/test.macho"),
		},
		{
			name:  "non-Go ELF",
			input: elfFile(2 << 20),
		},
		{
			name:  "non-Go Mach-O",
			input: readFile(b, "../../rust/binary/testdata/test.macho"),
		},
	}
	for _, bm := range benchmarks {
		b.Run(bm.name, func(b *testing.B) {
			r := bytes.NewReader(bm.input)
			p := gobinary.NewParser()
			b.ReportAllocs()
			for b.Loop() {
				_, _, _ = p.Parse(b.Context(), r)
			}
		})
	}
}

func readFile(tb testing.TB, name string) []byte {
	tb.Helper()
	b, err := os.ReadFile(name)
	require.NoError(tb, err)
	return b
}

// readCounter counts the bytes read through ReadAt.
type readCounter struct {
	*bytes.Reader
	n int
}

func (r *readCounter) ReadAt(p []byte, off int64) (int, error) {
	n, err := r.Reader.ReadAt(p, off)
	r.n += n
	return n, err
}

// elfFile returns a little-endian ELF executable whose only section,
// .data, fills a writable segment of size bytes.
func elfFile(size int) []byte {
	const shstrtab = "\x00.data\x00.shstrtab\x00"
	hdrSize := binary.Size(elf.Header64{})
	progSize := binary.Size(elf.Prog64{})
	dataOff := uint64(hdrSize + progSize)
	strOff := dataOff + uint64(size)
	b, _ := binary.Append(nil, binary.LittleEndian, elf.Header64{
		Ident:     [elf.EI_NIDENT]byte{0x7f, 'E', 'L', 'F', byte(elf.ELFCLASS64), byte(elf.ELFDATA2LSB), byte(elf.EV_CURRENT)},
		Type:      uint16(elf.ET_EXEC),
		Machine:   uint16(elf.EM_X86_64),
		Version:   uint32(elf.EV_CURRENT),
		Phoff:     uint64(hdrSize),
		Shoff:     strOff + uint64(len(shstrtab)),
		Ehsize:    uint16(hdrSize),
		Phentsize: uint16(progSize),
		Phnum:     1,
		Shentsize: uint16(binary.Size(elf.Section64{})),
		Shnum:     3,
		Shstrndx:  2,
	})
	b, _ = binary.Append(b, binary.LittleEndian, elf.Prog64{
		Type:   uint32(elf.PT_LOAD),
		Flags:  uint32(elf.PF_R | elf.PF_W),
		Off:    dataOff,
		Vaddr:  dataOff,
		Filesz: uint64(size),
		Memsz:  uint64(size),
	})
	b = append(b, make([]byte, size)...)
	b = append(b, shstrtab...)
	b, _ = binary.Append(b, binary.LittleEndian, []elf.Section64{
		{},
		{
			Name:  1,
			Type:  uint32(elf.SHT_PROGBITS),
			Flags: uint64(elf.SHF_ALLOC | elf.SHF_WRITE),
			Addr:  dataOff,
			Off:   dataOff,
			Size:  uint64(size),
		},
		{
			Name: 7,
			Type: uint32(elf.SHT_STRTAB),
			Off:  strOff,
			Size: uint64(len(shstrtab)),
		},
	})
	return b
}

// fatFile returns a fat Mach-O file holding the thin files, one for each
// of amd64 and arm64.
func fatFile(files ...[]byte) []byte {
	const (
		align = 12 // log2 of the alignment of each file
		page  = 1 << align
	)
	roundUp := func(n int) int {
		return (n + page - 1) &^ (page - 1)
	}
	cpus := []macho.Cpu{macho.CpuAmd64, macho.CpuArm64}
	b := binary.BigEndian.AppendUint32(nil, macho.MagicFat)
	b = binary.BigEndian.AppendUint32(b, uint32(len(files)))
	off := page
	for i, f := range files {
		b, _ = binary.Append(b, binary.BigEndian, macho.FatArchHeader{
			Cpu:    cpus[i],
			Offset: uint32(off),
			Size:   uint32(len(f)),
			Align:  align,
		})
		off = roundUp(off + len(f))
	}
	for _, f := range files {
		b = append(b, make([]byte, roundUp(len(b))-len(b))...)
		b = append(b, f...)
	}
	return b
}

// withoutSectionHeaders returns a copy of the little-endian 64-bit ELF file
// b with its section headers removed, as sstrip leaves a file.
func withoutSectionHeaders(t *testing.T, b []byte) []byte {
	var hdr elf.Header64
	_, err := binary.Decode(b, binary.LittleEndian, &hdr)
	require.NoError(t, err)
	hdr.Shoff, hdr.Shnum, hdr.Shstrndx = 0, 0, 0
	b = slices.Clone(b)
	_, err = binary.Encode(b, binary.LittleEndian, hdr)
	require.NoError(t, err)
	return b
}

// withoutSectionNames returns a copy of the little-endian 64-bit ELF file b
// whose header gives SHN_UNDEF for its section name table, which leaves its
// sections with empty names.
func withoutSectionNames(t *testing.T, b []byte) []byte {
	var hdr elf.Header64
	_, err := binary.Decode(b, binary.LittleEndian, &hdr)
	require.NoError(t, err)
	hdr.Shstrndx = 0
	b = slices.Clone(b)
	_, err = binary.Encode(b, binary.LittleEndian, hdr)
	require.NoError(t, err)
	return b
}
