package binary_test

import (
	"bytes"
	"debug/macho"
	"encoding/binary"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	rustbinary "github.com/aquasecurity/trivy/pkg/dependency/parser/rust/binary"
)

// TestParseSections checks that Parse rules out a non-Rust Mach-O file from
// its load commands alone.
func TestParseSections(t *testing.T) {
	goELF := readFile(t, "../../golang/binary/testdata/test.elf")
	goMachO := readFile(t, "../../golang/binary/testdata/test.macho")
	rustMachO := readFile(t, "testdata/test.macho")
	tests := []struct {
		name    string
		input   []byte
		wantErr error
	}{
		{
			name:    "non-Rust ELF",
			input:   goELF,
			wantErr: rustbinary.ErrNonRustBinary,
		},
		{
			name:    "non-Rust Mach-O",
			input:   goMachO,
			wantErr: rustbinary.ErrNonRustBinary,
		},
		{
			name:    "non-Rust fat Mach-O",
			input:   fatFile(goMachO, goMachO),
			wantErr: rustbinary.ErrNonRustBinary,
		},
		{
			// go-rustaudit rejects fat files.
			name:    "fat Mach-O",
			input:   fatFile(rustMachO, rustMachO),
			wantErr: rustbinary.ErrUnrecognizedExe,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &readCounter{Reader: bytes.NewReader(tt.input)}
			_, _, err := rustbinary.NewParser().Parse(t.Context(), r)
			require.ErrorIs(t, err, tt.wantErr)
			assert.Less(t, r.n, 16<<10, "bytes read")
		})
	}
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
			name:  "non-Rust ELF",
			input: readFile(b, "../../golang/binary/testdata/test.elf"),
		},
		{
			name:  "non-Rust Mach-O",
			input: readFile(b, "../../golang/binary/testdata/test.macho"),
		},
	}
	for _, bm := range benchmarks {
		b.Run(bm.name, func(b *testing.B) {
			r := bytes.NewReader(bm.input)
			p := rustbinary.NewParser()
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
