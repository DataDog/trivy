package executable_test

import (
	"bytes"
	"io"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/trivy/pkg/dependency/parser/executable"
)

func TestFindSubmatch(t *testing.T) {
	const chunk = 1 << 20
	filler := func(n int) string {
		return strings.Repeat("x", n)
	}
	tests := []struct {
		name string
		data string
		want string
	}{
		{
			name: "first string",
			data: "v1.2.3\x00v4.5.6\x00",
			want: "1.2.3",
		},
		{
			name: "unterminated last string",
			data: "foo\x00v1.2.3",
			want: "1.2.3",
		},
		{
			name: "string across chunks",
			data: filler(chunk-4) + "\x00v1.2.3\x00v4.5.6\x00",
			want: "1.2.3",
		},
		{
			name: "string ending a chunk",
			data: filler(chunk-8) + "\x00v1.2.3\x00v4.5.6\x00",
			want: "1.2.3",
		},
		{
			name: "string too long for a chunk",
			data: filler(chunk) + "v0.0.0\x00v1.2.3\x00",
			want: "1.2.3",
		},
		{
			name: "string over several chunks",
			data: filler(3*chunk+5) + "\x00foo\x00v1.2.3",
			want: "1.2.3",
		},
		{
			name: "no match",
			data: "foo\x00v1.2\x00" + filler(chunk),
		},
		{
			name: "empty",
		},
	}
	re := regexp.MustCompile(`^v(\d+\.\d+\.\d+)$`)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			x := &memExe{data: []byte(tt.data)}
			var got string
			if m := executable.FindSubmatch(x, re); m != nil {
				got = string(m[1])
			}
			assert.Equal(t, tt.want, got)
			assert.LessOrEqual(t, x.max, chunk, "largest read")
		})
	}
}

// memExe is an executable whose data section is data. It records the size
// of the largest read.
type memExe struct {
	data []byte
	max  int
}

func (x *memExe) ReadData(addr, size uint64) ([]byte, error) {
	return x.data[addr:min(addr+size, uint64(len(x.data)))], nil
}

func (x *memExe) DataReader(addr uint64) (*io.SectionReader, error) {
	return io.NewSectionReader(x, int64(addr), int64(len(x.data))-int64(addr)), nil
}

func (x *memExe) DataStart() (uint64, uint64) {
	return 0, uint64(len(x.data))
}

func (x *memExe) ReadAt(p []byte, off int64) (int, error) {
	x.max = max(x.max, len(p))
	return bytes.NewReader(x.data).ReadAt(p, off)
}
