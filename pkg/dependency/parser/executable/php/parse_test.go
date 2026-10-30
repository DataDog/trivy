package phpparser

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func TestParse(t *testing.T) {
	tests := []struct {
		name      string
		inputFile string
		want      []types.Package
		wantErr   string
	}{
		{
			name:      "ELF",
			inputFile: "../nodejs/testdata/php.elf",
			want: []types.Package{
				{
					ID:      "php@8.0.7",
					Name:    "php",
					Version: "8.0.7",
				},
			},
		},
		{
			name:      "sad path",
			inputFile: "testdata/dummy",
			wantErr:   "unrecognized executable format",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := os.Open(tt.inputFile)
			require.NoError(t, err)
			defer f.Close()
			r := &readRecorder{File: f}

			parser := NewParser()
			got, _, err := parser.Parse(t.Context(), r)
			if tt.wantErr != "" {
				require.Error(t, err)
				require.ErrorContains(t, err, tt.wantErr)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
			assert.LessOrEqual(t, r.max, 1<<20, "largest read")
		})
	}
}

// readRecorder records the size of the largest read from a file.
type readRecorder struct {
	*os.File
	max int
}

func (r *readRecorder) ReadAt(p []byte, off int64) (int, error) {
	r.max = max(r.max, len(p))
	return r.File.ReadAt(p, off)
}

func BenchmarkParse(b *testing.B) {
	f, err := os.Open("../nodejs/testdata/php.elf")
	require.NoError(b, err)
	defer f.Close()
	parser := NewParser()
	b.ReportAllocs()
	for b.Loop() {
		if _, _, err := parser.Parse(b.Context(), f); err != nil {
			b.Fatal(err)
		}
	}
}
