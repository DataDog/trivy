package javaparser

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"os"
	"slices"
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
			name:      "jre-8u421-linux-x64",
			inputFile: "testdata/java.jre-8u421-linux-x64.elf",
			want: []types.Package{
				{
					ID:      "java@1.8.0_421-b09",
					Name:    "java",
					Version: "1.8.0_421-b09",
				},
			},
		},
		{
			name:      "OpenJDK21U-jdk_x64_linux_hotspot_21.0.4_7",
			inputFile: "testdata/java.OpenJDK21U-jdk_x64_linux_hotspot_21.0.4_7.elf",
			want: []types.Package{
				{
					ID:      "java@1.8.0_44-b02",
					Name:    "java",
					Version: "1.8.0_44-b02",
				},
			},
		},
		{
			name:      "openjdk-23+37_linux-x64_bin",
			inputFile: "testdata/java.openjdk-23+37_linux-x64_bin.elf",
			want: []types.Package{
				{
					ID:      "java@23+37-2369",
					Name:    "java",
					Version: "23+37-2369",
				},
			},
		},
		{
			name:      "openjdk-8u44-linux-x64",
			inputFile: "testdata/java.openjdk-8u44-linux-x64.elf",
			want: []types.Package{
				{
					ID:      "java@1.8.0_44-b02",
					Name:    "java",
					Version: "1.8.0_44-b02",
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

			parser := NewParser()
			got, _, err := parser.Parse(t.Context(), f)
			if tt.wantErr != "" {
				require.Error(t, err)
				require.ErrorContains(t, err, tt.wantErr)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestParse_segmentPastEnd(t *testing.T) {
	data, err := os.ReadFile("testdata/java.jre-8u421-linux-x64.elf")
	require.NoError(t, err)

	// Make .rodata and the segment that holds it claim 2^50 bytes, as a
	// crafted file can.
	f, err := elf.NewFile(bytes.NewReader(data))
	require.NoError(t, err)
	s := slices.IndexFunc(f.Sections, func(s *elf.Section) bool { return s.Name == ".rodata" })
	require.GreaterOrEqual(t, s, 0)
	addr := f.Sections[s].Addr
	p := slices.IndexFunc(f.Progs, func(p *elf.Prog) bool {
		return p.Vaddr <= addr && addr < p.Vaddr+p.Filesz
	})
	require.GreaterOrEqual(t, p, 0)
	le := binary.LittleEndian
	shoff, shentsize := le.Uint64(data[0x28:]), uint64(le.Uint16(data[0x3a:]))
	phoff, phentsize := le.Uint64(data[0x20:]), uint64(le.Uint16(data[0x36:]))
	le.PutUint64(data[shoff+uint64(s)*shentsize+32:], 1<<50) // sh_size of an Elf64_Shdr
	le.PutUint64(data[phoff+uint64(p)*phentsize+32:], 1<<50) // p_filesz of an Elf64_Phdr

	got, _, err := NewParser().Parse(t.Context(), bytes.NewReader(data))
	require.NoError(t, err)
	assert.Empty(t, got)
}
