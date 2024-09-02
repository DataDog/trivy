package javaparser

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
			got, _, err := parser.Parse(f)
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
