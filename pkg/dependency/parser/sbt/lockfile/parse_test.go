package lockfile

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
)

func TestParser_Parse(t *testing.T) {
	tests := []struct {
		name      string
		inputFile string
		want      []ftypes.Package
	}{
		{
			name:      "v1 happy path",
			inputFile: "testdata/v1_happy.sbt.lock",
			want: []ftypes.Package{
				{
					ID:        "org.apache.commons:commons-lang3:3.9",
					Name:      "org.apache.commons:commons-lang3",
					Version:   "3.9",
					Locations: []ftypes.Location{{}},
				},
				{
					ID:        "org.scala-lang:scala-library:2.12.10",
					Name:      "org.scala-lang:scala-library",
					Version:   "2.12.10",
					Locations: []ftypes.Location{{}},
				},
				{
					ID:        "org.typelevel:cats-core_2.12:2.9.0",
					Name:      "org.typelevel:cats-core_2.12",
					Version:   "2.9.0",
					Locations: []ftypes.Location{{}},
				},
			},
		},
		{
			name:      "empty",
			inputFile: "testdata/empty.sbt.lock",
			want:      nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parser := NewParser()
			f, err := os.Open(tt.inputFile)
			require.NoError(t, err)

			libs, _, err := parser.Parse(t.Context(), f)
			require.NoError(t, err)

			assert.Equal(t, tt.want, libs)
		})
	}
}
