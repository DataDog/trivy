package pip

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func Test_pipAnalyzer_Analyze(t *testing.T) {
	tests := []struct {
		name string
		dir  string
		want *analyzer.AnalysisResult
	}{
		{
			name: "happy path",
			dir:  filepath.Join("testdata", "happy"),
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.Pip,
						FilePath: "requirements.txt",
						Packages: types.Packages{
							{
								Name:    "annotated-types",
								Version: "0.7.0",
								Locations: []types.Location{
									{
										StartLine: 1,
										EndLine:   1,
									},
								},
							},
							{
								Name:    "click",
								Version: "8.0.0",
								Locations: []types.Location{
									{
										StartLine: 2,
										EndLine:   2,
									},
								},
							},
							{
								Name:    "Flask",
								Version: "2.0.0",
								Locations: []types.Location{
									{
										StartLine: 3,
										EndLine:   3,
									},
								},
							},
							{
								Name:    "itsdangerous",
								Version: "2.0.0",
								Locations: []types.Location{
									{
										StartLine: 4,
										EndLine:   4,
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "happy path with not related filename",
			dir:  "testdata/empty",
			want: &analyzer.AnalysisResult{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// The scanning host has a Python, as a virtual environment and
			// in PATH, with click installed in its site-packages.
			python := t.TempDir()
			metadata := filepath.Join(python, "lib", "python3.12", "site-packages", "click-8.0.0.dist-info", "METADATA")
			require.NoError(t, os.MkdirAll(filepath.Dir(metadata), 0o755))
			require.NoError(t, os.WriteFile(metadata, []byte("Metadata-Version: 2.1\nName: click\nVersion: 8.0.0\nLicense: BSD-3-Clause\n\n"), 0o644))
			require.NoError(t, os.Mkdir(filepath.Join(python, "bin"), 0o755))
			require.NoError(t, os.WriteFile(filepath.Join(python, "bin", "python3"), nil, 0o755))
			t.Setenv("VIRTUAL_ENV", python)
			t.Setenv("PATH", filepath.Join(python, "bin"))

			a, err := newPipLibraryAnalyzer(analyzer.AnalyzerOptions{})
			require.NoError(t, err)

			got, err := a.PostAnalyze(t.Context(), analyzer.PostAnalysisInput{
				FS: os.DirFS(tt.dir),
			})

			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_pipAnalyzer_Required(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
		want     bool
	}{
		{
			name:     "happy",
			filePath: "test/requirements.txt",
			want:     true,
		},
		{
			name:     "sad",
			filePath: "a/b/c/d/test.sum",
			want:     false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := pipLibraryAnalyzer{}
			got := a.Required(tt.filePath, nil)
			assert.Equal(t, tt.want, got)
		})
	}
}
