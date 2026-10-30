package nuget

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func Test_nugetLibraryAnalyzer_Analyze(t *testing.T) {
	tests := []struct {
		name string
		dir  string
		want *analyzer.AnalysisResult
	}{
		{
			name: "happy path config file.",
			dir:  "testdata/config",
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.NuGet,
						FilePath: "packages.config",
						Packages: types.Packages{
							{
								Name:    "Microsoft.AspNet.WebApi",
								Version: "5.2.2",
							},
							{
								Name:    "Newtonsoft.Json",
								Version: "6.0.4",
							},
						},
					},
				},
			},
		},
		{
			name: "happy path lock file.",
			dir:  "testdata/lock",
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.NuGet,
						FilePath: "packages.lock.json",
						Packages: types.Packages{
							{
								ID:           "Newtonsoft.Json@12.0.3",
								Name:         "Newtonsoft.Json",
								Version:      "12.0.3",
								Relationship: types.RelationshipDirect,
								Locations: []types.Location{
									{
										StartLine: 5,
										EndLine:   10,
									},
								},
							},
							{
								ID:           "NuGet.Frameworks@5.7.0",
								Name:         "NuGet.Frameworks",
								Version:      "5.7.0",
								Relationship: types.RelationshipDirect,
								Locations: []types.Location{
									{
										StartLine: 11,
										EndLine:   19,
									},
								},
								DependsOn: []string{"Newtonsoft.Json@12.0.3"},
							},
						},
					},
				},
			},
		},
		{
			name: "happy path lock file without dependencies.",
			dir:  "testdata/lock-without-deps",
			want: &analyzer.AnalysisResult{},
		},
		{
			name: "sad path",
			dir:  "testdata/sad",
			want: &analyzer.AnalysisResult{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, err := newNugetLibraryAnalyzer(analyzer.AnalyzerOptions{})
			require.NoError(t, err)

			got, err := a.PostAnalyze(t.Context(), analyzer.PostAnalysisInput{
				FS: os.DirFS(tt.dir),
			})

			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_nugetLibraryAnalyzer_Analyze_cache(t *testing.T) {
	// The global packages folder of the scanning host has a nuspec for
	// Newtonsoft.Json.
	packages := t.TempDir()
	nuspec := filepath.Join(packages, "newtonsoft.json", "12.0.3", "newtonsoft.json.nuspec")
	require.NoError(t, os.MkdirAll(filepath.Dir(nuspec), 0o755))
	require.NoError(t, os.WriteFile(nuspec, []byte(`<package><metadata><license type="expression">MIT</license></metadata></package>`), 0o644))
	t.Setenv("NUGET_PACKAGES", packages)

	a, err := newNugetLibraryAnalyzer(analyzer.AnalyzerOptions{})
	require.NoError(t, err)

	got, err := a.PostAnalyze(t.Context(), analyzer.PostAnalysisInput{
		FS: os.DirFS("testdata/lock"),
	})
	require.NoError(t, err)
	require.Len(t, got.Applications, 1)
	for _, pkg := range got.Applications[0].Packages {
		assert.Empty(t, pkg.Licenses, pkg.ID)
	}
}

func Test_nugetLibraryAnalyzer_Required(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
		want     bool
	}{
		{
			name:     "config",
			filePath: "test/packages.config",
			want:     true,
		},
		{
			name:     "lock",
			filePath: "test/packages.lock.json",
			want:     true,
		},
		{
			name:     "zip",
			filePath: "test.zip",
			want:     false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := nugetLibraryAnalyzer{}
			got := a.Required(tt.filePath, nil)
			assert.Equal(t, tt.want, got)
		})
	}
}
