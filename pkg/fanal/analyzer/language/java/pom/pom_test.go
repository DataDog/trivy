package pom

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func Test_pomAnalyzer_Analyze(t *testing.T) {
	tests := []struct {
		name      string
		inputDir  string
		inputFile string
		want      *analyzer.AnalysisResult
		wantErr   string
	}{
		{
			name:      "happy path",
			inputFile: "testdata/happy/pom.xml",
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.Pom,
						FilePath: "testdata/happy/pom.xml",
						Packages: types.Packages{
							{
								ID:           "com.example:example:1.0.0::775be61e",
								Name:         "com.example:example",
								Version:      "1.0.0",
								Licenses:     []string{"Apache 2.0"},
								Relationship: types.RelationshipRoot,
								DependsOn: []string{
									"com.example:example-api:2.0.0::3f5226c1",
								},
							},
							{
								ID:           "com.example:example-api:2.0.0::3f5226c1",
								Name:         "com.example:example-api",
								Version:      "2.0.0",
								Relationship: types.RelationshipDirect,
								Locations: []types.Location{
									{
										StartLine: 28,
										EndLine:   32,
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name:      "happy dir path",
			inputDir:  "testdata/happy",
			inputFile: "pom.xml",
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.Pom,
						FilePath: "pom.xml",
						Packages: types.Packages{
							{
								ID:           "com.example:example:1.0.0::775be61e",
								Name:         "com.example:example",
								Version:      "1.0.0",
								Relationship: types.RelationshipRoot,
								Licenses:     []string{"Apache 2.0"},
								DependsOn: []string{
									"com.example:example-api:2.0.0::3f5226c1",
								},
							},
							{
								ID:           "com.example:example-api:2.0.0::3f5226c1",
								Name:         "com.example:example-api",
								Version:      "2.0.0",
								Relationship: types.RelationshipDirect,
								Locations: []types.Location{
									{
										StartLine: 28,
										EndLine:   32,
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name:      "happy path for maven-invoker-plugin integration tests",
			inputFile: "testdata/mark-as-dev/src/it/example/pom.xml",
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.Pom,
						FilePath: "testdata/mark-as-dev/src/it/example/pom.xml",
						Packages: types.Packages{
							{
								ID:           "com.example:example:1.0.0::c6140fc9",
								Name:         "com.example:example",
								Version:      "1.0.0",
								Licenses:     []string{"Apache 2.0"},
								Relationship: types.RelationshipRoot,
								DependsOn: []string{
									"com.example:example-api:@example.version@::ea8c6bb9",
								},
								Dev: true,
							},
							{
								ID:           "com.example:example-api:@example.version@::ea8c6bb9",
								Name:         "com.example:example-api",
								Version:      "@example.version@",
								Relationship: types.RelationshipDirect,
								Locations: []types.Location{
									{
										StartLine: 28,
										EndLine:   32,
									},
								},
								Dev: true,
							},
						},
					},
				},
			},
		},
		{
			name:      "unsupported requirement",
			inputFile: "testdata/requirements/pom.xml",
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.Pom,
						FilePath: "testdata/requirements/pom.xml",
						Packages: types.Packages{
							{
								ID:           "com.example:example:2.0.0::729d323a",
								Name:         "com.example:example",
								Version:      "2.0.0",
								Licenses:     []string{"Apache 2.0"},
								Relationship: types.RelationshipRoot,
							},
							{
								ID:           "org.example:example-api::fc45c739",
								Name:         "org.example:example-api",
								Relationship: types.RelationshipDirect,
								Locations: []types.Location{
									{
										StartLine: 21,
										EndLine:   25,
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name:      "sad path",
			inputFile: "testdata/broken/pom.xml",
			wantErr:   "xml decode error",
		},
		{
			name:      "sad dir path",
			inputDir:  "testdata/broken",
			inputFile: "pom.xml",
			wantErr:   "xml decode error",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := os.Open(filepath.Join(tt.inputDir, tt.inputFile))
			require.NoError(t, err)
			defer f.Close()

			a := pomAnalyzer{}
			got, err := a.Analyze(t.Context(), analyzer.AnalysisInput{
				Dir:      tt.inputDir,
				FilePath: tt.inputFile,
				Content:  f,
				Options: analyzer.AnalysisOptions{
					Offline: true,
				},
			})
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_pomAnalyzer_Analyze_layer(t *testing.T) {
	// A file in an image layer comes with an empty Dir, and the working
	// directory of the scanning process holds a POM for the parent of app.
	t.Chdir(t.TempDir())
	parent := `<project>
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>parent</artifactId>
  <version>1.0.0</version>
  <packaging>pom</packaging>
  <licenses><license><name>License of the scanning host</name></license></licenses>
</project>`
	require.NoError(t, os.WriteFile("pom.xml", []byte(parent), 0o600))
	app := `<project>
  <modelVersion>4.0.0</modelVersion>
  <parent>
    <groupId>com.example</groupId>
    <artifactId>parent</artifactId>
    <version>1.0.0</version>
  </parent>
  <groupId>com.example</groupId>
  <artifactId>app</artifactId>
  <version>1.0.0</version>
</project>`

	a := pomAnalyzer{}
	got, err := a.Analyze(t.Context(), analyzer.AnalysisInput{
		FilePath: "app/pom.xml",
		Content:  strings.NewReader(app),
		Options: analyzer.AnalysisOptions{
			Offline: true,
		},
	})
	require.NoError(t, err)
	require.Len(t, got.Applications, 1)
	require.Len(t, got.Applications[0].Packages, 1)
	assert.Equal(t, "com.example:app", got.Applications[0].Packages[0].Name)
	assert.Empty(t, got.Applications[0].Packages[0].Licenses)
}

func Test_pomAnalyzer_Required(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
		want     bool
	}{
		{
			name:     "happy",
			filePath: "test/pom.xml",
			want:     true,
		},
		{
			name:     "no extension",
			filePath: "test/pom",
			want:     false,
		},
		{
			name:     "json",
			filePath: "test/pom.json",
			want:     false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := pomAnalyzer{}
			got := a.Required(tt.filePath, nil)
			assert.Equal(t, tt.want, got)
		})
	}
}
