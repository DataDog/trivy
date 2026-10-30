package mod

import (
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/internal/testutil"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func Test_gomodAnalyzer_Analyze(t *testing.T) {
	tests := []struct {
		name  string
		txtar string
		want  *analyzer.AnalysisResult
	}{
		{
			name:  "happy",
			txtar: "testdata/happy.txtar",
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.GoModule,
						FilePath: "go.mod",
						Packages: types.Packages{
							{
								ID:           "github.com/org/repo",
								Name:         "github.com/org/repo",
								Relationship: types.RelationshipRoot,
								DependsOn: []string{
									"github.com/aquasecurity/go-dep-parser@v0.0.0-20220406074731-71021a481237",
									"golang.org/x/xerrors@v0.0.0-20200804184101-5ec99f83aff1", // No parent found, so it's added here.
								},
								ExternalReferences: []types.ExternalRef{
									{
										Type: types.RefVCS,
										URL:  "https://github.com/org/repo",
									},
								},
							},
							{
								ID:           "github.com/aquasecurity/go-dep-parser@v0.0.0-20220406074731-71021a481237",
								Name:         "github.com/aquasecurity/go-dep-parser",
								Version:      "v0.0.0-20220406074731-71021a481237",
								Relationship: types.RelationshipDirect,
								ExternalReferences: []types.ExternalRef{
									{
										Type: types.RefVCS,
										URL:  "https://github.com/aquasecurity/go-dep-parser",
									},
								},
							},
							{
								ID:           "golang.org/x/xerrors@v0.0.0-20200804184101-5ec99f83aff1",
								Name:         "golang.org/x/xerrors",
								Version:      "v0.0.0-20200804184101-5ec99f83aff1",
								Relationship: types.RelationshipIndirect,
								Indirect:     true,
							},
						},
					},
				},
			},
		},
		{
			name:  "less than 1.17",
			txtar: "testdata/merge.txtar",
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.GoModule,
						FilePath: "go.mod",
						Packages: types.Packages{
							{
								ID:           "github.com/org/repo",
								Name:         "github.com/org/repo",
								Relationship: types.RelationshipRoot,
								DependsOn: []string{
									"github.com/aquasecurity/go-dep-parser@v0.0.0-20230219131432-590b1dfb6edd",
									"github.com/BurntSushi/toml@v0.3.1",
								},
								ExternalReferences: []types.ExternalRef{
									{
										Type: types.RefVCS,
										URL:  "https://github.com/org/repo",
									},
								},
							},
							{
								ID:           "github.com/aquasecurity/go-dep-parser@v0.0.0-20230219131432-590b1dfb6edd",
								Name:         "github.com/aquasecurity/go-dep-parser",
								Version:      "v0.0.0-20230219131432-590b1dfb6edd",
								Relationship: types.RelationshipDirect,
								ExternalReferences: []types.ExternalRef{
									{
										Type: types.RefVCS,
										URL:  "https://github.com/aquasecurity/go-dep-parser",
									},
								},
							},
							{
								ID:           "github.com/BurntSushi/toml@v0.3.1",
								Name:         "github.com/BurntSushi/toml",
								Version:      "v0.3.1",
								Relationship: types.RelationshipIndirect,
								Indirect:     true,
							},
						},
					},
				},
			},
		},
		{
			name:  "no go.sum",
			txtar: "testdata/no-go-sum.txtar",
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.GoModule,
						FilePath: "go.mod",
						Packages: types.Packages{
							{
								ID:           "github.com/org/repo",
								Name:         "github.com/org/repo",
								Relationship: types.RelationshipRoot,
								DependsOn: []string{
									"github.com/aquasecurity/go-dep-parser@v0.0.0-20230219131432-590b1dfb6edd",
								},
								ExternalReferences: []types.ExternalRef{
									{
										Type: types.RefVCS,
										URL:  "https://github.com/org/repo",
									},
								},
							},
							{
								ID:           "github.com/aquasecurity/go-dep-parser@v0.0.0-20230219131432-590b1dfb6edd",
								Name:         "github.com/aquasecurity/go-dep-parser",
								Version:      "v0.0.0-20230219131432-590b1dfb6edd",
								Relationship: types.RelationshipDirect,
								ExternalReferences: []types.ExternalRef{
									{
										Type: types.RefVCS,
										URL:  "https://github.com/aquasecurity/go-dep-parser",
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name:  "sad go.mod",
			txtar: "testdata/sad.txtar",
			want:  &analyzer.AnalysisResult{},
		},
		{
			name:  "vendor dir",
			txtar: "testdata/vendor-dir-exists.txtar",
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.GoModule,
						FilePath: "go.mod",
						Packages: types.Packages{
							{
								ID:           "github.com/org/repo",
								Name:         "github.com/org/repo",
								Relationship: types.RelationshipRoot,
								DependsOn: []string{
									"github.com/aquasecurity/go-dep-parser@v0.0.1",
									"golang.org/x/xerrors@v0.0.0-20200804184101-5ec99f83aff1",
								},
								ExternalReferences: []types.ExternalRef{
									{
										Type: types.RefVCS,
										URL:  "https://github.com/org/repo",
									},
								},
							},
							{
								ID:           "github.com/aquasecurity/go-dep-parser@v0.0.1",
								Name:         "github.com/aquasecurity/go-dep-parser",
								Version:      "v0.0.1",
								Relationship: types.RelationshipDirect,
								ExternalReferences: []types.ExternalRef{
									{
										Type: types.RefVCS,
										URL:  "https://github.com/aquasecurity/go-dep-parser",
									},
								},
							},
							{
								ID:           "golang.org/x/xerrors@v0.0.0-20200804184101-5ec99f83aff1",
								Name:         "golang.org/x/xerrors",
								Version:      "v0.0.0-20200804184101-5ec99f83aff1",
								Relationship: types.RelationshipIndirect,
								Indirect:     true,
							},
						},
					},
				},
			},
		},
	}

	// The module cache of the scanning host has a go.mod for the
	// go-dep-parser that happy.txtar requires.
	gopath := t.TempDir()
	gomod := filepath.Join(gopath, "pkg", "mod", "github.com", "aquasecurity", "go-dep-parser@v0.0.0-20220406074731-71021a481237", "go.mod")
	require.NoError(t, os.MkdirAll(filepath.Dir(gomod), 0o755))
	require.NoError(t, os.WriteFile(gomod, []byte("module github.com/aquasecurity/go-dep-parser\n\nrequire golang.org/x/xerrors v0.0.0-20220907171357-04be3eba64a2\n"), 0o644))
	t.Setenv("GOPATH", gopath)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Load test case txtar as fs.FS
			fsys := testutil.TxtarToFS(t, tt.txtar)

			a, err := newGoModAnalyzer(analyzer.AnalyzerOptions{})
			require.NoError(t, err)

			ctx := t.Context()
			got, err := a.PostAnalyze(ctx, analyzer.PostAnalysisInput{
				FS: fsys,
			})
			require.NoError(t, err)

			if len(got.Applications) > 0 {
				sort.Sort(got.Applications[0].Packages)
				sort.Sort(tt.want.Applications[0].Packages)
			}
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_gomodAnalyzer_Required(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
		want     bool
	}{
		{
			name:     "go.mod",
			filePath: "test/go.mod",
			want:     true,
		},
		{
			name:     "go.sum",
			filePath: "test/foo/go.sum",
			want:     true,
		},
		{
			name:     "sad",
			filePath: "a/b/c/d/test.sum",
			want:     false,
		},
		{
			name:     "license in vendor",
			filePath: "test/vendor/github.com/aquasecurity/go-dep-parser/LICENSE",
			want:     false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := gomodAnalyzer{}
			got := a.Required(tt.filePath, nil)
			assert.Equal(t, tt.want, got)
		})
	}
}
