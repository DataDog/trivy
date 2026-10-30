package conan

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func Test_conanLockAnalyzer_Analyze(t *testing.T) {
	tests := []struct {
		name string
		dir  string
		want *analyzer.AnalysisResult
	}{
		{
			name: "happy path V1",
			dir:  "testdata/happy",
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.Conan,
						FilePath: "conan.lock",
						Packages: types.Packages{
							{
								ID:           "openssl/3.0.5",
								Name:         "openssl",
								Version:      "3.0.5",
								Relationship: types.RelationshipDirect,
								DependsOn: []string{
									"zlib/1.2.12",
								},
								Locations: []types.Location{
									{
										StartLine: 12,
										EndLine:   21,
									},
								},
							},
							{
								ID:           "zlib/1.2.12",
								Name:         "zlib",
								Version:      "1.2.12",
								Indirect:     true,
								Relationship: types.RelationshipIndirect,
								Locations: []types.Location{
									{
										StartLine: 22,
										EndLine:   28,
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name: "happy path V2",
			dir:  "testdata/happy_v2",
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.Conan,
						FilePath: "release.lock",
						Packages: types.Packages{
							{
								ID:           "openssl/3.2.2",
								Name:         "openssl",
								Version:      "3.2.2",
								Relationship: types.RelationshipUnknown,
								Locations: []types.Location{
									{
										StartLine: 5,
										EndLine:   5,
									},
								},
							},
							{
								ID:           "zlib/1.3.1",
								Name:         "zlib",
								Version:      "1.3.1",
								Relationship: types.RelationshipUnknown,
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
			name: "empty file",
			dir:  "testdata/empty",
			want: &analyzer.AnalysisResult{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, err := newConanLockAnalyzer(analyzer.AnalyzerOptions{})
			require.NoError(t, err)

			got, err := a.PostAnalyze(t.Context(), analyzer.PostAnalysisInput{
				FS: os.DirFS(tt.dir),
			})

			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}

func Test_conanLockAnalyzer_Analyze_cache(t *testing.T) {
	// The Conan cache of the scanning host has a conanfile.py for zlib.
	home := t.TempDir()
	conanfile := filepath.Join(home, "p", "zlib41bd3946e7341", "e", "conanfile.py")
	require.NoError(t, os.MkdirAll(filepath.Dir(conanfile), 0o755))
	require.NoError(t, os.WriteFile(conanfile, []byte("class ZlibConan(ConanFile):\n    name = \"zlib\"\n    license = \"Zlib\"\n"), 0o644))
	t.Setenv("CONAN_HOME", home)

	a, err := newConanLockAnalyzer(analyzer.AnalyzerOptions{})
	require.NoError(t, err)

	got, err := a.PostAnalyze(t.Context(), analyzer.PostAnalysisInput{
		FS: os.DirFS("testdata/happy"),
	})
	require.NoError(t, err)
	require.Len(t, got.Applications, 1)
	for _, pkg := range got.Applications[0].Packages {
		assert.Empty(t, pkg.Licenses, pkg.ID)
	}
}

func Test_conanLockAnalyzer_Required(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
		want     bool
	}{
		{
			name:     "default name",
			filePath: "conan.lock",
			want:     true,
		},
		{
			name:     "name with prefix",
			filePath: "pkga_deps.lock",
			want:     false,
		},
		{
			name:     "txt",
			filePath: "test.txt",
			want:     false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := conanLockAnalyzer{}
			got := a.Required(tt.filePath, nil)
			assert.Equal(t, tt.want, got)
		})
	}
}
