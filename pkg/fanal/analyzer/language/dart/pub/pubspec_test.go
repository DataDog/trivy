package pub

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func Test_pubSpecLockAnalyzer_Analyze(t *testing.T) {
	tests := []struct {
		name    string
		dir     string
		want    *analyzer.AnalysisResult
		wantErr assert.ErrorAssertionFunc
	}{
		{
			name: "happy path",
			dir:  "testdata/happy",
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.Pub,
						FilePath: "pubspec.lock",
						Packages: types.Packages{
							{
								ID:           "crypto@3.0.3",
								Name:         "crypto",
								Version:      "3.0.3",
								Relationship: types.RelationshipDirect,
							},
							{
								ID:           "meta@1.11.0",
								Name:         "meta",
								Version:      "1.11.0",
								Relationship: types.RelationshipDirect,
							},
							{
								ID:           "collection@1.17.0",
								Name:         "collection",
								Version:      "1.17.0",
								Indirect:     true,
								Relationship: types.RelationshipIndirect,
							},
							{
								ID:           "typed_data@1.3.2",
								Name:         "typed_data",
								Version:      "1.3.2",
								Indirect:     true,
								Relationship: types.RelationshipIndirect,
							},
						},
					},
				},
			},
			wantErr: assert.NoError,
		},
		{
			name:    "empty file",
			dir:     "testdata/empty",
			want:    &analyzer.AnalysisResult{},
			wantErr: assert.NoError,
		},
		{
			name:    "broken file",
			dir:     "testdata/broken",
			want:    &analyzer.AnalysisResult{},
			wantErr: assert.Error,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, err := newPubSpecLockAnalyzer(analyzer.AnalyzerOptions{})
			require.NoError(t, err)

			got, err := a.PostAnalyze(t.Context(), analyzer.PostAnalysisInput{
				FS: os.DirFS(tt.dir),
			})

			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_pubSpecLockAnalyzer_Analyze_cache(t *testing.T) {
	// The pub cache of the scanning host has a pubspec.yaml for crypto.
	cache := t.TempDir()
	pubspec := filepath.Join(cache, "hosted", "pub.dev", "crypto-3.0.3", "pubspec.yaml")
	require.NoError(t, os.MkdirAll(filepath.Dir(pubspec), 0o755))
	require.NoError(t, os.WriteFile(pubspec, []byte("name: crypto\nversion: 3.0.3\ndependencies:\n  typed_data: ^1.3.0\n"), 0o644))
	t.Setenv("PUB_CACHE", cache)

	a, err := newPubSpecLockAnalyzer(analyzer.AnalyzerOptions{})
	require.NoError(t, err)

	got, err := a.PostAnalyze(t.Context(), analyzer.PostAnalysisInput{
		FS: os.DirFS("testdata/happy"),
	})
	require.NoError(t, err)
	require.Len(t, got.Applications, 1)
	for _, pkg := range got.Applications[0].Packages {
		assert.Empty(t, pkg.DependsOn, pkg.ID)
	}
}

func Test_pubSpecLockAnalyzer_Required(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
		want     bool
	}{
		{
			name:     "happy path",
			filePath: "pubspec.lock",
			want:     true,
		},
		{
			name:     "sad path",
			filePath: "test.txt",
			want:     false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := pubSpecLockAnalyzer{}
			got := a.Required(tt.filePath, nil)
			assert.Equal(t, tt.want, got)
		})
	}
}
