package gradle

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

const junitPOM = `<project>
  <groupId>junit</groupId>
  <artifactId>junit</artifactId>
  <version>4.13</version>
  <licenses>
    <license>
      <name>Eclipse Public License 1.0</name>
    </license>
  </licenses>
  <dependencies>
    <dependency>
      <groupId>org.hamcrest</groupId>
      <artifactId>hamcrest-core</artifactId>
      <version>1.3</version>
    </dependency>
  </dependencies>
</project>
`

func Test_gradleLockAnalyzer_Analyze(t *testing.T) {
	tests := []struct {
		name string
		dir  string
		want *analyzer.AnalysisResult
	}{
		{
			name: "happy path",
			dir:  "testdata/lockfiles/happy",
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.Gradle,
						FilePath: "gradle.lockfile",
						Packages: types.Packages{
							{
								ID:           "junit:junit:4.13",
								Name:         "junit:junit",
								Version:      "4.13",
								Relationship: types.RelationshipUnknown,
								Locations: []types.Location{
									{
										StartLine: 4,
										EndLine:   4,
									},
								},
							},
							{
								ID:           "org.hamcrest:hamcrest-core:1.3",
								Name:         "org.hamcrest:hamcrest-core",
								Version:      "1.3",
								Relationship: types.RelationshipUnknown,
								Locations: []types.Location{
									{
										StartLine: 5,
										EndLine:   5,
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
			dir:  "testdata/lockfiles/empty",
			want: &analyzer.AnalysisResult{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// The Gradle cache of the scanning user holds a pom for junit
			// with a license and a dependency.
			home := t.TempDir()
			pom := filepath.Join(home, ".gradle", "caches", "modules-2", "files-2.1", "junit", "junit", "4.13",
				"5c17760663fae422643fc859fd352c68a1d91bfc", "junit-4.13.pom")
			require.NoError(t, os.MkdirAll(filepath.Dir(pom), 0o755))
			require.NoError(t, os.WriteFile(pom, []byte(junitPOM), 0o644))
			t.Setenv("HOME", home)
			t.Setenv("GRADLE_USER_HOME", "")

			a, err := newGradleLockAnalyzer(analyzer.AnalyzerOptions{})
			require.NoError(t, err)

			got, err := a.PostAnalyze(t.Context(), analyzer.PostAnalysisInput{
				FS: os.DirFS(tt.dir),
			})

			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_nugetLibraryAnalyzer_Required(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
		want     bool
	}{
		{
			name:     "default name",
			filePath: "test/gradle.lockfile",
			want:     true,
		},
		{
			name:     "name with prefix",
			filePath: "test/settings-gradle.lockfile",
			want:     true,
		},
		{
			name:     "txt",
			filePath: "test/test.txt",
			want:     false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := gradleLockAnalyzer{}
			got := a.Required(tt.filePath, nil)
			assert.Equal(t, tt.want, got)
		})
	}
}
