package executable

import (
	"io/fs"
	"os"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func Test_javaRuntimeAnalyzer_PostAnalyze(t *testing.T) {
	app := func(filePath, version, vendor string) types.Application {
		return types.Application{
			Type:     types.JavaExecutable,
			FilePath: filePath,
			Packages: types.Packages{
				{
					ID:         "java@" + version,
					Name:       "java",
					Version:    version,
					Maintainer: vendor,
					FilePath:   filePath,
				},
			},
		}
	}
	// Corretto 8 ships no release file.
	want := []types.Application{
		app("jdk-21.0.4+7/bin/java", "21.0.4+7-LTS", "Eclipse Adoptium"),
		app("jdk8u514-b01/bin/java", "1.8.0_514-b01", "Eclipse Adoptium"),
		app("jdk8u514-b01/jre/bin/java", "1.8.0_514-b01", "Eclipse Adoptium"),
		app("amazon-corretto-8.514.01.1-linux-x64/bin/java", "1.8.0_514-b01", ""),
	}

	a, err := newJavaRuntimeAnalyzer(analyzer.AnalyzerOptions{})
	require.NoError(t, err)
	got, err := a.PostAnalyze(t.Context(), analyzer.PostAnalysisInput{
		FS: os.DirFS("testdata/jdk"),
	})
	require.NoError(t, err)
	assert.ElementsMatch(t, want, got.Applications)
}

func Test_javaRuntimeAnalyzer_Required(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
		mode     fs.FileMode
		size     int
		want     bool
	}{
		{name: "launcher", filePath: "usr/lib/jvm/java-17/bin/java", mode: 0o755, want: true},
		{name: "not executable", filePath: "usr/lib/jvm/java-17/bin/java", mode: 0o644, want: false},
		{name: "release", filePath: "usr/lib/jvm/java-17/release", mode: 0o644, size: 1610, want: true},
		{name: "large release", filePath: "usr/lib/jvm/java-17/release", mode: 0o644, size: maxReleaseSize + 1, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fsys := fstest.MapFS{tt.filePath: {Mode: tt.mode, Data: make([]byte, tt.size)}}
			info, err := fsys.Stat(tt.filePath)
			require.NoError(t, err)
			a := &javaRuntimeAnalyzer{}
			assert.Equal(t, tt.want, a.Required(tt.filePath, info))
		})
	}
}
