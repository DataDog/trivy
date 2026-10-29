package executable

import (
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func Test_executableAnalyzer_Analyze(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
		want     *analyzer.AnalysisResult
	}{
		{
			name:     "binary",
			filePath: "testdata/binary",
			want:     nil,
		},
		{
			name:     "text",
			filePath: "testdata/hello.txt",
			want:     nil,
		},
		{
			name:     "Python binary",
			filePath: "testdata/python2.7",
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.PythonExecutable,
						FilePath: "testdata/python2.7",
						Packages: types.Packages{
							{
								ID:       "python@2.7.18",
								Name:     "python",
								Version:  "2.7.18",
								FilePath: "testdata/python2.7",
							},
						},
					},
				},
			},
		},
		{
			name:     "Php Binary",
			filePath: "testdata/php",
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.PhpExecutable,
						FilePath: "testdata/php",
						Packages: types.Packages{
							{
								ID:       "php@8.0.7",
								Name:     "php",
								Version:  "8.0.7",
								FilePath: "testdata/php",
							},
						},
					},
				},
			},
		},
		{
			name:     "NodeJS Binary",
			filePath: "testdata/node",
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.NodeJsExecutable,
						FilePath: "testdata/node",
						Packages: types.Packages{
							{
								ID:       "node@12.16.3",
								Name:     "node",
								Version:  "12.16.3",
								FilePath: "testdata/node",
							},
						},
					},
				},
			},
		},
		{
			name:     "Java Binary",
			filePath: "testdata/java",
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.JavaExecutable,
						FilePath: "testdata/java",
						Packages: types.Packages{
							{
								ID:       "java@1.8.0_421-b09",
								Name:     "java",
								Version:  "1.8.0_421-b09",
								FilePath: "testdata/java",
							},
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := os.Open(tt.filePath)
			require.NoError(t, err)
			defer f.Close()

			stat, err := f.Stat()
			require.NoError(t, err)

			a := executableAnalyzer{}
			got, err := a.Analyze(t.Context(), analyzer.AnalysisInput{
				FilePath: tt.filePath,
				Content:  f,
				Info:     stat,
			})
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

// An artifact whose walk cannot keep a file, such as an image layer, hands
// the analyzer a copy under a temporary name.
func Test_executableAnalyzer_AnalyzeCopy(t *testing.T) {
	b, err := os.ReadFile("testdata/python2.7")
	require.NoError(t, err)
	tmp := filepath.Join(t.TempDir(), "analyzer-file-123")
	require.NoError(t, os.WriteFile(tmp, b, 0o600))
	f, err := os.Open(tmp)
	require.NoError(t, err)
	defer f.Close()
	stat, err := f.Stat()
	require.NoError(t, err)

	got, err := executableAnalyzer{}.Analyze(t.Context(), analyzer.AnalysisInput{
		FilePath: "usr/local/bin/python2.7",
		Content:  f,
		Info:     stat,
	})
	require.NoError(t, err)
	want := &analyzer.AnalysisResult{
		Applications: []types.Application{
			{
				Type:     types.PythonExecutable,
				FilePath: "usr/local/bin/python2.7",
				Packages: types.Packages{
					{
						ID:       "python@2.7.18",
						Name:     "python",
						Version:  "2.7.18",
						FilePath: "usr/local/bin/python2.7",
					},
				},
			},
		},
	}
	assert.Equal(t, want, got)
}

func Test_executableAnalyzer_Required(t *testing.T) {
	tests := []struct {
		filePath string
		mode     fs.FileMode
		want     bool
	}{
		{filePath: "usr/bin/python3.11", mode: 0o755, want: true},
		{filePath: "usr/lib/x86_64-linux-gnu/libpython3.11.so.1.0", mode: 0o755, want: true},
		{filePath: "usr/local/bin/node", mode: 0o755, want: true},
		{filePath: "usr/sbin/php-fpm", mode: 0o755, want: true},
		{filePath: "usr/lib/jvm/java-17/bin/java", mode: 0o755, want: true},
		{filePath: "usr/bin/ls", mode: 0o755, want: false},
		{filePath: "opt/app/lib/libtorch.so", mode: 0o755, want: false},
		{filePath: "usr/bin/python3", mode: 0o644, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.filePath, func(t *testing.T) {
			fsys := fstest.MapFS{tt.filePath: {Mode: tt.mode}}
			info, err := fsys.Stat(tt.filePath)
			require.NoError(t, err)
			got := executableAnalyzer{}.Required(tt.filePath, info)
			assert.Equal(t, tt.want, got)
		})
	}
}
