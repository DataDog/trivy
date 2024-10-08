package executable

import (
	"context"
	"os"
	"testing"

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
								ID:      "python@2.7.18",
								Name:    "python",
								Version: "2.7.18",
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
								ID:      "php@8.0.7",
								Name:    "php",
								Version: "8.0.7",
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
								ID:      "node@12.16.3",
								Name:    "node",
								Version: "12.16.3",
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
								ID:      "java@1.8.0_421-b09",
								Name:    "java",
								Version: "1.8.0_421-b09",
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
			got, err := a.Analyze(context.Background(), analyzer.AnalysisInput{
				FilePath: tt.filePath,
				Content:  f,
				Info:     stat,
			})
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
