package analyzer_test

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/mapfs"
)

// timeoutGroup holds slowAnalyzer, apart from the builtin analyzers.
const timeoutGroup analyzer.Group = "timeout"

const typeSlow analyzer.Type = "slow"

// slowAnalyzer is a post analyzer that runs out of time after one result.
type slowAnalyzer struct{}

func (slowAnalyzer) Type() analyzer.Type               { return typeSlow }
func (slowAnalyzer) Version() int                      { return 1 }
func (slowAnalyzer) Required(string, os.FileInfo) bool { return true }
func (slowAnalyzer) Group() analyzer.Group             { return timeoutGroup }
func (slowAnalyzer) PostAnalyze(context.Context, analyzer.PostAnalysisInput) (*analyzer.AnalysisResult, error) {
	res := &analyzer.AnalysisResult{
		Applications: []types.Application{{Type: types.Jar, FilePath: "a.jar"}},
	}
	return res, xerrors.Errorf("jar walk error: %w", context.DeadlineExceeded)
}

func init() {
	analyzer.RegisterPostAnalyzer(typeSlow, func(analyzer.AnalyzerOptions) (analyzer.PostAnalyzer, error) {
		return slowAnalyzer{}, nil
	})
}

func TestAnalyzerGroup_PostAnalyzeTimeout(t *testing.T) {
	a, err := analyzer.NewAnalyzerGroup(analyzer.AnalyzerOptions{Group: timeoutGroup})
	require.NoError(t, err)
	composite, err := analyzer.NewCompositeFS()
	require.NoError(t, err)
	mfs := mapfs.New()
	require.NoError(t, mfs.WriteVirtualFile("a.jar", nil, 0o644))
	composite.Set(typeSlow, mfs)

	result := new(analyzer.AnalysisResult)
	err = a.PostAnalyze(t.Context(), composite, result, analyzer.AnalysisOptions{})
	require.ErrorIs(t, err, context.DeadlineExceeded)
	require.ErrorContains(t, err, "slow post analysis timeout after 1 results")
	assert.Equal(t, []types.Application{{Type: types.Jar, FilePath: "a.jar"}}, result.Applications)
}
