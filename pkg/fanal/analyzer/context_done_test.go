package analyzer_test

import (
	"context"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/mapfs"
)

// doneGroup holds the recorders, apart from the builtin analyzers.
const doneGroup analyzer.Group = "context-done"

const typeRecorder analyzer.Type = "recorder"

// calls counts the analyses the recorders ran.
var calls atomic.Int64

// postRecorder is a post analyzer that counts its runs.
type postRecorder struct{}

func (postRecorder) Type() analyzer.Type               { return typeRecorder }
func (postRecorder) Version() int                      { return 1 }
func (postRecorder) Required(string, os.FileInfo) bool { return true }
func (postRecorder) Group() analyzer.Group             { return doneGroup }
func (postRecorder) PostAnalyze(context.Context, analyzer.PostAnalysisInput) (*analyzer.AnalysisResult, error) {
	calls.Add(1)
	return nil, nil
}

// fileRecorder is a deferred per-file analyzer that counts its runs. It
// takes a language type, as only those are deferred.
type fileRecorder struct{}

func (fileRecorder) Type() analyzer.Type               { return analyzer.TypeCocoaPods }
func (fileRecorder) Version() int                      { return 1 }
func (fileRecorder) Required(string, os.FileInfo) bool { return true }
func (fileRecorder) Group() analyzer.Group             { return doneGroup }
func (fileRecorder) Analyze(context.Context, analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	calls.Add(1)
	return nil, nil
}

func init() {
	analyzer.RegisterPostAnalyzer(typeRecorder, func(analyzer.AnalyzerOptions) (analyzer.PostAnalyzer, error) {
		return postRecorder{}, nil
	})
	analyzer.RegisterAnalyzer(fileRecorder{})
}

func TestAnalyzerGroup_ContextDone(t *testing.T) {
	a, err := analyzer.NewAnalyzerGroup(analyzer.AnalyzerOptions{
		Group:                     doneGroup,
		DeferApplicationAnalyzers: true,
	})
	require.NoError(t, err)
	composite, err := analyzer.NewCompositeFS()
	require.NoError(t, err)
	mfs := mapfs.New()
	require.NoError(t, mfs.WriteVirtualFile("Podfile.lock", []byte("PODS:\n"), 0o644))
	composite.Set(typeRecorder, mfs)
	composite.Set(analyzer.TypeCocoaPods, mfs)

	ctx, cancel := context.WithDeadline(t.Context(), time.Now().Add(-time.Second))
	defer cancel()
	calls.Store(0)
	result := new(analyzer.AnalysisResult)
	err = a.PostAnalyze(ctx, composite, result, analyzer.AnalysisOptions{})
	require.ErrorIs(t, err, context.DeadlineExceeded)
	err = a.DeferredAnalyze(ctx, composite, result, analyzer.AnalysisOptions{})
	require.ErrorIs(t, err, context.DeadlineExceeded)
	assert.Zero(t, calls.Load(), "analyses run after the deadline")
}
