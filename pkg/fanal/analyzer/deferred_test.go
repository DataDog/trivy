package analyzer_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

// passGroup holds the readers, apart from the builtin analyzers.
const passGroup analyzer.Group = "deferred-pass"

// reader is a deferred analyzer that reads the first 64 bytes of each file,
// as the binary analyzers read headers. It reports the files under report/
// as applications.
type reader struct {
	typ analyzer.Type

	// mu guards read, dir and content.
	mu      sync.Mutex
	read    map[string]int           // bytes read, by path
	dir     map[string]string        // input.Dir, by path
	content map[string]io.ReadSeeker // input.Content, by path
}

func (r *reader) Type() analyzer.Type               { return r.typ }
func (r *reader) Version() int                      { return 1 }
func (r *reader) Required(string, os.FileInfo) bool { return true }
func (r *reader) Group() analyzer.Group             { return passGroup }
func (r *reader) Analyze(_ context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	var b [64]byte
	n, err := io.ReadFull(input.Content, b[:])
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) {
		return nil, err
	}
	r.mu.Lock()
	r.read[input.FilePath] += n
	r.dir[input.FilePath] = input.Dir
	r.content[input.FilePath] = input.Content
	r.mu.Unlock()
	if filepath.Dir(input.FilePath) != "report" {
		return nil, nil
	}
	return &analyzer.AnalysisResult{
		Applications: []types.Application{{Type: types.LangType(r.typ), FilePath: input.FilePath}},
	}, nil
}

func (r *reader) reset() {
	r.mu.Lock()
	r.read = make(map[string]int)
	r.dir = make(map[string]string)
	r.content = make(map[string]io.ReadSeeker)
	r.mu.Unlock()
}

// The readers take language types, as only those are deferred. They run in
// the order of their types.
var (
	firstReader  = &reader{typ: analyzer.TypeMixLock}
	secondReader = &reader{typ: analyzer.TypeSwift}
)

func init() {
	analyzer.RegisterAnalyzer(firstReader)
	analyzer.RegisterAnalyzer(secondReader)
}

// linkFiles writes the files under a temp dir and links them for both
// readers.
func linkFiles(t testing.TB, files map[string]string) *analyzer.CompositeFS {
	root := t.TempDir()
	composite, err := analyzer.NewCompositeFS()
	require.NoError(t, err)
	t.Cleanup(func() { _ = composite.Cleanup() })
	for p, content := range files {
		name := filepath.Join(root, filepath.FromSlash(p))
		require.NoError(t, os.MkdirAll(filepath.Dir(name), 0o700))
		require.NoError(t, os.WriteFile(name, []byte(content), 0o600))
		require.NoError(t, composite.CreateLink([]analyzer.Type{firstReader.typ, secondReader.typ}, root, p, name))
	}
	return composite
}

func TestAnalyzerGroup_DeferredAnalyzeOneFile(t *testing.T) {
	a, err := analyzer.NewAnalyzerGroup(analyzer.AnalyzerOptions{
		Group:                     passGroup,
		DeferApplicationAnalyzers: true,
		Parallel:                  2,
	})
	require.NoError(t, err)
	composite := linkFiles(t, map[string]string{
		"lib/a.so":  "hello",
		"report/b":  "world!",
		"lib/c.bin": "0123456789",
	})

	firstReader.reset()
	secondReader.reset()
	result := new(analyzer.AnalysisResult)
	require.NoError(t, a.DeferredAnalyze(t.Context(), composite, result, analyzer.AnalysisOptions{}))

	// Both readers read each file from its start, from one open, and the
	// second one skips the file the first one reported.
	assert.Equal(t, map[string]int{"lib/a.so": 5, "lib/c.bin": 10, "report/b": 6}, firstReader.read)
	assert.Equal(t, map[string]int{"lib/a.so": 5, "lib/c.bin": 10}, secondReader.read)
	for _, p := range []string{"lib/a.so", "lib/c.bin"} {
		assert.Same(t, firstReader.content[p], secondReader.content[p], p)
	}
	assert.Equal(t, []types.Application{{Type: types.LangType(firstReader.typ), FilePath: "report/b"}}, result.Applications)
}

func TestAnalyzerGroup_DeferredAnalyzeRoots(t *testing.T) {
	a, err := analyzer.NewAnalyzerGroup(analyzer.AnalyzerOptions{
		Group:                     passGroup,
		DeferApplicationAnalyzers: true,
	})
	require.NoError(t, err)

	// Each reader has lib/a.so under a root of its own.
	composite, err := analyzer.NewCompositeFS()
	require.NoError(t, err)
	t.Cleanup(func() { _ = composite.Cleanup() })
	roots := make(map[analyzer.Type]string)
	for _, r := range []*reader{firstReader, secondReader} {
		root := t.TempDir()
		name := filepath.Join(root, "lib", "a.so")
		require.NoError(t, os.MkdirAll(filepath.Dir(name), 0o700))
		require.NoError(t, os.WriteFile(name, []byte(r.typ), 0o600))
		require.NoError(t, composite.CreateLink([]analyzer.Type{r.typ}, root, "lib/a.so", name))
		roots[r.typ] = root
	}

	firstReader.reset()
	secondReader.reset()
	require.NoError(t, a.DeferredAnalyze(t.Context(), composite, new(analyzer.AnalysisResult), analyzer.AnalysisOptions{}))
	for _, r := range []*reader{firstReader, secondReader} {
		assert.Equal(t, map[string]string{"lib/a.so": roots[r.typ]}, r.dir, r.typ)
		assert.Equal(t, map[string]int{"lib/a.so": len(r.typ)}, r.read, r.typ)
	}
}

// BenchmarkAnalyzerGroup_DeferredAnalyze runs two deferred analyzers on
// 2,000 files, as gobinary and rustbinary run on executables.
func BenchmarkAnalyzerGroup_DeferredAnalyze(b *testing.B) {
	a, err := analyzer.NewAnalyzerGroup(analyzer.AnalyzerOptions{
		Group:                     passGroup,
		DeferApplicationAnalyzers: true,
		Parallel:                  1,
	})
	require.NoError(b, err)
	files := make(map[string]string)
	content := string(make([]byte, 4096))
	for i := range 2000 {
		files[fmt.Sprintf("lib/pkg%d/lib%d.so", i/100, i)] = content
	}
	composite := linkFiles(b, files)
	b.ReportAllocs()
	for b.Loop() {
		firstReader.reset()
		secondReader.reset()
		if err := a.DeferredAnalyze(b.Context(), composite, new(analyzer.AnalysisResult), analyzer.AnalysisOptions{}); err != nil {
			b.Fatal(err)
		}
	}
}
