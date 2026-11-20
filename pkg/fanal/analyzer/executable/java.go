package executable

import (
	"context"
	"io/fs"
	"os"
	"path"
	"strings"

	"golang.org/x/xerrors"

	javaparser "github.com/aquasecurity/trivy/pkg/dependency/parser/executable/java"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/language"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/fanal/utils"
	"github.com/aquasecurity/trivy/pkg/parallel"
	xio "github.com/aquasecurity/trivy/pkg/x/io"
)

func init() {
	analyzer.RegisterPostAnalyzer(analyzer.TypeJavaRuntime, newJavaRuntimeAnalyzer)
}

const (
	javaRuntimeVersion = 2

	// maxReleaseSize bounds the release files the analyzer takes. Those
	// of JDK builds hold 0.5 to 1.6 KB.
	maxReleaseSize = 64 << 10
)

// javaRuntimeAnalyzer reports the version of each java launcher and the
// vendor that the release file of its Java home names.
type javaRuntimeAnalyzer struct {
	parallel int
}

func newJavaRuntimeAnalyzer(opts analyzer.AnalyzerOptions) (analyzer.PostAnalyzer, error) {
	return &javaRuntimeAnalyzer{parallel: opts.Parallel}, nil
}

func (a *javaRuntimeAnalyzer) PostAnalyze(ctx context.Context, input analyzer.PostAnalysisInput) (*analyzer.AnalysisResult, error) {
	onFile := func(filePath string, _ fs.FileInfo, r xio.ReadSeekerAt) (*types.Application, error) {
		if path.Base(filePath) != "java" {
			return nil, nil
		}
		app, err := language.ParsePackage(ctx, types.JavaExecutable, filePath, r, javaparser.NewParser(), false)
		if err != nil || app == nil {
			return app, err
		}
		vendor := implementor(input.FS, filePath)
		for i := range app.Packages {
			app.Packages[i].Maintainer = vendor
		}
		return app, nil
	}

	var apps []types.Application
	onResult := func(app *types.Application) error {
		if app != nil {
			apps = append(apps, *app)
		}
		return nil
	}

	err := parallel.WalkDir(ctx, input.FS, ".", a.parallel, onFile, onResult)
	result := &analyzer.AnalysisResult{Applications: apps}
	if err != nil {
		return result, xerrors.Errorf("java runtime walk error: %w", err)
	}
	return result, nil
}

// implementor returns the IMPLEMENTOR of the release file of the Java home
// of launcher: the directory above bin, or above jre in a JDK 8.
func implementor(fsys fs.FS, launcher string) string {
	home := path.Dir(path.Dir(launcher))
	b, err := fs.ReadFile(fsys, path.Join(home, "release"))
	if err != nil && path.Base(home) == "jre" {
		b, err = fs.ReadFile(fsys, path.Join(path.Dir(home), "release"))
	}
	if err != nil {
		return ""
	}
	for line := range strings.Lines(string(b)) {
		if v, ok := strings.CutPrefix(line, "IMPLEMENTOR="); ok {
			return strings.Trim(strings.TrimSpace(v), `"`)
		}
	}
	return ""
}

func (a *javaRuntimeAnalyzer) Required(filePath string, info os.FileInfo) bool {
	switch path.Base(filePath) {
	case "java":
		return utils.IsExecutable(info)
	case "release":
		return info.Size() <= maxReleaseSize
	}
	return false
}

func (a *javaRuntimeAnalyzer) Type() analyzer.Type {
	return analyzer.TypeJavaRuntime
}

func (a *javaRuntimeAnalyzer) Version() int {
	return javaRuntimeVersion
}
