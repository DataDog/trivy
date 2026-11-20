package executable

import (
	"context"
	"io/fs"
	"os"
	"path"

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

const javaRuntimeVersion = 1

// javaRuntimeAnalyzer reports the version of each java launcher.
type javaRuntimeAnalyzer struct {
	parallel int
}

func newJavaRuntimeAnalyzer(opts analyzer.AnalyzerOptions) (analyzer.PostAnalyzer, error) {
	return &javaRuntimeAnalyzer{parallel: opts.Parallel}, nil
}

func (a *javaRuntimeAnalyzer) PostAnalyze(ctx context.Context, input analyzer.PostAnalysisInput) (*analyzer.AnalysisResult, error) {
	onFile := func(filePath string, _ fs.FileInfo, r xio.ReadSeekerAt) (*types.Application, error) {
		return language.ParsePackage(ctx, types.JavaExecutable, filePath, r, javaparser.NewParser(), false)
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

func (a *javaRuntimeAnalyzer) Required(filePath string, info os.FileInfo) bool {
	return path.Base(filePath) == "java" && utils.IsExecutable(info)
}

func (a *javaRuntimeAnalyzer) Type() analyzer.Type {
	return analyzer.TypeJavaRuntime
}

func (a *javaRuntimeAnalyzer) Version() int {
	return javaRuntimeVersion
}
