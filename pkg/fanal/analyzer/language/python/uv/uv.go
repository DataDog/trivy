package uv

import (
	"context"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"golang.org/x/xerrors"

	uvparser "github.com/aquasecurity/trivy/pkg/dependency/parser/python/uv"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/language"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/utils/fsutils"
)

func init() {
	analyzer.RegisterPostAnalyzer(analyzer.TypeUv, NewUvAnalyzer)
}

const version = 1

type uvAnalyzer struct {
	logger     *log.Logger
	lockParser language.Parser
}

func NewUvAnalyzer(_ analyzer.AnalyzerOptions) (analyzer.PostAnalyzer, error) {
	return &uvAnalyzer{
		logger:     log.WithPrefix("uv"),
		lockParser: uvparser.NewParser(),
	}, nil
}

func (a *uvAnalyzer) PostAnalyze(ctx context.Context, input analyzer.PostAnalysisInput) (*analyzer.AnalysisResult, error) {
	var apps []types.Application
	required := func(path string, d fs.DirEntry) bool {
		return filepath.Base(path) == types.UvLock
	}

	err := fsutils.WalkDir(ctx, input.FS, ".", required, input.Options.WalkErrCallback, func(path string, d fs.DirEntry, r io.Reader) error {
		// Parse uv.lock
		app, err := language.Parse(types.Uv, path, r, a.lockParser)
		if err != nil {
			a.logger.Warn("Failed to parse uv lockfile", log.Err(err))
			return nil
		} else if app == nil {
			return nil
		}

		apps = append(apps, *app)

		return nil
	})

	result := &analyzer.AnalysisResult{
		Applications: apps,
	}

	if err != nil {
		return result, xerrors.Errorf("walk error: %w", err)
	}

	return result, nil
}

func (a *uvAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	return filepath.Base(filePath) == types.UvLock
}

func (a *uvAnalyzer) Type() analyzer.Type {
	return analyzer.TypeUv
}

func (a *uvAnalyzer) Version() int {
	return version
}
