package pip

import (
	"context"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/dependency/parser/python/pip"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/language"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/utils/fsutils"
)

func init() {
	analyzer.RegisterPostAnalyzer(analyzer.TypePip, newPipLibraryAnalyzer)
}

const version = 1

type pipLibraryAnalyzer struct {
	detectionPriority types.DetectionPriority
}

func newPipLibraryAnalyzer(opts analyzer.AnalyzerOptions) (analyzer.PostAnalyzer, error) {
	return pipLibraryAnalyzer{
		detectionPriority: opts.DetectionPriority,
	}, nil
}

func (a pipLibraryAnalyzer) PostAnalyze(ctx context.Context, input analyzer.PostAnalysisInput) (*analyzer.AnalysisResult, error) {
	var apps []types.Application

	required := func(_ string, _ fs.DirEntry) bool {
		// Parse all required files: `conan.lock` (from a.Required func) + input.FilePatterns.Match()
		return true
	}

	useMinVersion := a.detectionPriority == types.PriorityComprehensive

	err := fsutils.WalkDir(ctx, input.FS, ".", required, input.Options.WalkErrCallback, func(pathPath string, _ fs.DirEntry, r io.Reader) error {
		app, err := language.Parse(ctx, types.Pip, pathPath, r, pip.NewParser(useMinVersion))
		if err != nil {
			return xerrors.Errorf("unable to parse requirements.txt: %w", err)
		}

		if app == nil {
			return nil
		}

		apps = append(apps, *app)
		return nil
	})
	result := &analyzer.AnalysisResult{
		Applications: apps,
	}
	if err != nil {
		return result, xerrors.Errorf("pip walt error: %w", err)
	}

	return result, nil
}

func (a pipLibraryAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	fileName := filepath.Base(filePath)
	return fileName == types.PipRequirements
}

func (a pipLibraryAnalyzer) Type() analyzer.Type {
	return analyzer.TypePip
}

func (a pipLibraryAnalyzer) Version() int {
	return version
}
