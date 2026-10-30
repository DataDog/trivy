package nuget

import (
	"context"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sort"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/dependency/parser/nuget/config"
	"github.com/aquasecurity/trivy/pkg/dependency/parser/nuget/lock"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/language"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/utils/fsutils"
)

func init() {
	analyzer.RegisterPostAnalyzer(analyzer.TypeNuget, newNugetLibraryAnalyzer)
}

const (
	version    = 3
	lockFile   = types.NuGetPkgsLock
	configFile = types.NuGetPkgsConfig
)

var requiredFiles = []string{
	lockFile,
	configFile,
}

type nugetLibraryAnalyzer struct {
	lockParser   language.Parser
	configParser language.Parser
}

func newNugetLibraryAnalyzer(_ analyzer.AnalyzerOptions) (analyzer.PostAnalyzer, error) {
	return &nugetLibraryAnalyzer{
		lockParser:   lock.NewParser(),
		configParser: config.NewParser(),
	}, nil
}

func (a *nugetLibraryAnalyzer) PostAnalyze(ctx context.Context, input analyzer.PostAnalysisInput) (*analyzer.AnalysisResult, error) {
	var apps []types.Application

	required := func(_ string, _ fs.DirEntry) bool {
		// Parse all required files: `packages.lock.json`, `packages.config` (from a.Required func) + input.FilePatterns.Match()
		return true
	}

	err := fsutils.WalkDir(ctx, input.FS, ".", required, input.Options.WalkErrCallback, func(path string, _ fs.DirEntry, r io.Reader) error {
		// Set the default parser
		parser := a.lockParser

		targetFile := filepath.Base(path)
		if targetFile == configFile {
			parser = a.configParser
		}

		app, err := language.Parse(ctx, types.NuGet, path, r, parser)
		if err != nil {
			return xerrors.Errorf("NuGet parse error: %w", err)
		}

		// nuget file doesn't contain dependencies
		if app == nil {
			return nil
		}

		sort.Sort(app.Packages)
		apps = append(apps, *app)
		return nil
	})
	result := &analyzer.AnalysisResult{
		Applications: apps,
	}
	if err != nil {
		return result, xerrors.Errorf("NuGet walk error: %w", err)
	}

	return result, nil
}

func (a *nugetLibraryAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	fileName := filepath.Base(filePath)
	return slices.Contains(requiredFiles, fileName)
}

func (a *nugetLibraryAnalyzer) Type() analyzer.Type {
	return analyzer.TypeNuget
}

func (a *nugetLibraryAnalyzer) Version() int {
	return version
}
