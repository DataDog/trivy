package conan

import (
	"context"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/dependency/parser/c/conan"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/language"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/utils/fsutils"
)

func init() {
	analyzer.RegisterPostAnalyzer(analyzer.TypeConanLock, newConanLockAnalyzer)
}

const (
	version = 2
)

// conanLockAnalyzer analyzes conan.lock
type conanLockAnalyzer struct {
	parser language.Parser
}

func newConanLockAnalyzer(_ analyzer.AnalyzerOptions) (analyzer.PostAnalyzer, error) {
	return conanLockAnalyzer{
		parser: conan.NewParser(),
	}, nil
}

func (a conanLockAnalyzer) PostAnalyze(ctx context.Context, input analyzer.PostAnalysisInput) (*analyzer.AnalysisResult, error) {
	required := func(_ string, _ fs.DirEntry) bool {
		// Parse all required files: `conan.lock` (from a.Required func) + input.FilePatterns.Match()
		return true
	}

	var apps []types.Application
	err := fsutils.WalkDir(ctx, input.FS, ".", required, input.Options.WalkErrCallback, func(filePath string, _ fs.DirEntry, r io.Reader) error {
		app, err := language.Parse(ctx, types.Conan, filePath, r, a.parser)
		if err != nil {
			return xerrors.Errorf("%s parse error: %w", filePath, err)
		}

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
		return nil, xerrors.Errorf("unable to parse conan lock file: %w", err)
	}

	return result, nil
}

func (a conanLockAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	// Lock file name can be anything
	// cf. https://docs.conan.io/1/versioning/lockfiles/introduction.html#locking-dependencies
	// By default, we only check the default filename - `conan.lock`.
	return filepath.Base(filePath) == types.ConanLock
}

func (a conanLockAnalyzer) Type() analyzer.Type {
	return analyzer.TypeConanLock
}

func (a conanLockAnalyzer) Version() int {
	return version
}
