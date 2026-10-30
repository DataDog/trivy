package pub

import (
	"context"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/dependency/parser/dart/pub"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/language"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/utils/fsutils"
)

func init() {
	analyzer.RegisterPostAnalyzer(analyzer.TypePubSpecLock, newPubSpecLockAnalyzer)
}

const version = 2

// pubSpecLockAnalyzer analyzes `pubspec.lock`
type pubSpecLockAnalyzer struct {
	parser language.Parser
}

func newPubSpecLockAnalyzer(opts analyzer.AnalyzerOptions) (analyzer.PostAnalyzer, error) {
	return pubSpecLockAnalyzer{
		parser: pub.NewParser(opts.DetectionPriority == types.PriorityComprehensive),
	}, nil
}

func (a pubSpecLockAnalyzer) PostAnalyze(ctx context.Context, input analyzer.PostAnalysisInput) (*analyzer.AnalysisResult, error) {
	var apps []types.Application

	required := func(_ string, _ fs.DirEntry) bool {
		// Parse all required files: `pubspec.lock` (from a.Required func) + input.FilePatterns.Match()
		return true
	}

	err := fsutils.WalkDir(ctx, input.FS, ".", required, input.Options.WalkErrCallback, func(path string, _ fs.DirEntry, r io.Reader) error {
		app, err := language.Parse(ctx, types.Pub, path, r, a.parser)
		if err != nil {
			return xerrors.Errorf("unable to parse %q: %w", path, err)
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
		return result, xerrors.Errorf("walk error: %w", err)
	}

	return result, nil
}

func (a pubSpecLockAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	return filepath.Base(filePath) == types.PubSpecLock
}

func (a pubSpecLockAnalyzer) Type() analyzer.Type {
	return analyzer.TypePubSpecLock
}

func (a pubSpecLockAnalyzer) Version() int {
	return version
}
