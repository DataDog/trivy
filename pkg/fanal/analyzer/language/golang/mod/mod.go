package mod

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"

	"github.com/samber/lo"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/dependency/parser/golang/mod"
	"github.com/aquasecurity/trivy/pkg/dependency/parser/golang/sum"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/language"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/utils/fsutils"
	xio "github.com/aquasecurity/trivy/pkg/x/io"
)

func init() {
	analyzer.RegisterPostAnalyzer(analyzer.TypeGoMod, newGoModAnalyzer)
}

const version = 2

var requiredFiles = []string{
	types.GoMod,
	types.GoSum,
}

type gomodAnalyzer struct {
	// root go.mod/go.sum
	modParser language.Parser
	sumParser language.Parser

	logger *log.Logger
}

func newGoModAnalyzer(opt analyzer.AnalyzerOptions) (analyzer.PostAnalyzer, error) {
	return &gomodAnalyzer{
		modParser: mod.NewParser(true, opt.DetectionPriority == types.PriorityComprehensive),
		sumParser: sum.NewParser(),
		logger:    log.WithPrefix("golang"),
	}, nil
}

func (a *gomodAnalyzer) PostAnalyze(ctx context.Context, input analyzer.PostAnalysisInput) (*analyzer.AnalysisResult, error) {
	var apps []types.Application

	required := func(path string, _ fs.DirEntry) bool {
		return filepath.Base(path) == types.GoMod || input.FilePatterns.Match(path)
	}

	werr := fsutils.WalkDir(ctx, input.FS, ".", required, input.Options.WalkErrCallback, func(path string, _ fs.DirEntry, _ io.Reader) error {
		// Parse go.mod
		gomod, err := parse(ctx, input.FS, path, a.modParser)
		if err != nil {
			return xerrors.Errorf("parse error: %w", err)
		} else if gomod == nil {
			return nil
		}

		if lessThanGo117(gomod) {
			// e.g. /app/go.mod => /app/go.sum
			sumPath := filepath.Join(filepath.Dir(path), types.GoSum)
			gosum, err := parse(ctx, input.FS, sumPath, a.sumParser)
			if err != nil && !errors.Is(err, fs.ErrNotExist) {
				return xerrors.Errorf("parse error: %w", err)
			}
			mergeGoSum(gomod, gosum)
		}

		apps = append(apps, *gomod)
		return nil
	})

	// Add orphan indirect dependencies under the main module
	a.addOrphanIndirectDepsUnderRoot(apps)

	result := &analyzer.AnalysisResult{
		Applications: apps,
	}

	if werr != nil {
		return result, xerrors.Errorf("gomod walk error: %w", werr)
	}

	return result, nil
}

func (a *gomodAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	fileName := filepath.Base(filePath)

	// Save required files (go.mod/go.sum)
	// Note: vendor directory doesn't contain these files, so we can skip checking for this.
	// See: https://github.com/aquasecurity/trivy/issues/8527#issuecomment-2777848027
	return slices.Contains(requiredFiles, fileName)
}

func (a *gomodAnalyzer) Type() analyzer.Type {
	return analyzer.TypeGoMod
}

func (a *gomodAnalyzer) Version() int {
	return version
}

// addOrphanIndirectDepsUnderRoot adds the orphan indirect dependencies under
// the main module, so that every package appears in the dependency tree. The
// tree comes from the go.mod of the main module, which makes the main module
// the parent of its direct dependencies alone.
func (a *gomodAnalyzer) addOrphanIndirectDepsUnderRoot(apps []types.Application) {
	for _, app := range apps {
		// Find the main module
		_, rootIdx, found := lo.FindIndexOf(app.Packages, func(pkg types.Package) bool {
			return pkg.Relationship == types.RelationshipRoot
		})
		if !found {
			continue
		}

		// Collect all orphan indirect dependencies that are unable to identify parents
		parents := app.Packages.ParentDeps()
		orphanDeps := lo.FilterMap(app.Packages, func(pkg types.Package, _ int) (string, bool) {
			return pkg.ID, pkg.Relationship == types.RelationshipIndirect && len(parents[pkg.ID]) == 0
		})
		// Add orphan indirect dependencies under the main module
		app.Packages[rootIdx].DependsOn = append(app.Packages[rootIdx].DependsOn, orphanDeps...)
	}
}

func parse(ctx context.Context, fsys fs.FS, path string, parser language.Parser) (*types.Application, error) {
	f, err := fsys.Open(path)
	if err != nil {
		return nil, xerrors.Errorf("file open error: %w", err)
	}
	defer f.Close()

	file, ok := f.(xio.ReadSeekCloserAt)
	if !ok {
		return nil, xerrors.Errorf("type assertion error: %w", err)
	}

	// Parse go.mod or go.sum
	return language.Parse(ctx, types.GoModule, path, file, parser)
}

func lessThanGo117(gomod *types.Application) bool {
	for _, lib := range gomod.Packages {
		// The indirect field is populated only in Go 1.17+
		if lib.Relationship == types.RelationshipIndirect {
			return false
		}
	}
	return true
}

func mergeGoSum(gomod, gosum *types.Application) {
	if gomod == nil || gosum == nil {
		return
	}
	uniq := make(map[string]types.Package)
	for _, lib := range gomod.Packages {
		// It will be used for merging go.sum.
		uniq[lib.Name] = lib
	}

	// For Go 1.16 or less, we need to merge go.sum into go.mod.
	for _, lib := range gosum.Packages {
		// Skip dependencies in go.mod so that go.mod should be preferred.
		if _, ok := uniq[lib.Name]; ok {
			continue
		}

		// This dependency doesn't exist in go.mod, so it must be an indirect dependency.
		lib.Indirect = true
		lib.Relationship = types.RelationshipIndirect
		uniq[lib.Name] = lib
	}

	gomod.Packages = lo.Values(uniq)
}
