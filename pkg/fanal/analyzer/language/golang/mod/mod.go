package mod

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"unicode"

	"github.com/samber/lo"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/dependency/parser/golang/mod"
	"github.com/aquasecurity/trivy/pkg/dependency/parser/golang/sum"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/language"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/licensing"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/utils/fsutils"
	xio "github.com/aquasecurity/trivy/pkg/x/io"
	xpath "github.com/aquasecurity/trivy/pkg/x/path"
)

func init() {
	analyzer.RegisterPostAnalyzer(analyzer.TypeGoMod, newGoModAnalyzer)
}

const version = 2

var (
	requiredFiles = []string{
		types.GoMod,
		types.GoSum,
	}
	licenseRegexp = regexp.MustCompile(`^(?i)((UN)?LICEN(S|C)E|COPYING|README|NOTICE).*$`)
)

type gomodAnalyzer struct {
	// root go.mod/go.sum
	modParser language.Parser
	sumParser language.Parser

	licenseClassifierConfidenceLevel float64

	logger *log.Logger
}

func newGoModAnalyzer(opt analyzer.AnalyzerOptions) (analyzer.PostAnalyzer, error) {
	return &gomodAnalyzer{
		modParser:                        mod.NewParser(true, opt.DetectionPriority == types.PriorityComprehensive),
		sumParser:                        sum.NewParser(),
		licenseClassifierConfidenceLevel: opt.LicenseScannerOption.ClassifierConfidenceLevel,
		logger:                           log.WithPrefix("golang"),
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

	if err := a.fillAdditionalData(input.FS, apps); err != nil {
		a.logger.Warn("Unable to collect additional info", log.Err(err))
	}

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
	if slices.Contains(requiredFiles, fileName) {
		return true
	}

	// Save license files from vendor directory
	if licenseRegexp.MatchString(fileName) && xpath.Contains(filePath, "vendor") {
		return true
	}

	return false
}

func (a *gomodAnalyzer) Type() analyzer.Type {
	return analyzer.TypeGoMod
}

func (a *gomodAnalyzer) Version() int {
	return version
}

// fillAdditionalData collects licenses from the vendor directory next to each
// go.mod, then updates applications.
func (a *gomodAnalyzer) fillAdditionalData(fsys fs.FS, apps []types.Application) error {
	licenses := make(map[string][]string)
	for i, app := range apps {
		// vendor directory next to go.mod
		vendorDir, err := newVendorDir(fsys, app.FilePath)
		if err != nil {
			continue
		}

		for j, pkg := range app.Packages {
			licenseNames, err := findLicense(vendorDir, pkg, licenses, a.licenseClassifierConfidenceLevel)
			if err != nil {
				return xerrors.Errorf("unable to collect license: %w", err)
			}
			apps[i].Packages[j].Licenses = licenseNames
		}
	}
	return nil
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

func findLicense(vendor vendorDir, pkg types.Package, licenses map[string][]string, classifierConfidenceLevel float64) ([]string, error) {
	if licenses[pkg.ID] != nil {
		return licenses[pkg.ID], nil
	}

	sub, err := vendor.Resolve(pkg)
	if err != nil {
		return nil, nil
	}

	var license *types.LicenseFile
	err = fs.WalkDir(sub, ".", func(path string, d fs.DirEntry, err error) error {
		switch {
		case err != nil:
			return err
		case !d.Type().IsRegular():
			return nil
		case !licenseRegexp.MatchString(filepath.Base(path)):
			return nil
		}

		// e.g. vendor/github.com/aquasecurity/go-dep-parser/LICENSE
		f, err := sub.Open(path)
		if err != nil {
			return xerrors.Errorf("file (%s) open error: %w", path, err)
		}
		defer f.Close()

		if l, err := licensing.Classify(path, f, classifierConfidenceLevel); err != nil {
			return xerrors.Errorf("license classify error: %w", err)
		} else if l != nil && len(l.Findings) > 0 { // License found
			license = l
			return fs.SkipAll // Stop walking
		}
		return nil
	})

	switch {
	// The module path may not exist
	case errors.Is(err, os.ErrNotExist):
		return nil, nil
	case err != nil && !errors.Is(err, io.EOF):
		return nil, xerrors.Errorf("unable to find a known open source license: %w", err)
	case license == nil || len(license.Findings) == 0:
		return nil, nil
	}

	// License found
	licenseNames := license.Findings.Names()
	licenses[pkg.ID] = licenseNames
	return licenseNames, nil
}

// normalizeModName escapes upper characters
// e.g. 'github.com/BurntSushi/toml' => 'github.com/!burnt!sushi'
func normalizeModName(name string) string {
	var newName []rune
	for _, c := range name {
		if unicode.IsUpper(c) {
			// 'A' => '!a'
			newName = append(newName, '!', unicode.ToLower(c))
		} else {
			newName = append(newName, c)
		}
	}
	return string(newName)
}

type vendorDir struct {
	root fs.FS
}

func newVendorDir(fsys fs.FS, modPath string) (vendorDir, error) {
	// vendor directory is in the same directory as go.mod
	vendor := filepath.Join(filepath.Dir(modPath), "vendor")
	sub, err := fs.Sub(fsys, vendor)
	if err != nil {
		return vendorDir{}, xerrors.Errorf("failed to access vendor directory: %w", err)
	}

	// Check if the directory exists.
	// fs.Sub doesn't return an error for non-existent directories,
	// so we need to explicitly verify the directory exists.
	if _, err := fs.Stat(sub, "."); err != nil {
		return vendorDir{}, xerrors.Errorf("vendor directory does not exist: %w", err)
	}

	return vendorDir{root: sub}, nil
}

// Resolve resolves the module directory for a given package.
// It doesn't add the version suffix to the module name.
// e.g. vendor/ => vendor/github.com/aquasecurity/go-dep-parser
func (d vendorDir) Resolve(pkg types.Package) (fs.FS, error) {
	return fs.Sub(d.root, normalizeModName(pkg.Name))
}
