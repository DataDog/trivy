package yarn

import (
	"archive/zip"
	"cmp"
	"context"
	"errors"
	"io"
	"io/fs"
	"maps"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/bmatcuk/doublestar/v4"
	"github.com/hashicorp/go-multierror"
	"github.com/samber/lo"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/dependency"
	"github.com/aquasecurity/trivy/pkg/dependency/parser/nodejs/packagejson"
	"github.com/aquasecurity/trivy/pkg/dependency/parser/nodejs/yarn"
	"github.com/aquasecurity/trivy/pkg/detector/library/compare/npm"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/language"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/language/nodejs/license"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/set"
	"github.com/aquasecurity/trivy/pkg/utils/fsutils"
	xio "github.com/aquasecurity/trivy/pkg/x/io"
)

func init() {
	analyzer.RegisterPostAnalyzer(analyzer.TypeYarn, newYarnAnalyzer)
}

const version = 2

// Taken from Yarn
// cf. https://github.com/yarnpkg/yarn/blob/328fd596de935acc6c3e134741748fcc62ec3739/src/resolvers/exotics/registry-resolver.js#L12
var fragmentRegexp = regexp.MustCompile(`(\S+):(@?.*?)(@(.*?)|)$`)

type yarnAnalyzer struct {
	logger            *log.Logger
	packageJsonParser *packagejson.Parser
	comparer          npm.Comparer
	license           *license.License
}

func newYarnAnalyzer(_ analyzer.AnalyzerOptions) (analyzer.PostAnalyzer, error) {
	return &yarnAnalyzer{
		logger:            log.WithPrefix("yarn"),
		packageJsonParser: packagejson.NewParser(),
		comparer:          npm.Comparer{},
		license:           license.NewLicense(),
	}, nil
}

type parserWithPatterns struct {
	patterns map[string][]string
}

func (p *parserWithPatterns) Parse(ctx context.Context, r xio.ReadSeekerAt) ([]types.Package, []types.Dependency, error) {
	pkgs, deps, patterns, err := yarn.NewParser().Parse(ctx, r)
	p.patterns = patterns
	return pkgs, deps, err
}

func (a yarnAnalyzer) PostAnalyze(ctx context.Context, input analyzer.PostAnalysisInput) (*analyzer.AnalysisResult, error) {
	var apps []types.Application

	required := func(path string, _ fs.DirEntry) bool {
		return filepath.Base(path) == types.YarnLock || input.FilePatterns.Match(path)
	}

	err := fsutils.WalkDir(ctx, input.FS, ".", required, input.Options.WalkErrCallback, func(filePath string, _ fs.DirEntry, r io.Reader) error {
		parser := &parserWithPatterns{}
		// Parse yarn.lock
		app, err := language.Parse(ctx, types.Yarn, filePath, r, parser)
		if err != nil {
			return xerrors.Errorf("parse error: %w", err)
		} else if app == nil {
			return nil
		}

		licenses, err := a.traverseLicenses(ctx, input.FS, filePath)
		if err != nil {
			a.logger.Debug("Unable to traverse licenses", log.Err(err))
			licenses = make(map[string][]string)
		}

		// Parse package.json alongside yarn.lock to find direct deps and mark dev deps
		dirs, err := a.analyzeDependencies(ctx, input.FS, path.Dir(filePath), app, parser.patterns)
		if err != nil {
			a.logger.Warn("Unable to parse package.json to remove dev dependencies",
				log.FilePath(path.Join(path.Dir(filePath), types.NpmPkg)), log.Err(err))
		}

		// Yarn installs in the node_modules of a workspace the packages
		// it keeps out of the root, such as a version that conflicts with
		// a hoisted one.
		for _, dir := range dirs {
			nm := path.Join(dir, "node_modules")
			if _, err := fs.Stat(input.FS, nm); err != nil {
				continue
			}
			if l, err := a.license.Traverse(ctx, input.FS, nm); err == nil {
				maps.Copy(licenses, l)
			}
		}

		// Fill licenses
		for i, lib := range app.Packages {
			if l, ok := licenses[lib.ID]; ok {
				app.Packages[i].Licenses = l
			}
		}

		// The walks above stop when ctx is done, which leaves app partial.
		if err := ctx.Err(); err != nil {
			return err
		}
		apps = append(apps, *app)

		return nil
	})
	result := &analyzer.AnalysisResult{
		Applications: apps,
	}
	if err != nil {
		return result, xerrors.Errorf("yarn walk error: %w", err)
	}

	return result, nil
}

func (a yarnAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	dirs, fileName := splitPath(filePath)

	if fileName == types.YarnLock &&
		// skipping yarn.lock in cache folders
		lo.Some(dirs, []string{
			"node_modules",
			".yarn",
		}) {
		return false
	}

	if fileName == types.YarnLock || fileName == types.NpmPkg {
		return true
	}

	// The path is slashed in analyzers.
	l := len(dirs)
	// Valid path to the zip file - **/.yarn/cache/*.zip
	if l > 1 && dirs[l-2] == ".yarn" && dirs[l-1] == "cache" && path.Ext(fileName) == ".zip" {
		return true
	}

	return false
}

func splitPath(filePath string) (dirs []string, fileName string) {
	fileName = filepath.Base(filePath)
	// The path is slashed in analyzers.
	dirs = strings.Split(path.Dir(filePath), "/")
	return dirs, fileName
}

func (a yarnAnalyzer) Type() analyzer.Type {
	return analyzer.TypeYarn
}

func (a yarnAnalyzer) Version() int {
	return version
}

// analyzeDependencies analyzes the package.json file next to yarn.lock,
// distinguishing between direct and transitive dependencies as well as production and development dependencies.
// It returns the directory of each workspace.
func (a yarnAnalyzer) analyzeDependencies(ctx context.Context, fsys fs.FS, dir string, app *types.Application, patterns map[string][]string) ([]string, error) {
	packageJsonPath := path.Join(dir, types.NpmPkg)
	root, workspaces, dirs, err := a.parsePackageJSON(ctx, fsys, packageJsonPath)
	if errors.Is(err, fs.ErrNotExist) {
		a.logger.Debug("package.json not found", log.FilePath(packageJsonPath))
		return nil, nil
	} else if err != nil {
		return nil, xerrors.Errorf("unable to parse root package.json: %w", err)
	}

	// Since yarn.lock file can contain same packages with different versions
	// we need to save versions separately for version comparison.
	pkgs := newPkgIndex(app.Packages)

	if err := a.resolveRootDependencies(&root, pkgs, patterns); err != nil {
		return nil, xerrors.Errorf("unable to resolve root dependencies: %w", err)
	}

	if err := a.resolveWorkspaceDependencies(workspaces, pkgs, patterns); err != nil {
		return nil, xerrors.Errorf("unable to resolve workspace dependencies: %w", err)
	}

	pkgSlice := lo.Values(pkgs.byID)
	sort.Sort(types.Packages(pkgSlice))

	// Save packages
	app.Packages = pkgSlice
	return dirs, nil
}

// parsePackageJSON returns the root package of the package.json at
// filePath, and the package and the directory of each of its workspaces.
func (a yarnAnalyzer) parsePackageJSON(ctx context.Context, fsys fs.FS, filePath string) (packagejson.Package, []packagejson.Package, []string, error) {
	// Parse package.json
	f, err := fsys.Open(filePath)
	if err != nil {
		return packagejson.Package{}, nil, nil, xerrors.Errorf("file open error: %w", err)
	}
	defer func() { _ = f.Close() }()

	root, err := a.packageJsonParser.Parse(f)
	if err != nil {
		return packagejson.Package{}, nil, nil, xerrors.Errorf("parse error: %w", err)
	}

	root.Package.ID = cmp.Or(root.Package.ID, filePath) // In case the package.json doesn't have a name or version
	root.Package.Relationship = types.RelationshipRoot

	workspaces, dirs, err := a.traverseWorkspaces(ctx, fsys, path.Dir(filePath), root.Workspaces)
	if err != nil {
		return packagejson.Package{}, nil, nil, xerrors.Errorf("traverse workspaces error: %w", err)
	}
	for i := range workspaces {
		workspaces[i].Package.Relationship = types.RelationshipWorkspace

		// Add workspace as a child of root
		root.DependsOn = append(root.DependsOn, workspaces[i].ID)
	}

	return root, workspaces, dirs, nil
}

// pkgIndex holds packages by ID and lists the IDs of the packages of each name.
type pkgIndex struct {
	byID   map[string]types.Package
	byName map[string][]string
}

func newPkgIndex(pkgs []types.Package) *pkgIndex {
	idx := &pkgIndex{
		byID:   make(map[string]types.Package, len(pkgs)),
		byName: make(map[string][]string, len(pkgs)),
	}
	for _, pkg := range pkgs {
		idx.set(pkg)
	}
	return idx
}

// set stores pkg in place of the package with its ID, if any.
func (idx *pkgIndex) set(pkg types.Package) {
	old, ok := idx.byID[pkg.ID]
	idx.byID[pkg.ID] = pkg
	if ok && old.Name == pkg.Name {
		return
	}
	if ok {
		idx.byName[old.Name] = slices.DeleteFunc(idx.byName[old.Name], func(id string) bool {
			return id == pkg.ID
		})
	}
	idx.byName[pkg.Name] = append(idx.byName[pkg.Name], pkg.ID)
}

func (a yarnAnalyzer) resolveRootDependencies(root *packagejson.Package, pkgs *pkgIndex,
	patterns map[string][]string) error {
	if err := a.resolveDependencies(root, pkgs, patterns); err != nil {
		return xerrors.Errorf("unable to resolve dependencies: %w", err)
	}

	// Add root package to the package map
	slices.Sort(root.Package.DependsOn)
	pkgs.set(root.Package)

	return nil
}

func (a yarnAnalyzer) resolveWorkspaceDependencies(workspaces []packagejson.Package, pkgs *pkgIndex,
	patterns map[string][]string) error {
	if len(workspaces) == 0 {
		return nil
	}

	for _, workspace := range workspaces {
		if err := a.resolveDependencies(&workspace, pkgs, patterns); err != nil {
			return xerrors.Errorf("unable to resolve dependencies: %w", err)
		}

		// Add workspace to the package map
		slices.Sort(workspace.Package.DependsOn)
		pkgs.set(workspace.Package)
	}

	return nil
}

// resolveDependencies resolves production and development dependencies from direct dependencies and patterns.
// It also flags dependencies as direct or indirect and updates the dependencies of the parent package.
func (a yarnAnalyzer) resolveDependencies(pkg *packagejson.Package, pkgs *pkgIndex, patterns map[string][]string) error {
	// Recursively walk dependencies and flags development dependencies.
	// Walk development dependencies first to avoid overwriting production dependencies.
	directDevDeps := pkg.DevDependencies
	if err := a.walkDependencies(&pkg.Package, pkgs, directDevDeps, patterns, true); err != nil {
		return xerrors.Errorf("unable to walk dependencies: %w", err)
	}

	// Recursively walk dependencies and flags production dependencies.
	directProdDeps := lo.Assign(pkg.Dependencies, pkg.OptionalDependencies)
	if err := a.walkDependencies(&pkg.Package, pkgs, directProdDeps, patterns, false); err != nil {
		return xerrors.Errorf("unable to walk dependencies: %w", err)
	}

	return nil
}

// walkDependencies recursively walk dependencies and flags them as direct or indirect.
// Note that it overwrites the existing package map.
func (a yarnAnalyzer) walkDependencies(parent *types.Package, pkgs *pkgIndex, directDeps map[string]string,
	patterns map[string][]string, dev bool) error {

	// Identify direct dependencies. Collect the candidates first:
	// renaming an alias below moves its ID to another name.
	var ids []string
	for name := range directDeps {
		ids = append(ids, pkgs.byName[name]...)
	}

	seenIDs := set.New[string]()
	for _, id := range ids {
		pkg := pkgs.byID[id]
		constraint := directDeps[pkg.Name]

		// Handle aliases
		// cf. https://classic.yarnpkg.com/lang/en/docs/cli/add/#toc-yarn-add-alias
		if m := fragmentRegexp.FindStringSubmatch(constraint); len(m) == 5 {
			pkg.Name = m[2] // original name
			constraint = m[4]
		}

		// Try to find an exact match to the pattern.
		// In some cases, patterns from yarn.lock and package.json may not match (e.g., yarn v2 uses the allowed version for ID).
		// Therefore, if the patterns don't match - compare versions.
		if pkgPatterns, found := patterns[pkg.ID]; !found || !slices.Contains(pkgPatterns, dependency.ID(types.Yarn, pkg.Name, constraint)) {
			// npm has own comparer to compare versions
			if match, err := a.comparer.MatchVersion(pkg.Version, constraint); err != nil {
				return xerrors.Errorf("unable to match version for %s", pkg.Name)
			} else if !match {
				continue
			}
		}

		// If the package is already marked as a production dependency, skip overwriting it.
		// Since the dev field is boolean, it cannot determine if the package is already processed,
		// so we need to check the relationship field.
		if pkg.Relationship == types.RelationshipUnknown || pkg.Dev {
			pkg.Dev = dev
		}

		// Mark as a direct dependency
		pkg.Indirect = false
		pkg.Relationship = types.RelationshipDirect

		pkgs.set(pkg)
		seenIDs.Append(pkg.ID)

		// Add a direct dependency to the parent package
		parent.DependsOn = append(parent.DependsOn, pkg.ID)

		// Walk indirect dependencies
		a.walkIndirectDependencies(pkg, pkgs, seenIDs)
	}

	return nil
}

func (a yarnAnalyzer) walkIndirectDependencies(pkg types.Package, pkgs *pkgIndex, seenIDs set.Set[string]) {
	for _, pkgID := range pkg.DependsOn {
		if seenIDs.Contains(pkgID) {
			continue // Skip if we've already seen this package
		}

		dep, ok := pkgs.byID[pkgID]
		if !ok {
			continue
		}

		if dep.Relationship == types.RelationshipUnknown || dep.Dev {
			dep.Dev = pkg.Dev
		}
		dep.Indirect = true
		dep.Relationship = types.RelationshipIndirect
		pkgs.set(dep)

		seenIDs.Append(dep.ID)

		// Recursively walk dependencies
		a.walkIndirectDependencies(dep, pkgs, seenIDs)
	}
}

// globEscaper escapes the characters that doublestar reads as pattern
// syntax, the ones it unescapes in a literal part of a pattern.
var globEscaper = strings.NewReplacer("*", `\*`, "?", `\?`, "[", `\[`, "]", `\]`, "{", `\{`, "}", `\}`)

// traverseWorkspaces returns the package.json and the directory of each
// workspace. As in Yarn, a workspace is a directory outside node_modules
// that matches one of the patterns and holds a package.json.
func (a yarnAnalyzer) traverseWorkspaces(ctx context.Context, fsys fs.FS, dir string, workspaces []string) ([]packagejson.Package, []string, error) {
	var pkgs []packagejson.Package
	var dirs []string

	walkFunc := func(match string, d fs.DirEntry) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		// Workspaces lie outside node_modules. On a match of a one-level
		// pattern such as *, doublestar takes SkipDir to skip the rest of
		// the match's directory, so return SkipDir only below node_modules,
		// where every sibling is in node_modules too.
		elems := strings.Split(match, "/")
		switch i := slices.Index(elems, "node_modules"); {
		case i == len(elems)-1:
			return nil
		case i >= 0:
			return fs.SkipDir
		}
		if !d.IsDir() {
			return nil
		}

		pkgJSONPath := path.Join(match, types.NpmPkg)
		f, err := fsys.Open(pkgJSONPath)
		if errors.Is(err, fs.ErrNotExist) || errors.Is(err, fs.ErrPermission) {
			return nil
		} else if err != nil {
			return xerrors.Errorf("file open error: %w", err)
		}
		defer f.Close()

		pkg, err := a.packageJsonParser.Parse(f)
		if err != nil {
			a.logger.Debug("Unable to parse workspace package.json", log.FilePath(pkgJSONPath), log.Err(err))
			return nil
		}
		pkg.Package.ID = cmp.Or(pkg.Package.ID, pkgJSONPath) // In case the package.json doesn't have a name or version
		pkgs = append(pkgs, pkg)
		dirs = append(dirs, match)
		return nil
	}

	for _, workspace := range workspaces {
		// We need to add the path to the `package.json` file
		// to properly get the pattern to search in `fs`
		workspace = path.Join(globEscaper.Replace(dir), workspace)
		// mapfs reads a name above its root from the disk, outside the
		// scanned files.
		if !fs.ValidPath(workspace) {
			a.logger.Debug("Skip the workspace pattern above the root", log.String("pattern", workspace))
			continue
		}
		if err := doublestar.GlobWalk(fsys, workspace, walkFunc); err != nil {
			return nil, nil, xerrors.Errorf("walk error: %w", err)
		}
	}
	return pkgs, dirs, nil
}

func (a yarnAnalyzer) traverseLicenses(ctx context.Context, fsys fs.FS, lockPath string) (map[string][]string, error) {
	sub, err := fs.Sub(fsys, path.Dir(lockPath))
	if err != nil {
		return nil, xerrors.Errorf("fs error: %w", err)
	}
	var errs error

	// Yarn v1
	licenses, err := a.traverseYarnClassicPkgs(ctx, sub)
	if err == nil {
		return licenses, nil
	}
	errs = multierror.Append(errs, err)

	// Yarn v2+
	licenses, err = a.traverseYarnModernPkgs(ctx, sub)
	if err == nil {
		return licenses, nil
	}
	errs = multierror.Append(errs, err)

	return nil, errs
}

func (a yarnAnalyzer) traverseYarnClassicPkgs(ctx context.Context, fsys fs.FS) (map[string][]string, error) {
	return a.license.Traverse(ctx, fsys, "node_modules")
}

func (a yarnAnalyzer) traverseYarnModernPkgs(ctx context.Context, fsys fs.FS) (map[string][]string, error) {
	sub, err := fs.Sub(fsys, ".yarn")
	if err != nil {
		return nil, xerrors.Errorf("fs error: %w", err)
	}

	var errs error
	licenses := make(map[string][]string)

	if ll, err := a.traverseUnpluggedDir(ctx, sub); err != nil {
		errs = multierror.Append(errs, err)
	} else {
		licenses = lo.Assign(licenses, ll)
	}

	if ll, err := a.traverseCacheDir(ctx, sub); err != nil {
		errs = multierror.Append(errs, err)
	} else {
		licenses = lo.Assign(licenses, ll)
	}

	if len(licenses) == 0 {
		return nil, errs
	}

	return licenses, nil
}

func (a yarnAnalyzer) traverseUnpluggedDir(ctx context.Context, fsys fs.FS) (map[string][]string, error) {
	// `unplugged` hold machine-specific build artifacts
	// Traverse .yarn/unplugged dir
	return a.license.Traverse(ctx, fsys, "unplugged")
}

func (a yarnAnalyzer) traverseCacheDir(ctx context.Context, fsys fs.FS) (map[string][]string, error) {
	// Traverse .yarn/cache dir
	licenses := make(map[string][]string)
	err := fsutils.WalkDir(ctx, fsys, "cache", fsutils.RequiredExt(".zip"), fsutils.DefaultWalkErrorCallback,
		func(_ string, d fs.DirEntry, r io.Reader) error {
			fi, err := d.Info()
			if err != nil {
				return xerrors.Errorf("file stat error: %w", err)
			}

			rr, err := xio.NewReadSeekerAt(r)
			if err != nil {
				return xerrors.Errorf("reader error: %w", err)
			}

			zr, err := zip.NewReader(rr, fi.Size())
			if err != nil {
				return xerrors.Errorf("zip reader error: %w", err)
			}

			if l, err := a.license.Traverse(ctx, zr, "node_modules"); err != nil {
				return xerrors.Errorf("license traverse error: %w", err)
			} else {
				licenses = lo.Assign(licenses, l)
			}
			return nil
		})

	if err != nil {
		return licenses, xerrors.Errorf("walk error: %w", err)
	}

	return licenses, nil
}
