// Detects dependencies from Rust binaries built with https://github.com/rust-secure-code/cargo-auditable
package binary

import (
	"context"
	"io"
	"slices"

	rustaudit "github.com/rust-secure-code/go-rustaudit"
	"github.com/samber/lo"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/dependency"
	exe "github.com/aquasecurity/trivy/pkg/dependency/parser/executable"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	xio "github.com/aquasecurity/trivy/pkg/x/io"
)

var (
	ErrUnrecognizedExe = xerrors.New("unrecognized executable format")
	ErrNonRustBinary   = xerrors.New("non Rust auditable binary")
)

// convertError detects rustaudit.ErrUnknownFileFormat and convert to
// ErrUnrecognizedExe and convert rustaudit.ErrNoRustDepInfo to ErrNonRustBinary
func convertError(err error) error {
	if err == rustaudit.ErrUnknownFileFormat {
		return ErrUnrecognizedExe
	}
	if err == rustaudit.ErrNoRustDepInfo {
		return ErrNonRustBinary
	}

	return err
}

type Parser struct{}

func NewParser() *Parser {
	return &Parser{}
}

// Parse scans files to try to report Rust crates and version injected into Rust binaries
// via https://github.com/rust-secure-code/cargo-auditable
func (p *Parser) Parse(_ context.Context, r xio.ReadSeekerAt) ([]ftypes.Package, []ftypes.Dependency, error) {
	if !mayBeRust(r) {
		return nil, nil, ErrNonRustBinary
	}
	info, err := rustaudit.GetDependencyInfo(r)
	if err != nil {
		return nil, nil, convertError(err)
	}

	var pkgs []ftypes.Package
	var deps []ftypes.Dependency
	for _, pkg := range info.Packages {
		if pkg.Kind != rustaudit.Runtime {
			continue
		}
		pkgID := packageID(pkg.Name, pkg.Version)
		pkgs = append(pkgs, ftypes.Package{
			ID:           pkgID,
			Name:         pkg.Name,
			Version:      pkg.Version,
			Relationship: lo.Ternary(pkg.Root, ftypes.RelationshipRoot, ftypes.RelationshipUnknown), // TODO: Determine the direct dependencies by checking the dependencies of the root crate
		})

		var childDeps []string
		for _, dep_idx := range pkg.Dependencies {
			dep := info.Packages[dep_idx]
			if dep.Kind == rustaudit.Runtime {
				childDeps = append(childDeps, packageID(dep.Name, dep.Version))
			}
		}
		if len(childDeps) > 0 {
			deps = append(deps, ftypes.Dependency{
				ID:        pkgID,
				DependsOn: childDeps,
			})
		}
	}

	return pkgs, deps, nil
}

// depSections are the names that go-rustaudit looks up for the
// cargo-auditable section of a Mach-O file.
var depSections = []string{".dep-v0", "rust-deps-v0"}

// mayBeRust reports whether r may hold cargo-auditable dependency
// information, from the load commands of a Mach-O file. go-rustaudit reads
// a Mach-O file with macho.NewFile, which decodes the whole symbol table.
// mayBeRust reports true for other files.
func mayBeRust(r io.ReaderAt) bool {
	names, err := exe.MachOSections(r)
	if err != nil {
		return true
	}
	return slices.ContainsFunc(names, func(name string) bool {
		return slices.Contains(depSections, name)
	})
}

func packageID(name, version string) string {
	return dependency.ID(ftypes.RustBinary, name, version)
}
