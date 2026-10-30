package license

import (
	"context"
	"io"
	"io/fs"
	"strings"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/dependency/parser/nodejs/packagejson"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/utils/fsutils"
)

type License struct {
	parser *packagejson.Parser
}

func NewLicense() *License {
	return &License{
		parser: packagejson.NewParser(),
	}
}

func (l *License) Traverse(ctx context.Context, fsys fs.FS, root string) (map[string][]string, error) {
	licenses := make(map[string][]string)
	walkDirFunc := func(pkgJSONPath string, _ fs.DirEntry, r io.Reader) error {
		pkg, err := l.parser.Parse(r)
		if err != nil {
			return xerrors.Errorf("unable to parse %q: %w", pkgJSONPath, err)
		}

		// Record the license that package.json names. A license kept in a
		// file stays unknown: licensing.Classify returns empty findings in
		// this build.
		if ok, _ := IsLicenseRefToFile(pkg.Licenses); !ok {
			licenses[pkg.ID] = pkg.Licenses
		}
		return nil
	}
	if err := fsutils.WalkDir(ctx, fsys, root, fsutils.RequiredFile(types.NpmPkg), fsutils.DefaultWalkErrorCallback, walkDirFunc); err != nil {
		return nil, xerrors.Errorf("walk error: %w", err)
	}

	return licenses, nil
}

// IsLicenseRefToFile The license field can refer to a file
// https://docs.npmjs.com/cli/v9/configuring-npm/package-json
func IsLicenseRefToFile(maybeLicenses []string) (bool, string) {
	if len(maybeLicenses) != 1 {
		// trying to find at least the LICENSE file
		return true, "LICENSE"
	}

	var licenseFileName string
	if strings.HasPrefix(maybeLicenses[0], "LicenseRef-") {
		// LicenseRef-<filename>
		licenseFileName = strings.Split(maybeLicenses[0], "-")[1]
	} else if strings.HasPrefix(maybeLicenses[0], "SEE LICENSE IN ") {
		// SEE LICENSE IN <filename>
		parts := strings.Split(maybeLicenses[0], " ")
		licenseFileName = parts[len(parts)-1]
	}

	return licenseFileName != "", licenseFileName
}
