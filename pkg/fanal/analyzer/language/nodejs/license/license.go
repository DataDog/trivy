package license

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"strings"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/dependency/parser/nodejs/packagejson"
	nodepkg "github.com/aquasecurity/trivy/pkg/fanal/analyzer/language/nodejs/pkg"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/utils/fsutils"
)

type License struct {
	logger     *log.Logger
	pkgManager string
	parser     *packagejson.Parser
}

func NewLicense(pkgManager string) *License {
	return &License{
		logger:     log.WithPrefix(pkgManager),
		pkgManager: pkgManager,
		parser:     packagejson.NewParser(),
	}
}

func (l *License) Traverse(ctx context.Context, fsys fs.FS, root string, errCallback fsutils.WalkDirErrorCallback) (map[string][]string, error) {
	if _, err := fs.Stat(fsys, root); errors.Is(err, fs.ErrNotExist) {
		l.logger.Info(fmt.Sprintf(`Run "%s install" to collect the license information of packages`, l.pkgManager),
			log.String("dir", root))
		return make(map[string][]string), nil
	}

	licenses := make(map[string][]string)
	walkDirFunc := func(pkgJSONPath string, _ fs.DirEntry, r io.Reader) error {
		pkg, err := l.parser.Parse(r)
		if err != nil {
			return xerrors.Errorf("unable to parse %q: %w", pkgJSONPath, err)
		}

		// Record the licenses that package.json names. A license kept in a
		// file stays unknown: licensing.Classify returns empty findings in
		// this build.
		if ok, _ := IsLicenseRefToFile(pkg.Licenses); !ok || len(pkg.Licenses) > 1 {
			licenses[pkg.ID] = pkg.Licenses
		}
		return nil
	}
	required := func(p string, _ fs.DirEntry) bool {
		return nodepkg.IsPackageRoot(p)
	}
	if err := fsutils.WalkDir(ctx, fsys, root, required, errCallback, walkDirFunc); err != nil {
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
