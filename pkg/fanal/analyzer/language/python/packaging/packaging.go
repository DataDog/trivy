package packaging

import (
	"context"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/samber/lo"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/dependency/parser/python/packaging"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/language"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/licensing"
	"github.com/aquasecurity/trivy/pkg/utils/fsutils"
	xio "github.com/aquasecurity/trivy/pkg/x/io"
)

func init() {
	analyzer.RegisterPostAnalyzer(analyzer.TypePythonPkg, newPackagingAnalyzer)
}

const version = 2

func newPackagingAnalyzer(_ analyzer.AnalyzerOptions) (analyzer.PostAnalyzer, error) {
	return &packagingAnalyzer{
		pkgParser: packaging.NewParser(),
	}, nil
}

var (
	eggFiles = []string{
		// .egg format
		// https://setuptools.readthedocs.io/en/latest/deprecated/python_eggs.html#eggs-and-their-formats
		// ".egg" is zip format. We check it in `eggAnalyzer`.
		"EGG-INFO/PKG-INFO",

		// .egg-info format: .egg-info can be a file or directory
		// https://setuptools.readthedocs.io/en/latest/deprecated/python_eggs.html#eggs-and-their-formats
		".egg-info",
		".egg-info/PKG-INFO",
		// https://github.com/aquasecurity/trivy/issues/9171
		".egg-info/METADATA",
	}
)

type packagingAnalyzer struct {
	pkgParser language.Parser
}

// PostAnalyze analyzes egg and wheel files.
func (a packagingAnalyzer) PostAnalyze(ctx context.Context, input analyzer.PostAnalysisInput) (*analyzer.AnalysisResult, error) {

	var apps []types.Application

	required := func(path string, _ fs.DirEntry) bool {
		return filepath.Base(path) == "METADATA" || isEggFile(path) || input.FilePatterns.Match(path)
	}

	err := fsutils.WalkDir(ctx, input.FS, ".", required, input.Options.WalkErrCallback, func(filePath string, _ fs.DirEntry, r io.Reader) error {
		rsa, ok := r.(xio.ReadSeekerAt)
		if !ok {
			return xerrors.New("invalid reader")
		}

		app, err := a.parse(ctx, filePath, rsa, input.Options.FileChecksum)
		if err != nil {
			return xerrors.Errorf("parse error: %w", err)
		} else if app == nil {
			return nil
		}

		dropLicenseFiles(app)
		apps = append(apps, *app)
		return nil
	})

	result := &analyzer.AnalysisResult{
		Applications: apps,
	}

	if err != nil {
		return result, xerrors.Errorf("python package walk error: %w", err)
	}
	return result, nil
}

// dropLicenseFiles deletes the file:// licenses that the parser makes from
// License-File fields. They point at license files, and licensing.Classify
// returns empty findings for every file in this build.
func dropLicenseFiles(app *types.Application) {
	for i, pkg := range app.Packages {
		var licenses []string
		for _, lic := range pkg.Licenses {
			if !strings.HasPrefix(lic, licensing.LicenseFilePrefix) {
				licenses = append(licenses, lic)
			}
		}
		app.Packages[i].Licenses = licenses
	}
}

func (a packagingAnalyzer) parse(ctx context.Context, filePath string, r xio.ReadSeekerAt, checksum bool) (*types.Application, error) {
	return language.ParsePackage(ctx, types.PythonPkg, filePath, r, a.pkgParser, checksum)
}

func (a packagingAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	return strings.HasSuffix(filePath, ".dist-info/METADATA") || isEggFile(filePath)
}

func isEggFile(filePath string) bool {
	return lo.SomeBy(eggFiles, func(fileName string) bool {
		return strings.HasSuffix(filePath, fileName)
	})
}

func (a packagingAnalyzer) Type() analyzer.Type {
	return analyzer.TypePythonPkg
}

func (a packagingAnalyzer) Version() int {
	return version
}
