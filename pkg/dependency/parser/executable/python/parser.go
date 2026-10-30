// Ported from https://github.com/golang/go/blob/e9c96835971044aa4ace37c7787de231bbde05d9/src/cmd/go/internal/version/version.go

package pythonparser

import (
	"context"
	"regexp"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/dependency"
	exe "github.com/aquasecurity/trivy/pkg/dependency/parser/executable"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	xio "github.com/aquasecurity/trivy/pkg/x/io"
)

var (
	ErrUnrecognizedExe = xerrors.New("unrecognized executable format")
	ErrNonPythonBinary = xerrors.New("non Python binary")
)

type Parser struct{}

func NewParser() *Parser {
	return &Parser{}
}

var versReg = regexp.MustCompile(`^\d{1,4}\.\d{1,4}\.\d{1,4}[-._a-zA-Z0-9]*$`)

// Parse scans file to try to report the Python version.
func (p *Parser) Parse(ctx context.Context, r xio.ReadSeekerAt) ([]ftypes.Package, []ftypes.Dependency, error) {
	x, err := exe.OpenExe(r)
	if err != nil {
		return nil, nil, ErrUnrecognizedExe
	}

	name, vers := findVers(x)
	if vers == "" {
		return nil, nil, nil
	}

	var libs []ftypes.Package
	libs = append(libs, ftypes.Package{
		ID:      dependency.ID(ftypes.PythonExecutable, name, vers),
		Name:    name,
		Version: vers,
	})

	return libs, nil, nil
}

// findVers finds and returns the Python version in the executable x.
func findVers(x exe.Exe) (mod, vers string) {
	// Python's version pattern is [NUL]3.11.2[NUL]: versReg matches a
	// whole string.
	if m := exe.FindSubmatch(x, versReg); m != nil {
		vers = string(m[0])
	}
	return "python", vers
}
