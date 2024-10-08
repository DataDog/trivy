// Ported from https://github.com/golang/go/blob/e9c96835971044aa4ace37c7787de231bbde05d9/src/cmd/go/internal/version/version.go

package javaparser

import (
	"golang.org/x/xerrors"
	"rsc.io/binaryregexp"

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

// Parse scans file to try to report the Python version.
func (p *Parser) Parse(r xio.ReadSeekerAt) ([]ftypes.Package, []ftypes.Dependency, error) {
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
		ID:      dependency.ID(ftypes.JavaExecutable, name, vers),
		Name:    name,
		Version: vers,
	})

	return libs, nil, nil
}

// findVers finds and returns the Java version in the executable x.
func findVers(x exe.Exe) (vers, mod string) {
	text, size := x.DataStart()
	data, err := x.ReadData(text, size)
	if err != nil {
		return
	}

	re := binaryregexp.MustCompile(`(\x00([0-9\.]+)\x00([0-9a-z\+-\._]+)\x00openjdk)?\x00java(\x00([0-9\.]+)\x00([0-9a-z\+-\._]+))?\x00`)
	match := re.FindSubmatch(data)
	if match != nil {
		if match[3] != nil {
			vers = string(match[3])
		}
		if match[6] != nil {
			vers = string(match[6])
		}
	}

	return "java", vers
}
