// Ported from https://github.com/golang/go/blob/e9c96835971044aa4ace37c7787de231bbde05d9/src/cmd/go/internal/version/version.go

package nodejsparser

import (
	"bytes"
	"regexp"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/dependency"
	exe "github.com/aquasecurity/trivy/pkg/dependency/parser/executable"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	xio "github.com/aquasecurity/trivy/pkg/x/io"
)

var (
	ErrUnrecognizedExe = xerrors.New("unrecognized executable format")
)

type Parser struct{}

func NewParser() *Parser {
	return &Parser{}
}

var versReg = regexp.MustCompile(`node\.js\/v(\d{1,3}\.\d{1,3}\.\d{1,3})`)

// Parse scans file to try to report the NodeJS version.
func (p *Parser) Parse(r xio.ReadSeekerAt) ([]ftypes.Package, []ftypes.Dependency, error) {
	x, err := exe.OpenExe(r)
	if err != nil {
		return nil, nil, ErrUnrecognizedExe
	}

	mod, vers := findVers(x)
	if vers == "" {
		return nil, nil, nil
	}

	var libs []ftypes.Package
	libs = append(libs, ftypes.Package{
		ID:      dependency.ID(ftypes.NodeJsExecutable, mod, vers),
		Name:    mod,
		Version: vers,
	})

	return libs, nil, nil
}

// findVers finds and returns the NodeJS version in the executable x.
func findVers(x exe.Exe) (vers, mod string) {
	text, size := x.DataStart()
	data, err := x.ReadData(text, size)
	if err != nil {
		return
	}

	for len(data) > 0 {
		// Extract the version number
		// split by null characters
		head, tail, _ := bytes.Cut(data, []byte("\000"))
		match := versReg.FindSubmatch(head)
		if match != nil {
			vers = string(match[1])
			break
		}
		data = tail
	}

	return "node", vers
}
