package javaparser

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
)

type Parser struct{}

func NewParser() *Parser {
	return &Parser{}
}

// versReg matches the strings the launcher passes to JLI_Launch
// (src/java.base/share/native/launcher/main.c): LAUNCHER_NAME ("openjdk",
// or "java" in Oracle JDK and Oracle GraalVM), PROGNAME ("java"),
// DOT_VERSION ("1.8" in JDK 8, "0.0" since JDK 9) and VERSION_STRING.
// They come in either order, and arm64 builds pad them with NULs to
// 8-byte boundaries.
var versReg = regexp.MustCompile(`(\x00+([0-9.]+)\x00+([0-9A-Za-z+._-]+)\x00+openjdk)?\x00+java(\x00+([0-9.]+)\x00+([0-9A-Za-z+._-]+))?\x00`)

// Parse scans file to try to report the Java version.
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

	match := versReg.FindSubmatch(data)
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
