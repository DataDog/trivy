package spec

import (
	"golang.org/x/xerrors"

	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
	"github.com/aquasecurity/trivy/pkg/types"
)

// ComplianceSpec represent the compliance specification
type ComplianceSpec struct {
	Spec iacTypes.Spec `yaml:"spec"`
}

// GetComplianceSpec accepct compliance flag name/path and return builtin or file system loaded spec
func GetComplianceSpec(specNameOrPath, cacheDir string) (ComplianceSpec, error) {
	// No compliance report was asked for. Upstream returns an empty spec here, and
	// pkg/flag calls this unconditionally while building options, so erroring would
	// fail every command.
	if specNameOrPath == "" {
		return ComplianceSpec{}, nil
	}
	return ComplianceSpec{}, xerrors.New("pkg/compliance not implemented")
}

// Scanners reads spec control and determines the scanners by check ID prefix
func (cs *ComplianceSpec) Scanners() (types.Scanners, error) {
	return nil, xerrors.New("pkg/compliance not implemented")
}
