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
func GetComplianceSpec(specNameOrPath string) (ComplianceSpec, error) {
	return ComplianceSpec{}, xerrors.New("pkg/compliance not implemented")
}

// Scanners reads spec control and determines the scanners by check ID prefix
func (cs *ComplianceSpec) Scanners() (types.Scanners, error) {
	return nil, xerrors.New("pkg/compliance not implemented")
}
