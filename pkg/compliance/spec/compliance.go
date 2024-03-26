package spec

import (
	"fmt"

	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

// ComplianceSpec represent the compliance specification
type ComplianceSpec struct {
	Spec iacTypes.Spec `yaml:"spec"`
}

// GetComplianceSpec accepct compliance flag name/path and return builtin or file system loaded spec
func GetComplianceSpec(specNameOrPath string) (ComplianceSpec, error) {
	return ComplianceSpec{}, fmt.Errorf("pkg/compliance not implemented")
}
