package report

import (
	"context"
	"io"

	"golang.org/x/xerrors"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/compliance/spec"
	"github.com/aquasecurity/trivy/pkg/types"
)

type Option struct {
	Format        types.Format
	Report        string
	Output        io.Writer
	Severities    []dbTypes.Severity
	ColumnHeading []string
}

// ComplianceReport represents a kubernetes scan report
type ComplianceReport struct {
}

// Writer defines the result write operation
type Writer interface {
	Write(ComplianceReport) error
}

// Write writes the results in the given format
func Write(ctx context.Context, report *ComplianceReport, option Option) error {
	return xerrors.New("pkg/compliance not implemented")
}

func BuildComplianceReport(scanResults []types.Results, cs spec.ComplianceSpec) (*ComplianceReport, error) {
	return nil, xerrors.New("pkg/compliance not implemented")
}
