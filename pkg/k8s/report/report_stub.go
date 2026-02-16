package report

import (
	"io"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/sbom/core"
	"github.com/aquasecurity/trivy/pkg/types"
)

const (
	AllReport     = "all"
	SummaryReport = "summary"

	workloadComponent = "workload"
	infraComponent    = "infra"
	infraNamespace    = "kube-system"
)

type Option struct {
	Format        types.Format
	Report        string
	Output        io.Writer
	Severities    []dbTypes.Severity
	ColumnHeading []string
	Scanners      types.Scanners
	APIVersion    string
}

// Report represents a kubernetes scan report
type Report struct {
	SchemaVersion int `json:",omitempty"`
	ClusterName   string
	Resources     []Resource `json:",omitempty"`
	BOM           *core.BOM  `json:"-"`
	name          string
}

// ConsolidatedReport represents a kubernetes scan report with consolidated findings
type ConsolidatedReport struct {
	SchemaVersion int `json:",omitempty"`
	ClusterName   string
	Findings      []Resource `json:",omitempty"`
}

// Resource represents a kubernetes resource report
type Resource struct {
	Namespace string `json:",omitempty"`
	Kind      string
	Name      string
	Metadata  []types.Metadata `json:",omitempty"`
	Results   types.Results    `json:",omitempty"`
	Error     string           `json:",omitempty"`

	// original report
	Report types.Report `json:"-"`
}
