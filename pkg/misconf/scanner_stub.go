package misconf

import (
	"context"
	"io/fs"
	"sort"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/iac/detection"

	_ "embed"
)

type DisabledCheck struct {
	ID      string
	Scanner string // For logging
	Reason  string // For logging
}

type ScannerOption struct {
	Trace                    bool
	Namespaces               []string
	PolicyPaths              []string
	DataPaths                []string
	DisableEmbeddedPolicies  bool
	DisableEmbeddedLibraries bool
	IncludeDeprecatedChecks  bool

	HelmValues              []string
	HelmValueFiles          []string
	HelmFileValues          []string
	HelmStringValues        []string
	HelmAPIVersions         []string
	HelmKubeVersion         string
	TerraformTFVars         []string
	CloudFormationParamVars []string
	TfExcludeDownloaded     bool
	K8sVersion              string

	FilePatterns      []string
	ConfigFileSchemas []*ConfigFileSchema

	DisabledChecks []DisabledCheck
	SkipFiles      []string
	SkipDirs       []string
}

func (o *ScannerOption) Sort() {
	sort.Strings(o.Namespaces)
	sort.Strings(o.PolicyPaths)
	sort.Strings(o.DataPaths)
}

type Scanner struct {
}

func NewScanner(t detection.FileType, opt ScannerOption) (*Scanner, error) {
	return nil, xerrors.New("pkg/misconf not implemented")
}

func (s *Scanner) Scan(ctx context.Context, fsys fs.FS) ([]types.Misconfiguration, error) {
	return nil, xerrors.New("pkg/misconf not implemented")
}
