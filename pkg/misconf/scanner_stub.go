package misconf

import (
	"context"
	"io/fs"
	"sort"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/iac/detection"
	"github.com/aquasecurity/trivy/pkg/iac/rego"

	_ "embed"
)

type ScannerOption struct {
	Trace                    bool
	Namespaces               []string
	PolicyPaths              []string
	DataPaths                []string
	DisableEmbeddedPolicies  bool
	DisableEmbeddedLibraries bool
	IncludeDeprecatedChecks  bool
	RegoErrorLimit           int

	HelmValues              []string
	HelmValueFiles          []string
	HelmFileValues          []string
	HelmStringValues        []string
	HelmAPIVersions         []string
	HelmKubeVersion         string
	TerraformTFVars         []string
	CloudFormationParamVars []string
	TfExcludeDownloaded     bool
	RawConfigScanners       []types.ConfigType
	K8sVersion              string

	FilePatterns      []string
	ConfigFileSchemas []*ConfigFileSchema

	AnsiblePlaybooks   []string
	AnsibleInventories []string
	AnsibleExtraVars   map[string]any

	SkipFiles []string
	SkipDirs  []string

	RegoScanner *rego.Scanner
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

func InitRegoScanner(opt ScannerOption) (*rego.Scanner, error) {
	return nil, xerrors.New("pkg/misconf not implemented")
}

func CheckPathExists(path string) (fs.FileInfo, string, error) {
	return nil, "", xerrors.New("pkg/misconf not implemented")
}
