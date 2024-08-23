package misconf

import (
	"context"
	"io/fs"
	"sort"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/fanal/types"

	_ "embed"
)

type ScannerOption struct {
	Trace                    bool
	RegoOnly                 bool
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
}

func (o *ScannerOption) Sort() {
	sort.Strings(o.Namespaces)
	sort.Strings(o.PolicyPaths)
	sort.Strings(o.DataPaths)
}

type Scanner struct {
}

func (s *Scanner) Scan(ctx context.Context, fsys fs.FS) ([]types.Misconfiguration, error) {
	return nil, xerrors.New("pkg/misconf not implemented")
}
