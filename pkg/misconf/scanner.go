package misconf

import (
	"context"
	"fmt"
	"io/fs"
	"path/filepath"
	"sort"

	"github.com/samber/lo"

	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/iac/detection"
	"github.com/aquasecurity/trivy/pkg/mapfs"

	_ "embed"
)

var enablediacTypes = map[detection.FileType]types.ConfigType{}

type ScannerOption struct {
	Debug                    bool
	Trace                    bool
	RegoOnly                 bool
	Namespaces               []string
	PolicyPaths              []string
	DataPaths                []string
	DisableEmbeddedPolicies  bool
	DisableEmbeddedLibraries bool

	HelmValues              []string
	HelmValueFiles          []string
	HelmFileValues          []string
	HelmStringValues        []string
	TerraformTFVars         []string
	CloudFormationParamVars []string
	TfExcludeDownloaded     bool
	K8sVersion              string
}

func (o *ScannerOption) Sort() {
	sort.Strings(o.Namespaces)
	sort.Strings(o.PolicyPaths)
	sort.Strings(o.DataPaths)
}

type Scanner struct {
}

func NewAzureARMScanner(filePatterns []string, opt ScannerOption) (*Scanner, error) {
	return nil, fmt.Errorf("not supported")
}

func NewCloudFormationScanner(filePatterns []string, opt ScannerOption) (*Scanner, error) {
	return nil, fmt.Errorf("not supported")
}

func NewDockerfileScanner(filePatterns []string, opt ScannerOption) (*Scanner, error) {
	return nil, fmt.Errorf("not supported")
}

func NewHelmScanner(filePatterns []string, opt ScannerOption) (*Scanner, error) {
	return nil, fmt.Errorf("not supported")
}

func NewKubernetesScanner(filePatterns []string, opt ScannerOption) (*Scanner, error) {
	return nil, fmt.Errorf("not supported")
}

func NewTerraformScanner(filePatterns []string, opt ScannerOption) (*Scanner, error) {
	return nil, fmt.Errorf("not supported")
}

func NewTerraformPlanScanner(filePatterns []string, opt ScannerOption) (*Scanner, error) {
	return nil, fmt.Errorf("not supported")
}

func (s *Scanner) Scan(ctx context.Context, fsys fs.FS) ([]types.Misconfiguration, error) {
	return nil, fmt.Errorf("not supported")
}

func (s *Scanner) filterFS(fsys fs.FS) (fs.FS, error) {
	return fsys, fmt.Errorf("not supported")
}

func CreatePolicyFS(policyPaths []string) (fs.FS, []string, error) {
	return nil, nil, fmt.Errorf("not supported")
}

func CreateDataFS(dataPaths []string, opts ...string) (fs.FS, []string, error) {
	fsys := mapfs.New()

	// Check if k8sVersion is provided
	if len(opts) > 0 {
		k8sVersion := opts[0]
		if err := fsys.MkdirAll("system", 0700); err != nil {
			return nil, nil, err
		}
		data := []byte(fmt.Sprintf(`{"k8s": {"version": %q}}`, k8sVersion))
		if err := fsys.WriteVirtualFile("system/k8s-version.json", data, 0600); err != nil {
			return nil, nil, err
		}
	}

	for _, path := range dataPaths {
		if err := fsys.CopyFilesUnder(path); err != nil {
			return nil, nil, err
		}
	}

	// dataPaths are no longer needed as fs.FS contains only needed files now.
	dataPaths = []string{"."}

	return fsys, dataPaths, nil
}

// ResultsToMisconf is exported for trivy-plugin-aqua purposes only
func ResultsToMisconf(configType types.ConfigType, scannerName string, results scan.Results) []types.Misconfiguration {
	misconfs := make(map[string]types.Misconfiguration)

	for _, result := range results {
		flattened := result.Flatten()

		query := fmt.Sprintf("data.%s.%s", result.RegoNamespace(), result.RegoRule())

		ruleID := result.Rule().AVDID
		if result.RegoNamespace() != "" && len(result.Rule().Aliases) > 0 {
			ruleID = result.Rule().Aliases[0]
		}

		cause := NewCauseWithCode(result)

		misconfResult := types.MisconfResult{
			Namespace: result.RegoNamespace(),
			Query:     query,
			Message:   flattened.Description,
			PolicyMetadata: types.PolicyMetadata{
				ID:                 ruleID,
				AVDID:              result.Rule().AVDID,
				Type:               fmt.Sprintf("%s Security Check", scannerName),
				Title:              result.Rule().Summary,
				Description:        result.Rule().Explanation,
				Severity:           string(flattened.Severity),
				RecommendedActions: flattened.Resolution,
				References:         flattened.Links,
			},
			CauseMetadata: cause,
			Traces:        result.Traces(),
		}

		filePath := flattened.Location.Filename
		misconf, ok := misconfs[filePath]
		if !ok {
			misconf = types.Misconfiguration{
				FileType: configType,
				FilePath: filepath.ToSlash(filePath), // defsec return OS-aware path
			}
		}

		if flattened.Warning {
			misconf.Warnings = append(misconf.Warnings, misconfResult)
		} else {
			switch flattened.Status {
			case scan.StatusPassed:
				misconf.Successes = append(misconf.Successes, misconfResult)
			case scan.StatusIgnored:
				misconf.Exceptions = append(misconf.Exceptions, misconfResult)
			case scan.StatusFailed:
				misconf.Failures = append(misconf.Failures, misconfResult)
			}
		}
		misconfs[filePath] = misconf
	}

	return types.ToMisconfigurations(misconfs)
}

func NewCauseWithCode(underlying scan.Result) types.CauseMetadata {
	flat := underlying.Flatten()
	cause := types.CauseMetadata{
		Resource:  flat.Resource,
		Provider:  flat.RuleProvider.DisplayName(),
		Service:   flat.RuleService,
		StartLine: flat.Location.StartLine,
		EndLine:   flat.Location.EndLine,
	}
	for _, o := range flat.Occurrences {
		cause.Occurrences = append(cause.Occurrences, types.Occurrence{
			Resource: o.Resource,
			Filename: o.Filename,
			Location: types.Location{
				StartLine: o.StartLine,
				EndLine:   o.EndLine,
			},
		})
	}
	if code, err := underlying.GetCode(); err == nil {
		cause.Code = types.Code{
			Lines: lo.Map(code.Lines, func(l scan.Line, i int) types.Line {
				return types.Line{
					Number:      l.Number,
					Content:     l.Content,
					IsCause:     l.IsCause,
					Annotation:  l.Annotation,
					Truncated:   l.Truncated,
					Highlighted: l.Highlighted,
					FirstCause:  l.FirstCause,
					LastCause:   l.LastCause,
				}
			}),
		}
	}
	return cause
}
