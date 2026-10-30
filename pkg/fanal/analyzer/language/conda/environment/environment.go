package environment

import (
	"context"
	"os"
	"path/filepath"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/dependency/parser/conda/environment"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/language"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	xio "github.com/aquasecurity/trivy/pkg/x/io"
)

func init() {
	analyzer.RegisterAnalyzer(&environmentAnalyzer{})
}

const version = 2

type parser struct{}

func (*parser) Parse(_ context.Context, r xio.ReadSeekerAt) ([]types.Package, []types.Dependency, error) {
	p := environment.NewParser()
	pkgs, err := p.Parse(r)
	if err != nil {
		return nil, nil, err
	}
	return pkgs.Packages, nil, nil
}

type environmentAnalyzer struct{}

func (a environmentAnalyzer) Analyze(ctx context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	res, err := language.Analyze(ctx, types.CondaEnv, input.FilePath, input.Content, &parser{})
	if err != nil {
		return nil, xerrors.Errorf("unable to parse environment.yaml: %w", err)
	}

	if res == nil {
		return nil, nil
	}
	return res, nil
}

func (a environmentAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	return filepath.Base(filePath) == types.CondaEnvYml || filepath.Base(filePath) == types.CondaEnvYaml
}

func (a environmentAnalyzer) Type() analyzer.Type {
	return analyzer.TypeCondaEnv
}

func (a environmentAnalyzer) Version() int {
	return version
}
