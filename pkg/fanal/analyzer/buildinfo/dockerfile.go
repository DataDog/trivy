package buildinfo

import (
	"context"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
)

func init() {
	analyzer.RegisterAnalyzer(&dockerfileAnalyzer{})
}

const dockerfileAnalyzerVersion = 1

// For Red Hat products
type dockerfileAnalyzer struct{}

func (a dockerfileAnalyzer) Analyze(_ context.Context, _ analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	return nil, xerrors.New("dockerfile analyzer is stubbed out")
}

func (a dockerfileAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	dir, file := filepath.Split(filepath.ToSlash(filePath))
	if dir != "root/buildinfo/" {
		return false
	}
	return strings.HasPrefix(file, "Dockerfile")
}

func (a dockerfileAnalyzer) Type() analyzer.Type {
	return analyzer.TypeRedHatDockerfileType
}

func (a dockerfileAnalyzer) Version() int {
	return dockerfileAnalyzerVersion
}

func (a dockerfileAnalyzer) StaticPaths() []string {
	return []string{"root/buildinfo"}
}
