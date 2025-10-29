package binary

import (
	"context"
	"errors"
	"os"
	"strings"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/dependency"
	"github.com/aquasecurity/trivy/pkg/dependency/parser/golang/binary"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/language"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/fanal/utils"
)

func init() {
	analyzer.RegisterAnalyzer(&gobinaryLibraryAnalyzer{})
}

const version = 1

type gobinaryLibraryAnalyzer struct{}

func (a gobinaryLibraryAnalyzer) Analyze(_ context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	p := binary.NewParser()
	res, err := language.Analyze(types.GoBinary, input.FilePath, input.Content, p)
	if errors.Is(err, binary.ErrUnrecognizedExe) || errors.Is(err, binary.ErrNonGoBinary) {
		return nil, nil
	} else if err != nil {
		return nil, xerrors.Errorf("go binary (filepath: %s) parse error: %w", input.FilePath, err)
	}

	handleStandaloneBinary(res)

	return res, nil
}

func (a gobinaryLibraryAnalyzer) Required(_ string, fileInfo os.FileInfo) bool {
	return utils.IsExecutable(fileInfo)
}

func (a gobinaryLibraryAnalyzer) Type() analyzer.Type {
	return analyzer.TypeGoBinary
}

func (a gobinaryLibraryAnalyzer) Version() int {
	return version
}

func handleStandaloneBinary(res *analyzer.AnalysisResult) {
	// this function implements a special handling of containerd binaries
	// in order to make it easier to identify containerd binaries, in addition to Go dependencies
	// we create a synthetic package (type StandaloneBinary) with the containerd version, and the actual
	// filesystem path

	newApplications := make([]types.Application, 0)

	for _, app := range res.Applications {
		foundContainerdVersion := ""
		for _, pkg := range app.Packages {
			if pkg.Relationship != types.RelationshipRoot {
				continue
			}

			if pkg.Name != "github.com/containerd/containerd/v2" {
				continue
			}

			foundContainerdVersion = pkg.Version
			break
		}

		if foundContainerdVersion != "" {
			// the version is prefixed with "v", as is standard with Go dependencies (e.g., v2.1.4)
			foundContainerdVersion = strings.TrimPrefix(foundContainerdVersion, "v")

			newApplications = append(newApplications, types.Application{
				Type:     types.StandaloneBinary,
				FilePath: app.FilePath,
				Packages: []types.Package{
					{
						ID:       dependency.ID(types.StandaloneBinary, "containerd", foundContainerdVersion),
						Name:     "containerd",
						Version:  foundContainerdVersion,
						FilePath: app.FilePath,
					},
				},
			})
		}
	}

	res.Applications = append(res.Applications, newApplications...)
}
