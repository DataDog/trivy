package executable

import (
	"context"
	"os"
	"regexp"

	"github.com/aquasecurity/trivy/pkg/dependency/parser/executable/nodejs"
	"github.com/aquasecurity/trivy/pkg/dependency/parser/executable/php"
	"github.com/aquasecurity/trivy/pkg/dependency/parser/executable/python"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/language"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/fanal/utils"
)

func init() {
	analyzer.RegisterAnalyzer(&executableAnalyzer{})
}

const version = 1

// executableAnalyzer calculates SHA-256 for each binary not managed by package managers (called unpackaged binaries)
// so that it can search for SBOM attestation in post-handler.
type executableAnalyzer struct{}

// Returns boolean argument in first argument, indicating whether the Executable version is detectable
func isDetectableLibraryExecutable(fileInfo os.FileInfo) (bool, types.TargetType, error) {
	isPythonExecutable := isDetectablePythonExecutable(fileInfo)
	if isPythonExecutable {
		return true, types.PythonExecutable, nil
	}
	isNodeJsExecutable := isDetectableNodeJsExecutable(fileInfo)
	if isNodeJsExecutable {
		return true, types.NodeJsExecutable, nil
	}
	isPhpExecutable := isDetectablePhpExecutable(fileInfo)
	if isPhpExecutable {
		return true, types.PhpExecutable, nil
	}
	return false, types.TargetType(""), nil
}

func isDetectablePythonExecutable(fileInfo os.FileInfo) bool {
	pythonLibNameRegex := regexp.MustCompile("^libpython[0-9]+(?:[.0-9])+[a-z]?[.]so.*$")
	pythonExecutableNameRegex := regexp.MustCompile("(?:.*/|^)python(?P<version>[0-9]+(?:[.0-9])+)?$")
	isPythonExecutable := pythonExecutableNameRegex.FindSubmatch([]byte(fileInfo.Name()))
	isPythonLibSo := pythonLibNameRegex.FindSubmatch([]byte(fileInfo.Name()))
	return (isPythonExecutable != nil || isPythonLibSo != nil)
}

func isDetectableNodeJsExecutable(fileInfo os.FileInfo) bool {
	nodejsExecutableNameRegex := regexp.MustCompile("(?:.*/|^)node(?P<version>[0-9]+(?:[.0-9])+)?$")
	isNodeJsExecutable := nodejsExecutableNameRegex.FindSubmatch([]byte(fileInfo.Name()))
	return (isNodeJsExecutable != nil)
}

func isDetectablePhpExecutable(fileInfo os.FileInfo) bool {
	phpExecutableNameRegex := regexp.MustCompile("(.*/|^)php[0-9]*$")
	phpLibNameRegex := regexp.MustCompile("(.*/|^)libphp[0-9a-z.-]*[.]so$")
	phpFpmNameRegex := regexp.MustCompile("(.*/|^)php-fpm[0-9]*$")
	phpCgiNameRegex := regexp.MustCompile("(.*/|^)php-cgi[0-9]*$")

	isPHPExecutable := phpExecutableNameRegex.FindSubmatch([]byte(fileInfo.Name()))
	isPHPLib := phpLibNameRegex.FindSubmatch([]byte(fileInfo.Name()))
	isPHPFpm := phpFpmNameRegex.FindSubmatch([]byte(fileInfo.Name()))
	isPHPCgi := phpCgiNameRegex.FindSubmatch([]byte(fileInfo.Name()))
	return (isPHPExecutable != nil || isPHPLib != nil || isPHPFpm != nil || isPHPCgi != nil)
}

func (a executableAnalyzer) Analyze(_ context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	// Skip non-binaries
	isBinary, err := utils.IsBinary(input.Content, input.Info.Size())
	if !isBinary || err != nil {
		return nil, nil
	}

	isDetectableLib, binaryType, err := isDetectableLibraryExecutable(input.Info)
	if isDetectableLib && binaryType != "" && err == nil {
		var res *analyzer.AnalysisResult = nil
		switch binaryType {
		case types.PythonExecutable:
			res, err = language.Analyze(types.PythonExecutable, input.FilePath, input.Content, pythonparser.NewParser())
		case types.NodeJsExecutable:
			res, err = language.Analyze(types.NodeJsExecutable, input.FilePath, input.Content, nodejsparser.NewParser())
		case types.PhpExecutable:
			res, err = language.Analyze(types.PhpExecutable, input.FilePath, input.Content, phpparser.NewParser())
		}
		if err != nil {
			return nil, err
		}
		if res != nil {
			return res, nil
		}
	}

	return nil, nil
}

func (a executableAnalyzer) Required(_ string, fileInfo os.FileInfo) bool {
	return utils.IsExecutable(fileInfo)
}

func (a executableAnalyzer) Type() analyzer.Type {
	return analyzer.TypeExecutable
}

func (a executableAnalyzer) Version() int {
	return version
}
