package executable

import (
	"context"
	"os"
	"path"
	"regexp"

	javaparser "github.com/aquasecurity/trivy/pkg/dependency/parser/executable/java"
	nodejsparser "github.com/aquasecurity/trivy/pkg/dependency/parser/executable/nodejs"
	phpparser "github.com/aquasecurity/trivy/pkg/dependency/parser/executable/php"
	pythonparser "github.com/aquasecurity/trivy/pkg/dependency/parser/executable/python"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/language"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/fanal/utils"
)

func init() {
	analyzer.RegisterAnalyzer(&executableAnalyzer{})
}

const version = 2

// executableAnalyzer calculates SHA-256 for each binary not managed by package managers (called unpackaged binaries)
// so that it can search for SBOM attestation in post-handler.
type executableAnalyzer struct{}

// Returns boolean argument in first argument, indicating whether the Executable version is detectable
func isDetectableLibraryExecutable(name string) (bool, types.TargetType, error) {
	isPythonExecutable := isDetectablePythonExecutable(name)
	if isPythonExecutable {
		return true, types.PythonExecutable, nil
	}
	isNodeJsExecutable := isDetectableNodeJsExecutable(name)
	if isNodeJsExecutable {
		return true, types.NodeJsExecutable, nil
	}
	isPhpExecutable := isDetectablePhpExecutable(name)
	if isPhpExecutable {
		return true, types.PhpExecutable, nil
	}
	isJavaExecutable := isDetectableJavaExecutable(name)
	if isJavaExecutable {
		return true, types.JavaExecutable, nil
	}
	return false, types.TargetType(""), nil
}

var (
	pythonLibNameRegex        = regexp.MustCompile("^libpython[0-9]+(?:[.0-9])+[a-z]?[.]so.*$")
	pythonExecutableNameRegex = regexp.MustCompile("(?:.*/|^)python(?P<version>[0-9]+(?:[.0-9])+)?$")
	nodejsExecutableNameRegex = regexp.MustCompile("(?:.*/|^)node(?P<version>[0-9]+(?:[.0-9])+)?$")
	phpExecutableNameRegex    = regexp.MustCompile("(.*/|^)php[0-9]*$")
	phpLibNameRegex           = regexp.MustCompile("(.*/|^)libphp[0-9a-z.-]*[.]so$")
	phpFpmNameRegex           = regexp.MustCompile("(.*/|^)php-fpm[0-9]*$")
	phpCgiNameRegex           = regexp.MustCompile("(.*/|^)php-cgi[0-9]*$")
)

func isDetectablePythonExecutable(name string) bool {
	isPythonExecutable := pythonExecutableNameRegex.FindSubmatch([]byte(name))
	isPythonLibSo := pythonLibNameRegex.FindSubmatch([]byte(name))
	return (isPythonExecutable != nil || isPythonLibSo != nil)
}

func isDetectableNodeJsExecutable(name string) bool {
	isNodeJsExecutable := nodejsExecutableNameRegex.FindSubmatch([]byte(name))
	return (isNodeJsExecutable != nil)
}

func isDetectablePhpExecutable(name string) bool {
	isPHPExecutable := phpExecutableNameRegex.FindSubmatch([]byte(name))
	isPHPLib := phpLibNameRegex.FindSubmatch([]byte(name))
	isPHPFpm := phpFpmNameRegex.FindSubmatch([]byte(name))
	isPHPCgi := phpCgiNameRegex.FindSubmatch([]byte(name))
	return (isPHPExecutable != nil || isPHPLib != nil || isPHPFpm != nil || isPHPCgi != nil)
}

func isDetectableJavaExecutable(name string) bool {
	return name == "java"
}

func (a executableAnalyzer) Analyze(ctx context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	// Skip non-binaries
	isBinary, err := utils.IsBinary(input.Content, input.Info.Size())
	if !isBinary || err != nil {
		return nil, nil
	}

	// Info may describe a copy of the file under a temporary name, so match
	// the name the file has in the artifact.
	isDetectableLib, binaryType, err := isDetectableLibraryExecutable(path.Base(input.FilePath))
	if isDetectableLib && binaryType != "" && err == nil {
		var res *analyzer.AnalysisResult = nil
		switch binaryType {
		case types.PythonExecutable:
			res, err = language.AnalyzePackage(ctx, types.PythonExecutable, input.FilePath, input.Content, pythonparser.NewParser(), false)
		case types.NodeJsExecutable:
			res, err = language.AnalyzePackage(ctx, types.NodeJsExecutable, input.FilePath, input.Content, nodejsparser.NewParser(), false)
		case types.PhpExecutable:
			res, err = language.AnalyzePackage(ctx, types.PhpExecutable, input.FilePath, input.Content, phpparser.NewParser(), false)
		case types.JavaExecutable:
			res, err = language.AnalyzePackage(ctx, types.JavaExecutable, input.FilePath, input.Content, javaparser.NewParser(), false)
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

// Required reports whether the analyzer can detect a version in the file:
// an executable named like a python, node, php, or java interpreter.
func (a executableAnalyzer) Required(filePath string, fileInfo os.FileInfo) bool {
	if !utils.IsExecutable(fileInfo) {
		return false
	}
	detectable, _, _ := isDetectableLibraryExecutable(path.Base(filePath))
	return detectable
}

func (a executableAnalyzer) Type() analyzer.Type {
	return analyzer.TypeExecutable
}

func (a executableAnalyzer) Version() int {
	return version
}
