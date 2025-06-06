package jar

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/dependency/parser/java/jar"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/language"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/javadb"
	"github.com/aquasecurity/trivy/pkg/parallel"
	xio "github.com/aquasecurity/trivy/pkg/x/io"
)

func init() {
	analyzer.RegisterPostAnalyzer(analyzer.TypeJar, newJavaLibraryAnalyzer)
}

const version = 1

var requiredExtensions = []string{
	".jar",
	".war",
	".ear",
	".par",
}

// javaLibraryAnalyzer analyzes jar/war/ear/par files
type javaLibraryAnalyzer struct {
	parallel int
}

func newJavaLibraryAnalyzer(options analyzer.AnalyzerOptions) (analyzer.PostAnalyzer, error) {
	return &javaLibraryAnalyzer{
		parallel: options.Parallel,
	}, nil
}

func (a *javaLibraryAnalyzer) PostAnalyze(ctx context.Context, input analyzer.PostAnalysisInput) (*analyzer.AnalysisResult, error) {
	offline := input.Options.Offline

	var javadbClient jar.Client

	if !offline {
		// TODO: think about the sonatype API and "--offline"
		client, err := javadb.NewClient()
		if err != nil {
			return nil, xerrors.Errorf("Unable to initialize the Java DB: %s", err)
		}
		defer func() { _ = client.Close() }()

		// Skip analyzing JAR files as the nil client means the Java DB was not downloaded successfully.
		if client == nil {
			return nil, nil
		}

		javadbClient = client
	}

	// It will be called on each JAR file
	onFile := func(path string, info fs.FileInfo, r xio.ReadSeekerAt) (*types.Application, error) {
		p := jar.NewParser(javadbClient, jar.WithSize(info.Size()), jar.WithOffline(offline), jar.WithFilePath(path))
		return language.ParsePackage(types.Jar, path, r, p, input.Options.FileChecksum)
	}

	var apps []types.Application
	onResult := func(app *types.Application) error {
		if app == nil {
			return nil
		}
		apps = append(apps, *app)
		return nil
	}

	err := parallel.WalkDir(ctx, input.FS, ".", a.parallel, onFile, onResult)
	result := &analyzer.AnalysisResult{
		Applications: apps,
	}
	if err != nil {
		return result, xerrors.Errorf("jar walk error: %w", err)
	}

	return result, nil
}

func (a *javaLibraryAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	ext := filepath.Ext(filePath)
	for _, required := range requiredExtensions {
		if strings.EqualFold(ext, required) {
			return true
		}
	}
	return false
}

func (a *javaLibraryAnalyzer) Type() analyzer.Type {
	return analyzer.TypeJar
}

func (a *javaLibraryAnalyzer) Version() int {
	return version
}
