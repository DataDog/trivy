package jar

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/javadb"
	"github.com/aquasecurity/trivy/pkg/mapfs"

	_ "modernc.org/sqlite"
)

func Test_javaLibraryAnalyzer_Analyze(t *testing.T) {
	tests := []struct {
		name            string
		inputFile       string
		includeChecksum bool
		want            *analyzer.AnalysisResult
	}{
		{
			name:      "happy path (WAR file)",
			inputFile: "testdata/test.war",
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.Jar,
						FilePath: "testdata/test.war",
						Packages: types.Packages{
							{
								Name:     "org.glassfish:javax.el",
								FilePath: "testdata/test.war/WEB-INF/lib/javax.el-3.0.0.jar",
								Version:  "3.0.0",
							},
							{
								Name:     "com.fasterxml.jackson.core:jackson-databind",
								FilePath: "testdata/test.war/WEB-INF/lib/jackson-databind-2.9.10.6.jar",
								Version:  "2.9.10.6",
							},
							{
								Name:     "com.fasterxml.jackson.core:jackson-annotations",
								FilePath: "testdata/test.war/WEB-INF/lib/jackson-annotations-2.9.10.jar",
								Version:  "2.9.10",
							},
							{
								Name:     "com.fasterxml.jackson.core:jackson-core",
								FilePath: "testdata/test.war/WEB-INF/lib/jackson-core-2.9.10.jar",
								Version:  "2.9.10",
							},
							{
								Name:     "org.slf4j:slf4j-api",
								FilePath: "testdata/test.war/WEB-INF/lib/slf4j-api-1.7.30.jar",
								Version:  "1.7.30",
							},
							{
								Name:     "com.cronutils:cron-utils",
								FilePath: "testdata/test.war/WEB-INF/lib/cron-utils-9.1.2.jar",
								Version:  "9.1.2",
							},
							{
								Name:     "org.apache.commons:commons-lang3",
								FilePath: "testdata/test.war/WEB-INF/lib/commons-lang3-3.11.jar",
								Version:  "3.11",
							},
							{
								Name:     "com.example:web-app",
								FilePath: "testdata/test.war",
								Version:  "1.0-SNAPSHOT",
							},
						},
					},
				},
			},
		},
		{
			name:            "happy path (PAR file)",
			inputFile:       "testdata/test.par",
			includeChecksum: true,
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.Jar,
						FilePath: "testdata/test.par",
						Packages: types.Packages{
							{
								Name:     "com.fasterxml.jackson.core:jackson-core",
								FilePath: "testdata/test.par/lib/jackson-core-2.9.10.jar",
								Version:  "2.9.10",
								Digest:   "sha1:d40913470259cfba6dcc90f96bcaa9bcff1b72e0",
							},
						},
					},
				},
			},
		},
		{
			name:      "happy path (package found in trivy-java-db by sha1)",
			inputFile: "testdata/test.jar",
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.Jar,
						FilePath: "testdata/test.jar",
						Packages: types.Packages{
							{
								Name:     "org.apache.tomcat.embed:tomcat-embed-websocket",
								FilePath: "testdata/test.jar",
								Version:  "9.0.65",
							},
						},
					},
				},
			},
		},
		{
			name:      "sad path",
			inputFile: "testdata/test.txt",
			want:      &analyzer.AnalysisResult{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// init java-trivy-db with skip update
			repo, err := name.NewTag(javadb.DefaultGHCRRepository)
			require.NoError(t, err)
			javadb.Init("testdata", []name.Reference{repo}, true, false, types.RegistryOptions{Insecure: false})

			a := javaLibraryAnalyzer{}
			ctx := t.Context()

			mfs := mapfs.New()
			err = mfs.MkdirAll(filepath.Dir(tt.inputFile), os.ModePerm)
			require.NoError(t, err)
			err = mfs.WriteFile(tt.inputFile, tt.inputFile)
			require.NoError(t, err)

			got, err := a.PostAnalyze(ctx, analyzer.PostAnalysisInput{
				FS:      mfs,
				Options: analyzer.AnalysisOptions{FileChecksum: tt.includeChecksum},
			})

			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

// A countingFS counts the bytes read with Read from the files it opens.
// Hashing a jar reads it with Read, and the zip reader uses ReadAt.
type countingFS struct {
	*mapfs.FS
	n atomic.Int64
}

func (fsys *countingFS) Open(path string) (fs.File, error) {
	f, err := fsys.FS.Open(path)
	if err != nil {
		return nil, err
	}
	rf, ok := f.(readSeekerAtFile)
	if !ok {
		return f, nil
	}
	return countingFile{rf, &fsys.n}, nil
}

type readSeekerAtFile interface {
	fs.File
	io.Seeker
	io.ReaderAt
}

type countingFile struct {
	readSeekerAtFile
	n *atomic.Int64
}

func (f countingFile) Read(p []byte) (int, error) {
	n, err := f.readSeekerAtFile.Read(p)
	f.n.Add(int64(n))
	return n, err
}

func Test_javaLibraryAnalyzer_hashOnce(t *testing.T) {
	tests := []struct {
		name      string
		inputFile string
		want      *analyzer.AnalysisResult
	}{
		{
			name:      "jar found in trivy-java-db by sha1",
			inputFile: "testdata/test.jar",
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.Jar,
						FilePath: "testdata/test.jar",
						Packages: types.Packages{
							{
								Name:     "org.apache.tomcat.embed:tomcat-embed-websocket",
								FilePath: "testdata/test.jar",
								Version:  "9.0.65",
								Digest:   "sha1:bd70dfeb39cc83c6934be24fa377b21e541dbe76",
							},
						},
					},
				},
			},
		},
		{
			name:      "par not found in trivy-java-db",
			inputFile: "testdata/test.par",
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.Jar,
						FilePath: "testdata/test.par",
						Packages: types.Packages{
							{
								Name:     "com.fasterxml.jackson.core:jackson-core",
								FilePath: "testdata/test.par/lib/jackson-core-2.9.10.jar",
								Version:  "2.9.10",
								Digest:   "sha1:d40913470259cfba6dcc90f96bcaa9bcff1b72e0",
							},
						},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo, err := name.NewTag(javadb.DefaultGHCRRepository)
			require.NoError(t, err)
			javadb.Init("testdata", []name.Reference{repo}, true, false, types.RegistryOptions{Insecure: false})

			mfs := mapfs.New()
			err = mfs.MkdirAll(filepath.Dir(tt.inputFile), os.ModePerm)
			require.NoError(t, err)
			err = mfs.WriteFile(tt.inputFile, tt.inputFile)
			require.NoError(t, err)
			fsys := &countingFS{FS: mfs}

			a := javaLibraryAnalyzer{}
			got, err := a.PostAnalyze(t.Context(), analyzer.PostAnalysisInput{
				FS:      fsys,
				Options: analyzer.AnalysisOptions{FileChecksumJar: true},
			})
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)

			// The Java DB search and the checksum share one read of the jar.
			fi, err := os.Stat(tt.inputFile)
			require.NoError(t, err)
			assert.Equal(t, fi.Size(), fsys.n.Load(), "bytes read")
		})
	}
}

func Benchmark_javaLibraryAnalyzer_PostAnalyze(b *testing.B) {
	repo, err := name.NewTag(javadb.DefaultGHCRRepository)
	require.NoError(b, err)
	javadb.Init("testdata", []name.Reference{repo}, true, false, types.RegistryOptions{Insecure: false})

	// Copies of a jar found in trivy-java-db by sha1.
	const n = 16
	mfs := mapfs.New()
	for i := range n {
		dir := fmt.Sprintf("lib%d", i)
		require.NoError(b, mfs.MkdirAll(dir, os.ModePerm))
		require.NoError(b, mfs.WriteFile(dir+"/test.jar", "testdata/test.jar"))
	}

	a := javaLibraryAnalyzer{parallel: 1}
	b.ReportAllocs()
	for b.Loop() {
		got, err := a.PostAnalyze(b.Context(), analyzer.PostAnalysisInput{
			FS:      mfs,
			Options: analyzer.AnalysisOptions{FileChecksumJar: true},
		})
		require.NoError(b, err)
		require.Len(b, got.Applications, n)
	}
}

func Test_javaLibraryAnalyzer_Required(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
		want     bool
	}{
		{
			name:     "war",
			filePath: "test/test.war",
			want:     true,
		},
		{
			name:     "jar",
			filePath: "test.jar",
			want:     true,
		},
		{
			name:     "ear",
			filePath: "a/b/c/d/test.ear",
			want:     true,
		},
		{
			name:     "capital jar",
			filePath: "a/b/c/d/test.JAR",
			want:     true,
		},
		{
			name:     "zip",
			filePath: "test.zip",
			want:     false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := javaLibraryAnalyzer{}
			got := a.Required(tt.filePath, nil)
			assert.Equal(t, tt.want, got)
		})
	}
}
