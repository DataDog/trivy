package jar_test

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/dependency/parser/java/jar"
	"github.com/aquasecurity/trivy/pkg/dependency/parser/java/jar/sonatype"
	"github.com/aquasecurity/trivy/pkg/digest"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	xos "github.com/aquasecurity/trivy/pkg/x/os"
)

var (
	// cd testdata/testimage/maven && docker build -t test .
	// docker run --rm --name test -it test bash
	// mvn dependency:list
	// mvn dependency:tree -Dscope=compile -Dscope=runtime | awk '/:tree/,/BUILD SUCCESS/' | awk 'NR > 1 { print }' | head -n -2 | awk '{print $NF}' | awk -F":" '{printf("{\""$1":"$2"\", \""$4 "\", \"\"},\n")}'
	// paths filled in manually
	wantMaven = []ftypes.Package{
		{
			Name:     "com.example:web-app",
			Version:  "1.0-SNAPSHOT",
			FilePath: "testdata/maven.war",
		},
		{
			Name:     "com.fasterxml.jackson.core:jackson-databind",
			Version:  "2.9.10.6",
			FilePath: "testdata/maven.war/WEB-INF/lib/jackson-databind-2.9.10.6.jar",
		},
		{
			Name:     "com.fasterxml.jackson.core:jackson-annotations",
			Version:  "2.9.10",
			FilePath: "testdata/maven.war/WEB-INF/lib/jackson-annotations-2.9.10.jar",
		},
		{
			Name:     "com.fasterxml.jackson.core:jackson-core",
			Version:  "2.9.10",
			FilePath: "testdata/maven.war/WEB-INF/lib/jackson-core-2.9.10.jar",
		},
		{
			Name:     "com.cronutils:cron-utils",
			Version:  "9.1.2",
			FilePath: "testdata/maven.war/WEB-INF/lib/cron-utils-9.1.2.jar",
		},
		{
			Name:     "org.slf4j:slf4j-api",
			Version:  "1.7.30",
			FilePath: "testdata/maven.war/WEB-INF/lib/slf4j-api-1.7.30.jar",
		},
		{
			Name:     "org.glassfish:javax.el",
			Version:  "3.0.0",
			FilePath: "testdata/maven.war/WEB-INF/lib/javax.el-3.0.0.jar",
		},
		{
			Name:     "org.apache.commons:commons-lang3",
			Version:  "3.11",
			FilePath: "testdata/maven.war/WEB-INF/lib/commons-lang3-3.11.jar",
		},
	}

	// cd testdata/testimage/gradle && docker build -t test .
	// docker run --rm --name test -it test bash
	// gradle app:dependencies --configuration implementation | grep "[+\]---" | cut -d" " -f2 | awk -F":" '{printf("{\""$1":"$2"\", \""$3"\", \"\"},\n")}'
	// paths filled in manually
	wantGradle = []ftypes.Package{
		{
			Name:     "commons-dbcp:commons-dbcp",
			Version:  "1.4",
			FilePath: "testdata/gradle.war/WEB-INF/lib/commons-dbcp-1.4.jar",
		},
		{
			Name:     "commons-pool:commons-pool",
			Version:  "1.6",
			FilePath: "testdata/gradle.war/WEB-INF/lib/commons-pool-1.6.jar",
		},
		{
			Name:     "log4j:log4j",
			Version:  "1.2.17",
			FilePath: "testdata/gradle.war/WEB-INF/lib/log4j-1.2.17.jar",
		},
		{
			Name:     "org.apache.commons:commons-compress",
			Version:  "1.19",
			FilePath: "testdata/gradle.war/WEB-INF/lib/commons-compress-1.19.jar",
		},
	}

	// manually created
	wantSHA1 = []ftypes.Package{
		{
			Name:     "org.springframework:spring-core",
			Version:  "5.3.3",
			FilePath: "testdata/test.jar",
		},
	}

	// offline
	wantOffline = []ftypes.Package{
		{
			Name:     "org.springframework:Spring Framework",
			Version:  "2.5.6.SEC03",
			FilePath: "testdata/test.jar",
		},
	}

	// manually created
	wantHeuristic = []ftypes.Package{
		{
			Name:     "com.example:heuristic",
			Version:  "1.0.0-SNAPSHOT",
			FilePath: "testdata/heuristic-1.0.0-SNAPSHOT.jar",
		},
	}

	// manually created
	wantFatjar = []ftypes.Package{
		{
			Name:     "com.google.guava:failureaccess",
			Version:  "1.0.1",
			FilePath: "testdata/hadoop-shaded-guava-1.1.0-SNAPSHOT.jar",
		},
		{
			Name:     "com.google.guava:guava",
			Version:  "29.0-jre",
			FilePath: "testdata/hadoop-shaded-guava-1.1.0-SNAPSHOT.jar",
		},
		{
			Name:     "com.google.guava:listenablefuture",
			Version:  "9999.0-empty-to-avoid-conflict-with-guava",
			FilePath: "testdata/hadoop-shaded-guava-1.1.0-SNAPSHOT.jar",
		},
		{
			Name:     "com.google.j2objc:j2objc-annotations",
			Version:  "1.3",
			FilePath: "testdata/hadoop-shaded-guava-1.1.0-SNAPSHOT.jar",
		},
		{
			Name:     "org.apache.hadoop.thirdparty:hadoop-shaded-guava",
			Version:  "1.1.0-SNAPSHOT",
			FilePath: "testdata/hadoop-shaded-guava-1.1.0-SNAPSHOT.jar",
		},
	}

	// manually created
	wantNestedJar = []ftypes.Package{
		{
			Name:     "test:nested",
			Version:  "0.0.1",
			FilePath: "testdata/nested.jar",
		},
		{
			Name:     "test:nested2",
			Version:  "0.0.2",
			FilePath: "testdata/nested.jar/META-INF/jars/nested2.jar",
		},
		{
			Name:     "test:nested3",
			Version:  "0.0.3",
			FilePath: "testdata/nested.jar/META-INF/jars/nested2.jar/META-INF/jars/nested3.jar",
		},
	}

	// Manually created.
	// Files of `io.quarkus.gizmo.gizmo-1.1.jar` (gizmo:1.1.0 (from sha1)):
	//├── bar
	//│   ├── bar
	//│   │   └── pom.properties (jackson-databind:2.13.4)
	//│   └── foo
	//│       └── pom.properties (jackson-databind:2.12.3)
	//├── foo
	//│   ├── bar
	//│   │   └── pom.properties (jackson-databind:2.12.3)
	//│   └── foo
	//│       └── pom.properties (jackson-databind:2.13.4)
	//├── jars
	//│   ├── log4j-1.2.16.jar (log4j:1.2.16)
	//│   └── log4j-1.2.17.jar (log4j:1.2.17)
	//└── META-INF
	//    ├── INDEX.LIST
	//    ├── MANIFEST.MF
	//    └── maven
	//        └── io.quarkus.gizmo
	//            └── gizmo
	//                ├── pom.properties (gizmo:1.1)
	//                └── pom.xml
	wantDuplicatesJar = []ftypes.Package{
		{
			Name:     "io.quarkus.gizmo:gizmo",
			Version:  "1.1",
			FilePath: "testdata/io.quarkus.gizmo.gizmo-1.1.jar",
		},
		{
			Name:     "log4j:log4j",
			Version:  "1.2.16",
			FilePath: "testdata/io.quarkus.gizmo.gizmo-1.1.jar/jars/log4j-1.2.16.jar",
		},
		{
			Name:     "log4j:log4j",
			Version:  "1.2.17",
			FilePath: "testdata/io.quarkus.gizmo.gizmo-1.1.jar/jars/log4j-1.2.17.jar",
		},
		{
			Name:     "com.fasterxml.jackson.core:jackson-databind",
			Version:  "2.12.3",
			FilePath: "testdata/io.quarkus.gizmo.gizmo-1.1.jar",
		},
		{
			Name:     "com.fasterxml.jackson.core:jackson-databind",
			Version:  "2.13.4",
			FilePath: "testdata/io.quarkus.gizmo.gizmo-1.1.jar",
		},
	}
)

type apiResponse struct {
	Response response `json:"response"`
}

type response struct {
	NumFound int   `json:"numFound"`
	Docs     []doc `json:"docs"`
}

type doc struct {
	ID           string `json:"id"`
	GroupID      string `json:"g"`
	ArtifactID   string `json:"a"`
	Version      string `json:"v"`
	P            string `json:"p"`
	VersionCount int    `json:"versionCount"`
}

func TestParse(t *testing.T) {
	vectors := []struct {
		name    string
		file    string // Test input file
		offline bool
		want    []ftypes.Package
	}{
		{
			name: "maven",
			file: "testdata/maven.war",
			want: wantMaven,
		},
		{
			name: "gradle",
			file: "testdata/gradle.war",
			want: wantGradle,
		},
		{
			name: "nested jars",
			file: "testdata/nested.jar",
			want: wantNestedJar,
		},
		{
			name: "sha1 search",
			file: "testdata/test.jar",
			want: wantSHA1,
		},
		{
			name:    "offline",
			file:    "testdata/test.jar",
			offline: true,
			want:    wantOffline,
		},
		{
			name: "artifactId search",
			file: "testdata/heuristic-1.0.0-SNAPSHOT.jar",
			want: wantHeuristic,
		},
		{
			name: "fat jar",
			file: "testdata/hadoop-shaded-guava-1.1.0-SNAPSHOT.jar",
			want: wantFatjar,
		},
		{
			name: "duplicate libraries",
			file: "testdata/io.quarkus.gizmo.gizmo-1.1.jar",
			want: wantDuplicatesJar,
		},
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		res := apiResponse{
			Response: response{
				NumFound: 1,
			},
		}

		switch {
		case strings.Contains(r.URL.Query().Get("q"), "springframework"):
			res.Response.NumFound = 0
		case strings.Contains(r.URL.Query().Get("q"), "c666f5bc47eb64ed3bbd13505a26f58be71f33f0"):
			res.Response.Docs = []doc{
				{
					ID:         "org.springframework.spring-core",
					GroupID:    "org.springframework",
					ArtifactID: "spring-core",
					Version:    "5.3.3",
				},
			}
		case strings.Contains(r.URL.Query().Get("q"), "Gizmo"):
			res.Response.NumFound = 0
		case strings.Contains(r.URL.Query().Get("q"), "1c78bbc4d8c58b9af8eee82b84f2c26ec48e9a2b"):
			res.Response.Docs = []doc{
				{
					ID:         "io.quarkus.gizmo.gizmo",
					GroupID:    "io.quarkus.gizmo",
					ArtifactID: "gizmo",
					Version:    "1.1.0",
				},
			}
		case strings.Contains(r.URL.Query().Get("q"), "heuristic"):
			res.Response.Docs = []doc{
				{
					ID:           "org.springframework.heuristic",
					GroupID:      "org.springframework",
					ArtifactID:   "heuristic",
					VersionCount: 10,
				},
				{
					ID:           "com.example.heuristic",
					GroupID:      "com.example",
					ArtifactID:   "heuristic",
					VersionCount: 100,
				},
			}
		}
		_ = json.NewEncoder(w).Encode(res)
	}))

	for _, v := range vectors {
		t.Run(v.name, func(t *testing.T) {
			f, err := os.Open(v.file)
			require.NoError(t, err)

			stat, err := f.Stat()
			require.NoError(t, err)

			c := sonatype.New(sonatype.WithURL(ts.URL), sonatype.WithHTTPClient(ts.Client()))
			p := jar.NewParser(c, jar.WithFilePath(v.file), jar.WithOffline(v.offline), jar.WithSize(stat.Size()))

			got, _, err := p.Parse(t.Context(), f)
			require.NoError(t, err)

			sort.Sort(ftypes.Packages(got))
			sort.Sort(ftypes.Packages(v.want))

			assert.Equal(t, v.want, got)
		})
	}
}

// A notFoundClient is a Client that finds no artifact. It calls onCall, if
// set, at each search.
type notFoundClient struct {
	onCall func()
}

func (c notFoundClient) call() {
	if c.onCall != nil {
		c.onCall()
	}
}

func (c notFoundClient) Exists(_, _ string) (bool, error) {
	c.call()
	return false, nil
}

func (c notFoundClient) SearchBySHA1(_ string) (jar.Properties, error) {
	c.call()
	return jar.Properties{}, jar.ArtifactNotFoundErr
}

func (c notFoundClient) SearchByArtifactID(_, _ string) (string, error) {
	c.call()
	return "", jar.ArtifactNotFoundErr
}

// A zipEntry is a file in an archive made by makeZip.
type zipEntry struct {
	name string
	data []byte
}

// makeZip returns a zip archive of entries, each compressed with method.
func makeZip(t testing.TB, method uint16, entries ...zipEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for _, e := range entries {
		f, err := w.CreateHeader(&zip.FileHeader{Name: e.name, Method: method})
		require.NoError(t, err)
		_, err = f.Write(e.data)
		require.NoError(t, err)
	}
	require.NoError(t, w.Close())
	return buf.Bytes()
}

// pomProperties returns the pom.properties entry of test:artifactID:version.
func pomProperties(artifactID, version string) zipEntry {
	return zipEntry{
		name: "META-INF/maven/test/" + artifactID + "/pom.properties",
		data: []byte("groupId=test\nartifactId=" + artifactID + "\nversion=" + version + "\n"),
	}
}

func TestParser_Digest(t *testing.T) {
	// The pom.properties of app-1.0.jar matches its name, so Parse searches
	// for the nested jar by SHA-1 and not for app-1.0.jar.
	app := makeZip(t, zip.Deflate,
		pomProperties("app", "1.0"),
		zipEntry{name: "lib/inner.jar", data: makeZip(t, zip.Deflate, zipEntry{name: "Inner.class"})},
	)
	tests := []struct {
		name    string
		file    string
		data    []byte // contents of file, read from disk if nil
		offline bool
		want    digest.Digest
	}{
		{
			name: "searched by sha1",
			file: "testdata/test.jar",
			want: "sha1:c666f5bc47eb64ed3bbd13505a26f58be71f33f0",
		},
		{
			name: "searched by sha1 with nested jars",
			file: "testdata/nested.jar",
			want: "sha1:16e646495b935f0439ba13d4b3da8d7b12e98117",
		},
		{
			name: "found by pom.properties",
			file: "testdata/hadoop-shaded-guava-1.1.0-SNAPSHOT.jar",
		},
		{
			name: "nested jar searched by sha1",
			file: "app-1.0.jar",
			data: app,
		},
		{
			name:    "offline",
			file:    "testdata/test.jar",
			offline: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := tt.data
			if data == nil {
				var err error
				data, err = os.ReadFile(tt.file)
				require.NoError(t, err)
			}

			p := jar.NewParser(notFoundClient{}, jar.WithFilePath(tt.file), jar.WithOffline(tt.offline),
				jar.WithSize(int64(len(data))))
			_, _, err := p.Parse(t.Context(), bytes.NewReader(data))
			require.NoError(t, err)
			assert.Equal(t, tt.want, p.Digest())
		})
	}
}

func TestParse_nestedArchive(t *testing.T) {
	want := []ftypes.Package{
		{
			Name:     "test:inner",
			Version:  "1.0",
			FilePath: "app.jar/lib/inner.jar",
		},
		{
			Name:     "test:innermost",
			Version:  "1.0",
			FilePath: "app.jar/lib/inner.jar/lib/innermost.jar",
		},
	}
	tests := []struct {
		name          string
		method        uint16
		prefix        string // data before the zip archive
		wantTempFiles int
	}{
		{
			name:   "stored",
			method: zip.Store,
		},
		{
			name:   "stored after a launch script",
			method: zip.Store,
			prefix: "#!/bin/sh\nexec java -jar \"$0\" \"$@\"\n",
		},
		{
			name:          "deflated",
			method:        zip.Deflate,
			wantTempFiles: 2,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// No pom.properties names its jar, so Parse searches for each
			// jar by SHA-1 while it holds the jar open.
			innermost := makeZip(t, tt.method, pomProperties("innermost", "1.0"))
			inner := makeZip(t, tt.method, pomProperties("inner", "1.0"),
				zipEntry{name: "lib/innermost.jar", data: innermost})
			app := append([]byte(tt.prefix), makeZip(t, tt.method, zipEntry{name: "lib/inner.jar", data: inner})...)

			var tempFiles int
			c := notFoundClient{onCall: func() {
				des, err := os.ReadDir(xos.TempDir())
				require.NoError(t, err)
				tempFiles = max(tempFiles, len(des))
			}}
			p := jar.NewParser(c, jar.WithFilePath("app.jar"), jar.WithSize(int64(len(app))))
			got, _, err := p.Parse(t.Context(), bytes.NewReader(app))
			require.NoError(t, err)
			assert.Equal(t, want, got)
			assert.Equal(t, tt.wantTempFiles, tempFiles, "temp files")
		})
	}
}

func TestParse_nestedArchivePastEnd(t *testing.T) {
	inner := makeZip(t, zip.Store, pomProperties("inner", "1.0"))
	app := makeZip(t, zip.Store, zipEntry{name: "lib/inner.jar", data: inner}, pomProperties("later", "1.0"))

	// Give lib/inner.jar a size in the central directory that runs 300
	// bytes past the end of app.jar.
	zr, err := zip.NewReader(bytes.NewReader(app), int64(len(app)))
	require.NoError(t, err)
	off, err := zr.File[0].DataOffset()
	require.NoError(t, err)
	le := binary.LittleEndian
	cd := le.Uint32(app[len(app)-22+16:]) // from the end of central directory record
	size := uint32(int64(len(app)) - off + 300)
	le.PutUint32(app[cd+20:], size) // compressed size
	le.PutUint32(app[cd+24:], size) // uncompressed size

	p := jar.NewParser(notFoundClient{}, jar.WithFilePath("app.jar"), jar.WithSize(int64(len(app))))
	got, _, err := p.Parse(t.Context(), bytes.NewReader(app))
	require.NoError(t, err)
	want := []ftypes.Package{
		{
			Name:     "test:later",
			Version:  "1.0",
			FilePath: "app.jar",
		},
	}
	assert.Equal(t, want, got)
}

func BenchmarkParse_nestedArchive(b *testing.B) {
	for _, bb := range []struct {
		name   string
		method uint16
	}{
		{
			name:   "stored",
			method: zip.Store,
		},
		{
			name:   "deflated",
			method: zip.Deflate,
		},
	} {
		b.Run(bb.name, func(b *testing.B) {
			// A fat jar of 32 jars, each holding 64 class files of 4 KiB.
			const n = 32
			rng := rand.NewChaCha8([32]byte{})
			var libs []zipEntry
			for i := range n {
				lib := []zipEntry{pomProperties(fmt.Sprintf("lib%d", i), "1.0")}
				for j := range 64 {
					class := make([]byte, 4<<10)
					_, _ = rng.Read(class) // ChaCha8.Read always fills class.
					lib = append(lib, zipEntry{name: fmt.Sprintf("lib%d/Class%d.class", i, j), data: class})
				}
				libs = append(libs, zipEntry{
					name: fmt.Sprintf("BOOT-INF/lib/lib%d-1.0.jar", i),
					data: makeZip(b, zip.Store, lib...),
				})
			}
			app := makeZip(b, bb.method, libs...)

			p := jar.NewParser(nil, jar.WithFilePath("app.jar"), jar.WithOffline(true), jar.WithSize(int64(len(app))))
			b.ReportAllocs()
			for b.Loop() {
				got, _, err := p.Parse(b.Context(), bytes.NewReader(app))
				require.NoError(b, err)
				require.Len(b, got, n)
			}
		})
	}
}

func TestParse_nestingDepth(t *testing.T) {
	// level0.jar holds level1.jar, which holds level2.jar, and so on.
	const levels = 10
	data := makeZip(t, zip.Store, pomProperties(fmt.Sprint("level", levels), "1.0"))
	for i := levels - 1; i >= 0; i-- {
		data = makeZip(t, zip.Store, pomProperties(fmt.Sprint("level", i), "1.0"),
			zipEntry{name: fmt.Sprintf("level%d.jar", i+1), data: data})
	}

	p := jar.NewParser(nil, jar.WithFilePath("level0.jar"), jar.WithOffline(true), jar.WithSize(int64(len(data))))
	got, _, err := p.Parse(t.Context(), bytes.NewReader(data))
	require.NoError(t, err)

	// Parse reads the archives nested up to 8 deep.
	var want []ftypes.Package
	filePath := "level0.jar"
	for i := range 9 {
		want = append(want, ftypes.Package{
			Name:     fmt.Sprintf("test:level%d", i),
			Version:  "1.0",
			FilePath: filePath,
		})
		filePath += fmt.Sprintf("/level%d.jar", i+1)
	}
	assert.Equal(t, want, got)
}

// A countingReader counts the bytes read from r.
type countingReader struct {
	r *bytes.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

func (c *countingReader) ReadAt(p []byte, off int64) (int, error) {
	n, err := c.r.ReadAt(p, off)
	c.n += int64(n)
	return n, err
}

func (c *countingReader) Seek(offset int64, whence int) (int64, error) {
	return c.r.Seek(offset, whence)
}

func TestParse_cancel(t *testing.T) {
	// Parse searches for each of these jars by SHA-1.
	lib := func(name string) zipEntry {
		return zipEntry{
			name: "lib/" + name + ".jar",
			data: makeZip(t, zip.Store, zipEntry{name: name + ".class"}),
		}
	}
	tests := []struct {
		name     string
		entries  []zipEntry
		cancelAt int // the search that cancels the context, or 0 to cancel it before Parse
	}{
		{
			name:    "before parse",
			entries: []zipEntry{lib("a"), lib("b")},
		},
		{
			name:     "between entries",
			entries:  []zipEntry{lib("a"), lib("b")},
			cancelAt: 1,
		},
		{
			name:     "in the last entry",
			entries:  []zipEntry{lib("a")},
			cancelAt: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app := makeZip(t, zip.Store, tt.entries...)
			r := &countingReader{r: bytes.NewReader(app)}

			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if tt.cancelAt == 0 {
				cancel()
			}
			var searches int
			var read int64 // bytes read when the context was canceled
			c := notFoundClient{onCall: func() {
				searches++
				if searches == tt.cancelAt {
					cancel()
					read = r.n
				}
			}}

			p := jar.NewParser(c, jar.WithFilePath("app.jar"), jar.WithSize(int64(len(app))))
			_, _, err := p.Parse(ctx, r)
			require.ErrorIs(t, err, context.Canceled)
			assert.Equal(t, read, r.n, "bytes read")
		})
	}
}
