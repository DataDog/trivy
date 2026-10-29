package multilayer_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/cache"
	"github.com/aquasecurity/trivy/pkg/fanal/artifact"
	"github.com/aquasecurity/trivy/pkg/fanal/artifact/multilayer"
	"github.com/aquasecurity/trivy/pkg/fanal/types"

	_ "github.com/aquasecurity/trivy/pkg/fanal/analyzer/language/java/pom"
)

const parentPOM = `<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>parent</artifactId>
  <version>1.0.0</version>
  <packaging>pom</packaging>
  <dependencyManagement>
    <dependencies>
      <dependency>
        <groupId>org.example</groupId>
        <artifactId>example-api</artifactId>
        <version>1.7.30</version>
      </dependency>
    </dependencies>
  </dependencyManagement>
</project>
`

const childPOM = `<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <parent>
    <groupId>com.example</groupId>
    <artifactId>parent</artifactId>
    <version>1.0.0</version>
  </parent>
  <artifactId>child</artifactId>
  <dependencies>
    <dependency>
      <groupId>org.example</groupId>
      <artifactId>example-api</artifactId>
    </dependency>
  </dependencies>
</project>
`

// oneLayer is a multilayer source with a single layer at path.
type oneLayer string

func (l oneLayer) ID() (string, error) { return "sha256:artifact", nil }

func (l oneLayer) Name() string { return "test" }

func (l oneLayer) Layers() []types.LayerSource {
	return []types.LayerSource{{Path: string(l), DiffID: "sha256:layer"}}
}

// The child POM takes the version of its dependency from the dependency
// management of its parent, which the pom analyzer reads from the layer on
// disk next to the child.
func TestArtifact_InspectParentPOM(t *testing.T) {
	dir := t.TempDir()
	for name, data := range map[string]string{
		"app/pom.xml":       parentPOM,
		"app/child/pom.xml": childPOM,
	} {
		p := filepath.Join(dir, name)
		require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o755))
		require.NoError(t, os.WriteFile(p, []byte(data), 0o644))
	}

	c := cache.NewMemoryCache()
	a, err := multilayer.NewArtifact(oneLayer(dir), c, artifact.Option{Offline: true})
	require.NoError(t, err)
	ref, err := a.Inspect(t.Context())
	require.NoError(t, err)
	require.Len(t, ref.BlobIDs, 1)
	blob, err := c.GetBlob(t.Context(), ref.BlobIDs[0])
	require.NoError(t, err)

	versions := make(map[string]string)
	for _, app := range blob.Applications {
		if app.FilePath != "app/child/pom.xml" {
			continue
		}
		for _, pkg := range app.Packages {
			versions[pkg.Name] = pkg.Version
		}
	}
	assert.Equal(t, "1.7.30", versions["org.example:example-api"])
}
