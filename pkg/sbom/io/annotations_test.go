package io_test

import (
	"testing"

	"github.com/package-url/packageurl-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/sbom/core"
	sbomio "github.com/aquasecurity/trivy/pkg/sbom/io"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/aquasecurity/trivy/pkg/uuid"
)

// TestLayerAnnotations_Encode verifies that ftypes.Layer.Annotations on a
// package are emitted as External properties (verbatim names, no
// aquasecurity:trivy: namespace) on the corresponding CycloneDX component.
// Annotations are an encode-only convenience; consumers read the emitted
// properties directly from the BOM rather than relying on Trivy's decoder
// to restore Layer.Annotations.
func TestLayerAnnotations_Encode(t *testing.T) {
	uuid.SetFakeUUID(t, "8ff14136-e09f-4df9-80ea-%012d")

	const (
		layerARNKey = "aws:lambda:LayerARN"
		layerARN    = "arn:aws:lambda:us-east-1:123456789012:layer:libpsl:3"
		layerTypKey = "aws:lambda:LayerType"
		layerTyp    = "layer"
	)

	pkgUID := "ABCDEF0123456789"
	report := types.Report{
		SchemaVersion: 2,
		ArtifactName:  "my-fn",
		ArtifactType:  ftypes.TypeMultiLayer,
		Results: types.Results{
			{
				Target: "var/task/requirements.txt",
				Class:  types.ClassLangPkg,
				Type:   ftypes.PythonPkg,
				Packages: []ftypes.Package{
					{
						Name:    "requests",
						Version: "2.31.0",
						Identifier: ftypes.PkgIdentifier{
							UID: pkgUID,
							PURL: &packageurl.PackageURL{
								Type:    packageurl.TypePyPi,
								Name:    "requests",
								Version: "2.31.0",
							},
						},
						Layer: ftypes.Layer{
							DiffID: "sha256:aaa",
							Annotations: map[string]string{
								layerARNKey: layerARN,
								layerTypKey: layerTyp,
							},
						},
					},
				},
			},
		},
	}

	// Encode
	bom, err := sbomio.NewEncoder().Encode(report)
	require.NoError(t, err)

	// On encode: the requests component should have External properties for
	// each annotation key (no aquasecurity:trivy: namespace prefix).
	var comp *core.Component
	for _, c := range bom.Components() {
		if c.PkgIdentifier.UID == pkgUID {
			comp = c
			break
		}
	}
	require.NotNil(t, comp, "requests component not found in encoded BOM")

	gotProps := map[string]core.Property{}
	for _, p := range comp.Properties {
		gotProps[p.Name] = p
	}
	require.Contains(t, gotProps, layerARNKey)
	assert.True(t, gotProps[layerARNKey].External, "%s must be emitted as an External property", layerARNKey)
	assert.Equal(t, layerARN, gotProps[layerARNKey].Value)
	require.Contains(t, gotProps, layerTypKey)
	assert.True(t, gotProps[layerTypKey].External)
	assert.Equal(t, layerTyp, gotProps[layerTypKey].Value)
}
