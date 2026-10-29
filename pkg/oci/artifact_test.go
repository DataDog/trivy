package oci_test

import (
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	fakei "github.com/google/go-containerregistry/pkg/v1/fake"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/oci"
)

type fakeLayer struct {
	v1.Layer
}

func (f fakeLayer) MediaType() (types.MediaType, error) {
	return "application/vnd.cncf.openpolicyagent.layer.v1.tar+gzip", nil
}

// errLayer is a layer whose content cannot be fetched.
type errLayer struct {
	v1.Layer
	err error
}

func (l errLayer) MediaType() (types.MediaType, error) {
	return "application/vnd.cncf.openpolicyagent.layer.v1.tar+gzip", nil
}

func (l errLayer) Compressed() (io.ReadCloser, error) {
	return nil, l.err
}

func TestArtifact_Download(t *testing.T) {
	layer, err := tarball.LayerFromFile("testdata/test.tar.gz")
	require.NoError(t, err)

	txtLayer, err := tarball.LayerFromFile("testdata/test.txt")
	require.NoError(t, err)

	flayer := fakeLayer{layer}

	type layersReturns struct {
		layers []v1.Layer
		err    error
	}
	tests := []struct {
		name          string
		input         string
		mediaType     string
		layersReturns layersReturns
		want          string
		wantErr       string
	}{
		{
			name:      "happy path",
			input:     "testdata/test.tar.gz",
			mediaType: "application/vnd.cncf.openpolicyagent.layer.v1.tar+gzip",
			layersReturns: layersReturns{
				layers: []v1.Layer{flayer},
			},
			want: "Hello, world",
		},
		{
			name:      "sad: two layers",
			mediaType: "application/vnd.cncf.openpolicyagent.layer.v1.tar+gzip",
			layersReturns: layersReturns{
				layers: []v1.Layer{
					layer,
					layer,
				},
			},
			wantErr: "OCI artifact must be a single layer",
		},
		{
			name:      "sad: Layers returns an error",
			mediaType: "application/vnd.cncf.openpolicyagent.layer.v1.tar+gzip",
			layersReturns: layersReturns{
				err: errors.New("error"),
			},
			wantErr: "OCI layer error",
		},
		{
			name:  "invalid gzip",
			input: "testdata/test.txt",
			layersReturns: layersReturns{
				layers: []v1.Layer{txtLayer},
			},
			wantErr: "unexpected EOF",
		},
		{
			name:      "sad: media type doesn't match",
			mediaType: "unknown",
			layersReturns: layersReturns{
				layers: []v1.Layer{layer},
			},
			wantErr: "unacceptable media type",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tempDir := t.TempDir()

			// Mock image
			img := new(fakei.FakeImage)
			img.LayersReturns(tt.layersReturns.layers, tt.layersReturns.err)
			img.ManifestReturns(&v1.Manifest{
				Layers: []v1.Descriptor{
					{
						MediaType: "application/vnd.cncf.openpolicyagent.layer.v1.tar+gzip",
						Size:      100,
						Digest: v1.Hash{
							Algorithm: "sha256",
							Hex:       "cba33656188782852f58993f45b68bfb8577f64cdcf02a604e3fc2afbeb5f2d8",
						},
						Annotations: map[string]string{
							"org.opencontainers.image.title": "bundle.tar.gz",
						},
					},
				},
			}, nil)

			artifact := oci.NewArtifact("repo", ftypes.RegistryOptions{}, oci.WithImage(img))
			err = artifact.Download(t.Context(), tempDir, oci.DownloadOption{
				MediaType: tt.mediaType,
				Quiet:     true,
			})
			if tt.wantErr != "" {
				assert.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)

			// Assert
			got, err := os.ReadFile(filepath.Join(tempDir, "test.txt"))
			require.NoError(t, err)

			assert.Equal(t, tt.want, string(got))
		})
	}
}

func TestArtifacts_Download(t *testing.T) {
	layer, err := tarball.LayerFromFile("testdata/test.tar.gz")
	require.NoError(t, err)

	tests := []struct {
		name     string
		fetchErr error
		wantErr  string
	}{
		{
			name:     "not found",
			fetchErr: &transport.Error{StatusCode: http.StatusNotFound},
		},
		{
			name: "unauthorized",
			fetchErr: &transport.Error{
				Errors:     []transport.Diagnostic{{Code: transport.UnauthorizedErrorCode}},
				StatusCode: http.StatusUnauthorized,
			},
			wantErr: "failed to download artifact from first",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tempDir := t.TempDir()

			artifacts := oci.Artifacts{
				oci.NewArtifact("first", ftypes.RegistryOptions{}, oci.WithImage(newFakeImage(errLayer{err: tt.fetchErr}))),
				oci.NewArtifact("second", ftypes.RegistryOptions{}, oci.WithImage(newFakeImage(fakeLayer{layer}))),
			}
			err := artifacts.Download(t.Context(), tempDir, oci.DownloadOption{Quiet: true})
			if tt.wantErr != "" {
				assert.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)

			got, err := os.ReadFile(filepath.Join(tempDir, "test.txt"))
			require.NoError(t, err)
			assert.Equal(t, "Hello, world", string(got))
		})
	}
}

func newFakeImage(layer v1.Layer) v1.Image {
	img := new(fakei.FakeImage)
	img.LayersReturns([]v1.Layer{layer}, nil)
	img.ManifestReturns(&v1.Manifest{
		Layers: []v1.Descriptor{
			{
				MediaType: "application/vnd.cncf.openpolicyagent.layer.v1.tar+gzip",
				Annotations: map[string]string{
					"org.opencontainers.image.title": "bundle.tar.gz",
				},
			},
		},
	}, nil)
	return img
}
