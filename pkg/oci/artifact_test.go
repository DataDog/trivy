package oci_test

import (
	"bytes"
	"cmp"
	"context"
	"errors"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	fakei "github.com/google/go-containerregistry/pkg/v1/fake"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/remote/transport"
	"github.com/google/go-containerregistry/pkg/v1/static"
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
		annotation    string
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
		{
			name:       "sad: filename with parent traversal",
			mediaType:  "application/vnd.cncf.openpolicyagent.layer.v1.tar+gzip",
			annotation: "../../../etc/passwd",
			layersReturns: layersReturns{
				layers: []v1.Layer{flayer},
			},
			wantErr: `invalid filename "../../../etc/passwd"`,
		},
		{
			name:       "sad: filename with absolute path",
			mediaType:  "application/vnd.cncf.openpolicyagent.layer.v1.tar+gzip",
			annotation: "/etc/passwd",
			layersReturns: layersReturns{
				layers: []v1.Layer{flayer},
			},
			wantErr: `invalid filename "/etc/passwd"`,
		},
		{
			name:       "sad: filename with subdirectory traversal",
			mediaType:  "application/vnd.cncf.openpolicyagent.layer.v1.tar+gzip",
			annotation: "foo/../../bar",
			layersReturns: layersReturns{
				layers: []v1.Layer{flayer},
			},
			wantErr: `invalid filename "foo/../../bar"`,
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
							"org.opencontainers.image.title": cmp.Or(tt.annotation, "bundle.tar.gz"),
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
		canceled bool // the context is done before the download
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
		},
		{
			name:     "connection refused",
			fetchErr: &net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNREFUSED},
		},
		{
			name:     "disk full",
			fetchErr: &fs.PathError{Op: "write", Path: "javadb.tar.gz", Err: syscall.ENOSPC},
			wantErr:  "failed to download artifact from first",
		},
		{
			name:     "canceled",
			fetchErr: context.Canceled,
			canceled: true,
			wantErr:  "failed to download artifact from first",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tempDir := t.TempDir()

			artifacts := oci.Artifacts{
				oci.NewArtifact("first", ftypes.RegistryOptions{}, oci.WithImage(newFakeImage(errLayer{err: tt.fetchErr}))),
				oci.NewArtifact("second", ftypes.RegistryOptions{}, oci.WithImage(newFakeImage(fakeLayer{layer}))),
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if tt.canceled {
				cancel()
			}
			err := artifacts.Download(ctx, tempDir, oci.DownloadOption{Quiet: true})
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

// TestArtifacts_DownloadStall downloads from a registry that stops sending,
// ahead of one that serves the artifact.
func TestArtifacts_DownloadStall(t *testing.T) {
	blob, err := os.ReadFile("testdata/test.tar.gz")
	require.NoError(t, err)

	tests := []struct {
		name string
		sent int // bytes of the layer sent before the stall, -1 for no answer at all
	}{
		{name: "no answer", sent: -1},
		{name: "stalled layer", sent: len(blob) / 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			artifacts := oci.Artifacts{
				oci.NewArtifact(serveArtifact(t, blob, tt.sent), ftypes.RegistryOptions{}),
				oci.NewArtifact(serveArtifact(t, blob, len(blob)), ftypes.RegistryOptions{}),
			}
			dir := t.TempDir()
			start := time.Now()
			err := artifacts.Download(t.Context(), dir, oci.DownloadOption{Quiet: true, StallTimeout: time.Second})
			require.NoError(t, err)
			assert.Less(t, time.Since(start), 10*time.Second)

			got, err := os.ReadFile(filepath.Join(dir, "test.txt"))
			require.NoError(t, err)
			assert.Equal(t, "Hello, world", string(got))
		})
	}
}

// serveArtifact serves blob as the single layer of an artifact from a
// registry in the test, and returns its repository. The registry stalls a
// request for the layer once it has sent the first sent bytes, and every
// request when sent is -1, until the client gives up.
func serveArtifact(t *testing.T, blob []byte, sent int) string {
	t.Helper()
	reg := registry.New()
	var pushed atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !pushed.Load() || sent >= len(blob) {
			reg.ServeHTTP(w, r)
			return
		}
		if sent < 0 {
			<-r.Context().Done()
			return
		}
		rec := httptest.NewRecorder()
		reg.ServeHTTP(rec, r)
		for k, v := range rec.Header() {
			w.Header()[k] = v
		}
		w.WriteHeader(rec.Code)
		if r.Method != http.MethodGet || !bytes.Equal(rec.Body.Bytes(), blob) {
			_, _ = w.Write(rec.Body.Bytes())
			return
		}
		_, _ = w.Write(blob[:sent])
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}))
	t.Cleanup(srv.Close)

	repo := strings.TrimPrefix(srv.URL, "http://") + "/test:1"
	img, err := mutate.Append(empty.Image, mutate.Addendum{
		Layer:       static.NewLayer(blob, "application/vnd.cncf.openpolicyagent.layer.v1.tar+gzip"),
		Annotations: map[string]string{"org.opencontainers.image.title": "bundle.tar.gz"},
	})
	require.NoError(t, err)
	ref, err := name.ParseReference(repo)
	require.NoError(t, err)
	require.NoError(t, remote.Write(ref, img))
	pushed.Store(true)
	return repo
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
