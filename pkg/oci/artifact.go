package oci

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/hashicorp/go-multierror"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/downloader"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/remote"
	xio "github.com/aquasecurity/trivy/pkg/x/io"
	xos "github.com/aquasecurity/trivy/pkg/x/os"
	xslices "github.com/aquasecurity/trivy/pkg/x/slices"
)

const (
	// Artifact types
	CycloneDXArtifactType = "application/vnd.cyclonedx+json"
	SPDXArtifactType      = "application/spdx+json"

	// Sigstore bundle artifact type for Cosign attestations in "new bundle format" > 2.5.0
	SigstoreBundleArtifactType = "application/vnd.dev.sigstore.bundle.v0.3+json"

	// Media types
	OCIImageManifest = "application/vnd.oci.image.manifest.v1+json"

	// Annotations
	titleAnnotation = "org.opencontainers.image.title"
)

var SupportedSBOMArtifactTypes = []string{
	CycloneDXArtifactType,
	SPDXArtifactType,
	SigstoreBundleArtifactType,
}

// Option is a functional option
type Option func(*Artifact)

// WithImage takes an OCI v1 Image
func WithImage(img v1.Image) Option {
	return func(a *Artifact) {
		a.image = img
	}
}

// Artifact is used to download artifacts such as vulnerability database and policies from OCI registries.
type Artifact struct {
	m          sync.Mutex
	repository string

	// For OCI registries
	types.RegistryOptions

	image v1.Image // For testing
}

// NewArtifact returns a new artifact
func NewArtifact(repo string, registryOpt types.RegistryOptions, opts ...Option) *Artifact {
	art := &Artifact{
		repository:      repo,
		RegistryOptions: registryOpt,
	}

	for _, o := range opts {
		o(art)
	}
	return art
}

func (a *Artifact) populate(ctx context.Context, opt types.RegistryOptions) error {
	if a.image != nil {
		return nil
	}

	a.m.Lock()
	defer a.m.Unlock()

	var nameOpts []name.Option
	if opt.Insecure {
		nameOpts = append(nameOpts, name.Insecure)
	}

	ref, err := name.ParseReference(a.repository, nameOpts...)
	if err != nil {
		return xerrors.Errorf("repository name error (%s): %w", a.repository, err)
	}

	a.image, err = remote.Image(ctx, ref, opt)
	if err != nil {
		return xerrors.Errorf("OCI repository error: %w", err)
	}
	return nil
}

type DownloadOption struct {
	MediaType string // Accept any media type if not specified
	Filename  string // Use the annotation if not specified
	Quiet     bool

	// StallTimeout, if set, ends a download that receives no data for that
	// long: no answer from the registry, or no byte of the layer.
	StallTimeout time.Duration
}

var errStalled = errors.New("download stalled")

func (a *Artifact) Download(ctx context.Context, dir string, opt DownloadOption) error {
	if opt.StallTimeout <= 0 {
		return a.downloadLayer(ctx, dir, opt, nil)
	}
	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	stall := time.AfterFunc(opt.StallTimeout, func() { cancel(errStalled) })
	defer stall.Stop()
	err := a.downloadLayer(ctx, dir, opt, stall)
	if err != nil && errors.Is(context.Cause(ctx), errStalled) {
		return xerrors.Errorf("no data for %s: %w", opt.StallTimeout, err)
	}
	return err
}

// downloadLayer downloads the layer of the artifact into dir. When stall is
// set, each read of the layer resets it to opt.StallTimeout.
func (a *Artifact) downloadLayer(ctx context.Context, dir string, opt DownloadOption, stall *time.Timer) error {
	if err := a.populate(ctx, a.RegistryOptions); err != nil {
		return err
	}

	layers, err := a.image.Layers()
	if err != nil {
		return xerrors.Errorf("OCI layer error: %w", err)
	}

	manifest, err := a.image.Manifest()
	if err != nil {
		return xerrors.Errorf("OCI manifest error: %w", err)
	}

	// A single layer is only supported now.
	if len(layers) != 1 || len(manifest.Layers) != 1 {
		return xerrors.Errorf("OCI artifact must be a single layer")
	}

	// Take the first layer
	layer := layers[0]

	// Take the file name of the first layer if not specified
	fileName := opt.Filename
	if fileName == "" {
		v, ok := manifest.Layers[0].Annotations[titleAnnotation]
		if !ok {
			return xerrors.Errorf("annotation %s is missing", titleAnnotation)
		}
		fileName = v
	}

	layerMediaType, err := layer.MediaType()
	if err != nil {
		return xerrors.Errorf("media type error: %w", err)
	} else if opt.MediaType != "" && opt.MediaType != string(layerMediaType) {
		return xerrors.Errorf("unacceptable media type: %s", string(layerMediaType))
	}

	if err = a.download(ctx, layer, fileName, dir, opt.Quiet, stall, opt.StallTimeout); err != nil {
		return xerrors.Errorf("oci download error: %w", err)
	}

	return nil
}

func (a *Artifact) download(ctx context.Context, layer v1.Layer, fileName, dir string, quiet bool, stall *time.Timer, stallTimeout time.Duration) error {
	rc, err := layer.Compressed()
	if err != nil {
		return xerrors.Errorf("failed to fetch the layer: %w", err)
	}
	defer rc.Close()

	// https://github.com/hashicorp/go-getter/issues/326
	tempDir, err := xos.MkdirTemp("", "oci-download-")
	if err != nil {
		return xerrors.Errorf("failed to create a temp dir: %w", err)
	}

	f, err := os.Create(filepath.Join(tempDir, fileName))
	if err != nil {
		return xerrors.Errorf("failed to create a temp file: %w", err)
	}
	defer func() {
		_ = f.Close()
		_ = os.RemoveAll(tempDir)
	}()

	var r io.Reader = rc
	if stall != nil {
		r = stallReader{rc, stall, stallTimeout}
	}

	// Download the layer content into a temporal file
	if _, err = xio.Copy(ctx, f, r); err != nil {
		return xerrors.Errorf("copy error: %w", err)
	}

	// Decompress the downloaded file if it is compressed and copy it into the dst
	// NOTE: it's local copying, the insecure option doesn't matter.
	if _, err = downloader.Download(ctx, f.Name(), dir, dir, downloader.Options{}); err != nil {
		return xerrors.Errorf("download error: %w", err)
	}

	return nil
}

// stallReader reads the layer of a download whose stall timer is t. Each read
// resets t to d, and the end of the layer stops it, since the rest of the
// download is local.
type stallReader struct {
	io.Reader
	t *time.Timer
	d time.Duration
}

func (r stallReader) Read(p []byte) (int, error) {
	n, err := r.Reader.Read(p)
	if err != nil {
		r.t.Stop()
	} else {
		r.t.Reset(r.d)
	}
	return n, err
}

func (a *Artifact) Digest(ctx context.Context) (string, error) {
	if err := a.populate(ctx, a.RegistryOptions); err != nil {
		return "", err
	}

	digest, err := a.image.Digest()
	if err != nil {
		return "", xerrors.Errorf("digest error: %w", err)
	}
	return digest.String(), nil
}

func (a *Artifact) Manifest(ctx context.Context) (*v1.Manifest, error) {
	if err := a.populate(ctx, a.RegistryOptions); err != nil {
		return nil, err
	}

	manifest, err := a.image.Manifest()
	if err != nil {
		return nil, xerrors.Errorf("get manifest: %w", err)
	}

	return manifest, nil
}

type Artifacts []*Artifact

// NewArtifacts returns a slice of artifacts.
func NewArtifacts(repos []name.Reference, opt types.RegistryOptions, opts ...Option) Artifacts {
	return xslices.Map(repos, func(r name.Reference) *Artifact {
		return NewArtifact(r.String(), opt, opts...)
	})
}

// Download downloads artifacts until one of them succeeds. It stops early at
// a local file error, such as a full disk, which the next artifact would meet
// as well, and once ctx is done.
func (a Artifacts) Download(ctx context.Context, dst string, opt DownloadOption) error {
	var errs error
	for i, art := range a {
		log.InfoContext(ctx, "Downloading artifact...", log.String("repo", art.repository))
		err := art.Download(ctx, dst, opt)
		if err == nil {
			log.InfoContext(ctx, "Artifact successfully downloaded", log.String("repo", art.repository))
			return nil
		}

		var pathErr *fs.PathError
		if ctx.Err() != nil || errors.As(err, &pathErr) {
			return xerrors.Errorf("failed to download artifact from %s: %w", art.repository, err)
		}
		log.ErrorContext(ctx, "Failed to download artifact", log.String("repo", art.repository), log.Err(err))
		if i < len(a)-1 {
			log.InfoContext(ctx, "Trying to download artifact from other repository...")
		}
		errs = multierror.Append(errs, err)
	}

	return xerrors.Errorf("failed to download artifact from any source: %w", errs)
}
