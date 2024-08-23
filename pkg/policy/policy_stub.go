package policy

import (
	"context"
	"fmt"
	"time"

	"golang.org/x/xerrors"
	"k8s.io/utils/clock"

	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/oci"
)

const (
	BundleVersion    = 1 // Latest released MAJOR version for trivy-checks
	BundleRepository = "mirror.gcr.io/aquasec/trivy-checks"
	policyMediaType  = "application/vnd.cncf.openpolicyagent.layer.v1.tar+gzip"
	updateInterval   = 24 * time.Hour
)

type options struct {
	artifact *oci.Artifact
	clock    clock.Clock
}

// WithOCIArtifact takes an OCI artifact
func WithOCIArtifact(art *oci.Artifact) Option {
	return func(opts *options) {
		opts.artifact = art
	}
}

// WithClock takes a clock
func WithClock(c clock.Clock) Option {
	return func(opts *options) {
		opts.clock = c
	}
}

// Option is a functional option
type Option func(*options)

// Client implements check operations
type Client struct {
	*options
	policyDir       string
	checkBundleRepo string
	quiet           bool
}

// Metadata holds default check metadata
type Metadata struct {
	Digest       string
	DownloadedAt time.Time
}

func (m Metadata) String() string {
	return fmt.Sprintf(`Check Bundle:
  Digest: %s
  DownloadedAt: %s
`, m.Digest, m.DownloadedAt.UTC())
}

// NewClient is the factory method for check client
func NewClient(cacheDir string, quiet bool, checkBundleRepo string, opts ...Option) (*Client, error) {
	return nil, xerrors.New("pkg/policy not implemented")
}

// DownloadBuiltinChecks download default policies from GitHub Pages
func (c *Client) DownloadBuiltinChecks(ctx context.Context, registryOpts types.RegistryOptions) error {
	return xerrors.New("pkg/policy not implemented")
}

// LoadBuiltinChecks loads default policies
func (c *Client) LoadBuiltinChecks() ([]string, error) {
	return nil, xerrors.New("pkg/policy not implemented")
}

// NeedsUpdate returns if the default check should be updated
func (c *Client) NeedsUpdate(ctx context.Context, registryOpts types.RegistryOptions) (bool, error) {
	return false, xerrors.New("pkg/policy not implemented")
}

func (c *Client) GetMetadata(ctx context.Context) (*Metadata, error) {
	return nil, xerrors.New("pkg/policy not implemented")
}

func (c *Client) Clear() error {
	return xerrors.New("pkg/policy not implemented")
}
