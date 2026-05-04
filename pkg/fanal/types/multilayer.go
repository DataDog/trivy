package types

// MultiLayer represents an artifact made of an ordered set of pre-extracted
// filesystem layers. The shape is the same as a multi-layer container image,
// but the layers are already on disk (no tar, no compression, no pull) and
// arrive with caller-supplied metadata. Use cases include serverless function
// packaging (AWS Lambda function code + layer ZIPs), pre-extracted OCI
// images, and any other "scan N filesystem trees as overlay layers" flow.
//
// Trivy holds no opinion on what the layers represent: callers attach
// domain-specific identifiers via LayerSource.Annotations.
type MultiLayer interface {
	// ID is a stable identifier for the artifact as a whole.
	ID() (string, error)

	// Name is a human-readable identifier.
	Name() string

	// Layers returns the ordered layers. Index 0 is the base layer; later
	// indices conceptually overlay earlier ones (matching OCI layer ordering
	// and AWS Lambda layer attachment order).
	Layers() []LayerSource
}

// LayerSource is one input layer of a MultiLayer artifact.
type LayerSource struct {
	// Path is the local filesystem path holding the extracted layer contents.
	Path string

	// DiffID identifies the layer content. If empty, the artifact computes
	// a deterministic hash of Path.
	DiffID string

	// Digest is an optional alternative identifier; mirrors DiffID by default.
	Digest string

	// CreatedBy is free-form provenance text for the layer.
	CreatedBy string

	// Annotations are free-form key/value pairs attached to every component
	// sourced from this layer. Domain integrations use this to carry their
	// own identifiers (e.g. cloud-specific layer ARNs). Trivy holds no
	// opinion on the keys.
	Annotations map[string]string
}
