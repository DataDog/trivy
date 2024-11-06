package types

import v1 "github.com/google/go-containerregistry/pkg/v1"

type Container interface {
	Name() string
	ID() (string, error)
	ConfigFile() (*v1.ConfigFile, error)
	Layers() []LayerPath
	LayerByDiffID(string) (LayerPath, error)
	LayerByDigest(string) (LayerPath, error)
	RepoTags() []string
	RepoDigests() []string
}

type LayerPath struct {
	DiffID string
	Digest string
	Path   string
}
