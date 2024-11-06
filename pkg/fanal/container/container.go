package container

import (
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/fanal/types"

	"github.com/distribution/reference"
	v1 "github.com/google/go-containerregistry/pkg/v1"
)

type container struct {
	refCanonical reference.Canonical
	refTagged    reference.NamedTagged
	imageID      string
	configFile   *v1.ConfigFile
	layers       []types.LayerPath
}

func NewContainer(refCanonical reference.Canonical, refTagged reference.NamedTagged, imageID string, configFile *v1.ConfigFile, layers []types.LayerPath) *container {
	return &container{
		refCanonical: refCanonical,
		refTagged:    refTagged,
		imageID:      imageID,
		configFile:   configFile,
		layers:       layers,
	}
}

func (ctr *container) Name() string {
	return reference.FamiliarName(ctr.refTagged) + ":" + ctr.refTagged.Tag()
}

func (ctr *container) ID() (string, error) {
	return ctr.imageID, nil
}

func (ctr *container) RepoTags() []string {
	return []string{reference.FamiliarName(ctr.refTagged) + ":" + ctr.refTagged.Tag()}
}

func (ctr *container) RepoDigests() []string {
	return []string{reference.FamiliarName(ctr.refTagged) + "@" + ctr.refCanonical.Digest().String()}
}

func (ctr *container) ConfigFile() (*v1.ConfigFile, error) {
	return ctr.configFile, nil
}

func (ctr *container) Layers() []types.LayerPath {
	return ctr.layers
}

func (ctr *container) LayerByDiffID(diffID string) (types.LayerPath, error) {
	for _, layer := range ctr.layers {
		if layer.DiffID == diffID {
			return layer, nil
		}
	}
	return types.LayerPath{}, xerrors.Errorf("unable to find diffID %s", diffID)
}

func (ctr *container) LayerByDigest(digest string) (types.LayerPath, error) {
	for _, layer := range ctr.layers {
		if layer.Digest == digest {
			return layer, nil
		}
	}
	return types.LayerPath{}, xerrors.Errorf("unable to find digest %s", digest)
}
