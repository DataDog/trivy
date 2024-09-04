package image

import (
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/cache"
	"github.com/aquasecurity/trivy/pkg/fanal/artifact"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func NewArtifact(img types.Image, c cache.ArtifactCache, opt artifact.Option) (artifact.Artifact, error) {
	return nil, xerrors.New("pkg/final/artifact/image not implemented")
}
