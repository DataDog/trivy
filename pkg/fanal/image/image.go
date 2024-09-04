package image

import (
	"context"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func NewContainerImage(ctx context.Context, imageName string, opt types.ImageOptions) (types.Image, func(), error) {
	return nil, nil, xerrors.New("pkg/fanal/image not implemented")
}
