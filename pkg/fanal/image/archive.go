package image

import (
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"golang.org/x/xerrors"
)

func NewArchiveImage(fileName string) (types.Image, error) {
	return nil, xerrors.New("pkg/fanal/image not implemented")
}
