package vm

import (
	"context"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/fanal/artifact"
)

type AMI struct {
	*EBS

	imageID string
}

func newAMI(imageID string, storage Storage, region, endpoint string) (*AMI, error) {
	return nil, xerrors.New("pkg/cloud not implemented")
}

func (a *AMI) Inspect(ctx context.Context) (artifact.Reference, error) {
	ref, err := a.EBS.Inspect(ctx)
	if err != nil {
		return artifact.Reference{}, err
	}
	ref.Name = a.imageID
	return ref, nil
}
