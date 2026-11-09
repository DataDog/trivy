package result

import (
	"context"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/types"
)

func applyPolicy(context.Context, *types.Result, string) error {
	return xerrors.New("Rego ignore policies not implemented")
}
