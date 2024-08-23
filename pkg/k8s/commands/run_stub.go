package commands

import (
	"context"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/flag"
)

func Run(ctx context.Context, args []string, opts flag.Options) error {
	return xerrors.New("pkg/compliance not implemented")
}
