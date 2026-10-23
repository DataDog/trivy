package commands

import (
	"context"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/flag"
)

func Run(_ context.Context, _ []string, _ flag.Options) error {
	return xerrors.New("pkg/compliance not implemented")
}
