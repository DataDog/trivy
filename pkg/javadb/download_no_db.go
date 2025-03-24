//go:build trivy_no_javadb

package javadb

import (
	"context"

	"golang.org/x/xerrors"
)

func (u *Updater) downloadDB(ctx context.Context) error {
	return xerrors.Errorf("download Java DB unavailable")
}
