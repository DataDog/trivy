//go:build !trivy_no_javadb

package javadb

import (
	"context"

	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/oci"
	"golang.org/x/xerrors"
)

func (u *Updater) downloadDB(ctx context.Context) error {
	log.InfoContext(ctx, "Downloading Java DB...")

	artifacts := oci.NewArtifacts(u.repos, u.registryOption)
	downloadOpt := oci.DownloadOption{
		MediaType: mediaType,
		Quiet:     u.quiet,
	}
	if err := artifacts.Download(ctx, u.dbDir, downloadOpt); err != nil {
		return xerrors.Errorf("failed to download Java DB: %w", err)
	}

	return nil
}
