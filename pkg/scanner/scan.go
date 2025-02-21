package scanner

import (
	"context"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/clock"
	"github.com/aquasecurity/trivy/pkg/fanal/artifact"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/types"
)

// Scanner implements the Artifact and Driver operations
type Scanner struct {
	driver   Driver
	artifact artifact.Artifact
}

// Driver defines operations of scanner
type Driver interface {
	Scan(ctx context.Context, target, artifactKey string, blobKeys []string, options types.ScanOptions) (
		results types.Results, osFound ftypes.OS, err error)
}

// NewScanner is the factory method of Scanner
func NewScanner(driver Driver, ar artifact.Artifact) Scanner {
	return Scanner{
		driver:   driver,
		artifact: ar,
	}
}

// ScanArtifact scans the artifacts and returns results
func (s Scanner) ScanArtifact(ctx context.Context, options types.ScanOptions) (types.Report, error) {
	artifactInfo, err := s.artifact.Inspect(ctx)
	if err != nil {
		return types.Report{}, xerrors.Errorf("failed analysis: %w", err)
	}
	defer func() {
		if err := s.artifact.Clean(artifactInfo); err != nil {
			log.Warn("Failed to clean the artifact",
				log.String("artifact", artifactInfo.Name), log.Err(err))
		}
	}()

	results, osFound, err := s.driver.Scan(ctx, artifactInfo.Name, artifactInfo.ID, artifactInfo.BlobIDs, options)
	if err != nil {
		return types.Report{}, xerrors.Errorf("scan failed: %w", err)
	}

	ptros := &osFound
	if osFound.Detected() && osFound.Eosl {
		log.Warn("This OS version is no longer supported by the distribution",
			log.String("family", string(osFound.Family)), log.String("version", osFound.Name))
		log.Warn("The vulnerability detection may be insufficient because security updates are not provided")
	} else if !osFound.Detected() {
		ptros = nil
	}

	return types.Report{
		SchemaVersion: 2, // github.com/aquasecurity/trivy/pkg/report.SchemaVersion but without importing the whole report package
		CreatedAt:     clock.Now(ctx),
		ArtifactName:  artifactInfo.Name,
		ArtifactType:  artifactInfo.Type,
		Metadata: types.Metadata{
			OS: ptros,

			// Container image
			ImageID:     artifactInfo.ImageMetadata.ID,
			DiffIDs:     artifactInfo.ImageMetadata.DiffIDs,
			RepoTags:    artifactInfo.ImageMetadata.RepoTags,
			RepoDigests: artifactInfo.ImageMetadata.RepoDigests,
			ImageConfig: artifactInfo.ImageMetadata.ConfigFile,
		},
		Results: results,
		BOM:     artifactInfo.BOM,
	}, nil
}
