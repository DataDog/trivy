package licensing

import (
	"io"

	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

// Classify returns a license file with empty findings. The license classifier
// has been stripped from this build to keep its corpus out of agent binaries.
func Classify(filePath string, r io.Reader, confidenceLevel float64) (*types.LicenseFile, error) {
	return &types.LicenseFile{FilePath: filePath}, nil
}
