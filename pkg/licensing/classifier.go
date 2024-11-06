package licensing

import (
	"io"

	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/set"
)

// LicenseFileNames are the base names (case-insensitive, without extension) of files
// commonly used to hold a license, e.g. LICENSE, LICENCE, COPYRIGHT.
var LicenseFileNames = set.NewCaseInsensitive("license", "licence", "copyright")

// Classify returns a license file with empty findings. The license classifier
// has been stripped from this build to keep its corpus out of agent binaries.
func Classify(filePath string, r io.Reader, confidenceLevel float64) (*types.LicenseFile, error) {
	return &types.LicenseFile{FilePath: filePath}, nil
}
