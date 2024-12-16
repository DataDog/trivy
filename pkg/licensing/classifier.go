package licensing

import (
	"io"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

// Classify detects and classifies the license found in a file
func Classify(filePath string, r io.Reader, confidenceLevel float64) (*types.LicenseFile, error) {
	return nil, xerrors.Errorf("not implemented")
}
