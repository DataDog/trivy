package rego

import (
	"io/fs"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/iac/scanners/options"
)

type RegoScannerProvider struct{}

func (s *RegoScannerProvider) InitRegoScanner(_ fs.FS, _ []options.ScannerOption) (*Scanner, error) {
	return nil, xerrors.New("pkg/iac/rego not implemented")
}
