package rego

import (
	"io/fs"
	"sync"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/iac/scanners/options"
)

type RegoScannerProvider struct {
	mu          sync.Mutex
	regoScanner *Scanner
}

func (s *RegoScannerProvider) InitRegoScanner(fsys fs.FS, opts []options.ScannerOption) (*Scanner, error) {
	return nil, xerrors.New("pkg/iac/rego not implemented")
}
