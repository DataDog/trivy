package scanner

import (
	"context"
	"fmt"

	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/trivy/pkg/flag"
)

type AWSScanner struct {
}

func NewScanner() *AWSScanner {
	return &AWSScanner{}
}

func (s *AWSScanner) Scan(ctx context.Context, option flag.Options) (scan.Results, bool, error) {
	return nil, false, fmt.Errorf("not supported")
}
