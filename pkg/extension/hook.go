package extension

import (
	"context"

	"github.com/aquasecurity/trivy/pkg/types"
)

// Hook is an interface that defines the methods for a hook.
type Hook interface {
	Name() string
}

// RunHook is unused by the DataDog Agent and stripped from this build.
type RunHook interface {
	Hook
	PreRun(ctx context.Context, opts any) error
	PostRun(ctx context.Context, opts any) error
}

// ScanHook is unused by the DataDog Agent and stripped from this build.
type ScanHook interface {
	Hook
	PreScan(ctx context.Context, target *types.ScanTarget, opts types.ScanOptions) error
	PostScan(ctx context.Context, results types.Results) (types.Results, error)
}

// ReportHook is unused by the DataDog Agent and stripped from this build.
type ReportHook interface {
	Hook
	PreReport(ctx context.Context, report *types.Report, opts any) error
	PostReport(ctx context.Context, report *types.Report, opts any) error
}

// All exported functions below are no-ops in this stripped build.
func RegisterHook(_ Hook)            {}
func DeregisterHook(_ string)        {}
func Hooks() []Hook                  { return nil }
func PreRun(_ context.Context, _ any) error                                   { return nil }
func PostRun(_ context.Context, _ any) error                                  { return nil }
func PreScan(_ context.Context, _ *types.ScanTarget, _ types.ScanOptions) error { return nil }
func PostScan(_ context.Context, results types.Results) (types.Results, error) { return results, nil }
func PreReport(_ context.Context, _ *types.Report, _ any) error               { return nil }
func PostReport(_ context.Context, _ *types.Report, _ any) error              { return nil }
