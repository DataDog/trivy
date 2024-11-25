package walker

import (
	"os"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
)

const defaultSizeThreshold = int64(100) << 20 // 200MB

var defaultSkipDirs = []string{
	"**/.git",
	"proc",
	"sys",
	"dev",
}

type ErrorCallback func(filePath string, err error) error

type Option struct {
	SkipFiles     []string
	SkipDirs      []string
	OnlyDirs      []string
	AllFiles      bool
	ErrorCallback ErrorCallback
}

type WalkFunc func(filePath string, info os.FileInfo, opener analyzer.Opener) error
