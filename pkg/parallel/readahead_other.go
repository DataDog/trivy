//go:build !linux

package parallel

import "os"

func readAhead(*os.File, int64) {}
