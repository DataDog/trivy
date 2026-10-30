//go:build linux

package parallel

import (
	"os"

	"golang.org/x/sys/unix"
)

// readAhead asks the kernel to start reading the head and the tail of f,
// which hold the headers, section tables and zip directories that analyzers
// read first.
func readAhead(f *os.File, size int64) {
	fd := int(f.Fd())
	if size <= aheadHead+aheadTail {
		_ = unix.Fadvise(fd, 0, size, unix.FADV_WILLNEED)
		return
	}
	_ = unix.Fadvise(fd, 0, aheadHead, unix.FADV_WILLNEED)
	_ = unix.Fadvise(fd, size-aheadTail, aheadTail, unix.FADV_WILLNEED)
}
