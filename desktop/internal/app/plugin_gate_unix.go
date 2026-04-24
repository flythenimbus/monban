//go:build darwin || linux

package app

import (
	"os"
	"syscall"
)

// statUID extracts the numeric owner uid from an os.FileInfo on Unix.
// Split out to a platform file because windows returns no uid.
func statUID(fi os.FileInfo) (uint32, bool) {
	sys, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return sys.Uid, true
}
