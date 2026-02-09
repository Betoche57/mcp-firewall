//go:build !linux

package sandbox

import (
	"fmt"
	"runtime"
)

// execCommand is not supported on non-Linux platforms.
func execCommand(_ string, _ []string, _ []string) error {
	return fmt.Errorf("sandbox exec is not supported on %s", runtime.GOOS)
}
