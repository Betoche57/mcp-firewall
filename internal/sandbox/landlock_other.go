//go:build !linux

package sandbox

// ApplyLandlock is not supported on non-Linux platforms.
func ApplyLandlock(_ SandboxExecConfig) error {
	return ErrLandlockUnsupported
}
