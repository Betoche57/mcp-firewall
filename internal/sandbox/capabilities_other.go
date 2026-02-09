//go:build !linux

package sandbox

// DetectCapabilities returns all-false on non-Linux platforms.
func DetectCapabilities() Capabilities {
	return Capabilities{}
}
