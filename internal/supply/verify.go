package supply

import "fmt"

// VerifyResult holds the outcome of a supply chain verification.
type VerifyResult struct {
	ResolvedPath string // absolute, symlinks resolved
	ComputedHash string // "sha256:..." (only if hash check was requested)
}

// Verify runs path validation + hash verification.
// Either check can be skipped (empty hash / empty allowedPaths).
func Verify(command, expectedHash string, allowedPaths []string) (*VerifyResult, error) {
	resolved, err := ResolvePath(command)
	if err != nil {
		return nil, fmt.Errorf("supply chain: %w", err)
	}

	// Path validation first (fail fast before computing hash)
	if err := ValidatePath(resolved, allowedPaths); err != nil {
		return nil, fmt.Errorf("supply chain: %w", err)
	}

	result := &VerifyResult{
		ResolvedPath: resolved,
	}

	// Hash verification (only if expected hash is provided)
	if expectedHash != "" {
		computed, err := ComputeFileHash(resolved)
		if err != nil {
			return nil, fmt.Errorf("supply chain: %w", err)
		}
		result.ComputedHash = computed

		if computed != expectedHash {
			return nil, fmt.Errorf("supply chain: hash mismatch for %q: expected %s, computed %s",
				resolved, expectedHash, computed)
		}
	}

	return result, nil
}
