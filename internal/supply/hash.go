package supply

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// ParseHash splits "sha256:hexdigest" into algorithm + digest.
func ParseHash(s string) (algorithm, digest string, err error) {
	idx := strings.Index(s, ":")
	if idx < 0 {
		return "", "", fmt.Errorf("invalid hash format %q: expected \"algorithm:digest\"", s)
	}

	algorithm = s[:idx]
	digest = s[idx+1:]

	if algorithm != "sha256" {
		return "", "", fmt.Errorf("unsupported hash algorithm %q: only \"sha256\" is supported", algorithm)
	}

	if digest == "" {
		return "", "", fmt.Errorf("empty digest in hash %q", s)
	}

	if len(digest) != 64 {
		return "", "", fmt.Errorf("sha256 digest must be 64 hex characters, got %d", len(digest))
	}

	if _, err := hex.DecodeString(digest); err != nil {
		return "", "", fmt.Errorf("invalid hex digest in hash %q: %w", s, err)
	}

	return algorithm, digest, nil
}

// ComputeFileHash resolves symlinks, verifies regular file, returns "sha256:<hex>".
func ComputeFileHash(path string) (string, error) {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return "", fmt.Errorf("resolving path %q: %w", path, err)
	}

	info, err := os.Stat(resolved)
	if err != nil {
		return "", fmt.Errorf("stat %q: %w", resolved, err)
	}

	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("%q is not a regular file", resolved)
	}

	f, err := os.Open(resolved)
	if err != nil {
		return "", fmt.Errorf("opening %q: %w", resolved, err)
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("hashing %q: %w", resolved, err)
	}

	return fmt.Sprintf("sha256:%x", h.Sum(nil)), nil
}
