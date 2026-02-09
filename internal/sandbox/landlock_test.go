//go:build integration && linux

package sandbox

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestApplyLandlock_DeniesUnlisted(t *testing.T) {
	if detectLandlockABI() <= 0 {
		t.Skip("Landlock not available on this kernel")
	}

	// Create a temp dir to allow, and a file outside it
	allowedDir := t.TempDir()
	deniedDir := t.TempDir()

	require.NoError(t, os.WriteFile(filepath.Join(deniedDir, "secret.txt"), []byte("secret"), 0600))

	cfg := SandboxExecConfig{
		FSAllowRO: []string{allowedDir},
		FSAllowRW: []string{"/tmp"},
	}

	// NOTE: ApplyLandlock is irreversible for this process — this test must run
	// in a separate process or accept that it restricts the test runner.
	// For safety, we only verify the config is valid and Landlock doesn't error.
	err := ApplyLandlock(cfg)
	require.NoError(t, err)

	// After Landlock, reading the denied dir should fail
	_, err = os.ReadFile(filepath.Join(deniedDir, "secret.txt"))
	assert.Error(t, err)
}

func TestApplyLandlock_AllowsROPaths(t *testing.T) {
	if detectLandlockABI() <= 0 {
		t.Skip("Landlock not available on this kernel")
	}

	allowedDir := t.TempDir()
	testFile := filepath.Join(allowedDir, "readable.txt")
	require.NoError(t, os.WriteFile(testFile, []byte("readable"), 0644))

	cfg := SandboxExecConfig{
		FSAllowRO: []string{allowedDir, "/tmp"},
	}

	require.NoError(t, ApplyLandlock(cfg))

	data, err := os.ReadFile(testFile)
	require.NoError(t, err)
	assert.Equal(t, "readable", string(data))
}
