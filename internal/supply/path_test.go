package supply

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResolvePath_Absolute(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "mybin")
	require.NoError(t, os.WriteFile(bin, []byte("#!/bin/sh\n"), 0755))

	resolved, err := ResolvePath(bin)
	require.NoError(t, err)
	assert.Equal(t, bin, resolved)
}

func TestResolvePath_LookPath(t *testing.T) {
	// "ls" should be on PATH on any test system
	resolved, err := ResolvePath("ls")
	require.NoError(t, err)
	assert.True(t, filepath.IsAbs(resolved))
}

func TestResolvePath_NotFound(t *testing.T) {
	_, err := ResolvePath("nonexistent-binary-that-does-not-exist-12345")
	require.Error(t, err)
}

func TestResolvePath_SymlinkFollowed(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	link := filepath.Join(dir, "link")
	require.NoError(t, os.WriteFile(target, []byte("#!/bin/sh\n"), 0755))
	require.NoError(t, os.Symlink(target, link))

	resolved, err := ResolvePath(link)
	require.NoError(t, err)
	assert.Equal(t, target, resolved)
}

func TestValidatePath_InAllowlist(t *testing.T) {
	err := ValidatePath("/usr/local/bin/mybin", []string{"/usr/local/bin"})
	require.NoError(t, err)
}

func TestValidatePath_OutsideAllowlist(t *testing.T) {
	err := ValidatePath("/opt/evil/binary", []string{"/usr/local/bin", "/usr/bin"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not under any allowed path")
}

func TestValidatePath_EmptyAllowlist(t *testing.T) {
	err := ValidatePath("/anywhere/is/fine", nil)
	require.NoError(t, err)

	err = ValidatePath("/anywhere/is/fine", []string{})
	require.NoError(t, err)
}

func TestValidatePath_ExactMatch(t *testing.T) {
	// Path is exactly the allowed path (a directory prefix match)
	err := ValidatePath("/usr/local/bin", []string{"/usr/local/bin"})
	require.NoError(t, err)
}

func TestValidatePath_TraversalPrevented(t *testing.T) {
	// Path that shares a prefix string but isn't actually under the directory
	err := ValidatePath("/usr/local/bin-evil/hack", []string{"/usr/local/bin"})
	require.Error(t, err)
}

func TestValidatePath_TildeExpansion(t *testing.T) {
	home, err := os.UserHomeDir()
	require.NoError(t, err)

	resolved := filepath.Join(home, "bin", "mybin")
	err = ValidatePath(resolved, []string{"~/bin"})
	require.NoError(t, err)
}
