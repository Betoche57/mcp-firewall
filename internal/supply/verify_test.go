package supply

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVerify_HashMatch(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "mybin")
	require.NoError(t, os.WriteFile(bin, []byte("binary content"), 0755))

	hash, err := ComputeFileHash(bin)
	require.NoError(t, err)

	result, err := Verify(bin, hash, nil)
	require.NoError(t, err)
	assert.Equal(t, bin, result.ResolvedPath)
	assert.Equal(t, hash, result.ComputedHash)
}

func TestVerify_HashMismatch(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "mybin")
	require.NoError(t, os.WriteFile(bin, []byte("binary content"), 0755))

	wrongHash := "sha256:0000000000000000000000000000000000000000000000000000000000000000"

	_, err := Verify(bin, wrongHash, nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "hash mismatch")
	assert.Contains(t, err.Error(), "expected")
	assert.Contains(t, err.Error(), "computed")
}

func TestVerify_NoHash(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "mybin")
	require.NoError(t, os.WriteFile(bin, []byte("binary content"), 0755))

	result, err := Verify(bin, "", nil)
	require.NoError(t, err)
	assert.Equal(t, bin, result.ResolvedPath)
	assert.Empty(t, result.ComputedHash)
}

func TestVerify_PathDenied(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "mybin")
	require.NoError(t, os.WriteFile(bin, []byte("binary content"), 0755))

	_, err := Verify(bin, "", []string{"/usr/local/bin"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not under any allowed path")
}

func TestVerify_NoRestrictions(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "mybin")
	require.NoError(t, os.WriteFile(bin, []byte("binary content"), 0755))

	result, err := Verify(bin, "", nil)
	require.NoError(t, err)
	assert.Equal(t, bin, result.ResolvedPath)
}

func TestVerify_BothChecks(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "mybin")
	require.NoError(t, os.WriteFile(bin, []byte("binary content"), 0755))

	hash, err := ComputeFileHash(bin)
	require.NoError(t, err)

	result, err := Verify(bin, hash, []string{dir})
	require.NoError(t, err)
	assert.Equal(t, bin, result.ResolvedPath)
	assert.Equal(t, hash, result.ComputedHash)
}

func TestVerify_PathDeniedBeforeHash(t *testing.T) {
	// When path is denied, hash check should not run (fail fast)
	dir := t.TempDir()
	bin := filepath.Join(dir, "mybin")
	require.NoError(t, os.WriteFile(bin, []byte("binary content"), 0755))

	wrongHash := "sha256:0000000000000000000000000000000000000000000000000000000000000000"
	_, err := Verify(bin, wrongHash, []string{"/usr/local/bin"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not under any allowed path")
}
