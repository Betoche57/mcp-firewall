package supply

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseHash_Valid(t *testing.T) {
	algo, digest, err := ParseHash("sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789")
	require.NoError(t, err)
	assert.Equal(t, "sha256", algo)
	assert.Equal(t, "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789", digest)
}

func TestParseHash_InvalidFormat(t *testing.T) {
	_, _, err := ParseHash("nocolonhere")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "format")
}

func TestParseHash_UnsupportedAlgorithm(t *testing.T) {
	_, _, err := ParseHash("md5:abcdef0123456789abcdef0123456789")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported")
}

func TestParseHash_EmptyDigest(t *testing.T) {
	_, _, err := ParseHash("sha256:")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "empty")
}

func TestParseHash_InvalidHexDigest(t *testing.T) {
	_, _, err := ParseHash("sha256:notvalidhex!!!")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "hex")
}

func TestParseHash_WrongLength(t *testing.T) {
	_, _, err := ParseHash("sha256:abcdef") // too short
	require.Error(t, err)
	assert.Contains(t, err.Error(), "64")
}

func TestComputeFileHash_RegularFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "testfile")
	content := []byte("hello world\n")
	require.NoError(t, os.WriteFile(path, content, 0644))

	expected := fmt.Sprintf("sha256:%x", sha256.Sum256(content))

	hash, err := ComputeFileHash(path)
	require.NoError(t, err)
	assert.Equal(t, expected, hash)
}

func TestComputeFileHash_NotFound(t *testing.T) {
	_, err := ComputeFileHash("/nonexistent/file/path")
	require.Error(t, err)
}

func TestComputeFileHash_Symlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	link := filepath.Join(dir, "link")
	content := []byte("symlink target content")
	require.NoError(t, os.WriteFile(target, content, 0644))
	require.NoError(t, os.Symlink(target, link))

	expected := fmt.Sprintf("sha256:%x", sha256.Sum256(content))

	hash, err := ComputeFileHash(link)
	require.NoError(t, err)
	assert.Equal(t, expected, hash)
}

func TestComputeFileHash_NotRegular(t *testing.T) {
	dir := t.TempDir()
	_, err := ComputeFileHash(dir) // directory, not a regular file
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not a regular file")
}
