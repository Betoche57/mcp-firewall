package sandbox

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStrictProfile_Defaults(t *testing.T) {
	p := StrictProfile()

	assert.Equal(t, "strict", p.Name)
	assert.False(t, p.Network)
	assert.Equal(t, "ro", p.Workspace)

	// Must deny sensitive dirs
	assert.Contains(t, p.FSDeny, "~/.ssh")
	assert.Contains(t, p.FSDeny, "~/.gnupg")
	assert.Contains(t, p.FSDeny, "~/.aws")

	// Must allow common system dirs RO
	assert.Contains(t, p.FSAllowRO, "/usr")
	assert.Contains(t, p.FSAllowRO, "/bin")

	// Must allow /tmp RW
	assert.Contains(t, p.FSAllowRW, "/tmp")

	// Must have reasonable env allowlist
	assert.Contains(t, p.EnvAllowlist, "PATH")
	assert.Contains(t, p.EnvAllowlist, "HOME")
}

func TestResolveProfile_Strict(t *testing.T) {
	p, err := ResolveProfile("strict", nil)
	require.NoError(t, err)
	assert.Equal(t, "strict", p.Name)
	assert.False(t, p.Network)
}

func TestResolveProfile_None(t *testing.T) {
	_, err := ResolveProfile("none", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "none")
}

func TestResolveProfile_Custom(t *testing.T) {
	network := true
	custom := map[string]SandboxProfileConfig{
		"my-profile": {
			Network:      &network,
			EnvAllowlist: []string{"PATH", "DATABASE_URL"},
			FSDeny:       []string{"~/.ssh"},
			FSAllowRO:    []string{"/usr", "/lib"},
			FSAllowRW:    []string{"/tmp", "/var/data"},
			Workspace:    "rw",
		},
	}

	p, err := ResolveProfile("my-profile", custom)
	require.NoError(t, err)
	assert.Equal(t, "my-profile", p.Name)
	assert.True(t, p.Network)
	assert.Equal(t, []string{"PATH", "DATABASE_URL"}, p.EnvAllowlist)
	assert.Equal(t, []string{"~/.ssh"}, p.FSDeny)
	assert.Equal(t, []string{"/usr", "/lib"}, p.FSAllowRO)
	assert.Equal(t, []string{"/tmp", "/var/data"}, p.FSAllowRW)
	assert.Equal(t, "rw", p.Workspace)
}

func TestResolveProfile_CustomDefaultsFromStrict(t *testing.T) {
	// Custom with no network field → defaults to strict's false
	custom := map[string]SandboxProfileConfig{
		"minimal": {
			EnvAllowlist: []string{"PATH"},
		},
	}

	p, err := ResolveProfile("minimal", custom)
	require.NoError(t, err)
	assert.False(t, p.Network)
	assert.Equal(t, "ro", p.Workspace)
}

func TestResolveProfile_Unknown(t *testing.T) {
	_, err := ResolveProfile("nonexistent", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nonexistent")
}

func TestResolveProfile_EmptyString(t *testing.T) {
	_, err := ResolveProfile("", nil)
	require.Error(t, err)
}
