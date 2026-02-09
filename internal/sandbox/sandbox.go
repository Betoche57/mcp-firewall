package sandbox

import "fmt"

// SandboxProfileConfig is the YAML-level config for a custom sandbox profile.
type SandboxProfileConfig struct {
	Network      *bool    `yaml:"network,omitempty" json:"network,omitempty"`
	EnvAllowlist []string `yaml:"env_allowlist,omitempty" json:"env_allowlist,omitempty"`
	FSDeny       []string `yaml:"fs_deny,omitempty" json:"fs_deny,omitempty"`
	FSAllowRO    []string `yaml:"fs_allow_ro,omitempty" json:"fs_allow_ro,omitempty"`
	FSAllowRW    []string `yaml:"fs_allow_rw,omitempty" json:"fs_allow_rw,omitempty"`
	Workspace    string   `yaml:"workspace,omitempty" json:"workspace,omitempty"`
}

// SandboxProfile is the resolved runtime profile used by the sandbox.
type SandboxProfile struct {
	Name         string
	Network      bool
	EnvAllowlist []string
	FSDeny       []string
	FSAllowRO    []string
	FSAllowRW    []string
	Workspace    string // "ro" (default), "rw", "none"
}

// StrictProfile returns the built-in strict sandbox profile.
func StrictProfile() SandboxProfile {
	return SandboxProfile{
		Name:    "strict",
		Network: false,
		EnvAllowlist: []string{
			"PATH", "HOME", "LANG", "LC_ALL", "TERM", "TMPDIR", "TZ", "USER", "SHELL",
		},
		FSDeny: []string{
			"~/.ssh",
			"~/.gnupg",
			"~/.aws",
			"~/.config/gcloud",
			"~/.kube",
		},
		FSAllowRO: []string{
			"/usr", "/lib", "/lib64", "/bin", "/sbin",
			"/etc/ssl", "/etc/ca-certificates",
			"/etc/ld.so.cache", "/etc/ld.so.conf", "/etc/ld.so.conf.d",
			"/etc/nsswitch.conf", "/etc/passwd", "/etc/group",
			"/etc/localtime", "/etc/resolv.conf",
			"/proc/self", "/dev/fd",
		},
		FSAllowRW: []string{
			"/tmp", "/dev/null", "/dev/zero", "/dev/urandom", "/dev/random",
		},
		Workspace: "ro",
	}
}

// ResolveProfile resolves a profile name to a SandboxProfile.
// "strict" returns the built-in. "none" and "" are errors (handled upstream).
// Custom names are looked up in the provided map.
func ResolveProfile(name string, custom map[string]SandboxProfileConfig) (SandboxProfile, error) {
	if name == "" {
		return SandboxProfile{}, fmt.Errorf("sandbox profile name must not be empty")
	}
	if name == "none" {
		return SandboxProfile{}, fmt.Errorf("sandbox profile %q is not a valid sandbox profile (use empty string to disable)", name)
	}
	if name == "strict" {
		return StrictProfile(), nil
	}

	cfg, ok := custom[name]
	if !ok {
		return SandboxProfile{}, fmt.Errorf("unknown sandbox profile %q", name)
	}

	p := SandboxProfile{
		Name:         name,
		EnvAllowlist: cfg.EnvAllowlist,
		FSDeny:       cfg.FSDeny,
		FSAllowRO:    cfg.FSAllowRO,
		FSAllowRW:    cfg.FSAllowRW,
		Workspace:    cfg.Workspace,
	}

	if cfg.Network != nil {
		p.Network = *cfg.Network
	}

	if p.Workspace == "" {
		p.Workspace = "ro"
	}

	return p, nil
}
