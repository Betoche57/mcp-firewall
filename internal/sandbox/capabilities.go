package sandbox

// Capabilities describes the host's sandbox capabilities.
type Capabilities struct {
	UserNamespace bool
	Landlock      bool
	LandlockABI   int // 0=unavailable, 1-6=ABI version
}

// EffectiveLevel returns the effective sandbox isolation level.
// "full" = user namespace + Landlock, "partial" = one of the two,
// "minimal" = neither (env filter only).
func (c Capabilities) EffectiveLevel() string {
	if c.UserNamespace && c.Landlock {
		return "full"
	}
	if c.UserNamespace || c.Landlock {
		return "partial"
	}
	return "minimal"
}
