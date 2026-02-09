package sandbox

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEffectiveLevel_Full(t *testing.T) {
	c := Capabilities{UserNamespace: true, Landlock: true, LandlockABI: 5}
	assert.Equal(t, "full", c.EffectiveLevel())
}

func TestEffectiveLevel_Partial_LandlockOnly(t *testing.T) {
	c := Capabilities{UserNamespace: false, Landlock: true, LandlockABI: 3}
	assert.Equal(t, "partial", c.EffectiveLevel())
}

func TestEffectiveLevel_Minimal(t *testing.T) {
	c := Capabilities{UserNamespace: false, Landlock: false}
	assert.Equal(t, "minimal", c.EffectiveLevel())
}

func TestEffectiveLevel_NamespaceOnlyIsPartial(t *testing.T) {
	c := Capabilities{UserNamespace: true, Landlock: false}
	assert.Equal(t, "partial", c.EffectiveLevel())
}

func TestDetectCapabilities_ReturnsStruct(t *testing.T) {
	c := DetectCapabilities()
	// Just verify it returns without panicking and level is valid
	level := c.EffectiveLevel()
	assert.Contains(t, []string{"full", "partial", "minimal"}, level)
}
