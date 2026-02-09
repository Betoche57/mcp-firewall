package sandbox

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFilterEnv_EmptyAllowlist(t *testing.T) {
	env := []string{"PATH=/usr/bin", "HOME=/root", "SECRET=hunter2"}
	got := FilterEnv(env, nil)
	assert.Empty(t, got)
}

func TestFilterEnv_SomeFiltered(t *testing.T) {
	env := []string{"PATH=/usr/bin", "HOME=/root", "SECRET=hunter2"}
	got := FilterEnv(env, []string{"PATH", "HOME"})
	assert.Equal(t, []string{"PATH=/usr/bin", "HOME=/root"}, got)
}

func TestFilterEnv_CaseExact(t *testing.T) {
	env := []string{"path=/usr/bin", "PATH=/usr/bin"}
	got := FilterEnv(env, []string{"PATH"})
	assert.Equal(t, []string{"PATH=/usr/bin"}, got)
}

func TestFilterEnv_MalformedEntry(t *testing.T) {
	env := []string{"PATH=/usr/bin", "NOEQUALS", "HOME=/root"}
	got := FilterEnv(env, []string{"PATH", "NOEQUALS", "HOME"})
	assert.Equal(t, []string{"PATH=/usr/bin", "HOME=/root"}, got)
}

func TestFilterEnv_EmptyEnv(t *testing.T) {
	got := FilterEnv(nil, []string{"PATH"})
	assert.Empty(t, got)
}

func TestFilterEnv_PreservesOrder(t *testing.T) {
	env := []string{"C=3", "A=1", "B=2"}
	got := FilterEnv(env, []string{"A", "B", "C"})
	assert.Equal(t, []string{"C=3", "A=1", "B=2"}, got)
}
