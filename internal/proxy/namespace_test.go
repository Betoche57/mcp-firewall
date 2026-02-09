package proxy

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNamespacedToolName(t *testing.T) {
	assert.Equal(t, "echo__greet", namespacedToolName("echo", "greet"))
	assert.Equal(t, "a__b", namespacedToolName("a", "b"))
}

func TestParseNamespacedToolName_Valid(t *testing.T) {
	alias, tool, ok := parseNamespacedToolName("echo__greet")
	assert.True(t, ok)
	assert.Equal(t, "echo", alias)
	assert.Equal(t, "greet", tool)
}

func TestParseNamespacedToolName_DoubleUnderscoreInTool(t *testing.T) {
	alias, tool, ok := parseNamespacedToolName("a__b__c")
	assert.True(t, ok)
	assert.Equal(t, "a", alias)
	assert.Equal(t, "b__c", tool)
}

func TestParseNamespacedToolName_NoSeparator(t *testing.T) {
	_, _, ok := parseNamespacedToolName("greet")
	assert.False(t, ok)
}

func TestParseNamespacedToolName_EmptyAlias(t *testing.T) {
	_, _, ok := parseNamespacedToolName("__greet")
	assert.False(t, ok)
}

func TestParseNamespacedToolName_EmptyTool(t *testing.T) {
	_, _, ok := parseNamespacedToolName("echo__")
	assert.False(t, ok)
}

func TestNamespacedResourceName(t *testing.T) {
	assert.Equal(t, "files__readme", namespacedResourceName("files", "readme"))
}
