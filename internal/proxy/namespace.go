package proxy

import "strings"

const namespaceSeparator = "__"

func namespacedToolName(alias, toolName string) string {
	return alias + namespaceSeparator + toolName
}

func parseNamespacedToolName(name string) (alias, toolName string, ok bool) {
	idx := strings.Index(name, namespaceSeparator)
	if idx <= 0 {
		return "", "", false
	}
	alias = name[:idx]
	toolName = name[idx+len(namespaceSeparator):]
	if toolName == "" {
		return "", "", false
	}
	return alias, toolName, true
}

func namespacedResourceName(alias, resourceName string) string {
	return alias + namespaceSeparator + resourceName
}
