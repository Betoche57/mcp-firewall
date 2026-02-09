package sandbox

import "strings"

// FilterEnv returns only env vars whose keys are in the allowlist.
// Entries without '=' are dropped. Key matching is case-sensitive.
func FilterEnv(env []string, allowlist []string) []string {
	if len(env) == 0 || len(allowlist) == 0 {
		return nil
	}

	allowed := make(map[string]bool, len(allowlist))
	for _, k := range allowlist {
		allowed[k] = true
	}

	var result []string
	for _, entry := range env {
		k, _, ok := strings.Cut(entry, "=")
		if !ok {
			continue
		}
		if allowed[k] {
			result = append(result, entry)
		}
	}
	return result
}
