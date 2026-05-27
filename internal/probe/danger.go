package probe

import "strings"

// dangerSubstrings mirrors nodeCommon.py:51 dangerApiList. Any path that
// contains one of these (case-insensitive) is skipped during probing to
// avoid invoking destructive endpoints.
var dangerSubstrings = []string{
	"del", "delete", "insert", "logout", "remove", "drop", "shutdown", "stop",
	"poweroff", "restart", "rewrite", "terminate", "deactivate", "halt", "disable",
}

// IsDangerous reports whether path contains any of the dangerSubstrings
// (case-insensitive substring match on the LOWERCASED path).
func IsDangerous(path string) bool {
	p := strings.ToLower(path)
	for _, d := range dangerSubstrings {
		if strings.Contains(p, d) {
			return true
		}
	}
	return false
}
