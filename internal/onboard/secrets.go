package onboard

import "regexp"

// secretValue finds a credential's value after its name in a log line:
// password=..., "api_key": "...", token: ..., and Authorization headers.
var secretValue = regexp.MustCompile(`(?i)((?:password|passwd|pwd|secret|token|api[_-]?key|apikey|cookie|session[_-]?id|private[_-]?key|authorization)"?\s*[:=]\s*"?)(?:(?:bearer|basic)\s+)?([^"\s,;&]+)`)

// MaskSecrets replaces the values of credentials in a sample line with
// [masked] before the line is sent to an AI model.
func MaskSecrets(line string) string {
	return secretValue.ReplaceAllString(line, "${1}[masked]")
}
