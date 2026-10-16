package onboard

import (
	"regexp"
	"strings"
)

// secretKeys are the names whose values are credentials.
const secretKeys = `(?:password|passwd|passphrase|pwd|pass|secret|client[_-]?secret|token|access[_-]?token|refresh[_-]?token|id[_-]?token|` +
	`api[_-]?key|apikey|key|auth|credentials?|session[_-]?id|sessionid|private[_-]?key|sig|signature|` +
	`x-amz-signature|x-amz-credential|x-amz-security-token|aws_secret_access_key|aws_session_token|authorization)`

var (
	pemBlock   = regexp.MustCompile(`-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----(?s:.*?)(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|$)`)
	urlUser    = regexp.MustCompile(`(?i)\b([a-z][a-z0-9+.-]*://[^/\s:@]*:)[^@\s/]+@`)
	cookieLine = regexp.MustCompile(`(?i)\b((?:set-)?cookie\s*:\s*)[^\r\n]*`)
	// In CEF and LEEF a value runs to the next key=, spaces and all.
	cefValue    = regexp.MustCompile(`(?i)(\b` + secretKeys + `=)((?:[^=\\]|\\.)*?)(\s+[A-Za-z0-9_.]+=|$)`)
	dquoted     = regexp.MustCompile(`(?i)(["']?\b` + secretKeys + `\b["']?\s*(?:=>|[:=])\s*)"(?:[^"\\]|\\.)*"`)
	squoted     = regexp.MustCompile(`(?i)(["']?\b` + secretKeys + `\b["']?\s*(?:=>|[:=])\s*)'(?:[^'\\]|\\.)*'`)
	unquoted    = regexp.MustCompile(`(?i)(["']?\b` + secretKeys + `\b["']?\s*(?:=>|[:=])\s*)(?:(?:bearer|basic|digest|negotiate|token)\s+)?([^\s"',;&<>]+)`)
	xmlElement  = regexp.MustCompile(`(?i)(<` + secretKeys + `>)[^<]*(</)`)
	spacedValue = regexp.MustCompile(`(?i)\b(password|passwd|passphrase)(\s+(?:is\s+)?)(\S+)`)
	tokenShapes = regexp.MustCompile(`\b(?:AKIA|ASIA)[A-Z0-9]{16}\b|\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*|` +
		`\b(?:ghp|gho|ghs|ghu|ghr)_[A-Za-z0-9]{20,}|\bgithub_pat_[A-Za-z0-9_]{20,}|\bxox[abprs]-[A-Za-z0-9-]{10,}|\bglpat-[A-Za-z0-9_-]{20,}|\bsk-[A-Za-z0-9_-]{20,}`)
)

// notSecret are words that follow "password" in log prose without being
// one: "Failed password for bob".
var notSecret = map[string]bool{"for": true, "from": true, "of": true, "to": true, "by": true, "on": true, "in": true, "was": true,
	"has": true, "had": true, "changed": true, "reset": true, "expired": true, "failed": true, "accepted": true, "incorrect": true,
	"invalid": true, "change": true, "authentication": true, "policy": true, "check": true, "mismatch": true, "and": true, "or": true}

// MaskSecrets replaces credentials in a sample line with [masked] before
// the line is sent to an AI model: values after credential names (quoted
// ones whole), passwords in URLs, cookie headers, private keys and the
// shapes of common access keys and tokens.
func MaskSecrets(line string) string {
	line = pemBlock.ReplaceAllString(line, "[masked private key]")
	line = urlUser.ReplaceAllString(line, "${1}[masked]@")
	line = cookieLine.ReplaceAllString(line, "${1}[masked]")
	if strings.Contains(line, "CEF:") || strings.Contains(line, "LEEF:") {
		for i := 0; i < 8; i++ {
			next := cefValue.ReplaceAllString(line, "${1}[masked]${3}")
			if next == line {
				break
			}
			line = next
		}
	}
	line = dquoted.ReplaceAllString(line, `${1}"[masked]"`)
	line = squoted.ReplaceAllString(line, `${1}'[masked]'`)
	line = unquoted.ReplaceAllStringFunc(line, func(m string) string {
		sub := unquoted.FindStringSubmatch(m)
		if strings.HasPrefix(sub[2], "[masked") {
			return m
		}
		return sub[1] + "[masked]"
	})
	line = xmlElement.ReplaceAllString(line, "${1}[masked]${2}")
	line = spacedValue.ReplaceAllStringFunc(line, func(m string) string {
		sub := spacedValue.FindStringSubmatch(m)
		if notSecret[strings.ToLower(sub[3])] || strings.HasPrefix(sub[3], "[masked") || strings.ContainsAny(sub[3][:1], "=:") {
			return m
		}
		return sub[1] + sub[2] + "[masked]"
	})
	return tokenShapes.ReplaceAllString(line, "[masked]")
}

// MaskSecretLines masks each line, and every line inside a private key
// block that spans lines.
func MaskSecretLines(lines []string) []string {
	out := make([]string, len(lines))
	inKey := false
	for i, l := range lines {
		begins := strings.Contains(l, "-----BEGIN ") && strings.Contains(l, "PRIVATE KEY-----")
		ends := strings.Contains(l, "-----END ") && strings.Contains(l, "PRIVATE KEY-----")
		switch {
		case inKey:
			inKey = !ends
			out[i] = "[masked private key]"
		case begins && !ends:
			inKey = true
			out[i] = l[:strings.Index(l, "-----BEGIN ")] + "-----BEGIN PRIVATE KEY-----"
		default:
			out[i] = MaskSecrets(l)
		}
	}
	return out
}
