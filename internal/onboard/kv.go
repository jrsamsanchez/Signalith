package onboard

import "strings"

// maxKeyLen is the longest key ParseKV takes.
const maxKeyLen = 64

// ParseKV reads key=value pairs (or key:value, with sep ":") from s, in
// order. Pairs are separated by white space, or by delim and white space.
// A value runs to the next key, so unquoted values may hold spaces
// (msg=Login failed for bob user=bob); a value in double or single quotes
// ends at its closing quote and loses the quotes.
func ParseKV(s, sep, delim string) [][2]string {
	if sep == "" {
		sep = "="
	}
	var out [][2]string
	pos := 0
	ks, ke, ok := nextKey(s, 0, sep, delim)
	for ok && len(out) < maxFields {
		key := s[ks:ke]
		vs := ke + len(sep)
		if sep == ":" && vs < len(s) && s[vs] == ' ' {
			vs++
		}
		if vs < len(s) && (s[vs] == '"' || s[vs] == '\'') {
			end := closingQuote(s, vs)
			out = append(out, [2]string{key, unquote(s[vs:end])})
			pos = end
			ks, ke, ok = nextKey(s, pos, sep, delim)
			continue
		}
		nks, nke, nok := nextKey(s, vs, sep, delim)
		end := len(s)
		if nok {
			end = nks
		}
		v := strings.TrimRight(s[vs:end], " \t")
		if delim != "" {
			v = strings.TrimRight(strings.TrimSuffix(v, delim), " \t")
		}
		out = append(out, [2]string{key, v})
		ks, ke, ok = nks, nke, nok
	}
	return out
}

// nextKey finds the next key at or after from: key characters right
// after the start of s, white space or delim, and right before sep.
func nextKey(s string, from int, sep, delim string) (int, int, bool) {
	for i := from; i < len(s); i++ {
		if i > 0 && !boundary(s[i-1], delim) {
			continue
		}
		if !keyStart(s[i]) {
			continue
		}
		j := i + 1
		for j < len(s) && j-i < maxKeyLen && keyChar(s[j]) {
			j++
		}
		if strings.HasPrefix(s[j:], sep) && !(sep == ":" && strings.HasPrefix(s[j:], "://")) {
			return i, j, true
		}
	}
	return 0, 0, false
}

func boundary(c byte, delim string) bool {
	return c == ' ' || c == '\t' || delim != "" && c == delim[0] || c == '[' || c == '{'
}

func keyStart(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '_' || c == '@'
}

func keyChar(c byte) bool {
	return keyStart(c) || c >= '0' && c <= '9' || c == '.' || c == '-'
}

// closingQuote returns the index just past the quote that closes the one
// at s[i], or len(s) when none does.
func closingQuote(s string, i int) int {
	q := s[i]
	for j := i + 1; j < len(s); j++ {
		switch s[j] {
		case '\\':
			j++
		case q:
			return j + 1
		}
	}
	return len(s)
}

// unquote strips a quoted value's quotes and backslash escapes.
func unquote(v string) string {
	if len(v) < 2 || v[len(v)-1] != v[0] {
		return strings.TrimLeft(v, `"'`)
	}
	v = v[1 : len(v)-1]
	if !strings.Contains(v, `\`) {
		return v
	}
	var b strings.Builder
	for i := 0; i < len(v); i++ {
		if v[i] == '\\' && i+1 < len(v) {
			i++
		}
		b.WriteByte(v[i])
	}
	return b.String()
}
