// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package query

import "strings"

// RenameField returns the name a rename pair gives the field name, and
// whether the pair renames it. A * in the old name matches any text, and
// the new name's * in the same place takes that text:
// rename *_ip as * renames src_ip to src.
func RenameField(p [2]string, name string) (string, bool) {
	if !strings.Contains(p[0], "*") {
		return p[1], name == p[0]
	}
	parts := strings.Split(p[0], "*")
	if !strings.HasPrefix(name, parts[0]) {
		return "", false
	}
	rest := name[len(parts[0]):]
	caps := make([]string, 0, len(parts)-1)
	for i, part := range parts[1:] {
		last := i == len(parts)-2
		var at int
		if last {
			if !strings.HasSuffix(rest, part) {
				return "", false
			}
			at = len(rest) - len(part)
		} else if at = strings.Index(rest, part); at < 0 {
			return "", false
		}
		caps = append(caps, rest[:at])
		rest = rest[at+len(part):]
	}
	if !strings.Contains(p[1], "*") {
		return p[1], true
	}
	var b strings.Builder
	for i, part := range strings.Split(p[1], "*") {
		if i > 0 {
			b.WriteString(caps[i-1])
		}
		b.WriteString(part)
	}
	return b.String(), true
}

// MaxRenameWildcards caps the * in one rename name.
const MaxRenameWildcards = 10

// checkRename returns what is wrong with a rename pair, or "".
func checkRename(from, to string) string {
	n, m := strings.Count(from, "*"), strings.Count(to, "*")
	switch {
	case n > MaxRenameWildcards:
		return "has too many *"
	case m > 0 && m != n:
		return "needs as many * in the new name as in the old one, as in rename *_ip as *"
	case n > 0 && strings.Contains(from, "**"):
		return "cannot have ** in the old name"
	case n > 0 && m == 0:
		return "renames every matching field to one name; put a * in the new name, as in rename *_ip as *"
	}
	return ""
}
