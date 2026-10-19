// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package query

import (
	"fmt"
	"strings"

	"github.com/jrsamsanchez/signalith/internal/datamodel"
)

// CheckDatamodel returns an error unless name is one of the built-in data
// models (in any case). datamodel= picks indices by name, so an unknown
// one could only ever match nothing, or something that is not an event.
func CheckDatamodel(name string) error {
	if _, ok := datamodel.Get(name); ok {
		return nil
	}
	names := make([]string, len(datamodel.Models))
	for i, m := range datamodel.Models {
		names[i] = m.Name
	}
	return fmt.Errorf("unknown data model %q; use one of %s", name, strings.Join(names, ", "))
}

// CheckIndex returns an error for an index= value that could reach more
// than Signalith's own event indices: a list, an exclusion, a system or
// hidden index, another cluster (remote:index) or date math, or a wildcard
// before the first "-", which could match outside the index prefix. What
// is left is one pattern of lower-case letters, digits, "-", "_", "." and
// "*" that starts with a literal prefix and "-". The search engine then
// requires that prefix to be the configured one. index=* alone is allowed:
// it means every Signalith event index, as when index= is left out.
func CheckIndex(v string) error {
	v = strings.ToLower(v)
	if v == "*" {
		return nil
	}
	bad := func(why string) error {
		return fmt.Errorf("index=%q %s. Use datamodel= (for example datamodel=Authentication), or one pattern of Signalith's daily indices such as signalith-* or signalith-authentication-2026.10.*", v, why)
	}
	switch {
	case v == "":
		return bad("is empty")
	case len(v) > 255:
		return bad("is too long")
	case strings.Contains(v, ","):
		return bad("lists several indices, which is not allowed")
	case strings.Contains(v, ":"):
		return bad("names another cluster, which is not allowed")
	case strings.ContainsAny(v, "<>{}"):
		return bad("uses date math, which is not allowed")
	case strings.ContainsAny(v[:1], "-_.+*"):
		return bad("must start with the index prefix (exclusions, wildcards and system or hidden indices are not allowed)")
	}
	for _, r := range v {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.' || r == '*') {
			return bad(fmt.Sprintf("has %q, which index patterns cannot contain", r))
		}
	}
	prefix, _, ok := strings.Cut(v, "-")
	if !ok || strings.Contains(prefix, "*") {
		return bad("must start with the index prefix and \"-\"")
	}
	return nil
}
