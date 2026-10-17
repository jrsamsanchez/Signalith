package ingest

import (
	"maps"
	"net/url"
	"strings"
)

// A webhook's address in a hook event (config.url) is whatever the admin
// set, and CI webhooks often carry a password or token in it
// (https://user:pass@ci.example.com/hook?token=...). Signalith never
// keeps them: the user name, password and query values of any address
// in a field whose name ends in url are replaced before the event's
// fields and its raw copy are made.

// githubRedact returns the event with the credentials in its addresses
// replaced, sharing what it does not change with r.
func githubRedact(r map[string]any) map[string]any {
	if v, changed := githubRedactValue("", r); changed {
		return v.(map[string]any)
	}
	return r
}

// githubRedactValue returns v with its addresses' credentials replaced,
// and whether any were; v itself is not changed. name is the field v is
// under.
func githubRedactValue(name string, v any) (any, bool) {
	switch x := v.(type) {
	case string:
		if strings.HasSuffix(strings.ToLower(name), "url") {
			if r := redactURL(x); r != x {
				return r, true
			}
		}
	case map[string]any:
		var out map[string]any
		for k, e := range x {
			if r, changed := githubRedactValue(k, e); changed {
				if out == nil {
					out = maps.Clone(x)
				}
				out[k] = r
			}
		}
		if out != nil {
			return out, true
		}
	case []any:
		var out []any
		for i, e := range x {
			if r, changed := githubRedactValue(name, e); changed {
				if out == nil {
					out = append([]any(nil), x...)
				}
				out[i] = r
			}
		}
		if out != nil {
			return out, true
		}
	}
	return v, false
}

// redactURL replaces an address's user name, password and query values.
func redactURL(s string) string {
	u, err := url.Parse(s)
	if err != nil {
		// Not an address Go reads: whatever follows @ or ? could be a
		// secret, so it is not kept.
		if strings.ContainsAny(s, "@?") {
			return kubeRedacted
		}
		return s
	}
	changed := false
	if u.User != nil {
		u.User = url.User(kubeRedacted)
		changed = true
	}
	if u.RawQuery != "" {
		q := u.Query()
		for k := range q {
			q[k] = []string{kubeRedacted}
		}
		u.RawQuery = q.Encode()
		changed = true
	}
	if u.Fragment != "" {
		u.Fragment = kubeRedacted
		changed = true
	}
	if !changed {
		return s
	}
	return u.String()
}
