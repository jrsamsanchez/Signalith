package tenants

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestValidID(t *testing.T) {
	for _, id := range []string{"ac", "acme", "contoso2", "a1b2c3", strings.Repeat("a", 24)} {
		if err := ValidID(id); err != nil {
			t.Errorf("ValidID(%q) = %v, want nil", id, err)
		}
	}
	for _, id := range []string{"", "a", "default", "Acme", "1acme", "ac-me", "ac_me", "ac.me", "ac me", "acme*", strings.Repeat("a", 25), "acmé"} {
		if ValidID(id) == nil {
			t.Errorf("ValidID(%q) = nil, want an error", id)
		}
	}
}

func TestPrefix(t *testing.T) {
	if got := Prefix("signalith", Default); got != "signalith" {
		t.Errorf("default prefix = %q", got)
	}
	if got := Prefix("signalith", ""); got != "signalith" {
		t.Errorf("empty tenant prefix = %q", got)
	}
	if got := Prefix("signalith", "acme"); got != "signalith.t.acme" {
		t.Errorf("acme prefix = %q", got)
	}
	if ValidConfiguredPrefix("signalith") != nil || ValidConfiguredPrefix("siem.t.x") == nil {
		t.Error("ValidConfiguredPrefix must refuse only prefixes with .t.")
	}
}

// match is OpenSearch's index wildcard matching: * matches any run of
// characters, everything else itself.
func match(pattern, name string) bool {
	parts := strings.Split(pattern, "*")
	if len(parts) == 1 {
		return pattern == name
	}
	if !strings.HasPrefix(name, parts[0]) {
		return false
	}
	name = name[len(parts[0]):]
	for _, p := range parts[1 : len(parts)-1] {
		i := strings.Index(name, p)
		if i < 0 {
			return false
		}
		name = name[i+len(p):]
	}
	return strings.HasSuffix(name, parts[len(parts)-1])
}

// indexNames are index names Signalith makes under prefix p.
func indexNames(p string) []string {
	return []string{
		p + "-authentication-2026.10.16", p + "-risk-2026.10.16", p + "-other-2026.10.16",
		p + "_findings", p + "_cases", p + "_intel", p + "_actions", p + "_notifications",
		p + "_playbook_runs", p + "_endpoints", p + "_vulns", p + "_runtime", p + "_config",
		p + "_sessions", p + "_audit-2026.10", p + "_config_retired_20261016",
	}
}

// patterns are the wildcard patterns Signalith builds from prefix p, and
// the widest a search's index= may name (it must start with p + "-").
func patterns(p string) []string {
	return []string{
		p + "-*", p + "_*", p + "-authentication-*", p + "-risk-*", p + "-other-*",
		p + "_audit-*", p + "_config_retired_*", p + "-*-*",
	}
}

// TestNoPatternReachesAnotherTenant is the property the index names rest
// on: no pattern of one tenant, default or not, matches an index of
// another, even when one ID starts with the other.
func TestNoPatternReachesAnotherTenant(t *testing.T) {
	for _, base := range []string{"signalith", "siem", "a-b", "x_y"} {
		ids := []string{Default, "ac", "acme", "acmex", "acme2", "acmeacme", "t", "tacme"}
		for _, a := range ids {
			if ValidID(a) != nil && a != Default {
				continue
			}
			for _, b := range ids {
				if a == b || ValidID(b) != nil && b != Default {
					continue
				}
				for _, pat := range patterns(Prefix(base, a)) {
					for _, name := range indexNames(Prefix(base, b)) {
						if match(pat, name) {
							t.Errorf("prefix %q: tenant %q's pattern %q matches tenant %q's index %q", base, a, pat, b, name)
						}
					}
				}
			}
			// Each tenant's own patterns do reach its own indices.
			if !match(Prefix(base, a)+"-*", Prefix(base, a)+"-authentication-2026.10.16") {
				t.Errorf("tenant %q cannot reach its own events", a)
			}
		}
	}
}

// TestSearchPrefixCheck is the search engine's rule for index=: the value
// must start with the tenant's own prefix and "-". No value that passes
// it for one tenant names an index of another.
func TestSearchPrefixCheck(t *testing.T) {
	own := Prefix("signalith", "acme") + "-"
	for _, other := range []string{"signalith", Prefix("signalith", "acmex"), Prefix("signalith", "ac")} {
		for _, name := range indexNames(other) {
			if strings.HasPrefix(name, own) {
				t.Errorf("index %q of %q starts with %q", name, other, own)
			}
		}
	}
}

func TestRegistry(t *testing.T) {
	dir := t.TempDir()
	r, err := Open(File(dir))
	if err != nil {
		t.Fatal(err)
	}
	if list, _ := r.List(); len(list) != 0 {
		t.Fatalf("new registry lists %v", list)
	}
	now := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
	if _, err := r.Add("zeta", "Zeta Corp", "admin", now); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Add("acme", " Acme ", "admin", now); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Add("acme", "Again", "admin", now); !errors.Is(err, ErrExists) {
		t.Errorf("adding acme twice: %v", err)
	}
	if _, err := r.Add("default", "Default", "admin", now); err == nil {
		t.Error("the default tenant's ID was accepted")
	}
	if _, err := r.Add("bad", "line\nbreak", "admin", now); err == nil {
		t.Error("a name with a control character was accepted")
	}
	list, err := r.List()
	if err != nil || len(list) != 2 || list[0].ID != "acme" || list[0].Name != "Acme" || list[1].ID != "zeta" {
		t.Fatalf("List = %+v, %v", list, err)
	}
	off := true
	if _, err := r.Change("acme", nil, &off); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Change("nobody", nil, &off); !errors.Is(err, ErrNotFound) {
		t.Errorf("changing a missing tenant: %v", err)
	}
	// Another process reading the same file sees the change.
	r2, err := Open(File(dir))
	if err != nil {
		t.Fatal(err)
	}
	got, err := r2.Get("acme")
	if err != nil || !got.Disabled || got.CreatedBy != "admin" || !got.Created.Equal(now) {
		t.Errorf("Get(acme) = %+v, %v", got, err)
	}
	if _, err := r2.Get(Default); !errors.Is(err, ErrNotFound) {
		t.Errorf("the default tenant is in the registry: %v", err)
	}
}

func TestRegistryRefusesDamagedFile(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string]string{
		"not json":  "{",
		"bad id":    `{"version":1,"tenants":[{"id":"ac-me","name":"x"}]}`,
		"duplicate": `{"version":1,"tenants":[{"id":"acme","name":"x"},{"id":"acme","name":"y"}]}`,
	} {
		p := filepath.Join(dir, strings.ReplaceAll(name, " ", "_")+".json")
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Open(p); err == nil {
			t.Errorf("%s: Open accepted the file", name)
		}
	}
}
