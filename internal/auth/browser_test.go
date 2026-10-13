package auth

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestBrowserKeyCookies(t *testing.T) {
	k := NewBrowserKey()
	now := time.Date(2026, 10, 13, 9, 0, 0, 0, time.UTC)
	v := k.Issue("Admin", "builtin:hash1", now)
	id, ok := k.Check("admin", "builtin:hash1", v, now.Add(time.Hour))
	if !ok || id == "" {
		t.Fatalf("a fresh cookie was refused (account names ignore case)")
	}
	if id2, _ := k.Check("admin", "builtin:hash1", k.Issue("admin", "builtin:hash1", now), now); id2 == id {
		t.Error("two cookies have the same browser id")
	}
	for name, c := range map[string]struct {
		account, version, value string
		at                      time.Time
	}{
		"another account":         {"vera", "builtin:hash1", v, now},
		"a changed password":      {"admin", "builtin:hash2", v, now},
		"too old":                 {"admin", "builtin:hash1", v, now.Add(KnownBrowserAge)},
		"from the future":         {"admin", "builtin:hash1", v, now.Add(-48 * time.Hour)},
		"changed":                 {"admin", "builtin:hash1", flip(v, len(v)-10), now},
		"with a changed id":       {"admin", "builtin:hash1", flip(v, len(browserPrefix)+14), now},
		"cut short":               {"admin", "builtin:hash1", v[:len(v)-4], now},
		"empty":                   {"admin", "builtin:hash1", "", now},
		"made with another key":   {"admin", "builtin:hash1", NewBrowserKey().Issue("admin", "builtin:hash1", now), now},
		"without its version tag": {"admin", "builtin:hash1", strings.TrimPrefix(v, browserPrefix), now},
	} {
		if _, ok := k.Check(c.account, c.version, c.value, c.at); ok {
			t.Errorf("a cookie for %s was accepted", name)
		}
	}
	// The cookie name stands for the account without naming it.
	if s := k.CookieSuffix("admin"); s != k.CookieSuffix(" ADMIN") || s == k.CookieSuffix("vera") || strings.Contains(s, "admin") {
		t.Errorf("cookie suffix %q", s)
	}
	if NewBrowserKey().CookieSuffix("admin") == k.CookieSuffix("admin") {
		t.Error("two keys give the same cookie name")
	}
}

func TestLoadBrowserKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "signin.key")
	k, created, err := LoadBrowserKey(path)
	if err != nil || !created {
		t.Fatalf("first load: created %v, %v", created, err)
	}
	now := time.Now()
	v := k.Issue("admin", "x", now)
	if runtime.GOOS != "windows" {
		if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 {
			t.Errorf("key file mode %v, %v; want 0600", fi.Mode().Perm(), err)
		}
	}
	// A restart reads the same key, so browsers stay known.
	k2, created, err := LoadBrowserKey(path)
	if err != nil || created {
		t.Fatalf("second load: created %v, %v", created, err)
	}
	if _, ok := k2.Check("admin", "x", v, now); !ok {
		t.Error("a cookie from before the restart was refused")
	}
	// Several processes starting at once agree on one key.
	path2 := filepath.Join(dir, "race.key")
	keys := make([]*BrowserKey, 8)
	var wg sync.WaitGroup
	for i := range keys {
		wg.Add(1)
		go func() {
			defer wg.Done()
			keys[i], _, _ = LoadBrowserKey(path2)
		}()
	}
	wg.Wait()
	v = keys[0].Issue("admin", "x", now)
	for i, k := range keys {
		if k == nil {
			t.Fatalf("load %d failed", i)
		}
		if _, ok := k.Check("admin", "x", v, now); !ok {
			t.Errorf("load %d got another key", i)
		}
	}
	// A damaged file is reported, not replaced.
	bad := filepath.Join(dir, "bad.key")
	if err := os.WriteFile(bad, []byte("# a comment\nnot a key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadBrowserKey(bad); err == nil || !strings.Contains(err.Error(), "Delete the file and restart Signalith") {
		t.Errorf("damaged key file: %v", err)
	}
	if b, _ := os.ReadFile(bad); string(b) != "# a comment\nnot a key\n" {
		t.Error("a damaged key file was changed")
	}
	// Line endings from a Windows editor are fine.
	data, _ := os.ReadFile(path)
	crlf := filepath.Join(dir, "crlf.key")
	if err := os.WriteFile(crlf, []byte(strings.ReplaceAll(string(data), "\n", "\r\n")), 0o600); err != nil {
		t.Fatal(err)
	}
	if k3, _, err := LoadBrowserKey(crlf); err != nil {
		t.Errorf("key file with CRLF: %v", err)
	} else if _, ok := k3.Check("admin", "x", k.Issue("admin", "x", now), now); !ok {
		t.Error("key file with CRLF read as another key")
	}
}

// flip changes the character at i of a cookie value.
func flip(v string, i int) string {
	c := byte('A')
	if v[i] == 'A' {
		c = 'B'
	}
	return v[:i] + string(c) + v[i+1:]
}
