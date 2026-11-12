// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package ingest

import (
	"strings"
	"testing"
)

func TestGitHubRedactValues(t *testing.T) {
	in := map[string]any{
		"config":       map[string]any{"url": "https://user:token@hooks.example.com/x?secret=abc#frag", "name": "hook"},
		"redirect_url": []any{"https://a.example/?k=v", "https://clean.example/"},
		"other":        "https://u:p@not-a-url-field.example/",
	}
	out, changed := githubRedactValue("", in)
	if !changed {
		t.Fatal("nothing was redacted")
	}
	m := out.(map[string]any)
	u := m["config"].(map[string]any)["url"].(string)
	if strings.Contains(u, "token") || strings.Contains(u, "abc") || strings.Contains(u, "frag") || !strings.Contains(u, "hooks.example.com") {
		t.Errorf("config.url = %q", u)
	}
	urls := m["redirect_url"].([]any)
	if strings.Contains(urls[0].(string), "k=v") || urls[1] != "https://clean.example/" {
		t.Errorf("urls = %v", urls)
	}
	if m["other"] != "https://u:p@not-a-url-field.example/" {
		t.Errorf("a field not named url was changed: %v", m["other"])
	}
	// The input is not changed.
	if in["config"].(map[string]any)["url"] != "https://user:token@hooks.example.com/x?secret=abc#frag" {
		t.Error("the input was changed")
	}
	if _, changed := githubRedactValue("url", "https://clean.example/"); changed {
		t.Error("a clean address was changed")
	}
	if _, changed := githubRedactValue("x", []any{"a"}); changed {
		t.Error("a clean list was changed")
	}
	for in, want := range map[string]string{
		"%zz@secret": kubeRedacted,
		"%zz plain":  "%zz plain",
	} {
		if got := redactURL(in); got != want {
			t.Errorf("redactURL(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSweepQueries(t *testing.T) {
	s := `GET /a?x=1&y=2 HTTP/1.1 then /b? and /c?z=3#f`
	got := sweepQueries(s, false)
	if strings.Contains(got, "x=1") || strings.Contains(got, "z=3") || !strings.Contains(got, "x="+RedactedValue) {
		t.Errorf("redacted = %q", got)
	}
	got = sweepQueries(s, true)
	if strings.Contains(got, "x=1") || strings.Contains(got, "/a?") || !strings.Contains(got, "/a HTTP/1.1") {
		t.Errorf("dropped = %q", got)
	}
	if got := sweepQueries("no addresses here", true); got != "no addresses here" {
		t.Errorf("plain text = %q", got)
	}
	f := map[string]any{"url": "https://x.example/p?token=abc#frag", "request": "GET /p?token=abc HTTP/1.1", "uri": "no-query"}
	ApplyURLQuery(f, URLQueryRedact)
	if strings.Contains(f["url"].(string), "abc") || !strings.HasSuffix(f["url"].(string), "#frag") {
		t.Errorf("url = %q", f["url"])
	}
	if strings.Contains(f["request"].(string), "abc") || !strings.HasSuffix(f["request"].(string), " HTTP/1.1") {
		t.Errorf("request = %q", f["request"])
	}
	if f["uri"] != "no-query" {
		t.Errorf("uri = %q", f["uri"])
	}
}
