// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package oslocal

import (
	"net/http"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseProxy(t *testing.T) {
	for in, want := range map[string]string{
		"proxy.example.com:3128":          "http://proxy.example.com:3128",
		"http://10.0.0.5:8080":            "http://10.0.0.5:8080",
		" https://proxy.example.com:443/": "https://proxy.example.com:443",
		"[fd00::1]:3128":                  "http://[fd00::1]:3128",
	} {
		u, err := parseProxy(in)
		if err != nil || u.String() != want {
			t.Errorf("parseProxy(%q) = %v, %v; want %s", in, u, err, want)
		}
	}
	for _, in := range []string{"", "http://", "socks5://proxy:1080", "http://user:secret@proxy:3128", "proxy:3128/path", "http://proxy:3128/?x=1",
		"bob:secret%et@proxy:3128", "http://bob:pa secret@proxy:3128", "http://bad host secret:1"} {
		u, err := parseProxy(in)
		if err == nil {
			t.Errorf("parseProxy(%q) = %v; want an error", in, u)
			continue
		}
		if strings.Contains(err.Error(), "secret") {
			t.Errorf("the error names the password: %v", err)
		}
	}
}

func TestWinHTTPProxy(t *testing.T) {
	for in, want := range map[string]string{
		"proxy:3128":                       "http://proxy:3128",
		"http=web:80;https=secure:443":     "http://secure:443",
		"http=web:80":                      "http://web:80",
		"ftp=f:21 proxy:8080":              "http://proxy:8080",
		"https=user:pw@bad:1;http=good:80": "http://good:80",
		"":                                 "",
	} {
		got := winHTTPProxy(in)
		if s := func() string {
			if got == nil {
				return ""
			}
			return got.String()
		}(); s != want {
			t.Errorf("winHTTPProxy(%q) = %q, want %q", in, s, want)
		}
	}
}

func TestClientProxy(t *testing.T) {
	c, err := Client("proxy.example.com:3128")
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest(http.MethodGet, URL(), nil)
	u, err := c.Transport.(*http.Transport).Proxy(req)
	if err != nil || u == nil || u.Host != "proxy.example.com:3128" {
		t.Fatalf("proxy = %v, %v", u, err)
	}
	if _, err := Client("http://u:p@proxy:1"); err == nil {
		t.Fatal("a proxy with a password was taken")
	}
	// Without one: the computer's setting, then HTTPS_PROXY.
	t.Setenv("HTTPS_PROXY", "http://envproxy:3128")
	c, err = Client("")
	if err != nil {
		t.Fatal(err)
	}
	if systemProxy() == nil {
		u, _ := c.Transport.(*http.Transport).Proxy(req)
		if u == nil || u.Host != "envproxy:3128" {
			t.Fatalf("HTTPS_PROXY was not used: %v", u)
		}
	}
}

func TestCheckRoom(t *testing.T) {
	l := testLayout(t)
	// The test machine's disk: enough room passes, and folders not made
	// yet are checked on their nearest parent.
	free, err := freeBytes(filepath.Dir(l.Data))
	if err != nil {
		t.Skip(err)
	}
	err = CheckRoom(l)
	if free >= zipRoom+programRoom && err != nil {
		t.Fatalf("CheckRoom with %d MB free: %v", free>>20, err)
	}
	if free < zipRoom+programRoom && (err == nil || !strings.Contains(err.Error(), "MB free")) {
		t.Fatalf("CheckRoom with %d MB free = %v", free>>20, err)
	}
	if got := existing(filepath.Join(l.Data, "a", "b")); got != filepath.Dir(l.Data) {
		t.Fatalf("existing = %s", got)
	}
}
