// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package assistant

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	neturl "net/url"
	"strings"
	"testing"
)

// The model's address cannot cut off Signalith's paths or point at cloud
// metadata (AI-03), and plain http is told apart by host (AI-02).
func TestModelAddressChecks(t *testing.T) {
	for _, bad := range []string{
		"http://10.0.0.5:8080/admin?",
		"http://10.0.0.5:8080/admin?x=1",
		"http://10.0.0.5:8080/admin#",
		"http://169.254.169.254/latest",
		"http://[fe80::1]:11434/v1",
		"http://[fd00:ec2::254]/",
		"http://[::ffff:169.254.169.254]/",
		"http://[fd20:ce::254]/computeMetadata/v1",
		"http://100.100.100.200/latest/meta-data",
	} {
		if CheckURL(bad) == nil {
			t.Errorf("CheckURL(%q) passed", bad)
		}
	}
	for _, good := range []string{"", "http://localhost:11434/v1", "https://api.openai.com/v1", "http://10.0.0.5:11434"} {
		if err := CheckURL(good); err != nil {
			t.Errorf("CheckURL(%q): %v", good, err)
		}
	}
	// Insecure: plain http beyond the local network. PlainRemote: plain
	// http to any other computer, which is warned about.
	for raw, want := range map[string][2]bool{
		"http://localhost:11434/v1":    {false, false},
		"http://127.0.0.1:11434":       {false, false},
		"http://[::1]:11434":           {false, false},
		"https://ollama.lan":           {false, false},
		"https://203.0.113.9/v1":       {false, false},
		"http://ollama:11434":          {false, true},
		"http://10.0.0.5:11434":        {false, true},
		"HTTP://192.168.1.20":          {false, true},
		"http://172.16.4.2:8000":       {false, true},
		"http://172.31.255.1":          {false, true},
		"http://[fd12:3456::1]:11434":  {false, true},
		"http://172.32.0.1":            {true, true},
		"http://203.0.113.9:11434/v1":  {true, true},
		"http://[2001:db8::1]:11434":   {true, true},
		"http://ollama.lan:11434":      {true, true},
		"http://models.example.com/v1": {true, true},
	} {
		if got := Insecure(raw); got != want[0] {
			t.Errorf("Insecure(%q) = %v", raw, got)
		}
		if got := PlainRemote(raw); got != want[1] {
			t.Errorf("PlainRemote(%q) = %v", raw, got)
		}
	}
}

// A connection to a link-local address is refused when it is made, so a
// name that resolves to one is refused too.
func TestModelClientRefusesLinkLocal(t *testing.T) {
	c := New(OpenAI, "http://169.254.169.254:80/v1", "m", "")
	// Without a proxy from the environment, which would make the
	// connection instead.
	c.HTTP.Transport.(*http.Transport).Proxy = nil
	_, err := c.ListModels(context.Background())
	if err == nil || !strings.Contains(err.Error(), "link-local") {
		t.Errorf("ListModels to 169.254.169.254: %v", err)
	}
}

// AI-03: through a proxy from the environment the connection is to the
// proxy, so the model's host is checked before the proxy is used.
func TestModelClientChecksTheHostBehindAProxy(t *testing.T) {
	proxyURL, _ := neturl.Parse("http://proxy.internal:3128")
	viaProxy := func(*http.Request) (*neturl.URL, error) { return proxyURL, nil }
	lookup := func(_ context.Context, _, host string) ([]netip.Addr, error) {
		switch host {
		case "evil.example":
			return []netip.Addr{netip.MustParseAddr("169.254.169.254")}, nil
		case "gcp6.example":
			return []netip.Addr{netip.MustParseAddr("fd20:ce::254")}, nil
		case "models.example":
			return []netip.Addr{netip.MustParseAddr("203.0.113.9")}, nil
		}
		return nil, errors.New("no such host")
	}
	p := checkedProxy(viaProxy, lookup)
	for raw, ok := range map[string]bool{
		"http://169.254.169.254/latest":            false,
		"http://100.100.100.200/latest":            false,
		"http://evil.example/v1":                   false,
		"http://gcp6.example/v1":                   false,
		"http://metadata.google.internal/":         false,
		"https://models.example/v1":                true,
		"https://only-the-proxy-resolves.example/": true,
		"http://10.0.0.5:11434/v1":                 true,
	} {
		req := httptest.NewRequest("GET", raw, nil)
		u, err := p(req)
		if ok && (err != nil || u != proxyURL) {
			t.Errorf("%s: proxy = %v, %v; want the proxy", raw, u, err)
		}
		if !ok && (err == nil || !strings.Contains(err.Error(), "metadata")) {
			t.Errorf("%s: proxy = %v, %v; want refused", raw, u, err)
		}
	}
	// The client's own transport goes through the check.
	tr := New(OpenAI, "http://169.254.169.254/v1", "m", "").HTTP.Transport.(*http.Transport)
	if tr.Proxy == nil {
		t.Fatal("the model client has no proxy function")
	}
}
