// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package assistant

import (
	"context"
	"net/http"
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
	for raw, want := range map[string]bool{
		"http://localhost:11434/v1": false,
		"http://127.0.0.1:11434":    false,
		"http://[::1]:11434":        false,
		"https://ollama.lan":        false,
		"http://ollama.lan:11434":   true,
		"http://10.0.0.5:11434":     true,
		"HTTP://10.0.0.5":           true,
	} {
		if got := Insecure(raw); got != want {
			t.Errorf("Insecure(%q) = %v", raw, got)
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
