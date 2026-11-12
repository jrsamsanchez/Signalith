// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"net/http"
	"strings"
	"testing"
)

// The assistant test and the model list check the address before they
// reach out to it: a provider that is not offered, an address with a
// query, a cloud metadata address and plain http to a public address are
// each answered in words, with nothing sent.
func TestAssistantChecksAddressFirst(t *testing.T) {
	ts, _ := newTestServer(t)
	values := func(provider, url string) string {
		return `{"values":{"assistant.provider":"` + provider + `","assistant.url":"` + url + `","assistant.model":"m"}}`
	}
	for _, c := range []struct {
		path, body string
		field      string
		want       string
	}{
		{"/api/settings/test/assistant", values("bogus", ""), "assistant.provider", ""},
		{"/api/settings/test/assistant", values("openai", "http://localhost:11434/v1?x=1"), "assistant.url", "? or #"},
		{"/api/settings/test/assistant", values("openai", "http://169.254.169.254/v1"), "assistant.url", "metadata"},
	} {
		code, out := do(t, ts, "POST", c.path, c.body, true)
		fields, _ := out["fields"].(map[string]any)
		msg, _ := fields[c.field].(string)
		if code >= 500 || msg == "" || !strings.Contains(msg, c.want) {
			t.Errorf("%s: %d %v", c.body, code, out)
		}
	}
	for _, c := range []struct{ body, want string }{
		{values("openai", "http://169.254.169.254/v1"), "Fix the address"},
		{values("openai", "http://203.0.113.5/v1"), "plain http to a public address"},
		{values("anthropic", ""), "Save an API key"},
	} {
		code, out := do(t, ts, "POST", "/api/settings/assistant/models", c.body, true)
		if msg, _ := out["message"].(string); code != http.StatusOK || !strings.Contains(msg, c.want) {
			t.Errorf("models %s: %d %v", c.body, code, out)
		}
	}
	for _, path := range []string{"/api/settings/test/assistant", "/api/settings/assistant/models", "/api/settings/test/opensearch"} {
		if code, _ := do(t, ts, "POST", path, `{`, true); code != http.StatusBadRequest {
			t.Errorf("%s bad JSON: %d", path, code)
		}
	}
	// OpenSearch's test needs an address.
	code, out := do(t, ts, "POST", "/api/settings/test/opensearch", `{"values":{"opensearch.url":"not a url"}}`, true)
	if fields, _ := out["fields"].(map[string]any); code >= 500 || fields["opensearch.url"] == nil {
		t.Errorf("opensearch: %d %v", code, out)
	}
}
