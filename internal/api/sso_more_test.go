// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"net/http"
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/oidc/oidctest"
)

// The single sign-on test names what to fill in, and says how the
// client secret is sent: not at all for a public client, in the form
// when the provider asks for it there.
func TestTestSSOMore(t *testing.T) {
	p := oidctest.New(t)
	ts, _ := newSSOServer(t, p, nil)
	test := func(body string) (int, map[string]any, string) {
		t.Helper()
		return call(t, ts, "POST", "/api/auth/oidc/test", body, "admin", adminPass, nil)
	}
	if code, _, _ := test(`{`); code != http.StatusBadRequest {
		t.Errorf("bad JSON: %d", code)
	}
	for body, key := range map[string]string{
		`{"clear":["auth.oidc.provider"]}`:  "auth.oidc.provider",
		`{"clear":["auth.oidc.issuer"]}`:    "auth.oidc.issuer",
		`{"clear":["auth.oidc.client_id"]}`: "auth.oidc.client_id",
	} {
		code, out, raw := test(body)
		if fields, _ := out["fields"].(map[string]any); code != http.StatusBadRequest || fields[key] == nil {
			t.Errorf("%s: %d %s", body, code, raw)
		}
	}

	step := func(raw, name string) string {
		t.Helper()
		_, out, _ := test(raw)
		for _, s := range out["steps"].([]any) {
			if st := s.(map[string]any); st["name"] == name {
				return st["detail"].(string)
			}
		}
		t.Errorf("%s: no step %q in %v", raw, name, out)
		return ""
	}
	if d := step(`{"clear":["auth.oidc.client_secret"]}`, "Client secret"); !strings.Contains(d, "a public client") {
		t.Errorf("public client: %q", d)
	}
	p.Set(func(p *oidctest.Provider) { p.AuthMethods = []string{"client_secret_post"} })
	if d := step(`{"values":{}}`, "Client secret"); !strings.Contains(d, "in the form") {
		t.Errorf("secret in the form: %q", d)
	}
}
