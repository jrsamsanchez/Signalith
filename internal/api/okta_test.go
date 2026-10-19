// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/okta"
)

// testKey stands in for a private key: the page only checks its shape,
// and the test's check never reads it.
const testKey = "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----"

func TestTestOkta(t *testing.T) {
	var got okta.Settings
	ts, _, _ := newSettingsServer(t, "", func(s *Server) {
		s.OktaCheck = func(_ context.Context, st okta.Settings) (*okta.CheckResult, error) {
			got = st
			if st.ClientID != "0oagood" {
				return nil, &okta.APIError{Status: 401, Code: "invalid_client", Message: "The client_assertion signature is invalid."}
			}
			return &okta.CheckResult{Auth: "oauth", DPoP: true, Events: 12}, nil
		}
	})
	test := func(body string) (int, map[string]any) {
		t.Helper()
		code, out, _ := call(t, ts, "POST", "/api/settings/test/okta", body, "admin", "s3cret-pass", nil)
		return code, out
	}
	if code, out := test(`{}`); code != 400 || out["fields"].(map[string]any)["okta.domain"] == nil {
		t.Errorf("empty %d %v", code, out)
	}
	for _, d := range []string{"example.okta.com:8443", "10.0.0.1", "example.okta.com/path", "not a host"} {
		if code, out := test(`{"values":{"okta.domain":"` + d + `"}}`); code != 400 || out["fields"].(map[string]any)["okta.domain"] == nil {
			t.Errorf("domain %q: %d %v", d, code, out)
		}
	}
	if code, out := test(`{"values":{"okta.domain":"example.okta.com","okta.client_id":"0oagood"}}`); code != 400 || out["fields"].(map[string]any)["okta.private_key"] == nil {
		t.Errorf("no key %d %v", code, out)
	}
	if code, out := test(`{"values":{"okta.domain":"example.okta.com","okta.client_id":"0oagood","okta.private_key":"-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----"}}`); code != 400 || out["fields"].(map[string]any)["okta.private_key"] == nil {
		t.Errorf("public key %d %v", code, out)
	}
	key, _ := json.Marshal(testKey)
	code, out := test(`{"values":{"okta.domain":"https://Example.Okta.com/","okta.client_id":"0oagood","okta.private_key":` + string(key) + `}}`)
	if code != 200 || out["ok"] != true || out["dpop"] != true || !strings.Contains(out["message"].(string), "12 events") {
		t.Errorf("good %d %v", code, out)
	}
	if got.Domain != "example.okta.com" || got.PrivateKey != testKey {
		t.Errorf("settings %+v", got.Domain)
	}
	code, out = test(`{"values":{"okta.domain":"example.okta.com","okta.client_id":"0oabad","okta.private_key":` + string(key) + `}}`)
	if code != 200 || out["ok"] != false || out["field"] != "okta.private_key" || strings.Contains(out["message"].(string), "AAAA") {
		t.Errorf("bad key %d %v", code, out)
	}
}

func TestOktaHealth(t *testing.T) {
	until := time.Date(2026, 10, 15, 10, 0, 0, 0, time.UTC)
	ts, _, _ := newSettingsServer(t, "okta:\n  domain: example.okta.com\n  api_token: t\n", func(s *Server) {
		s.OktaCursor = func(_ context.Context, domain string) (okta.Cursor, bool, error) {
			return okta.Cursor{Domain: domain, Until: until, LastRecords: 3, LastError: "E0000047"}, true, nil
		}
	})
	_, out, _ := call(t, ts, "GET", "/api/health", "", "admin", "s3cret-pass", nil)
	m, _ := out["okta"].(map[string]any)
	if m["on"] != true || m["domain"] != "example.okta.com" || m["last_error"] != "E0000047" {
		t.Errorf("health %v", out["okta"])
	}
}
