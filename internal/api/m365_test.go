// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/m365"
)

func TestTestM365(t *testing.T) {
	var got m365.Settings
	ts, _, _ := newSettingsServer(t, "", func(s *Server) {
		s.M365Check = func(_ context.Context, st m365.Settings) (map[string]bool, error) {
			got = st
			if st.ClientSecret != "good" {
				return nil, &m365.APIError{Status: 401, Code: "invalid_client", Message: "AADSTS7000215: Invalid client secret provided."}
			}
			return map[string]bool{"Audit.Exchange": true}, nil
		}
	})
	test := func(body string) (int, map[string]any) {
		t.Helper()
		code, out, _ := call(t, ts, "POST", "/api/settings/test/m365", body, "admin", "s3cret-pass", nil)
		return code, out
	}
	if code, out := test(`{}`); code != 400 || out["fields"].(map[string]any)["m365.tenant_id"] == nil {
		t.Errorf("empty %d %v", code, out)
	}
	if code, out := test(`{"values":{"m365.tenant_id":"not-an-id"}}`); code != 400 || out["fields"].(map[string]any)["m365.tenant_id"] == nil {
		t.Errorf("bad tenant %d %v", code, out)
	}
	ids := `"m365.tenant_id":"11111111-2222-3333-4444-555555555555","m365.client_id":"66666666-7777-8888-9999-000000000000"`
	code, out := test(`{"values":{` + ids + `,"m365.client_secret":"good","m365.cloud":"gcc_high"}}`)
	if code != 200 || out["ok"] != true || !strings.Contains(out["message"].(string), "1 of the 4") {
		t.Errorf("good %d %v", code, out)
	}
	if got.TokenURL != "https://login.microsoftonline.us/11111111-2222-3333-4444-555555555555/oauth2/v2.0/token" || got.APIURL != "https://manage.office365.us" {
		t.Errorf("settings %+v", got)
	}
	code, out = test(`{"values":{` + ids + `,"m365.client_secret":"bad"}}`)
	if code != 200 || out["ok"] != false || out["field"] != "m365.client_secret" {
		t.Errorf("bad secret %d %v", code, out)
	}
}

func TestM365Health(t *testing.T) {
	until := time.Date(2026, 10, 15, 10, 0, 0, 0, time.UTC)
	ts, _, _ := newSettingsServer(t, "m365:\n  tenant_id: 11111111-2222-3333-4444-555555555555\n  client_id: 66666666-7777-8888-9999-000000000000\n  client_secret: s\n", func(s *Server) {
		s.M365Cursors = func(_ context.Context, tenant string) ([]m365.Cursor, error) {
			return []m365.Cursor{{Tenant: tenant, ContentType: "Audit.Exchange", Until: until, LastRecords: 3, LastError: "AF429"}}, nil
		}
	})
	_, out, _ := call(t, ts, "GET", "/api/health", "", "admin", "s3cret-pass", nil)
	m, _ := out["m365"].(map[string]any)
	types, _ := m["content_types"].([]any)
	if m["on"] != true || len(types) != 1 || types[0].(map[string]any)["last_error"] != "AF429" {
		t.Errorf("health %v", out["m365"])
	}
}
