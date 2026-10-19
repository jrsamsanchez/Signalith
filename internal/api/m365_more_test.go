package api

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/m365"
)

// The Microsoft 365 test names the ID or secret still missing, and says
// when every audit log is subscribed to.
func TestTestM365More(t *testing.T) {
	ts, _, _ := newSettingsServer(t, "", func(s *Server) {
		s.M365Check = func(context.Context, m365.Settings) (map[string]bool, error) {
			all := map[string]bool{}
			for _, ct := range m365.ContentTypes {
				all[ct] = true
			}
			return all, nil
		}
	})
	test := func(body string) (int, map[string]any) {
		t.Helper()
		code, out, _ := call(t, ts, "POST", "/api/settings/test/m365", body, "admin", "s3cret-pass", nil)
		return code, out
	}
	if code, _ := test(`{`); code != http.StatusBadRequest {
		t.Errorf("bad JSON: %d", code)
	}
	tenant := `"m365.tenant_id":"11111111-2222-3333-4444-555555555555"`
	client := `"m365.client_id":"66666666-7777-8888-9999-000000000000"`
	for body, key := range map[string]string{
		`{"values":{` + tenant + `}}`:                "m365.client_id",
		`{"values":{` + tenant + `,` + client + `}}`: "m365.client_secret",
	} {
		code, out := test(body)
		if fields, _ := out["fields"].(map[string]any); code != http.StatusBadRequest || fields[key] == nil {
			t.Errorf("%s: %d %v", body, code, out)
		}
	}
	code, out := test(`{"values":{` + tenant + `,` + client + `,"m365.client_secret":"made-up-secret"}}`)
	if msg, _ := out["message"].(string); code != http.StatusOK || out["ok"] != true || strings.Contains(msg, "starts the rest") {
		t.Errorf("all subscribed: %d %v", code, out)
	}
}

// A failed Microsoft 365 test is worded by what Microsoft said.
func TestExplainM365(t *testing.T) {
	for _, c := range []struct {
		err   error
		field string
		want  string
	}{
		{&m365.APIError{Status: 400, Code: "unauthorized_client", Message: "AADSTS700016: Application not found"}, "m365.client_id", "no app with that application ID"},
		{&m365.APIError{Status: 400, Code: "invalid_request", Message: "AADSTS90002: Tenant not found"}, "m365.tenant_id", "no tenant with that ID"},
		{&m365.APIError{Status: 403, Code: "AF20010", Message: "not permitted"}, "m365.client_id", "ActivityFeed.Read"},
		{context.DeadlineExceeded, "", "did not answer in time"},
		{errors.New("connection refused"), "", "Connection refused"},
	} {
		msg, field := explainM365(c.err)
		if field != c.field || !strings.Contains(msg, c.want) {
			t.Errorf("%v: %q %q", c.err, msg, field)
		}
	}
}
