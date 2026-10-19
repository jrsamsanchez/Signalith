package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/okta"
)

// Each way an Okta test fails is worded for the setting to fix.
func TestExplainOkta(t *testing.T) {
	for _, c := range []struct {
		err         error
		oauth       bool
		want, field string
	}{
		{&okta.APIError{Status: 401, Code: "invalid_client", Message: "Invalid value for 'client_id' parameter."}, true, "no app with that client ID", "okta.client_id"},
		{&okta.APIError{Status: 401, Code: "invalid_client", Message: "The client_assertion signature is invalid."}, true, "refused the app's sign-in", "okta.private_key"},
		{&okta.APIError{Status: 400, Code: "invalid_scope"}, true, "did not grant the okta.logs.read scope", "okta.client_id"},
		{&okta.APIError{Status: 400, Code: "unauthorized_client"}, true, "did not grant the okta.logs.read scope", "okta.client_id"},
		{&okta.APIError{Status: 401, Code: "E0000011"}, true, "refused the app's token", "okta.client_id"},
		{&okta.APIError{Status: 401}, false, "refused the API token", "okta.api_token"},
		{&okta.APIError{Status: 403, Code: "E0000006"}, true, "may not read the System Log", "okta.client_id"},
		{&okta.APIError{Status: 403}, false, "token's admin may not read", "okta.api_token"},
		{&okta.APIError{Status: 404}, false, "has no System Log API", "okta.domain"},
		{&okta.APIError{Status: 429}, false, "rate limit", ""},
		{&okta.APIError{Status: 500, Message: "server error"}, false, "", ""},
		{errors.New("the private key is not PEM"), true, "The private key is not PEM.", "okta.private_key"},
		{errors.New("the private key is not PEM"), false, "The private key is not PEM.", "okta.api_token"},
		{fmt.Errorf("read: %w", context.DeadlineExceeded), false, "did not answer in time", "okta.domain"},
		{errors.New("dial tcp: no such host"), false, "Dial tcp: no such host.", ""},
	} {
		msg, field := explainOkta(c.err, c.oauth)
		if !strings.Contains(msg, c.want) || field != c.field {
			t.Errorf("explainOkta(%v, %v) = %q, %q", c.err, c.oauth, msg, field)
		}
	}
	for n, want := range map[int]string{0: "no events yet", 1: "1 event", 7: "7 events", 1000: "1,000 events or more"} {
		if got := oktaEvents(n); got != want {
			t.Errorf("oktaEvents(%d) = %q", n, got)
		}
	}
}

// A test with an API token, and the settings it needs first.
func TestTestOktaToken(t *testing.T) {
	ts, _, _ := newSettingsServer(t, "", func(s *Server) {
		s.OktaCheck = func(_ context.Context, st okta.Settings) (*okta.CheckResult, error) {
			if st.OAuth() || st.APIToken != "made-up-okta-token" {
				return nil, errors.New("unexpected settings")
			}
			return &okta.CheckResult{Auth: "token", Events: 3}, nil
		}
	})
	test := func(body string) (int, map[string]any) {
		t.Helper()
		code, out, _ := call(t, ts, "POST", "/api/settings/test/okta", body, "admin", "s3cret-pass", nil)
		return code, out
	}
	if code, _ := test(`{`); code != http.StatusBadRequest {
		t.Errorf("bad JSON: %d", code)
	}
	key, _ := json.Marshal(testKey)
	for _, values := range []string{
		`{"okta.domain":"example.okta.com","okta.private_key":` + string(key) + `}`,
		`{"okta.domain":"example.okta.com"}`,
	} {
		code, out := test(`{"values":` + values + `}`)
		if fields, _ := out["fields"].(map[string]any); code != http.StatusBadRequest || fields["okta.client_id"] == nil {
			t.Errorf("%s: %d %v", values, code, out)
		}
	}
	code, out := test(`{"values":{"okta.domain":"example.okta.com","okta.api_token":"made-up-okta-token"}}`)
	if msg, _ := out["message"].(string); code != http.StatusOK || out["ok"] != true || out["auth"] != "token" || !strings.Contains(msg, "with the API token") || !strings.Contains(msg, "3 events") {
		t.Errorf("token: %d %v", code, out)
	}
}

// The health page says the System Log is read, and why it cannot say how
// far.
func TestOktaHealthWithoutCursor(t *testing.T) {
	for _, c := range []struct {
		cursor func(context.Context, string) (okta.Cursor, bool, error)
		want   string
	}{
		{nil, ""},
		{func(context.Context, string) (okta.Cursor, bool, error) { return okta.Cursor{}, false, errDown }, "could not read how far"},
	} {
		ts, _, _ := newSettingsServer(t, "okta:\n  domain: example.okta.com\n  api_token: t\n", func(s *Server) { s.OktaCursor = c.cursor })
		_, out, _ := call(t, ts, "GET", "/api/health", "", "admin", "s3cret-pass", nil)
		m, _ := out["okta"].(map[string]any)
		if msg, _ := m["error"].(string); m["on"] != true || !strings.Contains(msg, c.want) || (c.want == "" && msg != "") {
			t.Errorf("health %v", m)
		}
	}
}
