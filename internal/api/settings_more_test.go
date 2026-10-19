package api

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Saving settings needs a config file; a settings file that cannot be
// read keeps everything as it is until a reset starts a new one, with
// a copy of the old.
func TestPutSettingsFileProblems(t *testing.T) {
	ts, _ := newTestServer(t)
	if code, out := do(t, ts, "PUT", "/api/settings", `{"values":{"search.max_events":5000}}`, true); code != http.StatusConflict || out["error"] != errNoConfigFile.Error() {
		t.Errorf("no config file: %d %v", code, out)
	}

	ts, srv, logs := newSettingsServer(t, "", nil)
	for _, body := range []string{`{`, `{"values":5}`} {
		if code, _ := do(t, ts, "PUT", "/api/settings", body, true); code != http.StatusBadRequest {
			t.Errorf("%s: %d", body, code)
		}
	}
	file := srv.conf().SettingsFile()
	if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte("values: [this is: not: settings\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, out := do(t, ts, "PUT", "/api/settings", `{"values":{"search.max_events":5000}}`, true); code != http.StatusConflict || out["code"] != "settings_file" {
		t.Errorf("unreadable settings file: %d %v", code, out)
	}
	code, out := do(t, ts, "PUT", "/api/settings", `{"reset_all":true}`, true)
	backup, _ := out["backup"].(string)
	if code != http.StatusOK || backup == "" {
		t.Fatalf("reset all: %d %v", code, out)
	}
	if b, err := os.ReadFile(backup); err != nil || !strings.Contains(string(b), "not: settings") {
		t.Errorf("backup %s: %q %v", backup, b, err)
	}
	if !strings.Contains(logs.String(), "settings saved") || !strings.Contains(logs.String(), "reset_all=true") {
		t.Errorf("not audited:\n%s", logs.String())
	}
}

// The list of models falls back to the ones Signalith knows of, or to
// typing one in, and says why: the form has problems, the service is
// down or lists none, the provider is off.
func TestAssistantModelsFallbacks(t *testing.T) {
	empty := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"data":[]}`))
	}))
	defer empty.Close()
	gone := httptest.NewServer(http.NotFoundHandler())
	goneURL := gone.URL
	gone.Close()
	ts, _, _ := newSettingsServer(t, "", nil)
	list := func(body string) (int, map[string]any) {
		t.Helper()
		code, out, _ := call(t, ts, "POST", "/api/settings/assistant/models", body, "admin", "s3cret-pass", nil)
		return code, out
	}
	if code, _ := list(`{`); code != http.StatusBadRequest {
		t.Errorf("bad JSON: %d", code)
	}
	for _, c := range []struct{ body, want string }{
		{`{"values":{"assistant.provider":"openai","assistant.url":"` + empty.URL + `/v1"}}`, "Enter the model's ID under Other."},
		{`{"values":{"assistant.provider":"openai","assistant.url":"` + goneURL + `/v1"}}`, "Couldn't reach the address"},
		{`{"values":{"assistant.provider":"openai","assistant.url":"not an address"}}`, "Enter a whole address"},
		{`{"values":{"assistant.provider":"openai","assistant.url":5}}`, "Fix the address or API key"},
	} {
		code, out := list(c.body)
		if msg, _ := out["message"].(string); code != http.StatusOK || out["live"] == true || !strings.Contains(msg, c.want) {
			t.Errorf("%s: %d %v", c.body, code, out)
		}
	}
	if code, out := list(`{"values":{"assistant.provider":""}}`); code != http.StatusOK || out["message"] != nil && out["message"] != "" {
		t.Errorf("provider off: %d %v", code, out)
	}
}

// A tenant's server takes the settings the default tenant's server
// applies at once.
func TestFollowLive(t *testing.T) {
	var acme *Server
	newTestServerWith(t, func(s *Server) { acme, s.TenantID = s, "acme" })
	front := *acme.conf()
	front.Search.MaxEvents = acme.conf().Search.MaxEvents + 123
	acme.FollowLive(&front)
	if got := acme.conf().Search.MaxEvents; got != front.Search.MaxEvents {
		t.Errorf("max events %d, want %d", got, front.Search.MaxEvents)
	}
	// Following the same settings again changes nothing.
	before := acme.conf()
	acme.FollowLive(&front)
	if acme.conf().Search.MaxEvents != before.Search.MaxEvents {
		t.Errorf("changed on a second follow")
	}
}

func TestWarningsByField(t *testing.T) {
	fields, rest := warningsByField([]string{
		"search.max_events is very high",
		"search.max_events is very high again",
		"something about nothing in particular",
	})
	if len(fields) != 1 || fields["search.max_events"] == "" || len(rest) != 1 || rest[0] != "something about nothing in particular" {
		t.Errorf("fields %v, rest %v", fields, rest)
	}
}
