package api

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/assistant"
)

// A refine needs a sample and a parser, and a model that answers.
func TestRefineParserRefusals(t *testing.T) {
	model := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":{"message":"the model is not loaded"}}`, http.StatusBadRequest)
	}))
	defer model.Close()
	ts, _, _ := newParsersServer(t, func(s *Server) { s.Assistant = assistant.New(assistant.OpenAI, model.URL, "m", "") })
	for _, c := range []struct {
		body string
		code int
	}{
		{`{`, http.StatusBadRequest},
		{`{"sample":"  \n "}`, http.StatusBadRequest},
		{`{"sample":"a=1"}`, http.StatusBadRequest},
		{`{"sample":"a=1","parser":{"name":"acme_fw","format":"kv"}}`, http.StatusBadGateway},
	} {
		if code, out := do(t, ts, "POST", "/api/parsers/refine", c.body, true); code != c.code {
			t.Errorf("%s: %d %v", c.body, code, out)
		}
	}
}

// Saving and removing parsers: the name and body are checked, and a
// parser that is not there cannot be removed. The input for agents
// needs a parser's name and an OS it knows.
func TestParserRefusals(t *testing.T) {
	ts, _, _ := newParsersServer(t, nil)
	if code, _ := do(t, ts, "PUT", "/api/parsers/acme_fw", `{`, true); code != http.StatusBadRequest {
		t.Errorf("bad JSON: %d", code)
	}
	if code, _ := do(t, ts, "PUT", "/api/parsers/Bad%20Name", `{"format":"kv"}`, true); code != http.StatusBadRequest {
		t.Errorf("bad name: %d", code)
	}
	if code, _ := do(t, ts, "DELETE", "/api/parsers/nope", "", true); code != http.StatusNotFound {
		t.Errorf("delete unknown: %d", code)
	}
	if code, _ := do(t, ts, "GET", "/api/parsers/Bad%20Name/input", "", true); code != http.StatusBadRequest {
		t.Errorf("input for a bad name: %d", code)
	}
	q := url.Values{"os": {"plan9"}, "paths": {"/var/log/acme.log"}}
	if code, _ := do(t, ts, "GET", "/api/parsers/acme_fw/input?"+q.Encode(), "", true); code != http.StatusBadRequest {
		t.Errorf("input for an unknown OS: %d", code)
	}
	q = url.Values{"paths": {"/var/log/acme.log\n\n/var/log/acme2.log"}}
	if code, out := do(t, ts, "GET", "/api/parsers/acme_fw/input?"+q.Encode(), "", true); code != http.StatusOK || out["input"] == "" {
		t.Errorf("input: %d %v", code, out)
	}
}

// Without a registry of its own the server keeps parsers in its state
// folder.
func TestParsersInStateDir(t *testing.T) {
	t.Setenv("SIGNALITH_STATE_DIR", t.TempDir())
	ts, _ := newTestServer(t)
	if code, out := do(t, ts, "GET", "/api/parsers", "", true); code != http.StatusOK || out["models"] == nil {
		t.Errorf("list: %d %v", code, out)
	}
	if code, _ := do(t, ts, "DELETE", "/api/parsers/nope", "", true); code != http.StatusNotFound {
		t.Errorf("delete unknown: %d", code)
	}
}
