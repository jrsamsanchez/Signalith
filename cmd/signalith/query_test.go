package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/config"
)

// queryConfig writes a signalith.yaml that uses OpenSearch at url.
func queryConfig(t *testing.T, url, extra string) string {
	t.Helper()
	for _, k := range []string{"SIGNALITH_OPENSEARCH_URL", "SIGNALITH_LOOKUPS_DIR", "SIGNALITH_ASSISTANT_API_KEY", "SIGNALITH_SETTINGS_FILE", "SIGNALITH_STATE_DIR"} {
		t.Setenv(k, "")
	}
	h, err := config.HashPassword("s3cret-pass")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "signalith.yaml")
	if err := os.WriteFile(path, []byte("opensearch:\n  url: "+url+"\nauth:\n  admin_password_hash: "+h+"\n"+extra), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestQueryCommandUsage(t *testing.T) {
	if _, err := capture(t, func() error { return cmdQuery(nil) }); err == nil || !strings.Contains(err.Error(), "usage: signalith query") {
		t.Errorf("no query: %v", err)
	}
	if _, err := capture(t, func() error { return cmdQuery([]string{"datamodel=Authentication | |"}) }); err == nil {
		t.Error("a query that does not parse was accepted")
	}
	missing := filepath.Join(t.TempDir(), "missing.yaml")
	if _, err := capture(t, func() error { return cmdQuery([]string{"-c", missing, "datamodel=Authentication"}) }); err == nil {
		t.Error("a query ran with no config file")
	}
}

// -explain needs no server: with no config file it explains with the
// defaults.
func TestQueryCommandExplain(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing.yaml")
	out, err := capture(t, func() error {
		return cmdQuery([]string{"-c", missing, "-explain", "datamodel=Authentication action=failure | stats count by user"})
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "1. ") || !strings.Contains(out, "/_search\n") {
		t.Fatalf("explain:\n%s", out)
	}
	_, body, _ := strings.Cut(out, "/_search\n")
	var req map[string]any
	if err := json.Unmarshal([]byte(body), &req); err != nil {
		t.Fatalf("the request is not JSON: %v\n%s", err, body)
	}
	if !strings.Contains(body, "failure") {
		t.Errorf("the request does not search for the action:\n%s", body)
	}
	// Explaining an intel query works even with no OpenSearch to read
	// indicators from.
	path := queryConfig(t, "http://127.0.0.1:1", "")
	if out, err := capture(t, func() error {
		return cmdQuery([]string{"-c", path, "-explain", "datamodel=Network_Traffic | threatmatch"})
	}); err != nil && !strings.Contains(err.Error(), "threatmatch") {
		t.Errorf("explain threatmatch: %v\n%s", err, out)
	}
}

func TestQueryCommandRuns(t *testing.T) {
	fos := newFakeOpenSearch(t)
	path := queryConfig(t, fos.URL, "")
	out, err := capture(t, func() error { return cmdQuery([]string{"-c", path, "datamodel=Authentication | head 5"}) })
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	var res map[string]any
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("the result is not JSON: %v\n%s", err, out)
	}
	found := false
	for _, r := range fos.Requests() {
		if strings.Contains(r, "_search") {
			found = true
		}
	}
	if !found {
		t.Errorf("OpenSearch was not searched: %v", fos.Requests())
	}
}

func TestQueryCommandIntelNeedsOpenSearch(t *testing.T) {
	path := queryConfig(t, "http://127.0.0.1:1", "")
	if _, err := capture(t, func() error {
		return cmdQuery([]string{"-c", path, "datamodel=Network_Traffic | intel"})
	}); err == nil || !strings.Contains(err.Error(), "threat intel") {
		t.Errorf("intel query without OpenSearch: %v", err)
	}
}

func TestAskCommand(t *testing.T) {
	if _, err := capture(t, func() error { return cmdAsk(nil) }); err == nil || !strings.Contains(err.Error(), "usage: signalith ask") {
		t.Errorf("no question: %v", err)
	}
	// The built-in translator needs no config file.
	missing := filepath.Join(t.TempDir(), "missing.yaml")
	out, err := capture(t, func() error {
		return cmdAsk([]string{"-c", missing, "failed logins from 203.0.113.9 in the last 24 hours"})
	})
	if err != nil {
		t.Fatal(err)
	}
	first, rest, _ := strings.Cut(out, "\n")
	if !strings.Contains(first, "203.0.113.9") || !strings.Contains(first, "Authentication") {
		t.Errorf("query %q", first)
	}
	if !strings.Contains(rest, `"from 203.0.113.9"`) || !strings.Contains(rest, "source is 203.0.113.9") {
		t.Errorf("the steps do not show the address:\n%s", rest)
	}
	// Words it does not know are listed.
	out, err = capture(t, func() error { return cmdAsk([]string{"-c", missing, "failed logins zorblatt"}) })
	if err == nil && !strings.Contains(out, "Not understood: ") {
		t.Errorf("unknown words not listed:\n%s", out)
	}
	// -ai needs the config file, and a model set in it.
	if _, err := capture(t, func() error { return cmdAsk([]string{"-c", missing, "-ai", "failed logins"}) }); err == nil {
		t.Error("-ai with no config file")
	}
	path := queryConfig(t, "http://127.0.0.1:1", "")
	if _, err := capture(t, func() error { return cmdAsk([]string{"-c", path, "-ai", "failed logins"}) }); err == nil || !strings.Contains(err.Error(), "no AI model is configured") {
		t.Errorf("-ai with no model: %v", err)
	}
}
