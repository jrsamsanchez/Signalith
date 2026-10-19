// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/ingest"
)

func hecSend(t *testing.T, url, path, auth, body string, header map[string]string) (int, map[string]any) {
	t.Helper()
	req, _ := http.NewRequest("POST", url+path, strings.NewReader(body))
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	for k, v := range header {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("%s: %d %s", path, resp.StatusCode, raw)
	}
	return resp.StatusCode, out
}

func TestHECIntake(t *testing.T) {
	ts, srv, fos, _, _ := newTokenServer(t)
	notYet := "sgl_" + strings.Repeat("a", 52)
	srv.Config.Ingest.HEC = true
	// Before the tokens are read: send again later.
	if code, out := hecSend(t, ts.URL, "/services/collector/event", "Splunk "+notYet, `{"event":"x"}`, nil); code != 503 || out["code"].(float64) != ingest.HECServerBusy {
		t.Fatalf("not loaded: %d %v", code, out)
	}
	srv.Config.Ingest.HEC = false
	if err := srv.Tokens.Load(context.Background()); err != nil {
		t.Fatal(err)
	}
	_, secret := createToken(t, ts, "Splunk forwarders")
	event := `{"event":"hello","host":"app1","sourcetype":"myapp","index":"main"}`

	// Off by default: nothing is taken, whatever the token.
	if code, out := hecSend(t, ts.URL, "/services/collector/event", "Splunk "+secret, event, nil); code != 403 || out["code"].(float64) != ingest.HECTokenDisabled {
		t.Fatalf("off: %d %v", code, out)
	}
	srv.Config.Ingest.HEC = true

	code, out := hecSend(t, ts.URL, "/services/collector/event", "Splunk "+secret, event, nil)
	if code != 200 || out["text"] != "Success" || out["code"].(float64) != 0 {
		t.Fatalf("event: %d %v", code, out)
	}
	doc := fos.bulk[len(fos.bulk)-1].Doc
	if doc["message"] != "hello" || doc["host"] != "app1" || doc["sourcetype"] != "myapp" || doc["orig_index"] != "main" ||
		doc[ingest.IntakeField] != ingest.IntakeHEC || doc[ingest.TokenField] != "Splunk forwarders" {
		t.Errorf("stored %v", doc)
	}
	// /raw, with gzip and the metadata in the query string; Bearer works too.
	code, out = hecSend(t, ts.URL, "/services/collector/raw?sourcetype=linux_secure&host=db1", "Bearer "+secret,
		string(gz([]byte("Oct 11 09:15:02 db1 sshd[811]: Failed password for bob from 192.0.2.4 port 50022 ssh2\n"))),
		map[string]string{"Content-Encoding": "gzip"})
	if code != 200 {
		t.Fatalf("raw: %d %v", code, out)
	}
	if doc := fos.bulk[len(fos.bulk)-1].Doc; doc["datamodel"] != "Authentication" || doc["user"] != "bob" {
		t.Errorf("raw stored %v", doc)
	}

	for _, c := range []struct {
		name, path, auth, body string
		status, code           int
	}{
		{"no token", "/services/collector/event", "", event, 401, ingest.HECTokenRequired},
		{"basic", "/services/collector/event", "Basic eDp5", event, 401, ingest.HECInvalidAuth},
		{"wrong token", "/services/collector/event", "Splunk not-a-token-0000000000000000", event, 403, ingest.HECInvalidToken},
		{"query token", "/services/collector/event?token=" + secret, "", event, 400, ingest.HECQueryAuth},
		{"bad event", "/services/collector/event", "Splunk " + secret, `{"host":"x"}`, 400, ingest.HECEventRequired},
		{"ack", "/services/collector/ack", "Splunk " + secret, `{"acks":[0]}`, 400, ingest.HECAckDisabled},
	} {
		n := len(fos.bulk)
		code, out := hecSend(t, ts.URL, c.path, c.auth, c.body, nil)
		if code != c.status || int(out["code"].(float64)) != c.code || len(fos.bulk) != n {
			t.Errorf("%s: %d %v", c.name, code, out)
		}
	}
	// A revoked token is refused as disabled.
	id, revoked := createToken(t, ts, "old")
	if code, _, raw := call(t, ts, "POST", "/api/agent-tokens/"+id+"/revoke", "", "admin", adminPass, nil); code != 200 {
		t.Fatalf("revoke: %d %s", code, raw)
	}
	if code, out := hecSend(t, ts.URL, "/services/collector/event", "Splunk "+revoked, event, nil); code != 403 || out["code"].(float64) != ingest.HECTokenDisabled {
		t.Errorf("revoked: %d %v", code, out)
	}
	req, _ := http.NewRequest("GET", ts.URL+"/services/collector/health", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("health: %d", resp.StatusCode)
	}
}
