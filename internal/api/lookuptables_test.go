package api

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/lookuptables"
)

func withLookupTables(t *testing.T) func(*Server) {
	return func(s *Server) {
		st, err := lookuptables.Open(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		s.Engine.Lookups = st
	}
}

func TestLookupTablesAPI(t *testing.T) {
	ts, _ := newTestServerWith(t, withLookupTables(t))
	if code, body := do(t, ts, "PUT", "/api/lookuptables/owners", "host,owner\nweb-01,=cmd\n", true); code != http.StatusOK || body["rows"] != float64(1) {
		t.Fatalf("PUT = %d %v", code, body)
	}
	if code, body := do(t, ts, "PUT", "/api/lookuptables/Bad%20Name", "a\n1\n", true); code != http.StatusBadRequest {
		t.Errorf("PUT bad name = %d %v", code, body)
	}
	if code, body := do(t, ts, "PUT", "/api/lookuptables/dup", "a,a\n", true); code != http.StatusBadRequest || !strings.Contains(body["error"].(string), "twice") {
		t.Errorf("PUT bad CSV = %d %v", code, body)
	}
	code, body := do(t, ts, "GET", "/api/lookuptables", "", true)
	if tables, _ := body["tables"].([]any); code != http.StatusOK || len(tables) != 1 {
		t.Fatalf("GET list = %d %v", code, body)
	}
	code, body = do(t, ts, "GET", "/api/lookuptables/owners", "", true)
	if rows, _ := body["rows"].([]any); code != http.StatusOK || len(rows) != 1 {
		t.Errorf("GET table = %d %v", code, body)
	}
	req, _ := http.NewRequest("GET", ts.URL+"/api/lookuptables/owners.csv", nil)
	req.SetBasicAuth("admin", "s3cret-pass")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	csv, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(csv) != "host,owner\nweb-01,'=cmd\n" {
		t.Errorf("CSV = %q", csv)
	}
	if code, _ := do(t, ts, "DELETE", "/api/lookuptables/owners", "", true); code != http.StatusNoContent {
		t.Errorf("DELETE = %d", code)
	}
	if code, _ := do(t, ts, "DELETE", "/api/lookuptables/owners", "", true); code != http.StatusNotFound {
		t.Errorf("second DELETE = %d", code)
	}
	if code, _ := do(t, ts, "GET", "/api/lookuptables", "", false); code != http.StatusUnauthorized {
		t.Errorf("GET without signing in = %d", code)
	}
}

func TestLookupTablesReadOnlyWithSeveralServers(t *testing.T) {
	ts, _ := newTestServerWith(t, func(s *Server) {
		withLookupTables(t)(s)
		s.Cluster = &fakeCluster{runs: true}
	})
	code, body := do(t, ts, "PUT", "/api/lookuptables/owners", "host,owner\nweb-01,ana\n", true)
	if code != http.StatusConflict || !strings.Contains(body["error"].(string), "several servers") {
		t.Errorf("PUT = %d %v", code, body)
	}
	if _, body := do(t, ts, "GET", "/api/lookuptables", "", true); body["multi_server"] != true {
		t.Errorf("GET list = %v, want multi_server", body)
	}
}
