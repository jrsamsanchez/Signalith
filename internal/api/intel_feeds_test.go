package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/intel"
	"github.com/jrsamsanchez/signalith/internal/users"
)

// feedCall sends a signed-in request and returns the status and raw body.
func feedCall(t *testing.T, ts *httptest.Server, method, path, body string, header ...string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest(method, ts.URL+path, strings.NewReader(body))
	req.SetBasicAuth("admin", "s3cret-pass")
	for i := 0; i+1 < len(header); i += 2 {
		req.Header.Set(header[i], header[i+1])
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func getRaw(t *testing.T, ts *httptest.Server, path string) string {
	t.Helper()
	_, body := feedCall(t, ts, "GET", path, "")
	return body
}

func asMap(t *testing.T, body string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(body), &m); err != nil {
		t.Fatalf("not JSON: %s", body)
	}
	return m
}

func TestIntelFeedsAPI(t *testing.T) {
	feedSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/needs-key" && r.Header.Get("X-Api-Key") != "k3y-secret":
			http.Error(w, "forbidden", http.StatusForbidden)
		case r.URL.Path == "/needs-key", r.URL.Path == "/ips.txt":
			w.Write([]byte("# list\n203.0.113.9\n198.51.100.0/24\n"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer feedSrv.Close()
	store := intel.NewStore(intel.NewMemory())
	if err := store.Load(context.Background()); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	var feeds *intel.Feeds
	ts, _ := newTestServerWith(t, func(s *Server) {
		s.Intel = store
		s.Engine.Intel = store
		feeds = &intel.Feeds{Store: store, Log: s.Log, AllowLoopback: true, File: filepath.Join(dir, "intel_feeds.yaml"), List: []intel.Feed{
			{Name: "from-config", URL: feedSrv.URL + "/ips.txt", Format: "lines", Type: "auto", Interval: time.Hour, MaxAge: 24 * time.Hour,
				Weight: 1, Enabled: true, Headers: map[string]string{"Authorization": "Bearer cfg-secret"}},
		}}
		s.Feeds = feeds
	})
	var bodies []string
	send := func(method, path, body string) (int, map[string]any) {
		t.Helper()
		code, raw := feedCall(t, ts, method, path, body)
		bodies = append(bodies, raw)
		if len(raw) == 0 || raw[0] != '{' {
			return code, nil
		}
		return code, asMap(t, raw)
	}

	code, out := send("GET", "/api/intel/feeds", "")
	list := out["feeds"].([]any)
	if code != 200 || len(list) != 1 || list[0].(map[string]any)["source"] != "config" || out["feeds_file"] != filepath.Join(dir, "intel_feeds.yaml") {
		t.Fatalf("list = %d %v", code, out)
	}

	// Add a feed with an API key; the key never comes back.
	code, out = send("POST", "/api/intel/feeds", `{"name":"page-feed","url":"`+feedSrv.URL+`/needs-key","interval":"30m",
		"headers":[{"name":"X-Api-Key","value":"k3y-secret"}],"tags":["botnet"]}`)
	if code != 200 || out["source"] != "ui" || out["format"] != "auto" || out["headers"].([]any)[0].(map[string]any)["set"] != true {
		t.Fatalf("add = %d %v", code, out)
	}
	code, out = send("POST", "/api/intel/feeds", `{"name":"Bad Name","url":"ftp://x","interval":"1m"}`)
	if code != 400 || len(out["problems"].([]any)) < 3 || out["fields"].(map[string]any)["interval"] == nil {
		t.Errorf("invalid add = %d %v", code, out)
	}
	if code, out = send("POST", "/api/intel/feeds", `{"name":"from-config","url":"https://feeds.example/x"}`); code != 400 ||
		!strings.Contains(out["fields"].(map[string]any)["name"].(string), "signalith.yaml") {
		t.Errorf("config name = %d %v", code, out)
	}

	// A change that leaves the key out keeps it.
	code, out = send("PUT", "/api/intel/feeds/page-feed", `{"description":"Changed","headers":[{"name":"X-Api-Key"}]}`)
	if code != 200 || out["description"] != "Changed" || out["interval"] != "30m" || len(out["tags"].([]any)) != 1 {
		t.Fatalf("update = %d %v", code, out)
	}
	if fd, _ := feeds.Get("page-feed"); fd.Headers["X-Api-Key"] != "k3y-secret" {
		t.Errorf("key lost: %+v", fd.Headers)
	}
	if code, _ := send("PUT", "/api/intel/feeds/from-config", `{"weight":2}`); code != 409 {
		t.Errorf("update config feed = %d", code)
	}
	if code, _ := send("PUT", "/api/intel/feeds/nope", `{}`); code != 404 {
		t.Errorf("update unknown = %d", code)
	}

	// Test without saving: by URL, and by name with the stored key.
	code, out = send("POST", "/api/intel/feeds/test", `{"url":"`+feedSrv.URL+`/ips.txt"}`)
	if code != 200 || out["ok"] != true || out["format"] != "lines" || out["type"] != "ip" || out["total"] != float64(2) || len(out["samples"].([]any)) != 2 {
		t.Errorf("test = %d %v", code, out)
	}
	code, out = send("POST", "/api/intel/feeds/test", `{"feed":"page-feed"}`)
	if code != 200 || out["ok"] != true {
		t.Errorf("test saved feed = %d %v", code, out)
	}
	code, out = send("POST", "/api/intel/feeds/test", `{"url":"`+feedSrv.URL+`/needs-key"}`)
	if code != 200 || out["ok"] != false || out["http_status"] != float64(403) || !strings.Contains(out["error"].(string), "may need an API key") {
		t.Errorf("test 403 = %d %v", code, out)
	}
	if code, _ := send("POST", "/api/intel/feeds/test", `{"url":"ftp://x"}`); code != 400 {
		t.Errorf("test bad url = %d", code)
	}
	if code, _ := send("POST", "/api/intel/feeds/test", `{"feed":"nope"}`); code != 404 {
		t.Errorf("test unknown feed = %d", code)
	}

	// The page feed downloads like any other.
	code, out = send("POST", "/api/intel/feeds/page-feed/refresh", "")
	if code != 200 || out["status"].(map[string]any)["count"] != float64(2) || store.CountSource("page-feed") != 2 {
		t.Fatalf("refresh = %d %v", code, out)
	}
	code, out = send("GET", "/api/intel", "")
	if code != 200 || len(out["feeds"].([]any)) != 2 || out["manage"] != true || out["file_error"] != nil {
		t.Errorf("overview = %d %v", code, out)
	}

	// Catalog.
	code, out = send("GET", "/api/intel/catalog", "")
	entries := out["entries"].([]any)
	if code != 200 || len(entries) != len(intel.Catalog) || entries[0].(map[string]any)["added"] != false {
		t.Errorf("catalog = %d %v", code, out)
	}
	code, out = send("POST", "/api/intel/catalog", `{"ids":["feodo-tracker","spamhaus-drop"]}`)
	if code != 200 || len(out["added"].([]any)) != 2 || len(out["skipped"].([]any)) != 0 {
		t.Errorf("catalog add = %d %v", code, out)
	}
	code, out = send("POST", "/api/intel/catalog", `{"ids":["feodo-tracker"]}`)
	if code != 200 || len(out["added"].([]any)) != 0 || len(out["skipped"].([]any)) != 1 {
		t.Errorf("catalog add again = %d %v", code, out)
	}
	if code, _ := send("POST", "/api/intel/catalog", `{}`); code != 400 {
		t.Errorf("catalog add nothing = %d", code)
	}

	// TAXII collections: a server that is not TAXII, in plain words.
	code, out = send("POST", "/api/intel/taxii/collections", `{"url":"`+feedSrv.URL+`/api1/"}`)
	if code != 200 || out["ok"] != false || !strings.Contains(out["error"].(string), "No TAXII 2.1 server") {
		t.Errorf("collections = %d %v", code, out)
	}

	// Delete, keeping the indicators to age out, then for good.
	if code, _ := send("DELETE", "/api/intel/feeds/page-feed?indicators=maybe", ""); code != 400 {
		t.Errorf("bad delete mode = %d", code)
	}
	code, out = send("DELETE", "/api/intel/feeds/page-feed?indicators=keep", "")
	if code != 200 || out["indicators_kept"] != true || store.CountSource("page-feed") != 2 {
		t.Errorf("delete keep = %d %v", code, out)
	}
	if code, _ := send("DELETE", "/api/intel/feeds/page-feed", ""); code != 404 {
		t.Errorf("delete again = %d", code)
	}
	// Indicators of a deleted feed can now be deleted one by one.
	kept, _ := store.List(intel.Filter{Source: "page-feed", Limit: 1})
	if code, _ := send("DELETE", "/api/intel/indicators/"+kept[0].ID, ""); code != 200 {
		t.Errorf("delete kept indicator = %d", code)
	}
	code, out = send("DELETE", "/api/intel/feeds/feodo-tracker", "")
	if code != 200 || out["indicators_removed"] != float64(0) {
		t.Errorf("delete = %d %v", code, out)
	}
	if code, _ := send("DELETE", "/api/intel/feeds/from-config", ""); code != 409 {
		t.Errorf("delete config feed = %d", code)
	}

	// No answer ever holds a secret value.
	for _, b := range bodies {
		for _, secret := range []string{"k3y-secret", "cfg-secret"} {
			if strings.Contains(b, secret) {
				t.Fatalf("an answer shows %s: %s", secret, b)
			}
		}
	}

	// Changes from another site are refused.
	code, _ = feedCall(t, ts, "POST", "/api/intel/feeds", `{"name":"evil","url":"https://evil.example/x"}`, "Sec-Fetch-Site", "cross-site")
	if code != 403 {
		t.Errorf("cross-site add = %d", code)
	}
	code, _ = feedCall(t, ts, "DELETE", "/api/intel/feeds/spamhaus-drop", "", "Origin", "https://evil.example")
	if code != 403 {
		t.Errorf("cross-site delete = %d", code)
	}
}

// A feeds file that cannot be read is reported on the page, which then
// cannot change feeds, so the file is never overwritten.
func TestIntelFeedsBrokenFile(t *testing.T) {
	store := intel.NewStore(intel.NewMemory())
	if err := store.Load(context.Background()); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "intel_feeds.yaml")
	if err := os.WriteFile(file, []byte("feeds: [this is: not valid"), 0o600); err != nil {
		t.Fatal(err)
	}
	ts, _ := newTestServerWith(t, func(s *Server) {
		s.Intel = store
		s.Feeds = &intel.Feeds{Store: store, Log: s.Log, File: file}
	})
	code, raw := feedCall(t, ts, "GET", "/api/intel", "")
	out := asMap(t, raw)
	if code != 200 || !strings.Contains(fmt.Sprint(out["file_error"]), "intel_feeds.yaml") {
		t.Errorf("overview = %d %v", code, out)
	}
	if code, _ := feedCall(t, ts, "POST", "/api/intel/feeds", `{"name":"x-feed","url":"https://feeds.example/x"}`); code != 503 {
		t.Errorf("add with a broken file = %d", code)
	}
}

func TestIntelFeedsOff(t *testing.T) {
	store := intel.NewStore(intel.NewMemory())
	ts, _ := newTestServerWith(t, func(s *Server) { s.Intel = store })
	for _, p := range []string{"/api/intel/feeds", "/api/intel/catalog"} {
		if code, _ := feedCall(t, ts, "GET", p, ""); code != 503 {
			t.Errorf("%s without feeds = %d", p, code)
		}
	}
}

// A server without the detection scheduler does not download feeds, so
// its page cannot add or change them: its feeds file is not the one the
// downloading server reads.
func TestIntelFeedsWithoutScheduler(t *testing.T) {
	feedSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("203.0.113.9\n")) }))
	defer feedSrv.Close()
	store := intel.NewStore(intel.NewMemory())
	if err := store.Load(context.Background()); err != nil {
		t.Fatal(err)
	}
	feeds := &intel.Feeds{Store: store, AllowLoopback: true, File: filepath.Join(t.TempDir(), "intel_feeds.yaml"), List: []intel.Feed{
		{Name: "from-config", URL: feedSrv.URL + "/ips.txt", Format: "lines", Type: "auto", Interval: time.Hour, MaxAge: 24 * time.Hour, Weight: 1, Enabled: true},
	}}
	if _, err := feeds.AddFeed(intel.FeedInput{Name: "page-feed", URL: feedSrv.URL + "/b.txt"}); err != nil {
		t.Fatal(err)
	}
	ts, _ := newTestServerWith(t, func(s *Server) {
		s.Config.Detections.Scheduler = false
		s.Intel = store
		s.Feeds = feeds
	})
	code, raw := feedCall(t, ts, "GET", "/api/intel", "")
	if out := asMap(t, raw); code != 200 || out["manage"] != false || out["downloads"] != false {
		t.Errorf("overview = %d %v", code, out)
	}
	for _, c := range []struct{ method, path, body string }{
		{"POST", "/api/intel/feeds", `{"name":"x-feed","url":"https://feeds.example/x"}`},
		{"PUT", "/api/intel/feeds/page-feed", `{"weight":2}`},
		{"DELETE", "/api/intel/feeds/page-feed", ""},
		{"POST", "/api/intel/catalog", `{"ids":["urlhaus"]}`},
		{"POST", "/api/intel/feeds/page-feed/refresh", ""},
	} {
		if code, raw := feedCall(t, ts, c.method, c.path, c.body); code != 409 || !strings.Contains(raw, "detections.scheduler is off here") {
			t.Errorf("%s %s = %d %s", c.method, c.path, code, raw)
		}
	}
	// A feed from signalith.yaml is the same on every server, so it can
	// still be downloaded by hand here.
	if code, raw := feedCall(t, ts, "POST", "/api/intel/feeds/from-config/refresh", ""); code != 200 {
		t.Errorf("refresh config feed = %d %s", code, raw)
	}
}

// A feed that is off is not downloaded by hand either.
func TestIntelRefreshFeedOff(t *testing.T) {
	store := intel.NewStore(intel.NewMemory())
	if err := store.Load(context.Background()); err != nil {
		t.Fatal(err)
	}
	feeds := &intel.Feeds{Store: store, File: filepath.Join(t.TempDir(), "intel_feeds.yaml")}
	off := false
	if _, err := feeds.AddFeed(intel.FeedInput{Name: "off-feed", URL: "https://feeds.example/x.txt", Enabled: &off}); err != nil {
		t.Fatal(err)
	}
	ts, _ := newTestServerWith(t, func(s *Server) {
		s.Intel = store
		s.Feeds = feeds
	})
	if code, raw := feedCall(t, ts, "POST", "/api/intel/feeds/off-feed/refresh", ""); code != 409 || !strings.Contains(raw, "turned off") {
		t.Errorf("refresh = %d %s", code, raw)
	}
}

// Feed tests are limited, so overlapping tests cannot use up the
// server's memory.
func TestIntelFeedTestBusy(t *testing.T) {
	release := make(chan struct{})
	in := make(chan struct{}, 4)
	feedSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		in <- struct{}{}
		<-release
		w.Write([]byte("203.0.113.9\n"))
	}))
	defer feedSrv.Close()
	defer close(release)
	store := intel.NewStore(intel.NewMemory())
	ts, _ := newTestServerWith(t, func(s *Server) {
		s.Intel = store
		s.Feeds = &intel.Feeds{Store: store, AllowLoopback: true}
	})
	body := `{"url":"` + feedSrv.URL + `/ips.txt"}`
	done := make(chan int, intel.MaxTests)
	for range intel.MaxTests {
		go func() {
			code, _ := feedCall(t, ts, "POST", "/api/intel/feeds/test", body)
			done <- code
		}()
	}
	for range intel.MaxTests {
		<-in
	}
	if code, raw := feedCall(t, ts, "POST", "/api/intel/feeds/test", body); code != 429 || !strings.Contains(raw, "try again") {
		t.Errorf("third test = %d %s", code, raw)
	}
	if code, _ := feedCall(t, ts, "POST", "/api/intel/taxii/collections", `{"url":"`+feedSrv.URL+`/api1/"}`); code != 429 {
		t.Errorf("collections while busy = %d", code)
	}
	for range intel.MaxTests {
		release <- struct{}{}
	}
	for range intel.MaxTests {
		if code := <-done; code != 200 {
			t.Errorf("test = %d", code)
		}
	}
}

// TestIntelFeedsForViewers checks that viewers see the feeds without the
// parts of an address or sign-in that can hold a secret, and cannot make
// the server download from an address they name.
func TestIntelFeedsForViewers(t *testing.T) {
	store := intel.NewStore(intel.NewMemory())
	if err := store.Load(context.Background()); err != nil {
		t.Fatal(err)
	}
	ts, _ := newTestServerWith(t, func(s *Server) {
		s.Intel = store
		s.Engine.Intel = store
		s.Feeds = &intel.Feeds{Store: store, Log: s.Log, File: filepath.Join(t.TempDir(), "intel_feeds.yaml"), List: []intel.Feed{
			{Name: "partner", URL: "https://feeds.example.com/list.txt?apikey=k3y-in-query", Format: "lines", Type: "auto",
				Interval: time.Hour, MaxAge: 24 * time.Hour, Weight: 1, Enabled: true},
			{Name: "taxii", Kind: intel.KindTAXII, URL: "https://taxii.example.com/api1/", Collection: "c1", Format: "stix", Type: "auto",
				Interval: time.Hour, MaxAge: 24 * time.Hour, Weight: 1, Enabled: true, Username: "svc-signalith", Password: "pw-secret"},
		}}
		s.Users = users.NewMemory()
		if _, err := s.Users.Create(context.Background(), users.NewUser{Username: "vera", Role: users.Viewer, Password: "role-password"}); err != nil {
			t.Fatal(err)
		}
	})
	for _, path := range []string{"/api/intel/feeds", "/api/intel"} {
		code, _, raw := call(t, ts, "GET", path, "", "vera", "role-password", nil)
		if code != 200 || !strings.Contains(raw, "https://feeds.example.com/list.txt?…") {
			t.Errorf("viewer %s = %d %s", path, code, raw)
		}
		for _, secret := range []string{"k3y-in-query", "svc-signalith", "pw-secret"} {
			if strings.Contains(raw, secret) {
				t.Errorf("viewer %s shows %q: %s", path, secret, raw)
			}
		}
		// Admins see the address they set, to edit it.
		if raw := getRaw(t, ts, path); !strings.Contains(raw, "apikey=k3y-in-query") || !strings.Contains(raw, "svc-signalith") {
			t.Errorf("admin %s = %s", path, raw)
		}
	}
	for _, path := range []string{"/api/intel/feeds/test", "/api/intel/taxii/collections"} {
		code, out := doAs(t, ts, "vera", "role-password", "POST", path, `{"url":"http://10.0.0.1/"}`)
		if code != http.StatusForbidden || out["code"] != "forbidden" {
			t.Errorf("viewer POST %s = %d %v", path, code, out)
		}
	}
}
