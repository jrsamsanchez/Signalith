package api

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/notify"
)

// newNotifyServer starts a server with notifications kept in a temporary
// file, sending through real senders (to test receivers on this machine).
func newNotifyServer(t *testing.T, change func(*Server)) (*httptest.Server, *Notify) {
	t.Helper()
	n := &Notify{Settings: &notify.Manager{File: filepath.Join(t.TempDir(), "notifications.yaml")},
		Deliveries: notify.NewMemory(), Sender: &notify.Senders{}, Server: "siem-a"}
	ts, _ := newTestServerWith(t, func(s *Server) {
		s.Notify = n
		s.Config.Server.PublicURL = "https://siem.example.com"
		if change != nil {
			change(s)
		}
	})
	return ts, n
}

func TestNotifyAPI(t *testing.T) {
	var mu sync.Mutex
	var got []string
	rc := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		got = append(got, r.URL.Path+" "+string(b))
		mu.Unlock()
		if strings.HasSuffix(r.URL.Path, "/broken") {
			http.Error(w, "no_service", http.StatusNotFound)
		}
	}))
	defer rc.Close()
	ts, n := newNotifyServer(t, nil)

	code, body := doAs(t, ts, "admin", "s3cret-pass", "GET", "/api/notify", "")
	if code != 200 || len(body["channels"].([]any)) != 0 || body["manage"] != true || body["link"] != "https://siem.example.com/#findings" {
		t.Fatalf("empty: %d %v", code, body)
	}
	save := `{"channels":[
		{"id":"slack","name":"#soc","type":"slack","url":"` + rc.URL + `/services/T0/B0/token-abcdef","allow_loopback":true},
		{"id":"hook","name":"SOAR","type":"webhook","url":"` + rc.URL + `/broken","allow_loopback":true,
		 "headers":[{"name":"Authorization","value":"Bearer header-secret"}],"signing_secret":"sig-secret"}],
	 "rules":[{"id":"urgent","name":"Urgent","channels":["slack","hook"]}]}`
	code, body = doAs(t, ts, "admin", "s3cret-pass", "PUT", "/api/notify", save)
	if code != 200 {
		t.Fatalf("save: %d %v", code, body)
	}
	raw := notifyJSON(t, body)
	for _, secret := range []string{"token-abcdef", "header-secret", "sig-secret"} {
		if strings.Contains(raw, secret) {
			t.Errorf("the answer holds %s: %s", secret, raw)
		}
	}
	chans := body["channels"].([]any)
	hook := chans[1].(map[string]any)
	if hook["url_set"] != true || hook["url_server"] != rc.URL || hook["signing_secret_set"] != true ||
		hook["headers"].([]any)[0].(map[string]any)["name"] != "Authorization" || hook["rules"].([]any)[0] != "Urgent" {
		t.Errorf("hook view %v", hook)
	}
	rule := body["rules"].([]any)[0].(map[string]any)
	if rule["summary"] != "High and critical findings from any detection go to Slack #soc and Webhook SOAR." || rule["enabled"] != true {
		t.Errorf("rule %v", rule)
	}

	// Problems name the setting.
	code, body = doAs(t, ts, "admin", "s3cret-pass", "PUT", "/api/notify", `{"channels":[{"name":"x","type":"teams"}]}`)
	if code != 400 || body["problems"].([]any)[0].(map[string]any)["field"] != "url" {
		t.Errorf("bad save: %d %v", code, body)
	}
	// A save over a newer revision is refused.
	code, _ = doAs(t, ts, "admin", "s3cret-pass", "PUT", "/api/notify", `{"revision":"old","channels":[]}`)
	if code != 409 {
		t.Errorf("stale save: %d", code)
	}

	// Send test, by ID: the result comes back and is recorded.
	code, body = doAs(t, ts, "admin", "s3cret-pass", "POST", "/api/notify/test", `{"id":"slack"}`)
	if code != 200 || body["ok"] != true {
		t.Fatalf("test: %d %v", code, body)
	}
	code, body = doAs(t, ts, "admin", "s3cret-pass", "POST", "/api/notify/test", `{"id":"hook"}`)
	if code != 200 || body["ok"] != false || !strings.Contains(body["error"].(string), "404 Not Found") || strings.Contains(body["error"].(string), rc.URL) {
		t.Errorf("failed test: %d %v", code, body)
	}
	// A channel being edited: its empty secrets are the saved ones.
	code, body = doAs(t, ts, "admin", "s3cret-pass", "POST", "/api/notify/test", `{"channel":{"id":"slack","name":"#soc","type":"slack","allow_loopback":true}}`)
	if code != 200 || body["ok"] != true {
		t.Errorf("edited test: %d %v", code, body)
	}
	if code, _ := doAs(t, ts, "admin", "s3cret-pass", "POST", "/api/notify/test", `{"id":"nope"}`); code != 404 {
		t.Errorf("unknown channel: %d", code)
	}
	mu.Lock()
	if len(got) != 3 || !strings.Contains(got[0], "Test message from Signalith") {
		t.Errorf("received %q", got)
	}
	mu.Unlock()

	code, body = doAs(t, ts, "admin", "s3cret-pass", "GET", "/api/notify/deliveries", "")
	list := body["deliveries"].([]any)
	if code != 200 || len(list) != 3 {
		t.Fatalf("deliveries: %d %v", code, body)
	}
	if d := list[1].(map[string]any); d["kind"] != "test" || d["status"] != "failed" || d["channel_name"] != "SOAR" || d["final"] != true {
		t.Errorf("latest delivery %v", d)
	}
	// The channel cards show the last delivery, and Health warns.
	_, body = doAs(t, ts, "admin", "s3cret-pass", "GET", "/api/notify", "")
	if last := body["channels"].([]any)[1].(map[string]any)["last"].(map[string]any); last["status"] != "failed" {
		t.Errorf("last %v", last)
	}
	_, body = doAs(t, ts, "admin", "s3cret-pass", "GET", "/api/health", "")
	if !strings.Contains(notifyJSON(t, body["warnings"]), "Notifications to Webhook SOAR are failing") {
		t.Errorf("health warnings %v", body["warnings"])
	}

	// Deleting a channel takes it out of its rules.
	code, body = doAs(t, ts, "admin", "s3cret-pass", "PUT", "/api/notify", `{"channels":[{"id":"slack","name":"#soc","type":"slack","allow_loopback":true}],
		"rules":[{"id":"urgent","name":"Urgent","channels":["slack","hook"]}]}`)
	if code != 200 || len(body["rules"].([]any)[0].(map[string]any)["channels"].([]any)) != 1 {
		t.Errorf("delete channel: %d %v", code, body)
	}
	if s, _ := n.Settings.Settings(); len(s.Channels) != 1 || s.Channels[0].URL == "" {
		t.Errorf("saved %+v", s)
	}
}

// A server that does not run the background jobs shows the settings but
// does not change them or send tests: its file is not the one used.
func TestNotifyOnlyWhereTheJobsRun(t *testing.T) {
	cl := &fakeCluster{}
	cl.set(false, "siem-a")
	ts, _ := newNotifyServer(t, func(s *Server) { s.Cluster = cl })
	code, body := doAs(t, ts, "admin", "s3cret-pass", "GET", "/api/notify", "")
	if code != 200 || body["manage"] != false || body["runs_on"] != "siem-a" || !strings.Contains(body["manage_why"].(string), "siem-a does") {
		t.Errorf("view %d %v", code, body)
	}
	if code, _ := doAs(t, ts, "admin", "s3cret-pass", "PUT", "/api/notify", `{"channels":[]}`); code != 409 {
		t.Errorf("save elsewhere: %d", code)
	}
	if code, _ := doAs(t, ts, "admin", "s3cret-pass", "POST", "/api/notify/test", `{"id":"x"}`); code != 409 {
		t.Errorf("test elsewhere: %d", code)
	}
	cl.set(true, "siem-b")
	if code, _ := doAs(t, ts, "admin", "s3cret-pass", "PUT", "/api/notify", `{"channels":[]}`); code != 200 {
		t.Errorf("save here: %d", code)
	}
}

func TestNotifyRoutesAreForAdmins(t *testing.T) {
	ts, _ := newRoleServer(t)
	for _, who := range []string{"vera", "andy"} {
		for _, r := range [][2]string{{"GET", "/api/notify"}, {"PUT", "/api/notify"}, {"POST", "/api/notify/test"}, {"GET", "/api/notify/deliveries"}} {
			if code, _ := doAs(t, ts, who, "role-password", r[0], r[1], "{}"); code != 403 {
				t.Errorf("%s %s %s = %d", who, r[0], r[1], code)
			}
		}
	}
	// Without notifications set up, admins hear so.
	if code, _ := doAs(t, ts, "admin", "s3cret-pass", "GET", "/api/notify", ""); code != 503 {
		t.Errorf("notifications off: %d", code)
	}
}

func TestNotifyDeliveriesListsNewestFirst(t *testing.T) {
	ts, n := newNotifyServer(t, nil)
	mem := n.Deliveries.(*notify.Memory)
	for _, id := range []string{"a", "b", "c"} {
		d := &notify.Delivery{ID: id, Kind: notify.KindFinding, Channel: "x", Status: notify.StatusSent, Message: notify.Message{Title: "t " + id}}
		mem.Claim(context.Background(), d)
	}
	_, body := doAs(t, ts, "admin", "s3cret-pass", "GET", "/api/notify/deliveries?limit=2", "")
	list := body["deliveries"].([]any)
	if len(list) != 2 || list[0].(map[string]any)["id"] != "c" || list[0].(map[string]any)["title"] != "t c" {
		t.Errorf("list %v", list)
	}
}

func notifyJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
