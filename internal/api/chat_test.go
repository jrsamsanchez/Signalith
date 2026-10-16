package api

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/chatops"
	"github.com/jrsamsanchez/signalith/internal/findings"
	"github.com/jrsamsanchez/signalith/internal/notify"
	"github.com/jrsamsanchez/signalith/internal/playbooks"
	"github.com/jrsamsanchez/signalith/internal/users"
)

// chatServer is a server with a Slack channel with buttons, a Teams app
// channel, a playbook run waiting for approval, a finding, and the
// viewer vera and analysts andy and bea.
func chatServer(t *testing.T) (*httptest.Server, *Server, *chatops.Memory, chan map[string]any, string) {
	t.Helper()
	answers := make(chan map[string]any, 10)
	slack := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var m map[string]any
		_ = json.NewDecoder(r.Body).Decode(&m)
		answers <- m
	}))
	t.Cleanup(slack.Close)
	store := chatops.NewMemory()
	runs := playbooks.NewMemory()
	var srv *Server
	ts, _ := newTestServerWith(t, func(s *Server) {
		srv = s
		s.Config.Server.PublicURL = "https://siem.example.com"
		s.Users = users.NewMemory()
		for name, role := range map[string]users.Role{"vera": users.Viewer, "andy": users.Analyst, "bea": users.Analyst} {
			if _, err := s.Users.Create(context.Background(), users.NewUser{Username: name, Role: role, Password: "role-password"}); err != nil {
				t.Fatal(err)
			}
		}
		notes := &notify.Manager{}
		if _, err := notes.Save(notify.Input{Channels: []notify.ChannelInput{
			{ID: "soc", Name: "#soc", Type: "slack", URL: "https://hooks.slack.com/services/T/B/x", SigningSecret: "slack-secret", ApproveInChat: true},
			{ID: "teams", Name: "SOC", Type: "teams_app", AppID: "11111111-2222-3333-4444-555555555555", TenantID: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", AppPassword: "pw"},
		}}); err != nil {
			t.Fatal(err)
		}
		s.Notify = &Notify{Settings: notes, Sender: &notify.Senders{}}
		s.Playbooks = &Playbooks{Manager: &playbooks.Manager{}, Runs: runs}
		s.Chat = &Chat{Store: store}
		svc := &chatops.Service{Store: store, Desk: chatDesk{s}, Channels: notes.Settings, Log: s.Log,
			PublicURL:  func() string { return s.conf().Server.PublicURL },
			SlackURLOK: func(u *url.URL) bool { return strings.HasPrefix(u.String(), slack.URL) }}
		s.Chat.Service = svc
	})
	now := time.Now().UTC()
	run := &playbooks.Run{ID: "run1", PlaybookName: "Brute force", FindingID: "f1", Status: playbooks.StatusWaiting, Created: now, Updated: now,
		Steps:    []playbooks.StepResult{{Step: 1, Kind: playbooks.StepAction, Status: playbooks.StepWaiting}},
		Approval: &playbooks.Approval{Step: 1, Action: "block", What: "Block 203.0.113.7.", Requested: now, Expires: now.Add(time.Hour)}}
	if _, err := runs.Claim(t.Context(), run); err != nil {
		t.Fatal(err)
	}
	if err := srv.Findings.Create(t.Context(), &findings.Finding{ID: "f1", Title: "Brute force", Status: findings.StatusNew, Severity: "high", Created: now}); err != nil {
		t.Fatal(err)
	}
	// A Slack account with a link waiting to be confirmed.
	_ = store.SaveToken(t.Context(), chatops.Token{ID: chatops.TokenID(strings.Repeat("ab", 32)), System: chatops.Slack, Team: "T1", TeamName: "acme",
		ChatUser: "U1", ChatName: "andy.s", Channel: "soc", Expires: now.Add(chatops.TokenLife)})
	return ts, srv, store, answers, slack.URL + "/actions/T1/1/x"
}

// slackClick posts a signed Slack click to the server.
func slackClick(t *testing.T, ts *httptest.Server, secret, user, trigger, actionID, value, responseURL string) int {
	t.Helper()
	payload, _ := json.Marshal(map[string]any{"type": "block_actions", "trigger_id": trigger, "response_url": responseURL,
		"user": map[string]any{"id": user, "username": "andy.s"}, "team": map[string]any{"id": "T1", "domain": "acme"},
		"actions": []any{map[string]any{"action_id": actionID, "value": value}}})
	body := url.Values{"payload": {string(payload)}}.Encode()
	req, _ := http.NewRequest("POST", ts.URL+"/api/chat/slack/soc", strings.NewReader(body))
	stamp := strconv.FormatInt(time.Now().Unix(), 10)
	req.Header.Set("X-Slack-Request-Timestamp", stamp)
	req.Header.Set("X-Slack-Signature", chatops.SlackSign(secret, stamp, []byte(body)))
	resp, err := noRedirect.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

func TestChatLinkAndApprove(t *testing.T) {
	ts, srv, store, answers, respURL := chatServer(t)
	tok := `{"token":"` + strings.Repeat("ab", 32) + `"}`

	// The click routes need no sign-in, but a Slack signature.
	if code := slackClick(t, ts, "wrong", "U1", "x", "signalith_ack", "v", "https://hooks.slack.com/x"); code != 401 {
		t.Fatalf("unsigned click = %d", code)
	}

	// The page shows which account a link is for, then links it to the
	// signed-in user.
	code, body := doAs(t, ts, "andy", "role-password", "POST", "/api/chat/link/check", tok)
	if code != 200 || body["account"] != "Slack user andy.s in acme" {
		t.Fatalf("check = %d %v", code, body)
	}
	if code, body = doAs(t, ts, "andy", "role-password", "POST", "/api/chat/link", tok); code != 200 || body["username"] != "andy" {
		t.Fatalf("link = %d %v", code, body)
	}
	if code, _ = doAs(t, ts, "bea", "role-password", "POST", "/api/chat/link", tok); code != 410 {
		t.Errorf("second use = %d", code)
	}
	if code, _ = doAs(t, ts, "andy", "role-password", "POST", "/api/chat/link", `{"token":"short"}`); code != 400 {
		t.Errorf("bad token = %d", code)
	}

	// Now andy's Slack clicks count as andy's.
	c, _ := srv.Notify.Settings.Settings()
	soc, _ := c.Channel("soc")
	approve := notify.SignButton(soc, notify.Button{Action: notify.ButtonApprove, ID: "run1", Step: 1})
	if code := slackClick(t, ts, "slack-secret", "U1", "t1", "signalith_approve", approve, respURL); code != 200 {
		t.Fatalf("click = %d", code)
	}
	srv.Chat.Service.Wait()
	m := <-answers
	if m["replace_original"] != true {
		t.Fatalf("answer = %v", m)
	}
	st, err := srv.Playbooks.Runs.Get(t.Context(), "run1")
	if err != nil || st.Status != playbooks.StatusApproved || st.Approval.DecidedBy != "andy" || !strings.Contains(st.Approval.Note, "Slack") {
		t.Fatalf("run = %+v %v", st.Run, err)
	}

	// Acknowledge makes andy the owner.
	ack := notify.SignButton(soc, notify.Button{Action: notify.ButtonAck, ID: "f1"})
	slackClick(t, ts, "slack-secret", "U1", "t2", "signalith_ack", ack, respURL)
	srv.Chat.Service.Wait()
	<-answers
	f, _ := srv.Findings.Get(t.Context(), "f1")
	if f.Owner != "andy" || f.Status != findings.StatusInProgress {
		t.Errorf("finding = %s %s", f.Owner, f.Status)
	}

	// Users see their own links only, and remove only their own.
	code, body = doAs(t, ts, "bea", "role-password", "GET", "/api/chat/accounts", "")
	if code != 200 || len(body["accounts"].([]any)) != 0 {
		t.Errorf("bea accounts = %d %v", code, body)
	}
	code, body = doAs(t, ts, "andy", "role-password", "GET", "/api/chat/accounts", "")
	list := body["accounts"].([]any)
	if code != 200 || len(list) != 1 {
		t.Fatalf("andy accounts = %d %v", code, body)
	}
	id := list[0].(map[string]any)["id"].(string)
	if code, _ = doAs(t, ts, "bea", "role-password", "DELETE", "/api/chat/accounts/"+id, ""); code != 404 {
		t.Errorf("bea removes andy's = %d", code)
	}
	// Admins see every link.
	if code, _ = doAs(t, ts, "andy", "role-password", "GET", "/api/chat/links", ""); code != 403 {
		t.Errorf("analyst all links = %d", code)
	}
	if code, body = do(t, ts, "GET", "/api/chat/links", "", true); code != 200 || len(body["links"].([]any)) != 1 {
		t.Errorf("admin links = %d %v", code, body)
	}
	if code, _ = doAs(t, ts, "andy", "role-password", "DELETE", "/api/chat/accounts/"+id, ""); code != 200 {
		t.Errorf("andy removes own = %d", code)
	}
	if len(store.LinksOf()) != 0 {
		t.Error("link kept")
	}
}

func TestChatCodeAndTeamsApp(t *testing.T) {
	ts, _, store, _, _ := chatServer(t)
	code, body := doAs(t, ts, "vera", "role-password", "POST", "/api/chat/code", "")
	if code != 200 || len(body["code"].(string)) != 11 {
		t.Fatalf("code = %d %v", code, body)
	}
	tk, err := store.PeekToken(t.Context(), chatops.TokenID(body["code"].(string)), time.Now())
	if err != nil || tk.Username != "vera" || tk.System != chatops.Teams {
		t.Fatalf("token = %+v %v", tk, err)
	}
	// A Teams code is not a link for the page.
	if code, _ = doAs(t, ts, "vera", "role-password", "POST", "/api/chat/link/check", `{"token":"`+strings.Repeat("cd", 32)+`"}`); code != 410 {
		t.Errorf("unknown token = %d", code)
	}

	// The Teams app download is for admins.
	if code, _ = doAs(t, ts, "andy", "role-password", "GET", "/api/notify/channels/teams/teams-app", ""); code != 403 {
		t.Errorf("analyst download = %d", code)
	}
	req, _ := http.NewRequest("GET", ts.URL+"/api/notify/channels/teams/teams-app", nil)
	req.SetBasicAuth("admin", "s3cret-pass")
	resp, err := noRedirect.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	zr, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if resp.StatusCode != 200 || err != nil {
		t.Fatalf("download = %d %v", resp.StatusCode, err)
	}
	var manifest map[string]any
	for _, f := range zr.File {
		if f.Name == "manifest.json" {
			r, _ := f.Open()
			_ = json.NewDecoder(r).Decode(&manifest)
			r.Close()
		}
	}
	bots, _ := manifest["bots"].([]any)
	if manifest["id"] != "11111111-2222-3333-4444-555555555555" || len(bots) != 1 || manifest["validDomains"].([]any)[0] != "siem.example.com" {
		t.Errorf("manifest = %v", manifest)
	}

	// The Notifications page shows where to point Slack and Teams.
	code, body = do(t, ts, "GET", "/api/notify", "", true)
	if code != 200 {
		t.Fatal(code)
	}
	for _, ch := range body["channels"].([]any) {
		c := ch.(map[string]any)
		want := "https://siem.example.com/api/chat/slack/soc"
		if c["type"] == "teams_app" {
			want = "https://siem.example.com/api/chat/teams/teams"
		}
		if c["chat_url"] != want || c["interactive"] != true {
			t.Errorf("channel %v: chat_url %v interactive %v", c["id"], c["chat_url"], c["interactive"])
		}
	}
}
