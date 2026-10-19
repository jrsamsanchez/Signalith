// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package chatops

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/notify"
	"github.com/jrsamsanchez/signalith/internal/playbooks"
	"github.com/jrsamsanchez/signalith/internal/users"
)

// fakeDesk records decisions and acknowledgements.
type fakeDesk struct {
	mu      sync.Mutex
	users   map[string]User
	decided []string
	acked   []string
	err     error
	owner   string
}

func (d *fakeDesk) User(name string) (User, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	u, ok := d.users[name]
	return u, ok
}

func (d *fakeDesk) Decide(_ context.Context, runID string, step int, user, note string, approve bool) (playbooks.Run, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.err != nil {
		return playbooks.Run{}, d.err
	}
	d.decided = append(d.decided, runID+"/"+strconv.Itoa(step)+"/"+user+"/"+strconv.FormatBool(approve)+"/"+note)
	return playbooks.Run{ID: runID, PlaybookName: "Brute force", Approval: &playbooks.Approval{Step: step, What: "Block 203.0.113.7 on the firewall."}}, nil
}

func (d *fakeDesk) Acknowledge(_ context.Context, findingID, user, note string) (Ack, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.acked = append(d.acked, findingID+"/"+user+"/"+note)
	return Ack{Title: "Brute force", Owner: d.owner}, nil
}

// slackFixture is a Slack channel with buttons, a service, and a fake
// response_url that records what Slack was told.
type slackFixture struct {
	svc     *Service
	desk    *fakeDesk
	store   *Memory
	channel notify.Channel
	answers chan map[string]any
	answer  *httptest.Server
	ts      *httptest.Server
	now     time.Time
	// team is the Slack workspace clicks come from; "" is T1.
	team string
}

func newSlackFixture(t *testing.T) *slackFixture {
	t.Helper()
	f := &slackFixture{answers: make(chan map[string]any, 10), now: time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)}
	f.answer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var m map[string]any
		_ = json.NewDecoder(r.Body).Decode(&m)
		f.answers <- m
	}))
	t.Cleanup(f.answer.Close)
	f.channel = notify.Channel{ID: "soc", Name: "#soc", Type: notify.TypeSlack, URL: "https://hooks.slack.com/services/T/B/x",
		SigningSecret: "slack-signing-secret", ApproveInChat: true}
	f.desk = &fakeDesk{users: map[string]User{
		"andy": {Username: "andy", Name: "Andy Analyst", Role: users.Analyst},
		"vera": {Username: "vera", Role: users.Viewer},
	}}
	f.store = NewMemory()
	f.svc = &Service{
		Store: f.store, Desk: f.desk, Log: slog.New(slog.DiscardHandler),
		Channels:  func() (notify.Settings, error) { return notify.Settings{Channels: []notify.Channel{f.channel}}, nil },
		PublicURL: func() string { return "https://siem.example.com/" },
		HTTP:      &http.Client{Transport: toFake{f.answer.URL}},
		Now:       func() time.Time { return f.now },
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/chat/slack/{channel}", f.svc.ServeSlack)
	f.ts = httptest.NewServer(mux)
	t.Cleanup(f.ts.Close)
	return f
}

// click sends a signed click on a button, as Slack would.
func (f *slackFixture) click(t *testing.T, user, trigger, actionID, value string, sign func(ts string, body []byte) string) int {
	t.Helper()
	team := f.team
	if team == "" {
		team = "T1"
	}
	payload := map[string]any{
		"type": "block_actions", "trigger_id": trigger, "response_url": "https://hooks.slack.com/actions/T/1/x",
		"user":    map[string]any{"id": "U" + user, "username": user, "team_id": team},
		"team":    map[string]any{"id": team, "domain": "acme"},
		"actions": []any{map[string]any{"action_id": actionID, "value": value, "action_ts": "1.2"}},
		"message": map[string]any{"text": "High: Brute force", "blocks": []any{
			map[string]any{"type": "header", "text": map[string]any{"type": "plain_text", "text": "High: Brute force"}},
			map[string]any{"type": "actions", "block_id": "signalith_actions", "elements": []any{
				map[string]any{"type": "button", "action_id": "signalith_approve", "value": value},
				map[string]any{"type": "button", "action_id": "signalith_open", "url": "https://siem.example.com/#approvals"},
			}},
		}},
	}
	raw, _ := json.Marshal(payload)
	body := []byte(url.Values{"payload": {string(raw)}}.Encode())
	ts := strconv.FormatInt(f.now.Unix(), 10)
	req, _ := http.NewRequest("POST", f.ts.URL+"/api/chat/slack/soc", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Slack-Request-Timestamp", ts)
	if sign == nil {
		sign = func(ts string, body []byte) string { return SlackSign(f.channel.SigningSecret, ts, body) }
	}
	req.Header.Set("X-Slack-Signature", sign(ts, body))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	f.svc.Wait()
	return resp.StatusCode
}

func (f *slackFixture) next(t *testing.T) map[string]any {
	t.Helper()
	select {
	case m := <-f.answers:
		return m
	case <-time.After(5 * time.Second):
		t.Fatal("Slack was not answered")
		return nil
	}
}

func (f *slackFixture) none(t *testing.T) {
	t.Helper()
	select {
	case m := <-f.answers:
		t.Fatalf("unexpected answer %v", m)
	default:
	}
}

func TestSlackClickFlow(t *testing.T) {
	f := newSlackFixture(t)
	approve := notify.SignButton(f.channel, notify.Button{Action: notify.ButtonApprove, ID: "run1", Step: 1})

	// An account with no link gets a link only it sees, and nothing is
	// decided.
	if code := f.click(t, "andy", "trig-1", "signalith_approve", approve, nil); code != 200 {
		t.Fatalf("click = %d", code)
	}
	m := f.next(t)
	text, _ := m["text"].(string)
	if m["response_type"] != "ephemeral" || m["replace_original"] != false || !strings.Contains(text, "<https://siem.example.com/#chat-link/") {
		t.Fatalf("unlinked answer = %v", m)
	}
	if len(f.desk.decided) != 0 {
		t.Fatalf("decided while unlinked: %v", f.desk.decided)
	}
	secret := text[strings.Index(text, "#chat-link/")+len("#chat-link/"):]
	secret = secret[:strings.Index(secret, "|")]
	tok, err := f.store.PeekToken(t.Context(), TokenID(secret), f.now)
	if err != nil || tok.ChatUser != "Uandy" || tok.Team != "T1" || tok.Channel != "soc" {
		t.Fatalf("token = %+v %v", tok, err)
	}
	// Linking is the web page's job (package api); here it is stored.
	if err := f.store.SaveLink(t.Context(), Link{ID: LinkID(Slack, "T1", "Uandy"), System: Slack, Team: "T1", ChatUser: "Uandy", Username: "andy"}); err != nil {
		t.Fatal(err)
	}

	// The same click again is ignored.
	f.click(t, "andy", "trig-1", "signalith_approve", approve, nil)
	f.none(t)

	// A linked analyst approves: the message loses its buttons but the
	// link, and says who approved.
	f.click(t, "andy", "trig-2", "signalith_approve", approve, nil)
	m = f.next(t)
	if m["replace_original"] != true {
		t.Fatalf("approve answer = %v", m)
	}
	blocks := m["blocks"].([]any)
	actions := blocks[1].(map[string]any)["elements"].([]any)
	if len(actions) != 1 || actions[0].(map[string]any)["action_id"] != "signalith_open" {
		t.Fatalf("buttons left = %v", actions)
	}
	outcome := blocks[2].(map[string]any)["elements"].([]any)[0].(map[string]any)["text"].(string)
	if !strings.Contains(outcome, "Approved by Andy Analyst (andy) in Slack") {
		t.Fatalf("outcome = %q", outcome)
	}
	if len(f.desk.decided) != 1 || f.desk.decided[0] != "run1/1/andy/true/Decided in Slack as andy." {
		t.Fatalf("decided = %v", f.desk.decided)
	}

	// Acknowledge.
	ack := notify.SignButton(f.channel, notify.Button{Action: notify.ButtonAck, ID: "f1"})
	f.click(t, "andy", "trig-3", "signalith_ack", ack, nil)
	m = f.next(t)
	if m["replace_original"] != true || len(f.desk.acked) != 1 || !strings.HasPrefix(f.desk.acked[0], "f1/andy/") {
		t.Fatalf("ack = %v %v", m, f.desk.acked)
	}

	// A click from another workspace that shares the Slack app is refused:
	// the channel is used in the first workspace that clicked.
	f.team = "T2"
	if code := f.click(t, "andy", "trig-4", "signalith_ack", ack, nil); code != 403 {
		t.Errorf("other workspace = %d", code)
	}
	f.team = ""

	// Once andy's sessions end (a new password, sign out everywhere, a
	// two-step sign-in reset), the link ends too.
	f.desk.mu.Lock()
	u := f.desk.users["andy"]
	u.Epoch++
	f.desk.users["andy"] = u
	f.desk.mu.Unlock()
	f.click(t, "andy", "trig-5", "signalith_ack", ack, nil)
	if m = f.next(t); !strings.Contains(m["text"].(string), "unlinked because") || len(f.desk.acked) != 1 {
		t.Fatalf("after sessions ended = %v %v", m, f.desk.acked)
	}
	if _, found, _ := f.store.Link(t.Context(), Slack, "T1", "Uandy"); found {
		t.Error("link kept after the user's sessions ended")
	}
}

func TestSlackRefusals(t *testing.T) {
	f := newSlackFixture(t)
	approve := notify.SignButton(f.channel, notify.Button{Action: notify.ButtonApprove, ID: "run1", Step: 1})
	for _, l := range []Link{
		{ID: LinkID(Slack, "T1", "Uandy"), System: Slack, Team: "T1", ChatUser: "Uandy", Username: "andy"},
		{ID: LinkID(Slack, "T1", "Uvera"), System: Slack, Team: "T1", ChatUser: "Uvera", Username: "vera"},
		{ID: LinkID(Slack, "T1", "Ugone"), System: Slack, Team: "T1", ChatUser: "Ugone", Username: "gone"},
	} {
		if err := f.store.SaveLink(t.Context(), l); err != nil {
			t.Fatal(err)
		}
	}

	// A bad signature, or an old request, is refused before anything.
	if code := f.click(t, "andy", "t1", "signalith_approve", approve, func(string, []byte) string { return "v0=00" }); code != 401 {
		t.Errorf("bad signature = %d", code)
	}
	f.now = f.now.Add(10 * time.Minute)
	old := f.now.Add(-10 * time.Minute)
	if code := f.click(t, "andy", "t2", "signalith_approve", approve, func(_ string, body []byte) string {
		return SlackSign(f.channel.SigningSecret, strconv.FormatInt(old.Unix(), 10), body)
	}); code != 401 {
		t.Errorf("mismatched timestamp = %d", code)
	}
	f.none(t)

	// A button Signalith did not sign, or one for another step's
	// object, is refused.
	forged := strings.Replace(approve, "run1", "run2", 1)
	f.click(t, "andy", "t3", "signalith_approve", forged, nil)
	if m := f.next(t); m["response_type"] != "ephemeral" || !strings.Contains(m["text"].(string), "not sent by Signalith") {
		t.Errorf("forged = %v", m)
	}

	// A viewer, or a user who can no longer sign in, may not decide.
	f.click(t, "vera", "t4", "signalith_approve", approve, nil)
	if m := f.next(t); !strings.Contains(m["text"].(string), "needs the Analyst role") {
		t.Errorf("viewer = %v", m)
	}
	f.click(t, "gone", "t5", "signalith_approve", approve, nil)
	if m := f.next(t); !strings.Contains(m["text"].(string), "can no longer sign in") {
		t.Errorf("gone = %v", m)
	}

	// A user who must set up two-step sign-in first is refused.
	f.desk.users["andy"] = User{Username: "andy", Role: users.Analyst, Blocked: "Your Signalith user must set up two-step sign-in first."}
	f.click(t, "andy", "t6", "signalith_approve", approve, nil)
	if m := f.next(t); !strings.Contains(m["text"].(string), "two-step") {
		t.Errorf("blocked = %v", m)
	}

	// A link made for an earlier user of the same name stops working.
	f.desk.users["andy"] = User{Username: "andy", Role: users.Analyst, Created: f.now}
	l := Link{ID: LinkID(Slack, "T1", "Uandy"), System: Slack, Team: "T1", ChatUser: "Uandy", Username: "andy", UserCreated: f.now.Add(-time.Hour)}
	_ = f.store.SaveLink(t.Context(), l)
	f.click(t, "andy", "t7", "signalith_approve", approve, nil)
	if m := f.next(t); !strings.Contains(m["text"].(string), "earlier Signalith user") {
		t.Errorf("stale link = %v", m)
	}
	if _, found, _ := f.store.Link(t.Context(), Slack, "T1", "Uandy"); found {
		t.Error("stale link kept")
	}

	// Approve is off on a channel that does not allow it; Reject still
	// works.
	_ = f.store.SaveLink(t.Context(), Link{ID: LinkID(Slack, "T1", "Uandy"), System: Slack, Team: "T1", ChatUser: "Uandy", Username: "andy", UserCreated: f.now})
	f.channel.ApproveInChat = false
	approve = notify.SignButton(f.channel, notify.Button{Action: notify.ButtonApprove, ID: "run1", Step: 1})
	f.click(t, "andy", "t8", "signalith_approve", approve, nil)
	if m := f.next(t); !strings.Contains(m["text"].(string), "turned off") {
		t.Errorf("approve off = %v", m)
	}
	reject := notify.SignButton(f.channel, notify.Button{Action: notify.ButtonReject, ID: "run1", Step: 1})
	f.click(t, "andy", "t9", "signalith_reject", reject, nil)
	if m := f.next(t); m["replace_original"] != true {
		t.Errorf("reject = %v", m)
	}
	if len(f.desk.decided) != 1 || !strings.Contains(f.desk.decided[0], "/false/") {
		t.Errorf("decided = %v", f.desk.decided)
	}

	// Someone else decided first: the message says so for everyone.
	f.desk.err = &playbooks.DecidedError{Run: playbooks.Run{Status: playbooks.StatusApproved, Approval: &playbooks.Approval{DecidedBy: "bea"}}}
	f.click(t, "andy", "t10", "signalith_reject", reject, nil)
	if m := f.next(t); m["replace_original"] != true || !strings.Contains(m["blocks"].([]any)[2].(map[string]any)["elements"].([]any)[0].(map[string]any)["text"].(string), "already approved by bea") {
		t.Errorf("decided first = %v", m)
	}

	// An unknown channel is not found; one without a signing secret
	// neither.
	resp, _ := http.Post(f.ts.URL+"/api/chat/slack/nope", "application/x-www-form-urlencoded", strings.NewReader("payload={}"))
	if resp.StatusCode != 404 {
		t.Errorf("unknown channel = %d", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestSlackResponseURLMustBeSlack(t *testing.T) {
	for raw, ok := range map[string]bool{
		"https://hooks.slack.com/actions/T/1/x": true,
		"http://hooks.slack.com/actions/T/1/x":  false,
		"https://hooks.slack.com.evil.example/": false,
		"https://user@hooks.slack.com/":         false,
		"https://hooks.slack.com:8443/":         false,
		"https://hooks.slack-gov.com/actions/x": true,
		"https://hooks.slack.com/a/../b":        false,
		"https://hooks.slack.com/actions?x=1":   false,
		"https://hooks.slack.com/":              false,
	} {
		u, _ := url.Parse(raw)
		if SlackResponseURLAllowed(u) != ok {
			t.Errorf("%s = %v", raw, !ok)
		}
	}
}

// botFramework is a fake Bot Framework: its OpenID metadata and keys,
// and tokens signed with them.
type botFramework struct {
	key *rsa.PrivateKey
	ts  *httptest.Server
	// endorse is the key's endorsements; nil is msteams.
	endorse []string
}

func newBotFramework(t *testing.T) *botFramework {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	b := &botFramework{key: key}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/.well-known/openidconfiguration", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"issuer": botIssuer, "jwks_uri": b.ts.URL + "/v1/.well-known/keys"})
	})
	mux.HandleFunc("GET /v1/.well-known/keys", func(w http.ResponseWriter, r *http.Request) {
		n := base64.RawURLEncoding.EncodeToString(key.N.Bytes())
		e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())
		endorse := b.endorse
		if endorse == nil {
			endorse = []string{"msteams"}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{
			map[string]any{"kty": "RSA", "kid": "k1", "use": "sig", "n": n, "e": e, "endorsements": endorse},
		}})
	})
	b.ts = httptest.NewServer(mux)
	t.Cleanup(b.ts.Close)
	return b
}

func (b *botFramework) token(t *testing.T, claims map[string]any) string {
	t.Helper()
	h, _ := json.Marshal(map[string]any{"alg": "RS256", "kid": "k1", "typ": "JWT"})
	c, _ := json.Marshal(claims)
	signed := base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(c)
	sum := sha256.Sum256([]byte(signed))
	sig, err := rsa.SignPKCS1v15(rand.Reader, b.key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return signed + "." + base64.RawURLEncoding.EncodeToString(sig)
}

const (
	testAppID  = "11111111-2222-3333-4444-555555555555"
	testTenant = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
)

// teamsFixture is a Teams app channel, a fake Bot Framework, a fake Bot
// Connector and Entra token endpoint, and a service.
type teamsFixture struct {
	svc       *Service
	desk      *fakeDesk
	store     *Memory
	channel   notify.Channel
	bf        *botFramework
	connector *httptest.Server
	posted    chan map[string]any
	ts        *httptest.Server
	now       time.Time
}

func newTeamsFixture(t *testing.T) *teamsFixture {
	t.Helper()
	f := &teamsFixture{bf: newBotFramework(t), posted: make(chan map[string]any, 10), now: time.Now()}
	f.connector = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/oauth2/v2.0/token"):
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "bot-token", "expires_in": 3600})
		case strings.Contains(r.URL.Path, "/v3/conversations/"):
			if r.Header.Get("Authorization") != "Bearer bot-token" {
				w.WriteHeader(401)
				return
			}
			var m map[string]any
			_ = json.NewDecoder(r.Body).Decode(&m)
			m["_path"] = r.URL.Path
			f.posted <- m
			_, _ = io.WriteString(w, `{"id":"act-1"}`)
		default:
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(f.connector.Close)
	f.channel = notify.Channel{ID: "teams", Name: "SOC", Type: notify.TypeTeamsApp, AppID: testAppID, TenantID: testTenant,
		AppPassword: "client-secret", ApproveInChat: true, AllowLoopback: true}
	f.desk = &fakeDesk{users: map[string]User{"andy": {Username: "andy", Role: users.Analyst}, "ada": {Username: "ada", Role: users.Admin}}}
	f.store = NewMemory()
	senders := &notify.Senders{TeamsLogin: f.connector.URL, Transport: toFake{f.connector.URL}, Conversations: f.store}
	f.svc = &Service{
		Store: f.store, Desk: f.desk, Teams: senders, Log: slog.New(slog.DiscardHandler),
		Channels:  func() (notify.Settings, error) { return notify.Settings{Channels: []notify.Channel{f.channel}}, nil },
		PublicURL: func() string { return "https://siem.example.com" },
		Verifier:  &BotVerifier{Metadata: f.bf.ts.URL + "/v1/.well-known/openidconfiguration"},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/chat/teams/{channel}", f.svc.ServeTeams)
	f.ts = httptest.NewServer(mux)
	t.Cleanup(f.ts.Close)
	return f
}

func (f *teamsFixture) claims() map[string]any {
	return map[string]any{"iss": botIssuer, "aud": testAppID, "exp": f.now.Add(time.Hour).Unix(), "nbf": f.now.Add(-time.Minute).Unix(),
		"serviceurl": "https://smba.trafficmanager.net/amer/"}
}

// private makes an activity come from a one-to-one chat with the app.
func private(a map[string]any) map[string]any {
	a["conversation"] = map[string]any{"id": "a:private-andy", "conversationType": "personal", "tenantId": testTenant}
	return a
}

// from makes an activity come from another Teams user.
func from(a map[string]any, name, objectID string) map[string]any {
	a["from"] = map[string]any{"id": "29:" + name, "name": name, "aadObjectId": objectID}
	return a
}

// activity is an activity from the fake Teams.
func (f *teamsFixture) activity(kind string, extra map[string]any) map[string]any {
	a := map[string]any{
		"type": kind, "id": "a-" + strconv.FormatInt(time.Now().UnixNano(), 10), "channelId": "msteams", "serviceUrl": "https://smba.trafficmanager.net/amer/",
		"from":         map[string]any{"id": "29:andy", "name": "Andy", "aadObjectId": "0000AAAA-0000-0000-0000-000000000001"},
		"recipient":    map[string]any{"id": "28:" + testAppID, "name": "Signalith"},
		"conversation": map[string]any{"id": "19:soc@thread.tacv2", "conversationType": "channel", "tenantId": testTenant},
		"channelData": map[string]any{"tenant": map[string]any{"id": testTenant}, "team": map[string]any{"id": "19:team@thread.tacv2", "name": "SOC team"},
			"channel": map[string]any{"id": "19:soc@thread.tacv2", "name": "Alerts"}},
	}
	for k, v := range extra {
		a[k] = v
	}
	return a
}

func (f *teamsFixture) send(t *testing.T, token string, a map[string]any) (int, map[string]any) {
	t.Helper()
	raw, _ := json.Marshal(a)
	req, _ := http.NewRequest("POST", f.ts.URL+"/api/chat/teams/teams", strings.NewReader(string(raw)))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	f.svc.Wait()
	return resp.StatusCode, out
}

func (f *teamsFixture) click(t *testing.T, value, verb string) map[string]any {
	t.Helper()
	code, out := f.send(t, f.bf.token(t, f.claims()), f.activity("invoke", map[string]any{"name": "adaptiveCard/action",
		"value": map[string]any{"action": map[string]any{"type": "Action.Execute", "verb": verb, "data": map[string]any{notify.TeamsButtonField: value}}}}))
	if code != 200 {
		t.Fatalf("click = %d %v", code, out)
	}
	return out
}

func TestTeamsFlow(t *testing.T) {
	f := newTeamsFixture(t)
	tok := f.bf.token(t, f.claims())

	// Adding the app to a team channel is not enough to get messages.
	if code, _ := f.send(t, tok, f.activity("conversationUpdate", map[string]any{"membersAdded": []any{map[string]any{"id": "28:" + testAppID}}})); code != 200 {
		t.Fatalf("added = %d", code)
	}
	if _, ok, _ := f.store.Conversation(t.Context(), "teams"); ok {
		t.Fatal("adding the app chose where the channel posts")
	}
	// Nor is "post here" from someone who is not a linked admin.
	f.send(t, tok, f.activity("message", map[string]any{"text": "<at>Signalith</at> post here"}))
	if reply := <-f.posted; !strings.Contains(reply["text"].(string), "Only a Signalith admin") {
		t.Fatalf("unlinked post here = %v", reply)
	}
	// A linked admin's "post here" chooses it.
	const adaID = "0000aaaa-0000-0000-0000-0000000000ad"
	_ = f.store.SaveLink(t.Context(), Link{ID: LinkID(Teams, testTenant, adaID), System: Teams, Team: testTenant, ChatUser: adaID, Username: "ada"})
	f.send(t, tok, from(f.activity("message", map[string]any{"text": "<at>Signalith</at> post here"}), "Ada", adaID))
	if reply := <-f.posted; !strings.Contains(reply["text"].(string), "from now on") {
		t.Fatalf("admin post here = %v", reply)
	}
	conv, ok, _ := f.store.Conversation(t.Context(), "teams")
	if !ok || conv.ConversationID != "19:soc@thread.tacv2" || conv.Place() != "SOC team > Alerts" || conv.TeamID != "19:team@thread.tacv2" || conv.AddedBy != "ada" {
		t.Fatalf("conversation = %+v %v", conv, ok)
	}

	// Messages now go there, with buttons.
	snd := f.svc.Teams
	msg := notify.Message{Kind: notify.KindApproval, Title: "Brute force", FindingID: "f1", RunID: "run1", Step: 2, Ask: "Playbook X waits to block 203.0.113.7."}
	if err := snd.Send(t.Context(), f.channel, msg); err != nil {
		t.Fatal(err)
	}
	posted := <-f.posted
	if posted["_path"] != "/amer/v3/conversations/19:soc@thread.tacv2/activities" {
		t.Errorf("posted to %v", posted["_path"])
	}
	card := posted["attachments"].([]any)[0].(map[string]any)["content"].(map[string]any)
	actions := card["actions"].([]any)
	approve := actions[0].(map[string]any)
	if approve["type"] != "Action.Execute" || approve["verb"] != "signalith.approve" || len(actions) != 2 {
		t.Fatalf("actions = %v", actions)
	}
	value := approve["data"].(map[string]any)[notify.TeamsButtonField].(string)

	// An unlinked account is told how to link, and nothing is decided.
	out := f.click(t, value, "signalith.approve")
	if out["type"] != "application/vnd.microsoft.activity.message" || !strings.Contains(out["value"].(string), "link ABCDE-12345") {
		t.Fatalf("unlinked = %v", out)
	}

	// A code made in Signalith, sent to the app, links the account.
	code := NewCode()
	_ = f.store.SaveToken(t.Context(), Token{ID: TokenID(code), System: Teams, Username: "andy", Expires: time.Now().Add(TokenLife)})
	if c, _ := f.send(t, tok, private(f.activity("message", map[string]any{"text": "link " + strings.ToLower(code)}))); c != 200 {
		t.Fatalf("link message = %d", c)
	}
	reply := <-f.posted
	if !strings.Contains(reply["text"].(string), "linked to the Signalith user andy") || !strings.HasSuffix(reply["_path"].(string), "/activities/"+"a-"+reply["_path"].(string)[strings.LastIndex(reply["_path"].(string), "a-")+2:]) {
		t.Fatalf("link reply = %v", reply)
	}
	if l, found, _ := f.store.Link(t.Context(), Teams, testTenant, "0000aaaa-0000-0000-0000-000000000001"); !found || l.Username != "andy" {
		t.Fatalf("link = %+v %v", l, found)
	}
	// The code works once.
	f.send(t, tok, private(f.activity("message", map[string]any{"text": "link " + code})))
	if reply := <-f.posted; !strings.Contains(reply["text"].(string), "not right, was used already") {
		t.Fatalf("second use = %v", reply)
	}
	// A code sent in a shared channel is spent, not used.
	shared := NewCode()
	_ = f.store.SaveToken(t.Context(), Token{ID: TokenID(shared), System: Teams, Username: "ada", Expires: time.Now().Add(TokenLife)})
	f.send(t, tok, f.activity("message", map[string]any{"text": "<at>Signalith</at> link " + shared}))
	if reply := <-f.posted; !strings.Contains(reply["text"].(string), "private chat") {
		t.Fatalf("code in a channel = %v", reply)
	}
	if _, err := f.store.PeekToken(t.Context(), TokenID(shared), time.Now()); !errors.Is(err, ErrTokenUsed) {
		t.Errorf("code sent in a channel still works: %v", err)
	}
	// An analyst cannot move where the channel posts, and an admin's move
	// waits for confirmation in Signalith.
	other := f.activity("message", map[string]any{"text": "<at>Signalith</at> post here", "conversation": map[string]any{"id": "19:other@thread.v2", "conversationType": "groupChat", "tenantId": testTenant, "name": "Mallory chat"}})
	f.send(t, tok, other)
	if reply := <-f.posted; !strings.Contains(reply["text"].(string), "needs the Admin role") {
		t.Fatalf("analyst post here = %v", reply)
	}
	f.send(t, tok, from(other, "Ada", adaID))
	if reply := <-f.posted; !strings.Contains(reply["text"].(string), "confirms the move") {
		t.Fatalf("admin move = %v", reply)
	}
	if conv, _, _ := f.store.Conversation(t.Context(), "teams"); conv.ConversationID != "19:soc@thread.tacv2" || conv.Next == nil || conv.Next.ConversationID != "19:other@thread.v2" {
		t.Fatalf("after move request = %+v", conv)
	}

	// Now the click decides, and the card says who did.
	out = f.click(t, value, "signalith.approve")
	if out["type"] != "application/vnd.microsoft.card.adaptive" {
		t.Fatalf("approve = %v", out)
	}
	text := out["value"].(map[string]any)["body"].([]any)[0].(map[string]any)["text"].(string)
	if !strings.Contains(text, "Approved by andy in Teams") || len(f.desk.decided) != 1 || !strings.HasPrefix(f.desk.decided[0], "run1/2/andy/true/") {
		t.Fatalf("approve = %q %v", text, f.desk.decided)
	}

	// A verb that does not match the signed action is refused.
	out = f.click(t, value, "signalith.reject")
	if !strings.Contains(out["value"].(string), "not sent by Signalith") {
		t.Fatalf("verb mismatch = %v", out)
	}

	// Removing the app from the team forgets where it posted.
	f.send(t, tok, f.activity("installationUpdate", map[string]any{"action": "remove"}))
	if _, ok, _ := f.store.Conversation(t.Context(), "teams"); ok {
		t.Error("conversation kept after the app was removed")
	}
}

func TestTeamsRefusals(t *testing.T) {
	f := newTeamsFixture(t)
	added := func(extra map[string]any) map[string]any {
		a := f.activity("conversationUpdate", map[string]any{"membersAdded": []any{map[string]any{"id": "28:" + testAppID}}})
		for k, v := range extra {
			a[k] = v
		}
		return a
	}
	claims := func(change func(map[string]any)) string {
		c := f.claims()
		change(c)
		return f.bf.token(t, c)
	}
	for name, tc := range map[string]struct {
		token string
		a     map[string]any
		want  int
	}{
		"no token":         {"", added(nil), 401},
		"other bot":        {claims(func(c map[string]any) { c["aud"] = "99999999-2222-3333-4444-555555555555" }), added(nil), 401},
		"other issuer":     {claims(func(c map[string]any) { c["iss"] = "https://evil.example" }), added(nil), 401},
		"expired":          {claims(func(c map[string]any) { c["exp"] = f.now.Add(-time.Hour).Unix() }), added(nil), 401},
		"other serviceurl": {claims(func(c map[string]any) { c["serviceurl"] = "https://smba.trafficmanager.net/emea/" }), added(nil), 401},
		"not signed":       {"eyJhbGciOiJub25lIn0.eyJpc3MiOiJodHRwczovL2FwaS5ib3RmcmFtZXdvcmsuY29tIn0.", added(nil), 401},
		"other tenant":     {f.bf.token(t, f.claims()), added(map[string]any{"channelData": map[string]any{"tenant": map[string]any{"id": "ffffffff-bbbb-cccc-dddd-eeeeeeeeeeee"}}}), 403},
		"not teams":        {f.bf.token(t, f.claims()), added(map[string]any{"channelId": "emulator"}), 403},
	} {
		if code, _ := f.send(t, tc.token, tc.a); code != tc.want {
			t.Errorf("%s = %d, want %d", name, code, tc.want)
		}
	}
	if _, ok, _ := f.store.Conversation(t.Context(), "teams"); ok {
		t.Error("a refused request recorded a conversation")
	}

	// Wrong codes are limited.
	tok := f.bf.token(t, f.claims())
	for i := 0; i < maxCodeTries; i++ {
		f.send(t, tok, private(f.activity("message", map[string]any{"text": "link WRONG-CODE"})))
		<-f.posted
	}
	code := NewCode()
	_ = f.store.SaveToken(t.Context(), Token{ID: TokenID(code), System: Teams, Username: "andy", Expires: time.Now().Add(TokenLife)})
	f.send(t, tok, private(f.activity("message", map[string]any{"text": "link " + code})))
	if reply := <-f.posted; !strings.Contains(reply["text"].(string), "Too many wrong codes") {
		t.Fatalf("after wrong codes = %v", reply)
	}
	// A Slack link token is not a Teams code.
	f2 := newTeamsFixture(t)
	secret := NewSecret()
	_ = f2.store.SaveToken(t.Context(), Token{ID: TokenID(secret), System: Slack, ChatUser: "U1", Team: "T1", Expires: time.Now().Add(TokenLife)})
	f2.send(t, f2.bf.token(t, f2.claims()), private(f2.activity("message", map[string]any{"text": "link " + secret})))
	if reply := <-f2.posted; !strings.Contains(reply["text"].(string), "not right") {
		t.Fatalf("slack token as code = %v", reply)
	}
}

func TestBotVerifierRereadsKeysOnce(t *testing.T) {
	bf := newBotFramework(t)
	var reads int
	inner := bf.ts.Config.Handler
	bf.ts.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/keys") {
			reads++
		}
		inner.ServeHTTP(w, r)
	})
	v := &BotVerifier{Metadata: bf.ts.URL + "/v1/.well-known/openidconfiguration"}
	claims := map[string]any{"iss": botIssuer, "aud": testAppID, "exp": time.Now().Add(time.Hour).Unix(), "serviceurl": "https://smba.trafficmanager.net/amer/"}
	if err := v.Verify(t.Context(), "Bearer "+bf.token(t, claims), testAppID, "https://smba.trafficmanager.net/amer"); err != nil {
		t.Fatal(err)
	}
	// A token from a key the set does not hold reads the keys again, but
	// not on every request.
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	bf2 := &botFramework{key: other}
	forged := bf2.token(t, claims)
	forged = strings.Replace(forged, base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","kid":"k1","typ":"JWT"}`)),
		base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","kid":"k2","typ":"JWT"}`)), 1)
	for range 3 {
		if err := v.Verify(t.Context(), "Bearer "+forged, testAppID, "https://smba.trafficmanager.net/amer"); err == nil {
			t.Fatal("forged token accepted")
		}
	}
	if reads != 2 {
		t.Errorf("keys read %d times, want 2", reads)
	}
}

func TestBotVerifierNeedsTeamsKeys(t *testing.T) {
	claims := map[string]any{"iss": botIssuer, "aud": testAppID, "exp": time.Now().Add(time.Hour).Unix(), "serviceurl": "https://smba.trafficmanager.net/amer/"}
	for name, endorse := range map[string][]string{"no endorsements": {}, "another channel": {"skype"}} {
		bf := newBotFramework(t)
		bf.endorse = endorse
		v := &BotVerifier{Metadata: bf.ts.URL + "/v1/.well-known/openidconfiguration"}
		if err := v.Verify(t.Context(), "Bearer "+bf.token(t, claims), testAppID, "https://smba.trafficmanager.net/amer"); err == nil {
			t.Errorf("%s: a key not endorsed for Teams was accepted", name)
		}
	}
}

func TestTokenUsedOnce(t *testing.T) {
	m := NewMemory()
	now := time.Now()
	_ = m.SaveToken(t.Context(), Token{ID: "a", System: Slack, ChatUser: "U", Expires: now.Add(time.Minute)})
	if _, err := m.TakeToken(t.Context(), "a", now); err != nil {
		t.Fatal(err)
	}
	if _, err := m.TakeToken(t.Context(), "a", now); !errors.Is(err, ErrTokenUsed) {
		t.Errorf("second take = %v", err)
	}
	_ = m.SaveToken(t.Context(), Token{ID: "b", System: Slack, ChatUser: "U", Expires: now.Add(-time.Second)})
	if _, err := m.PeekToken(t.Context(), "b", now); !errors.Is(err, ErrTokenUsed) {
		t.Errorf("expired = %v", err)
	}
	if _, err := m.PeekToken(t.Context(), "c", now); !errors.Is(err, ErrNotFound) {
		t.Errorf("missing = %v", err)
	}
	if err := m.Purge(t.Context(), now); err != nil || len(m.tokens) != 0 {
		t.Errorf("purge left %v", m.tokens)
	}
}

func TestCodes(t *testing.T) {
	seen := map[string]bool{}
	for range 100 {
		c := NewCode()
		if len(c) != 11 || c[5] != '-' || strings.ContainsAny(c, "01ILO") || seen[c] {
			t.Fatalf("code %q", c)
		}
		seen[c] = true
		if TokenID(c) != TokenID(" "+strings.ToLower(strings.ReplaceAll(c, "-", ""))+" ") {
			t.Fatalf("typed code %q does not match", c)
		}
	}
	if mentionText("<at>Signalith</at>  link  ab-cd ") != "link ab-cd" {
		t.Error("mentionText")
	}
}

func TestTeamsAppPackage(t *testing.T) {
	zip, err := TeamsAppPackage(notify.Channel{ID: "t", Name: "SOC", Type: notify.TypeTeamsApp, AppID: testAppID}, "https://siem.example.com:9000")
	if err != nil || len(zip) < 200 || string(zip[:2]) != "PK" {
		t.Fatalf("package = %d bytes, %v", len(zip), err)
	}
}

// toFake is a transport that sends every request to the fake server at
// target, whatever host it names, as a real service's address would be
// reached in production.
type toFake struct{ target string }

func (f toFake) RoundTrip(r *http.Request) (*http.Response, error) {
	u, err := url.Parse(f.target)
	if err != nil {
		return nil, err
	}
	r = r.Clone(r.Context())
	r.URL.Scheme, r.URL.Host, r.Host = u.Scheme, u.Host, u.Host
	return http.DefaultTransport.RoundTrip(r)
}
