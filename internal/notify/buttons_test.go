// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package notify

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestButtonsAreSignedForTheirChannel(t *testing.T) {
	c := Channel{ID: "soc", Type: TypeSlack, SigningSecret: "secret-one", ApproveInChat: true}
	b := Button{Action: ButtonApprove, ID: "run1", Step: 2}
	v := SignButton(c, b)
	if got, err := ParseButton(c, v); err != nil || got != b {
		t.Fatalf("parse = %+v %v", got, err)
	}
	other := c
	other.ID = "other"
	rotated := c
	rotated.SigningSecret = "secret-two"
	for name, tc := range map[string]struct {
		c Channel
		v string
	}{
		"other channel":  {other, v},
		"secret changed": {rotated, v},
		"other run":      {c, strings.Replace(v, "run1", "run2", 1)},
		"other step":     {c, strings.Replace(v, "|2|", "|3|", 1)},
		"other action":   {c, strings.Replace(v, "approve", "reject", 1)},
		"no secret":      {Channel{ID: "soc", Type: TypeSlack}, v},
		"garbage":        {c, "v1|approve|run1"},
		"unknown action": {c, SignButton(c, Button{Action: "delete", ID: "x"})},
	} {
		if _, err := ParseButton(tc.c, tc.v); !errors.Is(err, ErrBadButton) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestMessageButtons(t *testing.T) {
	slack := Channel{ID: "soc", Name: "#soc", Type: TypeSlack, SigningSecret: "s", ApproveInChat: true}
	approval := Message{Kind: KindApproval, Title: "Brute force", FindingID: "f1", RunID: "r1", Step: 1, Ask: "Block it?", Link: "https://x/#approvals"}
	finding := Message{Kind: KindFinding, Title: "Brute force", FindingID: "f1"}
	labels := func(c Channel, m Message) []string {
		var out []string
		for _, b := range m.buttons(c) {
			out = append(out, b.Action)
		}
		return out
	}
	if got := labels(slack, approval); strings.Join(got, ",") != "approve,reject" {
		t.Errorf("approval = %v", got)
	}
	if got := labels(slack, finding); strings.Join(got, ",") != "ack" {
		t.Errorf("finding = %v", got)
	}
	noApprove := slack
	noApprove.ApproveInChat = false
	if got := labels(noApprove, approval); strings.Join(got, ",") != "reject" {
		t.Errorf("approve off = %v", got)
	}
	plain := slack
	plain.SigningSecret = ""
	if got := labels(plain, approval); got != nil {
		t.Errorf("not interactive = %v", got)
	}

	// Slack: the buttons carry signed values; Approve asks to confirm.
	body := slack.clone()
	raw, _ := json.Marshal(approval.slackBody(body))
	var msg struct {
		Blocks []struct {
			Type     string `json:"type"`
			Elements []struct {
				ActionID string         `json:"action_id"`
				Value    string         `json:"value"`
				URL      string         `json:"url"`
				Confirm  map[string]any `json:"confirm"`
			} `json:"elements"`
		} `json:"blocks"`
	}
	_ = json.Unmarshal(raw, &msg)
	last := msg.Blocks[len(msg.Blocks)-1]
	if last.Type != "actions" || len(last.Elements) != 3 || last.Elements[0].ActionID != "signalith_approve" || last.Elements[0].Confirm == nil ||
		last.Elements[2].URL != "https://x/#approvals" {
		t.Fatalf("slack actions = %s", raw)
	}
	if b, err := ParseButton(slack, last.Elements[1].Value); err != nil || b.Action != ButtonReject || b.ID != "r1" || b.Step != 1 {
		t.Errorf("reject value = %+v %v", b, err)
	}

	// A Teams workflow card has no buttons, only the link.
	card := approval.teamsCard(Channel{ID: "t", Type: TypeTeams})
	if acts := card["actions"].([]any); len(acts) != 1 {
		t.Errorf("teams workflow actions = %v", acts)
	}
}

// fakeTeams is Microsoft Entra's token endpoint and a Bot Connector.
type fakeTeams struct {
	ts       *httptest.Server
	tokens   atomic.Int32
	posts    atomic.Int32
	reject   atomic.Int32 // posts to answer 401 first
	lastBody atomic.Value
	login    func(w http.ResponseWriter, r *http.Request)
}

func newFakeTeams(t *testing.T) *fakeTeams {
	f := &fakeTeams{}
	f.ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/oauth2/v2.0/token"):
			if f.login != nil {
				f.login(w, r)
				return
			}
			_ = r.ParseForm()
			if r.Form.Get("client_secret") != "client-secret" || r.Form.Get("scope") != botScope || r.Form.Get("grant_type") != "client_credentials" {
				w.WriteHeader(401)
				_, _ = io.WriteString(w, `{"error":"invalid_client","error_description":"AADSTS7000215: Invalid client secret provided.\r\nTrace ID: x"}`)
				return
			}
			f.tokens.Add(1)
			_, _ = io.WriteString(w, `{"access_token":"tok","expires_in":3600}`)
		default:
			if f.reject.Load() > 0 {
				f.reject.Add(-1)
				w.WriteHeader(401)
				return
			}
			if r.Header.Get("Authorization") != "Bearer tok" {
				w.WriteHeader(403)
				return
			}
			b, _ := io.ReadAll(r.Body)
			f.lastBody.Store(string(b))
			f.posts.Add(1)
			_, _ = io.WriteString(w, `{"id":"1"}`)
		}
	}))
	t.Cleanup(f.ts.Close)
	return f
}

type oneConversation struct{ c *Conversation }

func (o oneConversation) Conversation(_ context.Context, channel string) (Conversation, bool, error) {
	if o.c == nil {
		return Conversation{}, false, nil
	}
	return *o.c, true, nil
}

func TestTeamsAppSend(t *testing.T) {
	f := newFakeTeams(t)
	conv := &Conversation{Channel: "t", ConversationID: "19:a@thread.tacv2", ServiceURL: "https://smba.trafficmanager.net/amer/", TenantID: "x"}
	s := &Senders{TeamsLogin: f.ts.URL, Conversations: oneConversation{conv},
		Transport: toFake{f.ts.URL}}
	c := Channel{ID: "t", Name: "SOC", Type: TypeTeamsApp, AppID: "11111111-2222-3333-4444-555555555555",
		TenantID: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", AppPassword: "client-secret", AllowLoopback: true, ApproveInChat: true}
	m := Message{Kind: KindFinding, Title: "Brute force", FindingID: "f1", Created: time.Now()}
	for range 2 {
		if err := s.Send(t.Context(), c, m); err != nil {
			t.Fatal(err)
		}
	}
	if f.tokens.Load() != 1 || f.posts.Load() != 2 {
		t.Errorf("tokens %d posts %d", f.tokens.Load(), f.posts.Load())
	}
	if body := f.lastBody.Load().(string); !strings.Contains(body, `"signalith.ack"`) {
		t.Errorf("no Acknowledge button: %s", body)
	}
	// A token Teams no longer takes is renewed once.
	f.reject.Store(1)
	if err := s.Send(t.Context(), c, m); err != nil || f.tokens.Load() != 2 {
		t.Errorf("after 401: %v, tokens %d", err, f.tokens.Load())
	}

	// A wrong secret says so, without the secret.
	bad := c
	bad.AppPassword = "wrong-secret-value"
	err := s.Send(t.Context(), bad, m)
	var se *SendError
	if !errors.As(err, &se) || se.Retry || !strings.Contains(se.Msg, "Invalid client secret provided") || strings.Contains(se.Msg, "wrong-secret-value") || strings.Contains(se.Msg, "Trace ID") {
		t.Errorf("bad secret = %v", err)
	}

	// Not added anywhere yet.
	s2 := &Senders{TeamsLogin: f.ts.URL, Conversations: oneConversation{}}
	if err := s2.Send(t.Context(), c, m); err == nil || !strings.Contains(err.Error(), "not in a Teams channel yet") {
		t.Errorf("no conversation = %v", err)
	}

	// A Bot Connector address that is not Microsoft's gets no token.
	foreign := *conv
	foreign.ServiceURL = f.ts.URL + "/amer/"
	s3 := &Senders{TeamsLogin: f.ts.URL, Conversations: oneConversation{&foreign}}
	before := f.tokens.Load()
	if err := s3.Send(t.Context(), c, m); err == nil || !strings.Contains(err.Error(), "not Microsoft's") || f.tokens.Load() != before {
		t.Errorf("foreign service URL = %v", err)
	}
}

func TestServiceURLAllowed(t *testing.T) {
	for raw, ok := range map[string]bool{
		"https://smba.trafficmanager.net/amer/":            true,
		"https://smba.infra.gcc.teams.microsoft.com/teams": true,
		"https://evil.trafficmanager.net/amer/":            false,
		"http://smba.trafficmanager.net/amer/":             false,
		"https://smba.trafficmanager.net:8443/":            false,
		"https://teams.microsoft.com.evil.example/":        false,
		"https://x@smba.trafficmanager.net/":               false,
		"https://smba.trafficmanager.net:443/amer/":        true,
		"https://smba.trafficmanager.net/amer/?x=1":        false,
		"https://smba.trafficmanager.net/a/../b":           false,
		"https://smba.trafficmanager.net/amer/#f":          false,
		"https://bot.botframework.com.evil.example/":       false,
	} {
		u, _ := url.Parse(raw)
		if ServiceURLAllowed(u) != ok {
			t.Errorf("%s = %v", raw, !ok)
		}
	}
}

func TestChannelInputTeamsAppAndSlackApp(t *testing.T) {
	m := &Manager{}
	in := Input{Channels: []ChannelInput{
		{ID: "slack", Name: "#soc", Type: TypeSlack, URL: "https://hooks.slack.com/services/T/B/x", SigningSecret: "abc123", ApproveInChat: true},
		{ID: "teams", Name: "SOC", Type: TypeTeamsApp, AppID: "11111111-2222-3333-4444-555555555555", TenantID: "AAAAAAAA-bbbb-cccc-dddd-eeeeeeeeeeee", AppPassword: "pw", ApproveInChat: true},
	}}
	s, err := m.Save(in)
	if err != nil {
		t.Fatal(err)
	}
	sl, _ := s.Channel("slack")
	tm, _ := s.Channel("teams")
	if !sl.Interactive() || !sl.ApproveInChat || !tm.Interactive() || tm.TenantID != "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee" {
		t.Fatalf("saved %+v %+v", sl, tm)
	}
	// Secrets left empty are kept; a new tenant needs the secret again.
	in.Channels[0].SigningSecret, in.Channels[1].AppPassword = "", ""
	if s, err = m.Save(in); err != nil {
		t.Fatal(err)
	}
	if sl, _ = s.Channel("slack"); sl.SigningSecret != "abc123" {
		t.Errorf("signing secret not kept")
	}
	in.Channels[1].TenantID = "bbbbbbbb-bbbb-cccc-dddd-eeeeeeeeeeee"
	var ie *InputError
	if _, err := m.Save(in); !errors.As(err, &ie) || !strings.Contains(err.Error(), "client secret again") {
		t.Errorf("moved tenant = %v", err)
	}
	// Without a signing secret, a Slack channel cannot approve.
	in.Channels[1].TenantID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	in.Channels[0].ClearSigningSecret = true
	if s, err = m.Save(in); err != nil {
		t.Fatal(err)
	}
	if sl, _ = s.Channel("slack"); sl.Interactive() || sl.ApproveInChat {
		t.Errorf("cleared = %+v", sl)
	}
	for name, ci := range map[string]ChannelInput{
		"app id":    {Name: "x", Type: TypeTeamsApp, AppID: "nope", TenantID: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", AppPassword: "pw"},
		"tenant":    {Name: "x", Type: TypeTeamsApp, AppID: "11111111-2222-3333-4444-555555555555", AppPassword: "pw"},
		"no secret": {Name: "x", Type: TypeTeamsApp, AppID: "11111111-2222-3333-4444-555555555555", TenantID: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"},
	} {
		if _, err := (&Manager{}).Save(Input{Channels: []ChannelInput{ci}}); !errors.As(err, &ie) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func FuzzParseButton(f *testing.F) {
	c := Channel{ID: "soc", Type: TypeSlack, SigningSecret: "s"}
	f.Add(SignButton(c, Button{Action: ButtonAck, ID: "f1"}))
	f.Add("v1|approve|r|1|00")
	f.Add("")
	f.Fuzz(func(t *testing.T, v string) {
		b, err := ParseButton(c, v)
		if err == nil && SignButton(c, b) != v {
			t.Fatalf("accepted %q, which signs as %q", v, SignButton(c, b))
		}
	})
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
