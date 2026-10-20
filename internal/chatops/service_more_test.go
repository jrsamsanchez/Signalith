// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package chatops

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
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
)

// failStore is a Memory whose calls fail when a test sets their error.
type failStore struct {
	*Memory
	mu                                     sync.Mutex
	link, saveLink, saveToken, takeToken   error
	seen, purge, conversation, saveConvErr error
}

func (s *failStore) err(e *error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return *e
}

func (s *failStore) set(e *error, v error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	*e = v
}

func (s *failStore) Link(ctx context.Context, system, team, chatUser string) (Link, bool, error) {
	if err := s.err(&s.link); err != nil {
		return Link{}, false, err
	}
	return s.Memory.Link(ctx, system, team, chatUser)
}

func (s *failStore) SaveLink(ctx context.Context, l Link) error {
	if err := s.err(&s.saveLink); err != nil {
		return err
	}
	return s.Memory.SaveLink(ctx, l)
}

func (s *failStore) SaveToken(ctx context.Context, t Token) error {
	if err := s.err(&s.saveToken); err != nil {
		return err
	}
	return s.Memory.SaveToken(ctx, t)
}

func (s *failStore) TakeToken(ctx context.Context, id string, now time.Time) (Token, error) {
	if err := s.err(&s.takeToken); err != nil {
		return Token{}, err
	}
	return s.Memory.TakeToken(ctx, id, now)
}

func (s *failStore) Seen(ctx context.Context, system, id string, now time.Time) (bool, error) {
	if err := s.err(&s.seen); err != nil {
		return false, err
	}
	return s.Memory.Seen(ctx, system, id, now)
}

func (s *failStore) Purge(ctx context.Context, now time.Time) error {
	if err := s.err(&s.purge); err != nil {
		return err
	}
	return s.Memory.Purge(ctx, now)
}

func (s *failStore) Conversation(ctx context.Context, ch string) (notify.Conversation, bool, error) {
	if err := s.err(&s.conversation); err != nil {
		return notify.Conversation{}, false, err
	}
	return s.Memory.Conversation(ctx, ch)
}

func (s *failStore) SaveConversation(ctx context.Context, c notify.Conversation) error {
	if err := s.err(&s.saveConvErr); err != nil {
		return err
	}
	return s.Memory.SaveConversation(ctx, c)
}

// logBuf collects log lines safely across goroutines.
type logBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *logBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *logBuf) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

func useFailStore(f *slackFixture) *failStore {
	fs := &failStore{Memory: f.store}
	f.svc.Store = fs
	return fs
}

// post sends a signed Slack request with the given form body.
func (f *slackFixture) post(t *testing.T, body string, header func(h http.Header, body []byte)) int {
	t.Helper()
	req, _ := http.NewRequest("POST", f.ts.URL+"/api/chat/slack/soc", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	ts := strconv.FormatInt(f.now.Unix(), 10)
	req.Header.Set("X-Slack-Request-Timestamp", ts)
	req.Header.Set("X-Slack-Signature", SlackSign(f.channel.SigningSecret, ts, []byte(body)))
	if header != nil {
		header(req.Header, []byte(body))
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	f.svc.Wait()
	return resp.StatusCode
}

func payloadBody(p map[string]any) string {
	raw, _ := json.Marshal(p)
	return url.Values{"payload": {string(raw)}}.Encode()
}

func basePayload(actionID, value string) map[string]any {
	return map[string]any{
		"type": "block_actions", "trigger_id": "", "response_url": "https://hooks.slack.com/actions/T/1/x",
		"user":    map[string]any{"id": "Uandy", "name": "andy-name", "team_id": "T1"},
		"actions": []any{map[string]any{"action_id": actionID, "value": value, "action_ts": "9.9"}},
	}
}

func TestSlackActOutcomes(t *testing.T) {
	f := newSlackFixture(t)
	_ = f.store.SaveLink(t.Context(), Link{ID: LinkID(Slack, "T1", "Uandy"), System: Slack, Team: "T1", ChatUser: "Uandy", Username: "andy"})
	approve := notify.SignButton(f.channel, notify.Button{Action: notify.ButtonApprove, ID: "run1", Step: 1})
	ack := notify.SignButton(f.channel, notify.Button{Action: notify.ButtonAck, ID: "f1"})
	text := func(m map[string]any) string {
		if m["replace_original"] == true && m["blocks"] != nil {
			b := m["blocks"].([]any)
			return b[len(b)-1].(map[string]any)["elements"].([]any)[0].(map[string]any)["text"].(string)
		}
		s, _ := m["text"].(string)
		return s
	}
	for i, tc := range []struct {
		err     error
		done    bool
		want    string
		approve bool
	}{
		{playbooks.ErrOtherStep, false, "Open Approvals", true},
		{playbooks.ErrNotFound, true, "no longer exists", true},
		{errors.New("disk full"), false, "could not record that", true},
	} {
		f.desk.mu.Lock()
		f.desk.err = tc.err
		f.desk.mu.Unlock()
		f.click(t, "andy", fmt.Sprint("o", i), "signalith_approve", approve, nil)
		m := f.next(t)
		if (m["replace_original"] == true) != tc.done || !strings.Contains(text(m), tc.want) {
			t.Errorf("%v: answer = %v", tc.err, m)
		}
	}
	f.desk.err = nil

	f.desk.owner = "bea"
	f.click(t, "andy", "a1", "signalith_ack", ack, nil)
	if m := f.next(t); !strings.Contains(text(m), "bea already owns this finding") {
		t.Errorf("ack owned = %v", m)
	}
	f.desk.ackErr = errors.New("down")
	f.click(t, "andy", "a2", "signalith_ack", ack, nil)
	if m := f.next(t); m["response_type"] != "ephemeral" || !strings.Contains(text(m), "could not acknowledge") {
		t.Errorf("ack error = %v", m)
	}

	// An action Signalith does not know is refused (ParseButton never
	// gives one, but act must not act on it).
	o := f.svc.act(t.Context(), f.channel, ChatUser{System: Slack, Team: "T1", ID: "Uandy", Name: "andy"}, notify.Button{Action: "zap", ID: "x"})
	if o.done || o.private != "Signalith does not know this button." {
		t.Errorf("unknown action = %+v", o)
	}
}

func TestSlackRequestShapes(t *testing.T) {
	f := newSlackFixture(t)
	_ = f.store.SaveLink(t.Context(), Link{ID: LinkID(Slack, "T1", "Uandy"), System: Slack, Team: "T1", ChatUser: "Uandy", Username: "andy"})
	ack := notify.SignButton(f.channel, notify.Button{Action: notify.ButtonAck, ID: "f1"})

	if code := f.post(t, "other=1", nil); code != 400 {
		t.Errorf("no payload = %d", code)
	}
	if code := f.post(t, "payload=%7B", nil); code != 400 {
		t.Errorf("payload not JSON = %d", code)
	}
	p := basePayload("signalith_ack", ack)
	p["type"] = "view_submission"
	if code := f.post(t, payloadBody(p), nil); code != 200 {
		t.Errorf("other type = %d", code)
	}
	for _, id := range []string{"signalith_open", "someone_else"} {
		if code := f.post(t, payloadBody(basePayload(id, ack)), nil); code != 200 {
			t.Errorf("%s = %d", id, code)
		}
	}
	f.none(t)
	p = basePayload("signalith_ack", ack)
	p["user"] = map[string]any{"name": "x"}
	if code := f.post(t, payloadBody(p), nil); code != 400 {
		t.Errorf("no user = %d", code)
	}
	p = basePayload("signalith_ack", ack)
	p["response_url"] = "https://evil.example/actions/x"
	if code := f.post(t, payloadBody(p), nil); code != 400 {
		t.Errorf("response_url elsewhere = %d", code)
	}

	// Signatures: none, a timestamp that is not a number, and one far in
	// the future.
	body := payloadBody(basePayload("signalith_ack", ack))
	if code := f.post(t, body, func(h http.Header, _ []byte) { h.Del("X-Slack-Signature") }); code != 401 {
		t.Errorf("unsigned = %d", code)
	}
	if code := f.post(t, body, func(h http.Header, b []byte) {
		h.Set("X-Slack-Request-Timestamp", "soon")
		h.Set("X-Slack-Signature", SlackSign(f.channel.SigningSecret, "soon", b))
	}); code != 401 {
		t.Errorf("bad timestamp = %d", code)
	}
	if code := f.post(t, body, func(h http.Header, b []byte) {
		ts := strconv.FormatInt(f.now.Add(time.Hour).Unix(), 10)
		h.Set("X-Slack-Request-Timestamp", ts)
		h.Set("X-Slack-Signature", SlackSign(f.channel.SigningSecret, ts, b))
	}); code != 401 {
		t.Errorf("future timestamp = %d", code)
	}
	if err := VerifySlack("s", http.Header{"X-Slack-Request-Timestamp": {strconv.FormatInt(f.now.Add(-time.Hour).Unix(), 10)}, "X-Slack-Signature": {"v0=1"}}, nil, f.now); !errors.Is(err, errSlackOld) {
		t.Errorf("old = %v", err)
	}

	// The team comes from the user when the payload has no team, and the
	// click ID from the action time when it has no trigger. With no
	// message to replace, the answer is the outcome's text.
	if code := f.post(t, body, nil); code != 200 {
		t.Fatalf("click = %d", code)
	}
	m := f.next(t)
	if m["replace_original"] != true || !strings.Contains(m["text"].(string), "Acknowledged by Andy Analyst (andy) in Slack") || m["blocks"] != nil {
		t.Errorf("answer = %v", m)
	}
	if f.desk.acked[0] != "f1/andy/Acknowledged in Slack as andy-name." {
		t.Errorf("acked = %v", f.desk.acked)
	}
	// The same action time again is the same click.
	f.post(t, body, nil)
	f.none(t)

	// Too large a body.
	if code := f.post(t, "payload="+strings.Repeat("a", maxSlackBody+1), nil); code != http.StatusRequestEntityTooLarge {
		t.Errorf("too large = %d", code)
	}
}

func TestSlackStoreFailures(t *testing.T) {
	f := newSlackFixture(t)
	logs := &logBuf{}
	f.svc.Log = slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	fs := useFailStore(f)
	ack := notify.SignButton(f.channel, notify.Button{Action: notify.ButtonAck, ID: "f1"})
	boom := errors.New("opensearch down")

	// The first request purges old tokens; a failure is only logged.
	fs.set(&fs.purge, boom)
	fs.set(&fs.conversation, boom)
	if code := f.click(t, "andy", "s1", "signalith_ack", ack, nil); code != 503 {
		t.Errorf("workspace check error = %d", code)
	}
	if !strings.Contains(logs.String(), "could not delete old chat tokens") {
		t.Errorf("purge failure not logged: %s", logs)
	}
	fs.set(&fs.conversation, nil)
	fs.set(&fs.saveConvErr, boom)
	if code := f.click(t, "andy", "s2", "signalith_ack", ack, nil); code != 503 {
		t.Errorf("workspace save error = %d", code)
	}
	fs.set(&fs.saveConvErr, nil)
	fs.set(&fs.seen, boom)
	if code := f.click(t, "andy", "s3", "signalith_ack", ack, nil); code != 503 {
		t.Errorf("seen error = %d", code)
	}
	fs.set(&fs.seen, nil)
	f.none(t)

	fs.set(&fs.link, boom)
	f.click(t, "andy", "s4", "signalith_ack", ack, nil)
	if m := f.next(t); !strings.Contains(m["text"].(string), "could not check who you are") {
		t.Errorf("link error = %v", m)
	}
	fs.set(&fs.link, nil)
	fs.set(&fs.saveToken, boom)
	f.click(t, "andy", "s5", "signalith_ack", ack, nil)
	if m := f.next(t); !strings.Contains(m["text"].(string), "could not make a link") {
		t.Errorf("token error = %v", m)
	}
	fs.set(&fs.saveToken, nil)

	// Without a public URL there is nowhere to send the person.
	f.svc.PublicURL = nil
	f.click(t, "andy", "s6", "signalith_ack", ack, nil)
	if m := f.next(t); !strings.Contains(m["text"].(string), "does not know its own address") {
		t.Errorf("no public URL = %v", m)
	}
	if len(f.desk.acked) != 0 {
		t.Errorf("acted despite failures: %v", f.desk.acked)
	}
}

func TestSlackAnswerFailures(t *testing.T) {
	f := newSlackFixture(t)
	logs := &logBuf{}
	f.svc.Log = slog.New(slog.NewTextHandler(logs, nil))
	ack := notify.SignButton(f.channel, notify.Button{Action: notify.ButtonAck, ID: "f1"})

	refusing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(500) }))
	defer refusing.Close()
	f.svc.HTTP = &http.Client{Transport: toFake{refusing.URL}}
	f.click(t, "andy", "r1", "signalith_ack", ack, nil)
	if !strings.Contains(logs.String(), "Slack refused the answer") {
		t.Errorf("refusal not logged: %s", logs)
	}

	f.svc.HTTP = &http.Client{Transport: errTransport{}}
	f.click(t, "andy", "r2", "signalith_ack", ack, nil)
	out := logs.String()
	if !strings.Contains(out, "could not answer a Slack button click") || strings.Contains(out, "/actions/T/1/x") {
		t.Errorf("transport failure logged as %s", out)
	}

	// The default client neither follows redirects nor waits forever.
	s := &Service{}
	c := s.httpClient()
	if c.Timeout != 10*time.Second || c.CheckRedirect(nil, nil) != http.ErrUseLastResponse {
		t.Errorf("default client = %+v", c)
	}
	if (&Service{}).log() != slog.Default() {
		t.Error("default logger")
	}
}

type errTransport struct{}

func (errTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("connection refused")
}

func TestServiceChannelAndRefusals(t *testing.T) {
	s := &Service{Log: slog.New(slog.DiscardHandler)}
	s.init()
	if _, ok := s.channel("soc", notify.TypeSlack); ok {
		t.Error("channel found with no channels")
	}
	s.Channels = func() (notify.Settings, error) { return notify.Settings{}, errors.New("bad settings") }
	if _, ok := s.channel("soc", notify.TypeSlack); ok {
		t.Error("channel found when settings fail")
	}
	if _, ok := s.channel("", notify.TypeSlack); ok {
		t.Error("empty ID found")
	}
	r := httptest.NewRequest("POST", "/", nil)
	r.RemoteAddr = "@pipe"
	if got := clientAddr(r); got != "@pipe" {
		t.Errorf("clientAddr = %q", got)
	}
	r.RemoteAddr = "[2001:db8::1]:443"
	if got := clientAddr(r); got != "2001:db8::1" {
		t.Errorf("clientAddr = %q", got)
	}
	// A flood from many addresses is forgotten rather than kept.
	for i := range 10002 {
		r.RemoteAddr = fmt.Sprintf("10.%d.%d.%d:1", i>>16&255, i>>8&255, i&255)
		s.refuse(r, Slack, "soc", errors.New("x"))
	}
	s.mu.Lock()
	n := len(s.refused)
	s.mu.Unlock()
	if n > 10000 {
		t.Errorf("refused addresses kept: %d", n)
	}
	if capital("") != "" || capital(" already done. ") != "Already done" {
		t.Error("capital")
	}
	if cutRunes("ééééé", 3) != "éé…" || cutRunes("ab", 3) != "ab" {
		t.Error("cutRunes")
	}
}

func TestTeamsMore(t *testing.T) {
	f := newTeamsFixture(t)
	fs := &failStore{Memory: f.store}
	f.svc.Store = fs
	tok := f.bf.token(t, f.claims())
	boom := errors.New("down")
	const adaID = "0000aaaa-0000-0000-0000-0000000000ad"
	_ = f.store.SaveLink(t.Context(), Link{ID: LinkID(Teams, testTenant, adaID), System: Teams, Team: testTenant, ChatUser: adaID, Username: "ada"})
	reply := func() string {
		t.Helper()
		select {
		case m := <-f.posted:
			return m["text"].(string)
		case <-time.After(5 * time.Second):
			t.Fatal("no reply")
			return ""
		}
	}

	// Requests that are not for a Teams app channel, or not JSON.
	resp, _ := http.Post(f.ts.URL+"/api/chat/teams/nope", "application/json", strings.NewReader("{}"))
	if resp.StatusCode != 404 {
		t.Errorf("unknown channel = %d", resp.StatusCode)
	}
	resp.Body.Close()
	resp, _ = http.Post(f.ts.URL+"/api/chat/teams/teams", "application/json", strings.NewReader("{"))
	if resp.StatusCode != 400 {
		t.Errorf("not JSON = %d", resp.StatusCode)
	}
	resp.Body.Close()
	resp, _ = http.Post(f.ts.URL+"/api/chat/teams/teams", "application/json", strings.NewReader(strings.Repeat(" ", maxTeamsBody+1)))
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Errorf("too large = %d", resp.StatusCode)
	}
	resp.Body.Close()

	// A Bot Connector address that is not Microsoft's, even in a signed
	// token, is refused.
	c := f.claims()
	c["serviceurl"] = "https://bots.evil.example/"
	if code, _ := f.send(t, f.bf.token(t, c), f.activity("message", map[string]any{"serviceUrl": "https://bots.evil.example/", "text": "hi"})); code != 403 {
		t.Errorf("foreign service URL = %d", code)
	}
	// Other activities are answered with nothing.
	if code, _ := f.send(t, tok, f.activity("typing", nil)); code != 200 {
		t.Errorf("typing = %d", code)
	}

	// Anything but a command gets help.
	f.send(t, tok, f.activity("message", map[string]any{"text": "<at>Signalith</at> hello"}))
	if r := reply(); !strings.Contains(r, "I post Signalith findings") {
		t.Errorf("help = %q", r)
	}
	// "post here" in a private chat is refused; in the same channel twice
	// is a no-op.
	f.send(t, tok, private(from(f.activity("message", map[string]any{"text": "post here"}), "Ada", adaID)))
	if r := reply(); !strings.Contains(r, "team channels and group chats only") {
		t.Errorf("private post here = %q", r)
	}
	fs.set(&fs.conversation, boom)
	f.send(t, tok, from(f.activity("message", map[string]any{"text": "post here"}), "Ada", adaID))
	if r := reply(); !strings.Contains(r, "could not check where it posts") {
		t.Errorf("conversation error = %q", r)
	}
	fs.set(&fs.conversation, nil)
	fs.set(&fs.saveConvErr, boom)
	f.send(t, tok, from(f.activity("message", map[string]any{"text": "post here"}), "Ada", adaID))
	if r := reply(); !strings.Contains(r, "could not save that") {
		t.Errorf("save error = %q", r)
	}
	fs.set(&fs.saveConvErr, nil)
	// With no channel name, the conversation's name is used.
	noName := f.activity("message", map[string]any{"text": "post here", "channelData": map[string]any{"tenant": map[string]any{"id": testTenant}},
		"conversation": map[string]any{"id": "19:soc@thread.tacv2", "conversationType": "groupChat", "tenantId": testTenant, "name": "Night shift"}})
	f.send(t, tok, from(noName, "Ada", adaID))
	if r := reply(); !strings.Contains(r, "from now on") {
		t.Errorf("first post here = %q", r)
	}
	if conv, _, _ := f.store.Conversation(t.Context(), "teams"); conv.ChannelName != "Night shift" {
		t.Errorf("conversation = %+v", conv)
	}
	f.send(t, tok, from(noName, "Ada", adaID))
	if r := reply(); !strings.Contains(r, "already posts") {
		t.Errorf("post here again = %q", r)
	}
	other := f.activity("message", map[string]any{"text": "post here", "conversation": map[string]any{"id": "19:other@thread.v2", "conversationType": "groupChat", "tenantId": testTenant}})
	fs.set(&fs.saveConvErr, boom)
	f.send(t, tok, from(other, "Ada", adaID))
	if r := reply(); !strings.Contains(r, "could not save that") {
		t.Errorf("move save error = %q", r)
	}
	fs.set(&fs.saveConvErr, nil)
	f.send(t, tok, from(other, "Ada", adaID))
	if r := reply(); !strings.Contains(r, "confirms the move") {
		t.Errorf("move = %q", r)
	}

	// Removing the app from the conversation it was to move to drops the
	// move, and keeps where it posts.
	removed := f.activity("installationUpdate", map[string]any{"action": "remove", "channelData": map[string]any{"tenant": map[string]any{"id": testTenant}},
		"conversation": map[string]any{"id": "19:other@thread.v2", "conversationType": "groupChat", "tenantId": testTenant}})
	if code, _ := f.send(t, tok, removed); code != 200 {
		t.Fatalf("removed = %d", code)
	}
	if conv, ok, _ := f.store.Conversation(t.Context(), "teams"); !ok || conv.ConversationID != "19:soc@thread.tacv2" || conv.Next != nil {
		t.Errorf("after removal from the next conversation = %+v %v", conv, ok)
	}

	// Linking: Teams must say who sent it, and store failures are said.
	anon := private(f.activity("message", map[string]any{"text": "link ABCDE-FGHJK"}))
	anon["from"] = map[string]any{"id": "29:x", "name": "X"}
	f.send(t, tok, anon)
	if r := reply(); !strings.Contains(r, "did not say who you are") {
		t.Errorf("anonymous link = %q", r)
	}
	fs.set(&fs.takeToken, boom)
	f.send(t, tok, private(f.activity("message", map[string]any{"text": "link ABCDE-FGHJK"})))
	if r := reply(); !strings.Contains(r, "could not check the code") {
		t.Errorf("take error = %q", r)
	}
	fs.set(&fs.takeToken, nil)
	code := NewCode()
	_ = f.store.SaveToken(t.Context(), Token{ID: TokenID(code), System: Teams, Username: "andy", Expires: time.Now().Add(TokenLife)})
	fs.set(&fs.saveLink, boom)
	f.send(t, tok, private(f.activity("message", map[string]any{"text": "link " + code})))
	if r := reply(); !strings.Contains(r, "could not save the link") {
		t.Errorf("save link error = %q", r)
	}
	fs.set(&fs.saveLink, nil)

	// Without a Teams sender nothing is answered, but the message is
	// still handled.
	f.svc.Teams = nil
	if code, _ := f.send(t, tok, f.activity("message", map[string]any{"text": "hello"})); code != 200 {
		t.Errorf("no sender = %d", code)
	}
}

func TestTeamsClickMore(t *testing.T) {
	f := newTeamsFixture(t)
	fs := &failStore{Memory: f.store}
	f.svc.Store = fs
	const andyID = "0000aaaa-0000-0000-0000-000000000001"
	_ = f.store.SaveLink(t.Context(), Link{ID: LinkID(Teams, testTenant, andyID), System: Teams, Team: testTenant, ChatUser: andyID, Username: "andy"})
	ack := notify.SignButton(f.channel, notify.Button{Action: notify.ButtonAck, ID: "f1"})
	tok := f.bf.token(t, f.claims())
	invoke := func(id string, change func(a map[string]any)) map[string]any {
		t.Helper()
		a := f.activity("invoke", map[string]any{"id": id, "name": "adaptiveCard/action",
			"value": map[string]any{"action": map[string]any{"type": "Action.Execute", "verb": notify.TeamsVerb(notify.ButtonAck), "data": map[string]any{notify.TeamsButtonField: ack}}}})
		if change != nil {
			change(a)
		}
		code, out := f.send(t, tok, a)
		if code != 200 {
			t.Fatalf("invoke = %d", code)
		}
		return out
	}

	out := invoke("c1", func(a map[string]any) { a["from"] = map[string]any{"id": "29:x"} })
	if !strings.Contains(out["value"].(string), "did not say who you are") {
		t.Errorf("anonymous click = %v", out)
	}
	fs.set(&fs.seen, errors.New("down"))
	out = invoke("c2", nil)
	if !strings.Contains(out["value"].(string), "could not record the click") {
		t.Errorf("seen error = %v", out)
	}
	fs.set(&fs.seen, nil)
	if out = invoke("c3", nil); out["type"] != "application/vnd.microsoft.card.adaptive" {
		t.Errorf("ack = %v", out)
	}
	if out = invoke("c3", nil); !strings.Contains(out["value"].(string), "already handled") {
		t.Errorf("same click again = %v", out)
	}
	if len(f.desk.acked) != 1 {
		t.Errorf("acked = %v", f.desk.acked)
	}

	// A private answer with a link carries the link in its text.
	f.channel.ApproveInChat = false
	approve := notify.SignButton(f.channel, notify.Button{Action: notify.ButtonApprove, ID: "run1", Step: 1})
	out = invoke("c4", func(a map[string]any) {
		a["value"] = map[string]any{"action": map[string]any{"type": "Action.Execute", "verb": notify.TeamsVerb(notify.ButtonApprove),
			"data": map[string]any{notify.TeamsButtonField: approve}}}
	})
	if v := out["value"].(string); !strings.Contains(v, "turned off") || !strings.Contains(v, "https://siem.example.com/#approvals") {
		t.Errorf("approve off = %v", out)
	}
}

func TestBotVerifierMore(t *testing.T) {
	bf := newBotFramework(t)
	now := time.Now()
	v := &BotVerifier{Metadata: bf.ts.URL + "/v1/.well-known/openidconfiguration", Client: bf.ts.Client(), Now: func() time.Time { return now }}
	base := func() map[string]any {
		return map[string]any{"iss": botIssuer, "aud": testAppID, "exp": now.Add(time.Hour).Unix(), "serviceurl": "https://smba.trafficmanager.net/amer/"}
	}
	verify := func(claims map[string]any) error {
		return v.Verify(t.Context(), "Bearer "+bf.token(t, claims), testAppID, "https://smba.trafficmanager.net/amer")
	}
	c := base()
	c["aud"] = []string{"other", strings.ToUpper(testAppID)}
	if err := verify(c); err != nil {
		t.Errorf("audience list = %v", err)
	}
	c["aud"] = []string{"other"}
	if err := verify(c); err == nil || !strings.Contains(err.Error(), "another bot") {
		t.Errorf("audience list without the bot = %v", err)
	}
	c["aud"] = 7
	if err := verify(c); err == nil {
		t.Error("numeric audience accepted")
	}
	c = base()
	c["nbf"] = now.Add(time.Hour).Unix()
	if err := verify(c); err == nil || !strings.Contains(err.Error(), "not valid yet") {
		t.Errorf("not yet valid = %v", err)
	}
	c = base()
	c["serviceurl"] = ""
	if err := verify(c); err == nil || !strings.Contains(err.Error(), "another Bot Connector") {
		t.Errorf("no service URL = %v", err)
	}
	if err := v.Verify(t.Context(), "Basic abc", testAppID, ""); err == nil {
		t.Error("basic auth accepted")
	}

	// Keys that cannot be read: the metadata server fails, or names keys
	// on another host. Keys read before are kept when a fresh read fails.
	broken := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/elsewhere" {
			_ = json.NewEncoder(w).Encode(map[string]any{"jwks_uri": "https://keys.evil.example/keys"})
			return
		}
		if r.URL.Path == "/keys-broken" {
			_ = json.NewEncoder(w).Encode(map[string]any{"jwks_uri": "http://" + r.Host + "/500"})
			return
		}
		w.WriteHeader(500)
	}))
	defer broken.Close()
	for _, path := range []string{"/500", "/elsewhere", "/keys-broken"} {
		bv := &BotVerifier{Metadata: broken.URL + path}
		if err := bv.Verify(t.Context(), "Bearer "+bf.token(t, base()), testAppID, "https://smba.trafficmanager.net/amer"); err == nil ||
			!strings.Contains(err.Error(), "could not read the Bot Framework's keys") {
			t.Errorf("%s: %v", path, err)
		}
	}
	if _, err := (&BotVerifier{Metadata: "http://bad host/"}).fetch(t.Context()); err == nil {
		t.Error("bad metadata address read")
	}

	// A token for a key the set lacks makes it read again; when that read
	// fails, the keys it has are kept.
	if err := verify(base()); err != nil {
		t.Fatal(err)
	}
	v.Metadata = broken.URL + "/500"
	now = now.Add(10 * time.Minute)
	ks, err := v.keySet(t.Context(), true)
	if err != nil || len(ks.Keys) != 1 {
		t.Errorf("keys after failed refresh = %v, %v", ks, err)
	}
	if (&BotVerifier{}).client().Timeout != 10*time.Second {
		t.Error("default client has no timeout")
	}
	if sameServiceURL("", "") || !sameServiceURL("https://A.example/x/", "https://a.example/x") {
		t.Error("sameServiceURL")
	}
}

func TestTeamsAppPackageLongName(t *testing.T) {
	long := strings.Repeat("Security Operations ", 10)
	data, err := TeamsAppPackage(notify.Channel{ID: "t", Name: long, Type: notify.TypeTeamsApp, AppID: testAppID}, "http://siem.local")
	if err != nil {
		t.Fatal(err)
	}
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		Name struct {
			Full string `json:"full"`
		} `json:"name"`
		Developer struct {
			Website string `json:"websiteUrl"`
		} `json:"developer"`
		ValidDomains []string `json:"validDomains"`
	}
	for _, zf := range zr.File {
		if zf.Name != "manifest.json" {
			continue
		}
		rc, err := zf.Open()
		if err != nil {
			t.Fatal(err)
		}
		err = json.NewDecoder(rc).Decode(&manifest)
		rc.Close()
		if err != nil {
			t.Fatal(err)
		}
	}
	// A name over 100 characters is cut; a plain-HTTP address is not a
	// valid domain for Teams.
	if n := len([]rune(manifest.Name.Full)); n != 100 || !strings.HasPrefix(manifest.Name.Full, "Signalith: Security") {
		t.Errorf("full name = %q (%d)", manifest.Name.Full, n)
	}
	if manifest.ValidDomains == nil || len(manifest.ValidDomains) != 0 || manifest.Developer.Website != "https://signalith.io" {
		t.Errorf("manifest = %+v", manifest)
	}
}
