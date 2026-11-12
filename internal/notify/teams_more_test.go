// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package notify

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestSmallTextHelpers(t *testing.T) {
	for in, want := range map[string]string{"https://siem.example.com/ ": "https://siem.example.com/#audit", "": "", "  ": ""} {
		if got := AuditLink(in); got != want {
			t.Errorf("AuditLink(%q) = %q", in, got)
		}
	}
	if (&Dispatcher{}).auditLink() != "" {
		t.Error("audit link without a public URL")
	}
	if got := (&Dispatcher{PublicURL: func() string { return "https://s/" }}).auditLink(); got != "https://s/#audit" {
		t.Errorf("auditLink %q", got)
	}
	for in, want := range map[string]string{"": "", ".": "", "The receiver failed.": "the receiver failed"} {
		if got := sentenceCase(in); got != want {
			t.Errorf("sentenceCase(%q) = %q", in, got)
		}
	}
}

func TestConversationPlace(t *testing.T) {
	for _, c := range []struct {
		conv Conversation
		want string
	}{
		{Conversation{TeamName: "SOC", ChannelName: "Alerts"}, "SOC > Alerts"},
		{Conversation{TeamName: "SOC"}, "SOC"},
		{Conversation{ChannelName: "Alerts"}, "Alerts"},
		{Conversation{}, "a Teams conversation"},
	} {
		if got := c.conv.Place(); got != c.want {
			t.Errorf("Place(%+v) = %q", c.conv, got)
		}
	}
}

type failingConversations struct{}

func (failingConversations) Conversation(context.Context, string) (Conversation, bool, error) {
	return Conversation{}, false, errors.New("runtime index unavailable")
}

func teamsChannel() Channel {
	return Channel{ID: "t", Name: "SOC", Type: TypeTeamsApp, AppID: "11111111-2222-3333-4444-555555555555",
		TenantID: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", AppPassword: "client-secret", AllowLoopback: true}
}

func TestTeamsAppSendProblems(t *testing.T) {
	f := newFakeTeams(t)
	c := teamsChannel()
	m := Message{Kind: KindFinding, Title: "Brute force", FindingID: "f1", Created: time.Now()}
	conv := Conversation{Channel: "t", ConversationID: "19:a@thread.tacv2", ServiceURL: "https://smba.trafficmanager.net/amer/", TenantID: "x"}

	// No conversations on this server, or none readable.
	if err := (&Senders{}).Send(t.Context(), c, m); err == nil || !strings.Contains(err.Error(), "not available on this server") {
		t.Errorf("no conversations: %v", err)
	}
	if err := (&Senders{Conversations: failingConversations{}}).Send(t.Context(), c, m); err == nil || !strings.Contains(err.Error(), "could not read where the Teams app posts") {
		t.Errorf("unreadable conversations: %v", err)
	}
	// A conversation ID Signalith will not put in a path.
	odd := conv
	odd.ConversationID = "19:a/../b"
	s := &Senders{TeamsLogin: f.ts.URL, Conversations: oneConversation{&odd}, Transport: toFake{f.ts.URL}}
	if err := s.Send(t.Context(), c, m); err == nil || !strings.Contains(err.Error(), "cannot post to") {
		t.Errorf("odd conversation: %v", err)
	}
	if _, err := s.TeamsPost(t.Context(), c, conv, "bad/reply", map[string]any{}); err == nil || !strings.Contains(err.Error(), "cannot post to") {
		t.Errorf("odd reply id: %v", err)
	}
	// An activity that cannot be encoded.
	if _, err := s.TeamsPost(t.Context(), c, conv, "", map[string]any{"x": make(chan int)}); err == nil {
		t.Error("an unencodable activity was sent")
	}

	// A reply goes under its activity.
	s = &Senders{TeamsLogin: f.ts.URL, Transport: toFake{f.ts.URL}}
	if id, err := s.TeamsPost(t.Context(), c, conv, "1234", map[string]any{"type": "message"}); err != nil || id != "1" {
		t.Errorf("reply: %q %v", id, err)
	}

	// Teams refusing twice is an answer error, not a loop.
	f.reject.Store(2)
	_, err := s.TeamsPost(t.Context(), c, conv, "", map[string]any{"type": "message"})
	var se *SendError
	if !errors.As(err, &se) || !strings.Contains(se.Msg, "401") {
		t.Errorf("rejected twice: %v", err)
	}
	f.reject.Store(0)
}

func TestTeamsLoginProblems(t *testing.T) {
	f := newFakeTeams(t)
	conv := Conversation{Channel: "t", ConversationID: "19:a@thread.tacv2", ServiceURL: "https://smba.trafficmanager.net/amer/", TenantID: "x"}
	c := teamsChannel()
	// Entra busy: tried again later.
	f.login = func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		io.WriteString(w, "busy")
	}
	s := &Senders{TeamsLogin: f.ts.URL, Transport: toFake{f.ts.URL}}
	_, err := s.TeamsPost(t.Context(), c, conv, "", map[string]any{"type": "message"})
	var se *SendError
	if !errors.As(err, &se) || !se.Retry || !strings.Contains(se.Msg, "503") {
		t.Errorf("entra busy: %v %+v", err, se)
	}
	// A token with a silly lifetime is kept for an hour, and used.
	f.login = func(w http.ResponseWriter, r *http.Request) {
		f.tokens.Add(1)
		io.WriteString(w, `{"access_token":"tok","expires_in":0}`)
	}
	if _, err := s.TeamsPost(t.Context(), c, conv, "", map[string]any{"type": "message"}); err != nil {
		t.Fatalf("token without lifetime: %v", err)
	}
	if _, err := s.TeamsPost(t.Context(), c, conv, "", map[string]any{"type": "message"}); err != nil || f.tokens.Load() != 1 {
		t.Errorf("token not kept: %v, %d tokens", err, f.tokens.Load())
	}
	// A login address that is protected, or does not parse.
	c2 := c
	c2.ID, c2.AllowLoopback = "t2", false
	s2 := &Senders{TeamsLogin: f.ts.URL}
	if _, err := s2.botToken(t.Context(), c2); err == nil {
		t.Error("a loopback login address was used")
	}
	s3 := &Senders{TeamsLogin: "http://[::1"}
	if _, err := s3.botToken(t.Context(), c2); err == nil {
		t.Error("a bad login address was used")
	}
	// A bad certificate authority in the channel.
	c4 := c
	c4.ID, c4.CAPEM = "t4", "not pem"
	s4 := &Senders{TeamsLogin: f.ts.URL}
	if _, err := s4.botToken(t.Context(), c4); err == nil {
		t.Error("a bad CA was used")
	}
}
