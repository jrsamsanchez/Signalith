package api

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/chatops"
	"github.com/jrsamsanchez/signalith/internal/notify"
)

func chatPost(t *testing.T, url, path, body string) int {
	t.Helper()
	req, _ := http.NewRequest("POST", url+path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := noRedirect.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

// Without chat buttons every chat route says so.
func TestChatOff(t *testing.T) {
	ts, _ := newTestServer(t)
	for _, path := range []string{"/api/chat/slack/soc", "/api/chat/teams/soc"} {
		if code := chatPost(t, ts.URL, path, "{}"); code != http.StatusServiceUnavailable {
			t.Errorf("%s: %d", path, code)
		}
	}
	for _, rt := range []struct{ method, path string }{
		{"GET", "/api/chat/accounts"}, {"GET", "/api/chat/links"}, {"DELETE", "/api/chat/links/x"},
		{"POST", "/api/notify/channels/x/teams-move"},
	} {
		if code, out := do(t, ts, rt.method, rt.path, "{}", true); code != http.StatusServiceUnavailable || out["error"] != errChatOff.Error() {
			t.Errorf("%s %s: %d %v", rt.method, rt.path, code, out)
		}
	}
}

// The service is made from the server's own parts when none is given:
// clicks and Teams messages that are not signed are refused.
func TestChatServiceFromServer(t *testing.T) {
	store := chatops.NewMemory()
	ts, _ := newTestServerWith(t, func(s *Server) {
		notes := &notify.Manager{}
		if _, err := notes.Save(notify.Input{Channels: []notify.ChannelInput{
			{ID: "soc", Name: "#soc", Type: "slack", URL: "https://hooks.slack.com/services/T/B/x", SigningSecret: "slack-secret", ApproveInChat: true},
		}}); err != nil {
			t.Fatal(err)
		}
		s.Notify = &Notify{Settings: notes, Sender: &notify.Senders{}}
		s.Chat = &Chat{Store: store}
	})
	if code := chatPost(t, ts.URL, "/api/chat/slack/soc", "payload=x"); code != http.StatusUnauthorized {
		t.Errorf("unsigned Slack click: %d", code)
	}
	if code := chatPost(t, ts.URL, "/api/chat/teams/soc", `{"type":"message"}`); code < 400 {
		t.Errorf("unsigned Teams message: %d", code)
	}
}

// An admin removes any link; one that is not there is a 404.
func TestChatLinkDelete(t *testing.T) {
	ts, _, store, _, _ := chatServer(t)
	tok := `{"token":"` + strings.Repeat("ab", 32) + `"}`
	if code, out := doAs(t, ts, "andy", "role-password", "POST", "/api/chat/link", tok); code != http.StatusOK {
		t.Fatalf("link: %d %v", code, out)
	}
	links := store.LinksOf()
	if len(links) != 1 {
		t.Fatalf("links %v", links)
	}
	if code, _ := do(t, ts, "DELETE", "/api/chat/links/nope", "", true); code != http.StatusNotFound {
		t.Errorf("unknown link: %d", code)
	}
	if code, out := do(t, ts, "DELETE", "/api/chat/links/"+links[0].ID, "", true); code != http.StatusOK || out["removed"] != links[0].ID {
		t.Errorf("remove: %d %v", code, out)
	}
	if code, _ := do(t, ts, "GET", "/api/notify/channels/nope/teams-app", "", true); code != http.StatusNotFound {
		t.Errorf("teams app of no channel: %d", code)
	}
}

// What a click changes needs the stores it changes.
func TestChatDeskWithoutStores(t *testing.T) {
	d := chatDesk{&Server{}}
	ctx := context.Background()
	if _, err := d.Decide(ctx, "run", 1, "andy", "", true); !errors.Is(err, errPlaybooksOff) {
		t.Errorf("Decide: %v", err)
	}
	if _, err := d.Acknowledge(ctx, "f1", "andy", ""); !errors.Is(err, errDetectionsOff) {
		t.Errorf("Acknowledge: %v", err)
	}
}
