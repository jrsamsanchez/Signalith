package api

import (
	"context"
	"net/http"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/notify"
	"github.com/jrsamsanchez/signalith/internal/setupguide"
)

// downGuide is a setup guide store that cannot be read or written.
type downGuide struct{}

func (downGuide) Get(context.Context, string) (setupguide.Choice, error) {
	return setupguide.Choice{}, errDown
}
func (downGuide) Put(context.Context, string, setupguide.Choice) error { return errDown }

// A guide store that cannot be reached is a 503 either way.
func TestSetupGuideStoreDown(t *testing.T) {
	ts, _ := newTestServerWith(t, func(s *Server) { s.SetupGuide = downGuide{} })
	if code, _ := do(t, ts, "GET", "/api/me/setup", "", true); code != http.StatusServiceUnavailable {
		t.Errorf("get: %d", code)
	}
	if code, _ := do(t, ts, "PUT", "/api/me/setup", `{"state":"later"}`, true); code != http.StatusServiceUnavailable {
		t.Errorf("put: %d", code)
	}
}

// The alerts step is done once a channel is set up, and the Security
// step once a report shows no risks.
func TestSetupGuideNotifyAndSecurity(t *testing.T) {
	ts, n := newNotifyServer(t, nil)
	_, body := do(t, ts, "GET", "/api/me/setup", "", true)
	if _, done := stepIDs(t, body); done["notify"] {
		t.Errorf("notify done without a channel: %v", body)
	}
	if _, err := n.Settings.Save(notify.Input{Channels: []notify.ChannelInput{
		{ID: "soc", Name: "#soc", Type: "slack", URL: "https://hooks.slack.com/services/T/B/x"},
	}}); err != nil {
		t.Fatal(err)
	}
	_, body = do(t, ts, "GET", "/api/me/setup", "", true)
	if ids, done := stepIDs(t, body); !done["notify"] {
		t.Errorf("notify not done with a channel: %v %v", ids, done)
	}

	ts, _, _ = newSecurityServer(t, nil)
	if code, _ := do(t, ts, "GET", "/api/security", "", true); code != http.StatusOK {
		t.Fatalf("security: %d", code)
	}
	_, body = do(t, ts, "GET", "/api/me/setup", "", true)
	found := false
	for _, st := range body["steps"].([]any) {
		if st := st.(map[string]any); st["id"] == "security" {
			found = true
			if st["unknown"] == true {
				t.Errorf("security step after a report: %v", st)
			}
		}
	}
	if !found {
		t.Errorf("no security step: %v", body["steps"])
	}
}
