package api

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/notify"
)

// forgetHealth drops the Health page's copy of the notification
// warnings, so the next read looks again.
func forgetHealth(n *Notify) {
	n.healthMu.Lock()
	n.healthAt = time.Time{}
	n.healthMu.Unlock()
}

// The Health page says nothing without channels, names at most three
// failing channels and says when there are more, and says when the
// notifications file cannot be read.
func TestNotifyHealthWarnings(t *testing.T) {
	var srv *Server
	ts, n := newNotifyServer(t, func(s *Server) {
		s.Config.Detections.Scheduler = true
		s.Notify.Sender = failSender{}
		srv = s
	})
	ctx := context.Background()
	if w := srv.notifyWarnings(ctx); w != nil {
		t.Errorf("no channels: %v", w)
	}
	var in []notify.ChannelInput
	for _, id := range []string{"a", "b", "c", "d"} {
		in = append(in, notify.ChannelInput{ID: id, Name: "#" + id, Type: "slack", URL: "https://hooks.slack.com/services/T/B/" + id})
	}
	if _, err := n.Settings.Save(notify.Input{Channels: in}); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"a", "b", "c", "d"} {
		if code, out := do(t, ts, "POST", "/api/notify/test", `{"id":"`+id+`"}`, true); out["ok"] != false {
			t.Fatalf("test %s: %d %v", id, code, out)
		}
	}
	forgetHealth(n)
	w := srv.notifyWarnings(ctx)
	if len(w) != 4 || !strings.Contains(w[3], "Other notification channels are failing too") {
		t.Errorf("four failing: %v", w)
	}

	file := filepath.Join(t.TempDir(), "notifications.yaml")
	if err := os.WriteFile(file, []byte("channels: [this is: not: yaml\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var broken *Server
	newNotifyServer(t, func(s *Server) {
		s.Config.Detections.Scheduler = true
		s.Notify.Settings = &notify.Manager{File: file}
		broken = s
	})
	if w := broken.notifyWarnings(ctx); len(w) != 1 || !strings.Contains(w[0], "Until then no notifications are sent") {
		t.Errorf("unreadable file: %v", w)
	}
}
