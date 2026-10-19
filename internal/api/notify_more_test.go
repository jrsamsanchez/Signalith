package api

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/notify"
)

// failSender refuses every message, as a channel whose service is down.
type failSender struct{}

func (failSender) Send(context.Context, notify.Channel, notify.Message) error {
	return errors.New("the service answered 500")
}

// A test message through a saved channel, or one being edited, says how
// it went; a failure shows on the Health page until a test goes through.
func TestNotifyTestMessages(t *testing.T) {
	var srv *Server
	ts, n := newNotifyServer(t, func(s *Server) {
		s.Config.Detections.Scheduler = true
		s.Notify.Sender = failSender{}
		srv = s
	})
	if _, err := n.Settings.Save(notify.Input{Channels: []notify.ChannelInput{
		{ID: "soc", Name: "#soc", Type: "slack", URL: "https://hooks.slack.com/services/T/B/x"},
	}}); err != nil {
		t.Fatal(err)
	}
	test := func(body string) (int, map[string]any) {
		t.Helper()
		return do(t, ts, "POST", "/api/notify/test", body, true)
	}
	if code, _ := test(`{`); code != http.StatusBadRequest {
		t.Errorf("bad JSON: %d", code)
	}
	if code, _ := test(`{"id":"nope"}`); code != http.StatusNotFound {
		t.Errorf("unknown channel: %d", code)
	}
	if code, out := test(`{"channel":{"id":"x","name":"x","type":"carrier-pigeon"}}`); code != http.StatusBadRequest || out["problems"] == nil {
		t.Errorf("bad channel: %d %v", code, out)
	}
	code, out := test(`{"id":"soc"}`)
	if code != http.StatusOK || out["ok"] != false || !strings.Contains(out["error"].(string), "500") || out["channel"] != "#soc" {
		t.Errorf("saved channel: %d %v", code, out)
	}
	code, out = test(`{"channel":{"name":"#new","type":"slack","url":"https://hooks.slack.com/services/T/B/y"}}`)
	if code != http.StatusOK || out["ok"] != false || out["channel"] != "#new" {
		t.Errorf("unsaved channel: %d %v", code, out)
	}
	warn := srv.notifyWarnings(context.Background())
	if len(warn) != 1 || !strings.Contains(warn[0], "#soc are failing") {
		t.Errorf("health: %v", warn)
	}
	// Read again within the half minute: the same, from memory.
	if again := srv.notifyWarnings(context.Background()); len(again) != 1 {
		t.Errorf("cached health: %v", again)
	}
}

// The reason saving is refused names the server that sends, or says
// none does now.
func TestNotifyElsewhere(t *testing.T) {
	cl := &fakeCluster{}
	s := &Server{Cluster: cl}
	newTestServerWith(t, func(srv *Server) {
		srv.Config.Detections.Scheduler = true
		s.Config = srv.Config
	})
	if err := s.notifyElsewhere(); err == nil || !strings.Contains(err.Error(), "no server runs the background jobs") {
		t.Errorf("no holder: %v", err)
	}
	cl.set(true, "siem-b")
	if err := s.notifyElsewhere(); err != nil {
		t.Errorf("runs the jobs: %v", err)
	}
	s.Config.Detections.Scheduler = false
	if err := s.notifyElsewhere(); !errors.Is(err, errNotifyNoJobs) {
		t.Errorf("scheduler off: %v", err)
	}
}
