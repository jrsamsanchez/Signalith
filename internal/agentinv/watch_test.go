// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package agentinv

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/ingest"
)

type listOf struct {
	agents []Agent
	err    error
}

func (l *listOf) List(context.Context) ([]Agent, int64, error) { return l.agents, 0, l.err }

type written struct {
	events  []ingest.Event
	origins []ingest.Origin
}

func (w *written) IngestEvents(ctx context.Context, evs []ingest.Event) (*ingest.Result, error) {
	w.events = append(w.events, evs...)
	w.origins = append(w.origins, ingest.OriginFrom(ctx))
	return &ingest.Result{}, nil
}

func TestSensorWatch(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	quiet := now.Add(-22 * time.Minute)
	list := &listOf{agents: []Agent{
		{Key: "k1", Name: "nsm-01", LastSeen: quiet, Sensor: &ingest.SensorStatus{}},
		{Key: "k2", Name: "nsm-02", LastSeen: now, Sensor: &ingest.SensorStatus{}},
		// Set up by hand: no status line, not watched.
		{Key: "k3", Name: "zeek-box", LastSeen: now.Add(-3 * time.Hour), Tag: "zeek.conn"},
		{Key: "k4", Name: "win-01", LastSeen: now.Add(-3 * time.Hour)},
	}}
	out := &written{}
	leader := true
	w := &SensorWatch{Agents: list, Events: out, Now: func() time.Time { return now }, Leader: func() bool { return leader }}
	if err := w.Check(ctx); err != nil {
		t.Fatal(err)
	}
	if len(out.events) != 1 {
		t.Fatalf("events: %+v", out.events)
	}
	ev := out.events[0]
	f := ev.Fields
	if f["sourcetype"] != "sensor:health" || f["host"] != "nsm-01" || f["signature"] != "Sensor silent" || ev.Model != "Other" ||
		!strings.Contains(f["message"].(string), "nsm-01 has sent nothing for 22 minutes (last heard 2026-10-15 11:38 UTC)") || ev.ID == "" {
		t.Errorf("event: %+v", ev)
	}
	if wl, _ := f["sensor_warnings"].([]string); len(wl) != 1 || wl[0] != "silent" {
		t.Errorf("warnings: %v", f["sensor_warnings"])
	}
	if out.origins[0].Intake != ingest.IntakeSignalith {
		t.Errorf("origin: %+v", out.origins[0])
	}
	first := ev.ID

	// The same silence: nothing more, until a day later.
	now = now.Add(5 * time.Minute)
	_ = w.Check(ctx)
	if len(out.events) != 1 {
		t.Fatalf("written twice: %d", len(out.events))
	}
	// nsm-02 keeps sending.
	list.agents[1].LastSeen = quiet.Add(24 * time.Hour)
	now = quiet.Add(24*time.Hour + time.Minute)
	_ = w.Check(ctx)
	if len(out.events) != 2 || out.events[1].ID == first || !strings.Contains(out.events[1].Fields["message"].(string), "24 hours") {
		t.Fatalf("a day later: %+v", out.events)
	}

	// Another server taking over writes the same event (same ID).
	w2 := &SensorWatch{Agents: list, Events: &written{}, Now: func() time.Time { return quiet.Add(30 * time.Minute) }}
	_ = w2.Check(ctx)
	if got := w2.Events.(*written).events; len(got) != 1 || got[0].ID != first {
		t.Errorf("takeover: %+v", got)
	}

	// Back, then silent again: a new silence.
	list.agents[0].LastSeen = now
	_ = w.Check(ctx)
	now = now.Add(20 * time.Minute)
	list.agents[1].LastSeen = now
	_ = w.Check(ctx)
	if len(out.events) != 3 || out.events[2].ID == first {
		t.Fatalf("new silence: %d", len(out.events))
	}

	// Not the jobs server, or the list could not be read: nothing.
	leader = false
	now = now.Add(48 * time.Hour)
	list.agents[1].LastSeen = now
	_ = w.Check(ctx)
	leader = true
	list.err = errors.New("opensearch is down")
	if err := w.Check(ctx); err == nil || len(out.events) != 3 {
		t.Errorf("not leader or no list: %v %d", err, len(out.events))
	}
}

// TestSensorWatchHostAgents: a Signalith Agent on a host that stops
// sending gets an agent:health event after its line's threshold, one a
// day for three days, and none for a line with the alert off (ASI-14).
func TestSensorWatchHostAgents(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	managed := func(token string) *ManagedStatus { return &ManagedStatus{Token: token} }
	list := &listOf{agents: []Agent{
		{Key: "h1", Name: "db-01", LastSeen: now.Add(-61 * time.Minute), Managed: managed("tok1")},
		{Key: "h2", Name: "web-01", LastSeen: now.Add(-30 * time.Minute), Managed: managed("tok1")},
		{Key: "h3", Name: "lab-01", LastSeen: now.Add(-5 * time.Hour), Managed: managed("quiet")},
		{Key: "h4", Name: "old-01", LastSeen: now.Add(-5 * time.Hour), Managed: managed("tok4")},
		// No status from the Signalith Agent: another agent, not watched.
		{Key: "h5", Name: "fb-01", LastSeen: now.Add(-5 * time.Hour)},
	}}
	out := &written{}
	w := &SensorWatch{Agents: list, Events: out, Now: func() time.Time { return now },
		HostSilentAfter: func(token string) time.Duration {
			switch token {
			case "quiet":
				return 0
			case "tok4":
				return 24 * time.Hour
			}
			return time.Hour
		}}
	if err := w.Check(ctx); err != nil {
		t.Fatal(err)
	}
	if len(out.events) != 1 {
		t.Fatalf("events: %+v", out.events)
	}
	ev := out.events[0]
	if f := ev.Fields; f["sourcetype"] != "agent:health" || f["host"] != "db-01" || f["signature"] != "Signalith Agent silent" || f["signature_id"] != "h1" ||
		!strings.Contains(f["message"].(string), "The Signalith Agent on db-01 has sent nothing for 1 hour (last heard 2026-10-15 10:59 UTC)") ||
		!strings.HasPrefix(ev.ID, "agent-health-") {
		t.Errorf("event: %+v", ev)
	}
	if out.origins[0].Intake != ingest.IntakeSignalith {
		t.Errorf("origin: %+v", out.origins[0])
	}

	// Daily for three days, then no more.
	for day := 1; day <= 5; day++ {
		now = now.Add(24 * time.Hour)
		list.agents[1].LastSeen, list.agents[2].LastSeen = now, now
		list.agents[3].LastSeen = now
		_ = w.Check(ctx)
	}
	var db int
	for _, e := range out.events {
		if e.Fields["host"] == "db-01" {
			db++
		}
	}
	if db != 3 || len(out.events) != 3 {
		t.Fatalf("db-01 events %d of %d, want 3", db, len(out.events))
	}

	// Heard again, then silent again: a new silence alerts again.
	list.agents[0].LastSeen = now
	_ = w.Check(ctx)
	now = now.Add(2 * time.Hour)
	list.agents[1].LastSeen = now
	_ = w.Check(ctx)
	if len(out.events) != 4 {
		t.Fatalf("new silence: %d events", len(out.events))
	}
}
