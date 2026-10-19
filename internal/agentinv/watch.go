// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package agentinv

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/jrsamsanchez/signalith/internal/ingest"
)

// SensorWatch writes a "Sensor silent" event (sourcetype sensor:health)
// when a network sensor that sends a status line goes silent: a search
// cannot find what did not arrive, so the built-in detection
// network-sensor-unhealthy reads these. One event is written per silence,
// and one more each day it lasts. It runs on the server that runs the
// background jobs; the events' IDs come from the sensor and the silence,
// so a second server taking over writes the same ones again, not new.
type SensorWatch struct {
	Agents interface {
		List(ctx context.Context) ([]Agent, int64, error)
	}
	Events interface {
		IngestEvents(ctx context.Context, events []ingest.Event) (*ingest.Result, error)
	}
	// Leader reports whether this server runs the background jobs; nil
	// for a single server, which always does.
	Leader func() bool
	Log    *slog.Logger
	Now    func() time.Time
	// Every is how often sensors are checked (5 minutes when zero).
	Every time.Duration

	mu sync.Mutex
	// written is, by agent key, the silence an event was written for: the
	// sensor's last batch, and how many days into the silence.
	written map[string]silence
}

type silence struct {
	lastSeen time.Time
	day      int
}

// SensorHealthSourcetype is the sourcetype of the events SensorWatch
// writes.
const SensorHealthSourcetype = "sensor:health"

// sensorRepeat is how often an event is written again while a sensor
// stays silent.
const sensorRepeat = 24 * time.Hour

func (w *SensorWatch) now() time.Time {
	if w.Now != nil {
		return w.Now()
	}
	return time.Now()
}

// Run checks the sensors every Every until ctx ends.
func (w *SensorWatch) Run(ctx context.Context) {
	every := w.Every
	if every <= 0 {
		every = 5 * time.Minute
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := w.Check(ctx); err != nil && ctx.Err() == nil && w.Log != nil {
				w.Log.Warn("silent network sensors could not be checked; Signalith tries again in 5 minutes", "err", err)
			}
		}
	}
}

// Check writes an event for each sensor that went silent since the last
// check, or has been silent another day.
func (w *SensorWatch) Check(ctx context.Context) error {
	if w.Leader != nil && !w.Leader() {
		return nil
	}
	list, _, err := w.Agents.List(ctx)
	if err != nil {
		// What other servers heard is not known: a sensor that sends to
		// them would look silent here.
		return err
	}
	now := w.now()
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.written == nil {
		w.written = map[string]silence{}
	}
	seen := map[string]bool{}
	var evs []ingest.Event
	var keys []string
	var marks []silence
	for _, a := range list {
		if a.Sensor == nil || a.Refusing {
			continue
		}
		seen[a.Key] = true
		if !Silent(a, now) {
			delete(w.written, a.Key)
			continue
		}
		s := silence{lastSeen: a.LastSeen, day: int(now.Sub(a.LastSeen) / sensorRepeat)}
		if prev, ok := w.written[a.Key]; ok && prev == s {
			continue
		}
		evs = append(evs, silentEvent(a, s, now))
		keys = append(keys, a.Key)
		marks = append(marks, s)
	}
	for k := range w.written {
		if !seen[k] {
			delete(w.written, k)
		}
	}
	if len(evs) == 0 {
		return nil
	}
	ctx = ingest.WithOrigin(ctx, ingest.Origin{Intake: ingest.IntakeSignalith})
	if _, err := w.Events.IngestEvents(ctx, evs); err != nil {
		return err
	}
	for i, k := range keys {
		w.written[k] = marks[i]
	}
	return nil
}

// silentEvent is the event for sensor a, silent since its last batch.
func silentEvent(a Agent, s silence, now time.Time) ingest.Event {
	name := a.Name
	if name == "" && len(a.Addresses) > 0 {
		name = a.Addresses[0]
	}
	quiet := now.Sub(a.LastSeen).Truncate(time.Minute)
	f := map[string]any{
		"sourcetype":      SensorHealthSourcetype,
		"vendor_product":  ingest.SensorStatusVendor,
		"signature":       "Sensor silent",
		"sensor_warnings": []string{"silent"},
		"message": fmt.Sprintf("%s has sent nothing for %s (last heard %s UTC): parts of the network go unwatched",
			name, quietFor(quiet), a.LastSeen.UTC().Format("2006-01-02 15:04")),
	}
	if name != "" {
		f["host"], f["dvc"] = name, name
	}
	return ingest.Event{Time: now, Model: "Other", Fields: f,
		ID: "sensor-health-" + hash16("silent", a.Key, a.LastSeen.UTC().Format(time.RFC3339Nano), fmt.Sprint(s.day))}
}

// quietFor writes a silence in minutes, hours or days.
func quietFor(d time.Duration) string {
	switch {
	case d < time.Hour:
		return fmt.Sprintf("%d minutes", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%d hours", int(d.Hours()))
	}
	return fmt.Sprintf("%d days", int(d.Hours()/24))
}
