// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package ingest

import (
	"testing"
	"time"
)

// A record split into events takes the log record's time, else the time
// the Collector saw it, when the record has none of its own.
func TestOTLPSplitTimes(t *testing.T) {
	rec := func() map[string]any {
		return map[string]any{"uuid": "u1", "eventType": "user.session.start", "actor": map[string]any{"id": "a"}}
	}
	at := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
	seen := at.Add(time.Minute)
	for _, c := range []struct {
		name           string
		time, observed uint64
		want           time.Time
	}{
		{"record time", uint64(at.UnixNano()), uint64(seen.UnixNano()), at},
		{"observed time", 0, uint64(seen.UnixNano()), seen},
		{"no time", 0, 0, now.UTC()},
	} {
		l := &otlpLog{body: rec(), resource: map[string]any{"host.name": "h1"}, time: c.time, observed: c.observed}
		evs := otlpEvents(l, now)
		if len(evs) != 1 {
			t.Fatalf("%s: %d events", c.name, len(evs))
		}
		if !evs[0].Time.Equal(c.want) {
			t.Errorf("%s: time = %v, want %v", c.name, evs[0].Time, c.want)
		}
	}
}

func TestOTLPEventBranches(t *testing.T) {
	res := map[string]any{"host.name": "res-host"}

	// A CloudTrail record as a map body.
	ct := map[string]any{"eventVersion": "1.08", "eventSource": "s3.amazonaws.com", "eventName": "GetObject",
		"eventTime": "2026-01-02T03:04:05Z", "awsRegion": "us-east-1"}
	ev := otlpEvent(&otlpLog{body: ct, resource: res}, now)
	if ev.Fields["sourcetype"] != CloudTrailSourcetype {
		t.Errorf("cloudtrail map = %v", ev.Fields)
	}

	// The syslog receiver without a host name of its own or a body: the
	// resource's host and the attribute's message.
	ev = otlpEvent(&otlpLog{resource: res, spanID: "abcd",
		attrs: map[string]any{"appname": "sshd", "proc_id": "12", "message": "hello there"}}, now)
	if ev.Fields["host"] != "res-host" || ev.Fields["message"] != "hello there" || ev.Fields["span_id"] != "abcd" {
		t.Errorf("syslog receiver = %v", ev.Fields)
	}

	// A journal record whose fields carry no message string: the body's
	// text becomes the message, and the event has a model.
	ev = otlpEvent(&otlpLog{body: map[string]any{"MESSAGE": 42}, resource: res}, now)
	if _, ok := ev.Fields["message"].(string); !ok {
		t.Errorf("journal message = %#v", ev.Fields["message"])
	}
	if ev.Model == "" {
		t.Error("an event without a model")
	}
	if !ev.Time.Equal(now.UTC()) {
		t.Errorf("journal time = %v", ev.Time)
	}
}
