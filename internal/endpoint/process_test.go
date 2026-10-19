// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package endpoint

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/jrsamsanchez/signalith/internal/ingest"
)

const macStart = `{"name":"signalith_process_start","unixTime":1760356900,"action":"added","decorations":{"hostname":"mbp-7"},` +
	`"columns":{"pid":"4242","path":"/usr/bin/osascript","cmdline":"osascript -e display dialog \"Password\" with hidden answer",` +
	`"cwd":"/Users/jdoe","uid":"501","username":"jdoe","parent":"4100","signing_id":"com.apple.osascript","team_id":"",` +
	`"platform_binary":"1","time":"1760356899","parent_path":"/bin/zsh","parent_cmdline":"-zsh"}}`

func TestParseResultsProcessStart(t *testing.T) {
	mac := &Node{ID: "n9", Hostname: "mbp", Platform: Darwin}
	b := ParseResults(mac, lines(t, macStart), time.Now())
	if len(b.Events) != 1 || b.Skipped != 0 {
		t.Fatalf("events = %+v, skipped %d", b.Events, b.Skipped)
	}
	ev := b.Events[0]
	want := map[string]any{
		"process_path": "/usr/bin/osascript", "process_name": "osascript",
		"process":    `osascript -e display dialog "Password" with hidden answer`,
		"process_id": int64(4242), "parent_process_id": int64(4100),
		"parent_process_path": "/bin/zsh", "parent_process_name": "zsh", "parent_process": "-zsh",
		"process_current_directory": "/Users/jdoe", "user": "jdoe", "user_id": "501",
		"host": "mbp-7", "dest": "mbp-7", "action": "allowed", "sourcetype": ProcessStartSourcetype,
		"signature_id": ProcessStartSourcetype, "vendor_product": "osquery", "endpoint_id": "n9",
	}
	if ev.Model != "Endpoint" {
		t.Errorf("model = %s", ev.Model)
	}
	for k, v := range want {
		if ev.Fields[k] != v {
			t.Errorf("%s = %#v, want %#v", k, ev.Fields[k], v)
		}
	}
	if !ev.Time.Equal(time.Unix(1760356899, 0)) {
		t.Errorf("time = %v", ev.Time)
	}
	// Every field is one Signalith already maps: macOS process starts
	// take nothing from the field budget.
	for k := range ev.Fields {
		if k != "_raw" && !ingest.KnownField(k) {
			t.Errorf("field %s is not a known field", k)
		}
	}

	// Only macOS hosts are asked for program starts; another host's are
	// not read, nor rows osquery did not report as new, nor rows without
	// the program.
	linux := &Node{ID: "n1", Hostname: "web1", Platform: Linux}
	if b := ParseResults(linux, lines(t, macStart), time.Now()); len(b.Events) != 0 || b.Skipped != 1 {
		t.Errorf("linux host: %+v", b)
	}
	removed := strings.Replace(macStart, `"action":"added"`, `"action":"removed"`, 1)
	noPath := strings.Replace(macStart, `"path":"/usr/bin/osascript",`, ``, 1)
	if b := ParseResults(mac, lines(t, removed, noPath), time.Now()); len(b.Events) != 0 || b.Skipped != 2 {
		t.Errorf("removed or no path: %+v", b)
	}
	// A parent that has quit is unknown; the command line is the path
	// when osquery has none.
	bare := `{"name":"signalith_process_start","action":"added","columns":{"path":"/tmp/x","parent":"1"}}`
	b = ParseResults(mac, lines(t, bare), time.Now())
	if len(b.Events) != 1 {
		t.Fatalf("bare: %+v", b)
	}
	if f := b.Events[0].Fields; f["process"] != "/tmp/x" || f["parent_process_path"] != nil || f["user"] != nil || f["host"] != "mbp" {
		t.Errorf("bare = %+v", f)
	}
}

func TestProcessStartCommandLineCut(t *testing.T) {
	long := strings.Repeat("é", maxCommandBytes) // two bytes each
	cols := map[string]any{"path": "/bin/echo", "cmdline": long}
	line, _ := json.Marshal(map[string]any{"name": ProcessStartQuery, "action": "added", "columns": cols})
	b := ParseResults(&Node{Platform: Darwin}, []json.RawMessage{line}, time.Now())
	if len(b.Events) != 1 {
		t.Fatal(b)
	}
	p := b.Events[0].Fields["process"].(string)
	if len(p) > maxCommandBytes || !utf8.ValidString(p) || !strings.HasPrefix(long, p) {
		t.Errorf("cut to %d bytes, valid %v", len(p), utf8.ValidString(p))
	}
}

func TestScheduleProcessStartsOnMacOnly(t *testing.T) {
	for _, p := range Platforms {
		found := false
		for _, q := range schedule(p, DefaultSettings()) {
			if q.name == qProcess {
				found = true
				if !strings.Contains(q.sql, "es_process_events") || !strings.Contains(q.sql, "event_type = 'exec'") || q.snapshot {
					t.Errorf("query = %+v", q)
				}
			}
		}
		if found != (p == Darwin) {
			t.Errorf("%s schedules program starts: %v", p, found)
		}
	}
}

// FuzzProcessStart feeds arbitrary result lines from a macOS host through
// ParseResults: it must never panic, and every program start it reads
// has a program and only known fields.
func FuzzProcessStart(f *testing.F) {
	f.Add([]byte(macStart))
	f.Add([]byte(`{"name":"signalith_process_start","action":"added","columns":{"path":"/a","pid":"x","parent":"-1","time":"99999999999999999999"}}`))
	f.Add([]byte(`"{\"name\":\"signalith_process_start\",\"action\":\"added\",\"columns\":{\"path\":7}}"`))
	f.Add([]byte(`{"name":"signalith_process_start","diffResults":{"added":[{"path":"/b","cmdline":"\u0000"}]}}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		b := ParseResults(&Node{ID: "n", Hostname: "h", Platform: Darwin}, []json.RawMessage{data}, time.Unix(1_800_000_000, 0))
		for _, ev := range b.Events {
			if ev.Model != "Endpoint" {
				continue
			}
			if ev.Fields["process_path"] == "" || ev.Fields["process_path"] == nil {
				t.Fatalf("no program: %+v", ev.Fields)
			}
			if p, _ := ev.Fields["process"].(string); len(p) > maxCommandBytes {
				t.Fatalf("command line of %d bytes", len(p))
			}
			for k := range ev.Fields {
				if k != "_raw" && !ingest.KnownField(k) {
					t.Fatalf("field %s is not known", k)
				}
			}
		}
	})
}
