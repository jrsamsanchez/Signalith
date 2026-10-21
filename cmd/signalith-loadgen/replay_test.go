// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/detect/packs"
	"github.com/jrsamsanchez/signalith/internal/ingest"
	"github.com/jrsamsanchez/signalith/internal/sigmacheck"
)

func TestReplayCorpusIsRecordedWindowsEvents(t *testing.T) {
	c, err := loadReplayCorpus()
	if err != nil {
		t.Fatal(err)
	}
	if len(c.events) < 500 {
		t.Fatalf("only %d recorded events", len(c.events))
	}
	t.Logf("%d recorded events, %d bytes on average", len(c.events), c.bytes/int64(len(c.events)))
}

// Every replayed event, recorded or quieted, is read by the Windows
// parser as the event it is, with the agent's name and the time sent.
func TestReplayBatchesParseAsWindowsEvents(t *testing.T) {
	c, err := loadReplayCorpus()
	if err != nil {
		t.Fatal(err)
	}
	f := newFleet("r", "tok", []string{"http://x"}, nil, newMetrics())
	f.corpus = c
	for _, share := range []float64{0, 1} {
		a := &simAgent{id: 3, host: `ws-"0003`, next: 1}
		var attacks int64
		for range (len(c.events) + 499) / 500 {
			b := f.buildReplay(a, 500, share)
			if b.tag != "win.events" {
				t.Fatalf("tag %q", b.tag)
			}
			attacks += b.attacks
			var recs []map[string]any
			if err := json.Unmarshal(b.body, &recs); err != nil {
				t.Fatalf("share %v: %v", share, err)
			}
			if len(recs) != 500 {
				t.Fatalf("%d records", len(recs))
			}
			for _, rec := range recs {
				if rec["Computer"] != a.host {
					t.Fatalf("computer %v", rec["Computer"])
				}
				at, err := time.Parse(time.RFC3339Nano, rec["TimeCreated"].(string))
				if err != nil || time.Since(at) > time.Minute {
					t.Fatalf("time %v: %v", rec["TimeCreated"], err)
				}
				ev := ingest.Normalize("win.events", rec, time.Now())
				if st, _ := ev.Fields["sourcetype"].(string); !strings.HasPrefix(st, "WinEventLog:") || ev.Fields["host"] != a.host {
					t.Fatalf("stored as %v from %v: %v", ev.Fields["sourcetype"], ev.Fields["host"], rec)
				}
			}
		}
		if want := a.next - 1; (share == 1 && attacks != want) || (share == 0 && attacks != 0) {
			t.Errorf("share %v: %d attacks of %d", share, attacks, want)
		}
	}
}

// The quieted copy of a recorded event keeps its fields but no longer
// matches the Sigma rule its recording is a test of.
func TestQuietEventsDoNotMatchTheirRules(t *testing.T) {
	files, err := fs.Glob(packs.Tests, "sigmahq/tests/*.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases, matched, quietMatched int
	for _, name := range files {
		raw, _ := fs.ReadFile(packs.Tests, name)
		var tf sigmacheck.TestFile
		if err := json.Unmarshal(raw, &tf); err != nil {
			t.Fatal(err)
		}
		var rule *sigmacheck.Rule
		for _, cs := range tf.Cases {
			if cs.Source == "synthesized" || !cs.Expect {
				continue
			}
			if rule == nil {
				src, err := os.ReadFile(path.Join("../../internal/detect/packs/sigmahq/rules", strings.TrimSuffix(path.Base(name), ".json")+".yml"))
				if err != nil {
					break
				}
				if rule, err = sigmacheck.Parse(src); err != nil {
					t.Fatal(err)
				}
			}
			view, ok := cs.SigmaView()
			if !ok {
				continue
			}
			cases++
			if m, _ := rule.Match(view); m {
				matched++
			}
			q := cs
			q.Data = quietData(cs.Data)
			if qv, _ := q.SigmaView(); qv != nil {
				if m, _ := rule.Match(qv); m {
					quietMatched++
				}
			}
		}
	}
	t.Logf("%d recorded SigmaHQ events: %d match their rule, %d still match once quieted", cases, matched, quietMatched)
	if cases < 100 || matched < cases*9/10 {
		t.Fatalf("%d of %d recorded events match their rule", matched, cases)
	}
	// Rules that look only at an event ID or a number still match; the
	// rest must not.
	if quietMatched > cases/20 {
		t.Errorf("%d of %d quieted events still match their rule", quietMatched, cases)
	}
}

func TestRot13(t *testing.T) {
	in := `C:\Windows\System32\cmd.exe /c whoami 10.0.0.1 {AB-12}`
	if got := rot13(in); got != `P:\Jvaqbjf\Flfgrz32\pzq.rkr /p jubnzv 10.0.0.1 {NO-12}` || rot13(got) != in {
		t.Errorf("rot13 %q", got)
	}
}

// A replaying fleet sends its batches with the Windows event log's tag.
func TestFleetReplaySendsTheTag(t *testing.T) {
	var mu sync.Mutex
	tags := map[string]int{}
	var events int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var recs []json.RawMessage
		_ = json.Unmarshal(body, &recs)
		mu.Lock()
		tags[r.Header.Get("X-Signalith-Tag")]++
		events += len(recs)
		mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]int{"indexed": len(recs)})
	}))
	defer srv.Close()
	m := newMetrics()
	m.SetPhase("load")
	f := newFleet("run1", "tok", []string{srv.URL}, srv.Client(), m)
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	share := 0.5
	f.Run(ctx, AgentLoad{N: 2, Rate: 200, Batch: 20, Replay: &ReplayLoad{AttackShare: &share}})
	f.Close()
	mu.Lock()
	defer mu.Unlock()
	if events == 0 || int64(events) != f.stored.Load() || len(tags) != 1 || tags["win.events"] == 0 {
		t.Fatalf("events %d stored %d tags %v", events, f.stored.Load(), tags)
	}
	if !f.replayed.Load() || m.Count("", "agent_bytes_sent") == 0 || m.Count("", "agent_attack_events_sent") == 0 {
		t.Errorf("replayed %v, bytes %d, attacks %d", f.replayed.Load(), m.Count("", "agent_bytes_sent"), m.Count("", "agent_attack_events_sent"))
	}
}

func TestScenarioReplayShare(t *testing.T) {
	_, err := parseScenario([]byte("name: x\ntargets: [https://a]\nphases:\n  - {name: p, for: 1m, agents: {n: 1, rate: 10, replay: {attack_share: 2}}}\n"))
	if err == nil || !strings.Contains(err.Error(), "attack_share") {
		t.Errorf("err %v", err)
	}
	s, err := parseScenario([]byte("name: x\ntargets: [https://a]\nphases:\n  - {name: p, for: 1m, agents: {n: 1, rate: 10, replay: {}}}\n"))
	if err != nil {
		t.Fatal(err)
	}
	if got := s.Phases[0].Agents.Replay.share(); got != defaultAttackShare {
		t.Errorf("default share %v", got)
	}
}
