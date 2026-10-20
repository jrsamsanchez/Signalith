// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package agentinv

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cluster/ostest"
	"github.com/jrsamsanchez/signalith/internal/store"
)

// syncBuffer is a log the inventory may write to from Run.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func canceled() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

func TestNilAndMemoryInventories(t *testing.T) {
	var v *Inventory
	v.Note(Contact{Name: "web-01"})
	v.NoteRefusedCA("192.0.2.1:443")
	v.Run(canceled())
	if b, e, last := v.Traffic(); b != 0 || e != 0 || !last.IsZero() {
		t.Errorf("nil traffic = %d %d %v", b, e, last)
	}
	if agents, over, err := v.List(context.Background()); len(agents) != 0 || over != 0 || err != nil {
		t.Errorf("nil list = %v %d %v", agents, over, err)
	}

	clk := &clock{t: time.Now().UTC().Truncate(time.Second)}
	m := &Inventory{Now: clk.now}
	m.Run(canceled())
	m.FlushNow(context.Background())
	if b, _, last := m.Traffic(); b != 0 || !last.IsZero() {
		t.Errorf("no traffic yet = %d %v", b, last)
	}
	m.Note(Contact{Name: "web-01", Address: "192.0.2.10", Events: 7})
	m.Note(Contact{Name: "web-01", Address: "192.0.2.10", Events: -3})
	if b, e, last := m.Traffic(); b != 2 || e != 7 || !last.Equal(clk.now()) {
		t.Errorf("traffic = %d %d %v", b, e, last)
	}
	m.NoteRefusedCA(":443")
	m.mu.Lock()
	n := len(m.refused)
	m.mu.Unlock()
	if n != 0 {
		t.Errorf("an address with no host was counted: %d", n)
	}
	if m.index() != "signalith_runtime" || m.serverCA() != "" || m.node() == "" || m.server() == "" {
		t.Errorf("defaults = %s %q %q %q", m.index(), m.serverCA(), m.node(), m.server())
	}
}

func TestFullListOverflowsThenEvicts(t *testing.T) {
	clk := &clock{t: time.Now().UTC().Truncate(time.Second)}
	var logs syncBuffer
	v := &Inventory{Now: clk.now, Log: slog.New(slog.NewTextHandler(&logs, nil))}
	v.mu.Lock()
	v.agents = map[string]*entry{}
	for i := range maxAgents {
		k := fmt.Sprintf("a%05d", i)
		v.agents[k] = &entry{doc: Doc{Agent: k, FirstSeen: clk.t.Add(-48 * time.Hour), LastSeen: clk.t.Add(-time.Minute)}, dirty: true}
	}
	v.mu.Unlock()

	// Every agent was heard from lately: the new one is only counted.
	v.Note(Contact{Name: "new-1", Address: "192.0.2.1"})
	v.Note(Contact{Name: "new-2", Address: "192.0.2.2"})
	v.mu.Lock()
	over, n := v.overflow, len(v.agents)
	v.mu.Unlock()
	if over != 2 || n != maxAgents || strings.Count(logs.String(), "more than 10,000 agents") != 1 {
		t.Errorf("overflow %d, %d agents, logs %s", over, n, logs.String())
	}

	// Once some are silent and written, the oldest makes room.
	v.mu.Lock()
	for _, k := range []string{"a00007", "a00008"} {
		v.agents[k].dirty = false
		v.agents[k].doc.LastSeen = clk.t.Add(-3 * time.Hour)
	}
	v.agents["a00008"].doc.LastSeen = clk.t.Add(-5 * time.Hour)
	v.mu.Unlock()
	v.Note(Contact{Name: "new-3", Address: "192.0.2.3"})
	v.mu.Lock()
	_, gone := v.agents["a00008"]
	_, kept := v.agents["a00007"]
	first, remembered := v.first["a00008"]
	n = len(v.agents)
	v.mu.Unlock()
	if gone || !kept || n != maxAgents || !remembered || !first.Equal(clk.t.Add(-48*time.Hour)) {
		t.Errorf("evicted %v kept %v n %d first %v %v", !gone, kept, n, first, remembered)
	}
}

func TestRunWritesAndKeepsFirstSeen(t *testing.T) {
	fos := ostest.New(t)
	c := store.New(store.Config{URL: fos.URL})
	clk := &clock{t: time.Now().UTC().Truncate(time.Second).Add(-2 * time.Hour)}
	contact := Contact{Name: "web-01", Address: "192.0.2.10", Events: 3}
	before := newInv(c, "n1", clk, pinA)
	before.Note(contact)
	before.FlushNow(context.Background())
	firstSeen := clk.now()

	// The server restarts: its new inventory hears from the agent first,
	// then reads when it heard from it before. Run stopped at once still
	// writes what it has.
	clk.add(time.Hour)
	after := newInv(c, "n1", clk, pinA)
	after.Note(contact)
	after.loadFirstSeen(context.Background())
	after.Run(canceled())
	agents := list(t, newInv(c, "n2", clk, pinA))
	if len(agents) != 1 || !agents[0].FirstSeen.Equal(firstSeen) || !agents[0].LastSeen.Equal(clk.now()) {
		t.Errorf("agents = %+v, want first seen %v", agents, firstSeen)
	}
}

func TestRunReportsUnreadableOpenSearch(t *testing.T) {
	fos := ostest.New(t)
	url := fos.URL
	fos.Close()
	var logs syncBuffer
	clk := &clock{t: time.Now()}
	v := newInv(store.New(store.Config{URL: url}), "n1", clk, "")
	v.Log = slog.New(slog.NewTextHandler(&logs, nil))
	v.Run(canceled())
	if !strings.Contains(logs.String(), "could not be read") {
		t.Errorf("logs = %s", logs.String())
	}
}

func TestSensorWatchRunStops(t *testing.T) {
	w := &SensorWatch{}
	done := make(chan struct{})
	go func() { w.Run(canceled()); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not stop")
	}
}
