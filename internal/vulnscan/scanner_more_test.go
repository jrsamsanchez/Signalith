// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package vulnscan

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/endpoint"
	"github.com/jrsamsanchez/signalith/internal/store"
)

// syncBuf collects log output from several goroutines.
type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func TestNmapProgram(t *testing.T) {
	ctx := context.Background()
	exe := fakeNmapPath(t, "ok")
	r := &Runner{Path: exe}
	hosts, err := r.Scan(ctx, target("192.0.2.0/24"), nil)
	if err != nil || len(hosts) != 2 || hosts[0].Address != "192.0.2.10" {
		t.Fatalf("scan = %+v, %v", hosts, err)
	}
	if v, err := NmapVersion(ctx, exe); err != nil || v != "7.94" {
		t.Errorf("version = %q, %v", v, err)
	}
	if err := selfTest(ctx, exe); err != nil {
		t.Errorf("self test = %v", err)
	}
	// The checks run the program for real when no fakes are given.
	c := &Checker{FindNmap: func() string { return exe }}
	checks, path := c.Run(ctx, DefaultSettings(), nil)
	if path != exe || checks[0].State != CheckOK || checks[1].State != CheckOK {
		t.Errorf("checks = %+v", checks[:2])
	}

	t.Setenv(fakeNmapEnv, "fail")
	if _, err := r.Scan(ctx, target("192.0.2.1"), nil); err == nil || err.Error() != `Nmap stopped with an error: Failed to resolve "nope.example".` {
		t.Errorf("failing scan = %v", err)
	}
	if err := selfTest(ctx, exe); err == nil || err.Error() != `Failed to resolve "nope.example".` {
		t.Errorf("failing self test = %v", err)
	}
	if _, err := NmapVersion(ctx, exe); err == nil || !strings.Contains(err.Error(), "--version failed") {
		t.Errorf("failing version = %v", err)
	}
	t.Setenv(fakeNmapEnv, "silent")
	if _, err := NmapVersion(ctx, exe); err == nil || !strings.Contains(err.Error(), "did not say which version") {
		t.Errorf("silent version = %v", err)
	}

	if _, err := (&Runner{Path: exe + "-missing"}).Scan(ctx, target("192.0.2.1"), nil); err == nil || !strings.HasPrefix(err.Error(), "could not start Nmap") {
		t.Errorf("missing program = %v", err)
	}
	if _, err := (&Runner{}).Scan(ctx, target("192.0.2.1"), nil); err == nil || !strings.Contains(err.Error(), "not installed") {
		t.Errorf("no program = %v", err)
	}
}

func TestFindNmap(t *testing.T) {
	exe := fakeNmapPath(t, "ok")
	t.Setenv("SIGNALITH_NMAP", exe)
	if got := FindNmap(); got != exe {
		t.Errorf("SIGNALITH_NMAP = %q", got)
	}
	t.Setenv("SIGNALITH_NMAP", t.TempDir())
	if got := FindNmap(); got != "" {
		t.Errorf("a folder = %q", got)
	}
	// With nothing on the PATH, only the usual places are looked in.
	t.Setenv("SIGNALITH_NMAP", "")
	t.Setenv("PATH", t.TempDir())
	if got := FindNmap(); got != "" && !slices.Contains(nmapPlaces(), got) {
		t.Errorf("found %q outside the usual places", got)
	}
	if len(nmapPlaces()) == 0 {
		t.Error("no usual places")
	}
}

func TestLimitedBuffer(t *testing.T) {
	var b limitedBuffer
	big := bytes.Repeat([]byte("x"), 40<<10)
	for range 3 {
		if n, err := b.Write(big); n != len(big) || err != nil {
			t.Fatalf("write = %d, %v", n, err)
		}
	}
	if got := len(b.Bytes()); got != 64<<10 {
		t.Errorf("kept %d bytes", got)
	}
}

func feedServer(t *testing.T, fail *atomic.Bool, hits *atomic.Int32) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if fail.Load() {
			http.Error(w, "down", http.StatusBadGateway)
			return
		}
		hits.Add(1)
		switch r.URL.Path {
		case "/kev.json":
			w.Write([]byte(kevJSON))
		case "/epss.csv.gz":
			w.Write(gz(epssCSV))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestExploitsCheck(t *testing.T) {
	ctx := context.Background()
	var fail atomic.Bool
	var hits atomic.Int32
	srv := feedServer(t, &fail, &hits)
	st := NewStore(endpoint.NewMemoryDocs(), "signalith")
	feeds := NewExploitFeeds(st, srv.URL+"/kev.json", srv.URL+"/epss.csv.gz")
	c := &Checker{Exploits: feeds}
	if ck := c.exploitsCheck(ctx, false); ck.State != CheckInfo || !strings.HasPrefix(ck.Detail, "Downloaded once there is a network") ||
		!strings.Contains(ck.Detail, "built into Signalith") {
		t.Errorf("built in, idle = %+v", ck)
	}
	if ck := c.exploitsCheck(ctx, true); ck.State != CheckInfo || !strings.HasPrefix(ck.Detail, "Not downloaded yet") {
		t.Errorf("built in, scanning = %+v", ck)
	}
	if kept, err := feeds.Refresh(ctx); !kept || err != nil {
		t.Fatalf("refresh = %v, %v", kept, err)
	}
	ck := c.exploitsCheck(ctx, true)
	if ck.State != CheckOK || !strings.Contains(ck.Detail, "Last downloaded") || !strings.Contains(ck.Detail, "EPSS scores of") ||
		strings.Contains(ck.Detail, "built into") {
		t.Errorf("downloaded = %+v", ck)
	}
	fail.Store(true)
	feeds.Now = func() time.Time { return time.Now().Add(48 * time.Hour) }
	if _, err := feeds.Refresh(ctx); err == nil {
		t.Fatal("refresh while down worked")
	}
	if ck := c.exploitsCheck(ctx, true); ck.State != CheckWarn || !strings.Contains(ck.Detail, "KEV catalog: ") || len(ck.Fix) != 3 {
		t.Errorf("failed download = %+v", ck)
	}
	// The whole check list includes it.
	c.FindNmap = func() string { return "" }
	checks, _ := c.Run(ctx, DefaultSettings(), nil)
	if !slices.ContainsFunc(checks, func(ch Check) bool { return ch.ID == "exploits" }) {
		t.Errorf("checks = %+v", checks)
	}
	if !maxTime(time.Unix(2, 0), time.Unix(1, 0)).Equal(time.Unix(2, 0)) || !maxTime(time.Unix(1, 0), time.Unix(2, 0)).Equal(time.Unix(2, 0)) {
		t.Error("maxTime")
	}
	if plural(1, "a", "b") != "a" || plural(2, "a", "b") != "b" {
		t.Error("plural")
	}
}

func TestStepRefreshesExploits(t *testing.T) {
	ctx := context.Background()
	var fail atomic.Bool
	var hits atomic.Int32
	srv := feedServer(t, &fail, &hits)
	var args []string
	s, _ := newScanner(t, "http://127.0.0.1:1", nmapXML, &args)
	logs := &syncBuf{}
	s.Log = slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	s.Exploits = NewExploitFeeds(s.Store, srv.URL+"/kev.json", srv.URL+"/epss.csv.gz")
	tg := target("192.0.2.1")
	tg.Schedule = Schedule{Every: Manual}
	if _, err := s.Store.SaveSettings(ctx, Settings{Targets: []Target{tg}}, store.Version{}, "alice"); err != nil {
		t.Fatal(err)
	}
	h := &Host{ID: "h1", TargetID: tg.ID, Address: "192.0.2.1", Services: []HostService{{Service: Service{Port: 80},
		Vulns: []Vuln{{CVE: "CVE-2023-25690", CVSS: 9.8, Severity: "critical"}}}}}
	if err := s.Store.SaveHosts(ctx, tg.ID, []*Host{h}); err != nil {
		t.Fatal(err)
	}
	if err := s.Step(ctx); err != nil {
		t.Fatal(err)
	}
	if hits.Load() != 2 || !strings.Contains(logs.String(), "hosts ranked again") {
		t.Errorf("feeds read %d times; logs %s", hits.Load(), logs)
	}
	got, err := s.Store.Host(ctx, "h1")
	if err != nil || got.Services[0].Vulns[0].EPSS != 0.3112 {
		t.Errorf("host = %+v, %v", got, err)
	}
	// The next step downloads nothing: the copy is fresh.
	if err := s.Step(ctx); err != nil {
		t.Fatal(err)
	}
	if hits.Load() != 2 {
		t.Errorf("downloaded again: %d", hits.Load())
	}
	// A failed download is only logged.
	fail.Store(true)
	s.Exploits.Now = func() time.Time { return time.Now().Add(48 * time.Hour) }
	if err := s.Step(ctx); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(logs.String(), "refresh incomplete") {
		t.Errorf("failure not logged: %s", logs)
	}
}

func TestScannerRunStopsWithContext(t *testing.T) {
	var args []string
	s, _ := newScanner(t, "http://127.0.0.1:1", nmapXML, &args)
	s.Log = slog.New(slog.DiscardHandler)
	s.Checker.Version = func(context.Context, string) (string, error) { return "7.94", nil }
	s.Checker.SelfTest = func(context.Context, string) error { return nil }
	s.Tick = time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	done := make(chan struct{})
	go func() { s.Run(ctx); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return after its context ended")
	}
	if got := s.Running(); len(got) != 0 {
		t.Errorf("running = %v", got)
	}
	// A paused scanner checks nothing.
	s2, _ := newScanner(t, "http://127.0.0.1:1", nmapXML, &args)
	s2.Paused = func() bool { return true }
	s2.Run(ctx)
	if reps, _ := s2.Store.Reports(context.Background()); len(reps) != 0 {
		t.Errorf("a paused scanner reported: %+v", reps)
	}
}

func TestMineKey(t *testing.T) {
	ctx := context.Background()
	var args []string
	s, _ := newScanner(t, "http://127.0.0.1:1", nmapXML, &args)
	s.NodeID = "node-a"
	a, b := target("192.0.2.1"), target("192.0.2.2")
	a.ID, b.ID, b.Name = "a", "b", "Lab"
	b.Scanner = "node-b"
	if _, err := s.Store.SaveSettings(ctx, Settings{Targets: []Target{a, b}}, store.Version{}, "alice"); err != nil {
		t.Fatal(err)
	}
	if got := s.mineKey(ctx); got != "a=192.0.2.1;" {
		t.Errorf("mine = %q", got)
	}
	s.Leader = func() bool { return false }
	if got := s.mineKey(ctx); got != "" {
		t.Errorf("not leader = %q", got)
	}
}
