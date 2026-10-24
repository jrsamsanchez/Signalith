// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package snapshots

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cluster/ostest"
	"github.com/jrsamsanchez/signalith/internal/store"
)

func TestSettingsSchedule(t *testing.T) {
	for _, c := range []struct {
		s          Settings
		cron, says string
		period     time.Duration
	}{
		{Settings{}, "30 2 * * *", "every day at 02:30 UTC", 24 * time.Hour},
		{Settings{Every: "12h", At: "3:05", TimeZone: "Europe/Berlin"}, "5 3,15 * * *", "every 12 hours from 03:05 Europe/Berlin", 12 * time.Hour},
		{Settings{Every: "6h", At: "23:00"}, "0 5,11,17,23 * * *", "every 6 hours from 23:00 UTC", 6 * time.Hour},
		{Settings{Every: "1h", At: "00:45"}, "45 * * * *", "every hour at minute 45", time.Hour},
		// What Validate refuses falls back to the defaults.
		{Settings{Every: "2d", At: "25:00"}, "30 2 * * *", "every day at 02:30 UTC", 24 * time.Hour},
	} {
		if got := c.s.Cron(); got != c.cron {
			t.Errorf("%+v: cron %q, want %q", c.s, got, c.cron)
		}
		if got := c.s.Describe(); got != c.says {
			t.Errorf("%+v: %q, want %q", c.s, got, c.says)
		}
		if got := c.s.Period(); got != c.period {
			t.Errorf("%+v: period %s", c.s, got)
		}
	}
	berlin, _ := time.LoadLocation("Europe/Berlin")
	for _, c := range []struct {
		s        Settings
		at, want time.Time
	}{
		{Settings{}, time.Date(2026, 3, 1, 1, 0, 0, 0, time.UTC), time.Date(2026, 3, 1, 2, 30, 0, 0, time.UTC)},
		{Settings{}, time.Date(2026, 3, 1, 2, 30, 0, 0, time.UTC), time.Date(2026, 3, 2, 2, 30, 0, 0, time.UTC)},
		{Settings{Every: "12h", At: "03:05", TimeZone: "Europe/Berlin"}, time.Date(2026, 3, 1, 4, 0, 0, 0, berlin), time.Date(2026, 3, 1, 15, 5, 0, 0, berlin)},
		{Settings{Every: "6h", At: "23:00"}, time.Date(2026, 3, 1, 23, 30, 0, 0, time.UTC), time.Date(2026, 3, 2, 5, 0, 0, 0, time.UTC)},
		{Settings{Every: "1h", At: "00:45"}, time.Date(2026, 3, 1, 10, 50, 0, 0, time.UTC), time.Date(2026, 3, 1, 11, 45, 0, 0, time.UTC)},
	} {
		if got := c.s.Next(c.at); !got.Equal(c.want) {
			t.Errorf("%+v after %s: %s, want %s", c.s, c.at, got, c.want)
		}
	}
	if p := (Settings{Repository: "Bad/Repo", Every: "2d", At: "7pm", TimeZone: "Mars/Base", Keep: MaxKeep + 1}).Problems(); len(p) != 5 {
		t.Errorf("problems: %q", p)
	}
	if p := (Settings{Repository: "s3-backups", Every: "12h", At: "01:00", TimeZone: "America/New_York", Keep: 30}).Problems(); len(p) != 0 {
		t.Errorf("problems: %q", p)
	}
	for _, z := range []string{"Local", "EST", "Factory"} {
		if CheckTimeZone(z) == nil {
			t.Errorf("%s is accepted", z)
		}
	}
}

type env struct {
	os     *ostest.Server
	m      *Manager
	now    time.Time
	fenced atomic.Int32
	deny   atomic.Bool
	set    Settings
	mu     sync.Mutex
}

func newEnv(t *testing.T) *env {
	t.Helper()
	e := &env{os: ostest.New(t), now: time.Now().UTC().Truncate(time.Second)}
	e.set = Settings{On: true}
	e.m = &Manager{Client: store.New(store.Config{URL: e.os.URL}), Prefix: "signalith",
		Settings: func() Settings { e.mu.Lock(); defer e.mu.Unlock(); return e.set },
		Fence: func(context.Context) error {
			e.fenced.Add(1)
			if e.deny.Load() {
				return errors.New("this server no longer runs the background jobs")
			}
			return nil
		},
		Now: func() time.Time { e.mu.Lock(); defer e.mu.Unlock(); return e.now },
	}
	return e
}

func (e *env) settings(f func(*Settings)) {
	e.mu.Lock()
	defer e.mu.Unlock()
	f(&e.set)
}

func (e *env) advance(d time.Duration) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.now = e.now.Add(d)
}

func TestSyncWritesThePolicy(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()

	// No repository yet: nothing is written, and the problem says what to
	// register.
	res, err := e.m.Sync(ctx)
	if err != nil || res.Action != "" || !strings.Contains(res.Problem, "no snapshot repository named signalith") {
		t.Fatalf("sync without a repository: %+v, %v", res, err)
	}
	if e.os.SMPolicy("signalith-daily") != nil || e.fenced.Load() != 0 {
		t.Fatal("wrote a policy for a missing repository")
	}
	e.m.Docker = true
	res, _ = e.m.Sync(ctx)
	if !strings.Contains(res.Problem, "sh snapshot.sh register") {
		t.Errorf("quick start advice: %q", res.Problem)
	}

	e.os.AddRepository("signalith", "fs")
	res, err = e.m.Sync(ctx)
	if err != nil || res.Action != "created" || res.Problem != "" {
		t.Fatalf("first sync: %+v, %v", res, err)
	}
	p := e.os.SMPolicy("signalith-daily")
	sc := p["snapshot_config"].(map[string]any)
	if sc["indices"] != "signalith-*,signalith_*,signalith.t.*" || sc["include_global_state"] != "false" || sc["repository"] != "signalith" {
		t.Errorf("snapshot_config: %v", sc)
	}
	cron := p["creation"].(map[string]any)["schedule"].(map[string]any)["cron"].(map[string]any)
	if cron["expression"] != "30 2 * * *" || cron["timezone"] != "UTC" {
		t.Errorf("schedule: %v", cron)
	}
	if cond := p["deletion"].(map[string]any)["condition"].(map[string]any); cond["max_count"] != float64(14) {
		t.Errorf("deletion: %v", cond)
	}

	// Nothing changed: nothing is written, and the lease is not asked.
	before := e.fenced.Load()
	if res, err := e.m.Sync(ctx); err != nil || res.Action != "" {
		t.Fatalf("second sync: %+v, %v", res, err)
	}
	if e.fenced.Load() != before {
		t.Error("asked the lease with nothing to write")
	}

	// A change of settings updates it in place, naming the version read.
	e.settings(func(s *Settings) { s.Keep, s.Every, s.TimeZone = 30, "12h", "Europe/Berlin" })
	if res, err := e.m.Sync(ctx); err != nil || res.Action != "updated" {
		t.Fatalf("update: %+v, %v", res, err)
	}
	p = e.os.SMPolicy("signalith-daily")
	if p["deletion"].(map[string]any)["condition"].(map[string]any)["max_count"] != float64(30) {
		t.Errorf("not updated: %v", p)
	}
	puts := 0
	for _, r := range e.os.Requests() {
		if strings.HasPrefix(r, "PUT /_plugins/_sm/policies/signalith-daily?if_seq_no=") {
			puts++
		}
	}
	if puts != 1 {
		t.Errorf("updates naming a version: %d", puts)
	}

	// A server that lost the job lease writes nothing.
	e.deny.Store(true)
	e.settings(func(s *Settings) { s.Keep = 7 })
	if _, err := e.m.Sync(ctx); err == nil {
		t.Fatal("a server without the lease wrote the policy")
	}
	if e.os.SMPolicy("signalith-daily")["deletion"].(map[string]any)["condition"].(map[string]any)["max_count"] != float64(30) {
		t.Error("written without the lease")
	}
	e.deny.Store(false)

	// Turned off: the policy goes, the snapshots stay.
	e.settings(func(s *Settings) { s.On = false })
	if res, err := e.m.Sync(ctx); err != nil || res.Action != "deleted" {
		t.Fatalf("off: %+v, %v", res, err)
	}
	if e.os.SMPolicy("signalith-daily") != nil {
		t.Error("policy kept after turning off")
	}
	if res, err := e.m.Sync(ctx); err != nil || res.Action != "" {
		t.Fatalf("off again: %+v, %v", res, err)
	}
}

func TestSyncLeavesAPolicyItDidNotMake(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.os.AddRepository("signalith", "fs")
	c := store.New(store.Config{URL: e.os.URL})
	if err := c.Do(ctx, http.MethodPost, "/_plugins/_sm/policies/signalith-daily", map[string]any{
		"creation":        map[string]any{"schedule": map[string]any{"cron": map[string]any{"expression": "0 * * * *", "timezone": "UTC"}}},
		"snapshot_config": map[string]any{"repository": "signalith", "indices": "*"}}, nil); err != nil {
		t.Fatal(err)
	}
	res, err := e.m.Sync(ctx)
	if err != nil || res.Action != "" || !strings.Contains(res.Problem, "Signalith did not make") {
		t.Fatalf("%+v, %v", res, err)
	}
	e.settings(func(s *Settings) { s.On = false })
	if res, _ := e.m.Sync(ctx); res.Action != "" || e.os.SMPolicy("signalith-daily") == nil {
		t.Fatalf("deleted someone else's policy: %+v", res)
	}
}

func TestSyncSaysWhatPermissionsToAdd(t *testing.T) {
	e := newEnv(t)
	e.os.AddRepository("signalith", "fs")
	e.os.SetFault(func(method, path string) *ostest.Fault {
		if strings.HasPrefix(path, "/_plugins/_sm/") {
			return &ostest.Fault{Status: http.StatusForbidden, Type: "security_exception"}
		}
		return nil
	})
	res, err := e.m.Sync(context.Background())
	if err != nil || !strings.Contains(res.Problem, Role) || !strings.Contains(res.Problem, "cluster:admin/opensearch/snapshot_management/*") {
		t.Fatalf("%+v, %v", res, err)
	}
	st := e.m.Status(context.Background(), true)
	if st.State != StateProblem || st.Alert() == "" || !strings.Contains(st.Problem, "cluster:admin/repository/get") {
		t.Errorf("status: %+v", st)
	}

	// Without Snapshot Management at all.
	e.os.SetFault(func(method, path string) *ostest.Fault {
		if strings.HasPrefix(path, "/_plugins/_sm/") {
			return &ostest.Fault{Status: http.StatusBadRequest, Type: "no handler found for uri"}
		}
		return nil
	})
	res, err = e.m.Sync(context.Background())
	if err != nil || !strings.Contains(res.Problem, "index-management") {
		t.Fatalf("%+v, %v", res, err)
	}
	// Off, the same answers are nothing to complain about: the policy is
	// not wanted.
	e.settings(func(s *Settings) { s.On = false })
	if res, err := e.m.Sync(context.Background()); err != nil || res.Problem != "" || res.Action != "" {
		t.Fatalf("off: %+v, %v", res, err)
	}
}

func TestStatus(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.settings(func(s *Settings) { s.On = false })
	if st := e.m.Status(ctx, true); st.State != StateOff || st.Alert() != "" {
		t.Fatalf("off: %+v", st)
	}
	e.settings(func(s *Settings) { s.On = true })
	e.os.AddRepository("signalith", "fs")
	st := e.m.Status(ctx, true)
	if st.State != StateWaiting || !st.Pending || st.Schedule != "every day at 02:30 UTC" || st.Keep != 14 {
		t.Fatalf("before the policy: %+v", st)
	}
	if _, err := e.m.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	st = e.m.Status(ctx, false)
	if st.State != StateWaiting || st.Pending || st.Kept != 0 {
		t.Fatalf("no snapshot yet: %+v", st)
	}

	// Two snapshots: one good, then a failure. The status shows the newest
	// and the newest that succeeded, and when the next is due.
	first := e.now.Add(-26 * time.Hour)
	e.os.SMRan("signalith-daily", "SUCCESS", first, 40*time.Second, first.Add(24*time.Hour))
	failed := first.Add(24 * time.Hour)
	next := failed.Add(24 * time.Hour)
	e.os.SMRan("signalith-daily", "FAILED", failed, time.Minute, next)
	// Cached for a minute.
	if st = e.m.Status(ctx, false); st.Kept != 0 {
		t.Fatalf("not cached: %+v", st)
	}
	e.advance(2 * time.Minute)
	st = e.m.Status(ctx, false)
	if st.State != StateOK || st.Kept != 1 || st.Last == nil || st.Last.State != "FAILED" || st.LastSuccess == nil ||
		!st.LastSuccess.Equal(first.Add(40*time.Second)) || st.Next == nil || !st.Next.Equal(next) || !strings.HasPrefix(st.Run, "FAILED") {
		t.Fatalf("after two runs: %+v", st)
	}
	if st.Alert() != "" {
		t.Errorf("alert within two periods: %q", st.Alert())
	}

	// After a change of schedule, OpenSearch still says the old next time
	// until it runs the new policy: the status works it out instead.
	e.settings(func(s *Settings) { s.At = "04:10" })
	if _, err := e.m.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	st = e.m.Status(ctx, true)
	if want := (Settings{At: "04:10"}).Next(e.now); st.Next == nil || !st.Next.Equal(want) {
		t.Fatalf("next after a change: %v, want %s", st.Next, want)
	}

	// Two days on without another success: late, a red Health item.
	e.advance(24 * time.Hour)
	st = e.m.Status(ctx, true)
	if st.State != StateLate || !strings.Contains(st.Alert(), "more than two scheduled periods ago") || !strings.Contains(st.Alert(), "FAILED") {
		t.Fatalf("late: %+v", st)
	}

	// A missing repository is a problem too.
	e.settings(func(s *Settings) { s.Repository = "elsewhere" })
	if st = e.m.Status(ctx, true); st.State != StateProblem || !strings.Contains(st.Alert(), "elsewhere") {
		t.Fatalf("missing repository: %+v", st)
	}
}

func TestStatusLateWithoutAnySnapshot(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.os.AddRepository("signalith", "fs")
	e.os.Clock = ostest.NewClock(e.now)
	if _, err := e.m.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	e.settings(func(s *Settings) { s.Every = "1h" })
	if _, err := e.m.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if st := e.m.Status(ctx, true); st.State != StateWaiting {
		t.Fatalf("just turned on: %+v", st)
	}
	e.advance(3 * time.Hour)
	if st := e.m.Status(ctx, true); st.State != StateLate || !strings.Contains(st.Alert(), "no successful snapshot") {
		t.Fatalf("never ran: %+v", st)
	}
}

// TestStatusOneReadAtATime checks that callers asking at once share one
// read of OpenSearch.
func TestStatusOneReadAtATime(t *testing.T) {
	e := newEnv(t)
	e.os.AddRepository("signalith", "fs")
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if st := e.m.Status(context.Background(), false); st.State != StateWaiting {
				t.Errorf("status: %+v", st)
			}
		}()
	}
	wg.Wait()
	reads := 0
	for _, r := range e.os.Requests() {
		if r == "GET /_snapshot/signalith" {
			reads++
		}
	}
	if reads != 1 {
		t.Errorf("%d reads", reads)
	}
}

func TestFilesBackupRecord(t *testing.T) {
	dir := t.TempDir()
	if ReadFilesBackup(dir) != nil {
		t.Fatal("record in an empty folder")
	}
	at := time.Now().UTC().Truncate(time.Second)
	owned := ""
	if err := WriteFilesBackup(dir, FilesBackup{At: at, File: "signalith-backup.zip", Files: 12, Version: "v1"}, func(p string) { owned = p }); err != nil {
		t.Fatal(err)
	}
	r := ReadFilesBackup(dir)
	if r == nil || !r.At.Equal(at) || r.File != "signalith-backup.zip" || r.Files != 12 || owned == "" {
		t.Fatalf("%+v, %q", r, owned)
	}
}

// day is the daily index of kind for the day n days ago.
func day(kind string, n int) string {
	return "signalith-" + kind + "-" + time.Now().UTC().AddDate(0, 0, -n).Format("2006.01.02")
}

func TestSyncLeavesColdIndicesOut(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.os.AddRepository("signalith", "fs")
	hot, cold1, cold2 := day("events", 0), day("events", 40), day("events", 41)
	e.os.Put(hot, "1", map[string]any{"message": "hot"})
	e.os.Mount(cold1)
	// Hot indices have no store.type, and are still known as hot.
	if c, h, err := e.m.coldIndices(ctx); err != nil || len(c) != 1 || c[0] != cold1 || len(h) != 1 || h[0] != hot {
		t.Fatalf("cold %q, hot %q, %v", c, h, err)
	}
	if res, err := e.m.Sync(ctx); err != nil || res.Action != "created" {
		t.Fatalf("first sync: %+v, %v", res, err)
	}
	indices := func() string {
		return e.os.SMPolicy("signalith-daily")["snapshot_config"].(map[string]any)["indices"].(string)
	}
	if got, want := indices(), "signalith-*,signalith_*,signalith.t.*,-"+cold1; got != want {
		t.Fatalf("indices %q, want %q", got, want)
	}
	if st := e.m.Status(ctx, true); st.Pending {
		t.Errorf("pending right after a sync: %+v", st)
	}

	// The same cold set: nothing to write.
	before := e.fenced.Load()
	if res, err := e.m.Sync(ctx); err != nil || res.Action != "" || e.fenced.Load() != before {
		t.Fatalf("sync with nothing new: %+v, %v", res, err)
	}

	// Another day goes cold: Status says the policy is behind, a server
	// without the lease leaves it, and the one with it updates it.
	e.os.Mount(cold2)
	if st := e.m.Status(ctx, true); !st.Pending {
		t.Error("a new cold day is not pending")
	}
	e.deny.Store(true)
	if _, err := e.m.Sync(ctx); err == nil || strings.Contains(indices(), cold2) {
		t.Fatalf("written without the lease: %q, %v", indices(), err)
	}
	e.deny.Store(false)
	if res, err := e.m.Sync(ctx); err != nil || res.Action != "updated" {
		t.Fatalf("sync after a new cold day: %+v, %v", res, err)
	}
	// In order of name: the older day first.
	want := "signalith-*,signalith_*,signalith.t.*,-" + cold2 + ",-" + cold1
	if got := indices(); got != want {
		t.Errorf("indices %q, want %q", got, want)
	}
}

func TestIndicesLeavingOut(t *testing.T) {
	base := Indices("signalith")
	if got, all := IndicesLeavingOut("signalith", nil, []string{day("events", 0)}); got != base || !all {
		t.Errorf("no cold: %q %v", got, all)
	}

	// A year and more of cold days for many tenants: too long one by one,
	// so whole months go, but not a month that still has a hot day.
	now := time.Now().UTC()
	var cold, hot []string
	for tenant := 0; tenant < 40; tenant++ {
		name := fmt.Sprintf("signalith.t.tenant%02d-events-", tenant)
		for d := 0; d < 400; d++ {
			idx := name + now.AddDate(0, 0, -d).Format("2006.01.02")
			if d < 7 {
				hot = append(hot, idx)
			} else {
				cold = append(cold, idx)
			}
		}
	}
	got, all := IndicesLeavingOut("signalith", cold, hot)
	if !all || len(got) > MaxIndices || !strings.HasPrefix(got, base+",-") {
		t.Fatalf("%d bytes, all %v", len(got), all)
	}
	for _, h := range hot {
		if strings.Contains(got, ","+"-"+h) || strings.Contains(got, "-"+h[:len(h)-3]+".*") {
			t.Fatalf("leaves out the hot %s", h)
		}
	}
	if !strings.Contains(got, ",-signalith.t.tenant00-events-"+now.AddDate(0, -3, 0).Format("2006.01")+".*") {
		t.Error("months are not left out whole")
	}
	// Every cold day is left out, by name or by its month.
	for _, c := range cold {
		if !strings.Contains(got, ",-"+c) && !strings.Contains(got, ",-"+c[:len(c)-3]+".*") {
			t.Fatalf("keeps the cold %s", c)
		}
	}
	// The month that holds the hot week's first day lists its cold days by
	// name.
	if c := hot[6]; now.AddDate(0, 0, -7).Month() == now.AddDate(0, 0, -6).Month() {
		if old := c[:len(c)-2] + now.AddDate(0, 0, -7).Format("02"); !strings.Contains(got, ",-"+old) {
			t.Errorf("%s is not listed by name", old)
		}
	}
	if again, _ := IndicesLeavingOut("signalith", append([]string(nil), cold...), hot); again != got {
		t.Error("not the same expression for the same indices")
	}

	// Too many even by year: none left out.
	var many []string
	for i := 0; i < 4000; i++ {
		many = append(many, fmt.Sprintf("signalith-restored-%04d", i))
	}
	if got, all := IndicesLeavingOut("signalith", many, nil); got != base || all {
		t.Errorf("over the limit: %d bytes, all %v", len(got), all)
	}
}
