package retention

import (
	"context"
	"errors"
	"sync"
	"testing"
)

// memStore is a PolicyStore in memory, as the shared policies are.
type memStore struct {
	mu    sync.Mutex
	saved Saved
	rev   int
}

func (s *memStore) Get() (Saved, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.saved.clone(), nil
}

func (s *memStore) Update(change func(*Saved)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := s.saved.clone()
	change(&next)
	s.saved = next
	s.rev++
	return nil
}

var errStale = errors.New("stale")

func (s *memStore) ETag() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return string(rune('a' + s.rev))
}

func (s *memStore) UpdateIf(etag string, change func(*Saved)) error {
	if etag != s.ETag() {
		return errStale
	}
	return s.Update(change)
}

// U17: while the policies wait to be confirmed, a run takes only the
// disk guard's steps.
func TestHoldRunsOnlyTheGuard(t *testing.T) {
	f := newFixture(t, Config{Days: 30})
	held := true
	f.m.Hold = func() (bool, string) { return held, "the servers' policies differed when they were imported" }
	f.m.ConfirmHold = func(context.Context, string) error { held = false; return nil }
	expired := f.add("endpoint", 31, GB, 1) // past keep_days
	oldest := f.add("endpoint", 29, 20*GB, 1)
	f.add("endpoint", 1, GB, 1)
	f.mem.DiskTotal, f.mem.DiskBase = 100*GB, 70*GB // 92%

	run, err := f.m.Run(context.Background(), TriggerSchedule, "")
	if err != nil {
		t.Fatal(err)
	}
	if !f.exists(expired) || run.Guard == nil || run.Guard.State != GuardOver {
		t.Errorf("a step other than the guard's ran: %+v, calls %v", run, f.mem.Calls)
	}
	if f.exists(oldest) && run.Deleted == 0 {
		t.Errorf("the guard did not act: %+v, calls %v", run, f.mem.Calls)
	}
	ov := f.m.Overview(context.Background())
	if ov.Hold == nil || ov.Hold.Reason == "" {
		t.Errorf("overview hold = %+v", ov.Hold)
	}
	if err := f.m.Confirm(context.Background(), "admin"); err != nil {
		t.Fatal(err)
	}
	if err := f.m.Confirm(context.Background(), "admin"); !errors.Is(err, ErrNoHold) {
		t.Errorf("second confirm = %v", err)
	}
	if _, err := f.m.Run(context.Background(), TriggerSchedule, ""); err != nil {
		t.Fatal(err)
	}
	if f.exists(expired) {
		t.Error("confirmed policies were not enforced")
	}
}

// U18: shared policies carry retention.days and the default; nothing
// comes from signalith.yaml, and a server that does not run retention may
// still change them.
func TestSharedPolicies(t *testing.T) {
	f := newFixture(t, Config{})
	days := 45
	st := &memStore{saved: Saved{Days: &days, From: map[string]Provenance{"days": {Source: "yaml", Node: "siem-a", At: "2026-10-01T10:00:00Z"}}}}
	f.m.Store, f.m.Shared = st, true
	f.m.Leader = func() (bool, string) { return false, "siem-a" }
	var seen []Settings
	f.m.OnSettings = func(s Settings) { seen = append(seen, s) }

	s, err := f.m.Settings()
	if err != nil || s.Default.KeepDays != 45 || s.DefaultSource != SourceDays {
		t.Fatalf("settings = %+v %v", s, err)
	}
	ov := f.m.Overview(context.Background())
	if !ov.Default.Editable || ov.Default.From == nil || ov.Default.From.Note != "Applied from signalith.yaml on siem-a, 2026-10-01" {
		t.Errorf("default view = %+v from %+v", ov.Default, ov.Default.From)
	}
	if !ov.Schedule.ReadOnly || ov.ETag == "" {
		t.Errorf("schedule = %+v etag %q", ov.Schedule, ov.ETag)
	}
	if err := f.m.SetDefaultIf(Policy{KeepDays: 60}, "stale"); !errors.Is(err, errStale) {
		t.Errorf("save at an old version = %v", err)
	}
	if err := f.m.SetDefaultIf(Policy{KeepDays: 60}, ov.ETag); err != nil {
		t.Fatal(err)
	}
	if s, _ := f.m.Settings(); s.Default.KeepDays != 60 || s.DefaultSource != SourceUI {
		t.Errorf("after the edit = %+v", s)
	}
	if len(seen) != 1 || seen[0].ShortestKeepDays() != 60 {
		t.Errorf("OnSettings = %+v", seen)
	}
	// Runs stay with the server that runs retention.
	if err := f.m.RunAsync(TriggerManual, "admin"); !errors.Is(err, ErrReadOnly) {
		t.Errorf("run on another server = %v", err)
	}
}
