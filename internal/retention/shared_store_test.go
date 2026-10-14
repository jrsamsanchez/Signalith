package retention

import (
	"context"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
)

// memManifests is a ManifestStore in memory, as servers that share one
// OpenSearch keep it.
type memManifests struct {
	mu   sync.Mutex
	docs map[string]Manifest
}

func (s *memManifests) Reserve(_ context.Context, m Manifest, skip func(string) bool) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.docs == nil {
		s.docs = map[string]Manifest{}
	}
	for n := 1; ; n++ {
		id := ArchiveID(m.Index, n)
		if _, ok := s.docs[id]; ok || skip(id) {
			continue
		}
		m.ID, m.State = id, ManifestPending
		s.docs[id] = m
		return id, nil
	}
}

func (s *memManifests) Complete(_ context.Context, m Manifest) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.docs[m.ID] = m
	return nil
}

func (s *memManifests) Abandon(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.docs, id)
	return nil
}

func (s *memManifests) List(context.Context) ([]Manifest, []string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Manifest
	for _, m := range s.docs {
		if m.State == ManifestComplete {
			out = append(out, m)
		}
	}
	return out, nil, nil
}

func (s *memManifests) Get(_ context.Context, id string) (Manifest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if m, ok := s.docs[id]; ok && m.State == ManifestComplete {
		return m, nil
	}
	return Manifest{}, ErrArchiveNotFound
}

func TestManifestStoreKeepsArchives(t *testing.T) {
	f := newFixture(t, Config{})
	store := &memManifests{}
	f.m.Archive.Manifests = store
	// A name another server reserved is passed over.
	name := f.add("authentication", 100, 1000, 3)
	if _, err := store.Reserve(context.Background(), Manifest{Index: name}, func(string) bool { return false }); err != nil {
		t.Fatal(err)
	}
	if err := f.m.SetPolicy("authentication", &Policy{KeepDays: 30, Archive: true}); err != nil {
		t.Fatal(err)
	}
	run, err := f.m.Run(context.Background(), TriggerManual, "")
	if err != nil || run.Archived != 1 {
		t.Fatalf("run = %+v, %v", run, err)
	}
	list, _, _ := f.m.Archive.List()
	if len(list) != 1 || list[0].ID != name+".2" || list[0].State != ManifestComplete {
		t.Fatalf("archives = %+v", list)
	}
	if m, err := f.m.Archive.ReadManifestFile(name + ".2"); err != nil || m.ID != name+".2" {
		t.Errorf("manifest file: %+v, %v", m, err)
	}
	// A pending manifest is not a copy: the index is archived again, not
	// just deleted, if it comes back.
	if _, err := f.m.Archive.Get(name); !errors.Is(err, ErrArchiveNotFound) {
		t.Errorf("pending archive found: %v", err)
	}
}

func TestClaimStopsAStep(t *testing.T) {
	f := newFixture(t, Config{})
	name := f.add("authentication", 100, 1000, 3)
	if err := f.m.SetPolicy("authentication", &Policy{KeepDays: 30}); err != nil {
		t.Fatal(err)
	}
	var claims []string
	f.m.Claim = func(_ context.Context, index, step string) error {
		claims = append(claims, step+" "+index)
		return errors.New("server b claimed it with epoch 7")
	}
	run, _ := f.m.Run(context.Background(), TriggerManual, "")
	if !f.exists(name) || run.Deleted != 0 || len(run.Errors) == 0 || !strings.Contains(run.Errors[0], "another server runs retention") {
		t.Fatalf("run = %+v", run)
	}
	if !slices.Contains(claims, "delete "+name) {
		t.Errorf("claims = %v", claims)
	}
}

func TestClaimBeforeDeleteAfterArchive(t *testing.T) {
	f := newFixture(t, Config{})
	name := f.add("authentication", 100, 1000, 3)
	if err := f.m.SetPolicy("authentication", &Policy{KeepDays: 30, Archive: true}); err != nil {
		t.Fatal(err)
	}
	var steps []string
	f.m.Claim = func(_ context.Context, index, step string) error {
		steps = append(steps, step)
		if step == ActionDelete {
			return errors.New("lost")
		}
		return nil
	}
	run, _ := f.m.Run(context.Background(), TriggerManual, "")
	if !f.exists(name) || run.Archived != 0 {
		t.Fatalf("run = %+v, exists %v", run, f.exists(name))
	}
	if !slices.Equal(steps, []string{ActionArchive, ActionDelete}) {
		t.Errorf("steps = %v", steps)
	}
}

func TestHeldBackWhenItCannotArchive(t *testing.T) {
	f := newFixture(t, Config{})
	name := f.add("authentication", 100, 1000, 3)
	if err := f.m.SetPolicy("authentication", &Policy{KeepDays: 30, Archive: true}); err != nil {
		t.Fatal(err)
	}
	f.m.CanArchive = func() (bool, string) { return false, "the archive folder is not the shared one" }
	run, _ := f.m.Run(context.Background(), TriggerManual, "")
	if !f.exists(name) || len(run.Errors) != 1 || !strings.Contains(run.Errors[0], "held back") {
		t.Fatalf("run = %+v", run)
	}
	if ov := f.m.Overview(context.Background()); ov.Archive.HeldBack == "" {
		t.Errorf("archive = %+v", ov.Archive)
	}
}

type memJobs struct {
	mu   sync.Mutex
	list []RestoreStatus
}

func (j *memJobs) Save(_ context.Context, l []RestoreStatus) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.list = slices.Clone(l)
	return nil
}

func (j *memJobs) Load(context.Context) ([]RestoreStatus, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	return slices.Clone(j.list), nil
}

type sinkHistory struct {
	runs []Run
	acts []Action
}

func (h *sinkHistory) Record(_ context.Context, run *Run, acts ...Action) error {
	if run != nil {
		h.runs = append(h.runs, *run)
	}
	h.acts = append(acts, h.acts...)
	return nil
}

func (h *sinkHistory) Recent(context.Context) (*Run, []Action, error) {
	if len(h.runs) == 0 {
		return nil, h.acts, nil
	}
	return &h.runs[len(h.runs)-1], h.acts, nil
}

func (h *sinkHistory) Source() string { return HistoryFromAudit }

func TestSharedRestoreProgressAndHistory(t *testing.T) {
	f := newFixture(t, Config{})
	jobs, hist := &memJobs{}, &sinkHistory{}
	f.m.Jobs, f.m.History = jobs, hist
	name := f.add("authentication", 100, 1000, 3)
	if err := f.m.SetPolicy("authentication", &Policy{KeepDays: 30, Archive: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.m.Run(context.Background(), TriggerManual, "admin"); err != nil {
		t.Fatal(err)
	}
	if len(hist.runs) != 1 || !slices.ContainsFunc(hist.acts, func(a Action) bool { return a.Action == ActionArchive && a.Index == name }) {
		t.Fatalf("history = %+v", hist)
	}
	if _, err := f.m.Restore(context.Background(), []string{name}, 3, "admin", true); err != nil {
		t.Fatal(err)
	}
	var last int64
	out, err := f.m.WaitRestores(context.Background(), []string{name}, func(done, total int64) { last = total })
	if err != nil || len(out) != 1 || out[0].State != RestoreDone || last != 3 {
		t.Fatalf("restores = %+v, %v (total %d)", out, err, last)
	}
	if list, _ := jobs.Load(context.Background()); len(list) != 1 || list[0].State != RestoreDone {
		t.Errorf("shared jobs = %+v", list)
	}
	// A server that does not run retention shows the shared progress.
	other := newFixture(t, Config{})
	other.m.Jobs = jobs
	other.m.Leader = func() (bool, string) { return false, "a" }
	if got := other.m.RestoreStatuses(context.Background()); len(got) != 1 || got[0].ID != name {
		t.Errorf("other server's restores = %+v", got)
	}
	if ov := f.m.Overview(context.Background()); ov.HistorySource != HistoryFromAudit {
		t.Errorf("history source = %q", ov.HistorySource)
	}
}
