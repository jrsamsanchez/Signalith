package clusterarchive

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/audit"
	"github.com/jrsamsanchez/signalith/internal/cluster/ostest"
	"github.com/jrsamsanchez/signalith/internal/retention"
	"github.com/jrsamsanchez/signalith/internal/shared"
	"github.com/jrsamsanchez/signalith/internal/store"
)

const prefix = "signalith"

func newClient(t *testing.T) *store.Client {
	t.Helper()
	fake := ostest.New(t)
	return store.New(store.Config{URL: fake.URL})
}

func manifest(index string) retention.Manifest {
	return retention.Manifest{Format: retention.ArchiveFormat, Index: index, Category: "authentication", Day: "2026-07-01", Docs: 3}
}

func TestReserveGivesEachServerItsOwnID(t *testing.T) {
	cl := newClient(t)
	a := &Manifests{Client: cl, Prefix: prefix, Server: "a", NodeID: "na"}
	b := &Manifests{Client: cl, Prefix: prefix, Server: "b", NodeID: "nb"}
	const index = "signalith-authentication-2026.07.01"
	var wg sync.WaitGroup
	ids := make([]string, 2)
	errs := make([]error, 2)
	for i, s := range []*Manifests{a, b} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ids[i], errs[i] = s.Reserve(context.Background(), manifest(index), nil)
		}()
	}
	wg.Wait()
	if errs[0] != nil || errs[1] != nil || ids[0] == ids[1] {
		t.Fatalf("ids %v, errors %v", ids, errs)
	}
	slices.Sort(ids)
	if !slices.Equal(ids, []string{index, index + ".2"}) {
		t.Errorf("ids = %v", ids)
	}
	// Pending manifests are not listed, nor found.
	if list, _, err := a.List(context.Background()); err != nil || len(list) != 0 {
		t.Fatalf("list = %+v, %v", list, err)
	}
	if _, err := a.Get(context.Background(), ids[0]); !errors.Is(err, retention.ErrArchiveNotFound) {
		t.Errorf("get pending = %v", err)
	}
	// Only the server that reserved an ID completes it.
	owner, other := a, b
	if d, _, _, _ := read(context.Background(), cl, prefix, ArchiveDocID(ids[0])); d.NodeID == "nb" {
		owner, other = b, a
	}
	m := manifest(index)
	m.ID, m.File = ids[0], ids[0]+".ndjson.gz"
	if err := other.Complete(context.Background(), m); err == nil {
		t.Error("another server completed the reservation")
	}
	if err := owner.Complete(context.Background(), m); err != nil {
		t.Fatal(err)
	}
	got, err := a.Get(context.Background(), ids[0])
	if err != nil || got.State != retention.ManifestComplete || got.Docs != 3 {
		t.Fatalf("get = %+v, %v", got, err)
	}
	// Abandon leaves a complete manifest alone, and drops a pending one.
	if err := owner.Abandon(context.Background(), ids[0]); err != nil {
		t.Fatal(err)
	}
	if err := other.Abandon(context.Background(), ids[1]); err != nil {
		t.Fatal(err)
	}
	if list, _, _ := a.List(context.Background()); len(list) != 1 || list[0].ID != ids[0] {
		t.Errorf("list = %+v", list)
	}
	if _, _, found, _ := read(context.Background(), cl, prefix, ArchiveDocID(ids[1])); found {
		t.Error("the abandoned reservation is still there")
	}
}

func TestHousekeepRemovesOldPending(t *testing.T) {
	cl := newClient(t)
	dir := t.TempDir()
	clock := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	s := &Manifests{Client: cl, Prefix: prefix, Server: "a", NodeID: "na", Now: func() time.Time { return clock }}
	id, err := s.Reserve(context.Background(), manifest("signalith-authentication-2026.07.01"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, id+".ndjson.gz"), []byte("x"), 0o666); err != nil {
		t.Fatal(err)
	}
	if n, err := s.Housekeep(context.Background(), dir); err != nil || n != 0 {
		t.Fatalf("young pending removed: %d, %v", n, err)
	}
	clock = clock.Add(PendingAge + time.Minute)
	if n, err := s.Housekeep(context.Background(), dir); err != nil || n != 1 {
		t.Fatalf("housekeep = %d, %v", n, err)
	}
	if _, err := os.Stat(filepath.Join(dir, id+".ndjson.gz")); !os.IsNotExist(err) {
		t.Errorf("the pending archive's file is still there: %v", err)
	}
}

func TestArchiveWritesThroughTheStore(t *testing.T) {
	cl := newClient(t)
	dir := t.TempDir()
	mem := retention.NewMemory()
	const index = "signalith-authentication-2026.07.01"
	mem.AddIndex(index, 100, retention.Doc{ID: "1", Source: json.RawMessage(`{"a":1}`)})
	// Two servers share the folder; one archive of the index exists.
	store := &Manifests{Client: cl, Prefix: prefix, Server: "a", NodeID: "na"}
	ar := &retention.Archive{Dir: dir, Manifests: store, Server: "a"}
	m1, err := ar.Write(context.Background(), mem, retention.Source{Index: index, Category: "authentication", Day: "2026-07-01"}, 1)
	if err != nil {
		t.Fatal(err)
	}
	other := &retention.Archive{Dir: dir, Server: "b", Manifests: &Manifests{Client: cl, Prefix: prefix, Server: "b", NodeID: "nb"}}
	m2, err := other.Write(context.Background(), mem, retention.Source{Index: index, Category: "authentication", Day: "2026-07-01"}, 1)
	if err != nil {
		t.Fatal(err)
	}
	if m1.ID == m2.ID || m2.Server != "b" || m2.State != retention.ManifestComplete {
		t.Fatalf("manifests %+v and %+v", m1, m2)
	}
	list, _, err := ar.List()
	if err != nil || len(list) != 2 {
		t.Fatalf("list = %+v, %v", list, err)
	}
	if err := ar.Verify(list[1]); err != nil {
		t.Error(err)
	}
}

func TestClaimRefusesALowerEpoch(t *testing.T) {
	cl := newClient(t)
	epochA, epochB := int64(3), int64(4)
	a := &Claimer{Client: cl, Prefix: prefix, Server: "a", NodeID: "na", Epoch: func() int64 { return epochA }}
	b := &Claimer{Client: cl, Prefix: prefix, Server: "b", NodeID: "nb", Epoch: func() int64 { return epochB }}
	const index = "signalith-authentication-2026.07.01"
	if err := a.Claim(context.Background(), index, retention.ActionArchive); err != nil {
		t.Fatal(err)
	}
	if err := b.Claim(context.Background(), index, retention.ActionDelete); err != nil {
		t.Fatal(err)
	}
	err := a.Claim(context.Background(), index, retention.ActionDelete)
	if !errors.Is(err, ErrSuperseded) || !strings.Contains(err.Error(), "epoch 4") {
		t.Fatalf("lower epoch claim = %v", err)
	}
	// While the lease is frozen nothing is written and nothing refused.
	a.Frozen = func() bool { return true }
	if err := a.Claim(context.Background(), index, retention.ActionDelete); err != nil {
		t.Errorf("frozen claim = %v", err)
	}
}

func TestJobs(t *testing.T) {
	cl := newClient(t)
	j := &Jobs{Client: cl, Prefix: prefix, Server: "a", NodeID: "na"}
	if list, err := j.Load(context.Background()); err != nil || len(list) != 0 {
		t.Fatalf("empty = %+v, %v", list, err)
	}
	in := []retention.RestoreStatus{{ID: "x", State: retention.RestoreRunning, Docs: 10, Restored: 4}}
	if err := j.Save(context.Background(), in); err != nil {
		t.Fatal(err)
	}
	if got, err := j.Load(context.Background()); err != nil || len(got) != 1 || got[0].Restored != 4 {
		t.Errorf("load = %+v, %v", got, err)
	}
}

// prefixAsAll stands in for OpenSearch's prefix query, which the fake does
// not have: every audit record here is a retention one.
type prefixAsAll struct{ *store.Client }

func (p prefixAsAll) Search(ctx context.Context, index string, body map[string]any) (map[string]any, error) {
	b, _ := json.Marshal(body)
	s := strings.ReplaceAll(string(b), `{"prefix":{"action":"retention."}}`, `{"match_all":{}}`)
	var out map[string]any
	_ = json.Unmarshal([]byte(s), &out)
	return p.Client.Search(ctx, index, out)
}

func TestHistoryAsAuditRecords(t *testing.T) {
	cl := newClient(t)
	sink := audit.NewSink(audit.SinkOptions{Dir: t.TempDir(), Client: cl, Prefix: prefix, Server: "a", NodeID: "na"})
	t.Cleanup(func() { sink.Close() })
	log := slog.New(audit.Handler(slog.NewTextHandler(&bytes.Buffer{}, nil), sink))
	h := &History{Client: prefixAsAll{cl}, Prefix: prefix, Log: log, Server: "a", NodeID: "na"}
	at := time.Date(2026, 10, 1, 1, 0, 0, 0, time.UTC)
	run := &retention.Run{Started: at, Finished: at, Trigger: retention.TriggerManual, Archived: 1, Errors: []string{}}
	act := retention.Action{Time: at, Action: retention.ActionArchive, Category: "authentication", Index: "signalith-authentication-2026.07.01",
		Reason: "Older than 90 days", Docs: 3, By: "admin"}
	if err := h.Record(context.Background(), run, act); err != nil {
		t.Fatal(err)
	}
	if err := sink.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	last, acts, err := h.Recent(context.Background())
	if err != nil || last == nil || last.Archived != 1 {
		t.Fatalf("last run = %+v, %v", last, err)
	}
	if len(acts) != 1 || acts[0].Index != act.Index || acts[0].Docs != 3 || acts[0].Server != "a" || acts[0].By != "admin" {
		t.Fatalf("actions = %+v", acts)
	}
}

func TestImporters(t *testing.T) {
	cl := newClient(t)
	dir := t.TempDir()
	mem := retention.NewMemory()
	const index = "signalith-authentication-2026.07.01"
	mem.AddIndex(index, 100, retention.Doc{ID: "1", Source: json.RawMessage(`{"a":1}`)})
	ar := &retention.Archive{Dir: filepath.Join(dir, "archive")}
	if _, err := ar.Write(context.Background(), mem, retention.Source{Index: index, Category: "authentication", Day: "2026-07-01"}, 1); err != nil {
		t.Fatal(err)
	}
	histFile := filepath.Join(dir, "retention_history.json")
	at := time.Date(2026, 10, 1, 1, 0, 0, 0, time.UTC)
	hist, _ := json.Marshal(map[string]any{
		"last_run": retention.Run{Started: at, Finished: at, Trigger: "schedule", Deleted: 2},
		"actions": []retention.Action{
			{Time: at, Action: retention.ActionDelete, Category: "authentication", Index: "signalith-authentication-2026.06.01", Reason: "Older than 90 days"},
			{Time: at.Add(-time.Hour), Action: retention.ActionArchive, Category: "authentication", Index: index, Reason: "Older than 90 days"},
		},
	})
	if err := os.WriteFile(histFile, hist, 0o666); err != nil {
		t.Fatal(err)
	}
	ims := Importers(ImportOptions{Client: cl, Prefix: prefix, HistoryFile: histFile, Archive: ar, Server: "a", NodeID: "na"})
	if len(ims) != 2 || ims[0].Name != shared.ImportRetentionHistory || ims[1].Name != shared.ImportArchives ||
		ims[0].MinLevel != shared.LevelSharedAudit || ims[1].MinLevel != shared.LevelSharedAudit {
		t.Fatalf("importers = %+v", ims)
	}
	for _, im := range ims {
		if h, err := im.Source(); err != nil || h == "" {
			t.Fatalf("%s source = %q, %v", im.Name, h, err)
		}
		// Twice: the second run adds nothing.
		for range 2 {
			if err := im.Run(context.Background(), "signalith"); err != nil {
				t.Fatalf("%s: %v", im.Name, err)
			}
		}
	}
	page, err := audit.Search(context.Background(), cl, prefix, audit.Query{Size: 50})
	if err != nil || len(page.Events) != 2 {
		t.Fatalf("audit records = %+v, %v", page, err)
	}
	h := &History{Client: prefixAsAll{cl}, Prefix: prefix}
	last, acts, err := h.Recent(context.Background())
	if err != nil || last == nil || last.Deleted != 2 || len(acts) != 2 || acts[0].Action != retention.ActionDelete || acts[0].Server != "a" {
		t.Fatalf("history = %+v %+v, %v", last, acts, err)
	}
	s := &Manifests{Client: cl, Prefix: prefix}
	list, _, err := s.List(context.Background())
	if err != nil || len(list) != 1 || list[0].ID != index {
		t.Fatalf("manifests = %+v, %v", list, err)
	}
	// Nothing to import gives an empty source.
	empty := Importers(ImportOptions{Client: cl, Prefix: prefix, HistoryFile: filepath.Join(dir, "none.json"), Archive: &retention.Archive{}})
	for _, im := range empty {
		if h, err := im.Source(); err != nil || h != "" {
			t.Errorf("%s source with nothing = %q, %v", im.Name, h, err)
		}
	}
}

func TestRestoreHandler(t *testing.T) {
	dir := t.TempDir()
	mem := retention.NewMemory()
	const index = "signalith-authentication-2026.07.01"
	docs := []retention.Doc{{ID: "1", Source: json.RawMessage(`{"a":1}`)}, {ID: "2", Source: json.RawMessage(`{"a":2}`)}}
	mem.AddIndex(index, 100, docs...)
	m := &retention.Manager{Cluster: mem, Prefix: prefix, Archive: &retention.Archive{Dir: dir},
		Store: retention.NewStore(filepath.Join(dir, "retention.yaml")), HistoryFile: filepath.Join(dir, "h.json")}
	man, err := m.Archive.Write(context.Background(), mem, retention.Source{Index: index, Category: "authentication", Day: "2026-07-01"}, 2)
	if err != nil {
		t.Fatal(err)
	}
	if err := mem.DeleteIndex(context.Background(), index); err != nil {
		t.Fatal(err)
	}
	var last [2]int64
	h := Handlers(m, func(_ context.Context, _ *shared.Request, done, total int64) error {
		last = [2]int64{done, total}
		return nil
	})[RequestArchiveRestore]
	args, _ := json.Marshal(ArchiveRestoreArgs{IDs: []string{man.ID}, KeepDays: 3, Confirm: true})
	req := &shared.Request{Type: RequestArchiveRestore, Args: args, RequestedBy: "admin"}
	if err := h(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	var res ArchiveRestoreResult
	if err := json.Unmarshal(req.Result, &res); err != nil || len(res.Restores) != 1 || res.Restores[0].State != retention.RestoreDone {
		t.Fatalf("result = %s, %v", req.Result, err)
	}
	if last != [2]int64{2, 2} {
		t.Errorf("progress = %v", last)
	}
	if _, got, ok := mem.Index(index); !ok || len(got) != 2 {
		t.Errorf("restored index: %v %d", ok, len(got))
	}
	if err := h(context.Background(), &shared.Request{Args: []byte(`{}`)}); err == nil {
		t.Error("a request without archives ran")
	}
}
