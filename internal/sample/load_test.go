package sample

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/assets"
	"github.com/jrsamsanchez/signalith/internal/cases"
	"github.com/jrsamsanchez/signalith/internal/datamodel"
	"github.com/jrsamsanchez/signalith/internal/findings"
	"github.com/jrsamsanchez/signalith/internal/intel"
	"github.com/jrsamsanchez/signalith/internal/store"
)

// fakeOS stands in for OpenSearch's REST calls the loader makes: it lists
// the indices holding sample documents, deletes from them (refusing on a
// write-blocked index, as OpenSearch does), counts what is left, and
// changes the block. The real thing is exercised by the integration test.
type fakeOS struct {
	mu      sync.Mutex
	indices []string // indices holding sample documents
	// late are indices whose sample documents a refresh has yet to make
	// searchable; onDelete runs after each delete, as writes that land
	// meanwhile would.
	late      []string
	onDelete  func(f *fakeOS)
	refreshes int
	blocked   map[string]bool // index.blocks.write
	deleted   []string        // indices deleted from
	cleared   map[string]bool // indices with no sample documents left
	log       []string        // refresh, search, count and delete:<index>, in order
}

func (f *fakeOS) Do(_ context.Context, method, path string, body, out any) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	index := strings.SplitN(strings.TrimPrefix(path, "/"), "/", 2)[0]
	reply := func(v any) error {
		if out == nil {
			return nil
		}
		b, _ := json.Marshal(v)
		return json.Unmarshal(b, out)
	}
	switch {
	case strings.Contains(path, "/_refresh"):
		f.log = append(f.log, "refresh")
		f.refreshes++
		f.indices = append(f.indices, f.late...)
		for _, ix := range f.late {
			delete(f.cleared, ix)
		}
		f.late = nil
		return nil
	case strings.Contains(path, "/_count"):
		f.log = append(f.log, "count")
		n := 0
		for _, ix := range f.indices {
			if !f.cleared[ix] {
				n++
			}
		}
		return reply(map[string]any{"count": n})
	case strings.Contains(path, "/_search"):
		f.log = append(f.log, "search")
		var buckets []map[string]any
		for _, ix := range f.indices {
			if !f.cleared[ix] {
				buckets = append(buckets, map[string]any{"key": ix, "doc_count": 1})
			}
		}
		return reply(map[string]any{"aggregations": map[string]any{"idx": map[string]any{"buckets": buckets}}})
	case strings.Contains(path, "/_delete_by_query"):
		if f.blocked[index] {
			return &store.Error{Status: http.StatusForbidden, Body: `{"error":{"type":"cluster_block_exception","reason":"index [` + index + `] blocked by: [FORBIDDEN/8/index write (api)];"}}`}
		}
		f.deleted = append(f.deleted, index)
		f.log = append(f.log, "delete:"+index)
		if f.cleared == nil {
			f.cleared = map[string]bool{}
		}
		f.cleared[index] = true
		if f.onDelete != nil {
			f.onDelete(f)
		}
		return reply(map[string]any{"deleted": 1})
	case method == "GET" && strings.Contains(path, "/_settings"):
		v := "false"
		if f.blocked[index] {
			v = "true"
		}
		return reply(map[string]any{index: map[string]any{"settings": map[string]any{"index.blocks.write": v}}})
	case method == "PUT" && strings.HasSuffix(path, "/_settings"):
		if f.blocked == nil {
			f.blocked = map[string]bool{}
		}
		f.blocked[index] = body.(map[string]any)["index.blocks.write"] == true
		return nil
	}
	return reply(map[string]any{})
}

// memDocs is the bit of OpenSearch the loader keeps its record in: one
// index of documents with versions, which a write that names an old
// version is refused, as OpenSearch refuses it. Servers that share one
// OpenSearch share one memDocs.
type memDocs struct {
	mu   sync.Mutex
	docs map[string]memDoc
	seq  int64
}

type memDoc struct {
	src json.RawMessage
	ver store.Version
}

func newMemDocs() *memDocs { return &memDocs{docs: map[string]memDoc{}} }

func (m *memDocs) key(index, id string) string { return index + "/" + id }

func (m *memDocs) next(body any) (memDoc, error) {
	b, err := json.Marshal(body)
	if err != nil {
		return memDoc{}, err
	}
	m.seq++
	return memDoc{src: b, ver: store.Version{SeqNo: m.seq, PrimaryTerm: 1, Version: m.seq}}, nil
}

func (m *memDocs) Get(_ context.Context, index, id string) (json.RawMessage, store.Version, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	d, ok := m.docs[m.key(index, id)]
	return d.src, d.ver, ok, nil
}

func (m *memDocs) Create(_ context.Context, index, id string, body any, _ bool) (store.Version, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.docs[m.key(index, id)]; ok {
		return store.Version{}, store.ErrExists
	}
	d, err := m.next(body)
	if err != nil {
		return store.Version{}, err
	}
	m.docs[m.key(index, id)] = d
	return d.ver, nil
}

func (m *memDocs) PutIf(_ context.Context, index, id string, body any, v store.Version, _ bool) (store.Version, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	cur, ok := m.docs[m.key(index, id)]
	switch {
	case !ok:
		return store.Version{}, store.ErrNotFound
	case !cur.ver.Same(v):
		return store.Version{}, store.ErrConflict
	}
	d, err := m.next(body)
	if err != nil {
		return store.Version{}, err
	}
	m.docs[m.key(index, id)] = d
	return d.ver, nil
}

func (m *memDocs) DeleteIf(_ context.Context, index, id string, v store.Version, _ bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cur, ok := m.docs[m.key(index, id)]
	switch {
	case !ok:
		return store.ErrNotFound
	case !cur.ver.Same(v):
		return store.ErrConflict
	}
	delete(m.docs, m.key(index, id))
	return nil
}

// put replaces the record as another process would, whatever its version.
func (m *memDocs) put(t *testing.T, doc stateDoc) {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	d, err := m.next(doc)
	if err != nil {
		t.Fatal(err)
	}
	m.docs[m.key("signalith_runtime", stateID)] = d
}

// record returns the record, or nil.
func (m *memDocs) record(t *testing.T) *stateDoc {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	d, ok := m.docs[m.key("signalith_runtime", stateID)]
	if !ok {
		return nil
	}
	var out stateDoc
	if err := json.Unmarshal(d.src, &out); err != nil {
		t.Fatal(err)
	}
	return &out
}

// fakeIntel is an in-memory IntelStore.
type fakeIntel struct{ inds []intel.Indicator }

func (f *fakeIntel) Add(_ context.Context, inds []intel.Indicator) error {
	f.inds = append(f.inds, inds...)
	return nil
}
func (f *fakeIntel) DeleteSource(_ context.Context, source string) (int, error) {
	var kept []intel.Indicator
	n := 0
	for _, ind := range f.inds {
		if ind.Source == source {
			n++
			continue
		}
		kept = append(kept, ind)
	}
	f.inds = kept
	return n, nil
}

// fakeBulk records the documents written; failAt makes that call (counted
// from 1) fail as an overloaded OpenSearch would.
type fakeBulk struct {
	mu     sync.Mutex
	docs   []store.IndexedDoc
	calls  int
	failAt int
	// rejectAll turns every document away, as indices that refuse writes
	// would.
	rejectAll bool
}

func (f *fakeBulk) Bulk(_ context.Context, docs []store.IndexedDoc) ([]store.BulkItemError, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.calls == f.failAt {
		return nil, &store.Error{Status: http.StatusTooManyRequests, Body: `{"error":{"type":"es_rejected_execution_exception","reason":"rejected"}}`}
	}
	if f.rejectAll {
		errs := make([]store.BulkItemError, len(docs))
		for i, d := range docs {
			errs[i] = store.BulkItemError{Index: d.Index, Pos: i, Type: "cluster_block_exception", Reason: "index [" + d.Index + "] blocked"}
		}
		return errs, nil
	}
	f.docs = append(f.docs, docs...)
	return nil, nil
}

// A user's asset list with a line the store cannot read: the server runs
// on with empty lists and leaves the file for the admin to fix.
const damagedAssets = "host,ip,cidr,owner,priority,category,bunit,location\n" +
	"real-dc,10.1.1.1,,IT,high,,Prod,\n" +
	"dc-01,10.20.0.10,,IT,critical,,Prod,\n" +
	"odd-box,10.1.1.2,,IT,urgent,,Prod,\n"

const userIdentities = "identity,name,email,manager,priority,category,bunit,watchlist\n" +
	"svc-backup,Real backup account,,,low,,Prod,\n"

func newTestLoader(t *testing.T, dir string) (*Loader, *assets.Store, *fakeOS, *fakeIntel, *fakeBulk) {
	t.Helper()
	lists, _ := assets.OpenStore(dir)
	fos := &fakeOS{indices: []string{"signalith-authentication-2026.10.09", "signalith-risk-2026.10.10"}}
	fi := &fakeIntel{}
	fb := &fakeBulk{}
	return &Loader{
		Prefix: "signalith", Bulk: fb, OS: fos, Intel: fi, Assets: lists,
		Findings: findings.NewMemory(), Cases: cases.NewMemory(), Docs: newMemDocs(),
		Server: "siem-a", Now: func() time.Time { return fixedNow },
	}, lists, fos, fi, fb
}

// seed records st as loaded (or partly loaded), as a load would have.
func seed(t *testing.T, l *Loader, st *State) {
	t.Helper()
	if _, err := l.Docs.Create(context.Background(), l.index(), stateID, stateDoc{Kind: stateKind, State: st}, false); err != nil {
		t.Fatal(err)
	}
}

func writeFile(t *testing.T, path, data string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(data), 0o640); err != nil {
		t.Fatal(err)
	}
}

func checkFile(t *testing.T, path, want string) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte(want)) {
		t.Errorf("%s changed:\n%s\nwant:\n%s", filepath.Base(path), got, want)
	}
}

// TestRemoveDeletesOnlyMarkedData: Remove deletes exactly what carries the
// load's marker. Findings and cases of the user's own about hosts and users
// that share a sample name stay, whenever they were created, and a case of
// the user's own is never deleted: sample findings are only unlinked.
func TestRemoveDeletesOnlyMarkedData(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	l, _, fos, fi, _ := newTestLoader(t, dir)
	id := "sample-20261013-115500"
	at := fixedNow.Add(-48 * time.Hour)
	fs, cs := l.Findings, l.Cases

	mk := func(fid, det, sample string, created time.Time, entity string) {
		f := &findings.Finding{ID: fid, DetectionID: det, Sample: sample, Severity: "high",
			Status: findings.StatusNew, Created: created, Updated: created,
			Entities: map[string]any{"risk_object": entity}}
		if err := fs.Create(ctx, f); err != nil {
			t.Fatal(err)
		}
	}
	mk("S1", "endpoint-credential-dumping", id, at, "ws-fin-07")
	mk("S2", "auth-brute-force", id, at, "db-01")
	mk("S3", "risk-threshold-exceeded", id, at, "dan.sato")
	mk("R1", "risk-threshold-exceeded", "", at, "dc-01")                         // real, a sample host's name
	mk("R2", "risk-multiple-tactics", "", fixedNow.Add(5*24*time.Hour), "dc-01") // real, long after the load
	mk("P1", "auth-password-spray", "", at, "someone.else")                      // real, unrelated

	for _, c := range []*cases.Case{
		{ID: "C1", Title: "Sample case", Sample: id, Findings: []string{"S1"}},
		{ID: "C2", Title: "Analyst case, mixed", Findings: []string{"S2", "P1"}},
		{ID: "C3", Title: "Analyst case, only sample findings", Findings: []string{"S3"}},
		{ID: "C4", Title: "Real investigation of dc-01", Findings: []string{"R1"}},
	} {
		c.Status, c.Created, c.Updated = findings.StatusInProgress, at, at
		if err := cs.Create(ctx, c); err != nil {
			t.Fatal(err)
		}
	}

	// A feed that happens to be called "sample" is the user's.
	_ = fi.Add(ctx, []intel.Indicator{
		{ID: "i1", Source: SampleIntelSource, Type: intel.TypeIP, Value: "203.0.113.45"},
		{ID: "i2", Source: intel.ManualSource, Type: intel.TypeIP, Value: "203.0.113.9"},
		{ID: "i3", Source: "sample", Type: intel.TypeIP, Value: "203.0.113.10"},
	})

	// The user's lists (one damaged) and the sample overlay.
	writeFile(t, filepath.Join(dir, assets.AssetsFile), damagedAssets)
	writeFile(t, filepath.Join(dir, assets.IdentitiesFile), userIdentities)
	if _, err := l.Assets.Reload(); err == nil {
		t.Fatal("the damaged asset list should not load")
	}
	d := Generate(Options{Now: fixedNow, Size: SizeSmall})
	if err := l.Assets.SetOverlay(d.Assets, d.Identities); err != nil {
		t.Fatal(err)
	}

	seed(t, l, &State{ID: id, Size: SizeSmall, LoadedAt: fixedNow, Start: d.Start, End: d.End, Cases: []string{"C1"}})
	if _, err := l.Remove(ctx, nil); err != nil {
		t.Fatalf("Remove: %v", err)
	}

	left := map[string]bool{}
	all, _, _ := fs.Search(ctx, findings.Filter{Limit: 100})
	for _, f := range all {
		left[f.ID] = true
	}
	for _, fid := range []string{"S1", "S2", "S3"} {
		if left[fid] {
			t.Errorf("sample finding %s should have been removed", fid)
		}
	}
	for _, fid := range []string{"R1", "R2", "P1"} {
		if !left[fid] {
			t.Errorf("finding %s is the user's and should have been kept", fid)
		}
	}

	if _, err := cs.Get(ctx, "C1"); err == nil {
		t.Error("the sample's own case C1 should have been deleted")
	}
	for cid, want := range map[string][]string{"C2": {"P1"}, "C3": nil, "C4": {"R1"}} {
		c, err := cs.Get(ctx, cid)
		if err != nil {
			t.Errorf("case %s is the user's and should have been kept: %v", cid, err)
			continue
		}
		if strings.Join(c.Findings, ",") != strings.Join(want, ",") {
			t.Errorf("case %s findings = %v, want %v", cid, c.Findings, want)
		}
	}

	var sources []string
	for _, ind := range fi.inds {
		sources = append(sources, ind.Source)
	}
	if strings.Join(sources, ",") != intel.ManualSource+",sample" {
		t.Errorf("intel left from sources %v, want the manual one and the user's feed called sample", sources)
	}

	// The overlay is gone and the user's files are as they were, the
	// damaged one included.
	for _, name := range []string{assets.OverlayAssetsFile, assets.OverlayIdentitiesFile} {
		if _, err := os.Stat(filepath.Join(dir, name)); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s should have been deleted: %v", name, err)
		}
	}
	if a, i := l.Assets.Overlay(); len(a)+len(i) != 0 {
		t.Errorf("overlay still holds %d assets and %d identities", len(a), len(i))
	}
	checkFile(t, filepath.Join(dir, assets.AssetsFile), damagedAssets)
	checkFile(t, filepath.Join(dir, assets.IdentitiesFile), userIdentities)

	if strings.Join(fos.deleted, ",") != strings.Join(fos.indices, ",") {
		t.Errorf("deleted from %v, want %v", fos.deleted, fos.indices)
	}
	if st, _ := l.Status(ctx); st != nil {
		t.Error("the record of the load should have been removed")
	}
	if rec := l.Docs.(*memDocs).record(t); rec != nil {
		t.Errorf("record left: %+v", rec)
	}
}

// TestRemoveLiftsWriteBlock: a day retention made read-only still has its
// sample events deleted, and is read-only again afterwards.
func TestRemoveLiftsWriteBlock(t *testing.T) {
	l, _, fos, _, _ := newTestLoader(t, t.TempDir())
	blocked := fos.indices[0]
	fos.blocked = map[string]bool{blocked: true}
	seed(t, l, &State{ID: "sample-x", Partial: true})
	if _, err := l.Remove(context.Background(), nil); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if strings.Join(fos.deleted, ",") != strings.Join(fos.indices, ",") {
		t.Errorf("deleted from %v, want %v", fos.deleted, fos.indices)
	}
	if !fos.blocked[blocked] {
		t.Errorf("%s should be read-only again", blocked)
	}
}

// TestLoadWritesOverlayNotUserLists: a load leaves the user's list files
// alone and a user's row always wins a lookup over a sample row for the
// same name. Events keep their own times back to six days ago, whatever
// the server's maximum event age, and the progress only moves forward.
func TestLoadWritesOverlayNotUserLists(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	const userAssets = "host,ip,cidr,owner,priority,category,bunit,location\ndc-01,10.20.0.10,,IT,critical,,Prod,\n"
	writeFile(t, filepath.Join(dir, assets.AssetsFile), userAssets)
	writeFile(t, filepath.Join(dir, assets.IdentitiesFile), userIdentities)
	l, lists, _, fi, fb := newTestLoader(t, dir)

	var pcts []int
	st, err := l.Load(ctx, SizeStandard, func(p Progress) { pcts = append(pcts, p.Percent) })
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if st.Partial || st.LoadedAt.IsZero() || st.Events == 0 || st.Indicators != len(fi.inds) {
		t.Errorf("state = %+v", st)
	}
	for i := 1; i < len(pcts); i++ {
		if pcts[i] < pcts[i-1] {
			t.Fatalf("progress went back: %v", pcts)
		}
	}
	if len(pcts) == 0 || pcts[len(pcts)-1] != 100 {
		t.Errorf("progress did not end at 100: %v", pcts)
	}

	checkFile(t, filepath.Join(dir, assets.AssetsFile), userAssets)
	checkFile(t, filepath.Join(dir, assets.IdentitiesFile), userIdentities)
	if a, ok := lists.Asset("dc-01"); !ok || a.BUnit != "Prod" {
		t.Errorf("dc-01 resolved to %+v; the user's row must win", a)
	}
	if i, ok := lists.Identity(`CORP\svc-backup`); !ok || i.BUnit != "Prod" {
		t.Errorf("svc-backup resolved to %+v; the user's row must win", i)
	}
	if a, ok := lists.Asset("ws-fin-07"); !ok || a.BUnit != SampleBUnit {
		t.Errorf("ws-fin-07 resolved to %+v, want the sample's row", a)
	}
	if _, ok := lists.Asset("10.10.1.26"); ok {
		t.Error("a private address resolved to a sample asset")
	}
	if len(lists.Assets()) != 1 {
		t.Errorf("Assets() = %d rows, want only the user's one", len(lists.Assets()))
	}
	if own := lists.Own(); own == lists {
		t.Error("Own() should leave the overlay out while it holds rows")
	} else if _, ok := own.Asset("ws-fin-07"); ok {
		t.Error("Own() still answers for a sample host")
	}

	// Every event kept its own time: none was moved to the load time.
	oldest := fixedNow
	for _, doc := range fb.docs {
		ts, _ := time.Parse(time.RFC3339Nano, doc.Doc["@timestamp"].(string))
		if ts.Before(oldest) {
			oldest = ts
		}
		if _, moved := doc.Doc["device_time"]; moved {
			t.Fatalf("an event was refiled at the load time: %v", doc.Doc)
		}
		if doc.Doc[datamodel.SampleField] != st.ID {
			t.Fatalf("an event lacks the marker: %v", doc.Doc)
		}
	}
	if oldest.After(st.Start.Add(24 * time.Hour)) {
		t.Errorf("oldest event %v; want the week back to %v", oldest, st.Start)
	}

	if _, err := l.Load(ctx, SizeSmall, nil); !errors.Is(err, ErrAlreadyLoaded) {
		t.Errorf("second Load = %v, want ErrAlreadyLoaded", err)
	}
}

// TestFailedLoadIsRemovable: a load that fails or is cancelled part way
// leaves a partial state, so the next load is refused and Remove takes out
// what it wrote.
func TestFailedLoadIsRemovable(t *testing.T) {
	ctx := context.Background()
	l, lists, _, fi, fb := newTestLoader(t, t.TempDir())
	fb.failAt = 2

	if _, err := l.Load(ctx, SizeStandard, nil); err == nil {
		t.Fatal("Load should fail when OpenSearch refuses a chunk")
	}
	st, err := l.Status(ctx)
	if err != nil || st == nil || !st.Partial || st.ID == "" {
		t.Fatalf("Status after a failed load = %+v, %v; want a partial state", st, err)
	}
	if _, err := l.Load(ctx, SizeSmall, nil); !errors.Is(err, ErrPartial) {
		t.Errorf("Load after a failed one = %v, want ErrPartial", err)
	}
	if _, err := l.Remove(ctx, nil); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if st, _ := l.Status(ctx); st != nil {
		t.Error("Remove should clear the partial state")
	}

	// Cancelled (Ctrl-C) after the intel and lists went in.
	cctx, cancel := context.WithCancel(ctx)
	defer cancel()
	_, err = l.Load(cctx, SizeSmall, func(p Progress) {
		if p.Phase == "Adding asset and identity context" {
			cancel()
		}
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled Load = %v", err)
	}
	if st, _ := l.Status(ctx); st == nil || !st.Partial {
		t.Fatalf("Status after a cancelled load = %+v; want partial", st)
	}
	if rec := l.Docs.(*memDocs).record(t); rec == nil || rec.Job != nil {
		t.Errorf("a stopped load should leave its record with no job running: %+v", rec)
	}
	if len(fi.inds) == 0 {
		t.Fatal("the cancelled load should have added its intel before stopping")
	}
	if _, err := l.Remove(ctx, nil); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if a, i := lists.Overlay(); len(fi.inds)+len(a)+len(i) != 0 {
		t.Errorf("left after Remove: %d indicators, %d assets, %d identities", len(fi.inds), len(a), len(i))
	}
}

// testClock is a monotonic clock a test moves on by hand.
type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *testClock) get() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *testClock) add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// useClock gives l a clock of the test's, and a pause that moves it on
// instead of waiting.
func useClock(l *Loader) *testClock {
	c := &testClock{now: time.Unix(1000, 0)}
	l.clock = c.get
	l.sleep = func(ctx context.Context, d time.Duration) error {
		c.add(d)
		return ctx.Err()
	}
	return c
}

// TestJobAcrossServers: a job running elsewhere (another server, or the
// command line) refuses a load and a removal and shows as activity; one
// whose record stood still for a minute is taken over by a removal.
func TestJobAcrossServers(t *testing.T) {
	ctx := context.Background()
	l, _, _, _, _ := newTestLoader(t, t.TempDir())
	clk := useClock(l)
	docs := l.Docs.(*memDocs)
	other := &Activity{Op: "load", Phase: "Writing events", Percent: 12, Server: "siem-b", Node: "n_b", Process: "p_b",
		PID: 999999, Started: time.Now(), Beat: time.Now()}
	docs.put(t, stateDoc{Kind: stateKind, State: &State{ID: "sample-b", Partial: true}, Job: other})

	if _, err := l.Load(ctx, SizeSmall, nil); !errors.Is(err, ErrBusy) {
		t.Fatalf("Load while siem-b loads = %v, want ErrBusy", err)
	}
	if _, err := l.Remove(ctx, nil); !errors.Is(err, ErrBusy) {
		t.Fatalf("Remove while siem-b loads = %v, want ErrBusy", err)
	}
	if a := l.Activity(ctx); a == nil || a.Phase != "Writing events" || a.Percent != 12 || a.Server != "siem-b" {
		t.Errorf("Activity = %+v", a)
	}

	// siem-b stopped mid-load: its record stands still.
	clk.add(StaleJob - time.Second)
	if a := l.Activity(ctx); a == nil {
		t.Fatal("a job quiet for less than a minute shows as stopped")
	}
	clk.add(time.Second)
	if a := l.Activity(ctx); a != nil {
		t.Errorf("a stopped job shows as activity: %+v", a)
	}
	if _, err := l.Load(ctx, SizeSmall, nil); !errors.Is(err, ErrPartial) {
		t.Fatalf("Load over siem-b's unfinished load = %v, want ErrPartial", err)
	}
	if st, err := l.Remove(ctx, nil); err != nil || st == nil || st.ID != "sample-b" {
		t.Fatalf("Remove of siem-b's unfinished load = %+v, %v", st, err)
	}
	if rec := docs.record(t); rec != nil {
		t.Errorf("record left after the removal: %+v", rec)
	}
	if _, err := l.Load(ctx, SizeSmall, nil); err != nil {
		t.Fatalf("Load once clear: %v", err)
	}
	if rec := docs.record(t); rec == nil || rec.Job != nil || rec.State.Partial {
		t.Errorf("record after the load: %+v", rec)
	}
}

// TestServersShareOneLoad: two servers that share one OpenSearch see one
// load. The second refuses to load again, can remove what the first
// loaded, and each server's asset and identity overlay follows.
func TestServersShareOneLoad(t *testing.T) {
	ctx := context.Background()
	a, listsA, _, _, _ := newTestLoader(t, t.TempDir())
	b, listsB, _, _, _ := newTestLoader(t, t.TempDir())
	b.Docs, b.Server = a.Docs, "siem-b"

	if _, err := a.Load(ctx, SizeSmall, nil); err != nil {
		t.Fatalf("load on siem-a: %v", err)
	}
	if st, err := b.Status(ctx); err != nil || st == nil || st.Partial {
		t.Fatalf("siem-b sees %+v, %v; want the load", st, err)
	}
	if _, err := b.Load(ctx, SizeSmall, nil); !errors.Is(err, ErrAlreadyLoaded) {
		t.Errorf("second load on siem-b = %v, want ErrAlreadyLoaded", err)
	}
	if _, ok := listsB.Asset("ws-fin-07"); ok {
		t.Fatal("siem-b has the sample's context before syncing")
	}
	if err := b.SyncLists(ctx); err != nil {
		t.Fatal(err)
	}
	if as, _ := listsB.Overlay(); len(as) == 0 {
		t.Error("siem-b did not add the sample's context")
	}
	if a, ok := listsB.Asset("ws-fin-07"); !ok || a.BUnit != SampleBUnit {
		t.Errorf("siem-b: ws-fin-07 = %+v", a)
	}

	if _, err := b.Remove(ctx, nil); err != nil {
		t.Fatalf("remove on siem-b: %v", err)
	}
	if st, _ := a.Status(ctx); st != nil {
		t.Errorf("siem-a still sees %+v", st)
	}
	if as, _ := listsA.Overlay(); len(as) == 0 {
		t.Fatal("siem-a lost its context before syncing; the test proves nothing")
	}
	if err := a.SyncLists(ctx); err != nil {
		t.Fatal(err)
	}
	if as, ids := listsA.Overlay(); len(as)+len(ids) != 0 {
		t.Errorf("siem-a kept %d sample assets and %d identities after the removal", len(as), len(ids))
	}
}

// TestJobTakenOver: a job whose record another process changed under it
// (it took the job for stopped) stops, and says so.
func TestJobTakenOver(t *testing.T) {
	ctx := context.Background()
	l, _, _, _, _ := newTestLoader(t, t.TempDir())
	docs := l.Docs.(*memDocs)
	_, err := l.Load(ctx, SizeSmall, func(p Progress) {
		if p.Phase == "Adding threat intel" {
			rec := docs.record(t)
			rec.Job = &Activity{Op: "remove", Server: "siem-b", Beat: time.Now()}
			rec.Owner = "siem-b-removal"
			docs.put(t, *rec)
		}
	})
	if !errors.Is(err, ErrTakenOver) {
		t.Fatalf("Load = %v, want ErrTakenOver", err)
	}
	if rec := docs.record(t); rec == nil || rec.Job == nil || rec.Job.Server != "siem-b" {
		t.Errorf("the job that was taken over wrote its record after all: %+v", rec)
	}
}

// TestRemoveUnnamedRecordDeletesNothing: a record that names no load (one
// with no state, or a state with no ID: a write gone wrong, or one made by
// hand) gives Remove nothing to find the sample by. Remove then deletes no
// events, findings or investigations, where an empty marker used to reach
// every one of them; it removes only what is the sample's whatever the
// load (its threat intel and asset and identity entries) and the record,
// so a load can start again.
func TestRemoveUnnamedRecordDeletesNothing(t *testing.T) {
	for _, tc := range []struct {
		name string
		body any
	}{
		{"no state", map[string]any{"kind": stateKind, "body": map[string]any{}}},
		{"empty ID, loaded", stateDoc{Kind: stateKind, State: &State{Size: SizeSmall, LoadedAt: fixedNow}}},
		{"empty ID, unfinished", stateDoc{Kind: stateKind, State: &State{Partial: true}}},
		{"empty ID, removal unfinished", stateDoc{Kind: stateKind, State: &State{Partial: true, Removing: true}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			dir := t.TempDir()
			l, _, fos, fi, _ := newTestLoader(t, dir)
			at := fixedNow.Add(-time.Hour)
			for _, f := range []*findings.Finding{
				{ID: "R1", DetectionID: "auth-brute-force", Status: findings.StatusNew, Created: at, Updated: at},
				{ID: "R2", DetectionID: "auth-password-spray", Status: findings.StatusNew, Created: at, Updated: at},
				{ID: "R3", DetectionID: "risk-threshold-exceeded", Status: findings.StatusNew, Created: at, Updated: at},
			} {
				if err := l.Findings.Create(ctx, f); err != nil {
					t.Fatal(err)
				}
			}
			if err := l.Cases.Create(ctx, &cases.Case{ID: "C1", Title: "Real investigation", Status: findings.StatusInProgress,
				Findings: []string{"R1"}, Created: at, Updated: at}); err != nil {
				t.Fatal(err)
			}
			_ = fi.Add(ctx, []intel.Indicator{
				{ID: "i1", Source: SampleIntelSource, Type: intel.TypeIP, Value: "203.0.113.45"},
				{ID: "i2", Source: intel.ManualSource, Type: intel.TypeIP, Value: "203.0.113.9"},
			})
			d := Generate(Options{Now: fixedNow, Size: SizeSmall})
			if err := l.Assets.SetOverlay(d.Assets, d.Identities); err != nil {
				t.Fatal(err)
			}
			l.Docs.(*memDocs).set(t, stateID, tc.body)

			st, err := l.Status(ctx)
			if err != nil || st == nil {
				t.Fatalf("status = %+v, %v; want the record shown, to be removed", st, err)
			}
			if _, err := l.Remove(ctx, nil); !errors.Is(err, ErrUnnamedLoad) {
				t.Fatalf("Remove = %v, want ErrUnnamedLoad", err)
			}

			if all, total, _ := l.Findings.Search(ctx, findings.Filter{Limit: 100}); total != 3 || len(all) != 3 {
				t.Errorf("%d findings left, want all 3 of the user's", total)
			}
			if c, err := l.Cases.Get(ctx, "C1"); err != nil || strings.Join(c.Findings, ",") != "R1" {
				t.Errorf("the user's case = %+v, %v; want it kept as it was", c, err)
			}
			for _, op := range fos.log {
				if op == "search" || op == "count" || strings.HasPrefix(op, "delete:") {
					t.Errorf("OpenSearch was asked to %s events by an empty marker", op)
				}
			}
			if len(fi.inds) != 1 || fi.inds[0].Source != intel.ManualSource {
				t.Errorf("intel left = %+v, want only the user's own", fi.inds)
			}
			if a, i := l.Assets.Overlay(); len(a)+len(i) != 0 {
				t.Errorf("overlay still holds %d assets and %d identities", len(a), len(i))
			}
			if rec := l.Docs.(*memDocs).record(t); rec != nil {
				t.Errorf("record left: %+v", rec)
			}
			// A load can start again.
			if st, err := l.Status(ctx); st != nil || err != nil {
				t.Errorf("status after = %+v, %v; want nothing loaded", st, err)
			}
		})
	}
}

// TestMarkerHelpersRefuseEmptyID: the loader's own searches and deletes by
// marker refuse an empty load ID rather than reach more than the sample.
func TestMarkerHelpersRefuseEmptyID(t *testing.T) {
	ctx := context.Background()
	l, _, fos, _, _ := newTestLoader(t, t.TempDir())
	r := &reporter{}
	if _, err := l.sampleFindingIDs(ctx, ""); !errors.Is(err, errNoLoadID) {
		t.Errorf("sampleFindingIDs = %v", err)
	}
	if err := l.removeCases(ctx, "", nil); !errors.Is(err, errNoLoadID) {
		t.Errorf("removeCases = %v", err)
	}
	if err := l.removeFindings(ctx, "", nil); !errors.Is(err, errNoLoadID) {
		t.Errorf("removeFindings = %v", err)
	}
	if err := l.deleteBySample(ctx, "", r); !errors.Is(err, errNoLoadID) {
		t.Errorf("deleteBySample = %v", err)
	}
	if err := l.deleteIn(ctx, "signalith-other-2026.10.13", ""); !errors.Is(err, errNoLoadID) {
		t.Errorf("deleteIn = %v", err)
	}
	if err := l.sweep(ctx, "", r); !errors.Is(err, errNoLoadID) {
		t.Errorf("sweep = %v", err)
	}
	for _, op := range fos.log {
		if op != "refresh" {
			t.Errorf("OpenSearch was asked to %s with an empty load ID", op)
		}
	}
}
