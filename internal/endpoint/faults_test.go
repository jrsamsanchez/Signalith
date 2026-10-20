// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package endpoint

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/store"
)

// faultDocs is MemoryDocs whose calls can fail: fail returns the error
// for an operation on a document (search has no ID).
type faultDocs struct {
	*MemoryDocs
	mu    sync.Mutex
	fail  func(op, id string) error
	doErr error
}

func (f *faultDocs) check(op, id string) error {
	f.mu.Lock()
	fn := f.fail
	f.mu.Unlock()
	if fn == nil {
		return nil
	}
	return fn(op, id)
}

func (f *faultDocs) set(fn func(op, id string) error) {
	f.mu.Lock()
	f.fail = fn
	f.mu.Unlock()
}

// failOn fails op on documents whose ID has part in it.
func failOn(op, part string, err error) func(string, string) error {
	return func(o, id string) error {
		if o == op && strings.Contains(id, part) {
			return err
		}
		return nil
	}
}

func (f *faultDocs) Do(ctx context.Context, m, p string, b, out any) error { return f.doErr }
func (f *faultDocs) Get(ctx context.Context, idx, id string) (json.RawMessage, store.Version, bool, error) {
	if err := f.check("get", id); err != nil {
		return nil, store.Version{}, false, err
	}
	return f.MemoryDocs.Get(ctx, idx, id)
}
func (f *faultDocs) Create(ctx context.Context, idx, id string, b any, r bool) (store.Version, error) {
	if err := f.check("create", id); err != nil {
		return store.Version{}, err
	}
	return f.MemoryDocs.Create(ctx, idx, id, b, r)
}
func (f *faultDocs) PutIf(ctx context.Context, idx, id string, b any, v store.Version, r bool) (store.Version, error) {
	if err := f.check("putif", id); err != nil {
		return store.Version{}, err
	}
	return f.MemoryDocs.PutIf(ctx, idx, id, b, v, r)
}
func (f *faultDocs) Update(ctx context.Context, idx, id string, fields map[string]any, r bool) (store.Version, error) {
	if err := f.check("update", id); err != nil {
		return store.Version{}, err
	}
	return f.MemoryDocs.Update(ctx, idx, id, fields, r)
}
func (f *faultDocs) DeleteIf(ctx context.Context, idx, id string, v store.Version, r bool) error {
	if err := f.check("delete", id); err != nil {
		return err
	}
	return f.MemoryDocs.DeleteIf(ctx, idx, id, v, r)
}
func (f *faultDocs) SearchDocs(ctx context.Context, idx string, q map[string]any) ([]store.Doc, error) {
	if err := f.check("search", ""); err != nil {
		return nil, err
	}
	return f.MemoryDocs.SearchDocs(ctx, idx, q)
}

var errDown = errors.New("opensearch down")

func faultStore() (*Store, *faultDocs, *time.Time) {
	d := &faultDocs{MemoryDocs: NewMemoryDocs()}
	s := NewStore(d, "sig")
	now := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	s.Now = func() time.Time { return now }
	return s, d, &now
}

func TestEnsureIndex(t *testing.T) {
	s, d, _ := faultStore()
	if err := s.EnsureIndex(context.Background()); err != nil {
		t.Errorf("new index = %v", err)
	}
	d.doErr = &store.Error{Status: http.StatusBadRequest, Body: `{"error":{"type":"resource_already_exists_exception"}}`}
	if err := s.EnsureIndex(context.Background()); err != nil {
		t.Errorf("existing index = %v", err)
	}
	d.doErr = &store.Error{Status: http.StatusForbidden, Body: "no"}
	if err := s.EnsureIndex(context.Background()); err == nil {
		t.Error("a refused index was taken")
	}
	if props := properties(); props["last_seen"].(map[string]any)["type"] != "date" || props["kind"].(map[string]any)["type"] != "keyword" {
		t.Errorf("properties = %v", props)
	}
	if (&InputError{Msg: "m"}).Error() != "m" {
		t.Error("InputError")
	}
}

func TestStoreFailures(t *testing.T) {
	ctx := context.Background()
	s, d, now := faultStore()
	n, key := enroll(t, s, "uuid-1", "web1")

	for _, c := range []struct {
		name string
		fail func(string, string) error
		run  func() error
	}{
		{"enroll: blocked read", failOn("get", "blocked:", errDown), func() error { return s.Enroll(ctx, &Node{ID: "x1", HostIdentifier: "h"}) }},
		{"enroll: search", failOn("search", "", errDown), func() error { return s.Enroll(ctx, &Node{ID: "x1", HostIdentifier: "h"}) }},
		{"enroll: old record", failOn("delete", "node:", errDown), func() error { return s.Enroll(ctx, &Node{ID: "x2", HostIdentifier: "uuid-1"}) }},
		{"enroll: create", failOn("create", "node:", errDown), func() error { return s.Enroll(ctx, &Node{ID: "x3"}) }},
		{"node", failOn("get", "node:", errDown), func() error { _, err := s.Node(ctx, n.ID); return err }},
		{"nodes", failOn("search", "", errDown), func() error { _, err := s.Nodes(ctx); return err }},
		{"remove: read", failOn("get", "node:", errDown), func() error { _, err := s.Remove(ctx, n.ID, false, "sam"); return err }},
		{"remove: block", failOn("create", "blocked:", errDown), func() error { _, err := s.Remove(ctx, n.ID, true, "sam"); return err }},
		{"remove: delete", failOn("delete", "node:", errDown), func() error { _, err := s.Remove(ctx, n.ID, false, "sam"); return err }},
		{"blocked", failOn("search", "", errDown), func() error { _, err := s.BlockedHosts(ctx); return err }},
		{"unblock: read", failOn("get", "blocked:", errDown), func() error { return s.Unblock(ctx, "uuid-1") }},
		{"revoke: search", failOn("search", "", errDown), func() error { _, err := s.RevokeToken(ctx, "t1"); return err }},
		{"checks: read", failOn("get", "chk:", errDown), func() error { return s.SaveChecks(ctx, n, nil) }},
		{"checks: search", failOn("search", "", errDown), func() error { _, err := s.Checks(ctx); return err }},
		{"host checks", failOn("get", "chk:", errDown), func() error { _, err := s.HostCheckResults(ctx, n.ID); return err }},
		{"settings", failOn("get", "settings", errDown), func() error { _, _, err := s.Settings(ctx); return err }},
		{"settings: create", failOn("create", "settings", errDown), func() error { return s.SaveSettings(ctx, DefaultSettings(), store.Version{}) }},
		{"live: create", failOn("create", "lq:", errDown), func() error { _, err := s.NewLiveQuery(ctx, "select 1", []string{n.ID}, "sam"); return err }},
		{"live: read", failOn("get", "lq:", errDown), func() error { _, _, err := s.LiveQuery(ctx, "abc"); return err }},
		{"pending", failOn("search", "", errDown), func() error { _, err := s.Pending(ctx, n); return err }},
		{"result: read", failOn("get", "lqr:", errDown), func() error { return s.SaveResult(ctx, n, "q", nil, 0, "") }},
		{"note config", failOn("update", "node:", errDown), func() error { return s.NoteConfig(ctx, n, "h2") }},
		{"note ips", failOn("update", "node:", errDown), func() error { return s.NoteIPs(ctx, n, []string{"192.0.2.9"}) }},
		{"flush", failOn("update", "node:", errDown), func() error { s.Seen(n, "192.0.2.1"); return s.Flush(ctx) }},
	} {
		d.set(c.fail)
		if err := c.run(); !errors.Is(err, errDown) {
			t.Errorf("%s: %v", c.name, err)
		}
		d.set(nil)
	}

	// A remove that loses a race with another still counts.
	d.set(failOn("delete", "node:", store.ErrNotFound))
	if _, err := s.Remove(ctx, n.ID, false, "sam"); err != nil {
		t.Errorf("remove gone = %v", err)
	}
	d.set(nil)
	if _, err := s.Remove(ctx, n.ID, false, "sam"); err != nil {
		t.Errorf("remove = %v", err)
	}
	if _, err := s.Remove(ctx, n.ID, false, "sam"); !errors.Is(err, ErrNotFound) {
		t.Errorf("remove again = %v", err)
	}

	// Authenticate: a failed read is not cached as "no such node".
	n2, key2 := enroll(t, s, "uuid-2", "web2")
	*now = now.Add(time.Minute)
	d.set(failOn("get", "node:", errDown))
	if _, err := s.Authenticate(ctx, key2); !errors.Is(err, errDown) {
		t.Errorf("authenticate while down = %v", err)
	}
	d.set(nil)
	if got, err := s.Authenticate(ctx, key2); err != nil || got.ID != n2.ID {
		t.Errorf("authenticate = %v %v", got, err)
	}
	// An unknown key is cached as unknown.
	if _, err := s.Authenticate(ctx, key); !errors.Is(err, ErrNotFound) {
		t.Errorf("removed key = %v", err)
	}
	if _, err := s.Authenticate(ctx, key); !errors.Is(err, ErrNotFound) {
		t.Errorf("removed key, cached = %v", err)
	}

	// A record that is not JSON.
	d.MemoryDocs.docs["node:bad"] = memDoc{src: json.RawMessage(`[`)}
	if _, err := s.Node(ctx, "bad"); err == nil {
		t.Error("a broken record was read")
	}
	if _, err := s.Remove(ctx, "bad", false, "sam"); err == nil {
		t.Error("a broken record was removed")
	}
	d.MemoryDocs.docs["node:empty"] = memDoc{src: json.RawMessage(`{"kind":"node"}`)}
	if nodes, err := s.Nodes(ctx); err != nil || len(nodes) != 1 {
		t.Errorf("nodes = %v %v", nodes, err)
	}
	d.MemoryDocs.docs["chk:"+n2.ID] = memDoc{src: json.RawMessage(`[`)}
	if _, err := s.HostCheckResults(ctx, n2.ID); err == nil {
		t.Error("broken checks were read")
	}
	d.MemoryDocs.docs["settings"] = memDoc{src: json.RawMessage(`[`)}
	if _, _, err := s.Settings(ctx); err == nil {
		t.Error("broken settings were read")
	}
	delete(d.MemoryDocs.docs, "settings")
	d.MemoryDocs.docs["lq:bad"] = memDoc{src: json.RawMessage(`[`)}
	if _, _, err := s.LiveQuery(ctx, "bad"); err == nil {
		t.Error("a broken live query was read")
	}
	if _, _, err := s.LiveQuery(ctx, "none"); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown live query = %v", err)
	}
	d.MemoryDocs.docs["lqr:bad:"+n2.ID] = memDoc{src: json.RawMessage(`[`)}
	if err := s.SaveResult(ctx, n2, "bad", nil, 0, ""); err == nil {
		t.Error("a broken result was saved over")
	}
	if err := s.Unblock(ctx, "never-blocked"); !errors.Is(err, ErrNotFound) {
		t.Errorf("unblock unknown = %v", err)
	}
}

func TestNodeNotes(t *testing.T) {
	ctx := context.Background()
	s, d, now := faultStore()
	n, key := enroll(t, s, "uuid-1", "web1")
	if err := s.NoteConfig(ctx, n, "h1"); err != nil {
		t.Fatal(err)
	}
	got, _ := s.Authenticate(ctx, key)
	if got.ConfigHash != "h1" {
		t.Errorf("config hash = %q", got.ConfigHash)
	}
	// The same configuration within the hour is not written again.
	d.set(failOn("update", "node:", errDown))
	if err := s.NoteConfig(ctx, got, "h1"); err != nil {
		t.Errorf("same config = %v", err)
	}
	d.set(nil)

	ips := []string{"192.0.2.2", "192.0.2.1"}
	for i := range 40 {
		ips = append(ips, fmt.Sprintf("198.51.100.%d", i+10))
	}
	if err := s.NoteIPs(ctx, got, ips); err != nil {
		t.Fatal(err)
	}
	got, _ = s.Authenticate(ctx, key)
	if len(got.IPs) != 32 || got.IPs[0] != "192.0.2.1" {
		t.Errorf("ips = %v", got.IPs)
	}
	d.set(failOn("update", "node:", errDown))
	if err := s.NoteIPs(ctx, got, append([]string(nil), got.IPs...)); err != nil {
		t.Errorf("same ips = %v", err)
	}
	d.set(nil)

	if err := s.NoteError(ctx, got, strings.Repeat("e", 600)); err != nil {
		t.Fatal(err)
	}
	stored, _ := s.Node(ctx, n.ID)
	if len(stored.LastError) != 500 || !stored.LastErrorAt.Equal(*now) {
		t.Errorf("last error = %d %v", len(stored.LastError), stored.LastErrorAt)
	}
	// A host removed meanwhile: notes are dropped.
	if _, err := s.Remove(ctx, n.ID, false, "sam"); err != nil {
		t.Fatal(err)
	}
	if err := s.NoteError(ctx, got, "x"); err != nil {
		t.Errorf("note on a removed host = %v", err)
	}

	// The node cache is emptied when full.
	s.mu.Lock()
	s.nodes = map[string]cachedNode{}
	for i := range maxCached {
		s.nodes[fmt.Sprint(i)] = cachedNode{}
	}
	s.cacheNode("new", nil)
	size := len(s.nodes)
	s.mu.Unlock()
	if size != 1 {
		t.Errorf("cache size = %d", size)
	}
}

func TestSettingsCacheAndChecks(t *testing.T) {
	ctx := context.Background()
	s, d, now := faultStore()
	set, err := s.CachedSettings(ctx)
	if err != nil || set.InventoryMinutes != 60 {
		t.Fatalf("defaults = %+v %v", set, err)
	}
	// Within the TTL the cached copy is used; past it, a failed read
	// keeps serving it.
	d.set(failOn("get", "settings", errDown))
	if _, err := s.CachedSettings(ctx); err != nil {
		t.Errorf("cached = %v", err)
	}
	*now = now.Add(time.Minute)
	if set, err := s.CachedSettings(ctx); err != nil || set.InventoryMinutes != 60 {
		t.Errorf("stale = %+v %v", set, err)
	}
	fresh, _, _ := faultStore()
	fresh.Docs.(*faultDocs).set(failOn("get", "settings", errDown))
	if _, err := fresh.CachedSettings(ctx); !errors.Is(err, errDown) {
		t.Errorf("no copy = %v", err)
	}
	d.set(nil)

	// Saving over a version.
	if err := s.SaveSettings(ctx, DefaultSettings(), store.Version{}); err != nil {
		t.Fatal(err)
	}
	_, v, _ := s.Settings(ctx)
	if err := s.SaveSettings(ctx, DefaultSettings(), v); err != nil {
		t.Errorf("save over = %v", err)
	}
	if err := s.SaveSettings(ctx, DefaultSettings(), v); !errors.Is(err, store.ErrConflict) {
		t.Errorf("stale save = %v", err)
	}

	// Validation.
	for name, mod := range map[string]func(*Settings){
		"check minutes": func(s *Settings) { s.CheckMinutes = 1 },
		"long path":     func(s *Settings) { s.FilePaths[Linux] = []string{"/" + strings.Repeat("a", maxPathLen)} },
		"many paths": func(s *Settings) {
			s.FilePaths[Linux] = nil
			for i := range maxPaths + 1 {
				s.FilePaths[Linux] = append(s.FilePaths[Linux], fmt.Sprintf("/p%d", i))
			}
		},
		"exclude": func(s *Settings) { s.ExcludePaths = map[string][]string{"beos": {"/x"}} },
	} {
		set := DefaultSettings()
		mod(&set)
		var ie *InputError
		if err := set.Validate(); !errors.As(err, &ie) {
			t.Errorf("%s: %v", name, err)
		}
	}

	// Checks: a stored document with no results, and one that keeps
	// changing until the tries run out.
	n, _ := enroll(t, s, "uuid-1", "web1")
	d.MemoryDocs.docs["chk:"+n.ID] = memDoc{src: json.RawMessage(`{"kind":"checks","node_id":"` + n.ID + `"}`), v: store.Version{SeqNo: 999, PrimaryTerm: 1}}
	if err := s.SaveChecks(ctx, n, []CheckResult{{ID: "c1", Result: "pass", At: *now}}); err != nil {
		t.Fatal(err)
	}
	if got, err := s.HostCheckResults(ctx, n.ID); err != nil || got["c1"].Result != "pass" {
		t.Errorf("checks = %v %v", got, err)
	}
	d.set(failOn("putif", "chk:", store.ErrConflict))
	if err := s.SaveChecks(ctx, n, []CheckResult{{ID: "c2", At: *now}}); !errors.Is(err, store.ErrConflict) {
		t.Errorf("always changing = %v", err)
	}
	d.set(failOn("putif", "chk:", errDown))
	if err := s.SaveChecks(ctx, n, nil); !errors.Is(err, errDown) {
		t.Errorf("checks write = %v", err)
	}
	d.set(nil)
}

func TestLiveQueryEdges(t *testing.T) {
	ctx := context.Background()
	s, d, now := faultStore()
	n, _ := enroll(t, s, "uuid-1", "web1")
	other, _ := enroll(t, s, "uuid-2", "web2")
	many := make([]string, maxLiveTargets+1)
	for _, c := range []struct {
		sql     string
		targets []string
	}{{strings.Repeat("x", maxSQLBytes+1), []string{n.ID}}, {"select 1", many}} {
		var ie *InputError
		if _, err := s.NewLiveQuery(ctx, c.sql, c.targets, "sam"); !errors.As(err, &ie) {
			t.Errorf("%d targets: %v", len(c.targets), err)
		}
	}
	q, err := s.NewLiveQuery(ctx, "select 1", []string{other.ID}, "sam")
	if err != nil {
		t.Fatal(err)
	}
	// Not for this host.
	if p, err := s.Pending(ctx, n); err != nil || len(p) != 0 {
		t.Errorf("pending for another = %v %v", p, err)
	}
	*now = now.Add(5 * time.Second)
	d.set(failOn("create", "lqr:", errDown))
	if _, err := s.Pending(ctx, other); !errors.Is(err, errDown) {
		t.Errorf("pending write = %v", err)
	}
	d.set(nil)
	if p, err := s.Pending(ctx, other); err != nil || p[q.ID] != "select 1" {
		t.Fatalf("pending = %v %v", p, err)
	}
	// A failure with no message, and a long one.
	if err := s.SaveResult(ctx, other, q.ID, nil, 1, ""); err != nil {
		t.Fatal(err)
	}
	_, res, err := s.LiveQuery(ctx, q.ID)
	if err != nil || len(res) != 1 || res[0].State != StateError || !strings.Contains(res[0].Error, "status 1") {
		t.Errorf("result = %+v %v", res, err)
	}
	if err := s.SaveResult(ctx, other, q.ID, nil, 0, strings.Repeat("m", 1200)); err != nil {
		t.Fatal(err)
	}
	_, res, _ = s.LiveQuery(ctx, q.ID)
	if len(res[0].Error) != 1000 {
		t.Errorf("long error = %d", len(res[0].Error))
	}
	// Another server answered first.
	d.set(failOn("putif", "lqr:", store.ErrConflict))
	if err := s.SaveResult(ctx, other, q.ID, nil, 0, ""); err != nil {
		t.Errorf("answered first = %v", err)
	}
	d.set(failOn("search", "", errDown))
	if _, _, err := s.LiveQuery(ctx, q.ID); !errors.Is(err, errDown) {
		t.Errorf("results search = %v", err)
	}
	d.set(nil)
}

func TestRevokeAndEnrollRaces(t *testing.T) {
	ctx := context.Background()
	s, d, _ := faultStore()
	for i := range 2 {
		n := &Node{ID: fmt.Sprintf("n%d", i), HostIdentifier: fmt.Sprintf("h%d", i), Hostname: "h", TokenID: "t1"}
		if err := s.Enroll(ctx, n); err != nil {
			t.Fatal(err)
		}
	}
	d.set(failOn("delete", "node:n0", store.ErrConflict))
	if n, err := s.RevokeToken(ctx, "t1"); err != nil || n != 1 {
		t.Errorf("revoke with a race = %d %v", n, err)
	}
	if err := s.Enroll(ctx, &Node{ID: "n2", HostIdentifier: "h2", Hostname: "h", TokenID: "t1"}); err != nil {
		t.Fatal(err)
	}
	d.set(failOn("delete", "node:", errDown))
	if _, err := s.RevokeToken(ctx, "t1"); !errors.Is(err, errDown) {
		t.Errorf("revoke failing = %v", err)
	}
	d.set(nil)

	// Hosts with the same name are listed by ID.
	nodes, err := s.Nodes(ctx)
	if err != nil || len(nodes) < 2 || nodes[0].ID > nodes[1].ID {
		t.Errorf("nodes = %v %v", nodes, err)
	}
	// Blocked hosts by name.
	for _, h := range []string{"zed", "abe"} {
		n := &Node{ID: "b" + h, HostIdentifier: "hid-" + h, Hostname: h}
		if err := s.Enroll(ctx, n); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Remove(ctx, n.ID, true, "sam"); err != nil {
			t.Fatal(err)
		}
	}
	if b, err := s.BlockedHosts(ctx); err != nil || len(b) != 2 || b[0].Hostname != "abe" {
		t.Errorf("blocked = %+v %v", b, err)
	}
	if matches(map[string]any{"prefix": map[string]any{}}, map[string]any{}) {
		t.Error("an unknown query matched")
	}

	// Run writes contact when stopped.
	n := &Node{ID: "runner", Hostname: "r"}
	if err := s.Enroll(ctx, n); err != nil {
		t.Fatal(err)
	}
	s.Seen(n, "192.0.2.7")
	rctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { s.Run(rctx, time.Hour); close(done) }()
	cancel()
	<-done
	if got, _ := s.Node(ctx, "runner"); got.Address != "192.0.2.7" {
		t.Errorf("not flushed: %+v", got)
	}
}
