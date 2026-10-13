package endpoint

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/store"
)

// testStore returns a store whose clock the test moves.
func testStore() (*Store, *MemoryDocs, *time.Time) {
	d := NewMemoryDocs()
	s := NewStore(d, "sig")
	now := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	s.Now = func() time.Time { return now }
	return s, d, &now
}

func enroll(t *testing.T, s *Store, hostID, hostname string) (*Node, string) {
	t.Helper()
	key, id := NewNodeKey()
	n := &Node{ID: id, HostIdentifier: hostID, Hostname: hostname, Platform: Linux, EnrolledAt: s.now()}
	if err := s.Enroll(context.Background(), n); err != nil {
		t.Fatal(err)
	}
	return n, key
}

func TestEnrollAuthenticateRemoveBlock(t *testing.T) {
	ctx := context.Background()
	s, _, now := testStore()
	n, key := enroll(t, s, "uuid-1", "web1")
	got, err := s.Authenticate(ctx, key)
	if err != nil || got.ID != n.ID {
		t.Fatalf("Authenticate = %v, %v", got, err)
	}
	if _, err := s.Authenticate(ctx, strings.Repeat("0", 64)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown key: %v", err)
	}
	if _, err := s.Authenticate(ctx, "short"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("short key: %v", err)
	}

	// Enrolling again replaces the earlier record and its key.
	n2, key2 := enroll(t, s, "uuid-1", "web1")
	nodes, _ := s.Nodes(ctx)
	if len(nodes) != 1 || nodes[0].ID != n2.ID {
		t.Fatalf("nodes after re-enroll = %+v", nodes)
	}
	*now = now.Add(nodeTTL + time.Second) // past the cached answer
	if _, err := s.Authenticate(ctx, key); !errors.Is(err, ErrNotFound) {
		t.Fatalf("old key still works: %v", err)
	}

	// Remove with block: the key stops working and enrolling is refused.
	if _, err := s.Remove(ctx, n2.ID, true, "admin"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Authenticate(ctx, key2); !errors.Is(err, ErrNotFound) {
		t.Fatalf("removed key still works: %v", err)
	}
	k3, id3 := NewNodeKey()
	_ = k3
	if err := s.Enroll(ctx, &Node{ID: id3, HostIdentifier: "uuid-1", Hostname: "web1"}); !errors.Is(err, ErrBlocked) {
		t.Fatalf("blocked host enrolled: %v", err)
	}
	bl, _ := s.BlockedHosts(ctx)
	if len(bl) != 1 || bl[0].Hostname != "web1" {
		t.Fatalf("blocked = %+v", bl)
	}
	if err := s.Unblock(ctx, "uuid-1"); err != nil {
		t.Fatal(err)
	}
	if err := s.Enroll(ctx, &Node{ID: id3, HostIdentifier: "uuid-1", Hostname: "web1"}); err != nil {
		t.Fatalf("unblocked host: %v", err)
	}
	if _, err := s.Remove(ctx, "nope", false, "admin"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("remove unknown: %v", err)
	}
}

func TestSeenFlushAndRevoke(t *testing.T) {
	ctx := context.Background()
	s, _, now := testStore()
	n, _ := enroll(t, s, "uuid-1", "web1")
	n.TokenID = ""
	*now = now.Add(time.Minute)
	s.Seen(n, "192.0.2.10")
	nodes, _ := s.Nodes(ctx)
	if !nodes[0].LastSeen.Equal(*now) || nodes[0].Address != "192.0.2.10" {
		t.Fatalf("pending note not merged: %+v", nodes[0])
	}
	if err := s.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	got, _ := s.Node(ctx, n.ID)
	if !got.LastSeen.Equal(*now) {
		t.Fatalf("last_seen not stored: %v", got.LastSeen)
	}

	key, id := NewNodeKey()
	_ = key
	if err := s.Enroll(ctx, &Node{ID: id, HostIdentifier: "uuid-2", Hostname: "db1", TokenID: "abc"}); err != nil {
		t.Fatal(err)
	}
	if c, err := s.RevokeToken(ctx, "abc"); err != nil || c != 1 {
		t.Fatalf("RevokeToken = %d, %v", c, err)
	}
	nodes, _ = s.Nodes(ctx)
	if len(nodes) != 1 || nodes[0].Hostname != "web1" {
		t.Fatalf("nodes after revoke = %+v", nodes)
	}
}

func TestSettingsSaveAndConflict(t *testing.T) {
	ctx := context.Background()
	s, _, _ := testStore()
	set, v, err := s.Settings(ctx)
	if err != nil || !v.IsZero() || !set.FIM || set.InventoryMinutes != 60 {
		t.Fatalf("defaults = %+v %v %v", set, v, err)
	}
	set.InventoryMinutes = 30
	if err := s.SaveSettings(ctx, set, v); err != nil {
		t.Fatal(err)
	}
	// A second save from the same stale version loses.
	if err := s.SaveSettings(ctx, set, v); !errors.Is(err, store.ErrConflict) && !errors.Is(err, store.ErrExists) {
		t.Fatalf("stale save: %v", err)
	}
	got, v2, _ := s.Settings(ctx)
	if got.InventoryMinutes != 30 || v2.IsZero() {
		t.Fatalf("saved = %+v", got)
	}
	bad := got
	bad.InventoryMinutes = 0
	var ie *InputError
	if err := s.SaveSettings(ctx, bad, v2); !errors.As(err, &ie) {
		t.Fatalf("invalid settings saved: %v", err)
	}
}

func TestChecksMergeAndDrop(t *testing.T) {
	ctx := context.Background()
	s, d, now := testStore()
	n, _ := enroll(t, s, "uuid-1", "web1")
	t0 := *now
	if err := s.SaveChecks(ctx, n, []CheckResult{{ID: "a", Result: "fail", At: t0}, {ID: "b", Result: "pass", At: t0}}); err != nil {
		t.Fatal(err)
	}
	// A newer result replaces; an older one does not.
	if err := s.SaveChecks(ctx, n, []CheckResult{{ID: "a", Result: "pass", At: t0.Add(time.Hour)}, {ID: "b", Result: "fail", At: t0.Add(-time.Hour)}}); err != nil {
		t.Fatal(err)
	}
	rs, err := s.HostCheckResults(ctx, n.ID)
	if err != nil || rs["a"].Result != "pass" || rs["b"].Result != "pass" {
		t.Fatalf("results = %+v, %v", rs, err)
	}
	all, _ := s.Checks(ctx)
	if len(all) != 1 || len(all[n.ID].Results) != 2 {
		t.Fatalf("Checks = %+v", all)
	}
	if _, err := s.Remove(ctx, n.ID, false, "admin"); err != nil {
		t.Fatal(err)
	}
	if _, _, found, _ := d.Get(ctx, "", checksDocID(n.ID)); found {
		t.Fatal("check results kept after the host was removed")
	}
}

func TestLiveQueryRunsOncePerHost(t *testing.T) {
	ctx := context.Background()
	s, _, now := testStore()
	a, _ := enroll(t, s, "uuid-a", "a")
	b, _ := enroll(t, s, "uuid-b", "b")
	var ie *InputError
	if _, err := s.NewLiveQuery(ctx, "  ", []string{a.ID}, "admin"); !errors.As(err, &ie) {
		t.Fatalf("empty SQL: %v", err)
	}
	if _, err := s.NewLiveQuery(ctx, "SELECT 1;", nil, "admin"); !errors.As(err, &ie) {
		t.Fatalf("no targets: %v", err)
	}
	q, err := s.NewLiveQuery(ctx, "SELECT 1;", []string{a.ID, b.ID}, "admin")
	if err != nil {
		t.Fatal(err)
	}
	p, err := s.Pending(ctx, a)
	if err != nil || p[q.ID] != "SELECT 1;" {
		t.Fatalf("Pending = %v, %v", p, err)
	}
	// A second poll (here or on another server) gets nothing.
	if p, _ := s.Pending(ctx, a); len(p) != 0 {
		t.Fatalf("query sent twice: %v", p)
	}
	if err := s.SaveResult(ctx, a, q.ID, []map[string]string{{"1": "1"}}, 0, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Pending(ctx, b); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveResult(ctx, b, q.ID, nil, 1, "no such table: nope"); err != nil {
		t.Fatal(err)
	}
	// A host it was never sent to cannot answer.
	c, _ := enroll(t, s, "uuid-c", "c")
	if err := s.SaveResult(ctx, c, q.ID, nil, 0, ""); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unsent result: %v", err)
	}
	_, res, err := s.LiveQuery(ctx, q.ID)
	if err != nil || len(res) != 2 {
		t.Fatalf("LiveQuery = %+v, %v", res, err)
	}
	if res[0].Hostname != "a" || res[0].State != StateDone || len(res[0].Rows) != 1 {
		t.Fatalf("a = %+v", res[0])
	}
	if res[1].State != StateError || res[1].Error != "no such table: nope" {
		t.Fatalf("b = %+v", res[1])
	}

	// Expired queries are no longer handed out.
	q2, _ := s.NewLiveQuery(ctx, "SELECT 2;", []string{c.ID}, "admin")
	*now = now.Add(liveQueryLife + time.Minute)
	if p, _ := s.Pending(ctx, c); p[q2.ID] != "" {
		t.Fatalf("expired query sent: %v", p)
	}
}

func TestCapRows(t *testing.T) {
	rows := make([]map[string]string, maxResultRows+5)
	for i := range rows {
		rows[i] = map[string]string{"v": "x"}
	}
	rows[0]["v"] = strings.Repeat("y", maxValueBytes+10)
	got, cut := capRows(rows)
	if !cut || len(got) != maxResultRows || len(got[0]["v"]) != maxValueBytes {
		t.Fatalf("capRows: cut=%v rows=%d len=%d", cut, len(got), len(got[0]["v"]))
	}
	if _, cut := capRows([]map[string]string{{"a": "b"}}); cut {
		t.Fatal("small result marked cut")
	}
}
