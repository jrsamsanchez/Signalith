package agenttokens

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cluster/ostest"
)

// logBuf is a log written to from several goroutines.
type logBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *logBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *logBuf) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

func withLog(r *Registry) *logBuf {
	var b logBuf
	r.Log = slog.New(slog.NewTextHandler(&b, nil))
	return &b
}

const conflictType = "version_conflict_engine_exception"

func TestWithoutOpenSearch(t *testing.T) {
	ctx := context.Background()
	shared := "a-long-shared-ingest-token-0123456789"
	r := &Registry{Legacy: func() []Legacy { return []Legacy{{Secret: shared}} }}
	if err := r.Load(ctx); err == nil || !strings.Contains(err.Error(), "no OpenSearch") {
		t.Errorf("Load = %v", err)
	}
	_, _, err := r.Create(ctx, "x", "", "sam")
	wantCode(t, err, CodeStoreUnavailable)
	_, _, err = r.Revoke(ctx, "0123456789ab", "sam")
	wantCode(t, err, CodeStoreUnavailable)
	_, _, err = r.Refuse(ctx, "0123456789ab", "sam")
	wantCode(t, err, CodeStoreUnavailable)
	_, _, err = r.SetCollect(ctx, "0123456789ab", Collect{}, "sam")
	wantCode(t, err, CodeStoreUnavailable)
	_, _, err = r.Rename(ctx, "0123456789ab", "x", "sam")
	wantCode(t, err, CodeStoreUnavailable)
	var e *Error
	if !errors.As(err, &e) || e.Error() != e.Msg || e.Unwrap() == nil {
		t.Errorf("error = %q %v", e.Error(), e.Unwrap())
	}

	// With no OpenSearch the process makes its own key for shared tokens.
	id, res := r.Check(shared)
	if res != Valid || !validID(id.ID) || r.LegacyID(shared) != id.ID {
		t.Errorf("shared = %+v %v", id, res)
	}
	if id.String() != id.Name+" ("+id.ID+")" {
		t.Errorf("String = %s", id)
	}
	if r.index() != "signalith_runtime" || r.node() == "" {
		t.Errorf("defaults = %s %s", r.index(), r.node())
	}
	r.Note(id.ID, "192.0.2.4", 3)
	r.flushUse(ctx)
	if u, err := r.Usage(ctx); err != nil || u[id.ID].Events1h != 3 || u[id.ID].Address != "192.0.2.4" {
		t.Errorf("usage = %+v %v", u, err)
	}
	if lt, ok := r.LegacyByID(ctx, id.ID); !ok || lt.Events1h != 3 || lt.LastUsedAt == nil {
		t.Errorf("LegacyByID = %+v %v", lt, ok)
	}
	if _, ok := r.LegacyByID(ctx, "0123456789ab"); ok {
		t.Error("an unknown shared token was found")
	}

	for _, bad := range []string{"", "sgl_short"} {
		if _, res := r.Check(bad); res != Unknown {
			t.Errorf("%q = %v", bad, res)
		}
	}
	if _, _, ok := r.findShared(r.current(), "not-an-id"); ok {
		t.Error("an invalid ID was found")
	}

	var nilReg *Registry
	nilReg.Note("x", "y", 1)
	if nilReg.current().loaded || nilReg.legacy() != nil {
		t.Error("nil registry")
	}

	// Run with nothing to read stops when asked.
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	r.Run(cctx)
}

func TestListingOrderAndLookups(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	shared := "a-long-shared-ingest-token-0123456789"
	r := &Registry{Legacy: func() []Legacy {
		return []Legacy{{Secret: shared, Source: "a"}, {Secret: shared, Source: "b"}}
	}}
	docs := []*tokenDoc{
		{ID: "000000000001", Name: "beta", State: StateActive, At: now},
		{ID: "000000000002", Name: "Alpha", State: StateActive, At: now},
		{ID: "000000000003", Name: "old", State: StateRevoked, At: now.Add(time.Minute)},
		{ID: "000000000004", Name: "old", State: StateRevoked, At: now},
		{ID: "000000000005", Name: "Twin", State: StateActive, At: now},
		{ID: "000000000006", Name: "twin", State: StateActive, At: now.Add(time.Second)},
	}
	r.apply(func(s *snapshot) {
		for _, d := range docs {
			s.tokens[d.ID] = d
		}
	})
	l := r.List(ctx)
	var order []string
	for _, tk := range l.Tokens {
		order = append(order, tk.ID[11:])
	}
	if strings.Join(order, "") != "215643" {
		t.Errorf("order = %v", order)
	}
	if len(l.Legacy) != 1 || l.Legacy[0].Source != "a" {
		t.Errorf("legacy = %+v", l.Legacy)
	}
	if a, la := r.Counts(); a != 4 || la != 1 {
		t.Errorf("counts = %d %d", a, la)
	}

	for name, want := range map[string]string{"000000000003": "000000000003", " ALPHA ": "000000000002", "twin": "", "nobody": "", "old": ""} {
		if id, ok := r.FindByName(name); id != want || ok != (want != "") {
			t.Errorf("FindByName(%q) = %q %v", name, id, ok)
		}
	}
	if _, ok := r.Get(ctx, "000000000009"); ok {
		t.Error("Get of an unknown token")
	}
	if tk, ok := r.Get(ctx, "000000000001"); !ok || tk.Name != "beta" {
		t.Errorf("Get = %+v", tk)
	}
	if r.Name("000000000002") != "Alpha" || r.Name("nope") != "" {
		t.Error("Name")
	}

	// New tokens past the limit are not counted; known ones still are.
	r.useMu.Lock()
	r.uses = map[string]*use{}
	for i := range MaxDocs + 64 {
		r.uses[hex.EncodeToString([]byte{byte(i >> 8), byte(i)})] = &use{}
	}
	r.useMu.Unlock()
	r.Note("brand-new", "192.0.2.1", 1)
	r.Note("0001", "192.0.2.1", 1)
	r.useMu.Lock()
	_, added := r.uses["brand-new"]
	known := r.uses["0001"].dirty
	r.useMu.Unlock()
	if added || !known {
		t.Errorf("added %v, known counted %v", added, known)
	}
}

func TestSharedBeforeLoad(t *testing.T) {
	fake := ostest.New(t)
	shared := "a-long-shared-ingest-token-0123456789"
	r := newReg(t, fake.URL, "n1", Legacy{Secret: shared, Source: "env"})
	// Before the key is read, a shared token is matched by its old ID
	// only, with no ID shown, and is let in.
	if id, ok := r.Lookup(IDOf(shared)); !ok || id.ID != "" || id.Name != "Shared token" {
		t.Errorf("Lookup = %+v %v", id, ok)
	}
	if !r.Active(IDOf(shared)) || r.LegacyID(shared) != "" {
		t.Error("before load")
	}
	if l := r.List(context.Background()); l.Loaded || len(l.Legacy) != 1 || l.Legacy[0].ID != "" || l.Legacy[0].Name != "Shared token" {
		t.Errorf("list = %+v", l)
	}
	if _, ok := r.Lookup("0123456789ab"); ok {
		t.Error("Lookup of nothing")
	}
}

func TestKeyMaking(t *testing.T) {
	ctx := context.Background()
	shared := "a-long-shared-ingest-token-0123456789"

	// A legacy document without a key keeps its refusals when the key is
	// added.
	fake := ostest.New(t)
	fake.Put("tt_runtime", legacyDocID, map[string]any{"kind": kindLegacy, "refused": map[string]any{"0123456789ab": map[string]any{"by": "kim"}}})
	r := newReg(t, fake.URL, "n1", Legacy{Secret: shared})
	if err := r.Load(ctx); err != nil {
		t.Fatal(err)
	}
	src := fake.Source("tt_runtime", legacyDocID)
	if src["id_key"] == nil || src["refused"].(map[string]any)["0123456789ab"] == nil {
		t.Errorf("legacy doc = %v", src)
	}
	if _, res := r.Check(shared); res != Valid {
		t.Errorf("check = %v", res)
	}

	// A document the search does not see, with a key, is the key.
	fake = ostest.New(t)
	key := strings.Repeat("ab", 32)
	fake.Put("tt_runtime", legacyDocID, map[string]any{"kind": "other", "id_key": key})
	r = newReg(t, fake.URL, "n1", Legacy{Secret: shared})
	if err := r.Load(ctx); err != nil {
		t.Fatal(err)
	}
	k, _ := hex.DecodeString(key)
	if r.LegacyID(shared) != legacyID(k, shared) {
		t.Error("the stored key was not used")
	}

	// Another server made the key first: this one tries again.
	fake = ostest.New(t)
	fake.FailN(1, "PUT", "_create", 409, conflictType)
	r = newReg(t, fake.URL, "n1", Legacy{Secret: shared})
	if err := r.Load(ctx); err != nil || r.LegacyID(shared) == "" {
		t.Errorf("after a race = %v %q", err, r.LegacyID(shared))
	}

	// The key cannot be saved: shared tokens wait, and the failure is
	// logged.
	fake = ostest.New(t)
	r = newReg(t, fake.URL, "n1", Legacy{Secret: shared})
	logs := withLog(r)
	if err := r.ensureIndex(ctx); err != nil {
		t.Fatal(err)
	}
	fake.FailN(1, "PUT", "_create", 400, "mapper_parsing_exception")
	if err := r.Load(ctx); err != nil {
		t.Fatal(err)
	}
	if _, res := r.Check(shared); res != NotLoaded || !strings.Contains(logs.String(), "could not be saved") {
		t.Errorf("check = %v, logs %s", res, logs.String())
	}
	// Run makes it at its first tick.
	rctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { r.Run(rctx); close(done) }()
	waitFor(t, func() bool { _, res := r.Check(shared); return res == Valid })
	cancel()
	<-done
}

func TestCasRetriesAndFailures(t *testing.T) {
	fake := ostest.New(t)
	ctx := context.Background()
	r := newReg(t, fake.URL, "n1")
	logs := withLog(r)
	tok, _, err := r.Create(ctx, "Linux", PurposeAgent, "sam")
	if err != nil {
		t.Fatal(err)
	}

	// Someone else wrote meanwhile: read again and write.
	fake.FailN(1, "PUT", "if_seq_no", 409, conflictType)
	if got, old, err := r.Rename(ctx, tok.ID, "Linux hosts", "sam"); err != nil || got.Name != "Linux hosts" || old != "Linux" {
		t.Errorf("rename after a conflict = %+v %q %v", got, old, err)
	}
	// The same name: nothing written.
	fake.Requests()
	if got, old, err := r.Rename(ctx, tok.ID, "Linux hosts", "sam"); err != nil || got.Name != old {
		t.Errorf("same name = %+v %q %v", got, old, err)
	}
	for _, req := range fake.Requests() {
		if strings.Contains(req, "if_seq_no") {
			t.Errorf("wrote %s", req)
		}
	}
	// The same collection settings: nothing written either.
	if _, _, err := r.SetCollect(ctx, tok.ID, Collect{}, "kim"); err != nil {
		t.Error(err)
	}
	_, _, err = r.SetCollect(ctx, tok.ID, Collect{LinuxLog: "syslog"}, "kim")
	var e *Error
	if !errors.As(err, &e) || e.Field != "linux_log" || !strings.Contains(e.Msg, "auto, file or journal") {
		t.Errorf("linux_log = %v", err)
	}

	// A refused write fails.
	fake.FailN(1, "PUT", "if_seq_no", 400, "mapper_parsing_exception")
	_, _, err = r.Rename(ctx, tok.ID, "Other", "sam")
	wantCode(t, err, CodeStoreUnavailable)

	// Conflicts until the caller gives up.
	cctx, cancel := context.WithCancel(ctx)
	fake.SetFault(func(m, p string) *ostest.Fault {
		if m == "PUT" && strings.Contains(p, "if_seq_no") {
			cancel()
			return &ostest.Fault{Status: 409, Type: conflictType}
		}
		return nil
	})
	_, _, err = r.Rename(cctx, tok.ID, "Third", "sam")
	wantCode(t, err, CodeStoreUnavailable)
	fake.SetFault(nil)

	// A stored document that is not this token's.
	fake.Put("tt_runtime", tokenDocID("00000000000f"), map[string]any{"kind": "x", "id": "something else"})
	_, _, err = r.Rename(ctx, "00000000000f", "x", "sam")
	wantCode(t, err, CodeNotFound)
	_, _, err = r.Rename(ctx, "bad", "x", "sam")
	wantCode(t, err, CodeNotFound)

	// Revoked: no rename. The hook's failure is logged; telling the other
	// servers fails and is logged too.
	r.OnRevoke(func(context.Context, string) (int, error) { return 1, errors.New("hosts index gone") })
	if _, n, err := r.Revoke(ctx, tok.ID, "sam"); err != nil || n != 1 {
		t.Fatalf("revoke = %d %v", n, err)
	}
	_, _, err = r.Rename(ctx, tok.ID, "x", "sam")
	wantCode(t, err, CodeRevoked)
	if !strings.Contains(logs.String(), "could not all be removed") {
		t.Errorf("logs = %s", logs.String())
	}
	fake.FailN(1, "PUT", "_doc/agenttokens", 400, "mapper_parsing_exception")
	if _, _, err := r.Create(ctx, "Windows", "", "sam"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(logs.String(), "could not be told") {
		t.Errorf("logs = %s", logs.String())
	}
}

func TestCreateFailures(t *testing.T) {
	fake := ostest.New(t)
	ctx := context.Background()
	r := newReg(t, fake.URL, "n1")
	if err := r.ensureIndex(ctx); err != nil {
		t.Fatal(err)
	}
	// The tokens cannot be read before the first change: still loading.
	fake.SetFault(func(m, p string) *ostest.Fault {
		if strings.Contains(p, "_search") {
			return &ostest.Fault{Status: 400, Type: "search_phase_execution_exception"}
		}
		return nil
	})
	_, _, err := r.Create(ctx, "x", "", "sam")
	wantCode(t, err, CodeLoading)
	fake.SetFault(nil)

	// An ID in use: another is drawn.
	fake.FailN(1, "PUT", "_create", 409, conflictType)
	if _, _, err := r.Create(ctx, "x", "", "sam"); err != nil {
		t.Errorf("after an ID in use = %v", err)
	}
	fake.FailN(5, "PUT", "_create", 409, conflictType)
	_, _, err = r.Create(ctx, "y", "", "sam")
	if wantCode(t, err, CodeStoreUnavailable); !strings.Contains(errors.Unwrap(err).Error(), "five new tokens") {
		t.Errorf("five = %v", errors.Unwrap(err))
	}
	fake.FailN(1, "PUT", "_create", 400, "mapper_parsing_exception")
	_, _, err = r.Create(ctx, "y", "", "sam")
	wantCode(t, err, CodeStoreUnavailable)

	// Once read, a failed read is OpenSearch being away.
	fake.SetFault(func(m, p string) *ostest.Fault {
		if strings.Contains(p, "_search") {
			return &ostest.Fault{Status: 400, Type: "search_phase_execution_exception"}
		}
		return nil
	})
	_, _, err = r.Create(ctx, "z", "", "sam")
	wantCode(t, err, CodeStoreUnavailable)
	fake.SetFault(nil)

	// As many documents as are kept, revoked ones included.
	for i := range MaxDocs {
		id := "000000" + hex6(i)
		fake.Put("tt_runtime", tokenDocID(id), map[string]any{"kind": kindToken, "id": id, "state": StateRevoked, "name": "t", "hash": id + strings.Repeat("0", 52)})
	}
	_, _, err = r.Create(ctx, "one more", "", "sam")
	if wantCode(t, err, CodeTooMany); !strings.Contains(err.Error(), "5,000") {
		t.Errorf("too many docs = %v", err)
	}
}

func TestSharedRefusalEdges(t *testing.T) {
	fake := ostest.New(t)
	ctx := context.Background()
	shared := "a-long-shared-ingest-token-0123456789"
	r := newReg(t, fake.URL, "n1", Legacy{Secret: shared})
	if err := r.Load(ctx); err != nil {
		t.Fatal(err)
	}
	id := r.LegacyID(shared)
	// Accepting one that is accepted, and refusing twice, change nothing.
	if lt, err := r.Accept(ctx, id, "sam"); err != nil || lt.Status != "accepted" {
		t.Errorf("accept = %+v %v", lt, err)
	}
	fake.FailN(1, "PUT", "if_seq_no", 409, conflictType)
	if lt, _, err := r.Refuse(ctx, id, "sam"); err != nil || lt.Status != "refused" || lt.RefusedBy != "sam" {
		t.Errorf("refuse after a conflict = %+v %v", lt, err)
	}
	if lt, _, err := r.Refuse(ctx, id, "kim"); err != nil || lt.Status != "refused" || lt.RefusedBy != "sam" {
		t.Errorf("refuse again = %+v %v", lt, err)
	}
	fake.FailN(1, "PUT", "if_seq_no", 400, "mapper_parsing_exception")
	_, err := r.Accept(ctx, id, "sam")
	wantCode(t, err, CodeStoreUnavailable)

	cctx, cancel := context.WithCancel(ctx)
	fake.SetFault(func(m, p string) *ostest.Fault {
		if m == "PUT" && strings.Contains(p, "if_seq_no") {
			cancel()
			return &ostest.Fault{Status: 409, Type: conflictType}
		}
		return nil
	})
	_, err = r.Accept(cctx, id, "sam")
	wantCode(t, err, CodeStoreUnavailable)
	fake.SetFault(nil)
}

func TestUsageEdges(t *testing.T) {
	fake := ostest.New(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	r := newReg(t, fake.URL, "a")
	r.Now = func() time.Time { return now }
	logs := withLog(r)
	// What this server wrote before it started, unused since; another
	// server's, older; one that is not a usage document.
	fake.Put("tt_runtime", useDocID("000000000001", "a"), map[string]any{"kind": kindUse, "agent": "000000000001", "node": "a",
		"last_seen": now.Add(-time.Minute), "address": "192.0.2.1", "events_1h": 4})
	fake.Put("tt_runtime", useDocID("000000000001", "b"), map[string]any{"kind": kindUse, "agent": "000000000001", "node": "b",
		"last_seen": now.Add(-2 * time.Hour), "address": "192.0.2.2", "events_1h": 9})
	fake.Put("tt_runtime", useDocID("000000000002", "b"), map[string]any{"kind": kindUse, "agent": 7})
	u, err := r.Usage(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got := u["000000000001"]; got.Address != "192.0.2.1" || got.Events1h != 4 || len(u) != 1 {
		t.Errorf("usage = %+v", u)
	}

	// Bulk writes refused: kept for the next flush, and logged.
	r.Note("000000000003", "192.0.2.3", 2)
	fake.FailN(1, "POST", "_bulk", 400, "illegal_argument_exception")
	r.flushUse(ctx)
	r.useMu.Lock()
	dirty := r.uses["000000000003"].dirty
	r.useMu.Unlock()
	if !dirty || !strings.Contains(logs.String(), "could not be saved") {
		t.Errorf("after a refused bulk: dirty %v, logs %s", dirty, logs.String())
	}
	r.flushUse(ctx)
	if fake.Source("tt_runtime", useDocID("000000000003", "a")) == nil {
		t.Error("not written on the next flush")
	}

	// The index cannot be made: kept too.
	down := ostest.New(t)
	plug := down.Plug(t)
	r2 := newReg(t, plug.URL, "a")
	plug.Pull()
	r2.Note("000000000004", "192.0.2.4", 1)
	r2.flushUse(ctx)
	r2.useMu.Lock()
	dirty = r2.uses["000000000004"].dirty
	r2.useMu.Unlock()
	if !dirty {
		t.Error("lost when the index could not be made")
	}
}

func TestRunFlushes(t *testing.T) {
	fake := ostest.New(t)
	r := newReg(t, fake.URL, "n1")
	r.Flush = time.Millisecond
	tok, _, err := r.Create(context.Background(), "Linux", "", "sam")
	if err != nil {
		t.Fatal(err)
	}
	r.Note(tok.ID, "192.0.2.9", 5)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { r.Run(ctx); close(done) }()
	waitFor(t, func() bool { return fake.Source("tt_runtime", useDocID(tok.ID, "n1")) != nil })
	cancel()
	<-done
}

func TestSmallTokenHelpers(t *testing.T) {
	if hintOf("abc") != "" || hintOf("abcdef") != "cdef" {
		t.Error("hintOf")
	}
	if _, ok := CleanName("bad\xff"); ok {
		t.Error("invalid UTF-8 was taken")
	}
	if LegacyName("abc") != "Shared token abc" {
		t.Error("LegacyName")
	}
	if isHex("0123abcz") {
		t.Error("isHex")
	}
}
