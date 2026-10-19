// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package shared

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cluster/ostest"
	"github.com/jrsamsanchez/signalith/internal/secrets"
	"github.com/jrsamsanchez/signalith/internal/store"
)

// "signalith cluster found" founds without the job lease, and the server
// is a member afterwards; mode changes reach the functions added with
// OnMode.
func TestFoundByHand(t *testing.T) {
	e := newEnv(t)
	a := e.server("siem-a", nil)
	var mu sync.Mutex
	var changes []string
	a.rt.OnMode(func(old, new Mode) {
		mu.Lock()
		defer mu.Unlock()
		changes = append(changes, string(old)+">"+string(new))
	})
	if err := a.rt.found(context.Background(), "signalith", false); !errors.Is(err, errNotHolder) {
		t.Fatalf("a founding without the lease = %v", err)
	}
	if err := a.rt.Found(context.Background(), "admin"); err != nil {
		t.Fatal(err)
	}
	a.wantMode(ModeMember)
	if _, body := clusterBody(t, e); body.CreatedBy != "siem-a" || body.CreatedByID != "n_siem-a" {
		t.Errorf("cluster %+v", body)
	}
	mu.Lock()
	got := strings.Join(changes, ",")
	mu.Unlock()
	if !strings.HasSuffix(got, ">"+string(ModeMember)) {
		t.Errorf("mode changes %q", got)
	}
	if c, prefix := a.rt.Target(); c == nil || prefix != testPrefix {
		t.Errorf("target %v %q", c, prefix)
	}
	if s := a.rt.Self(); s.NodeID != "n_siem-a" || s.Name != "siem-a" || s.BootID == "" || s.BootID != a.rt.BootID() {
		t.Errorf("self %+v", s)
	}
	if a.rt.NodeCfg() == nil {
		t.Error("no nodecfg document")
	}
}

// A create whose answer was lost, but which made the document, is a
// founding: the server reads the document back and is its founder.
func TestFoundingWhoseAnswerWasLostButMade(t *testing.T) {
	e := newEnv(t)
	a := e.server("siem-a", nil)
	var dropped atomic.Bool
	e.os.SetFault(func(method, path string) *ostest.Fault {
		if method == http.MethodPut && strings.Contains(path, "/_create/"+ClusterDocID) && dropped.CompareAndSwap(false, true) {
			return &ostest.Fault{Drop: true}
		}
		return nil
	})
	if err := a.rt.Found(context.Background(), "admin"); err != nil {
		t.Fatal(err)
	}
	a.wantMode(ModeMember)
	if env, _ := clusterBody(t, e); macKID(env.MAC) != a.key().ID() {
		t.Errorf("cluster signed with %s, key %s", macKID(env.MAC), a.key().ID())
	}
}

// A create that fails while another server's cluster document is there
// gives ErrClusterExists, and the key made for it is not kept.
func TestFoundingLosesToAnotherCluster(t *testing.T) {
	e := newEnv(t)
	a := e.server("siem-a", nil)
	a.holds.Store(true)
	a.step()
	a.wantMode(ModeMember)

	b := e.server("siem-b", nil)
	e.os.SetFault(func(method, path string) *ostest.Fault {
		if method == http.MethodPut && strings.Contains(path, "/_create/"+ClusterDocID) {
			return &ostest.Fault{Status: http.StatusInternalServerError, Type: "internal_error"}
		}
		return nil
	})
	if err := b.rt.Found(context.Background(), "admin"); !errors.Is(err, ErrClusterExists) {
		t.Fatalf("Found = %v", err)
	}
	if files := ClusterKeyFiles(b.dir); len(files) != 0 {
		t.Errorf("kept keys %v", files)
	}
	// With no cluster document at all, the error is the store's own, and
	// the key is not kept either.
	e.os.Delete(testIndex, ClusterDocID)
	c := e.server("siem-c", nil)
	err := c.rt.Found(context.Background(), "admin")
	if err == nil || errors.Is(err, ErrClusterExists) {
		t.Fatalf("Found = %v", err)
	}
	if files := ClusterKeyFiles(c.dir); len(files) != 0 {
		t.Errorf("kept keys %v", files)
	}
}

// The approvals waiting to be taken, and one server's pending document
// with the fingerprint of its key.
func TestApprovedAndPendingOf(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	a := e.server("siem-a", nil)
	a.holds.Store(true)
	a.step()
	b := e.server("siem-b", nil)
	b.wantMode(ModeLegacyB)

	if got, err := a.rt.Approved(ctx); err != nil || len(got) != 0 {
		t.Errorf("approved = %v, %v", got, err)
	}
	p, ok, err := a.rt.PendingOf(ctx, "n_siem-b")
	if err != nil || !ok || p.Fingerprint != b.rt.Status().Fingerprint || p.Name != "siem-b" {
		t.Fatalf("PendingOf = %+v %v %v", p, ok, err)
	}
	if _, ok, err := a.rt.PendingOf(ctx, "n_nobody"); ok || err != nil {
		t.Errorf("PendingOf a server never seen = %v %v", ok, err)
	}
	// A document under another server's id, and one with a key that is
	// not a key.
	e.os.Put(testRuntime, PendingID("n_other"), map[string]any{"kind": PendingKind, "node_id": "n_siem-b"})
	if _, ok, err := a.rt.PendingOf(ctx, "n_other"); ok || err != nil {
		t.Errorf("PendingOf a document of another id = %v %v", ok, err)
	}
	e.os.Put(testRuntime, PendingID("n_bad"), map[string]any{"kind": PendingKind, "node_id": "n_bad", "node_pub": "not a key"})
	if _, ok, err := a.rt.PendingOf(ctx, "n_bad"); ok || err == nil {
		t.Errorf("PendingOf a document with a bad key = %v %v", ok, err)
	}

	other, err := NewNodeKey()
	if err != nil {
		t.Fatal(err)
	}
	approve(t, a, b, other.Public())
	// An approval stored under another server's id is not listed.
	e.os.Put(testRuntime, ApprovalID("n_x"), map[string]any{"kind": ApprovalKind, "node_id": "n_y"})
	got, err := a.rt.Approved(ctx)
	if err != nil || len(got) != 1 || !got["n_siem-b"] {
		t.Errorf("approved = %v, %v", got, err)
	}

	idle := NewRuntime(RuntimeOptions{StateDir: t.TempDir(), Self: Self{NodeID: "n_z", Name: "siem-z"}, Clock: e.clock})
	if _, err := idle.Approved(ctx); err == nil {
		t.Error("approvals listed without OpenSearch")
	}
	if _, _, err := idle.PendingOf(ctx, "n_siem-b"); err == nil {
		t.Error("a pending document read without OpenSearch")
	}
}

// AcceptRestore on the runtime writes every document above the highest
// revision any server's heartbeat reports; a server that is not a member
// cannot. A server's heartbeat that stopped, or that is not seen at all,
// is offline.
func TestRuntimeAcceptRestoreAndPeers(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	peers := []Peer{{NodeID: "n_siem-a", Name: "siem-a", Live: true}, {NodeID: "n_old", Live: false, MaxRev: 50}}
	a := e.server("siem-a", func(o *RuntimeOptions) { o.Peers = func() []Peer { return peers } })
	a.holds.Store(true)
	a.step()
	a.wantMode(ModeMember)
	if err := a.rt.AcceptRestore(ctx, "sam", 0); err != nil {
		t.Fatal(err)
	}
	if env, _ := clusterBody(t, e); env.Rev != 51 {
		t.Errorf("cluster document at rev %d, want 51", env.Rev)
	}
	for id, want := range map[string]bool{"n_siem-a": false, "n_old": true, "n_never": true} {
		if got := a.rt.offline(id); got != want {
			t.Errorf("offline(%s) = %v", id, got)
		}
	}

	b := e.server("siem-b", nil)
	if err := b.rt.AcceptRestore(ctx, "sam", 0); !errors.Is(err, ErrNotMember) {
		t.Errorf("AcceptRestore on a server not in the cluster = %v", err)
	}
	if b.rt.offline("n_siem-a") {
		t.Error("a runtime that knows no heartbeats calls a server offline")
	}
}

// The modes that use the server's own files, and the errors that say why
// a change waits.
func TestModesAndPausedErrors(t *testing.T) {
	for m, want := range map[Mode]bool{ModeLegacyA: true, ModeLegacyB: true, ModeLegacyC: true, ModeStarting: true,
		ModeMember: false, ModeDegraded: false, ModeKeyMissing: false} {
		if m.Legacy() != want {
			t.Errorf("%s.Legacy() = %v", m, !want)
		}
	}
	if s := (&PausedError{}).Error(); strings.Contains(s, "(") || !strings.Contains(s, "paused") {
		t.Errorf("PausedError = %q", s)
	}
	if s := (&PausedError{Why: "OpenSearch is down"}).Error(); !strings.Contains(s, "(OpenSearch is down)") {
		t.Errorf("PausedError = %q", s)
	}
	if s := (&MovingError{What: "users"}).Error(); !strings.Contains(s, "moving its users into the cluster") {
		t.Errorf("MovingError = %q", s)
	}
	e := newEnv(t)
	b := e.server("siem-b", nil)
	var paused *PausedError
	if err := b.rt.Writable(); !errors.As(err, &paused) || paused.Why == "" {
		t.Errorf("Writable on a server not in the cluster = %v", err)
	}
}

// SaveResult keeps the entries other servers wrote into a result that is
// a JSON object, and SetProgress records how far a request came.
func TestRequestSaveResultAndProgress(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	a, _ := e.hub("siem-a")
	b, _ := e.hub("siem-b")
	ra, rb := NewRequests(a, "n_a"), NewRequests(b, "n_b")
	req, err := ra.SubmitTo(ctx, "restart", []string{"n_a", "n_b"}, true, nil, "sam")
	if err != nil {
		t.Fatal(err)
	}
	mine, _, err := ra.Get(ctx, req.ID)
	if err != nil {
		t.Fatal(err)
	}
	theirs, _, err := rb.Get(ctx, req.ID)
	if err != nil {
		t.Fatal(err)
	}
	mine.Result = json.RawMessage(`{"n_a":"moved"}`)
	mine.Progress = Progress{Done: 1, Total: 2}
	if err := ra.SaveResult(ctx, mine); err != nil {
		t.Fatal(err)
	}
	// B's copy is older: it is read again, and A's entry kept.
	theirs.Result = json.RawMessage(`{"n_b":"stayed"}`)
	if err := rb.SaveResult(ctx, theirs); err != nil {
		t.Fatal(err)
	}
	got, _, err := ra.Get(ctx, req.ID)
	if err != nil {
		t.Fatal(err)
	}
	var res map[string]string
	if err := json.Unmarshal(got.Result, &res); err != nil || res["n_a"] != "moved" || res["n_b"] != "stayed" {
		t.Errorf("result %s, %v", got.Result, err)
	}
	if err := ra.SetProgress(ctx, got, 2, 2); err != nil {
		t.Fatal(err)
	}
	if again, _, _ := rb.Get(ctx, req.ID); again.Progress != (Progress{Done: 2, Total: 2}) {
		t.Errorf("progress %+v", again.Progress)
	}
	// A request that is gone.
	if err := ra.SaveResult(ctx, &Request{ID: "r_gone"}); err == nil {
		t.Error("saved the result of a request that is not there")
	}

	for _, c := range []struct{ theirs, mine, want string }{
		{`{"a":1}`, ``, `{"a":1}`},
		{`{"a":1}`, `{"b":2}`, `{"a":1,"b":2}`},
		{`{"a":1}`, `{"a":3}`, `{"a":3}`},
		{`[1]`, `{"b":2}`, `{"b":2}`},
		{`{"a":1}`, `"done"`, `"done"`},
		{`null`, `{"b":2}`, `{"b":2}`},
	} {
		if got := string(mergeResult(json.RawMessage(c.theirs), json.RawMessage(c.mine))); got != c.want {
			t.Errorf("mergeResult(%s, %s) = %s, want %s", c.theirs, c.mine, got, c.want)
		}
	}
}

// reset-key signs every document again with the new key, empties what
// was sealed with the lost one, names the new key and this server alone
// in the keyring, and bumps the watch documents.
func TestResign(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	a, _ := e.hub("siem-a")
	d := NewDoc[testBody](a, "users", "users", 1)
	if _, err := d.Mutate(ctx, "sam", func(v *testBody) error { v.Name = "jlee"; return nil }); err != nil {
		t.Fatal(err)
	}
	lost := e.key
	e.putSigned(lost, "settings", "settings", 1, 4, `{"pw":"enc:v1:`+lost.ID()+`:eA==","n":5}`, nil)
	e.putSigned(lost, KeyringDocID, "keyring", 1, 2, `{"active":"`+lost.ID()+`","keys":[{"kid":"`+lost.ID()+`"}],"members":{"n_a":{"name":"siem-a"},"n_b":{"name":"siem-b"}}}`, nil)
	e.os.Put(testIndex, "junk", map[string]any{"x": 1})
	if _, err := a.Bump(ctx, "users"); err != nil {
		t.Fatal(err)
	}

	docs, bad, err := ReadAll(ctx, e.c, testPrefix)
	if err != nil {
		t.Fatal(err)
	}
	if len(bad) != 1 || bad[0] != "junk" {
		t.Errorf("bad %v", bad)
	}
	k, err := NewClusterKey()
	if err != nil {
		t.Fatal(err)
	}
	self := KeyringMember{Name: "siem-a"}
	e.os.Requests()
	dropped, err := Resign(ctx, e.c, testPrefix, docs, k, 100, "admin", "siem-a", "2026-10-12T10:00:00Z", "n_a", self)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(dropped, ",") != "settings pw" {
		t.Errorf("dropped %v", dropped)
	}
	after, _, err := ReadAll(ctx, e.c, testPrefix)
	if err != nil {
		t.Fatal(err)
	}
	for _, sd := range after {
		env := sd.Envelope
		if err := Verify(NewKeySet(k), sd.ID, &env); err != nil || env.Rev != 100 || env.UpdatedBy.User != "admin" {
			t.Errorf("%s: rev %d by %+v: %v", sd.ID, env.Rev, env.UpdatedBy, err)
		}
		switch sd.ID {
		case "settings":
			if !strings.Contains(env.Body, `"pw":""`) || !strings.Contains(env.Body, `"n":5`) {
				t.Errorf("settings body %s", env.Body)
			}
		case KeyringDocID:
			var kr KeyringBody
			if err := json.Unmarshal([]byte(env.Body), &kr); err != nil || kr.Active != k.ID() || len(kr.Keys) != 1 || len(kr.Members) != 1 || kr.Members["n_a"].Name != "siem-a" {
				t.Errorf("keyring %s, %v", env.Body, err)
			}
		}
	}
	bumped := false
	for _, r := range e.os.Requests() {
		if strings.HasPrefix(r, "PUT ") && strings.Contains(r, "watch:users") {
			bumped = true
		}
	}
	if !bumped {
		t.Error("the watch document was not bumped")
	}

	// No keyring document: one is made. A body that is not JSON is
	// reported, and the rest still signed.
	e.os.Delete(testIndex, KeyringDocID)
	e.putSigned(k, "broken", "settings", 1, 100, `not json`, nil)
	docs, _, err = ReadAll(ctx, e.c, testPrefix)
	if err != nil {
		t.Fatal(err)
	}
	k2, err := NewClusterKey()
	if err != nil {
		t.Fatal(err)
	}
	_, err = Resign(ctx, e.c, testPrefix, docs, k2, 101, "admin", "siem-a", "2026-10-12T11:00:00Z", "n_a", self)
	if err == nil || !strings.Contains(err.Error(), "broken") {
		t.Errorf("Resign = %v", err)
	}
	src := e.os.Source(testIndex, KeyringDocID)
	if src == nil {
		t.Fatal("no keyring document was made")
	}
	raw, _ := json.Marshal(src)
	var env Envelope
	if err := json.Unmarshal(raw, &env); err != nil || Verify(NewKeySet(k2), KeyringDocID, &env) != nil || !strings.Contains(env.Body, k2.ID()) {
		t.Errorf("keyring %+v, %v", env, err)
	}
}

// reset-key reports each document it could not sign again, and goes on
// with the others.
func TestResignFaults(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	a, _ := e.hub("siem-a")
	d := NewDoc[testBody](a, "users", "users", 1)
	if _, err := d.Mutate(ctx, "sam", func(v *testBody) error { v.Name = "jlee"; return nil }); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Bump(ctx, "users"); err != nil {
		t.Fatal(err)
	}
	e.putSigned(e.key, KeyringDocID, "keyring", 1, 2, `[1]`, nil)
	docs, _, err := ReadAll(ctx, e.c, testPrefix)
	if err != nil {
		t.Fatal(err)
	}
	k, _ := NewClusterKey()
	failing(e, func(method, path string) bool {
		return method == http.MethodPut && strings.Contains(path, "/_doc/users")
	})
	_, err = Resign(ctx, e.c, testPrefix, docs, k, 50, "admin", "siem-a", "2026-10-12T10:00:00Z", "n_a", KeyringMember{Name: "siem-a"})
	if err == nil || !strings.Contains(err.Error(), "users:") || !strings.Contains(err.Error(), KeyringDocID+":") {
		t.Errorf("Resign = %v", err)
	}
	// No keyring, and its create and the watch bumps refused.
	e.os.Delete(testIndex, KeyringDocID)
	failing(e, writes)
	_, err = Resign(ctx, e.c, testPrefix, nil, k, 51, "admin", "siem-a", "2026-10-12T10:00:00Z", "n_a", KeyringMember{Name: "siem-a"})
	if err == nil || !strings.Contains(err.Error(), KeyringDocID) {
		t.Errorf("Resign without a keyring = %v", err)
	}
	failing(e, func(_, path string) bool { return strings.Contains(path, "_search") })
	if _, err := Resign(ctx, e.c, testPrefix, nil, k, 52, "admin", "siem-a", "2026-10-12T10:00:00Z", "n_a", KeyringMember{Name: "siem-a"}); err == nil {
		t.Error("Resign with the watch search refused")
	}
	if _, _, err := ReadAll(ctx, e.c, testPrefix); err == nil {
		t.Error("ReadAll with the search refused")
	}
}

// The limiter's and the audit's keys are their own, and the same for the
// same cluster key.
func TestLockAndAuditKeys(t *testing.T) {
	k, err := NewClusterKey()
	if err != nil {
		t.Fatal(err)
	}
	subs := [][]byte{k.MACKey(), k.CookieKey(), k.ArchiveKey(), k.KnownBrowserKey(), k.LockKey(), k.AuditKey()}
	for i := range subs {
		for j := range i {
			if string(subs[i]) == string(subs[j]) {
				t.Errorf("sub-keys %d and %d are the same", i, j)
			}
		}
	}
	if string(k.LockKey()) != string(k.LockKey()) || len(k.AuditKey()) != 32 {
		t.Error("the sub-keys are not stable")
	}
}

// signalith secrets passes the key of a key file through its reseal:
// a new value is written back, an error or a file that is not JSON is
// reported.
func TestResealKeyFile(t *testing.T) {
	data := []byte(`{"kid":"0000aaaa","key":"enc:v1:old"}`)
	out, n, err := ResealClusterKeyFile(data, func(s secrets.Stored) (string, error) {
		if s.Field != "cluster.key/0000aaaa" || s.Label != "cluster key 0000aaaa" || s.Value != "enc:v1:old" {
			t.Errorf("stored %+v", s)
		}
		return "enc:v1:new", nil
	})
	if err != nil || n != 1 || !strings.Contains(string(out), `"key": "enc:v1:new"`) || !strings.HasSuffix(string(out), "\n") {
		t.Errorf("out %s, %d, %v", out, n, err)
	}
	boom := errors.New("boom")
	if _, _, err := ResealNodeKeyFile(data, func(secrets.Stored) (string, error) { return "", boom }); !errors.Is(err, boom) {
		t.Errorf("a failed reseal = %v", err)
	}
	if _, _, err := ResealNodeKeyFile([]byte("not json"), func(secrets.Stored) (string, error) { return "", nil }); err == nil {
		t.Error("a file that is not JSON was resealed")
	}
}

// An approval that does not hold a usable key is not taken, and logged
// once.
func TestTakeApprovalRefusals(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	a := e.server("siem-a", nil)
	a.holds.Store(true)
	a.step()
	b := e.server("siem-b", nil)
	b.wantMode(ModeLegacyB)
	nk, err := (KeyStore{Dir: b.dir, Master: b.master}).LoadNodeKey()
	if err != nil {
		t.Fatal(err)
	}
	k := a.key()
	sealed := func(kid string, plain string) json.RawMessage {
		t.Helper()
		s, err := SealToNode(nk.Public(), "n_siem-b", kid, []byte(plain))
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := json.Marshal(ApprovalDoc{Kind: ApprovalKind, NodeID: "n_siem-b", KID: kid, Sealed: s})
		return raw
	}
	other, _ := NewClusterKey()
	for name, src := range map[string]json.RawMessage{
		"not json":    json.RawMessage(`[`),
		"no kid":      json.RawMessage(`{"kind":"approval"}`),
		"not sealed":  json.RawMessage(`{"kind":"approval","kid":"` + k.ID() + `","sealed":"x"}`),
		"damaged":     sealed(k.ID(), "!!"),
		"short":       sealed(k.ID(), "AAAA"),
		"another kid": sealed(k.ID(), other.Text()),
		"another key": sealed(other.ID(), other.Text()),
	} {
		if b.rt.takeApproval(ctx, nk, src, store.Version{}) {
			t.Errorf("%s: taken", name)
		}
	}
	if n := len(ClusterKeyFiles(b.dir)); n != 0 {
		t.Errorf("%d keys kept", n)
	}
	if got := strings.Count(b.logs.String(), "an approval for this server cannot be used"); got < 5 {
		t.Errorf("logged %d refusals", got)
	}
	before := strings.Count(b.logs.String(), "cannot be used")
	b.rt.takeApproval(ctx, nk, json.RawMessage(`[`), store.Version{})
	b.rt.takeApproval(ctx, nk, json.RawMessage(`[`), store.Version{})
	if after := strings.Count(b.logs.String(), "cannot be used"); after != before+1 {
		t.Errorf("the same refusal logged %d times", after-before)
	}

	// The pending list skips documents that are not what they say.
	e.os.Put(testRuntime, PendingID("n_x"), map[string]any{"kind": PendingKind, "node_id": "n_y"})
	e.os.Put(testRuntime, PendingID("n_bad"), map[string]any{"kind": PendingKind, "node_id": "n_bad", "node_pub": "not a key"})
	list, err := a.rt.Pending(ctx)
	if err != nil || len(list) != 1 || list[0].NodeID != "n_siem-b" {
		t.Errorf("pending = %+v, %v", list, err)
	}
	idle := NewRuntime(RuntimeOptions{StateDir: t.TempDir(), Self: Self{NodeID: "n_z", Name: "siem-z"}, Clock: e.clock})
	if _, err := idle.Pending(ctx); err == nil {
		t.Error("pending listed without OpenSearch")
	}
	if err := b.rt.WriteApproval(ctx, ApprovalDoc{NodeID: "n_x"}); err == nil {
		t.Error("a server not in the cluster wrote an approval")
	}
	// Deletes refused while dropping stale documents.
	failing(e, func(method, _ string) bool { return method == http.MethodDelete })
	if _, err := a.rt.DropStalePending(ctx, e.clock.Now().Add(PendingStale+time.Hour)); err == nil {
		t.Error("DropStalePending with deletes refused")
	}
	failing(e, func(_, path string) bool { return strings.Contains(path, "_search") })
	if _, err := a.rt.DropStalePending(ctx, e.clock.Now()); err == nil {
		t.Error("DropStalePending with the search refused")
	}
	if _, err := a.rt.Pending(ctx); err == nil {
		t.Error("Pending with the search refused")
	}
	if _, err := a.rt.Approved(ctx); err == nil {
		t.Error("Approved with the search refused")
	}
}
