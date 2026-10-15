package shared

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"
)

const testRuntime = testPrefix + "_runtime"

// approve does what clusterjoin.Approver does for server b on member a:
// list it in the keyring, then write the approval.
func approve(t *testing.T, a *testServer, b *testServer, sealTo []byte) {
	t.Helper()
	ctx := context.Background()
	k := a.key()
	sealed, err := SealToNode(sealTo, b.rt.opts.Self.NodeID, k.ID(), []byte(k.Text()))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.rt.Keyring().Mutate(ctx, "sam", func(kb *KeyringBody) error {
		kb.Members[b.rt.opts.Self.NodeID] = KeyringMember{Name: b.rt.opts.Self.Name, NodePub: base64.StdEncoding.EncodeToString(sealTo),
			Fingerprint: Fingerprint(sealTo), AddedBy: AddedByApproval}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := a.rt.WriteApproval(ctx, ApprovalDoc{NodeID: b.rt.opts.Self.NodeID, KID: k.ID(), Sealed: sealed, By: "sam", At: time.Now()}); err != nil {
		t.Fatal(err)
	}
}

func TestWaitingServerIsApproved(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	a := e.server("siem-a", nil)
	a.holds.Store(true)
	a.step()
	a.wantMode(ModeMember)

	b := e.server("siem-b", func(o *RuntimeOptions) {
		o.JoinInfo = func() PendingDoc {
			return PendingDoc{Version: "1.5.0", NodeURL: "https://siem-b:8443", Addresses: []string{"10.0.0.6"}}
		}
	})
	b.wantMode(ModeLegacyB)
	fp := b.rt.Status().Fingerprint
	src := e.os.Source(testRuntime, PendingID("n_siem-b"))
	if src == nil {
		t.Fatal("a server waiting to join wrote no pending document")
	}
	if src["fingerprint"] != fp || src["name"] != "siem-b" || src["version"] != "1.5.0" || src["node_url"] != "https://siem-b:8443" || src["os"] == "" {
		t.Errorf("pending = %v", src)
	}
	mustContain(t, "log", b.logs.String(), "waits to join cluster 'Signalith'")
	mustContain(t, "log", b.logs.String(), fp)
	if w := b.rt.Waiting(); !strings.Contains(w, "waits to join cluster 'Signalith'") || !strings.Contains(w, fp) || !strings.Contains(w, "signalith cluster approve") {
		t.Errorf("sign-in page line %q", w)
	}
	if a.rt.Waiting() != "" {
		t.Error("a member says it waits")
	}
	list, err := a.rt.Pending(ctx)
	if err != nil || len(list) != 1 || list[0].NodeID != "n_siem-b" || list[0].Fingerprint != fp {
		t.Fatalf("pending = %+v, %v", list, err)
	}
	w := b.rt.Warnings()
	if len(w) == 0 || !strings.Contains(w[0].Text, "signalith cluster approve") || !strings.Contains(w[0].Text, fp) {
		t.Errorf("warnings = %+v", w)
	}

	// It writes again every minute, keeping when it first asked.
	first := src["at"]
	b.step()
	if e.os.Source(testRuntime, PendingID("n_siem-b"))["at"] != first {
		t.Error("the pending document was written again within a minute")
	}
	e.clock.Advance(PendingEvery + time.Second)
	b.step()
	again := e.os.Source(testRuntime, PendingID("n_siem-b"))
	if again["at"] == first || again["requested_at"] != src["requested_at"] {
		t.Errorf("rewritten = %v, first %v", again, src)
	}

	// A forged pending document's fingerprint is worked out again from
	// its key.
	other, _ := NewNodeKey()
	e.os.Put(testRuntime, PendingID("n_forged"), map[string]any{"kind": PendingKind, "node_id": "n_forged", "name": "siem-a",
		"node_pub": other.PublicText(), "fingerprint": fp, "at": e.clock.Now()})
	list, _ = a.rt.Pending(ctx)
	for _, p := range list {
		if p.NodeID == "n_forged" && p.Fingerprint != other.Fingerprint() {
			t.Errorf("the forged document shows fingerprint %s", p.Fingerprint)
		}
	}
	e.os.Delete(testRuntime, PendingID("n_forged"))

	// An approval sealed to another node key is not used.
	approve(t, a, b, other.Public())
	b.step()
	b.wantMode(ModeLegacyB)
	if len(ClusterKeyFiles(b.dir)) != 0 {
		t.Fatal("a server kept a key from an approval it cannot open")
	}
	mustContain(t, "log", b.logs.String(), "cannot be used")

	// An approval forged by someone who can write the runtime index: a
	// key of their own, sealed to the server's public node key. It opens,
	// but does not verify the cluster document: nothing is kept, and the
	// approval is deleted.
	nk, err := (KeyStore{Dir: b.dir, Master: b.master}).LoadNodeKey()
	if err != nil {
		t.Fatal(err)
	}
	theirs, _ := NewClusterKey()
	forged, err := SealToNode(nk.Public(), "n_siem-b", theirs.ID(), []byte(theirs.Text()))
	if err != nil {
		t.Fatal(err)
	}
	e.os.Put(testRuntime, ApprovalID("n_siem-b"), map[string]any{"kind": ApprovalKind, "node_id": "n_siem-b", "kid": theirs.ID(), "sealed": forged, "at": e.clock.Now()})
	b.step()
	b.wantMode(ModeLegacyB)
	if len(ClusterKeyFiles(b.dir)) != 0 {
		t.Fatal("a server kept a key that does not verify the cluster document")
	}
	if e.os.Source(testRuntime, ApprovalID("n_siem-b")) != nil {
		t.Error("the forged approval was not deleted")
	}
	mustContain(t, "log", b.logs.String(), "does not verify the cluster's settings")

	// The real approval: the key is taken, then the server joins.
	approve(t, a, b, nk.Public())
	if e.os.Source(testRuntime, PendingID("n_siem-b")) != nil {
		t.Error("the pending document is still there after the approval")
	}
	b.step()
	if e.os.Source(testRuntime, ApprovalID("n_siem-b")) != nil {
		t.Error("the approval is still there after the server took it")
	}
	if !fileExists(ClusterKeyPath(b.dir, a.key().ID())) {
		t.Fatal("the approved server did not keep the cluster key")
	}
	b.step()
	b.wantMode(ModeMember)
	if b.rt.Waiting() != "" {
		t.Error("a joined server still says it waits")
	}
	if b.key().ID() != a.key().ID() {
		t.Errorf("joined with %s", b.key().ID())
	}
	kr, _ := b.rt.Keyring().Get()
	if m := kr.Members["n_siem-b"]; m.AddedBy != AddedByApproval || m.Fingerprint != fp {
		t.Errorf("keyring member = %+v", m)
	}
	mustContain(t, "log", b.logs.String(), "was approved")
	if list, _ := a.rt.Pending(ctx); len(list) != 0 {
		t.Errorf("still pending: %+v", list)
	}
}

func TestStalePendingIsDropped(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	a := e.server("siem-a", nil)
	a.holds.Store(true)
	a.step()
	b := e.server("siem-b", nil)
	b.wantMode(ModeLegacyB)
	e.os.Put(testRuntime, ApprovalID("n_gone"), map[string]any{"kind": ApprovalKind, "node_id": "n_gone", "at": e.clock.Now()})
	if n, err := a.rt.DropStalePending(ctx, e.clock.Now().Add(time.Hour)); err != nil || n != 0 {
		t.Fatalf("dropped %d, %v", n, err)
	}
	// A server in legacy mode never drops anything.
	if n, _ := b.rt.DropStalePending(ctx, e.clock.Now().Add(PendingStale+time.Hour)); n != 0 {
		t.Errorf("legacy dropped %d", n)
	}
	if n, err := a.rt.DropStalePending(ctx, e.clock.Now().Add(PendingStale+time.Hour)); err != nil || n != 2 {
		t.Fatalf("dropped %d, %v", n, err)
	}
	if e.os.Source(testRuntime, PendingID("n_siem-b")) != nil || e.os.Source(testRuntime, ApprovalID("n_gone")) != nil {
		t.Error("stale documents are still there")
	}
}

// A read-only runtime (the command line) never asks to join.
func TestReadOnlyNeverAsksToJoin(t *testing.T) {
	e := newEnv(t)
	a := e.server("siem-a", nil)
	a.holds.Store(true)
	a.step()
	b := e.server("siem-b", func(o *RuntimeOptions) { o.ReadOnly = true })
	b.wantMode(ModeLegacyB)
	if e.os.Source(testRuntime, PendingID("n_siem-b")) != nil {
		t.Error("a read-only runtime wrote a pending document")
	}
}

func TestKeyFileWarnsWithoutSecuredOpenSearch(t *testing.T) {
	e := newEnv(t)
	k, err := NewClusterKey()
	if err != nil {
		t.Fatal(err)
	}
	a := e.server("siem-a", func(o *RuntimeOptions) {
		o.KeyFile = writeKeyFile(t, k)
		o.Secured = func() error { return errors.New("Multi-server needs OpenSearch with security turned on.") }
	})
	a.holds.Store(true)
	a.step()
	a.wantMode(ModeMember)
	mustContain(t, "log", a.logs.String(), "while OpenSearch is not secured")
	var found bool
	for _, w := range a.rt.Warnings() {
		found = found || w.Level == "red" && strings.Contains(w.Text, "key file") && strings.Contains(w.Text, "security turned on")
	}
	if !found {
		t.Errorf("warnings %+v", a.rt.Warnings())
	}
	// Secured: no warning.
	b := e.server("siem-b", func(o *RuntimeOptions) {
		o.KeyFile = writeKeyFile(t, k)
		o.Secured = func() error { return nil }
	})
	b.step()
	for _, w := range b.rt.Warnings() {
		if strings.Contains(w.Text, "key file") {
			t.Errorf("a secured OpenSearch warns: %+v", w)
		}
	}
}
