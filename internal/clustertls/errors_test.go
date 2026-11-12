// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package clustertls

import (
	"context"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/agentinv"
	"github.com/jrsamsanchez/signalith/internal/cluster"
	"github.com/jrsamsanchez/signalith/internal/shared"
	"github.com/jrsamsanchez/signalith/internal/tlsauto"
)

func TestCheckStep(t *testing.T) {
	next := &OtherCA{CASHA256: "NE:XT"}
	prev := &OtherCA{CASHA256: "PR:EV"}
	block := []string{"siem-b is not ready"}
	for _, tc := range []struct {
		name     string
		b        Body
		blockers []string
		step     string
		want     string
		err      string
	}{
		{"prepare", Body{CASHA256: "CU:RR"}, nil, StepPrepare, "CU:RR", ""},
		{"prepare blocked", Body{CASHA256: "CU:RR"}, block, StepPrepare, "", "not every server is ready to replace"},
		{"prepare again", Body{CASHA256: "CU:RR", Next: next}, block, StepPrepare, "CU:RR", ""},
		{"prepare switched", Body{CASHA256: "CU:RR", Previous: prev}, nil, StepPrepare, "", ErrRetireFirst.Error()},
		{"switch", Body{Next: next}, nil, StepSwitch, "NE:XT", ""},
		{"switch nothing", Body{}, nil, StepSwitch, "", "no new certificate authority is prepared"},
		{"switch blocked", Body{Next: next}, block, StepSwitch, "", "not every server is ready to switch"},
		{"abort", Body{Next: next}, block, StepAbort, "NE:XT", ""},
		{"abort switched", Body{Previous: prev}, nil, StepAbort, "", "already switched"},
		{"abort nothing", Body{}, nil, StepAbort, "", "nothing to abort"},
		{"retire", Body{Previous: prev}, nil, StepRetire, "PR:EV", ""},
		{"retire prepared", Body{Next: next}, nil, StepRetire, "", "hasn't switched"},
		{"retire nothing", Body{}, nil, StepRetire, "", "no certificate authority is waiting"},
		{"retire blocked", Body{Previous: prev}, block, StepRetire, "", "ready to retire"},
		{"bogus", Body{}, nil, "bogus", "", ErrBadStep.Error()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := CheckStep(&tc.b, tc.blockers, tc.step)
			if tc.err == "" {
				if err != nil || got != tc.want {
					t.Fatalf("CheckStep = %q, %v; want %q", got, err, tc.want)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.err) {
				t.Fatalf("CheckStep error %v, want %q", err, tc.err)
			}
		})
	}
	if Blockers(nil, nil, time.Now()) != nil {
		t.Fatal("blockers of no document")
	}
}

// A holder whose document is not tracked yet refuses every change.
func TestUntrackedTLS(t *testing.T) {
	ctx := context.Background()
	ca := makeCA(t, "a", time.Now())
	tl := New()
	if b, ok := tl.Get(); ok || b == nil {
		t.Fatalf("Get: %v %v", b, ok)
	}
	if n, p := tl.Others(); n != nil || p != nil {
		t.Fatal("Others of no document")
	}
	if c, k, err := tl.Store().Load(); c != nil || k != nil || err != nil {
		t.Fatalf("Load of no document: %v %v %v", c, k, err)
	}
	if err := tl.Resealer()(ctx); err != nil {
		t.Fatalf("Resealer: %v", err)
	}
	if tl.logger() == nil {
		t.Fatal("no logger")
	}
	if _, _, err := tl.openSealed(ca.cert, ca.fp, "enc:x"); err == nil {
		t.Fatal("opened a key with no settings")
	}
	steps := map[string]error{}
	_, _, steps["prepare"] = tl.PrepareNext(ctx, "admin", "")
	_, steps["switch"] = tl.SwitchNext(ctx, "admin", "siem", "")
	_, steps["retire"] = tl.RetirePrevious(ctx, "admin", "")
	_, steps["abort"] = tl.AbortNext(ctx, "admin", "")
	steps["publish"] = tl.Publish(ctx, "admin", "siem", ca.pem, ca.key, nil)
	_, steps["import"] = tl.ImportKey(ctx, "admin", nil, ca.key)
	steps["retired"] = tl.AddRetired(ctx, "siem", ca.cert)
	steps["name"] = tl.Store().AddName(ctx, "siem.lan")
	_, steps["submit"] = tl.SubmitPublish(ctx, nil, "n_a", ca.fp, "admin")
	raw, _ := json.Marshal(RotateArgs{Step: StepPrepare})
	steps["rotate"] = RotateHandler(tl, nil, "siem", nil)(ctx, &shared.Request{Args: raw})
	pub, _ := json.Marshal(PublishArgs{CASHA256: ca.fp})
	steps["handler"] = Handler(tl, nil, "siem", nil)(ctx, &shared.Request{Args: pub})
	for name, err := range steps {
		if err == nil {
			t.Errorf("%s: no error with no shared settings", name)
		}
	}
}

func TestSubscribersAndReset(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	ca := makeCA(t, "a", time.Now(), "siem.example.com")
	tl, h := e.server("siem-a")
	var mu sync.Mutex
	calls := 0
	tl.OnChange(func(_, nw *Body) {
		mu.Lock()
		defer mu.Unlock()
		calls++
	})
	if err := tl.Publish(ctx, "admin", "siem-a", ca.pem, ca.key, nil); err != nil {
		t.Fatal(err)
	}
	if err := h.Cycle(ctx); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	n := calls
	mu.Unlock()
	if n == 0 {
		t.Fatal("the subscriber was not told of the publish")
	}
	tl.Reset()
	if err := tl.Store().AddName(ctx, "siem.example.com"); err != nil {
		t.Fatal(err)
	}
	// The same name again changes nothing.
	if err := tl.Store().AddName(ctx, "siem.example.com"); err != nil {
		t.Fatal(err)
	}
	if err := tl.Store().AddName(ctx, "other.test"); err == nil {
		t.Fatal("a name the certificate authority may not sign was added")
	}
	if err := h.Cycle(ctx); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if calls != n {
		t.Fatal("a subscriber was told after Reset")
	}
}

func TestNoCertificateAuthorityYet(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	tl, _ := e.server("siem-a")
	if _, err := tl.SwitchNext(ctx, "admin", "siem-a", ""); !errors.Is(err, errNoCA) {
		t.Errorf("switch: %v", err)
	}
	if _, err := tl.RetirePrevious(ctx, "admin", ""); !errors.Is(err, errNoCA) {
		t.Errorf("retire: %v", err)
	}
	if _, err := tl.AbortNext(ctx, "admin", ""); !errors.Is(err, errNoCA) {
		t.Errorf("abort: %v", err)
	}
	if err := tl.AddRetired(ctx, "siem-a", nil); err != nil {
		t.Errorf("AddRetired of nothing: %v", err)
	}
	if err := tl.Resealer()(ctx); err != nil {
		t.Errorf("Resealer of no document: %v", err)
	}
	if err := tl.Store().AddName(ctx, "siem.lan"); err == nil {
		t.Error("a name added with no certificate authority")
	}
	if _, err := tl.ImportKey(ctx, "admin", nil, nil); err == nil {
		t.Error("imported no key")
	}
}

func TestRotationRefusals(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	ca := makeCA(t, "a", time.Now().Add(-time.Hour), "siem.example.com")
	tl, h := e.server("siem-a")
	if err := tl.Publish(ctx, "admin", "siem-a", ca.pem, ca.key, nil); err != nil {
		t.Fatal(err)
	}
	fp, _, err := tl.PrepareNext(ctx, "admin", ca.fp)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tl.RetirePrevious(ctx, "admin", ""); err == nil || !strings.Contains(err.Error(), "switch first") {
		t.Errorf("retire while prepared: %v", err)
	}
	if _, err := tl.AbortNext(ctx, "admin", ca.fp); err == nil || !strings.Contains(err.Error(), "look again") {
		t.Errorf("abort of another one: %v", err)
	}
	if n, p := tl.Others(); n == nil || p != nil || !SameFingerprint(tlsauto.Fingerprint(n.Cert.Raw), fp) {
		t.Errorf("Others while prepared: %v %v", n, p)
	}
	if _, err := tl.AbortNext(ctx, "admin", fp); err != nil {
		t.Fatal(err)
	}
	// Without a cluster key nothing can be sealed or signed.
	h.SetKeys(shared.NewKeySet(nil))
	if _, err := tl.publishArgs("n_a", ca.fp, "admin", time.Now()); err == nil {
		t.Error("signed a request with no cluster key")
	}
	other := makeCA(t, "b", time.Now())
	if err := tl.Publish(ctx, "admin", "siem-a", other.pem, other.key, nil); err == nil || !strings.Contains(err.Error(), "no cluster key") {
		t.Errorf("published with no cluster key: %v", err)
	}
	if _, _, err := tl.PrepareNext(ctx, "admin", ""); err == nil || !strings.Contains(err.Error(), "no cluster key") {
		t.Errorf("prepared with no cluster key: %v", err)
	}
}

func TestRotateHandlerErrors(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	ca := makeCA(t, "a", time.Now().Add(-time.Hour))
	tl, _ := e.server("siem-a")
	if err := tl.Publish(ctx, "admin", "siem-a", ca.pem, ca.key, nil); err != nil {
		t.Fatal(err)
	}
	var readErr error
	run := RotateHandler(tl, func(context.Context) ([]cluster.Heartbeat, error) { return nil, readErr }, "siem-a", nil)
	call := func(step, fp string) error {
		raw, _ := json.Marshal(RotateArgs{Step: step, CASHA256: fp})
		return run(ctx, &shared.Request{ID: "rq_1", RequestedBy: "admin", Args: raw})
	}
	if err := run(ctx, &shared.Request{Args: json.RawMessage(`[`)}); err == nil {
		t.Error("arguments that are not JSON")
	}
	readErr = errors.New("timeout")
	if err := call(StepPrepare, ca.fp); err == nil || !strings.Contains(err.Error(), "heartbeats cannot be read") {
		t.Errorf("prepare without heartbeats: %v", err)
	}
	readErr = nil
	if err := call(StepPrepare, "AB:CD"); err == nil {
		t.Error("prepared against another certificate authority")
	}
	fp, _, err := tl.PrepareNext(ctx, "admin", ca.fp)
	if err != nil {
		t.Fatal(err)
	}
	readErr = errors.New("timeout")
	if err := call(StepSwitch, fp); err == nil || !strings.Contains(err.Error(), "not safe to switch") {
		t.Errorf("switch without heartbeats: %v", err)
	}
	readErr = nil
	if err := call(StepSwitch, ca.fp); err == nil {
		t.Error("switched to one that is not prepared")
	}
	if err := call(StepSwitch, fp); err != nil {
		t.Fatal(err)
	}
	if err := call(StepAbort, fp); err == nil || !strings.Contains(err.Error(), "already switched") {
		t.Errorf("abort after the switch: %v", err)
	}
	if err := run(cancelledCtx(), &shared.Request{Args: json.RawMessage(`{"step":"retire"}`)}); err == nil {
		t.Error("ran without reading the document")
	}
}

func cancelledCtx() context.Context {
	c, cancel := context.WithCancel(context.Background())
	cancel()
	return c
}

func TestValidateBody(t *testing.T) {
	now := time.Now()
	cur := makeCA(t, "cur", now.Add(-time.Hour), "siem.example.com")
	old := makeCA(t, "old", now.Add(-time.Hour), "siem.example.com")
	leaf := leafOf(t, cur)
	garbage := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("junk")}))
	base := func() *Body { return &Body{CACertPEM: string(cur.pem), CASHA256: cur.fp} }
	prev := func(o *OtherCA) *Body { b := base(); b.Previous = o; return b }
	oldCA := func() *OtherCA { return &OtherCA{CACertPEM: string(old.pem), CASHA256: old.fp} }
	many := make([]string, MaxNames+1)
	for i := range many {
		many[i] = fmt.Sprintf("n%d.siem.example.com", i)
	}
	for _, tc := range []struct {
		name string
		b    *Body
		want string
	}{
		{"garbage", &Body{CACertPEM: garbage}, "cannot be read"},
		{"not a CA", &Body{CACertPEM: string(pemOf(leaf)), CASHA256: tlsauto.Fingerprint(leaf.Raw)}, "not a certificate authority"},
		{"key in the clear", &Body{CACertPEM: string(cur.pem), CASHA256: cur.fp, CAKey: "-----BEGIN PRIVATE KEY-----"}, "not sealed"},
		{"too many names", &Body{CACertPEM: string(cur.pem), CASHA256: cur.fp, Names: many}, "more than"},
		{"next and previous", func() *Body { b := prev(oldCA()); b.Next = oldCA(); return b }(), "both"},
		{"other garbage", prev(&OtherCA{CACertPEM: garbage}), "cannot be read"},
		{"other fingerprint", prev(&OtherCA{CACertPEM: string(old.pem), CASHA256: cur.fp}), "does not match its fingerprint"},
		{"other is current", prev(&OtherCA{CACertPEM: string(cur.pem), CASHA256: cur.fp}), "twice"},
		{"other key in the clear", prev(&OtherCA{CACertPEM: string(old.pem), CASHA256: old.fp, CAKey: "plain"}), "other key is not sealed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := validate(tc.b); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("validate: %v, want %q", err, tc.want)
			}
		})
	}
	if err := validate(prev(oldCA())); err != nil {
		t.Fatalf("a valid body: %v", err)
	}
	if (&OtherCA{CACertPEM: garbage}).clusterCA() != nil {
		t.Fatal("a CA that cannot be read for tlsauto")
	}
}

func TestPublishRefusesBadInput(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	ca := makeCA(t, "a", time.Now())
	other := makeCA(t, "b", time.Now())
	tl, _ := e.server("siem-a")
	for name, tc := range map[string]struct {
		pem []byte
		key crypto.Signer
	}{
		"no PEM":        {[]byte("nothing"), ca.key},
		"not a cert":    {pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("x")}), ca.key},
		"garbage cert":  {pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("junk")}), ca.key},
		"another's key": {ca.pem, other.key},
		"no key":        {ca.pem, nil},
	} {
		if err := tl.Publish(ctx, "admin", "siem-a", tc.pem, tc.key, nil); err == nil {
			t.Errorf("%s: published", name)
		}
	}
	if _, ok := tl.Get(); ok {
		t.Fatal("something was published")
	}
	if err := tl.Publish(ctx, "admin", "siem-a", ca.pem, ca.key, nil); err != nil {
		t.Fatal(err)
	}
	// The certificate given with a key must be the cluster's.
	for name, certPEM := range map[string][]byte{
		"no PEM":       []byte("nothing"),
		"garbage cert": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("junk")}),
		"another CA":   other.pem,
	} {
		if _, err := tl.ImportKey(ctx, "admin", certPEM, ca.key); err == nil {
			t.Errorf("import with %s: accepted", name)
		}
	}
	if _, err := tl.ImportKey(cancelledCtx(), "admin", nil, ca.key); err == nil {
		t.Error("imported without reading the document")
	}
	if changed, err := tl.ImportKey(ctx, "admin", ca.pem, ca.key); err != nil || changed {
		t.Errorf("import of the key it holds: %v %v", changed, err)
	}
}

func TestParseKeyForms(t *testing.T) {
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecDER, err := x509.MarshalECPrivateKey(ec)
	if err != nil {
		t.Fatal(err)
	}
	rk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	xk, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	xDER, err := x509.MarshalPKCS8PrivateKey(xk)
	if err != nil {
		t.Fatal(err)
	}
	enc := func(typ string, der []byte) []byte { return pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}) }
	for _, tc := range []struct {
		name string
		data []byte
		ok   bool
	}{
		{"ec", enc("EC PRIVATE KEY", ecDER), true},
		{"rsa", enc("RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(rk)), true},
		{"damaged ec", enc("EC PRIVATE KEY", []byte("junk")), false},
		{"cannot sign", enc("PRIVATE KEY", xDER), false},
	} {
		k, err := ParseKey(tc.data)
		if (err == nil) != tc.ok || (tc.ok && k == nil) {
			t.Errorf("%s: %v %v", tc.name, k, err)
		}
	}
	for _, tc := range []struct {
		name string
		data []byte
	}{
		{"not PEM", []byte("nothing")},
		{"damaged", enc("PRIVATE KEY", []byte("junk"))},
		{"cannot sign", enc("PRIVATE KEY", xDER)},
	} {
		if _, err := parseKey(tc.data); err == nil {
			t.Errorf("parseKey %s: no error", tc.name)
		}
	}
}

func TestPublishHandlerAndImporterEdges(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	ca := makeCA(t, "a", time.Now())
	other := makeCA(t, "b", time.Now())
	tl, h := e.server("siem-b")
	// A server that no longer has a CA of its own publishes nothing.
	a, err := tl.publishArgs("n_b", ca.fp, "admin", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(a)
	req := &shared.Request{ID: "rq_1", Target: "n_b", Args: raw, RequestedBy: "admin"}
	none := Handler(tl, func() (*x509.Certificate, crypto.Signer, []string) { return nil, nil, nil }, "siem-b", slog.New(slog.DiscardHandler))
	if err := none(ctx, req); err == nil || !strings.Contains(err.Error(), "no longer has") {
		t.Errorf("no CA of its own: %v", err)
	}
	// Its own CA with a key that is not its own cannot be published.
	bad := Handler(tl, func() (*x509.Certificate, crypto.Signer, []string) { return ca.cert, other.key, nil }, "siem-b", nil)
	if err := bad(ctx, req); err == nil {
		t.Error("published a CA with another's key")
	}
	// A request is submitted to the shared settings, signed.
	sub, err := tl.SubmitPublish(ctx, shared.NewRequests(h, "n_b"), "n_b", ca.fp, "admin")
	if err != nil {
		t.Fatal(err)
	}
	var got PublishArgs
	if err := json.Unmarshal(sub.Args, &got); err != nil || got.MAC == "" || got.Target != "n_b" {
		t.Fatalf("submitted %+v %v", got, err)
	}

	// The importer: no way to read the local CA, one with no key, and
	// another CA published meanwhile.
	if h, err := Importer(ImporterOptions{TLS: tl}).Source(); err != nil || h != "" {
		t.Errorf("no local CA: %q %v", h, err)
	}
	noKey := Importer(ImporterOptions{TLS: tl, Local: func() (*x509.Certificate, crypto.Signer, []string) { return ca.cert, nil, nil }})
	if err := noKey.Run(ctx, "admin"); err != nil {
		t.Errorf("a CA with no key: %v", err)
	}
	now := time.Now()
	servers := func(context.Context) ([]Server, error) { return []Server{hb("siem-b", ca, now, true)}, nil }
	wrong := Importer(ImporterOptions{TLS: tl, Node: "siem-b", Now: func() time.Time { return now }, Servers: servers,
		Local: func() (*x509.Certificate, crypto.Signer, []string) { return ca.cert, other.key, nil }})
	if err := wrong.Run(ctx, "admin"); err == nil {
		t.Error("published a CA with another's key")
	}
	if err := tl.Publish(ctx, "admin", "siem-a", other.pem, other.key, nil); err != nil {
		t.Fatal(err)
	}
	// Another server published its own meanwhile: the import is done.
	tl2, _ := e.server("siem-c")
	late := Importer(ImporterOptions{TLS: tl2, Node: "siem-c", Servers: servers,
		Local: func() (*x509.Certificate, crypto.Signer, []string) { return ca.cert, ca.key, nil }})
	if err := late.Run(ctx, "admin"); err != nil {
		t.Errorf("another CA published meanwhile: %v", err)
	}
}

func TestCandidatesOrder(t *testing.T) {
	now := time.Now()
	early := makeCA(t, "early", now.Add(-2*time.Hour))
	later := makeCA(t, "later", now.Add(-time.Hour))
	twin := makeCA(t, "twin", now.Add(-time.Hour))
	servers := []Server{hb("siem-c", later, now, false), hb("siem-b", early, now, false), hb("siem-d", twin, now, false)}
	// An agent with an empty pin list and one address is no one's.
	agents := []agentinv.Agent{{Key: "k1", Name: "web1", Addresses: []string{"10.0.0.1"}, CA: []string{""}, LastSeen: now}}
	cs := Candidates(servers, agents, now)
	if len(cs) != 3 {
		t.Fatalf("%d candidates", len(cs))
	}
	// No agents and no founder: the oldest first, then by fingerprint.
	if !SameFingerprint(cs[0].CASHA256, early.fp) || !cs[0].Preselected {
		t.Fatalf("first %s, want the oldest %s", cs[0].CASHA256, early.fp)
	}
	if strings.Compare(cs[1].CASHA256, cs[2].CASHA256) > 0 && cs[1].NotBefore.Equal(cs[2].NotBefore) {
		t.Fatalf("same age not ordered by fingerprint: %s %s", cs[1].CASHA256, cs[2].CASHA256)
	}
	r := refOf(agents[0])
	if r.Address != "10.0.0.1" || r.Key != "k1" {
		t.Fatalf("refOf %+v", r)
	}
}

// A key lost to a reset of the cluster key is not given back by a
// server that has no cluster key to seal it with.
func TestImportKeyWithoutAClusterKey(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	ca := makeCA(t, "a", time.Now().Add(-time.Hour), "siem-a.example.com")
	a, _ := e.server("siem-a")
	if err := a.Publish(ctx, "admin", "siem-a", ca.pem, ca.key, []string{"agents.lan"}); err != nil {
		t.Fatal(err)
	}
	e.resetKey("siem-a")
	tl, h := e.server("siem-b")
	h.SetKeys(shared.NewKeySet(nil))
	if _, err := tl.ImportKey(ctx, "admin", ca.pem, ca.key); err == nil {
		t.Error("a key imported with no cluster key")
	}
}

// A rotation step asked on a server that has not read another server's
// step yet is judged against the tls document as it is: done already, or
// refused when what it saw changed meanwhile.
func TestRotationStepsFromAStaleServer(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	ca := makeCA(t, "a", time.Now().Add(-time.Hour), "siem-a.example.com")
	a, _ := e.server("siem-a")
	b, hb := e.server("siem-b")
	if err := a.Publish(ctx, "admin", "siem-a", ca.pem, ca.key, []string{"agents.lan"}); err != nil {
		t.Fatal(err)
	}
	cycle := func() {
		t.Helper()
		if err := hb.Cycle(ctx); err != nil {
			t.Fatal(err)
		}
	}
	prepare := func() string {
		t.Helper()
		fp, _, err := a.PrepareNext(ctx, "admin", "")
		if err != nil {
			t.Fatal(err)
		}
		return fp
	}
	cycle()

	// Prepared on A: B prepares nothing more.
	fp := prepare()
	if got, already, err := b.PrepareNext(ctx, "admin", ""); err == nil && (!already || got != fp) ||
		err != nil && !strings.Contains(err.Error(), "meanwhile") {
		t.Errorf("prepare on B: %s %v %v", got, already, err)
	}
	cycle()

	// Switched on A: B's switch is done already.
	if _, err := a.SwitchNext(ctx, "admin", "siem-a", fp); err != nil {
		t.Fatal(err)
	}
	if already, err := b.SwitchNext(ctx, "admin", "siem-b", fp); err != nil || !already {
		t.Errorf("switch on B: %v %v", already, err)
	}
	cycle()

	// Retired on A: B's retirement is done already.
	if _, err := a.RetirePrevious(ctx, "admin", ""); err != nil {
		t.Fatal(err)
	}
	if already, err := b.RetirePrevious(ctx, "admin", ""); err != nil || !already {
		t.Errorf("retire on B: %v %v", already, err)
	}
	cycle()

	// Another one prepared on A after B looked: B's abort and switch of
	// the one it saw are refused.
	prepare()
	cycle()
	if _, err := a.AbortNext(ctx, "admin", ""); err != nil {
		t.Fatal(err)
	}
	prepare()
	if _, err := b.AbortNext(ctx, "admin", ""); err == nil || !strings.Contains(err.Error(), "changed meanwhile") {
		t.Errorf("abort on B of another prepared CA: %v", err)
	}
	// B has read the document again; A replaces the prepared one again.
	if _, err := a.AbortNext(ctx, "admin", ""); err != nil {
		t.Fatal(err)
	}
	prepare()
	if _, err := b.SwitchNext(ctx, "admin", "siem-b", ""); err == nil || !strings.Contains(err.Error(), "changed meanwhile") {
		t.Errorf("switch on B to another prepared CA: %v", err)
	}
	cycle()

	// Aborted on A: B's abort is done already.
	if _, err := a.AbortNext(ctx, "admin", ""); err != nil {
		t.Fatal(err)
	}
	if already, err := b.AbortNext(ctx, "admin", ""); err != nil || !already {
		t.Errorf("abort on B: %v %v", already, err)
	}
	cycle()

	// Switched on A: B can no longer abort.
	fp = prepare()
	cycle()
	if _, err := a.SwitchNext(ctx, "admin", "siem-a", fp); err != nil {
		t.Fatal(err)
	}
	if _, err := b.AbortNext(ctx, "admin", ""); !errors.Is(err, errAbortSwitched) {
		t.Errorf("abort on B after the switch: %v", err)
	}
	switchAgain := func() {
		t.Helper()
		if _, err := a.SwitchNext(ctx, "admin", "siem-a", prepare()); err != nil {
			t.Fatal(err)
		}
	}
	cycle()

	// Retired and replaced again on A: the one B would retire is gone.
	if _, err := a.RetirePrevious(ctx, "admin", ""); err != nil {
		t.Fatal(err)
	}
	switchAgain()
	if _, err := b.RetirePrevious(ctx, "admin", ""); err == nil || !strings.Contains(err.Error(), "changed meanwhile") {
		t.Errorf("retire on B of another previous CA: %v", err)
	}
	if _, err := a.RetirePrevious(ctx, "admin", ""); err != nil {
		t.Fatal(err)
	}
	cycle()

	// Switched on A after B looked: B prepares against a CA no longer
	// in use.
	switchAgain()
	if _, _, err := b.PrepareNext(ctx, "admin", ""); !errors.Is(err, ErrOtherCA) {
		t.Errorf("prepare on B after a switch: %v", err)
	}
}
