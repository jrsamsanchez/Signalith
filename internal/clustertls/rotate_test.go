// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package clustertls

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"log/slog"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cluster"
	"github.com/jrsamsanchez/signalith/internal/shared"
	"github.com/jrsamsanchez/signalith/internal/tlsauto"
)

// heartbeat is a running server's heartbeat that uses the cluster's
// certificate authority cur, hands out next and serves a certificate
// from leaf.
func heartbeat(name, cur, next, leaf string, now time.Time) cluster.Heartbeat {
	return cluster.Heartbeat{NodeID: "n_" + name, Name: name, State: cluster.StateReady, HeartbeatAt: now,
		TLS: &cluster.TLSStatus{Mode: ModeAuto, Cluster: true, CASHA256: cur, NextCASHA256: next, LeafCASHA256: leaf, CARotation: true}}
}

// The cluster's certificate authority is replaced in three steps: the
// next one is made like the one in use and sealed bound to its own
// fingerprint, the switch waits for every running server to hand it out,
// and the retirement for every one to serve a certificate from it. Each
// step taken twice changes nothing more.
func TestRotateCASteps(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	ca := makeCA(t, "a", time.Now().Add(-time.Hour), "siem-a.example.com")
	tl, _ := e.server("siem-a")
	if _, _, err := tl.PrepareNext(ctx, "admin", ""); err == nil {
		t.Error("prepared with no certificate authority")
	}
	if err := tl.Publish(ctx, "admin", "siem-a", ca.pem, ca.key, []string{"agents.lan"}); err != nil {
		t.Fatal(err)
	}
	if b, _ := tl.Get(); b.Rotation() != RotationNone {
		t.Fatalf("state %s", b.Rotation())
	}
	if _, err := tl.SwitchNext(ctx, "admin", "siem-a", ""); err == nil {
		t.Error("switched with nothing prepared")
	}
	if _, _, err := tl.PrepareNext(ctx, "admin", "AB:CD"); err == nil {
		t.Error("prepared against another certificate authority than the one seen")
	}

	fp, already, err := tl.PrepareNext(ctx, "admin", ca.fp)
	if err != nil || already || fp == "" || SameFingerprint(fp, ca.fp) {
		t.Fatalf("prepare: %s %v %v", fp, already, err)
	}
	if again, already, err := tl.PrepareNext(ctx, "admin", ca.fp); err != nil || !already || again != fp {
		t.Errorf("prepare again: %s %v %v", again, already, err)
	}
	b, _ := tl.Get()
	if b.Rotation() != RotationPrepared || b.Next.By != "admin" || b.Next.At.IsZero() {
		t.Fatalf("after prepare %+v", b.Next)
	}
	next, err := b.Next.Cert()
	if err != nil {
		t.Fatal(err)
	}
	// The same template and name constraints as the one in use.
	if !slices.Equal(next.PermittedDNSDomains, ca.cert.PermittedDNSDomains) || len(next.PermittedIPRanges) != len(ca.cert.PermittedIPRanges) ||
		!next.PermittedDNSDomainsCritical || !next.MaxPathLenZero || !tlsauto.ServerOnly(next) {
		t.Errorf("next CA constraints %v %v", next.PermittedDNSDomains, next.PermittedIPRanges)
	}
	// Sealed, never in the clear, and bound to its own fingerprint.
	raw, _ := json.Marshal(b)
	if strings.Contains(string(raw), "PRIVATE KEY") {
		t.Fatal("the next key is in the clear")
	}
	if _, _, err := tl.openSealed(ca.cert, b.CASHA256, b.Next.CAKey); err == nil {
		t.Error("the next key opened under the current certificate")
	}
	if _, _, err := tl.openSealed(next, b.Next.CASHA256, b.Next.CAKey); err != nil {
		t.Errorf("the next key: %v", err)
	}
	// Each server hands out both.
	m, err := tlsauto.New(tlsauto.Options{Dir: filepath.Join(t.TempDir(), "tls"), Store: tl.Store()})
	if err != nil {
		t.Fatal(err)
	}
	m.SetClusterCAs(tl.Others)
	if n := m.Next(); n == nil || n.Fingerprint != fp {
		t.Fatalf("Manager's next %+v", n)
	}
	bundle := x509.NewCertPool()
	if !bundle.AppendCertsFromPEM(m.AgentCAPEM()) || strings.Count(string(m.AgentCAPEM()), "BEGIN CERTIFICATE") != 2 {
		t.Fatalf("bundle %s", m.AgentCAPEM())
	}
	if st := StatusOf(m, "", ""); st.NextCASHA256 != fp || st.LeafCASHA256 != ca.fp {
		t.Errorf("status %+v", st)
	}

	// The switch waits for every running server.
	now := time.Now()
	hbs := []cluster.Heartbeat{heartbeat("siem-a", ca.fp, fp, ca.fp, now), heartbeat("siem-b", ca.fp, "", ca.fp, now)}
	if bl := Blockers(b, hbs, now); len(bl) != 1 || !strings.Contains(bl[0], "siem-b doesn't hand out") {
		t.Errorf("blockers %v", bl)
	}
	// Stopped, offline, own files, no HTTPS: not waited for.
	hbs[1].State = cluster.StateStopped
	files := cluster.Heartbeat{Name: "siem-f", State: cluster.StateReady, HeartbeatAt: now, TLS: &cluster.TLSStatus{Mode: ModeFiles, CARotation: true}}
	off := cluster.Heartbeat{Name: "siem-o", State: cluster.StateReady, HeartbeatAt: now, TLS: StatusOf(nil, "", "")}
	old := cluster.Heartbeat{Name: "siem-old", State: cluster.StateReady, HeartbeatAt: now}
	if bl := Blockers(b, append(hbs, files, off), now); len(bl) != 0 {
		t.Errorf("blockers %v", bl)
	}
	if bl := Blockers(b, append(hbs, old), now); len(bl) != 1 || !strings.Contains(bl[0], "siem-old runs a version that can't replace") {
		t.Errorf("an older server: %v", bl)
	}

	if _, err := tl.SwitchNext(ctx, "admin", "siem-a", ca.fp); err == nil {
		t.Error("switched to a fingerprint that is not the prepared one")
	}
	if already, err := tl.SwitchNext(ctx, "admin", "siem-a", fp); err != nil || already {
		t.Fatalf("switch: %v %v", already, err)
	}
	if already, err := tl.SwitchNext(ctx, "admin", "siem-a", fp); err != nil || !already {
		t.Errorf("switch again: %v %v", already, err)
	}
	b, _ = tl.Get()
	if b.Rotation() != RotationSwitched || !SameFingerprint(b.CASHA256, fp) || !SameFingerprint(b.Previous.CASHA256, ca.fp) ||
		!slices.Equal(b.Names, []string{"agents.lan"}) || !slices.ContainsFunc(b.RetiredFingerprints(), func(r string) bool { return SameFingerprint(r, ca.fp) }) {
		t.Fatalf("after switch %+v", b)
	}
	if _, _, err := tl.PrepareNext(ctx, "admin", ""); !errors.Is(err, ErrRetireFirst) {
		t.Errorf("prepare while switched: %v", err)
	}
	// The server issues itself a certificate from the new one, and still
	// hands out the old one with it.
	if err := m.UseStore(tl.Store()); err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(next)
	if _, err := m.Leaf().Verify(x509.VerifyOptions{Roots: pool, DNSName: "agents.lan"}); err != nil {
		t.Errorf("certificate after the switch: %v", err)
	}
	if m.Next() != nil || strings.Count(string(m.AgentCAPEM()), "BEGIN CERTIFICATE") != 2 {
		t.Errorf("after the switch: next %v, bundle %s", m.Next(), m.AgentCAPEM())
	}
	if st := StatusOf(m, "", ""); st.LeafCASHA256 != fp || st.CASHA256 != fp || st.NextCASHA256 != "" {
		t.Errorf("status after the switch %+v", st)
	}

	// The retirement waits for every running server's certificate.
	hbs = []cluster.Heartbeat{heartbeat("siem-a", fp, "", fp, now), heartbeat("siem-b", fp, "", ca.fp, now)}
	if bl := Blockers(b, hbs, now); len(bl) != 1 || !strings.Contains(bl[0], "siem-b's certificate") {
		t.Errorf("retire blockers %v", bl)
	}
	if _, err := tl.RetirePrevious(ctx, "admin", fp); err == nil {
		t.Error("retired the certificate authority in use")
	}
	if already, err := tl.RetirePrevious(ctx, "admin", ca.fp); err != nil || already {
		t.Fatalf("retire: %v %v", already, err)
	}
	if already, err := tl.RetirePrevious(ctx, "admin", ca.fp); err != nil || !already {
		t.Errorf("retire again: %v %v", already, err)
	}
	b, _ = tl.Get()
	if b.Rotation() != RotationNone || b.Previous != nil {
		t.Fatalf("after retire %+v", b)
	}
	if strings.Count(string(m.AgentCAPEM()), "BEGIN CERTIFICATE") != 1 {
		t.Errorf("bundle after retire %s", m.AgentCAPEM())
	}
	r := BuildReport(ReportInput{Body: b, Now: now})
	if r.Rotation == nil || r.Rotation.State != RotationNone {
		t.Errorf("report %+v", r.Rotation)
	}
}

// The handler on the server that runs the jobs checks the servers again
// before a switch, and reports a step taken before.
func TestRotateHandler(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	ca := makeCA(t, "a", time.Now().Add(-time.Hour))
	tl, _ := e.server("siem-a")
	if err := tl.Publish(ctx, "admin", "siem-a", ca.pem, ca.key, nil); err != nil {
		t.Fatal(err)
	}
	var hbs []cluster.Heartbeat
	run := RotateHandler(tl, func(context.Context) ([]cluster.Heartbeat, error) { return hbs, nil }, "siem-a", nil)
	call := func(step, fp string) (*shared.Request, error) {
		raw, _ := json.Marshal(RotateArgs{Step: step, CASHA256: fp})
		req := &shared.Request{ID: "rq_1", RequestedBy: "admin", Args: raw}
		return req, run(ctx, req)
	}
	if _, err := call("bogus", ""); err == nil {
		t.Error("unknown step ran")
	}
	req, err := call(StepPrepare, ca.fp)
	if err != nil {
		t.Fatal(err)
	}
	var res RotateResult
	_ = json.Unmarshal(req.Result, &res)
	fp := res.CASHA256
	if fp == "" || res.Already {
		t.Fatalf("prepare result %+v", res)
	}
	now := time.Now()
	hbs = []cluster.Heartbeat{heartbeat("siem-b", ca.fp, "", ca.fp, now)}
	if _, err := call(StepSwitch, fp); err == nil || !strings.Contains(err.Error(), "siem-b doesn't hand out") {
		t.Fatalf("switch while siem-b is not ready: %v", err)
	}
	hbs[0].TLS.NextCASHA256 = fp
	if _, err := call(StepSwitch, fp); err != nil {
		t.Fatal(err)
	}
	req, err = call(StepSwitch, fp)
	_ = json.Unmarshal(req.Result, &res)
	if err != nil || !res.Already {
		t.Errorf("switch again: %v %+v", err, res)
	}
	if _, err := call(StepRetire, ca.fp); err == nil || !strings.Contains(err.Error(), "siem-b's certificate") {
		t.Fatalf("retire while siem-b is not ready: %v", err)
	}
	hbs[0].TLS.CASHA256, hbs[0].TLS.LeafCASHA256 = fp, fp
	if _, err := call(StepRetire, ca.fp); err != nil {
		t.Fatal(err)
	}
}

// A key rotation reseals the next certificate authority's key too.
func TestResealNext(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	ca := makeCA(t, "a", time.Now().Add(-time.Hour))
	tl, h := e.server("siem-a")
	if err := tl.Publish(ctx, "admin", "siem-a", ca.pem, ca.key, nil); err != nil {
		t.Fatal(err)
	}
	if _, _, err := tl.PrepareNext(ctx, "admin", ""); err != nil {
		t.Fatal(err)
	}
	k2, err := shared.NewClusterKey()
	if err != nil {
		t.Fatal(err)
	}
	h.SetKeys(shared.NewKeySet(k2, e.key))
	if err := tl.Resealer()(ctx); err != nil {
		t.Fatal(err)
	}
	h.SetKeys(shared.NewKeySet(k2))
	b, _ := tl.Get()
	if !strings.Contains(b.Next.CAKey, k2.ID()) {
		t.Fatalf("the next key was not resealed: %s", b.Next.CAKey[:20])
	}
	next, _ := b.Next.Cert()
	if _, _, err := tl.openSealed(next, b.Next.CASHA256, b.Next.CAKey); err != nil {
		t.Error(err)
	}
}

// Prepare waits for every running server to run a version that keeps the
// next and previous certificate authorities, and names the others.
func TestPrepareWaitsForOlderServers(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	ca := makeCA(t, "a", time.Now().Add(-time.Hour))
	tl, _ := e.server("siem-a")
	if err := tl.Publish(ctx, "admin", "siem-a", ca.pem, ca.key, nil); err != nil {
		t.Fatal(err)
	}
	b, _ := tl.Get()
	now := time.Now()
	older := heartbeat("siem-c", ca.fp, "", ca.fp, now)
	older.TLS.CARotation = false
	noTLS := cluster.Heartbeat{Name: "siem-d", State: cluster.StateReady, HeartbeatAt: now}
	stopped := cluster.Heartbeat{Name: "siem-e", State: cluster.StateStopped, HeartbeatAt: now}
	hbs := []cluster.Heartbeat{heartbeat("siem-a", ca.fp, "", ca.fp, now), older, noTLS, stopped}
	bl := Blockers(b, hbs, now)
	if len(bl) != 1 || !strings.Contains(bl[0], "siem-c, siem-d run a version that can't replace") || strings.Contains(bl[0], "siem-a") || strings.Contains(bl[0], "siem-e") {
		t.Fatalf("blockers %v", bl)
	}
	if _, err := CheckStep(b, bl, StepPrepare); err == nil || !strings.Contains(err.Error(), "siem-c, siem-d") {
		t.Errorf("check: %v", err)
	}
	run := RotateHandler(tl, func(context.Context) ([]cluster.Heartbeat, error) { return hbs, nil }, "siem-a", nil)
	raw, _ := json.Marshal(RotateArgs{Step: StepPrepare, CASHA256: ca.fp})
	if err := run(ctx, &shared.Request{ID: "rq_1", RequestedBy: "admin", Args: raw}); err == nil || !strings.Contains(err.Error(), "siem-c, siem-d") {
		t.Fatalf("handler: %v", err)
	}
	if b, _ := tl.Get(); b.Next != nil {
		t.Fatal("prepared with an older server running")
	}
	hbs = hbs[:1]
	if err := run(ctx, &shared.Request{ID: "rq_2", RequestedBy: "admin", Args: raw}); err != nil {
		t.Fatal(err)
	}
	if b, _ := tl.Get(); b.Next == nil {
		t.Fatal("not prepared once every server can")
	}
}

// A next key the resealer cannot open keeps its sealed value, and the
// failure is logged for the audit; the current key is still resealed.
func TestResealKeepsWhatItCannotOpen(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	ca := makeCA(t, "a", time.Now().Add(-time.Hour))
	tl, h := e.server("siem-a")
	var logs strings.Builder
	tl.SetLog(slog.New(slog.NewTextHandler(&logs, nil)))
	if err := tl.Publish(ctx, "admin", "siem-a", ca.pem, ca.key, nil); err != nil {
		t.Fatal(err)
	}
	if _, _, err := tl.PrepareNext(ctx, "admin", ""); err != nil {
		t.Fatal(err)
	}
	// The next key sealed with a key no server has any more.
	lost, _ := shared.NewClusterKey()
	b, _ := tl.Get()
	bogus, err := lost.SecretsKey().Seal(keyField(b.Next.CASHA256), "x")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tl.Doc().Mutate(ctx, "test", func(c *Body) error { c.Next.CAKey = bogus; return nil }); err != nil {
		t.Fatal(err)
	}
	k2, _ := shared.NewClusterKey()
	h.SetKeys(shared.NewKeySet(k2, e.key))
	if err := tl.Resealer()(ctx); err != nil {
		t.Fatal(err)
	}
	b, _ = tl.Get()
	if b.Next == nil || b.Next.CAKey != bogus {
		t.Fatalf("the next key was not kept: %+v", b.Next)
	}
	if !strings.Contains(b.CAKey, k2.ID()) {
		t.Error("the current key was not resealed")
	}
	if out := logs.String(); !strings.Contains(out, "audit=true") || !strings.Contains(out, "old sealed value is kept") || !strings.Contains(out, b.Next.CASHA256) {
		t.Errorf("log: %s", out)
	}
}
