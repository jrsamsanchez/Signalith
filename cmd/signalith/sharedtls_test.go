package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/agentinv"
	"github.com/jrsamsanchez/signalith/internal/cluster/ostest"
	"github.com/jrsamsanchez/signalith/internal/clustertls"
	"github.com/jrsamsanchez/signalith/internal/shared"
	"github.com/jrsamsanchez/signalith/internal/tlsauto"
)

// fastTLSPoll makes the servers look at the tls document often.
func fastTLSPoll(t *testing.T) {
	old := tlsPoll
	tlsPoll = 100 * time.Millisecond
	t.Cleanup(func() { tlsPoll = old })
}

// caFingerprint is the SHA-256 fingerprint of the certificate in p, as
// tlsauto writes it.
func caFingerprint(t *testing.T, p []byte) string {
	t.Helper()
	block, _ := pem.Decode(p)
	if block == nil {
		t.Fatal("no PEM certificate")
	}
	return tlsauto.Fingerprint(block.Bytes)
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// dialWith reaches addr over TLS trusting only caPEM, checking the name.
func dialWith(addr string, caPEM []byte) error {
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caPEM)
	conn, err := tls.Dial("tcp", addr, &tls.Config{RootCAs: pool})
	if err != nil {
		return err
	}
	return conn.Close()
}

// The founder of a cluster of one publishes its own certificate
// authority: its fingerprint stays, and ca.key leaves its disk once the
// cluster keeps the key. A server that joins with a certificate authority
// of its own takes the cluster's within a poll, retires its own to
// tls/retired, and flags agents pinned to it; a name added on one server
// reaches the other's certificate; the move probe trusts the cluster's
// certificate authority, with the name checked.
func TestClusterCAAcrossServers(t *testing.T) {
	t.Setenv(clusterKeyFileEnv, "")
	fastSharedCheck(t)
	fastTLSPoll(t)
	fos := ostest.New(t)
	a := startRunnerWith(t, runOptions{scheduler: true, os: fos, name: "siem-a"})
	caA := a.ownCA()
	fpA := caFingerprint(t, caA)
	a.settingsShared()
	eventually(t, "A publishes its certificate authority", func() bool {
		b, ok := a.r.sharedContent.tls.tls.Get()
		return ok && clustertls.SameFingerprint(b.CASHA256, fpA)
	})
	certsA := a.r.sharedContent.tls.certs.Load()
	eventually(t, "A uses the cluster's store and deletes ca.key", func() bool {
		return certsA.Store() == tlsauto.KindCluster && !fileExists(filepath.Join(a.dir, "tls", "ca.key"))
	})
	if certsA.Fingerprint() != fpA || !fileExists(filepath.Join(a.dir, "tls", "cluster-ca.txt")) {
		t.Fatalf("A's CA %s, want %s", certsA.Fingerprint(), fpA)
	}
	if err := dialWith(a.addr, caA); err != nil {
		t.Fatalf("A's certificate with its own CA: %v", err)
	}
	if err := certsA.Prepare(tlsauto.ScopeStandard); err == nil || !strings.Contains(err.Error(), "cluster's certificate authority") {
		t.Fatalf("Prepare on A: %v", err)
	}
	// The sealed key is in the document, never in the clear.
	var doc map[string]any
	if !sharedBody(t, fos, clustertls.DocID, &doc) || strings.Contains(string(mustJSON(t, doc)), "PRIVATE KEY") {
		t.Fatalf("tls document %v", doc)
	}

	giveKey(t, a)
	// B starts with the cluster key: it makes a certificate authority of
	// its own on its first start, as every server does, and takes the
	// cluster's as soon as it reads the tls document.
	b := startRunnerWith(t, runOptions{scheduler: true, os: fos, name: "siem-b"})
	b.useHTTPS(caA)
	b.settingsShared()
	certsB := b.r.sharedContent.tls.certs.Load()
	eventually(t, "B takes the cluster's certificate authority", func() bool {
		return certsB.Fingerprint() == fpA && certsB.Store() == tlsauto.KindCluster
	})
	if err := dialWith(b.addr, caA); err != nil {
		t.Fatalf("B's certificate with the cluster's CA: %v", err)
	}
	if fileExists(filepath.Join(b.dir, "tls", "ca.key")) {
		t.Error("B kept its own ca.key")
	}
	retired, _ := filepath.Glob(filepath.Join(b.dir, "tls", "retired", "*", "ca.pem"))
	if len(retired) != 1 {
		t.Fatalf("retired on B: %v", retired)
	}
	caB, _ := os.ReadFile(retired[0])
	fpB := caFingerprint(t, caB)
	if fpB == fpA {
		t.Fatal("B retired the cluster's certificate authority")
	}
	eventually(t, "the cluster records B's old certificate authority", func() bool {
		body, ok := a.r.sharedContent.tls.tls.Get()
		return ok && slices.ContainsFunc(body.RetiredFingerprints(), func(fp string) bool { return clustertls.SameFingerprint(fp, fpB) })
	})
	pin := agentinv.Pin(fpB)
	for _, rs := range []*running{a, b} {
		if inv := rs.r.agents.Load(); inv == nil || inv.Retired == nil || !slices.Contains(inv.Retired(), pin) {
			t.Errorf("%s: agents pinned to B's old CA are not flagged", rs.r.node.Name())
		}
	}
	eventually(t, "B's heartbeat says it uses the cluster's certificate authority", func() bool {
		hb := fos.Source("signalith_runtime", "node:"+b.r.node.ID())
		st, _ := hb["tls_ca"].(map[string]any)
		return st != nil && st["cluster"] == true && clustertls.SameFingerprint(st["ca_sha256"].(string), fpA)
	})

	// A name added on A (Add data) reaches B's certificate.
	if err := certsA.EnsureName("agents.internal"); err != nil {
		t.Fatal(err)
	}
	eventually(t, "B's certificate covers the name added on A", func() bool { return certsB.Covers("agents.internal") })
	if fileExists(filepath.Join(a.dir, "tls", "names.txt")) && strings.Contains(readFile(t, filepath.Join(a.dir, "tls", "names.txt")), "agents.internal") {
		t.Error("the cluster's name went to names.txt")
	}

	// The move probe trusts the cluster's certificate authority, and
	// checks the name.
	conf := a.r.sharedContent.tls.probeTLS(false, "")
	if conf == nil || conf.InsecureSkipVerify {
		t.Fatalf("probe config %+v", conf)
	}
	// The cluster's certificate authority alone, not the system's too.
	only := x509.NewCertPool()
	only.AppendCertsFromPEM(caA)
	if !conf.RootCAs.Equal(only) {
		t.Fatal("the probe trusts more than the cluster's certificate authority")
	}
	// A server with its own certificate files is checked against the
	// system's and its own root, so B's certificate fails there.
	if conn, err := tls.Dial("tcp", b.addr, a.r.sharedContent.tls.probeTLS(true, "")); err == nil {
		conn.Close()
		t.Fatal("a files-mode probe trusted the cluster's certificate authority")
	}
	conn, err := tls.Dial("tcp", b.addr, conf)
	if err != nil {
		t.Fatalf("probe of B: %v", err)
	}
	conn.Close()
	bad := conf.Clone()
	bad.ServerName = "not-a-name-of-b.example"
	if conn, err := tls.Dial("tcp", b.addr, bad); err == nil {
		conn.Close()
		t.Fatal("the probe accepted a certificate for another name")
	}

	// A restart in place of B keeps the cluster's certificate authority.
	b.stop()
	b2 := startRunnerWith(t, runOptions{scheduler: true, os: fos, name: "siem-b", dir: b.dir})
	_ = b2
	if fileExists(filepath.Join(b.dir, "tls", "ca.key")) {
		t.Fatal("B made a certificate authority of its own again")
	}
	eventually(t, "B serves from the cluster's certificate authority again", func() bool {
		m := b2.r.sharedContent.tls.certs.Load()
		return m != nil && m.Fingerprint() == fpA && b2.r.sharedContent.tls.attached.Load() == m
	})

	// ca.key leaves the founder's disk only once the document read back
	// now holds it and the copy in cache.enc does too: with the document
	// gone from OpenSearch, or tampered with, the key would stay.
	ctx := context.Background()
	if !a.r.sharedContent.tls.keyKept(ctx, a.r.shared, certsA) {
		t.Fatal("keyKept false while the cluster keeps the key")
	}
	src := fos.Source(shared.ConfigIndex("signalith"), clustertls.DocID)
	mac := src["mac"].(string)
	flip := "0"
	if strings.HasPrefix(mac, "0") {
		flip = "1"
	}
	src["mac"] = flip + mac[1:]
	fos.Put(shared.ConfigIndex("signalith"), clustertls.DocID, src)
	if a.r.sharedContent.tls.keyKept(ctx, a.r.shared, certsA) {
		t.Error("keyKept with a tampered document")
	}
	fos.Delete(shared.ConfigIndex("signalith"), clustertls.DocID)
	if a.r.sharedContent.tls.keyKept(ctx, a.r.shared, certsA) {
		t.Error("keyKept with the document gone")
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// Servers set up separately each keep their own certificate authority:
// the founder publishes nothing while another server uses another, a
// server of its own keeps ca.key and names.txt as before, and an admin's
// choice (signalith cluster tls choose) makes the server holding the one
// chosen publish it.
func TestClusterCAChoice(t *testing.T) {
	t.Setenv(clusterKeyFileEnv, "")
	fastSharedCheck(t)
	fastTLSPoll(t)
	fos := ostest.New(t)
	b := startRunnerWith(t, runOptions{os: fos, name: "siem-b"})
	fpB := caFingerprint(t, b.ownCA())
	eventually(t, "B's heartbeat with its certificate authority", func() bool {
		hb := fos.Source("signalith_runtime", "node:"+b.r.node.ID())
		st, _ := hb["tls_ca"].(map[string]any)
		return st != nil && st["ca_sha256"] == fpB && st["mode"] == "auto" && st["cluster"] != true
	})
	certsB := b.r.sharedContent.tls.certs.Load()
	if err := certsB.EnsureName("b-agents.internal"); err != nil {
		t.Fatal(err)
	}

	a := startRunnerWith(t, runOptions{scheduler: true, os: fos, name: "siem-a"})
	fpA := caFingerprint(t, a.ownCA())
	a.settingsShared()
	eventually(t, "A records the tls import", func() bool {
		cb, ok := a.r.shared.Cluster().Get()
		_, done := cb.Import.Done[shared.ImportTLS]
		return ok && done && a.r.shared.SharedTLS()
	})
	if _, ok := a.r.sharedContent.tls.tls.Get(); ok {
		t.Fatal("A published its certificate authority although B uses another")
	}
	// Each keeps its own, as before.
	for _, rs := range []*running{a, b} {
		m := rs.r.sharedContent.tls.certs.Load()
		if m.Store() != tlsauto.KindFiles || !fileExists(filepath.Join(rs.dir, "tls", "ca.key")) || fileExists(filepath.Join(rs.dir, "tls", "cluster-ca.txt")) {
			t.Fatalf("%s: store %s", rs.r.node.Name(), m.Store())
		}
	}
	if !strings.Contains(readFile(t, filepath.Join(b.dir, "tls", "names.txt")), "b-agents.internal") {
		t.Error("B, a server of its own, did not keep its name in names.txt")
	}

	out, err := a.clusterCmd("tls", "-json")
	if err != nil {
		t.Fatalf("cluster tls: %v\n%s", err, out)
	}
	var st clustertls.Report
	if err := json.Unmarshal([]byte(out[:strings.LastIndex(out, "}")+1]), &st); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if st.Published || len(st.Candidates) != 2 {
		t.Fatalf("cluster tls %+v", st)
	}
	if out, err := a.clusterCmd("tls", "choose", "nobody", "-yes"); err == nil {
		t.Fatalf("an unknown server was chosen:\n%s", out)
	}
	out, err = a.clusterCmd("tls", "choose", "siem-a", "-yes")
	if err != nil || !strings.Contains(out, "now siem-a's") {
		t.Fatalf("choose: %v\n%s", err, out)
	}
	body, ok := a.r.sharedContent.tls.tls.Get()
	eventually(t, "A sees the cluster's certificate authority", func() bool {
		body, ok = a.r.sharedContent.tls.tls.Get()
		return ok
	})
	if !clustertls.SameFingerprint(body.CASHA256, fpA) || body.PublishedBy != "siem-a" {
		t.Fatalf("published %+v", body)
	}
	eventually(t, "A uses it", func() bool {
		return a.r.sharedContent.tls.certs.Load().Store() == tlsauto.KindCluster
	})
	if out, err := a.clusterCmd("tls", "choose", fpB, "-yes"); err == nil || !strings.Contains(err.Error(), "already has") {
		t.Fatalf("a second choice: %v\n%s", err, out)
	}
	out, err = a.clusterCmd("tls")
	if err != nil || !strings.Contains(out, fpA) || !strings.Contains(out, "the cluster's") {
		t.Fatalf("cluster tls: %v\n%s", err, out)
	}
	// B has no cluster key: it keeps its own, files and all.
	if m := b.r.sharedContent.tls.certs.Load(); m.Fingerprint() != fpB || !fileExists(filepath.Join(b.dir, "tls", "ca.key")) {
		t.Fatal("B, which is not a member, took the cluster's certificate authority")
	}
}
