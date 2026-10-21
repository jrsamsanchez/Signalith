// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cluster/ostest"
	"github.com/jrsamsanchez/signalith/internal/clustertls"
	"github.com/jrsamsanchez/signalith/internal/tlsauto"
)

// fetchCA downloads the CA file Add data gives (both CAs while one is
// replaced) from addr, trusting caPEM.
func fetchCA(t *testing.T, addr string, caPEM []byte) string {
	t.Helper()
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caPEM)
	c := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}}
	resp, err := c.Get("https://" + addr + "/api/tls/ca.pem?which=both")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		t.Fatalf("ca.pem?which=both: %d %s", resp.StatusCode, b)
	}
	return string(b)
}

// heartbeatTLS is the TLS status in server id's heartbeat.
func heartbeatTLS(fos *ostest.Server, id string) map[string]any {
	hb := fos.Source("signalith_runtime", "node:"+id)
	st, _ := hb["tls_ca"].(map[string]any)
	return st
}

// signalith cluster tls rotate-ca replaces the cluster's certificate
// authority on every server: prepare hands out both, switch waits for
// every server to hand out the new one and then every server issues
// itself a certificate from it, and retire waits for those certificates.
func TestClusterCARotation(t *testing.T) {
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
	giveKey(t, a)
	b := startRunnerWith(t, runOptions{scheduler: true, os: fos, name: "siem-b"})
	b.settingsShared()
	certsB := b.r.sharedContent.tls.certs.Load()
	eventually(t, "B takes the cluster's certificate authority", func() bool {
		return certsB.Fingerprint() == fpA && certsB.Store() == tlsauto.KindCluster
	})

	if out, err := a.clusterCmd("tls", "rotate-ca", "switch", "-yes"); err == nil {
		t.Fatalf("switched with nothing prepared:\n%s", out)
	}
	if out, err := a.clusterCmd("tls", "rotate-ca", "bogus", "-yes"); err == nil || !strings.Contains(err.Error(), "usage") {
		t.Fatalf("bogus step: %v\n%s", err, out)
	}
	out, err := a.clusterCmd("tls", "rotate-ca", "prepare", "-yes")
	if err != nil || !strings.Contains(out, "has a new certificate authority") {
		t.Fatalf("prepare: %v\n%s", err, out)
	}
	body, _ := a.r.sharedContent.tls.tls.Get()
	eventually(t, "A reads the next certificate authority", func() bool {
		body, _ = a.r.sharedContent.tls.tls.Get()
		return body.Next != nil
	})
	fpN := body.Next.CASHA256
	next, _ := body.Next.Cert()
	// Every server hands out both, over the connection agents already
	// trust; the certificate in use stays.
	for _, rs := range []*running{a, b} {
		id := rs.r.node.ID()
		eventually(t, rs.r.node.Name()+" hands out the next certificate authority", func() bool {
			st := heartbeatTLS(fos, id)
			return st != nil && st["next_ca_sha256"] == fpN
		})
		bundle := fetchCA(t, rs.addr, caA)
		if strings.Count(bundle, "BEGIN CERTIFICATE") != 2 {
			t.Fatalf("%s's CA file:\n%s", rs.r.node.Name(), bundle)
		}
		if m := rs.r.sharedContent.tls.certs.Load(); m.Next() == nil || m.Next().Fingerprint != fpN {
			t.Errorf("%s: Next %+v", rs.r.node.Name(), m.Next())
		}
	}
	out, err = a.clusterCmd("tls")
	if err != nil || !strings.Contains(out, "prepared on") || !strings.Contains(out, fpN) || !strings.Contains(out, "managed agents: 0 of 0 have the new") {
		t.Fatalf("cluster tls: %v\n%s", err, out)
	}
	if out, err := a.clusterCmd("tls", "rotate-ca", "retire", "-yes"); err == nil {
		t.Fatalf("retired before the switch:\n%s", out)
	}

	out, err = a.clusterCmd("tls", "rotate-ca", "switch", "-yes")
	if err != nil || !strings.Contains(out, "issues its certificate from the new certificate authority") {
		t.Fatalf("switch: %v\n%s", err, out)
	}
	newPEM := []byte(body.Next.CACertPEM)
	for _, rs := range []*running{a, b} {
		m := rs.r.sharedContent.tls.certs.Load()
		eventually(t, rs.r.node.Name()+" serves a certificate from the new certificate authority", func() bool {
			return m.Fingerprint() == fpN && m.Leaf() != nil && m.Leaf().CheckSignatureFrom(next) == nil
		})
		if err := dialWith(rs.addr, newPEM); err != nil {
			t.Errorf("%s with the new CA: %v", rs.r.node.Name(), err)
		}
		// The old one is still handed out.
		if bundle := fetchCA(t, rs.addr, newPEM); strings.Count(bundle, "BEGIN CERTIFICATE") != 2 {
			t.Errorf("%s's CA file after the switch:\n%s", rs.r.node.Name(), bundle)
		}
		if !fileExists(filepath.Join(rs.dir, "tls", "cluster-ca.txt")) || !strings.Contains(readFile(t, filepath.Join(rs.dir, "tls", "cluster-ca.txt")), fpN) {
			t.Errorf("%s's cluster mark", rs.r.node.Name())
		}
	}
	for _, rs := range []*running{a, b} {
		id := rs.r.node.ID()
		eventually(t, rs.r.node.Name()+"'s heartbeat says its certificate is from the new one", func() bool {
			st := heartbeatTLS(fos, id)
			return st != nil && st["leaf_ca_sha256"] == fpN
		})
	}
	out, err = a.clusterCmd("tls", "rotate-ca", "retire", "-yes")
	if err != nil || !strings.Contains(out, "is retired") {
		t.Fatalf("retire: %v\n%s", err, out)
	}
	eventually(t, "the old certificate authority is no longer handed out", func() bool {
		return strings.Count(string(b.r.sharedContent.tls.certs.Load().AgentCAPEM()), "BEGIN CERTIFICATE") == 1
	})
	body, _ = a.r.sharedContent.tls.tls.Get()
	if body.Previous != nil || !clustertls.SameFingerprint(body.CASHA256, fpN) ||
		!strings.Contains(strings.Join(body.RetiredFingerprints(), " "), fpA) {
		t.Fatalf("after retire %+v", body)
	}
	if err := dialWith(b.addr, caA); err == nil {
		t.Error("B still serves a certificate the old CA vouches for")
	}
}
