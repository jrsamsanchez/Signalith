//go:build integration && linux

package integration

// The cluster's one certificate authority (servers.md, One certificate
// authority) with real `signalith serve` processes: a cluster that grew
// from one server shares that server's, a server that joins takes it,
// servers set up separately keep their own until an admin chooses, and a
// server without the cluster key keeps its own as before.

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// caFingerprint is the SHA-256 fingerprint (AB:CD:...) of the
// certificate in a PEM file, "" when there is none.
func caFingerprint(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return ""
	}
	return derFingerprint(block.Bytes)
}

func derFingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	parts := make([]string, len(sum))
	for i, b := range sum {
		parts[i] = fmt.Sprintf("%02X", b)
	}
	return strings.Join(parts, ":")
}

// ownCA is the fingerprint of the certificate authority in the server's
// tls/ca.pem.
func (s *testServer) ownCA() string {
	return caFingerprint(s.h.t, filepath.Join(s.dir, "tls", "ca.pem"))
}

// leaf is the certificate the server serves over HTTPS now.
func (s *testServer) leaf() *x509.Certificate {
	conn, err := tls.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", s.port), &tls.Config{InsecureSkipVerify: true}) //nolint:gosec // the test checks the chain itself
	if err != nil {
		return nil
	}
	defer conn.Close()
	if certs := conn.ConnectionState().PeerCertificates; len(certs) > 0 {
		return certs[0]
	}
	return nil
}

// chainsTo reports whether the server's certificate comes from the
// certificate authority in caPEM and covers name.
func (s *testServer) chainsTo(caPEM []byte, name string) bool {
	leaf := s.leaf()
	pool := x509.NewCertPool()
	if leaf == nil || !pool.AppendCertsFromPEM(caPEM) {
		return false
	}
	_, err := leaf.Verify(x509.VerifyOptions{Roots: pool, DNSName: name})
	return err == nil
}

// clusterTLS is GET /api/cluster/tls, as much of it as the tests read.
type clusterTLS struct {
	On        bool `json:"on"`
	Published bool `json:"published"`
	CA        *struct {
		CASHA256    string   `json:"ca_sha256"`
		Names       []string `json:"names"`
		PublishedBy string   `json:"published_by"`
	} `json:"ca"`
	Retired []struct {
		CASHA256 string `json:"ca_sha256"`
		Server   string `json:"server"`
	} `json:"retired"`
	Servers []struct {
		Name     string `json:"name"`
		CASHA256 string `json:"ca_sha256"`
		Cluster  bool   `json:"cluster"`
	} `json:"servers"`
	Candidates []struct {
		CASHA256    string   `json:"ca_sha256"`
		Servers     []string `json:"servers"`
		Preselected bool     `json:"preselected"`
	} `json:"candidates"`
}

func (s *testServer) clusterTLS() (clusterTLS, bool) {
	var out clusterTLS
	code := s.call(http.MethodGet, "/api/cluster/tls", nil, &out)
	return out, code == http.StatusOK
}

// A cluster that grew from one server shares that server's certificate
// authority: nothing changes for its agents, its ca.key leaves the disk,
// a server that joins takes it and retires its own, a name added on one
// server reaches the other's certificate, and a server without the
// cluster key keeps its own as before.
func TestClusterTLSOneCA(t *testing.T) {
	h := newClusterHarness(t)
	a := h.startLeader("siem-a", serverOptions{})
	fpA := a.ownCA()
	caA, err := os.ReadFile(filepath.Join(a.dir, "tls", "ca.pem"))
	if err != nil || fpA == "" {
		t.Fatalf("siem-a has no certificate authority: %v", err)
	}
	waitUntil(t, 60*time.Second, "siem-a shares its certificate authority", func() bool {
		v, ok := a.clusterTLS()
		return ok && v.Published && v.CA != nil && v.CA.CASHA256 == fpA
	})
	waitUntil(t, 30*time.Second, "siem-a's ca.key leaves the disk", func() bool {
		_, err := os.Stat(filepath.Join(a.dir, "tls", "ca.key"))
		return os.IsNotExist(err)
	})
	if a.ownCA() != fpA || !a.chainsTo(caA, "127.0.0.1") {
		t.Fatal("siem-a's certificate authority changed when it was shared")
	}

	b := h.start("siem-b", serverOptions{noJobs: true})
	waitUntil(t, 60*time.Second, "siem-b takes the cluster's certificate authority", func() bool {
		return b.ownCA() == fpA && b.chainsTo(caA, "127.0.0.1")
	})
	retired, _ := filepath.Glob(filepath.Join(b.dir, "tls", "retired", "*", "ca.pem"))
	if len(retired) != 1 {
		t.Fatalf("siem-b retired %d certificate authorities", len(retired))
	}
	fpOldB := caFingerprint(t, retired[0])
	if _, err := os.Stat(filepath.Join(b.dir, "tls", "ca.key")); !os.IsNotExist(err) {
		t.Error("siem-b kept the key of its own certificate authority")
	}
	// An agent configuration made on siem-a works against siem-b: the
	// CA file each gives out is the same.
	var pemB []byte
	if resp, err := b.api.Get(fmt.Sprintf("https://127.0.0.1:%d/api/tls/ca.pem", b.port)); err == nil {
		pemB, _ = io.ReadAll(resp.Body)
		resp.Body.Close()
	}
	if caFingerprintPEM(pemB) != fpA {
		t.Errorf("siem-b gives out %q, not the cluster's", caFingerprintPEM(pemB))
	}
	waitUntil(t, 30*time.Second, "the retired certificate authority is listed", func() bool {
		v, ok := a.clusterTLS()
		return ok && slices.ContainsFunc(v.Retired, func(r struct {
			CASHA256 string `json:"ca_sha256"`
			Server   string `json:"server"`
		}) bool {
			return r.CASHA256 == fpOldB && r.Server == "siem-b"
		})
	})

	// A name added on siem-a is covered by siem-b's certificate.
	if code := a.call(http.MethodPost, "/api/tls/names", map[string]string{"name": "agents.internal"}, nil); code != http.StatusOK {
		t.Fatalf("adding a name: %d", code)
	}
	waitUntil(t, 30*time.Second, "siem-b's certificate covers the name added on siem-a", func() bool {
		return b.chainsTo(caA, "agents.internal")
	})

	// The Security page cannot change the cluster's.
	var refused map[string]any
	if code := b.call(http.MethodPost, "/api/security/ca", map[string]string{"action": "prepare"}, &refused); code != http.StatusConflict {
		t.Errorf("prepare on a server of the cluster: %d %v", code, refused)
	}

	// A server without the cluster key keeps its own, files and all.
	c := h.start("siem-c", serverOptions{noKey: true, noJobs: true})
	fpC := c.ownCA()
	time.Sleep(5 * time.Second)
	if c.ownCA() != fpC || fpC == fpA {
		t.Error("siem-c, without the cluster key, took the cluster's certificate authority")
	}
	if _, err := os.Stat(filepath.Join(c.dir, "tls", "ca.key")); err != nil {
		t.Errorf("siem-c lost tls/ca.key: %v", err)
	}
	if _, err := os.Stat(filepath.Join(c.dir, "tls", "retired")); !os.IsNotExist(err) {
		t.Error("siem-c retired a certificate authority")
	}
}

// Servers set up separately keep their own certificate authorities until
// an admin chooses one; the server holding it shares it and the other
// takes it.
func TestClusterTLSChoice(t *testing.T) {
	h := newClusterHarness(t)
	// siem-b starts first, with its own certificate authority, before
	// there is a cluster; siem-a then makes the cluster and sees two.
	b := h.start("siem-b", serverOptions{noJobs: true})
	fpB := b.ownCA()
	caB, _ := os.ReadFile(filepath.Join(b.dir, "tls", "ca.pem"))
	a := h.startLeader("siem-a", serverOptions{})
	fpA := a.ownCA()
	if fpA == fpB || fpA == "" {
		t.Fatal("the servers share a certificate authority from the start")
	}
	var v clusterTLS
	waitUntil(t, 60*time.Second, "both certificate authorities offered", func() bool {
		var ok bool
		v, ok = a.clusterTLS()
		return ok && v.On && len(v.Candidates) == 2
	})
	if v.Published {
		t.Fatal("a certificate authority was shared before anyone chose")
	}
	for _, s := range []*testServer{a, b} {
		if _, err := os.Stat(filepath.Join(s.dir, "tls", "ca.key")); err != nil {
			t.Errorf("%s lost its ca.key before the choice", s.name)
		}
	}
	// No agents either way: siem-a made the cluster, so its is suggested.
	if !v.Candidates[0].Preselected || v.Candidates[0].CASHA256 != fpA {
		t.Errorf("suggested %+v", v.Candidates[0])
	}
	if code := a.call(http.MethodPost, "/api/cluster/tls/choose", map[string]string{"ca_sha256": "AB:CD"}, nil); code != http.StatusBadRequest {
		t.Errorf("an unknown certificate authority: %d", code)
	}
	var out map[string]any
	if code := a.call(http.MethodPost, "/api/cluster/tls/choose", map[string]string{"ca_sha256": fpB}, &out); code != http.StatusAccepted || out["request_id"] == nil {
		t.Fatalf("choose: %d %v", code, out)
	}
	waitUntil(t, 60*time.Second, "siem-a takes siem-b's certificate authority", func() bool {
		return a.ownCA() == fpB && a.chainsTo(caB, "127.0.0.1")
	})
	v, _ = a.clusterTLS()
	if !v.Published || v.CA.CASHA256 != fpB || v.CA.PublishedBy != "siem-b" {
		t.Errorf("after the choice %+v", v)
	}
	if code := a.call(http.MethodPost, "/api/cluster/tls/choose", map[string]string{"ca_sha256": fpA}, nil); code != http.StatusConflict {
		t.Errorf("a second choice: %d", code)
	}
	waitUntil(t, 30*time.Second, "siem-b's ca.key leaves the disk", func() bool {
		_, err := os.Stat(filepath.Join(b.dir, "tls", "ca.key"))
		return os.IsNotExist(err)
	})
	if b.ownCA() != fpB {
		t.Error("siem-b's certificate authority changed when it was shared")
	}
}

func caFingerprintPEM(b []byte) string {
	block, _ := pem.Decode(b)
	if block == nil {
		return ""
	}
	return derFingerprint(block.Bytes)
}
