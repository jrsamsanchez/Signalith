package api

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/agentinv"
	"github.com/jrsamsanchez/signalith/internal/cluster"
	"github.com/jrsamsanchez/signalith/internal/clustertls"
	"github.com/jrsamsanchez/signalith/internal/shared"
	"github.com/jrsamsanchez/signalith/internal/tlsauto"
	"github.com/jrsamsanchez/signalith/internal/users"
)

// memCA is a cluster's certificate authority kept in memory, as
// clustertls keeps it, for a Manager to use (tlsauto.UseStore).
type memCA struct {
	ca  *x509.Certificate
	key crypto.Signer
}

func (s memCA) Load() (*x509.Certificate, crypto.Signer, error) { return s.ca, s.key, nil }
func (memCA) Make(*x509.Certificate) error                      { return errors.New("not here") }
func (memCA) Names() []string                                   { return nil }
func (memCA) AddName(context.Context, string) error             { return nil }
func (memCA) Kind() string                                      { return tlsauto.KindCluster }

// fakeClusterTLS is the cluster's certificate authority as the API sees
// it: published once body is set.
type fakeClusterTLS struct {
	mu       sync.Mutex
	off      string
	body     *clustertls.Body
	writable error
	asked    []string // node, fp
}

func (f *fakeClusterTLS) Off() string { return f.off }
func (f *fakeClusterTLS) CA() (*clustertls.Body, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.body, f.body != nil
}
func (f *fakeClusterTLS) Founder() string { return "n_a" }
func (f *fakeClusterTLS) Writable() error { return f.writable }
func (f *fakeClusterTLS) Publish(_ context.Context, node, fp, _ string) (*shared.Request, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.asked = append(f.asked, node, fp)
	return &shared.Request{ID: "rq_1"}, nil
}

// tlsCluster is two servers with their certificates' heartbeats.
type tlsCluster struct {
	a, b *cluster.TLSStatus
	// aOffline marks siem-a offline.
	aOffline bool
}

func (c *tlsCluster) RunsJobs() bool    { return false }
func (c *tlsCluster) JobHolder() string { return "siem-a" }
func (c *tlsCluster) Banners() []string { return nil }
func (c *tlsCluster) Status() cluster.Status {
	now := time.Now()
	a := &cluster.Heartbeat{NodeID: "n_a", Name: "siem-a", HeartbeatAt: now, TLS: c.a}
	b := &cluster.Heartbeat{NodeID: "n_b", Name: "siem-b", HeartbeatAt: now, TLS: c.b}
	stateA := cluster.StateReady
	if c.aOffline {
		stateA = cluster.StateOffline
	}
	return cluster.Status{Self: "n_b", Servers: []cluster.ServerStatus{
		{NodeID: "n_a", Name: "siem-a", State: stateA, HeartbeatAt: now, Detail: a},
		{NodeID: "n_b", Name: "siem-b", Self: true, State: cluster.StateReady, HeartbeatAt: now, Detail: b},
	}}
}

func caPEM(m *tlsauto.Manager) string { return string(m.CAPEM()) }

// newClusterTLSServer is siem-b, with siem-a's certificate manager a and
// its own b, and two users who are not admins.
func newClusterTLSServer(t *testing.T, ct ClusterTLS, a, b *tlsauto.Manager) (*httptest.Server, *tlsCluster) {
	t.Helper()
	cl := &tlsCluster{a: clustertls.StatusOf(a, "", ""), b: clustertls.StatusOf(b, "", "")}
	ts, _ := newTestServerWith(t, func(s *Server) {
		s.TLS = b
		s.Cluster = cl
		if ct != nil {
			s.ClusterTLS = ct
		}
		s.Users = users.NewMemory()
		for _, u := range []users.NewUser{{Username: "vera", Role: users.Viewer, Password: "role-password"}, {Username: "ana", Role: users.Analyst, Password: "role-password"}} {
			if _, err := s.Users.Create(context.Background(), u); err != nil {
				t.Fatal(err)
			}
		}
	})
	return ts, cl
}

// The cluster's certificate authority routes are for admins only.
func TestClusterTLSIsForAdmins(t *testing.T) {
	a, b := newCertManager(t), newCertManager(t)
	ts, _ := newClusterTLSServer(t, &fakeClusterTLS{}, a, b)
	for _, user := range []string{"vera", "ana"} {
		if code, _ := doAs(t, ts, user, "role-password", "GET", "/api/cluster/tls", ""); code != http.StatusForbidden {
			t.Errorf("%s GET: %d", user, code)
		}
		if code, _ := doAs(t, ts, user, "role-password", "POST", "/api/cluster/tls/choose", `{"ca_sha256":"`+a.Fingerprint()+`"}`); code != http.StatusForbidden {
			t.Errorf("%s POST: %d", user, code)
		}
	}
}

// Without a cluster, the page says why, and nothing can be chosen.
func TestClusterTLSOff(t *testing.T) {
	a, b := newCertManager(t), newCertManager(t)
	ts, _ := newClusterTLSServer(t, nil, a, b)
	code, out := do(t, ts, "GET", "/api/cluster/tls", "", true)
	if code != 200 || out["on"] != false || !strings.Contains(out["off"].(string), "isn't a member") {
		t.Fatalf("GET %d %v", code, out)
	}
	if code, out := do(t, ts, "POST", "/api/cluster/tls/choose", `{"ca_sha256":"`+a.Fingerprint()+`"}`, true); code != http.StatusServiceUnavailable {
		t.Errorf("POST %d %v", code, out)
	}
	ts2, _ := newClusterTLSServer(t, &fakeClusterTLS{off: "Every server keeps its own certificate authority until all of them run a version that shares one."}, a, b)
	if _, out := do(t, ts2, "GET", "/api/cluster/tls", "", true); out["on"] != false || !strings.Contains(out["off"].(string), "a version that shares one") {
		t.Errorf("below the level: %v", out)
	}
}

// Two servers set up separately: the choice lists both, and choosing
// one asks the server holding it to publish it.
func TestClusterTLSChoose(t *testing.T) {
	a, b := newCertManager(t), newCertManager(t)
	ct := &fakeClusterTLS{}
	ts, cl := newClusterTLSServer(t, ct, a, b)
	code, out := do(t, ts, "GET", "/api/cluster/tls", "", true)
	if code != 200 || out["on"] != true || out["published"] != false {
		t.Fatalf("GET %d %v", code, out)
	}
	cands := out["candidates"].([]any)
	if len(cands) != 2 {
		t.Fatalf("candidates %v", cands)
	}
	first := cands[0].(map[string]any)
	// No agents either way: the founder's goes first.
	if first["preselected"] != true || first["ca_sha256"] != a.Fingerprint() || first["servers"].([]any)[0] != "siem-a" {
		t.Errorf("preselected %v", first)
	}
	servers := out["servers"].([]any)
	if len(servers) != 2 || servers[1].(map[string]any)["self"] != true || servers[1].(map[string]any)["mode"] != "auto" {
		t.Errorf("servers %v", servers)
	}

	if code, out := do(t, ts, "POST", "/api/cluster/tls/choose", `{"ca_sha256":"AB:CD"}`, true); code != http.StatusBadRequest {
		t.Errorf("unknown: %d %v", code, out)
	}
	if code, out := do(t, ts, "POST", "/api/cluster/tls/choose", `{}`, true); code != http.StatusBadRequest {
		t.Errorf("none: %d %v", code, out)
	}
	ct.writable = &shared.PausedError{Why: "the cluster key is missing"}
	if code, out := do(t, ts, "POST", "/api/cluster/tls/choose", `{"ca_sha256":"`+b.Fingerprint()+`"}`, true); code != http.StatusServiceUnavailable {
		t.Errorf("not writable: %d %v", code, out)
	}
	ct.writable = nil
	// siem-a is offline: its certificate authority is listed, but it
	// cannot publish it now.
	cl.aOffline = true
	_, out = do(t, ts, "GET", "/api/cluster/tls", "", true)
	for _, c := range out["candidates"].([]any) {
		if c := c.(map[string]any); c["ca_sha256"] == a.Fingerprint() && c["up"] != false {
			t.Errorf("offline candidate %v", c)
		}
	}
	if code, out := do(t, ts, "POST", "/api/cluster/tls/choose", `{"ca_sha256":"`+a.Fingerprint()+`"}`, true); code != http.StatusServiceUnavailable ||
		!strings.Contains(out["error"].(string), "siem-a is offline") {
		t.Errorf("offline: %d %v", code, out)
	}
	if len(ct.asked) != 0 {
		t.Fatalf("asked an offline server %v", ct.asked)
	}
	cl.aOffline = false
	// Written without colons, in lower case: the same fingerprint.
	fp := strings.ToLower(strings.ReplaceAll(b.Fingerprint(), ":", ""))
	code, out = do(t, ts, "POST", "/api/cluster/tls/choose", `{"ca_sha256":"`+fp+`"}`, true)
	if code != http.StatusAccepted || out["request_id"] != "rq_1" || out["server"] != "siem-b" {
		t.Fatalf("choose %d %v", code, out)
	}
	if len(ct.asked) != 2 || ct.asked[0] != "n_b" || ct.asked[1] != b.Fingerprint() {
		t.Errorf("asked %v", ct.asked)
	}

	// Once one is published, the choice is over.
	ct.mu.Lock()
	ct.body = &clustertls.Body{CACertPEM: caPEM(b), CASHA256: b.Fingerprint(), Names: []string{"agents.internal"}, PublishedBy: "siem-b", PublishedAt: time.Now(),
		Retired: []clustertls.RetiredCA{{CACertPEM: caPEM(a), Server: "siem-a", RetiredAt: time.Now()}}}
	ct.mu.Unlock()
	if code, out := do(t, ts, "POST", "/api/cluster/tls/choose", `{"ca_sha256":"`+a.Fingerprint()+`"}`, true); code != http.StatusConflict {
		t.Errorf("after publishing: %d %v", code, out)
	}
	_, out = do(t, ts, "GET", "/api/cluster/tls", "", true)
	ca, _ := out["ca"].(map[string]any)
	if out["published"] != true || ca == nil || ca["ca_sha256"] != b.Fingerprint() || len(out["candidates"].([]any)) != 0 {
		t.Fatalf("published %v", out)
	}
	if r := out["retired"].([]any); len(r) != 1 || r[0].(map[string]any)["ca_sha256"] != a.Fingerprint() {
		t.Errorf("retired %v", out["retired"])
	}
	// siem-a still uses its own: amber nothing, but not the cluster's.
	if sa := out["servers"].([]any)[0].(map[string]any); sa["cluster"] != false || sa["ca_sha256"] != a.Fingerprint() {
		t.Errorf("siem-a %v", sa)
	}
}

// A server using the cluster's certificate authority serves it to agents
// and browsers, says so, and refuses a change of its own.
func TestClusterCAOnSecurityPage(t *testing.T) {
	a := newCertManager(t)
	ca, key, _ := a.LocalPair()
	var srv *Server
	ts, _, _ := newSecurityServer(t, func(s *Server) {
		srv = s
		if err := s.TLS.UseStore(memCA{ca: ca, key: key}); err != nil {
			t.Fatal(err)
		}
	})
	if srv.TLS.Fingerprint() != a.Fingerprint() {
		t.Fatal("the server did not take the cluster's certificate authority")
	}
	resp, body := get(t, ts, "/api/security")
	if resp.StatusCode != 200 || !strings.Contains(body, `"ca_owner":"cluster"`) {
		t.Fatalf("security %d %s", resp.StatusCode, body)
	}
	before := srv.TLS.Fingerprint()
	code, out := do(t, ts, "POST", "/api/security/ca", `{"action":"prepare","scope":"strict"}`, true)
	if code != http.StatusConflict || !strings.Contains(out["error"].(string), "cluster's certificate authority") {
		t.Fatalf("prepare %d %v", code, out)
	}
	if srv.TLS.Next() != nil || srv.TLS.Fingerprint() != before || srv.Config.Server.CAScope() == "strict" {
		t.Error("a refused change changed something")
	}
	// ca.pem is the cluster's.
	r, err := http.Get(ts.URL + "/api/tls/ca.pem")
	if err != nil {
		t.Fatal(err)
	}
	pemBytes, _ := io.ReadAll(r.Body)
	r.Body.Close()
	block, _ := pem.Decode(pemBytes)
	if block == nil || tlsauto.Fingerprint(block.Bytes) != a.Fingerprint() {
		t.Errorf("ca.pem is not the cluster's")
	}
	_, h := do(t, ts, "GET", "/api/health", "", true)
	if tl, _ := h["tls"].(map[string]any); tl == nil || tl["cluster_ca"] != true {
		t.Errorf("health tls %v", h["tls"])
	}
}

// A server of its own says nothing about a cluster.
func TestSecurityWithoutClusterCA(t *testing.T) {
	ts, _, _ := newSecurityServer(t, nil)
	_, body := get(t, ts, "/api/security")
	if strings.Contains(body, "ca_owner") {
		t.Errorf("ca_owner on a server of its own: %s", body)
	}
	_, h := do(t, ts, "GET", "/api/health", "", true)
	if tl, _ := h["tls"].(map[string]any); tl != nil && tl["cluster_ca"] != nil {
		t.Errorf("health tls %v", tl)
	}
}

// An agent whose configuration trusts only a retired certificate
// authority needs a new configuration, for that reason.
func TestAgentOfRetiredCA(t *testing.T) {
	s := &Server{}
	a := agentinv.Agent{Key: "k", CA: []string{"aaaa"}, LastSeen: time.Now(), NeedsConfig: true, Reason: agentinv.ReasonRetiredCA}
	if v := s.agentFlags(a, "bbbb", "", time.Now()); len(v.NeedsConfig) != 1 || v.NeedsConfig[0] != "retired_ca" {
		t.Errorf("retired: %v", v.NeedsConfig)
	}
	a.NeedsConfig, a.Reason = false, ""
	if v := s.agentFlags(a, "bbbb", "", time.Now()); len(v.NeedsConfig) != 1 || v.NeedsConfig[0] != "ca" {
		t.Errorf("other CA: %v", v.NeedsConfig)
	}
}
