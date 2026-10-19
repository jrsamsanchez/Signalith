// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cluster"
	"github.com/jrsamsanchez/signalith/internal/clusterpki"
)

// osca is the certificate authority a cluster keeps, or none.
type osca struct {
	b atomic.Pointer[clusterpki.Body]
}

func (o *osca) CA() (*clusterpki.Body, bool) {
	b := o.b.Load()
	return b, b != nil
}

// The Servers page shows the certificate authority the cluster keeps,
// with the certificates it revoked that have not expired, and who each
// server signs in to OpenSearch as; a server of its own says it is alone.
func TestClusterOSIdentity(t *testing.T) {
	ts, _ := newTestServer(t)
	code, out := do(t, ts, "GET", "/api/cluster/opensearch-identity", "", true)
	if code != http.StatusOK || out["alone"] != true || out["ca"] != nil || len(out["servers"].([]any)) != 0 {
		t.Errorf("alone: %d %v", code, out)
	}

	now := time.Now().UTC()
	body := &clusterpki.Body{CASHA256: "AB:CD", ImportedBy: "admin", ImportedOn: "siem-a", ImportedAt: now.Add(-time.Hour),
		Revoked: []clusterpki.Revoked{
			{Serial: "01", NotAfter: now.Add(24 * time.Hour)},
			{Serial: "01", NotAfter: now.Add(24 * time.Hour)},
			{Serial: "02", NotAfter: now.Add(-time.Hour)},
		}}
	st := cluster.Status{Servers: []cluster.ServerStatus{
		{NodeID: "n_a", Name: "siem-a", State: "online", Self: true,
			Detail: &cluster.Heartbeat{OSIdentity: &cluster.OSIdentityStatus{CN: "siem-a", Managed: true, CASHA256: "AB:CD"}}},
		{NodeID: "n_b", Name: "siem-b", State: "offline"},
	}}
	var ca osca
	ca.b.Store(body)
	ts, _ = newTestServerWith(t, func(s *Server) {
		s.Cluster = statusCluster{st: st}
		s.ClusterOSIdentity = &ca
	})
	code, out = do(t, ts, "GET", "/api/cluster/opensearch-identity", "", true)
	if code != http.StatusOK || out["alone"] != nil {
		t.Fatalf("member: %d %v", code, out)
	}
	if c, _ := out["ca"].(map[string]any); c == nil || c["ca_sha256"] != "AB:CD" || c["imported_on"] != "siem-a" || c["revoked"] != float64(1) {
		t.Errorf("ca: %v", out["ca"])
	}
	servers := out["servers"].([]any)
	if len(servers) != 2 {
		t.Fatalf("servers: %v", servers)
	}
	a, b := servers[0].(map[string]any), servers[1].(map[string]any)
	if a["self"] != true || a["identity"].(map[string]any)["cn"] != "siem-a" || b["identity"] != nil || b["state"] != "offline" {
		t.Errorf("servers: %v", servers)
	}

	// Before a certificate authority is imported there is none to show.
	ca.b.Store(nil)
	if _, out := do(t, ts, "GET", "/api/cluster/opensearch-identity", "", true); out["ca"] != nil || len(out["servers"].([]any)) != 2 {
		t.Errorf("no CA: %v", out)
	}
}
