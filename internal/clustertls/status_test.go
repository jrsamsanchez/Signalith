package clustertls

import (
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cluster"
	"github.com/jrsamsanchez/signalith/internal/tlsauto"
)

func TestStatusAndHeartbeats(t *testing.T) {
	m, err := tlsauto.New(tlsauto.Options{Dir: filepath.Join(t.TempDir(), "tls"), Names: []string{"siem-a.lan"}})
	if err != nil {
		t.Fatal(err)
	}
	st := StatusOf(m, "siem-a.lan", "")
	if st.Mode != ModeAuto || st.Cluster || st.CASHA256 != m.Fingerprint() || st.CACertPEM != string(m.CAPEM()) ||
		!st.CoversShared || st.ChangePending || st.LeafExpires == nil || !slices.Contains(st.Names, "siem-a.lan") {
		t.Errorf("status %+v", st)
	}
	if StatusOf(m, "siem.example.org", "").CoversShared {
		t.Error("covers a shared name it does not")
	}
	if err := m.Prepare(tlsauto.ScopeStandard); err != nil {
		t.Fatal(err)
	}
	if !StatusOf(m, "", "").ChangePending {
		t.Error("change not reported")
	}
	if StatusOf(nil, "", "") != nil {
		t.Error("nil manager")
	}

	now := time.Now()
	servers := FromHeartbeats([]cluster.Heartbeat{
		{NodeID: "n_a", Name: "siem-a", HeartbeatAt: now, TLS: st},
		{NodeID: "n_b", Name: "siem-b", HeartbeatAt: now},
		{NodeID: "n_c", Name: "siem-c", HeartbeatAt: now.Add(-time.Hour)},
		{NodeID: "n_d", Name: "siem-d", HeartbeatAt: now, State: cluster.StateStopped},
	}, "n_a", now)
	if len(servers) != 4 || !servers[0].Up || !servers[1].Up || servers[2].Up || servers[3].Up {
		t.Errorf("up %+v", servers)
	}
	servers = servers[:2]
	if len(servers) != 2 || !servers[0].Founder || servers[1].Founder || servers[0].CACertPEM == "" || servers[1].CACertPEM != "" ||
		!slices.Contains(servers[0].Names, "siem-a.lan") {
		t.Fatalf("servers %+v", servers)
	}
	if cs := Candidates(servers, nil, now); len(cs) != 1 || cs[0].CASHA256 != m.Fingerprint() || cs[0].Servers[0] != "siem-a" {
		t.Errorf("candidates %+v", cs)
	}
}
