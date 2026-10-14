package clustertls

import (
	"time"

	"github.com/jrsamsanchez/signalith/internal/cluster"
	"github.com/jrsamsanchez/signalith/internal/tlsauto"
)

// Modes of a server's HTTPS certificate in its heartbeat.
const (
	ModeAuto  = "auto"
	ModeFiles = "files"
)

// StatusOf is what m serves, for this server's heartbeat: sharedHost is
// the cluster's shared address ("" for none), adoptErr why it has not
// taken the cluster's certificate authority ("" when it has or there is
// none).
func StatusOf(m *tlsauto.Manager, sharedHost, adoptErr string) *cluster.TLSStatus {
	if m == nil {
		return nil
	}
	st := &cluster.TLSStatus{Mode: ModeFiles, Names: m.Names(), Outside: m.Outside(), AdoptError: adoptErr,
		CoversShared: sharedHost == "" || m.Covers(sharedHost)}
	if m.LocalCA() {
		st.Mode = ModeAuto
		st.Cluster = m.Store() == tlsauto.KindCluster
		st.ChangePending = m.Next() != nil || m.Previous() != nil
	}
	if pem := m.CAPEM(); pem != nil {
		st.CACertPEM, st.CASHA256 = string(pem), m.Fingerprint()
	}
	if leaf := m.Leaf(); leaf != nil {
		exp := leaf.NotAfter.UTC()
		st.LeafExpires = &exp
	}
	return st
}

// UpWithin is how fresh a heartbeat must be for its server to count as
// running: twice the time after which servers count one as offline, for
// clocks a little apart.
var UpWithin = 2 * cluster.DefaultTiming.Offline

// FromHeartbeats turns the servers' heartbeats into what Candidates and
// the importer read; founder is the node id of the server that founded
// the cluster, now the time the heartbeats' ages count from. A heartbeat
// without a TLS status has no certificate authority of its own to offer.
func FromHeartbeats(hbs []cluster.Heartbeat, founder string, now time.Time) []Server {
	out := make([]Server, 0, len(hbs))
	for _, hb := range hbs {
		s := Server{NodeID: hb.NodeID, Name: hb.Name, Founder: founder != "" && hb.NodeID == founder, SeenAt: hb.HeartbeatAt,
			Up: hb.State != cluster.StateStopped && hb.State != cluster.StateOffline && now.Sub(hb.HeartbeatAt) <= UpWithin}
		if hb.TLS != nil {
			s.CACertPEM = hb.TLS.CACertPEM
			s.Files = hb.TLS.Mode == ModeFiles
			s.Names = append(append(s.Names, hb.TLS.Names...), hb.TLS.Outside...)
		}
		out = append(out, s)
	}
	return out
}
