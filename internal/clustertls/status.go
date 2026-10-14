package clustertls

import (
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

// FromHeartbeats turns the servers' heartbeats into what Candidates and
// the importer read; founder is the node id of the server that founded
// the cluster. A heartbeat without a TLS status has no certificate
// authority of its own to offer.
func FromHeartbeats(hbs []cluster.Heartbeat, founder string) []Server {
	out := make([]Server, 0, len(hbs))
	for _, hb := range hbs {
		s := Server{NodeID: hb.NodeID, Name: hb.Name, Founder: founder != "" && hb.NodeID == founder, SeenAt: hb.HeartbeatAt}
		if hb.TLS != nil {
			s.CACertPEM = hb.TLS.CACertPEM
			s.Names = append(append(s.Names, hb.TLS.Names...), hb.TLS.Outside...)
		}
		out = append(out, s)
	}
	return out
}
