package clustertls

import (
	"cmp"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/jrsamsanchez/signalith/internal/agentinv"
	"github.com/jrsamsanchez/signalith/internal/cluster"
	"github.com/jrsamsanchez/signalith/internal/tlsauto"
)

// MaxListed caps the agents a candidate lists by name in a Report; the
// counts are always whole.
const MaxListed = 200

// Report is the cluster's certificate authority as the Servers page and
// signalith cluster tls show it: the one published, each server's
// certificate and, while none is chosen, the ones to choose from.
type Report struct {
	// Published is false while the cluster has no certificate authority:
	// each server keeps its own until an admin chooses one.
	Published bool `json:"published"`
	// CA is the cluster's, nil while none is published.
	CA *CAView `json:"ca,omitempty"`
	// Retired are the certificate authorities the servers used before
	// the cluster's, newest first.
	Retired []RetiredView `json:"retired"`
	// Servers are the servers seen in the last day, by name.
	Servers []ServerView `json:"servers"`
	// Candidates are the certificate authorities to choose from while
	// none is published, the preselected first; empty once one is.
	Candidates []Candidate `json:"candidates"`
}

// CAView is the cluster's certificate authority.
type CAView struct {
	CASHA256  string    `json:"ca_sha256"`
	Subject   string    `json:"subject"`
	Scope     string    `json:"scope,omitempty"`
	NotBefore time.Time `json:"not_before"`
	NotAfter  time.Time `json:"not_after"`
	// Names are the names every server's certificate covers besides its
	// own (the addresses agents were set up with), oldest first.
	Names       []string  `json:"names"`
	PublishedBy string    `json:"published_by"`
	PublishedAt time.Time `json:"published_at"`
}

// RetiredView is a certificate authority a server used before the
// cluster's.
type RetiredView struct {
	CASHA256  string    `json:"ca_sha256"`
	Server    string    `json:"server,omitempty"`
	RetiredAt time.Time `json:"retired_at"`
}

// ServerView is one server's certificate, from its heartbeat.
type ServerView struct {
	NodeID string `json:"node_id"`
	Name   string `json:"name"`
	Self   bool   `json:"self,omitempty"`
	// Reported is false for a server whose version does not report its
	// certificate; the fields after it are then empty.
	Reported bool `json:"reported"`
	// Mode is auto (Signalith's own certificate authority) or files (the
	// admin's certificate files).
	Mode     string `json:"mode,omitempty"`
	CASHA256 string `json:"ca_sha256,omitempty"`
	// Cluster is true when it uses the cluster's certificate authority.
	Cluster bool `json:"cluster"`
	// Names are the names its certificate covers, and Outside those it
	// should but its certificate authority may not sign.
	Names         []string   `json:"names"`
	Outside       []string   `json:"outside"`
	CoversShared  bool       `json:"covers_shared"`
	ChangePending bool       `json:"change_pending,omitempty"`
	LeafExpires   *time.Time `json:"leaf_expires,omitempty"`
	// Problem says why it has not taken the cluster's certificate
	// authority, "" when it has or there is none.
	Problem string `json:"problem,omitempty"`
	// Warnings are what the Servers page shows in amber or red for it.
	Warnings []string `json:"warnings"`
}

// ReportInput is what BuildReport reads.
type ReportInput struct {
	// Body is the tls document, nil while none is published.
	Body *Body
	// Heartbeats are the servers' heartbeats.
	Heartbeats []cluster.Heartbeat
	// Founder is the node id of the server that founded the cluster, and
	// Self this server's.
	Founder, Self string
	// Agents is the agent inventory, read only while none is published.
	Agents []agentinv.Agent
	Now    time.Time
}

// BuildReport puts together the Report of in.
func BuildReport(in ReportInput) *Report {
	now := in.Now
	if now.IsZero() {
		now = time.Now()
	}
	r := &Report{Retired: []RetiredView{}, Servers: []ServerView{}, Candidates: []Candidate{}}
	var clusterFP string
	if b := in.Body; b != nil && b.CASHA256 != "" {
		r.Published, clusterFP = true, b.CASHA256
		v := &CAView{CASHA256: b.CASHA256, Names: append([]string{}, b.Names...), PublishedBy: b.PublishedBy, PublishedAt: b.PublishedAt}
		if ca, err := b.Cert(); err == nil {
			v.Subject, v.NotBefore, v.NotAfter = ca.Subject.CommonName, ca.NotBefore.UTC(), ca.NotAfter.UTC()
			if info := tlsauto.InfoOf(ca); info != nil {
				v.Scope = info.Scope
			}
		}
		r.CA = v
		for i := len(b.Retired) - 1; i >= 0; i-- {
			old := b.Retired[i]
			if ca := parsePEM(old.CACertPEM); ca != nil {
				r.Retired = append(r.Retired, RetiredView{CASHA256: tlsauto.Fingerprint(ca.Raw), Server: old.Server, RetiredAt: old.RetiredAt})
			}
		}
	}
	// The roots of the servers' certificates, for the warning on
	// certificate files whose root differs.
	roots := map[string]bool{}
	for _, hb := range in.Heartbeats {
		if now.Sub(hb.HeartbeatAt) <= ServerSeen && hb.TLS != nil && hb.TLS.CASHA256 != "" {
			roots[strings.ToUpper(hb.TLS.CASHA256)] = true
		}
	}
	for _, hb := range in.Heartbeats {
		if now.Sub(hb.HeartbeatAt) > ServerSeen {
			continue
		}
		r.Servers = append(r.Servers, serverView(hb, in.Self, clusterFP, roots))
	}
	slices.SortFunc(r.Servers, func(a, b ServerView) int { return cmp.Compare(a.Name, b.Name) })
	if !r.Published {
		r.Candidates = Candidates(FromHeartbeats(in.Heartbeats, in.Founder, now), in.Agents, now)
		for i := range r.Candidates {
			c := &r.Candidates[i]
			if len(c.Agents) > MaxListed {
				c.Agents = c.Agents[:MaxListed]
			}
			if len(c.Breaks) > MaxListed {
				c.Breaks = c.Breaks[:MaxListed]
			}
		}
	}
	return r
}

// serverView is one server's row: clusterFP is the cluster's certificate
// authority ("" for none), roots the roots of every server's certificate.
func serverView(hb cluster.Heartbeat, self, clusterFP string, roots map[string]bool) ServerView {
	v := ServerView{NodeID: hb.NodeID, Name: hb.Name, Self: self != "" && hb.NodeID == self, Names: []string{}, Outside: []string{}, Warnings: []string{}}
	t := hb.TLS
	if t == nil {
		v.Warnings = append(v.Warnings, "It runs a version that doesn't report its certificate, so Signalith can't tell which certificate authority it uses.")
		return v
	}
	v.Reported = true
	v.Mode, v.CASHA256, v.Cluster, v.CoversShared, v.ChangePending, v.LeafExpires, v.Problem =
		t.Mode, t.CASHA256, t.Cluster, t.CoversShared, t.ChangePending, t.LeafExpires, t.AdoptError
	v.Names = append(v.Names, t.Names...)
	v.Outside = append(v.Outside, t.Outside...)
	if len(t.Outside) > 0 {
		v.Warnings = append(v.Warnings, fmt.Sprintf("Its certificate leaves out %s, because its certificate authority may not vouch for %s.",
			strings.Join(t.Outside, ", "), plural(len(t.Outside), "that name", "those names")))
	}
	if !t.CoversShared {
		v.Warnings = append(v.Warnings, "Its certificate doesn't cover the cluster's shared address, so agents sent there by a load balancer refuse it.")
	}
	switch {
	case t.Mode == ModeFiles && t.CASHA256 != "" && clusterFP != "" && !SameFingerprint(t.CASHA256, clusterFP):
		v.Warnings = append(v.Warnings, "It uses your own certificate files, from another certificate authority than the cluster's, so agents set up for the other servers refuse it.")
	case t.Mode == ModeFiles && t.CASHA256 != "" && len(roots) > 1:
		v.Warnings = append(v.Warnings, "It uses your own certificate files, from another certificate authority than some other servers, so agents set up for those refuse it.")
	case clusterFP != "" && t.Mode == ModeAuto && !t.Cluster && t.ChangePending:
		v.Warnings = append(v.Warnings, "A change of its own certificate authority is in progress. It takes the cluster's once that is finished or cancelled on its Security page.")
	}
	return v
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// Find returns the candidate what names: its fingerprint, or the name or
// node id of a server that uses it.
func (r *Report) Find(what string) (*Candidate, bool) {
	what = strings.TrimSpace(what)
	if what == "" {
		return nil, false
	}
	for i := range r.Candidates {
		c := &r.Candidates[i]
		if SameFingerprint(c.CASHA256, what) || slices.Contains(c.Servers, what) || slices.Contains(c.NodeIDs, what) {
			return c, true
		}
	}
	return nil, false
}
