package clustertls

import (
	"cmp"
	"crypto/x509"
	"encoding/pem"
	"slices"
	"time"

	"github.com/jrsamsanchez/signalith/internal/agentinv"
	"github.com/jrsamsanchez/signalith/internal/tlsauto"
)

// How far back a server and an agent count for the choice.
const (
	// ServerSeen: servers seen in the last day.
	ServerSeen = 24 * time.Hour
	// AgentSeen: agents that reached a server over HTTPS in the last week.
	AgentSeen = 7 * 24 * time.Hour
)

// Server is one server as the choice sees it, from its heartbeat.
type Server struct {
	NodeID string
	Name   string
	// Founder is true for the server that founded the cluster.
	Founder bool
	// SeenAt is its last heartbeat.
	SeenAt time.Time
	// CACertPEM is the certificate authority its certificate comes from,
	// "" without one of Signalith's own (its own certificate files).
	CACertPEM string
	// Names are the names its certificate should cover.
	Names []string
	// Files is true for a server with the admin's certificate files: it
	// keeps them whatever is chosen, and has no key to publish.
	Files bool
	// Up is true while the server runs: its heartbeat is fresh and it
	// did not stop. Only a server that runs can publish its certificate
	// authority.
	Up bool
}

// AgentRef names an agent in a candidate's lists.
type AgentRef struct {
	Key  string `json:"key"`
	Name string `json:"name"`
	// Address is its last address, for an agent that sends no name.
	Address string `json:"address,omitempty"`
}

// Uncovered is a server whose names a certificate authority may not sign.
type Uncovered struct {
	Server string   `json:"server"`
	Names  []string `json:"names"`
}

// Candidate is one certificate authority an admin may keep for the
// cluster.
type Candidate struct {
	CASHA256  string    `json:"ca_sha256"`
	Subject   string    `json:"subject"`
	Scope     string    `json:"scope"`
	NotBefore time.Time `json:"not_before"`
	NotAfter  time.Time `json:"not_after"`
	// Servers are the names of the servers that use it now, and NodeIDs
	// their node ids, in the same order, those that run first: the first
	// one publishes it.
	Servers []string `json:"servers"`
	NodeIDs []string `json:"node_ids"`
	// Up is false when none of its servers runs now, so none can publish
	// it until one is started again.
	Up bool `json:"up"`
	// Founder is true when the founder uses it.
	Founder bool `json:"founder,omitempty"`
	// Agents are the agents whose configuration trusts it, or (for one
	// that sends no pin) that reached one of its servers over HTTPS in the
	// last week. Breaks are the agents that use another candidate and not
	// this one: they need a new configuration if it is kept. Agents of
	// servers with the admin's certificate files are in neither, since
	// no choice changes those.
	Agents []AgentRef `json:"agents"`
	Breaks []AgentRef `json:"breaks"`
	// AgentCount and BreakCount count them all, where a report lists only
	// the first MaxListed of each.
	AgentCount int `json:"agent_count"`
	BreakCount int `json:"break_count"`
	// CannotCover lists the servers whose names its name constraints
	// forbid: their certificates would leave those names out.
	CannotCover []Uncovered `json:"cannot_cover"`
	// Preselected marks the one Signalith suggests: most agents, then
	// the founder's, then the oldest.
	Preselected bool `json:"preselected,omitempty"`

	ca *x509.Certificate
	up []bool // per NodeIDs
}

// Candidates lists the certificate authorities in use among the servers
// seen since now-ServerSeen, one per fingerprint, the preselected first
// and then by agents. It is empty when no server has one of its own.
func Candidates(servers []Server, agents []agentinv.Agent, now time.Time) []Candidate {
	byFP := map[string]*Candidate{}
	var order []string
	var seen []Server
	for _, s := range servers {
		if now.Sub(s.SeenAt) > ServerSeen {
			continue
		}
		seen = append(seen, s)
		ca := parsePEM(s.CACertPEM)
		if ca == nil || s.Files {
			continue
		}
		fp := tlsauto.Fingerprint(ca.Raw)
		c := byFP[fp]
		if c == nil {
			c = &Candidate{CASHA256: fp, Subject: ca.Subject.CommonName, NotBefore: ca.NotBefore.UTC(), NotAfter: ca.NotAfter.UTC(),
				Agents: []AgentRef{}, Breaks: []AgentRef{}, CannotCover: []Uncovered{}, ca: ca}
			if in := tlsauto.InfoOf(ca); in != nil {
				c.Scope = in.Scope
			}
			byFP[fp] = c
			order = append(order, fp)
		}
		// The servers that run first: the first one publishes it.
		at := len(c.Servers)
		if s.Up {
			at = 0
			for at < len(c.NodeIDs) && c.up[at] {
				at++
			}
		}
		c.Servers = slices.Insert(c.Servers, at, s.Name)
		c.NodeIDs = slices.Insert(c.NodeIDs, at, s.NodeID)
		c.up = slices.Insert(c.up, at, s.Up)
		c.Up = c.Up || s.Up
		c.Founder = c.Founder || s.Founder
	}
	// Which candidates each agent uses: an agent that uses none (it sends
	// only to servers with the admin's certificate files, or trusts only
	// a certificate authority no server uses) is not changed by the
	// choice.
	tlsAgents := map[string]bool{}
	for _, a := range agents {
		if a.Refusing {
			continue
		}
		for _, fp := range order {
			c := byFP[fp]
			if usesCA(a, c, now) {
				c.Agents = append(c.Agents, refOf(a))
				tlsAgents[a.Key] = true
			}
		}
	}
	for _, fp := range order {
		c := byFP[fp]
		mine := map[string]bool{}
		for _, r := range c.Agents {
			mine[r.Key] = true
		}
		for _, a := range agents {
			if tlsAgents[a.Key] && !mine[a.Key] {
				c.Breaks = append(c.Breaks, refOf(a))
			}
		}
		for _, s := range seen {
			if s.Files {
				// It keeps the admin's certificate files whatever is chosen.
				continue
			}
			var out []string
			for _, n := range s.Names {
				if n, ok := tlsauto.NormalizeName(n); ok && !tlsauto.CAAllows(c.ca, n) && !slices.Contains(out, n) {
					out = append(out, n)
				}
			}
			if len(out) > 0 {
				c.CannotCover = append(c.CannotCover, Uncovered{Server: s.Name, Names: out})
			}
		}
	}
	out := make([]Candidate, 0, len(order))
	for _, fp := range order {
		c := byFP[fp]
		c.AgentCount, c.BreakCount = len(c.Agents), len(c.Breaks)
		out = append(out, *c)
	}
	slices.SortStableFunc(out, func(a, b Candidate) int {
		if c := cmp.Compare(b.AgentCount, a.AgentCount); c != 0 {
			return c
		}
		if a.Founder != b.Founder {
			if a.Founder {
				return -1
			}
			return 1
		}
		if c := a.NotBefore.Compare(b.NotBefore); c != 0 {
			return c
		}
		return cmp.Compare(a.CASHA256, b.CASHA256)
	})
	if len(out) > 0 {
		out[0].Preselected = true
	}
	return out
}

// usesCA reports whether agent a uses candidate c: its configuration
// trusts c's pin, or, for one that sends no pin, it reached one of c's
// servers over HTTPS in the last week.
func usesCA(a agentinv.Agent, c *Candidate, now time.Time) bool {
	pin := agentinv.Pin(c.CASHA256)
	pinned := false
	for _, pins := range a.CA {
		if pins == "" {
			continue
		}
		pinned = true
		if agentinv.TrustsCA(pins, pin) {
			return true
		}
	}
	if pinned || now.Sub(a.LastSeen) > AgentSeen || !slices.Contains(a.Transports, agentinv.TransportTLS) {
		return false
	}
	return slices.ContainsFunc(a.Servers, func(s string) bool { return slices.Contains(c.Servers, s) })
}

func refOf(a agentinv.Agent) AgentRef {
	r := AgentRef{Key: a.Key, Name: a.Name}
	if len(a.Addresses) > 0 {
		r.Address = a.Addresses[0]
	}
	return r
}

func parsePEM(s string) *x509.Certificate {
	block, _ := pem.Decode([]byte(s))
	if block == nil || block.Type != "CERTIFICATE" {
		return nil
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil || !c.IsCA {
		return nil
	}
	return c
}

// Roots lists the fingerprints of Signalith's own certificate authorities
// in use among the servers seen since now-ServerSeen, once each. A server
// with the admin's certificate files keeps them whatever the cluster
// uses, so its root is not among them.
func Roots(servers []Server, now time.Time) []string {
	var out []string
	for _, s := range servers {
		if now.Sub(s.SeenAt) > ServerSeen || s.Files {
			continue
		}
		if ca := parsePEM(s.CACertPEM); ca != nil {
			if fp := tlsauto.Fingerprint(ca.Raw); !slices.Contains(out, fp) {
				out = append(out, fp)
			}
		}
	}
	return out
}
