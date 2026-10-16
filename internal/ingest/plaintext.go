package ingest

import (
	"net/netip"
	"slices"
	"sort"
	"sync"
	"time"
)

// maxSenders caps the agents each list remembers; when full, the one heard
// from longest ago is forgotten. maxSenderHosts caps the host names kept
// for one address.
const (
	maxSenders     = 1000
	maxSenderHosts = 8
)

// Why an agent's batch was turned away (Sender.Reason).
const (
	// RefusedPlaintext: sent over plain HTTP while
	// server.tls.plaintext_ingest is deny.
	RefusedPlaintext = "plaintext"
	// RefusedOldToken: sent with the example token from an older
	// docker-compose.yml, which this server no longer accepts.
	RefusedOldToken = "old_token"
	// RefusedRevoked: sent with an agent token that was revoked, or a
	// shared one an admin stopped accepting.
	RefusedRevoked = "revoked"
	// RefusedToken: sent with a wrong ingest token, or none.
	RefusedToken = "token"
)

// Sender is an agent the Health page warns about: one that sends events
// over plain HTTP, which anyone on the network path can read and change,
// or one whose batches are turned away.
type Sender struct {
	Address  string    `json:"address"`
	Requests int64     `json:"requests"`
	LastSeen time.Time `json:"last_seen"`
	// Hosts are the host names in the agent's events, newest last. Behind
	// a NAT or Docker Desktop's port forwarding every agent has the same
	// address, and these tell them apart. Refused batches are not read,
	// so refused agents have none.
	Hosts []string `json:"hosts,omitempty"`
	// Reason is why a refused agent was turned away (RefusedPlaintext
	// and the rest).
	Reason string `json:"reason,omitempty"`
}

type senderKey struct {
	addr   netip.Addr
	reason string
}

// senderLog remembers recent senders, capped at maxSenders.
type senderLog struct {
	mu sync.Mutex
	m  map[senderKey]*Sender
}

func (l *senderLog) note(now time.Time, from netip.Addr, reason string, hosts []string) {
	if !from.IsValid() {
		return
	}
	from = from.Unmap().WithZone("")
	key := senderKey{from, reason}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.m == nil {
		l.m = map[senderKey]*Sender{}
	}
	e, ok := l.m[key]
	if !ok {
		if len(l.m) >= maxSenders {
			var oldest senderKey
			first := true
			for k, x := range l.m {
				if first || x.LastSeen.Before(l.m[oldest].LastSeen) {
					oldest, first = k, false
				}
			}
			delete(l.m, oldest)
		}
		e = &Sender{Address: from.String(), Reason: reason}
		l.m[key] = e
	}
	e.Requests++
	e.LastSeen = now
	for _, h := range hosts {
		if h == "" {
			continue
		}
		e.Hosts = slices.DeleteFunc(e.Hosts, func(x string) bool { return x == h })
		e.Hosts = append(e.Hosts, h)
		if len(e.Hosts) > maxSenderHosts {
			e.Hosts = e.Hosts[len(e.Hosts)-maxSenderHosts:]
		}
	}
}

func (l *senderLog) since(since time.Time) []Sender {
	l.mu.Lock()
	out := make([]Sender, 0, len(l.m))
	for _, e := range l.m {
		if !e.LastSeen.Before(since) {
			x := *e
			x.Hosts = slices.Clone(e.Hosts)
			out = append(out, x)
		}
	}
	l.mu.Unlock()
	sort.Slice(out, func(i, j int) bool {
		if !out[i].LastSeen.Equal(out[j].LastSeen) {
			return out[i].LastSeen.After(out[j].LastSeen)
		}
		if out[i].Address != out[j].Address {
			return out[i].Address < out[j].Address
		}
		return out[i].Reason < out[j].Reason
	})
	return out
}

// NotePlaintext records that the agent at from sent a batch over plain
// HTTP, with the host names in its events, so admins can find the agents
// to update before they turn plain-text ingest off.
func (p *Pipeline) NotePlaintext(from netip.Addr, hosts []string) {
	p.plaintext.note(p.now().UTC(), from, "", hosts)
}

// PlaintextSenders lists the agents that sent over plain HTTP since
// since, most recent first.
func (p *Pipeline) PlaintextSenders(since time.Time) []Sender {
	return p.plaintext.since(since)
}

// NoteRefused records that the agent at from was turned away for reason
// (RefusedPlaintext and the rest). Agents keep such batches and send them
// again, so admins need to know which ones to fix.
func (p *Pipeline) NoteRefused(from netip.Addr, reason string) {
	p.refused.note(p.now().UTC(), from, reason, nil)
}

// RefusedSenders lists the agents turned away since since, most recent
// first.
func (p *Pipeline) RefusedSenders(since time.Time) []Sender {
	return p.refused.since(since)
}
