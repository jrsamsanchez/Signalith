package api

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cluster"
)

// agentRecycle is how many batches an agent sends on one kept-alive
// connection before it opens a new one, when several servers share the
// work: a load balancer then spreads agents over a server that comes back.
const agentRecycle = 100

// destinationTimeout bounds the DNS lookups of the destinations check.
const destinationTimeout = 3 * time.Second

// lookupHost resolves a host name for the destinations check; tests
// replace it.
var lookupHost = net.DefaultResolver.LookupHost

// destination is one answer to "Where do agents send?" on Add data.
type destination struct {
	// Kind is shared (server.public_url: a load balancer or DNS name in
	// front of every server, or this server alone), self (this server's
	// own address) or server (another server's own address).
	Kind string `json:"kind"`
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
	URL  string `json:"url"`
	// For shared: what the address resolves to, and which servers it
	// reaches and misses, by their own addresses.
	Resolves []resolvedAddr `json:"resolves,omitempty"`
	Reaches  []string       `json:"reaches,omitempty"`
	Misses   []string       `json:"misses,omitempty"`
	Problem  string         `json:"problem,omitempty"`
}

type resolvedAddr struct {
	Addr   string `json:"addr"`
	Server string `json:"server,omitempty"`
}

// handleAgentDestinations answers GET /api/agents/destinations: where
// agents can send, with a DNS check of the shared address.
func (s *Server) handleAgentDestinations(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), destinationTimeout)
	defer cancel()
	var st cluster.Status
	if s.Cluster != nil {
		st = s.Cluster.Status()
	}
	choices, warning := destinationsOf(ctx, s.conf().Server.PublicURL, st)
	out := map[string]any{"choices": choices}
	if warning != "" {
		out["warning"] = warning
	}
	writeJSON(w, http.StatusOK, out)
}

// servers returns the servers in st that agents could send to, with an
// address: every one that is not offline or stopped.
func agentServers(st cluster.Status) []cluster.ServerStatus {
	var out []cluster.ServerStatus
	for _, sv := range st.Servers {
		if sv.Detail != nil && sv.Detail.NodeURL != "" && running(sv) {
			out = append(out, sv)
		}
	}
	return out
}

func destinationsOf(ctx context.Context, publicURL string, st cluster.Status) ([]destination, string) {
	shared := destination{Kind: "shared", URL: publicURL}
	servers := agentServers(st)
	var rest []destination
	for _, sv := range servers {
		d := destination{Kind: "server", ID: sv.NodeID, Name: sv.Name, URL: sv.Detail.NodeURL}
		if sv.Self {
			d.Kind = "self"
		}
		rest = append(rest, d)
	}
	if len(servers) < 2 {
		// One server: agents send to it, by whatever address.
		return append([]destination{shared}, rest...), ""
	}

	// Which addresses are each server's own?
	owners := map[netip.Addr][]string{}
	for _, sv := range servers {
		for _, a := range resolve(ctx, hostOf(sv.Detail.NodeURL)) {
			owners[a] = append(owners[a], sv.Name)
		}
	}
	host := hostOf(publicURL)
	addrs := resolve(ctx, host)
	if len(addrs) == 0 {
		shared.Problem = host + " does not resolve from this server, so this server cannot tell which servers it reaches."
		return append([]destination{shared}, rest...), ""
	}
	if !slices.ContainsFunc(addrs, func(a netip.Addr) bool { return !a.IsLoopback() }) {
		// This computer only: Add data already says other machines can't
		// reach it.
		return append([]destination{shared}, rest...), ""
	}
	reached := map[string]bool{}
	for _, a := range addrs {
		names := owners[a]
		shared.Resolves = append(shared.Resolves, resolvedAddr{Addr: a.String(), Server: strings.Join(names, ", ")})
		for _, n := range names {
			reached[n] = true
		}
	}
	for _, sv := range servers {
		if reached[sv.Name] {
			shared.Reaches = append(shared.Reaches, sv.Name)
		} else {
			shared.Misses = append(shared.Misses, sv.Name)
		}
	}
	warning := ""
	switch {
	case len(shared.Reaches) == 0:
		// None of the servers' own addresses: a load balancer's, as it
		// should be. Nothing to say.
	case len(shared.Reaches) == 1 && len(shared.Resolves) == 1:
		warning = fmt.Sprintf("Agents sent to %s wait while %s is down. Add a load balancer or DNS name for automatic failover.",
			shared.Reaches[0], shared.Reaches[0])
	case len(shared.Misses) > 0:
		shared.Problem = fmt.Sprintf("%s reaches %s but not %s. Add the missing servers' addresses to the DNS name, or put a load balancer in front.",
			host, joinAnd(shared.Reaches), joinAnd(shared.Misses))
	}
	return append([]destination{shared}, rest...), warning
}

// hostOf returns the host of an address such as https://siem:8080.
func hostOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

// resolve returns the addresses host stands for: itself when it is an IP
// address, else what DNS answers (none when it cannot).
func resolve(ctx context.Context, host string) []netip.Addr {
	if host == "" {
		return nil
	}
	if a, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{a.Unmap().WithZone("")}
	}
	names, err := lookupHost(ctx, host)
	if err != nil {
		return nil
	}
	var out []netip.Addr
	for _, n := range names {
		if a, err := netip.ParseAddr(n); err == nil {
			a = a.Unmap().WithZone("")
			if !slices.Contains(out, a) {
				out = append(out, a)
			}
		}
	}
	slices.SortFunc(out, netip.Addr.Compare)
	return out
}

var errUnknownDestination = errors.New("no such server: choose shared, self or a server listed by GET /api/agents/destinations")

// agentDestination returns the address an agent configuration sends to
// for to (shared, self or a server's ID), and whether that is another
// server, whose certificate this one cannot check names against.
func (s *Server) agentDestination(to string) (string, bool, error) {
	if to == "shared" {
		return s.conf().Server.PublicURL, false, nil
	}
	if s.Cluster == nil {
		return "", false, errUnknownDestination
	}
	for _, sv := range agentServers(s.Cluster.Status()) {
		if (to == "self" && sv.Self) || to == sv.NodeID {
			return sv.Detail.NodeURL, !sv.Self, nil
		}
	}
	return "", false, errUnknownDestination
}

// agentRecycleFor returns Options.Recycle: agentRecycle when this server
// shares its OpenSearch with others, else 0 (the configuration as it was).
func (s *Server) agentRecycleFor() int {
	if s.Cluster != nil && len(s.Cluster.Status().Servers) > 1 {
		return agentRecycle
	}
	return 0
}
