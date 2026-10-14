package main

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/jrsamsanchez/signalith/internal/agentinv"
	"github.com/jrsamsanchez/signalith/internal/clustertls"
	"github.com/jrsamsanchez/signalith/internal/shared"
)

// signalith cluster tls: the cluster's certificate authority, and the
// choice of one when the servers were set up with their own.

// clusterTLSStatus is what signalith cluster tls -json prints.
type clusterTLSStatus struct {
	// Published is false while the cluster has no certificate authority.
	Published   bool                   `json:"published"`
	CASHA256    string                 `json:"ca_sha256,omitempty"`
	Names       []string               `json:"names"`
	PublishedBy string                 `json:"published_by,omitempty"`
	PublishedAt *time.Time             `json:"published_at,omitempty"`
	Retired     []string               `json:"retired"`
	Servers     []clusterTLSServer     `json:"servers"`
	Candidates  []clustertls.Candidate `json:"candidates,omitempty"`
}

// clusterTLSServer is one server's certificate, from its heartbeat.
type clusterTLSServer struct {
	Name     string `json:"name"`
	NodeID   string `json:"node_id"`
	Mode     string `json:"mode,omitempty"`
	CASHA256 string `json:"ca_sha256,omitempty"`
	// Cluster is true when it uses the cluster's certificate authority.
	Cluster bool     `json:"cluster"`
	Outside []string `json:"outside,omitempty"`
	Problem string   `json:"problem,omitempty"`
}

// tlsState reads the cluster's certificate authority, the servers'
// certificates and, while none is chosen, the candidates.
func (x *clusterCLI) tlsState(ctx context.Context) (*shared.Runtime, *clusterTLSStatus, error) {
	rt := x.runtime(true, "")
	if m, why := rt.Mode(); m != shared.ModeMember {
		return nil, nil, fmt.Errorf("this server cannot use the cluster's shared settings now (%s)", cmp.Or(why, m.Text()))
	}
	if !rt.SharedTLS() {
		return nil, nil, fmt.Errorf("the cluster does not keep one certificate authority yet: every server must run a version that reads level %d first", shared.LevelSharedTLS)
	}
	hbs, err := x.heartbeats(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("the servers' heartbeats cannot be read: %w", err)
	}
	cb, _ := rt.Cluster().Get()
	out := &clusterTLSStatus{Names: []string{}, Retired: []string{}, Servers: []clusterTLSServer{}}
	b, ok := x.tls.tls.Get()
	if ok {
		at := b.PublishedAt
		out.Published, out.CASHA256, out.PublishedBy, out.PublishedAt = true, b.CASHA256, b.PublishedBy, &at
		out.Names = append(out.Names, b.Names...)
		out.Retired = append(out.Retired, b.RetiredFingerprints()...)
	}
	for _, hb := range hbs {
		s := clusterTLSServer{Name: hb.Name, NodeID: hb.NodeID}
		if t := hb.TLS; t != nil {
			s.Mode, s.CASHA256, s.Cluster, s.Outside, s.Problem = t.Mode, t.CASHA256, t.Cluster, t.Outside, t.AdoptError
		}
		out.Servers = append(out.Servers, s)
	}
	if !ok {
		agents, _, _ := (&agentinv.Inventory{Client: x.cl, Prefix: x.prefix()}).List(ctx)
		out.Candidates = clustertls.Candidates(clustertls.FromHeartbeats(hbs, cb.CreatedByID), agents, time.Now())
	}
	return rt, out, nil
}

// tlsStatus prints the cluster's certificate authority.
func (x *clusterCLI) tlsStatus(ctx context.Context, asJSON bool) error {
	_, st, err := x.tlsState(ctx)
	if err != nil {
		return err
	}
	if asJSON {
		enc := json.NewEncoder(x.out)
		enc.SetIndent("", "  ")
		return enc.Encode(st)
	}
	w := tabwriter.NewWriter(x.out, 0, 0, 2, ' ', 0)
	if st.Published {
		fmt.Fprintf(w, "Certificate authority:\tthe cluster's, published by %s on %s\n", st.PublishedBy, st.PublishedAt.Format(time.DateOnly))
		fmt.Fprintf(w, "Fingerprint:\t%s\n", st.CASHA256)
		fmt.Fprintf(w, "Names:\t%s\n", cmp.Or(strings.Join(st.Names, ", "), "(none added)"))
		if len(st.Retired) > 0 {
			fmt.Fprintf(w, "Retired:\t%s\n", strings.Join(st.Retired, "\n\t"))
		}
	} else {
		fmt.Fprintf(w, "Certificate authority:\tnone chosen yet; each server keeps its own\n")
	}
	w.Flush()
	fmt.Fprintln(x.out, "\nServers:")
	w = tabwriter.NewWriter(x.out, 0, 0, 2, ' ', 0)
	for _, s := range st.Servers {
		ca := cmp.Or(s.CASHA256, "-")
		if s.Cluster {
			ca += " (the cluster's)"
		}
		fmt.Fprintf(w, "  %s\t%s\t%s\n", s.Name, cmp.Or(s.Mode, "-"), ca)
		if len(s.Outside) > 0 {
			fmt.Fprintf(w, "  \t\tleft out of its certificate: %s\n", strings.Join(s.Outside, ", "))
		}
		if s.Problem != "" {
			fmt.Fprintf(w, "  \t\t%s\n", s.Problem)
		}
	}
	w.Flush()
	if len(st.Candidates) > 0 {
		fmt.Fprintln(x.out, "\nCertificate authorities to choose from (signalith cluster tls choose <server or fingerprint>):")
		for _, c := range st.Candidates {
			mark := " "
			if c.Preselected {
				mark = "*"
			}
			fmt.Fprintf(x.out, " %s %s, used by %s: %d agents; %d would need a new configuration\n", mark, c.CASHA256,
				strings.Join(c.Servers, ", "), len(c.Agents), len(c.Breaks))
			for _, u := range c.CannotCover {
				fmt.Fprintf(x.out, "     cannot sign %s's names: %s\n", u.Server, strings.Join(u.Names, ", "))
			}
		}
	}
	return nil
}

// tlsChoose asks the server holding the certificate authority what names
// (a server's name or node id, or a fingerprint) to publish it as the
// cluster's, and waits for it.
func (x *clusterCLI) tlsChoose(ctx context.Context, what string, yes bool) error {
	rt, st, err := x.tlsState(ctx)
	if err != nil {
		return err
	}
	if st.Published {
		return fmt.Errorf("the cluster already has a certificate authority (%s); changing it comes in a later version", st.CASHA256)
	}
	i := slices.IndexFunc(st.Candidates, func(c clustertls.Candidate) bool {
		return clustertls.SameFingerprint(c.CASHA256, what) || slices.Contains(c.Servers, what) || slices.Contains(c.NodeIDs, what)
	})
	if i < 0 {
		return fmt.Errorf("no server seen in the last day uses a certificate authority %q names; signalith cluster tls lists them", what)
	}
	c := st.Candidates[i]
	q := fmt.Sprintf("Keep %s's certificate authority (%s) for the whole cluster? The other servers take it within seconds", c.Servers[0], c.CASHA256)
	if len(c.Breaks) > 0 {
		q += fmt.Sprintf(", and %d agents need a new configuration", len(c.Breaks))
	}
	if err := x.confirm(q+".", yes); err != nil {
		return err
	}
	req, err := rt.Requests().Submit(ctx, clustertls.RequestPublish, c.NodeIDs[0], clustertls.PublishArgs{CASHA256: c.CASHA256}, x.by)
	if err != nil {
		return err
	}
	x.audit("asked a server to publish its certificate authority as the cluster's", "server", c.Servers[0], "ca_sha256", c.CASHA256, "request", req.ID)
	deadline := time.Now().Add(cliRequestWait)
	for {
		got, ok, err := rt.Requests().Get(ctx, req.ID)
		if err == nil && ok && got.Over() {
			if got.State == shared.RequestFailed {
				return fmt.Errorf("%s did not publish it: %s", c.Servers[0], got.Error)
			}
			fmt.Fprintf(x.out, "The cluster's certificate authority is now %s's (%s). The other servers take it within seconds.\n", c.Servers[0], c.CASHA256)
			return nil
		}
		if time.Now().After(deadline) {
			fmt.Fprintf(x.out, "Asked %s to publish it (request %s); it has not answered yet. signalith cluster tls shows when it has.\n", c.Servers[0], req.ID)
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
}

// cliRequestWait is how long a command waits for a request it made.
var cliRequestWait = time.Minute

// errTLSUsage is the usage of signalith cluster tls.
var errTLSUsage = errors.New("usage: signalith cluster tls [-c file] [-json]\n       signalith cluster tls choose [-c file] [-yes] <server or fingerprint>")

// tlsCommand runs signalith cluster tls with its arguments.
func (x *clusterCLI) tlsCommand(ctx context.Context, pos []string, asJSON, yes bool) error {
	switch {
	case len(pos) == 0:
		return x.tlsStatus(ctx, asJSON)
	case len(pos) == 2 && pos[0] == "choose":
		return x.tlsChoose(ctx, pos[1], yes)
	}
	return errTLSUsage
}
