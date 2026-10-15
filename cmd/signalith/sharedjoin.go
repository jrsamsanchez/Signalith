package main

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/jrsamsanchez/signalith/internal/api"
	"github.com/jrsamsanchez/signalith/internal/cluster"
	"github.com/jrsamsanchez/signalith/internal/clusterjoin"
	"github.com/jrsamsanchez/signalith/internal/clusterpki"
	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/shared"
	"github.com/jrsamsanchez/signalith/internal/tlsauto"
)

// Adding servers to the cluster (internal/clusterjoin): join tokens made
// on the Servers page or with signalith cluster token, the public join a
// new server makes with one (signalith join), and the approval of a
// server that waits with its fingerprint. The token documents are one
// shared collection (sharedDocs.join); everything else is in the
// runtime index.

// joinInfo is what a server waiting for approval says about itself in
// its pending document.
func joinInfo(c *config.Config) func() shared.PendingDoc {
	nu := nodeURL(c)
	return func() shared.PendingDoc {
		return shared.PendingDoc{Version: version, NodeURL: nu, Addresses: localAddresses(8)}
	}
}

// localAddresses lists up to max of this machine's own addresses,
// loopback and link-local ones left out.
func localAddresses(max int) []string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	var out []string
	for _, a := range addrs {
		n, ok := a.(*net.IPNet)
		if !ok || n.IP.IsLoopback() || n.IP.IsLinkLocalUnicast() || n.IP.IsLinkLocalMulticast() {
			continue
		}
		out = append(out, n.IP.String())
		if len(out) == max {
			break
		}
	}
	return out
}

// joinAPI is the cluster's joins as the API uses them (api.ClusterJoin).
type joinAPI struct {
	rt     *shared.Runtime
	tokens *clusterjoin.Tokens
	c      *config.Config
	node   string
	log    *slog.Logger
	// leaf signs a joining server's HTTPS certificate from the cluster's
	// certificate authority; nil gives none.
	leaf clusterjoin.LeafFunc
	// osca issues a joining server its own OpenSearch certificate when
	// the cluster keeps OpenSearch's certificate authority; nil shares.
	osca *clusterpki.OSCA
}

// sharedJoin returns the API's view of the cluster's joins for the start
// with the configuration c and the HTTPS certificate certs; nil on a
// server that keeps no shared settings.
func (r *runner) sharedJoin(c *config.Config, certs *tlsauto.Manager) api.ClusterJoin {
	if r.shared == nil || r.sharedContent == nil {
		return nil
	}
	j := &joinAPI{rt: r.shared, tokens: r.sharedContent.join, c: c, log: r.log, osca: r.sharedContent.osca}
	if r.node != nil {
		j.node = r.node.Name()
	}
	j.leaf = r.joinLeaf(certs)
	return j
}

// joinLeaf signs the joining server's HTTPS certificate from the
// cluster's certificate authority (tlsauto.SignCSR), when the cluster has
// published one; without one (files mode, a choice of certificate
// authority still to make, a cluster below that level) the joining server
// gets none and makes its own certificate authority, as before.
func (r *runner) joinLeaf(*tlsauto.Manager) clusterjoin.LeafFunc {
	if r.sharedContent == nil || r.sharedContent.tls == nil {
		return nil
	}
	ct := r.sharedContent.tls.tls
	return func(csrPEM []byte, names []string) ([]byte, []byte, error) {
		b, ok := ct.Get()
		if !ok || b.CACertPEM == "" {
			return nil, nil, nil
		}
		ca, key, err := ct.Store().Load()
		if err != nil || ca == nil || key == nil {
			return nil, nil, err
		}
		leaf, err := tlsauto.SignCSR(ca, key, csrPEM, names, time.Now())
		if err != nil {
			return nil, nil, err
		}
		return []byte(b.CACertPEM), leaf, nil
	}
}

func (j *joinAPI) view() clusterjoin.View { return clusterjoin.ViewOf(j.c) }

// tokenURL is the address a join token names: this server's
// server.node_url, else server.public_url, else the address the admin's
// browser reached it at. It must be https, and not one only this computer
// reaches (localhost, a loopback address): the new server would reach
// itself there.
func (j *joinAPI) tokenURL(origin string) (string, error) {
	for _, u := range []string{j.c.Server.NodeURL, j.c.Server.PublicURL, origin} {
		if u = strings.TrimSpace(u); u == "" {
			continue
		}
		if p, err := url.Parse(u); err == nil && p.Scheme == "https" && p.Hostname() != "" && !tokenHostLocal(p.Hostname()) {
			return u, nil
		}
	}
	return "", errTokenURL
}

// errTokenURL: no address a new server reaches this one at.
var errTokenURL = errors.New("a join token needs this server's https address that the new server reaches: set server.node_url (or server.public_url) on the Settings page, " +
	"or make the token from a browser that reaches this server by such an address (not localhost)")

func (j *joinAPI) Issue(ctx context.Context, by string, req api.JoinTokenRequest) (*clusterjoin.Issued, error) {
	if err := j.rt.Writable(); err != nil {
		return nil, err
	}
	if err := j.view().Secured(); err != nil {
		return nil, err
	}
	u, err := j.tokenURL(req.Origin)
	if err != nil {
		return nil, err
	}
	return j.tokens.Issue(ctx, clusterjoin.IssueArgs{By: by, Node: cmp.Or(j.node, j.rt.Self().Name), URL: u, CADER: req.CADER,
		TTL: time.Duration(req.TTLMinutes) * time.Minute, Platform: req.Platform, Note: req.Note, NodeURL: req.NodeURL})
}

func (j *joinAPI) Revoke(ctx context.Context, by, id string) error {
	return j.tokens.Revoke(ctx, by, id)
}

func (j *joinAPI) Tokens() []clusterjoin.TokenInfo { return j.tokens.List() }

func (j *joinAPI) approver() *clusterjoin.Approver {
	a := &clusterjoin.Approver{RT: j.rt, Secured: j.view().Secured, Log: j.log}
	if j.osca != nil {
		a.Readmit = j.osca.Readmit
	}
	return a
}

func (j *joinAPI) Pending(ctx context.Context) ([]shared.PendingDoc, error) {
	if m, _ := j.rt.Mode(); m != shared.ModeMember {
		return nil, nil
	}
	return j.approver().Pending(ctx)
}

func (j *joinAPI) Approve(ctx context.Context, nodeID, fingerprint, by string) (*shared.PendingDoc, error) {
	return j.approver().Approve(ctx, nodeID, fingerprint, by)
}

func (j *joinAPI) Answer(ctx context.Context, req *clusterjoin.Request) (string, error) {
	return clusterjoin.Answer(ctx, clusterjoin.Deps{RT: j.rt, Tokens: j.tokens, Version: version, View: j.view,
		IssueLeaf: j.leaf, Credential: joinCredential(j.view, j.osca), Log: j.log}, req)
}

// joinCredential is the OpenSearch credential a joining server gets:
// its own certificate, issued for the key of its CSR, when the cluster
// keeps OpenSearch's certificate authority (osca); otherwise the
// answering server's own, which the servers then share.
func joinCredential(view func() clusterjoin.View, osca *clusterpki.OSCA) clusterjoin.CredentialFunc {
	shared := clusterjoin.DefaultCredential(view)
	return func(ctx context.Context, name, nodeID string, csrPEM []byte) (clusterjoin.OSCredential, error) {
		if osca == nil || len(csrPEM) == 0 {
			return shared(ctx, name, nodeID, csrPEM)
		}
		cr, err := osca.JoinCredential(ctx, name, nodeID, csrPEM)
		if errors.Is(err, clusterpki.ErrShared) {
			return shared(ctx, name, nodeID, csrPEM)
		}
		if err != nil {
			return clusterjoin.OSCredential{}, fmt.Errorf("could not issue %s its OpenSearch certificate: %w", name, err)
		}
		return clusterjoin.OSCredential{ClientCertPEM: string(cr.ClientCertPEM), CAPEM: string(cr.CAPEM), Managed: true}, nil
	}
}

func (j *joinAPI) Waiting() string { return j.rt.Waiting() }

// joinJobs is the housekeeping of joins, run by the server that runs the
// background jobs: expired join tokens are deleted, and the requests of
// servers that stopped waiting for approval a day ago.
func (r *runner) joinJobs() []cluster.Job {
	if r.shared == nil || r.sharedContent == nil {
		return nil
	}
	rt, tokens, log := r.shared, r.sharedContent.join, r.log
	return []cluster.Job{{Name: "join housekeeping", Run: func(ctx context.Context) {
		for {
			joinHousekeep(ctx, rt, tokens, time.Now(), log)
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Hour):
			}
		}
	}}}
}

// joinHousekeep is one round of joinJobs at now.
func joinHousekeep(ctx context.Context, rt *shared.Runtime, tokens *clusterjoin.Tokens, now time.Time, log *slog.Logger) {
	if n, err := tokens.Expire(ctx, now); err != nil {
		if ctx.Err() == nil {
			log.Warn("could not delete the expired join tokens", "err", err)
		}
	} else if n > 0 {
		log.Info(fmt.Sprintf("deleted %d expired join tokens", n))
	}
	if n, err := rt.DropStalePending(ctx, now); err != nil {
		if ctx.Err() == nil {
			log.Warn("could not delete the old requests to join", "err", err)
		}
	} else if n > 0 {
		log.Info(fmt.Sprintf("deleted %d requests to join that no server came back for", n))
	}
}
