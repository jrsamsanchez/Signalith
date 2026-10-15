package main

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"text/tabwriter"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cluster"
	"github.com/jrsamsanchez/signalith/internal/clusterpki"
	"github.com/jrsamsanchez/signalith/internal/ospki"
	"github.com/jrsamsanchez/signalith/internal/shared"
)

// signalith cluster opensearch-ca: OpenSearch's certificate authority,
// which the cluster keeps to give each server its own OpenSearch
// certificate (see sharedosid.go).

// osCACommand runs signalith cluster opensearch-ca [import <key> |
// revoke <server> | crl].
func (x *clusterCLI) osCACommand(ctx context.Context, pos []string, certFile, outFile string, asJSON, yes bool) error {
	switch {
	case len(pos) == 0:
		return x.osCAStatus(ctx, asJSON)
	case pos[0] == "import" && len(pos) == 2:
		return x.osCAImport(ctx, pos[1], certFile)
	case pos[0] == "revoke" && len(pos) == 2:
		return x.osCARevoke(ctx, pos[1], yes)
	case pos[0] == "crl" && len(pos) == 1:
		return x.osCACRL(outFile)
	}
	return errors.New("usage: signalith cluster opensearch-ca [-json]\n" +
		"       signalith cluster opensearch-ca import [-cert root-ca.pem] <root-ca-key.pem>\n" +
		"       signalith cluster opensearch-ca revoke [-yes] <server>\n" +
		"       signalith cluster opensearch-ca crl [-o file]")
}

// osCARevoke ends the OpenSearch access of the server named server (its
// name or node id) at once: its certificates go on the revocation list.
func (x *clusterCLI) osCARevoke(ctx context.Context, server string, yes bool) error {
	if _, err := x.osCARuntime(false); err != nil {
		return err
	}
	b, ok := x.osca.Get()
	if !ok {
		return clusterpki.ErrShared
	}
	nodeID, name := "", server
	for n, is := range b.Issued {
		if is.NodeID == server || n == clusterpki.Norm(server) {
			nodeID, name = is.NodeID, n
			break
		}
	}
	if nodeID == "" {
		hbs, err := x.heartbeats(ctx)
		if err != nil {
			return fmt.Errorf("the servers' heartbeats cannot be read: %w", err)
		}
		for _, hb := range hbs {
			if hb.NodeID == server || hb.Name == server {
				nodeID, name = hb.NodeID, hb.Name
				break
			}
		}
	}
	if nodeID == "" {
		return fmt.Errorf("no server %q has, or had, an OpenSearch certificate from the cluster", server)
	}
	if nodeID == x.self.NodeID {
		return errors.New("that is this server: revoke it from another one")
	}
	if err := x.confirm(fmt.Sprintf("%s (%s) will lose its OpenSearch access at once, and get no new certificate unless it joins the cluster again. Go on?", name, nodeID), yes); err != nil {
		return err
	}
	revoked, err := x.osca.RevokeNode(ctx, x.by, nodeID)
	if err != nil {
		return err
	}
	fmt.Fprintf(x.out, "Revoked %d OpenSearch %s of %s.\n", len(revoked), map[bool]string{true: "certificate", false: "certificates"}[len(revoked) == 1], name)
	fmt.Fprintln(x.out, "Each server with opensearch.crl_file set writes the new revocation list within a minute; OpenSearch nodes without one need a copy: signalith cluster opensearch-ca crl -o crl.pem.")
	return nil
}

// osCACRL writes the revocation list to outFile, or prints it.
func (x *clusterCLI) osCACRL(outFile string) error {
	if _, err := x.osCARuntime(true); err != nil {
		return err
	}
	b, err := x.osca.CRL(time.Now())
	if err != nil {
		return err
	}
	return x.write(outFile, b)
}

// osCARuntime is a runtime of a member, which can read and change the
// shared settings.
func (x *clusterCLI) osCARuntime(readOnly bool) (*shared.Runtime, error) {
	rt := x.runtime(readOnly, "")
	if m, why := rt.Mode(); m != shared.ModeMember {
		return nil, fmt.Errorf("this server cannot use the cluster's shared settings now (%s)", cmp.Or(why, m.Text()))
	}
	return rt, nil
}

// osCAImport hands the certificate authority whose key is in keyFile to
// the cluster. Its certificate is certFile, or root-ca.pem next to the
// key, as opensearch-certs writes them.
func (x *clusterCLI) osCAImport(ctx context.Context, keyFile, certFile string) error {
	if certFile == "" {
		certFile = filepath.Join(filepath.Dir(keyFile), ospki.RootCAFile)
	}
	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		return err
	}
	defer clear(keyPEM)
	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		return fmt.Errorf("%w (give the certificate authority's certificate with -cert)", err)
	}
	ca, err := ospki.PairFromPEM(certPEM, keyPEM)
	if err != nil {
		return err
	}
	caFile, _, _ := x.c.OpenSearchTLSFiles()
	if err := clusterpki.Trusted(caFile, ca.Cert); err != nil {
		return err
	}
	if _, err := x.osCARuntime(false); err != nil {
		return err
	}
	if err := x.osca.Import(ctx, x.by, x.self.Name, certPEM, keyPEM); err != nil {
		return err
	}
	b, _ := x.osca.Get()
	fmt.Fprintf(x.out, "The cluster keeps OpenSearch's certificate authority now (%s).\n", b.CASHA256)
	fmt.Fprintln(x.out, "Each server that signs in to OpenSearch with a certificate from it gets one of its own, CN=signalith-server-<name>, within a minute.")
	fmt.Fprintf(x.out, "Keep %s safe and offline: anyone who holds it can sign in to OpenSearch as anything.\n", keyFile)
	return nil
}

// osCAStatus prints OpenSearch's certificate authority and who each
// server signs in as.
func (x *clusterCLI) osCAStatus(ctx context.Context, asJSON bool) error {
	if _, err := x.osCARuntime(true); err != nil {
		return err
	}
	hbs, err := x.heartbeats(ctx)
	if err != nil {
		return fmt.Errorf("the servers' heartbeats cannot be read: %w", err)
	}
	slices.SortFunc(hbs, func(a, b cluster.Heartbeat) int { return cmp.Compare(a.Name, b.Name) })
	b, ok := x.osca.Get()
	if asJSON {
		type server struct {
			NodeID   string `json:"node_id"`
			Name     string `json:"name"`
			Identity any    `json:"identity"`
		}
		out := struct {
			CA      *clusterpki.Body `json:"ca"`
			Servers []server         `json:"servers"`
		}{}
		if ok {
			c := *b
			c.CAKey = ""
			out.CA = &c
		}
		for _, hb := range hbs {
			out.Servers = append(out.Servers, server{hb.NodeID, hb.Name, hb.OSIdentity})
		}
		enc := json.NewEncoder(x.out)
		enc.SetIndent("", "  ")
		return enc.Encode(out)
	}
	w := tabwriter.NewWriter(x.out, 0, 0, 2, ' ', 0)
	if ok {
		fmt.Fprintf(w, "OpenSearch's certificate authority:\tkept by the cluster since %s (handed over by %s)\n", b.ImportedAt.Format(time.DateOnly), b.ImportedBy)
		fmt.Fprintf(w, "Fingerprint:\t%s\n", b.CASHA256)
	} else {
		fmt.Fprintln(w, "OpenSearch's certificate authority:\tnot kept by the cluster, so servers share one OpenSearch credential")
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, "SERVER\tSIGNS IN AS\tEXPIRES\tNOTE")
	for _, hb := range hbs {
		id := hb.OSIdentity
		if id == nil {
			fmt.Fprintf(w, "%s\t(not reported)\t\t\n", hb.Name)
			continue
		}
		who, until, note := cmp.Or(id.CN, id.User), "", id.Problem
		if id.NotAfter != nil {
			until = id.NotAfter.Format(time.DateOnly)
		}
		switch {
		case id.Managed:
			who += " (its own)"
		case id.Shared:
			who += " (shared)"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", hb.Name, who, until, note)
	}
	return w.Flush()
}
