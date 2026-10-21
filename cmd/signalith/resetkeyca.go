// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cluster"
	"github.com/jrsamsanchez/signalith/internal/clustertls"
	"github.com/jrsamsanchez/signalith/internal/secrets"
	"github.com/jrsamsanchez/signalith/internal/shared"
	"github.com/jrsamsanchez/signalith/internal/tlsauto"
)

// The cluster's certificate authority key is sealed with the cluster key
// like the passwords, so reset-key empties it too: no server can renew
// its HTTPS certificate afterwards, and the certificates in use run until
// they expire. reset-key says so, with the day, and asks first.

// caKeyValue is the certificate authority's key among the values
// Resign empties.
const caKeyValue = clustertls.DocID + " ca_key"

// lostCA returns the fingerprint of the cluster's certificate authority
// when docs hold its key sealed, so that signing them with a new cluster
// key empties it, and "" otherwise.
func lostCA(docs []shared.StoredDoc) string {
	for _, d := range docs {
		if d.ID != clustertls.DocID || d.Envelope.Deleted || d.Envelope.Body == "" {
			continue
		}
		var b clustertls.Body
		if json.Unmarshal([]byte(d.Envelope.Body), &b) != nil || b.CACertPEM == "" || !secrets.IsSealed(b.CAKey) {
			return ""
		}
		return b.CASHA256
	}
	return ""
}

// certExpiry is when a server's HTTPS certificate from the cluster's
// certificate authority expires.
type certExpiry struct {
	Server  string
	Expires time.Time
}

// certExpiries lists the certificates from the certificate authority fp
// that reset-key can see, soonest first: each server's last heartbeat,
// and own, this server's certificate in its tls folder (nil for none),
// in place of its heartbeat's.
func certExpiries(fp string, hbs []cluster.Heartbeat, self string, own *certExpiry) []certExpiry {
	var out []certExpiry
	if own != nil {
		out = append(out, *own)
	}
	for _, hb := range hbs {
		t := hb.TLS
		if (own != nil && hb.NodeID == self) || t == nil || t.LeafExpires == nil || !clustertls.SameFingerprint(t.CASHA256, fp) {
			continue
		}
		out = append(out, certExpiry{Server: hb.Name, Expires: t.LeafExpires.UTC()})
	}
	slices.SortFunc(out, func(a, b certExpiry) int {
		return cmp.Or(a.Expires.Compare(b.Expires), strings.Compare(a.Server, b.Server))
	})
	return out
}

// caLossText is what reset-key says before it empties the key of the
// cluster's certificate authority, given the certificates it can see.
func caLossText(certs []certExpiry) string {
	var b strings.Builder
	b.WriteString("The cluster's certificate authority key is lost too. It is sealed with the lost cluster key, so it is emptied with the rest (tls ca_key), " +
		"and afterwards no server can renew its HTTPS certificate or make a new one.\n")
	before := "they expire (at most 397 days after they were issued)"
	if len(certs) == 0 {
		b.WriteString("Signalith can't see when the servers' certificates expire: they run until then, at most 397 days after they were issued.\n")
	} else {
		before = shortDay(certs[0].Expires)
		b.WriteString("The certificates it can see run until:\n")
		for _, c := range certs {
			fmt.Fprintf(&b, "  %s, %s\n", c.Server, shortDay(c.Expires))
		}
		fmt.Fprintf(&b, "From %s, agents, browsers and syslog senders refuse each server whose certificate expired.\n", before)
	}
	b.WriteString("Before you go on, choose one:\n" +
		"  - Stop here and find a copy of the cluster key: a file signalith cluster export-key wrote, which signalith cluster import-key takes back. " +
		"A folder signalith cluster export --to-files wrote also holds the certificate authority's key (ca.key in its tls folder): keep it, and give it back afterwards with signalith cluster tls import.\n")
	fmt.Fprintf(&b, "  - Or plan to have agents, browsers and syslog senders trust a new certificate authority before %s.\n", before)
	return b.String()
}

// shortDay is a date as reset-key prints it.
func shortDay(t time.Time) string { return t.UTC().Format("2 Jan 2006") }

// caExpiries reads the certificates from the certificate authority fp
// that reset-key can see: this server's in its tls folder, and the
// others' from their last heartbeats.
func (x *clusterCLI) caExpiries(ctx context.Context, fp string) []certExpiry {
	var own *certExpiry
	if o, ok := certOptions(x.c); ok && o.CertFile == "" {
		if m, err := tlsauto.Inspect(o); err == nil && clustertls.SameFingerprint(m.Fingerprint(), fp) {
			if leaf := m.Leaf(); leaf != nil {
				own = &certExpiry{Server: x.self.Name, Expires: leaf.NotAfter.UTC()}
			}
		}
	}
	rctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	hbs, _ := readHeartbeats(rctx, x.cl, x.prefix())
	return certExpiries(fp, hbs, x.self.NodeID, own)
}
