package security

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"net"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/tlsauto"
)

// TLSFactsFrom reads the certificate m serves, or returns nil without
// one. The server adds what it saw at runtime (refusals, names used).
func TLSFactsFrom(m *tlsauto.Manager, c *config.Config) *TLSFacts {
	if m == nil {
		return nil
	}
	t := &TLSFacts{ScopeSetup: c.Server.CAScope()}
	if leaf := m.Leaf(); leaf != nil {
		t.Leaf = leafFacts(leaf)
	}
	if m.LocalCA() {
		t.Mode = config.TLSAuto
		t.Outside = m.Outside()
		t.CA, t.Next, t.Previous = m.CAInfo(), m.Next(), m.Previous()
		t.ClusterCA = m.Store() == tlsauto.KindCluster
		t.WouldCover = map[string][]string{
			tlsauto.ScopeStandard: m.WouldCover(tlsauto.ScopeStandard),
			tlsauto.ScopeStrict:   m.WouldCover(tlsauto.ScopeStrict),
		}
		return t
	}
	t.Mode = config.TLSFiles
	t.CertFile, t.KeyFile = c.TLSFiles()
	if u, err := url.Parse(c.Server.PublicURL); err == nil && u.Hostname() != "" {
		t.PublicHost = u.Hostname()
		t.CoversPublicHost = m.Covers(t.PublicHost)
	}
	t.CAMissing = m.CAPEM() == nil && !m.PublicCA()
	return t
}

// leafFacts reads a certificate's end date and how strong it is.
func leafFacts(c *x509.Certificate) *LeafFacts {
	l := &LeafFacts{NotAfter: c.NotAfter, NoName: !slices.ContainsFunc(c.DNSNames, func(n string) bool {
		n = strings.ToLower(n)
		return n != "localhost" && !strings.HasSuffix(n, ".localhost") && !strings.HasPrefix(n, "*.")
	})}
	if k, ok := c.PublicKey.(*rsa.PublicKey); ok {
		l.RSABits = k.N.BitLen()
	}
	switch c.SignatureAlgorithm {
	case x509.SHA1WithRSA, x509.ECDSAWithSHA1, x509.DSAWithSHA1:
		l.SHA1 = true
	}
	return l
}

// seenLookupTimeout bounds looking up the names seen, all at once.
const seenLookupTimeout = 2 * time.Second

// SeenFrom lists the names people used to reach this server, whether a
// strict certificate authority made now would cover each, and for those
// it wouldn't, whether the name is this server's (see SeenName.Own).
func SeenFrom(ctx context.Context, m *tlsauto.Manager) []SeenName {
	if m == nil || !m.LocalCA() {
		return nil
	}
	out := []SeenName{}
	for _, s := range m.SeenNames() {
		out = append(out, SeenName{Name: s.Name, LastSeen: s.LastSeen,
			CoveredStrict: m.WouldAllow(tlsauto.ScopeStrict, strings.Trim(s.Name, "[]"))})
	}
	markOwn(ctx, out, ownAddrs(), net.DefaultResolver.LookupNetIP)
	return out
}

// lookupFunc looks a name up, as net.Resolver.LookupNetIP does.
type lookupFunc func(ctx context.Context, network, host string) ([]netip.Addr, error)

// markOwn sets Own on the names a strict certificate authority wouldn't
// cover: a private network name or address, or one that is, or leads
// to, one of own.
func markOwn(ctx context.Context, names []SeenName, own []netip.Addr, lookup lookupFunc) {
	ctx, cancel := context.WithTimeout(ctx, seenLookupTimeout)
	defer cancel()
	isOwn := func(a netip.Addr) bool { return slices.Contains(own, a.Unmap().WithZone("")) }
	var wg sync.WaitGroup
	for i := range names {
		n := &names[i]
		host := strings.Trim(n.Name, "[]")
		switch a, err := netip.ParseAddr(host); {
		case n.CoveredStrict:
		case tlsauto.PrivateName(host):
			n.Own = true
		case err == nil:
			n.Own = isOwn(a)
		default:
			wg.Add(1)
			go func() {
				defer wg.Done()
				addrs, err := lookup(ctx, "ip", host)
				n.Own = err == nil && len(addrs) > 0 && slices.ContainsFunc(addrs, isOwn)
			}()
		}
	}
	wg.Wait()
}

// ownAddrs are this computer's addresses.
func ownAddrs() []netip.Addr {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	var out []netip.Addr
	for _, a := range addrs {
		if p, err := netip.ParsePrefix(a.String()); err == nil {
			out = append(out, p.Addr().Unmap().WithZone(""))
		}
	}
	return out
}
