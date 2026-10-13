// Package ldaptest runs a small LDAP server in the same process, for tests
// and demos. It answers simple binds and searches with the filters
// directory sign-in uses (and, or, not, equality, presence, substrings,
// and Active Directory's in-chain and bitwise matching rules), and speaks
// LDAPS and StartTLS with a certificate from its own test CA. It is not a
// real directory: there are no schemas, and the only write is a modify by
// an account AllowWrite names (see Modifies).
package ldaptest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"
)

// Options choose how the server listens.
type Options struct {
	// Addr defaults to 127.0.0.1 on a free port.
	Addr string
	// TLS serves ldaps:// instead of ldap://.
	TLS bool
	// StartTLS lets ldap:// clients switch to TLS.
	StartTLS bool
	// CertHosts are the names on the server certificate; default
	// 127.0.0.1 and localhost.
	CertHosts []string
	// ActiveDirectory makes the server act like AD: anonymous searches
	// are refused, refused binds carry AD's "data 52e" codes, and users
	// get a memberOf attribute listing the groups that name them.
	ActiveDirectory bool
}

// Server is a running fake directory.
type Server struct {
	// URL is ldap://host:port or ldaps://host:port.
	URL string
	// CACert is the PEM certificate of the CA that signed the server
	// certificate.
	CACert string

	opts      Options
	ln        net.Listener
	tlsConfig *tls.Config
	wg        sync.WaitGroup

	mu        sync.Mutex
	entries   map[string]*entry // by normalized DN
	passwords map[string]string // by normalized DN
	mustReset map[string]bool   // by normalized DN
	writers   map[string]bool   // by normalized DN
	filters   []string
	binds     []string
	modifies  []string
	conns     int
	open      map[net.Conn]bool
}

type entry struct {
	dn    string
	attrs map[string][]string // by lower-case name
	names map[string]string   // lower-case name -> name as given
}

// Start runs a server until Close.
func Start(opts Options) (*Server, error) {
	if opts.Addr == "" {
		opts.Addr = "127.0.0.1:0"
	}
	if len(opts.CertHosts) == 0 {
		opts.CertHosts = []string{"127.0.0.1", "localhost"}
	}
	s := &Server{opts: opts, entries: map[string]*entry{}, passwords: map[string]string{}, mustReset: map[string]bool{},
		open: map[net.Conn]bool{}}
	if opts.TLS || opts.StartTLS {
		cfg, caPEM, err := newCertificates(opts.CertHosts)
		if err != nil {
			return nil, err
		}
		s.tlsConfig, s.CACert = cfg, caPEM
	}
	ln, err := net.Listen("tcp", opts.Addr)
	if err != nil {
		return nil, err
	}
	s.ln = ln
	scheme := "ldap"
	if opts.TLS {
		scheme = "ldaps"
	}
	s.URL = scheme + "://" + ln.Addr().String()
	s.wg.Add(1)
	go s.accept()
	return s, nil
}

// Close stops the server and ends open connections.
func (s *Server) Close() {
	s.ln.Close()
	s.mu.Lock()
	for c := range s.open {
		c.Close()
	}
	s.mu.Unlock()
	s.wg.Wait()
}

// Add stores an entry. Attribute names ignore case, as in LDAP.
func (s *Server) Add(dn string, attrs map[string][]string) {
	e := &entry{dn: dn, attrs: map[string][]string{}, names: map[string]string{}}
	for k, v := range attrs {
		e.attrs[strings.ToLower(k)] = slices.Clone(v)
		e.names[strings.ToLower(k)] = k
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries[norm(dn)] = e
}

// SetPassword lets dn bind with password.
func (s *Server) SetPassword(dn, password string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.passwords[norm(dn)] = password
}

// MustChangePassword makes dn's correct password fail the way Active
// Directory refuses a password that must be changed first (data 773).
func (s *Server) MustChangePassword(dn string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.mustReset[norm(dn)] = true
}

// AllowWrite lets the account dn change entries with modify requests.
// Others are refused with insufficientAccessRights, as a directory
// refuses an account without delegated write rights.
func (s *Server) AllowWrite(dn string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.writers == nil {
		s.writers = map[string]bool{}
	}
	s.writers[norm(dn)] = true
}

// Attr returns an entry's values of an attribute, or nil.
func (s *Server) Attr(dn, attr string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.entries[norm(dn)]
	if !ok {
		return nil
	}
	return slices.Clone(e.attrs[strings.ToLower(attr)])
}

// Modifies returns every modify request received, as "dn: op attr=values"
// lines, accepted or not.
func (s *Server) Modifies() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.modifies)
}

// Filters returns every search filter received, as text.
func (s *Server) Filters() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.filters)
}

// Binds returns the DN of every bind received.
func (s *Server) Binds() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.binds)
}

// Connections returns how many connections were accepted.
func (s *Server) Connections() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.conns
}

// norm makes a DN comparable: parsed and lower-cased when it parses.
func norm(dn string) string {
	d, err := ldap.ParseDN(dn)
	if err != nil {
		return strings.ToLower(strings.TrimSpace(dn))
	}
	parts := make([]string, 0, len(d.RDNs))
	for _, r := range d.RDNs {
		var avs []string
		for _, a := range r.Attributes {
			avs = append(avs, strings.ToLower(a.Type)+"="+strings.ToLower(a.Value))
		}
		parts = append(parts, strings.Join(avs, "+"))
	}
	return strings.Join(parts, ",")
}

func (s *Server) accept() {
	defer s.wg.Done()
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return
		}
		s.mu.Lock()
		s.conns++
		s.open[c] = true
		s.mu.Unlock()
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.serve(c)
		}()
	}
}

const startTLSOID = "1.3.6.1.4.1.1466.20037"

// session is one client connection.
type session struct {
	s     *Server
	c     net.Conn
	tls   bool
	bound string // DN bound as; "" is anonymous
}

func (s *Server) serve(c net.Conn) {
	ss := &session{s: s, c: c}
	defer func() {
		s.mu.Lock()
		delete(s.open, c)
		s.mu.Unlock()
		ss.c.Close()
	}()
	if s.opts.TLS {
		tc := tls.Server(c, s.tlsConfig)
		if err := tc.Handshake(); err != nil {
			return
		}
		ss.c, ss.tls = tc, true
	}
	for {
		p, err := ber.ReadPacket(ss.c)
		if err != nil || len(p.Children) < 2 {
			return
		}
		id, _ := p.Children[0].Value.(int64)
		op := p.Children[1]
		switch op.Tag {
		case ldap.ApplicationBindRequest:
			ss.bind(id, op)
		case ldap.ApplicationUnbindRequest:
			return
		case ldap.ApplicationSearchRequest:
			ss.search(id, op)
		case ldap.ApplicationModifyRequest:
			ss.modify(id, op)
		case ldap.ApplicationExtendedRequest:
			if !ss.extended(id, op) {
				return
			}
		case ldap.ApplicationAbandonRequest:
		default:
			ss.send(result(id, ldap.ApplicationExtendedResponse, ldap.LDAPResultProtocolError, "unsupported operation"))
		}
	}
}

func (ss *session) send(p *ber.Packet) { _, _ = ss.c.Write(p.Bytes()) }

func result(id int64, tag ber.Tag, code int, msg string) *ber.Packet {
	p := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Response")
	p.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, id, "MessageID"))
	r := ber.Encode(ber.ClassApplication, ber.TypeConstructed, tag, nil, "Response")
	r.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, int64(code), "resultCode"))
	r.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "matchedDN"))
	r.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, msg, "diagnosticMessage"))
	p.AppendChild(r)
	return p
}

func (ss *session) bind(id int64, op *ber.Packet) {
	const tag = ldap.ApplicationBindResponse
	if len(op.Children) < 3 {
		ss.send(result(id, tag, ldap.LDAPResultProtocolError, "bad bind request"))
		return
	}
	dn, pw := op.Children[1].Data.String(), op.Children[2].Data.String()
	s := ss.s
	s.mu.Lock()
	s.binds = append(s.binds, dn)
	want, known := s.passwords[norm(dn)]
	reset := s.mustReset[norm(dn)]
	s.mu.Unlock()
	switch {
	case pw == "":
		// Like real servers, a bind without a password is an
		// "unauthenticated" bind that succeeds as anonymous: the trap
		// clients must avoid.
		ss.bound = ""
		ss.send(result(id, tag, ldap.LDAPResultSuccess, ""))
	case known && pw == want && reset:
		ss.send(result(id, tag, ldap.LDAPResultInvalidCredentials,
			"80090308: LdapErr: DSID-0C09042A, comment: AcceptSecurityContext error, data 773, v3839"))
	case known && pw == want:
		ss.bound = dn
		ss.send(result(id, tag, ldap.LDAPResultSuccess, ""))
	default:
		msg := "invalid credentials"
		if s.opts.ActiveDirectory {
			msg = "80090308: LdapErr: DSID-0C09042A, comment: AcceptSecurityContext error, data 52e, v3839"
		}
		ss.send(result(id, tag, ldap.LDAPResultInvalidCredentials, msg))
	}
}

func (ss *session) extended(id int64, op *ber.Packet) bool {
	const tag = ldap.ApplicationExtendedResponse
	oid := ""
	if len(op.Children) > 0 {
		oid = op.Children[0].Data.String()
	}
	if oid != startTLSOID || !ss.s.opts.StartTLS || ss.tls {
		ss.send(result(id, tag, ldap.LDAPResultProtocolError, "unsupported extended operation"))
		return true
	}
	ss.send(result(id, tag, ldap.LDAPResultSuccess, ""))
	tc := tls.Server(ss.c, ss.s.tlsConfig)
	if err := tc.Handshake(); err != nil {
		return false
	}
	ss.c, ss.tls = tc, true
	return true
}

func (ss *session) search(id int64, op *ber.Packet) {
	const done = ldap.ApplicationSearchResultDone
	if len(op.Children) < 8 {
		ss.send(result(id, done, ldap.LDAPResultProtocolError, "bad search request"))
		return
	}
	s := ss.s
	base := op.Children[0].Data.String()
	scope, _ := op.Children[1].Value.(int64)
	sizeLimit, _ := op.Children[3].Value.(int64)
	filter := op.Children[6]
	var want []string
	for _, a := range op.Children[7].Children {
		want = append(want, strings.ToLower(a.Data.String()))
	}
	text, _ := ldap.DecompileFilter(filter)
	s.mu.Lock()
	s.filters = append(s.filters, text)
	s.mu.Unlock()
	if s.opts.ActiveDirectory && ss.bound == "" {
		ss.send(result(id, done, ldap.LDAPResultOperationsError,
			"000004DC: LdapErr: DSID-0C090A5C, comment: In order to perform this operation a successful bind must be completed on the connection., data 0, v4563"))
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	nb := norm(base)
	if _, ok := s.entries[nb]; !ok {
		ss.send(result(id, done, ldap.LDAPResultNoSuchObject, "no such object: "+base))
		return
	}
	var keys []string
	for k := range s.entries {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	sent := 0
	for _, k := range keys {
		if !inScope(k, nb, scope) {
			continue
		}
		e := s.entries[k]
		if !s.match(e, filter) {
			continue
		}
		if sizeLimit > 0 && int64(sent) >= sizeLimit {
			ss.send(result(id, done, ldap.LDAPResultSizeLimitExceeded, ""))
			return
		}
		ss.send(s.entryPacket(id, e, want))
		sent++
	}
	ss.send(result(id, done, ldap.LDAPResultSuccess, ""))
}

// modify applies a modify request (RFC 4511 section 4.6): add, delete or
// replace attribute values, all or nothing.
func (ss *session) modify(id int64, op *ber.Packet) {
	const tag = ldap.ApplicationModifyResponse
	if len(op.Children) < 2 {
		ss.send(result(id, tag, ldap.LDAPResultProtocolError, "bad modify request"))
		return
	}
	s := ss.s
	dn := op.Children[0].Data.String()
	type change struct {
		op   int64
		attr string
		vals []string
	}
	var changes []change
	for _, c := range op.Children[1].Children {
		if len(c.Children) < 2 || len(c.Children[1].Children) < 1 {
			ss.send(result(id, tag, ldap.LDAPResultProtocolError, "bad change"))
			return
		}
		kind, _ := c.Children[0].Value.(int64)
		ch := change{op: kind, attr: c.Children[1].Children[0].Data.String()}
		if len(c.Children[1].Children) > 1 {
			for _, v := range c.Children[1].Children[1].Children {
				ch.vals = append(ch.vals, v.Data.String())
			}
		}
		changes = append(changes, ch)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, ch := range changes {
		s.modifies = append(s.modifies, fmt.Sprintf("%s: %d %s=%s", dn, ch.op, ch.attr, strings.Join(ch.vals, "|")))
	}
	if ss.bound == "" || !s.writers[norm(ss.bound)] {
		ss.send(result(id, tag, ldap.LDAPResultInsufficientAccessRights,
			"00002098: SecErr: DSID-03150F94, problem 4003 (INSUFF_ACCESS_RIGHTS), data 0"))
		return
	}
	e, ok := s.entries[norm(dn)]
	if !ok {
		ss.send(result(id, tag, ldap.LDAPResultNoSuchObject, "no such object: "+dn))
		return
	}
	attrs := map[string][]string{}
	for k, v := range e.attrs {
		attrs[k] = slices.Clone(v)
	}
	for _, ch := range changes {
		k := strings.ToLower(ch.attr)
		switch ch.op {
		case ldap.AddAttribute:
			attrs[k] = append(attrs[k], ch.vals...)
		case ldap.DeleteAttribute:
			if _, has := attrs[k]; !has {
				ss.send(result(id, tag, ldap.LDAPResultNoSuchAttribute, "no such attribute: "+ch.attr))
				return
			}
			if len(ch.vals) == 0 {
				delete(attrs, k)
				continue
			}
			attrs[k] = slices.DeleteFunc(attrs[k], func(v string) bool { return slices.Contains(ch.vals, v) })
			if len(attrs[k]) == 0 {
				delete(attrs, k)
			}
		case ldap.ReplaceAttribute:
			if len(ch.vals) == 0 {
				delete(attrs, k)
			} else {
				attrs[k] = slices.Clone(ch.vals)
			}
		default:
			ss.send(result(id, tag, ldap.LDAPResultProtocolError, "bad modify operation"))
			return
		}
		if _, named := e.names[k]; !named {
			e.names[k] = ch.attr
		}
	}
	e.attrs = attrs
	ss.send(result(id, tag, ldap.LDAPResultSuccess, ""))
}

func inScope(dn, base string, scope int64) bool {
	switch scope {
	case ldap.ScopeBaseObject:
		return dn == base
	case ldap.ScopeSingleLevel:
		rest, ok := strings.CutSuffix(dn, ","+base)
		return ok && !strings.Contains(rest, ",")
	default:
		return dn == base || strings.HasSuffix(dn, ","+base)
	}
}

// values returns an attribute's values, including the memberOf an AD
// server computes from groups' member lists.
func (s *Server) values(e *entry, attr string) []string {
	attr = strings.ToLower(attr)
	if v, ok := e.attrs[attr]; ok {
		return v
	}
	if attr == "memberof" && s.opts.ActiveDirectory {
		return s.directGroups(e.dn)
	}
	if attr == "distinguishedname" {
		return []string{e.dn}
	}
	return nil
}

func (s *Server) directGroups(dn string) []string {
	n := norm(dn)
	var out []string
	for _, g := range s.entries {
		if slices.ContainsFunc(g.attrs["member"], func(m string) bool { return norm(m) == n }) {
			out = append(out, g.dn)
		}
	}
	slices.Sort(out)
	return out
}

func (s *Server) entryPacket(id int64, e *entry, want []string) *ber.Packet {
	p := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Response")
	p.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, id, "MessageID"))
	r := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ldap.ApplicationSearchResultEntry, nil, "Entry")
	r.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, e.dn, "DN"))
	attrs := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Attributes")
	all := len(want) == 0 || slices.Contains(want, "*")
	names := map[string]string{}
	if all {
		for k, n := range e.names {
			names[k] = n
		}
	}
	for _, w := range want {
		if w != "*" && w != "1.1" {
			names[w] = w
			if n, ok := e.names[w]; ok {
				names[w] = n
			}
		}
	}
	keys := make([]string, 0, len(names))
	for k := range names {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, k := range keys {
		vals := s.values(e, k)
		if len(vals) == 0 {
			continue
		}
		a := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Attribute")
		a.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, names[k], "Type"))
		set := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSet, nil, "Values")
		for _, v := range vals {
			set.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, v, "Value"))
		}
		a.AppendChild(set)
		attrs.AppendChild(a)
	}
	r.AppendChild(attrs)
	p.AppendChild(r)
	return p
}

// dnAttributes hold DNs, so their values compare as DNs.
var dnAttributes = map[string]bool{"member": true, "memberof": true, "uniquemember": true, "distinguishedname": true, "manager": true}

func (s *Server) equal(attr, a, b string) bool {
	if dnAttributes[strings.ToLower(attr)] {
		return norm(a) == norm(b)
	}
	if strings.EqualFold(attr, "objectCategory") && !strings.Contains(b, "=") {
		// AD expands objectCategory=person to the category's DN.
		if d, err := ldap.ParseDN(a); err == nil && len(d.RDNs) > 0 && len(d.RDNs[0].Attributes) > 0 {
			return strings.EqualFold(d.RDNs[0].Attributes[0].Value, b)
		}
	}
	return strings.EqualFold(a, b)
}

// match evaluates a search filter against an entry. The caller holds mu.
func (s *Server) match(e *entry, f *ber.Packet) bool {
	str := func(p *ber.Packet) string { return p.Data.String() }
	switch f.Tag {
	case ldap.FilterAnd:
		for _, c := range f.Children {
			if !s.match(e, c) {
				return false
			}
		}
		return true
	case ldap.FilterOr:
		for _, c := range f.Children {
			if s.match(e, c) {
				return true
			}
		}
		return false
	case ldap.FilterNot:
		return len(f.Children) == 1 && !s.match(e, f.Children[0])
	case ldap.FilterPresent:
		attr := strings.ToLower(f.Data.String())
		return attr == "objectclass" || len(s.values(e, attr)) > 0
	case ldap.FilterEqualityMatch:
		attr, want := str(f.Children[0]), str(f.Children[1])
		return slices.ContainsFunc(s.values(e, attr), func(v string) bool { return s.equal(attr, v, want) })
	case ldap.FilterSubstrings:
		attr := str(f.Children[0])
		return slices.ContainsFunc(s.values(e, attr), func(v string) bool { return substrings(strings.ToLower(v), f.Children[1].Children) })
	case ldap.FilterExtensibleMatch:
		var rule, attr, value string
		for _, c := range f.Children {
			switch c.Tag {
			case ldap.MatchingRuleAssertionMatchingRule:
				rule = str(c)
			case ldap.MatchingRuleAssertionType:
				attr = strings.ToLower(str(c))
			case ldap.MatchingRuleAssertionMatchValue:
				value = str(c)
			}
		}
		switch rule {
		case "1.2.840.113556.1.4.1941": // LDAP_MATCHING_RULE_IN_CHAIN
			switch attr {
			case "member":
				return s.memberInChain(e, norm(value), map[string]bool{})
			case "memberof":
				return slices.ContainsFunc(s.groupsInChain(e.dn), func(g string) bool { return norm(g) == norm(value) })
			}
		case "1.2.840.113556.1.4.803": // LDAP_MATCHING_RULE_BIT_AND
			bits, err := strconv.ParseInt(value, 10, 64)
			if err != nil {
				return false
			}
			return slices.ContainsFunc(s.values(e, attr), func(v string) bool {
				n, err := strconv.ParseInt(v, 10, 64)
				return err == nil && n&bits == bits
			})
		}
	}
	return false
}

func substrings(v string, parts []*ber.Packet) bool {
	for i, p := range parts {
		sub := strings.ToLower(p.Data.String())
		switch p.Tag {
		case ldap.FilterSubstringsInitial:
			if !strings.HasPrefix(v, sub) {
				return false
			}
			v = v[len(sub):]
		case ldap.FilterSubstringsAny:
			j := strings.Index(v, sub)
			if j < 0 {
				return false
			}
			v = v[j+len(sub):]
		case ldap.FilterSubstringsFinal:
			if !strings.HasSuffix(v, sub) || (i == 0 && len(v) < len(sub)) {
				return false
			}
		}
	}
	return true
}

// memberInChain reports whether group e has target as a member, directly
// or through groups inside it.
func (s *Server) memberInChain(e *entry, target string, seen map[string]bool) bool {
	k := norm(e.dn)
	if seen[k] {
		return false
	}
	seen[k] = true
	for _, m := range e.attrs["member"] {
		nm := norm(m)
		if nm == target {
			return true
		}
		if g, ok := s.entries[nm]; ok && s.memberInChain(g, target, seen) {
			return true
		}
	}
	return false
}

// groupsInChain returns every group dn belongs to, directly or through
// other groups.
func (s *Server) groupsInChain(dn string) []string {
	var out []string
	seen := map[string]bool{}
	queue := []string{dn}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for _, g := range s.directGroups(cur) {
			if !seen[norm(g)] {
				seen[norm(g)] = true
				out = append(out, g)
				queue = append(queue, g)
			}
		}
	}
	return out
}

// newCertificates makes a test CA and a server certificate it signs.
func newCertificates(hosts []string) (*tls.Config, string, error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, "", err
	}
	now := time.Now()
	caTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Signalith test CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, "", err
	}
	ca, _ := x509.ParseCertificate(caDER)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, "", err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: hosts[0]},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		return nil, "", err
	}
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	return &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}, string(caPEM), nil
}
