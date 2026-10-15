package ospki

// Keeping the CA and issuing more certificates under it: renewals, more
// OpenSearch nodes, and one client certificate per Signalith server when
// several share one OpenSearch.

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

const (
	// RootCAKeyFile is the CA's key, kept next to RootCAFile in a folder
	// of its own: never in OpenSearch's certs folder or Signalith's.
	RootCAKeyFile = "root-ca-key.pem"
	// ImportDir is the folder in Signalith's state folder that the CA is
	// handed over in (bootstrap-docker -export-ca-key), as ExportCAFile
	// and ExportCAKeyFile. Signalith reads them once and deletes the key.
	ImportDir       = "import"
	ExportCAFile    = "opensearch-ca.pem"
	ExportCAKeyFile = "opensearch-ca-key.pem"
	// ServerClientPrefix starts the common name of each Signalith
	// server's own client certificate, which roles_mapping.yml maps to
	// signalith_server. It is not just "signalith-", which would also
	// match the admin certificate (signalith-admin).
	ServerClientPrefix = "signalith-server-"
)

// ErrNoCAKey is LoadCA's error for a CA certificate without its key, as
// versions before the key was kept left.
var ErrNoCAKey = errors.New("the OpenSearch CA's key was not kept")

// CAFiles returns the CA's certificate and key, by name, for the folder
// the key is kept in.
func (s *Set) CAFiles() map[string][]byte {
	return map[string][]byte{RootCAFile: s.CA.CertPEM(), RootCAKeyFile: s.CA.KeyPEM()}
}

// NewCA makes a CA that lasts Validity from now.
func NewCA(now time.Time) (*Pair, error) {
	if now.IsZero() {
		now = time.Now()
	}
	key, err := rsa.GenerateKey(rand.Reader, KeyBits)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial(),
		Subject:               pkix.Name{CommonName: "Signalith OpenSearch CA", Organization: []string{Org}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(Validity),
		IsCA:                  true,
		BasicConstraintsValid: true,
		MaxPathLenZero:        true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &Pair{Cert: c, Key: key}, nil
}

// LoadCA reads the CA certificate and key from dir (RootCAFile and
// RootCAKeyFile). It returns ErrNoCAKey when only the certificate is
// there, and an fs.ErrNotExist error when neither is.
func LoadCA(dir string) (*Pair, error) {
	certPEM, err := readFile(dir, RootCAFile)
	if err != nil {
		return nil, err
	}
	c, err := parseCert(certPEM)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", RootCAFile, err)
	}
	if !c.IsCA {
		return nil, fmt.Errorf("%s is not a CA certificate", RootCAFile)
	}
	keyPEM, err := readFile(dir, RootCAKeyFile)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ErrNoCAKey
	}
	if err != nil {
		return nil, err
	}
	key, err := parseKey(keyPEM)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", RootCAKeyFile, err)
	}
	if !key.PublicKey.Equal(c.PublicKey) {
		return nil, fmt.Errorf("%s is not the key of %s", RootCAKeyFile, RootCAFile)
	}
	return &Pair{Cert: c, Key: key}, nil
}

// IssueNode makes an OpenSearch node certificate under ca for the common
// name cn, covering cn, localhost, 127.0.0.1 and names (more host names or
// IP addresses). It lasts Validity, or until the CA expires if sooner.
func IssueNode(ca *Pair, cn string, names []string, now time.Time) (*Pair, error) {
	dns, ips, err := nodeNames(cn, names)
	if err != nil {
		return nil, err
	}
	// Nodes connect to each other as both server and client.
	return issue(ca, cn, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}, dns, ips, now, Validity)
}

// IssueClient makes a client certificate under ca for the common name
// cn, lasting validity or until the CA expires if sooner. The admin and
// Signalith's shared client certificate last Validity; each server's own
// (ServerClientName) is meant to be shorter.
func IssueClient(ca *Pair, cn string, now time.Time, validity time.Duration) (*Pair, error) {
	if cn == "" {
		return nil, errors.New("a client certificate needs a name")
	}
	return issue(ca, cn, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, nil, nil, now, validity)
}

func issue(ca *Pair, cn string, usage []x509.ExtKeyUsage, dns []string, ips []net.IP, now time.Time, validity time.Duration) (*Pair, error) {
	if ca == nil || ca.Key == nil {
		return nil, ErrNoCAKey
	}
	key, err := rsa.GenerateKey(rand.Reader, KeyBits)
	if err != nil {
		return nil, err
	}
	c, err := issueKey(ca, cn, usage, dns, ips, &key.PublicKey, now, validity)
	if err != nil {
		return nil, err
	}
	return &Pair{Cert: c, Key: key}, nil
}

// issueKey makes a certificate under ca for the public key pub.
func issueKey(ca *Pair, cn string, usage []x509.ExtKeyUsage, dns []string, ips []net.IP, pub *rsa.PublicKey, now time.Time, validity time.Duration) (*x509.Certificate, error) {
	if ca == nil || ca.Key == nil {
		return nil, ErrNoCAKey
	}
	if now.IsZero() {
		now = time.Now()
	}
	notAfter := now.Add(validity)
	if ca.Cert.NotAfter.Before(notAfter) {
		notAfter = ca.Cert.NotAfter
	}
	notBefore := now.Add(-time.Hour)
	if notBefore.Before(ca.Cert.NotBefore) {
		notBefore = ca.Cert.NotBefore
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial(),
		Subject:               pkix.Name{CommonName: cn, Organization: []string{Org}},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           usage,
		DNSNames:              dns,
		IPAddresses:           ips,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, pub, ca.Key)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

// nodeNames checks a node's common name and sorts what its certificate
// covers into host names and IP addresses: cn, localhost, 127.0.0.1 and
// names, each once.
func nodeNames(cn string, names []string) ([]string, []net.IP, error) {
	if err := CheckNodeName(cn); err != nil {
		return nil, nil, err
	}
	var dns []string
	var ips []net.IP
	seen := map[string]bool{}
	for _, n := range append([]string{cn, "localhost", "127.0.0.1"}, names...) {
		n = strings.TrimSpace(n)
		if n == "" || seen[strings.ToLower(n)] {
			continue
		}
		seen[strings.ToLower(n)] = true
		if a, err := netip.ParseAddr(strings.Trim(n, "[]")); err == nil {
			if k := "ip:" + a.Unmap().String(); !seen[k] {
				seen[k] = true
				ips = append(ips, a.Unmap().AsSlice())
			}
			continue
		}
		if !validDNSName(n) {
			return nil, nil, fmt.Errorf("%q is not a host name or IP address", n)
		}
		dns = append(dns, strings.ToLower(n))
	}
	return dns, ips, nil
}

// CheckNames says what is wrong with more names for a node certificate,
// if anything: each must be a host name or an IP address.
func CheckNames(names []string) error {
	_, _, err := nodeNames(NodeName, names)
	return err
}

// CheckNodeName says what is wrong with an OpenSearch node's common name:
// it must be a host name, and not one Signalith's own certificates use
// (signalith, or anything starting with signalith-), so the settings that
// recognize nodes, the admin and Signalith's servers can never mistake one
// certificate for another.
func CheckNodeName(cn string) error {
	if _, err := netip.ParseAddr(cn); err == nil || !validDNSName(cn) {
		return fmt.Errorf("node name %q must be a host name, such as opensearch or search1.example.com", cn)
	}
	if l := strings.ToLower(cn); l == ClientName || strings.HasPrefix(l, ClientName+"-") {
		return fmt.Errorf("node name %q is taken: names starting with signalith are for Signalith's own certificates", cn)
	}
	return nil
}

// ServerClientName is the common name of a Signalith server's own client
// certificate: ServerClientPrefix and the server's name, which must be a
// lower-case DNS label such as siem-a.
func ServerClientName(server string) (string, error) {
	if server == "" || len(server) > 63-len(ServerClientPrefix) || server[0] == '-' || server[len(server)-1] == '-' {
		return "", fmt.Errorf("server name %q must be a short lower-case name such as siem-a", server)
	}
	for _, r := range server {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
			return "", fmt.Errorf("server name %q must be a short lower-case name such as siem-a (letters, digits and -)", server)
		}
	}
	return ServerClientPrefix + server, nil
}

// NodeFileNames are the certificate and key files of node i (from 1) in
// OpenSearch's certs folder: node.pem and node-key.pem for the first, as
// a single node has always used, node-2.pem and node-2-key.pem after.
func NodeFileNames(i int) (cert, key string) {
	if i <= 1 {
		return NodeCertFile, NodeKeyFile
	}
	n := "node-" + strconv.Itoa(i)
	return n + ".pem", n + "-key.pem"
}

// NodeCN is node i's common name: opensearch for the first, then
// opensearch-2 and so on.
func NodeCN(i int) string {
	if i <= 1 {
		return NodeName
	}
	return NodeName + "-" + strconv.Itoa(i)
}

// NodesDN returns the distinguished names for plugins.security.nodes_dn,
// one per node common name.
func NodesDN(names ...string) []string {
	out := make([]string, 0, len(names))
	for _, n := range names {
		out = append(out, DN(n))
	}
	return out
}

// NamesOf returns the host names and IP addresses a certificate covers,
// so a renewed node certificate keeps the names added before.
func NamesOf(p *Pair) []string {
	if p == nil || p.Cert == nil {
		return nil
	}
	out := append([]string(nil), p.Cert.DNSNames...)
	for _, ip := range p.Cert.IPAddresses {
		out = append(out, ip.String())
	}
	return out
}

// ReadPair reads a certificate and, when keyName is not empty, its key
// from dir.
func ReadPair(dir, certName, keyName string) (*Pair, error) {
	b, err := readFile(dir, certName)
	if err != nil {
		return nil, err
	}
	c, err := parseCert(b)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", certName, err)
	}
	p := &Pair{Cert: c}
	if keyName != "" {
		b, err := readFile(dir, keyName)
		if err != nil {
			return nil, err
		}
		if p.Key, err = parseKey(b); err != nil {
			return nil, fmt.Errorf("%s: %w", keyName, err)
		}
	}
	return p, nil
}
