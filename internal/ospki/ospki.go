// Package ospki makes the certificates that secure OpenSearch for
// Signalith, so no demo certificate or well-known password is ever used: a
// certificate authority (CA) of its own, a certificate for the OpenSearch
// node (HTTPS and node-to-node TLS), an admin certificate for OpenSearch's
// security tools, and a client certificate Signalith signs in to
// OpenSearch with. It also holds the OpenSearch security settings that go
// with them, the same ones the Docker quick start uses.
//
// The keys are RSA, which the OpenSearch documentation uses throughout,
// and are written in PKCS#8, the only form OpenSearch reads. The CA's key
// is kept apart from the certificates (root-ca-key.pem, never in a folder
// OpenSearch or Signalith reads), so certificates can be renewed, and more
// nodes and servers added, under the same CA: see ca.go.
package ospki

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"embed"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Names in the certificates. OpenSearch's settings name the node and the
// admin by them, and its role mapping names Signalith's user.
const (
	Org = "Signalith"
	// NodeName is the node's common name in the Docker quick start, which
	// is also the address Signalith reaches it at there.
	NodeName = "opensearch"
	// AdminName is the admin certificate's common name
	// (plugins.security.authcz.admin_dn).
	AdminName = "signalith-admin"
	// ClientName is Signalith's user name in OpenSearch: its client
	// certificate's common name (roles_mapping.yml).
	ClientName = "signalith"
)

// KeyBits is the RSA key size. Tests lower it to save time.
var KeyBits = 3072

// Validity is how long the CA and the certificates last.
const Validity = 10 * 365 * 24 * time.Hour

// Files for OpenSearch (its config folder's certs folder) and for
// Signalith. Keys end in -key.pem.
const (
	RootCAFile     = "root-ca.pem"
	NodeCertFile   = "node.pem"
	NodeKeyFile    = "node-key.pem"
	AdminCertFile  = "admin.pem"
	AdminKeyFile   = "admin-key.pem"
	ClientCAFile   = "opensearch-ca.pem"
	ClientCertFile = "opensearch-client.pem"
	ClientKeyFile  = "opensearch-client-key.pem"
)

// DN returns the distinguished name OpenSearch's settings use for the
// certificate with common name cn, such as CN=signalith,O=Signalith.
func DN(cn string) string { return "CN=" + cn + ",O=" + Org }

// IsKey reports whether a file name from this package holds a private key.
func IsKey(name string) bool { return strings.HasSuffix(name, "-key.pem") }

// Pair is a certificate and its key.
type Pair struct {
	Cert *x509.Certificate
	Key  *rsa.PrivateKey
}

// CertPEM returns the certificate in PEM.
func (p *Pair) CertPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: p.Cert.Raw})
}

// KeyPEM returns the key in PKCS#8 PEM ("BEGIN PRIVATE KEY").
func (p *Pair) KeyPEM() []byte {
	der, err := x509.MarshalPKCS8PrivateKey(p.Key)
	if err != nil {
		panic(err) // an RSA key always marshals
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

// Set is a CA and the certificates it issued.
type Set struct {
	CA, Node, Admin, Client *Pair
}

// Options shape a Set.
type Options struct {
	// Node is the node certificate's common name; default NodeName.
	Node string
	// Names are more host names or IP addresses the node certificate
	// covers, besides Node, localhost and 127.0.0.1.
	Names []string
	// Now is the start of validity; zero uses the current time.
	Now time.Time
}

// New makes a CA and, from it, the node, admin and Signalith client
// certificates.
func New(o Options) (*Set, error) {
	if o.Node == "" {
		o.Node = NodeName
	}
	if o.Now.IsZero() {
		o.Now = time.Now()
	}
	// Bad names fail before the slow part, making keys.
	if _, _, err := nodeNames(o.Node, o.Names); err != nil {
		return nil, err
	}
	ca, err := NewCA(o.Now)
	if err != nil {
		return nil, err
	}
	s := &Set{CA: ca}
	if s.Node, err = IssueNode(ca, o.Node, o.Names, o.Now); err != nil {
		return nil, err
	}
	if s.Admin, err = IssueClient(ca, AdminName, o.Now, Validity); err != nil {
		return nil, err
	}
	if s.Client, err = IssueClient(ca, ClientName, o.Now, Validity); err != nil {
		return nil, err
	}
	return s, nil
}

// OpenSearchFiles returns the files for OpenSearch's certs folder, by
// name.
func (s *Set) OpenSearchFiles() map[string][]byte {
	return map[string][]byte{
		RootCAFile:    s.CA.CertPEM(),
		NodeCertFile:  s.Node.CertPEM(),
		NodeKeyFile:   s.Node.KeyPEM(),
		AdminCertFile: s.Admin.CertPEM(),
		AdminKeyFile:  s.Admin.KeyPEM(),
	}
}

// SignalithFiles returns the files Signalith connects to OpenSearch with,
// by name: opensearch.ca_file, cert_file and key_file.
func (s *Set) SignalithFiles() map[string][]byte {
	return map[string][]byte{
		ClientCAFile:   s.CA.CertPEM(),
		ClientCertFile: s.Client.CertPEM(),
		ClientKeyFile:  s.Client.KeyPEM(),
	}
}

// Check reads a set back from OpenSearch's folder and Signalith's and
// says what is wrong with it, if anything: a file missing or unreadable, a
// certificate not from the CA, not matching its key or with another name,
// or one that expires within margin of now. The error is a *CheckError,
// which tells a problem with the CA from one with a certificate it issued.
func Check(opensearchDir, signalithDir, node string, now time.Time, margin time.Duration) error {
	if node == "" {
		node = NodeName
	}
	caPEM, err := readFile(opensearchDir, RootCAFile)
	if err != nil {
		return &CheckError{CA: true, File: RootCAFile, Err: err}
	}
	ca, err := ParseCA(caPEM, now, margin)
	if err != nil {
		return &CheckError{CA: true, File: RootCAFile, Err: err}
	}
	if b, err := readFile(signalithDir, ClientCAFile); err != nil {
		return &CheckError{File: ClientCAFile, Err: err}
	} else if !bytes.Equal(bytes.TrimSpace(b), bytes.TrimSpace(caPEM)) {
		return &CheckError{File: ClientCAFile, Err: fmt.Errorf("%s is not the same CA as %s", ClientCAFile, RootCAFile)}
	}
	for _, f := range []struct{ dir, cert, key, cn string }{
		{opensearchDir, NodeCertFile, NodeKeyFile, node},
		{opensearchDir, AdminCertFile, AdminKeyFile, AdminName},
		{signalithDir, ClientCertFile, ClientKeyFile, ClientName},
	} {
		if err := CheckPair(f.dir, f.cert, f.key, f.cn, ca, now, margin); err != nil {
			return err
		}
	}
	return nil
}

// CheckError is what Check and CheckPair find wrong. CA is true when the
// problem is the CA certificate itself (missing, not a CA, expiring),
// which no renewal under that CA can fix; otherwise File names the file
// to make again.
type CheckError struct {
	CA   bool
	File string
	Err  error
}

func (e *CheckError) Error() string { return e.Err.Error() }
func (e *CheckError) Unwrap() error { return e.Err }

// ParseCA parses a CA certificate in PEM and checks that it is a CA that
// lasts beyond margin from now.
func ParseCA(b []byte, now time.Time, margin time.Duration) (*x509.Certificate, error) {
	ca, err := parseCert(b)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", RootCAFile, err)
	}
	if !ca.IsCA {
		return nil, fmt.Errorf("%s is not a CA certificate", RootCAFile)
	}
	if !now.Add(margin).Before(ca.NotAfter) {
		return nil, fmt.Errorf("%s expires on %s", RootCAFile, ca.NotAfter.Format(time.DateOnly))
	}
	return ca, nil
}

// CheckPair checks one certificate in dir and its key: issued by ca, for
// the common name cn, matching its key and lasting beyond margin from now.
// The error is a *CheckError naming the certificate or key file.
func CheckPair(dir, certName, keyName, cn string, ca *x509.Certificate, now time.Time, margin time.Duration) error {
	file, err := checkPair(dir, certName, keyName, cn, ca, now, margin)
	if err != nil {
		return &CheckError{File: file, Err: err}
	}
	return nil
}

func checkPair(dir, certName, keyName, cn string, ca *x509.Certificate, now time.Time, margin time.Duration) (string, error) {
	certPEM, err := readFile(dir, certName)
	if err != nil {
		return certName, err
	}
	c, err := parseCert(certPEM)
	if err != nil {
		return certName, fmt.Errorf("%s: %w", certName, err)
	}
	if err := c.CheckSignatureFrom(ca); err != nil {
		return certName, fmt.Errorf("%s was not issued by %s", certName, RootCAFile)
	}
	if c.Subject.CommonName != cn || len(c.Subject.Organization) != 1 || c.Subject.Organization[0] != Org {
		return certName, fmt.Errorf("%s is for %s, not %s", certName, c.Subject, DN(cn))
	}
	if !now.Add(margin).Before(c.NotAfter) {
		return certName, fmt.Errorf("%s expires on %s", certName, c.NotAfter.Format(time.DateOnly))
	}
	keyPEM, err := readFile(dir, keyName)
	if err != nil {
		return keyName, err
	}
	rk, err := parseKey(keyPEM)
	if err != nil {
		return keyName, fmt.Errorf("%s: %w", keyName, err)
	}
	if !rk.PublicKey.Equal(c.PublicKey) {
		return keyName, fmt.Errorf("%s is not the key of %s", keyName, certName)
	}
	return "", nil
}

// readFile reads one of the set's files, with an error that names it.
func readFile(dir, name string) ([]byte, error) {
	b, err := os.ReadFile(filepath.Join(dir, name))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, missingError(name)
	}
	if err != nil {
		return nil, fmt.Errorf("cannot read %s: %w", name, err)
	}
	return b, nil
}

// parseKey reads an RSA key in PKCS#8 PEM.
func parseKey(b []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(b)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, errors.New("no PKCS#8 key (BEGIN PRIVATE KEY) in it")
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	rk, ok := k.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("not an RSA key")
	}
	return rk, nil
}

// missingError says a file is missing; it is an fs.ErrNotExist.
type missingError string

func (e missingError) Error() string { return string(e) + " is missing" }
func (e missingError) Unwrap() error { return fs.ErrNotExist }

func parseCert(b []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(b)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("no PEM certificate in it")
	}
	return x509.ParseCertificate(block.Bytes)
}

func serial() *big.Int {
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		panic(err)
	}
	return n.Add(n, big.NewInt(1))
}

// validDNSName accepts host names such as opensearch or
// search-1.example.com.
func validDNSName(s string) bool {
	s = strings.TrimSuffix(s, ".")
	if s == "" || len(s) > 253 {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
				return false
			}
		}
	}
	return true
}

// ---- OpenSearch security settings ----

// securityFiles are the OpenSearch security plugin's files that replace
// the image's or package's own in its opensearch-security folder.
// deploy/docker/opensearch/security holds the same files.
//
//go:embed security/*.yml
var securityFiles embed.FS

// SecurityFiles returns the files for OpenSearch's opensearch-security
// folder, by name: config.yml (sign-in with a certificate only),
// internal_users.yml (no users with passwords), roles.yml (what Signalith
// may do) and roles_mapping.yml (Signalith's certificate gets that role).
func SecurityFiles() map[string][]byte {
	out := map[string][]byte{}
	entries, _ := fs.ReadDir(securityFiles, "security")
	for _, e := range entries {
		b, err := securityFiles.ReadFile("security/" + e.Name())
		if err == nil {
			out[e.Name()] = b
		}
	}
	return out
}

// Settings returns the opensearch.yml settings that turn on TLS and
// certificate sign-in with this package's files in the certs folder next
// to opensearch.yml, for the node with common name node.
func Settings(node string) string { return SettingsFor(node, nil) }

// SettingsFor is Settings for a node of a cluster: nodes_dn lists the
// node and every peer, the common names of the other nodes' certificates.
func SettingsFor(node string, peers []string) string {
	if node == "" {
		node = NodeName
	}
	return `# HTTPS on the REST API (9200) and TLS between nodes (9300), with
# certificates from Signalith's own OpenSearch CA, in the certs folder next
# to this file.
plugins.security.ssl.transport.pemcert_filepath: certs/` + NodeCertFile + `
plugins.security.ssl.transport.pemkey_filepath: certs/` + NodeKeyFile + `
plugins.security.ssl.transport.pemtrustedcas_filepath: certs/` + RootCAFile + `
# Nodes are recognized by their certificate's name (nodes_dn below), not
# by their address, which can change.
plugins.security.ssl.transport.enforce_hostname_verification: false
plugins.security.ssl.transport.enabled_protocols: ["TLSv1.3", "TLSv1.2"]
plugins.security.ssl.http.enabled: true
plugins.security.ssl.http.pemcert_filepath: certs/` + NodeCertFile + `
plugins.security.ssl.http.pemkey_filepath: certs/` + NodeKeyFile + `
plugins.security.ssl.http.pemtrustedcas_filepath: certs/` + RootCAFile + `
plugins.security.ssl.http.clientauth_mode: OPTIONAL
plugins.security.ssl.http.enabled_protocols: ["TLSv1.3", "TLSv1.2"]
# The admin certificate may change the security settings (securityadmin.sh).
plugins.security.authcz.admin_dn: ["` + DN(AdminName) + `"]
plugins.security.nodes_dn: ["` + strings.Join(NodesDN(append([]string{node}, peers...)...), `", "`) + `"]
# On first start, load the security settings from the opensearch-security
# folder (config.yml, roles.yml and the others). Existing indices stay.
plugins.security.allow_default_init_securityindex: true
plugins.security.allow_unsafe_democertificates: false
# No audit log in OpenSearch: Signalith is its only user and keeps its own.
# Without this OpenSearch logs an error that its audit log cannot work.
plugins.security.audit.type: noop
`
}
