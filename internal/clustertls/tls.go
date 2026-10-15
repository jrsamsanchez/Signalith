// Package clustertls keeps one certificate authority for the whole
// cluster: the tls document of the shared settings holds its certificate,
// its key sealed under the cluster key, and the names every server's
// certificate covers. Each server issues and renews its own certificate
// from it (internal/tlsauto, through Store), so an agent set up against
// one server trusts every other, and no server has to be up for the
// others to renew.
//
// A cluster of one publishes its own certificate authority (Importer), so
// nothing changes for its agents. Servers that were set up separately
// each have their own: nothing is published until an admin chooses which
// to keep (Candidates), and the server that holds it publishes it
// (RequestPublish).
package clustertls

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/jrsamsanchez/signalith/internal/secrets"
	"github.com/jrsamsanchez/signalith/internal/shared"
	"github.com/jrsamsanchez/signalith/internal/store"
	"github.com/jrsamsanchez/signalith/internal/tlsauto"
)

// The tls document.
const (
	DocID  = "tls"
	Kind   = "tls"
	Format = 1
	// MaxNames caps the names kept for every server's certificate; the
	// oldest go first, as on a server of its own.
	MaxNames = 32
)

// systemUser writes the changes Signalith makes by itself.
const systemUser = "signalith"

// ErrOtherCA: the cluster already has another certificate authority.
var ErrOtherCA = errors.New("the cluster already has another certificate authority")

// Body is the tls document's body.
type Body struct {
	// CACertPEM is the certificate authority, in PEM.
	CACertPEM string `json:"ca_cert_pem"`
	// CAKey is its private key (PKCS #8, PEM), sealed with the cluster
	// key and bound to CASHA256 (see keyField), so it cannot be moved
	// under another certificate.
	CAKey string `json:"ca_key"`
	// CASHA256 is the certificate's SHA-256 fingerprint, AB:CD:...
	CASHA256 string `json:"ca_sha256"`
	// Names are the names EnsureName added on any server (the addresses
	// agents were set up with), oldest first: every server's certificate
	// covers them.
	Names []string `json:"names"`
	// Retired are certificate authorities servers of the cluster used
	// before they took this one (AddRetired), oldest first: agents whose
	// configuration trusts only those need a new one. A later version
	// that changes the cluster's adds the one it replaces.
	Retired []RetiredCA `json:"retired,omitempty"`
	// PublishedBy is the server that published the certificate authority,
	// PublishedAt when.
	PublishedBy  string    `json:"published_by"`
	PublishedAt  time.Time `json:"published_at"`
	shared.Extra `json:"-"`
}

// RetiredCA is a certificate authority the cluster no longer uses.
type RetiredCA struct {
	CACertPEM string    `json:"ca_cert_pem"`
	RetiredAt time.Time `json:"retired_at"`
	// Server is the server that used it, "" for the cluster's own.
	Server string `json:"server,omitempty"`
}

// keyField binds the sealed key to the certificate's fingerprint.
func keyField(fp string) string { return "tls.ca_key@" + fp }

// Cert returns the certificate authority of b.
func (b *Body) Cert() (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(b.CACertPEM))
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("the tls document holds no certificate")
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("the tls document's certificate cannot be read: %w", err)
	}
	return c, nil
}

// validate checks a body read or about to be written: a certificate
// authority whose fingerprint is CASHA256, with a sealed key.
func validate(b *Body) error {
	c, err := b.Cert()
	if err != nil {
		return err
	}
	if !c.IsCA {
		return errors.New("the tls document's certificate is not a certificate authority")
	}
	if !SameFingerprint(tlsauto.Fingerprint(c.Raw), b.CASHA256) {
		return errors.New("the tls document's fingerprint does not match its certificate")
	}
	if !secrets.IsSealed(b.CAKey) {
		return errors.New("the tls document's key is not sealed")
	}
	if len(b.Names) > MaxNames {
		return fmt.Errorf("the tls document has %d names, more than %d", len(b.Names), MaxNames)
	}
	return nil
}

// SameFingerprint compares two SHA-256 fingerprints written with or
// without colons, in either case.
func SameFingerprint(a, b string) bool {
	n := func(s string) string { return strings.ToLower(strings.NewReplacer(":", "", " ", "").Replace(s)) }
	return a != "" && n(a) == n(b)
}

// TLS holds the tls document, made again on each hub the runtime builds
// (Track), and passes its changes to whoever uses them now.
type TLS struct {
	mu   sync.Mutex
	hub  *shared.Hub
	doc  *shared.Doc[Body]
	subs []func(old, new *Body)
}

// New returns the holder; Track makes the document.
func New() *TLS { return &TLS{} }

// Track makes the tls document on h.
func (t *TLS) Track(h *shared.Hub) {
	d := shared.NewDoc[Body](h, DocID, Kind, Format)
	d.Validate = validate
	d.OnChange(func(old, nw *Body) {
		t.mu.Lock()
		subs := slices.Clone(t.subs)
		t.mu.Unlock()
		for _, fn := range subs {
			fn(old, nw)
		}
	})
	t.mu.Lock()
	t.hub, t.doc = h, d
	t.mu.Unlock()
}

// Reset forgets the subscribers of a start that ended.
func (t *TLS) Reset() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.subs = nil
}

// OnChange adds a function called with the old and new body whenever
// another copy is applied; old is nil the first time.
func (t *TLS) OnChange(fn func(old, new *Body)) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.subs = append(t.subs, fn)
}

// Doc returns the tls document, nil before Track.
func (t *TLS) Doc() *shared.Doc[Body] {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.doc
}

func (t *TLS) parts() (*shared.Hub, *shared.Doc[Body], error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.doc == nil {
		return nil, nil, errors.New("the shared settings are not open")
	}
	return t.hub, t.doc, nil
}

// Get returns the tls document's body, and false when no certificate
// authority was published yet.
func (t *TLS) Get() (*Body, bool) {
	_, d, err := t.parts()
	if err != nil {
		return new(Body), false
	}
	return d.Get()
}

// Publish makes the certificate authority certPEM, with key, the
// cluster's, with names as its first names, written by the user by on
// the server node. It only creates the document: when one exists with
// the same certificate authority that is success too (two servers of a
// cluster of one may race), and with another it returns ErrOtherCA.
func (t *TLS) Publish(ctx context.Context, by, node string, certPEM []byte, key crypto.Signer, names []string) error {
	h, d, err := t.parts()
	if err != nil {
		return err
	}
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return errors.New("no PEM certificate to publish")
	}
	ca, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return err
	}
	if !ca.IsCA || key == nil || !samePublicKey(ca.PublicKey, key.Public()) {
		return errors.New("the certificate authority and its key do not belong together")
	}
	fp := tlsauto.Fingerprint(ca.Raw)
	keyPEM, err := marshalKey(key)
	if err != nil {
		return err
	}
	k := h.Keys().Active()
	if k == nil {
		return errors.New("this server has no cluster key")
	}
	sealed, err := k.SecretsKey().Seal(keyField(fp), keyPEM)
	if err != nil {
		return err
	}
	b := &Body{CACertPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw})), CAKey: sealed, CASHA256: fp,
		Names: capNames(cleanNames(ca, names)), PublishedBy: node, PublishedAt: time.Now().UTC()}
	_, err = d.Create(ctx, by, b)
	if errors.Is(err, store.ErrExists) {
		if err := d.Load(ctx); err != nil {
			return err
		}
		cur, ok := d.Get()
		if ok && SameFingerprint(cur.CASHA256, fp) {
			return nil
		}
		return ErrOtherCA
	}
	return err
}

// cleanNames keeps the names ca may sign, normalised, once each.
func cleanNames(ca *x509.Certificate, names []string) []string {
	var out []string
	for _, n := range names {
		if n, err := tlsauto.CheckName(ca, n); err == nil && !slices.Contains(out, n) {
			out = append(out, n)
		}
	}
	return out
}

func capNames(names []string) []string {
	if len(names) > MaxNames {
		names = names[len(names)-MaxNames:]
	}
	return names
}

// open returns the certificate authority of b and its key, opened with
// the cluster's keys.
func (t *TLS) open(b *Body) (*x509.Certificate, crypto.Signer, error) {
	ca, err := b.Cert()
	if err != nil {
		return nil, nil, err
	}
	fp := tlsauto.Fingerprint(ca.Raw)
	if !SameFingerprint(fp, b.CASHA256) {
		return nil, nil, errors.New("the tls document's fingerprint does not match its certificate")
	}
	// Opened each time, from the copy held now, and never kept here: the
	// HTTPS certificate's Manager is the one place the key stays.
	t.mu.Lock()
	h := t.hub
	t.mu.Unlock()
	if h == nil {
		return nil, nil, errors.New("the shared settings are not open")
	}
	// The field names the fingerprint the document says, so a key sealed
	// for another certificate does not open.
	plain, err := opener(h.Keys()).Open(keyField(b.CASHA256), b.CAKey)
	if err != nil {
		return nil, nil, fmt.Errorf("the cluster's certificate authority key cannot be opened: %w", err)
	}
	key, err := parseKey([]byte(plain))
	if err != nil {
		return nil, nil, err
	}
	if !samePublicKey(ca.PublicKey, key.Public()) {
		return nil, nil, errors.New("the cluster's certificate authority key does not belong to its certificate")
	}
	return ca, key, nil
}

// opener opens a value sealed with any of the cluster's keys.
func opener(keys *shared.KeySet) secrets.Opener {
	var out []secrets.Opener
	if keys != nil {
		for _, id := range keys.IDs() {
			if k := keys.Get(id); k != nil {
				out = append(out, k.SecretsKey())
			}
		}
	}
	return secrets.Chain(out...)
}

func marshalKey(key crypto.Signer) (string, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", err
	}
	defer clear(der)
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})), nil
}

func parseKey(b []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, errors.New("the cluster's certificate authority key is not PEM")
	}
	defer clear(block.Bytes)
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	s, ok := k.(crypto.Signer)
	if !ok {
		return nil, errors.New("the cluster's certificate authority key cannot sign")
	}
	return s, nil
}

func samePublicKey(a, b crypto.PublicKey) bool {
	ka, ok := a.(interface{ Equal(crypto.PublicKey) bool })
	return ok && ka.Equal(b)
}

// Store returns the cluster's certificate authority as a tlsauto store.
func (t *TLS) Store() tlsauto.CAStore { return caStore{t} }

type caStore struct{ t *TLS }

func (caStore) Kind() string { return tlsauto.KindCluster }

// Load returns the cluster's certificate authority, nil, nil, nil when
// none was published.
func (s caStore) Load() (*x509.Certificate, crypto.Signer, error) {
	b, ok := s.t.Get()
	if !ok {
		return nil, nil, nil
	}
	return s.t.open(b)
}

func (caStore) Make(*x509.Certificate) error {
	return errors.New("a server never makes the cluster's certificate authority")
}

// Names lists the names every server's certificate covers.
func (s caStore) Names() []string {
	b, _ := s.t.Get()
	return slices.Clone(b.Names)
}

// AddName adds name to the cluster's names, or moves it, last, unless the certificate
// authority may not sign it (refused in the words a server of its own
// uses). The oldest names go past MaxNames.
func (s caStore) AddName(ctx context.Context, name string) error {
	_, d, err := s.t.parts()
	if err != nil {
		return err
	}
	_, err = d.Mutate(ctx, systemUser, func(b *Body) error {
		if b.CACertPEM == "" {
			return errors.New("the cluster has no certificate authority yet")
		}
		ca, err := b.Cert()
		if err != nil {
			return err
		}
		n, err := tlsauto.CheckName(ca, name)
		if err != nil {
			return err
		}
		// Last, as the newest: the oldest go first.
		if len(b.Names) > 0 && b.Names[len(b.Names)-1] == n {
			return errUnchanged
		}
		b.Names = slices.DeleteFunc(b.Names, func(o string) bool { return o == n })
		b.Names = capNames(append(b.Names, n))
		return nil
	})
	if errors.Is(err, errUnchanged) {
		return nil
	}
	return err
}

// errUnchanged stops a Mutate that has nothing to write.
var errUnchanged = errors.New("unchanged")

// MaxRetired caps the certificate authorities Body.Retired keeps; the
// oldest go first.
const MaxRetired = 64

// AddRetired records ca, the certificate authority the server named
// server used before it took the cluster's, among Body.Retired, once. The
// cluster's own is never added.
func (t *TLS) AddRetired(ctx context.Context, server string, ca *x509.Certificate) error {
	_, d, err := t.parts()
	if err != nil {
		return err
	}
	if ca == nil {
		return nil
	}
	fp := tlsauto.Fingerprint(ca.Raw)
	_, err = d.Mutate(ctx, systemUser, func(b *Body) error {
		if SameFingerprint(b.CASHA256, fp) {
			return errUnchanged
		}
		for _, r := range b.Retired {
			if c := parsePEM(r.CACertPEM); c != nil && SameFingerprint(tlsauto.Fingerprint(c.Raw), fp) {
				return errUnchanged
			}
		}
		b.Retired = append(b.Retired, RetiredCA{CACertPEM: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw})),
			RetiredAt: time.Now().UTC(), Server: server})
		if len(b.Retired) > MaxRetired {
			b.Retired = b.Retired[len(b.Retired)-MaxRetired:]
		}
		return nil
	})
	if errors.Is(err, errUnchanged) {
		return nil
	}
	return err
}

// RetiredFingerprints lists the fingerprints of the certificate
// authorities in b.Retired.
func (b *Body) RetiredFingerprints() []string {
	var out []string
	for _, r := range b.Retired {
		if c := parsePEM(r.CACertPEM); c != nil {
			out = append(out, tlsauto.Fingerprint(c.Raw))
		}
	}
	return out
}
