// Package clusterpki gives each Signalith server of a cluster its own
// OpenSearch client certificate, CN=signalith-server-<name>, when
// Signalith made OpenSearch's certificates (internal/ospki). The OpenSearch
// certificate authority is handed to the cluster once (bootstrap-docker
// -export-ca-key, or signalith cluster opensearch-ca import) and kept in
// the osca document of the shared settings, its key sealed under the
// cluster key. Every server then issues itself a certificate that lasts
// 90 days and renews it 30 days before it expires (Identity), so a server
// that leaves the cluster, and with it the cluster key, loses its access
// to OpenSearch when its certificate runs out, and no two servers share
// one credential.
//
// Holding the cluster key while an osca document exists is equivalent to
// being able to sign any certificate under OpenSearch's certificate
// authority, the admin certificate included: Issue only ever signs
// signalith-server-<name>, but the key itself is the cluster's to protect.
package clusterpki

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"maps"
	"slices"
	"sync"
	"time"

	"github.com/jrsamsanchez/signalith/internal/clustertls"
	"github.com/jrsamsanchez/signalith/internal/ospki"
	"github.com/jrsamsanchez/signalith/internal/secrets"
	"github.com/jrsamsanchez/signalith/internal/shared"
	"github.com/jrsamsanchez/signalith/internal/store"
	"github.com/jrsamsanchez/signalith/internal/tlsauto"
)

// The osca document.
const (
	DocID  = "osca"
	Kind   = "osca"
	Format = 1
	// MaxIssued caps the servers Body.Issued records; those whose
	// certificate expired longest ago go first.
	MaxIssued = 256
)

// systemUser writes the changes Signalith makes by itself.
const systemUser = "signalith"

// ErrOtherCA: the cluster already keeps another OpenSearch certificate
// authority.
var ErrOtherCA = errors.New("OpenSearch's certificates come from another certificate authority than the one Signalith keeps; " +
	"import the key of the one OpenSearch uses, or make OpenSearch's certificates again from the kept one (bootstrap-docker -new-ca makes a new one for both)")

// Body is the osca document's body.
type Body struct {
	// CACertPEM is OpenSearch's certificate authority, in PEM.
	CACertPEM string `json:"ca_cert_pem"`
	// CAKey is its private key (PKCS #8, PEM), sealed with the cluster
	// key and bound to CASHA256 (keyField), so it cannot be moved under
	// another certificate.
	CAKey string `json:"ca_key"`
	// CASHA256 is the certificate's SHA-256 fingerprint, AB:CD:...
	CASHA256 string `json:"ca_sha256"`
	// ImportedBy is the user who handed it over, ImportedOn the server
	// that imported it, ImportedAt when.
	ImportedBy string    `json:"imported_by"`
	ImportedOn string    `json:"imported_on,omitempty"`
	ImportedAt time.Time `json:"imported_at"`
	// Issued is the last certificate issued to each server, by the name
	// in its common name (Norm).
	Issued       map[string]Issued `json:"issued,omitempty"`
	shared.Extra `json:"-"`
}

// Issued is a certificate issued to a server.
type Issued struct {
	// Serial is its serial number, in hex.
	Serial   string    `json:"serial"`
	NotAfter time.Time `json:"not_after"`
	// NodeID is the server it was issued to: another server may not take
	// the name while it is valid.
	NodeID   string    `json:"node_id"`
	IssuedAt time.Time `json:"issued_at"`
}

// keyField binds the sealed key to the certificate's fingerprint.
func keyField(fp string) string { return "osca.key@" + fp }

// Cert returns the certificate authority of b.
func (b *Body) Cert() (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(b.CACertPEM))
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("the osca document holds no certificate")
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("the osca document's certificate cannot be read: %w", err)
	}
	return c, nil
}

// validate checks a body read or about to be written.
func validate(b *Body) error {
	c, err := b.Cert()
	if err != nil {
		return err
	}
	if !c.IsCA {
		return errors.New("the osca document's certificate is not a certificate authority")
	}
	if !clustertls.SameFingerprint(tlsauto.Fingerprint(c.Raw), b.CASHA256) {
		return errors.New("the osca document's fingerprint does not match its certificate")
	}
	if !secrets.IsSealed(b.CAKey) {
		return errors.New("the osca document's key is not sealed")
	}
	if len(b.Issued) > MaxIssued {
		return fmt.Errorf("the osca document lists %d servers, more than %d", len(b.Issued), MaxIssued)
	}
	return nil
}

// OSCA holds the osca document, made again on each hub the runtime builds
// (Track).
type OSCA struct {
	mu   sync.Mutex
	hub  *shared.Hub
	doc  *shared.Doc[Body]
	subs []func()
}

// New returns the holder; Track makes the document.
func New() *OSCA { return &OSCA{} }

// Track makes the osca document on h.
func (o *OSCA) Track(h *shared.Hub) {
	d := shared.NewDoc[Body](h, DocID, Kind, Format)
	d.Validate = validate
	d.OnChange(func(_, _ *Body) {
		o.mu.Lock()
		subs := slices.Clone(o.subs)
		o.mu.Unlock()
		for _, fn := range subs {
			fn()
		}
	})
	o.mu.Lock()
	o.hub, o.doc = h, d
	o.mu.Unlock()
}

// Reset forgets the subscribers of a start that ended.
func (o *OSCA) Reset() {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.subs = nil
}

// OnChange adds a function called whenever another copy is applied.
func (o *OSCA) OnChange(fn func()) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.subs = append(o.subs, fn)
}

// Doc returns the osca document, nil before Track.
func (o *OSCA) Doc() *shared.Doc[Body] {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.doc
}

func (o *OSCA) parts() (*shared.Hub, *shared.Doc[Body], error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.doc == nil {
		return nil, nil, errors.New("the shared settings are not open")
	}
	return o.hub, o.doc, nil
}

// Get returns the osca document's body, and false when no certificate
// authority was imported.
func (o *OSCA) Get() (*Body, bool) {
	_, d, err := o.parts()
	if err != nil {
		return new(Body), false
	}
	return d.Get()
}

// Import hands OpenSearch's certificate authority certPEM, with its key
// keyPEM, to the cluster, by the user by on the server node. It only
// creates the document: when one exists with the same certificate
// authority that is success too, and with another it returns ErrOtherCA.
// The caller checks first that OpenSearch's connection trusts it
// (Trusted).
func (o *OSCA) Import(ctx context.Context, by, node string, certPEM, keyPEM []byte) error {
	h, d, err := o.parts()
	if err != nil {
		return err
	}
	ca, err := ospki.PairFromPEM(certPEM, keyPEM)
	if err != nil {
		return err
	}
	fp := tlsauto.Fingerprint(ca.Cert.Raw)
	if cur, ok := d.Get(); ok {
		if clustertls.SameFingerprint(cur.CASHA256, fp) {
			return nil
		}
		return ErrOtherCA
	}
	k := h.Keys().Active()
	if k == nil {
		return errors.New("this server has no cluster key")
	}
	sealed, err := k.SecretsKey().Seal(keyField(fp), string(ca.KeyPEM()))
	if err != nil {
		return err
	}
	b := &Body{CACertPEM: string(ca.CertPEM()), CAKey: sealed, CASHA256: fp,
		ImportedBy: by, ImportedOn: node, ImportedAt: time.Now().UTC()}
	_, err = d.Create(ctx, by, b)
	if errors.Is(err, store.ErrExists) {
		if err := d.Load(ctx); err != nil {
			return err
		}
		cur, ok := d.Get()
		if ok && clustertls.SameFingerprint(cur.CASHA256, fp) {
			return nil
		}
		return ErrOtherCA
	}
	return err
}

// Replace puts OpenSearch's certificate authority certPEM, with its key
// keyPEM, in place of the one the cluster keeps, by the user by on the
// server node, after OpenSearch's certificates were made again under a
// new one (bootstrap-docker -new-ca). The certificates issued under the
// old one are forgotten, so each server gets a new one. The caller checks
// first that OpenSearch's connection trusts the new one and no longer the
// old one.
func (o *OSCA) Replace(ctx context.Context, by, node string, certPEM, keyPEM []byte) error {
	h, d, err := o.parts()
	if err != nil {
		return err
	}
	ca, err := ospki.PairFromPEM(certPEM, keyPEM)
	if err != nil {
		return err
	}
	fp := tlsauto.Fingerprint(ca.Cert.Raw)
	k := h.Keys().Active()
	if k == nil {
		return errors.New("this server has no cluster key")
	}
	sealed, err := k.SecretsKey().Seal(keyField(fp), string(ca.KeyPEM()))
	if err != nil {
		return err
	}
	_, err = d.Mutate(ctx, by, func(b *Body) error {
		if clustertls.SameFingerprint(b.CASHA256, fp) {
			return errUnchanged
		}
		b.CACertPEM, b.CAKey, b.CASHA256 = string(ca.CertPEM()), sealed, fp
		b.ImportedBy, b.ImportedOn, b.ImportedAt = by, node, time.Now().UTC()
		b.Issued = nil
		return nil
	})
	if errors.Is(err, errUnchanged) {
		return nil
	}
	return err
}

// errUnchanged stops a Mutate that has nothing to write.
var errUnchanged = errors.New("unchanged")

// open returns the certificate authority of b with its key, opened with
// the cluster's keys. It is opened each time and never kept.
func (o *OSCA) open(b *Body) (*ospki.Pair, error) {
	o.mu.Lock()
	h := o.hub
	o.mu.Unlock()
	if h == nil {
		return nil, errors.New("the shared settings are not open")
	}
	c, err := b.Cert()
	if err != nil {
		return nil, err
	}
	if !clustertls.SameFingerprint(tlsauto.Fingerprint(c.Raw), b.CASHA256) {
		return nil, errors.New("the osca document's fingerprint does not match its certificate")
	}
	plain, err := opener(h.Keys()).Open(keyField(b.CASHA256), b.CAKey)
	if err != nil {
		return nil, fmt.Errorf("OpenSearch's certificate authority key cannot be opened with this server's cluster key: %w", err)
	}
	return ospki.PairFromPEM([]byte(b.CACertPEM), []byte(plain))
}

// Opens reports whether this server can open the certificate authority's
// key now, and why not.
func (o *OSCA) Opens() error {
	b, ok := o.Get()
	if !ok {
		return errors.New("the cluster keeps no OpenSearch certificate authority")
	}
	_, err := o.open(b)
	return err
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

// pruneIssued drops the entries over MaxIssued whose certificates
// expired longest ago.
func pruneIssued(m map[string]Issued) {
	if len(m) <= MaxIssued {
		return
	}
	names := slices.Collect(maps.Keys(m))
	slices.SortFunc(names, func(a, b string) int { return m[a].NotAfter.Compare(m[b].NotAfter) })
	for _, n := range names[:len(m)-MaxIssued] {
		delete(m, n)
	}
}
