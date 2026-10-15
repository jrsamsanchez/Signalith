package clusterpki

import (
	"context"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jrsamsanchez/signalith/internal/ospki"
)

const (
	// Validity is how long a server's own certificate lasts.
	Validity = 90 * 24 * time.Hour
	// RenewBefore is how long before it expires a server renews it.
	RenewBefore = 30 * 24 * time.Hour
)

// ErrNoCA: the cluster keeps no OpenSearch certificate authority.
var ErrNoCA = errors.New("the cluster keeps no OpenSearch certificate authority")

// ErrNameTaken: another server holds a valid certificate for the name.
var ErrNameTaken = errors.New("another server has a valid OpenSearch certificate for this name")

// maxName is the longest name a common name has room for.
const maxName = 63 - len(ospki.ServerClientPrefix)

// Norm turns a server's name (config.ValidNodeName: letters of both
// cases, digits, . - _) into the lower-case label its certificate's common
// name uses: . and _ become -, and it is cut to fit. Two names that norm
// alike share a common name, so Issue gives it to one server at a time.
func Norm(name string) string {
	n := strings.Map(func(r rune) rune {
		switch {
		case r >= 'A' && r <= 'Z':
			return r + 'a' - 'A'
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-':
			return r
		case r == '.' || r == '_':
			return '-'
		}
		return -1
	}, name)
	n = strings.Trim(n, "-")
	if len(n) > maxName {
		n = strings.TrimRight(n[:maxName], "-")
	}
	return n
}

// ClientName is the common name of the server name's own certificate:
// signalith-server-<Norm(name)>.
func ClientName(name string) (string, error) {
	n := Norm(name)
	cn, err := ospki.ServerClientName(n)
	if err != nil {
		return "", fmt.Errorf("server name %q cannot name an OpenSearch certificate: %w", name, err)
	}
	// Never the shared certificate's or the admin's name, whatever the
	// prefix becomes.
	if cn == ospki.ClientName || cn == ospki.AdminName {
		return "", fmt.Errorf("%s is reserved", cn)
	}
	return cn, nil
}

// Issue signs a certificate for the server name, whose node id is
// nodeID, with the key of the certificate request csrPEM (the key never
// leaves the server that uses it): CN=signalith-server-<Norm(name)>, for
// client authentication only, lasting Validity. It records it in the
// osca document, and refuses a name another server holds a valid
// certificate for (ErrNameTaken).
func (o *OSCA) Issue(ctx context.Context, name, nodeID string, csrPEM []byte, now time.Time) (certPEM []byte, notAfter time.Time, err error) {
	_, d, err := o.parts()
	if err != nil {
		return nil, time.Time{}, err
	}
	if nodeID == "" {
		return nil, time.Time{}, errors.New("a server's certificate needs its node id")
	}
	b, ok := d.Get()
	if !ok {
		return nil, time.Time{}, ErrNoCA
	}
	if now.IsZero() {
		now = time.Now()
	}
	cn, err := ClientName(name)
	if err != nil {
		return nil, time.Time{}, err
	}
	key := Norm(name)
	if taken(b, key, nodeID, now) {
		return nil, time.Time{}, ErrNameTaken
	}
	ca, err := o.open(b)
	if err != nil {
		return nil, time.Time{}, err
	}
	cert, err := ospki.SignClientRequest(ca, cn, csrPEM, now, Validity)
	if err != nil {
		return nil, time.Time{}, err
	}
	_, err = d.Mutate(ctx, systemUser, func(b *Body) error {
		if !clusterSame(b, ca.Cert.Raw) {
			return errors.New("OpenSearch's certificate authority changed meanwhile")
		}
		if taken(b, key, nodeID, now) {
			return ErrNameTaken
		}
		if b.Issued == nil {
			b.Issued = map[string]Issued{}
		}
		b.Issued[key] = Issued{Serial: cert.SerialNumber.Text(16), NotAfter: cert.NotAfter.UTC(), NodeID: nodeID, IssuedAt: now.UTC()}
		pruneIssued(b.Issued)
		return nil
	})
	if err != nil {
		return nil, time.Time{}, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}), cert.NotAfter, nil
}

// taken reports whether another server than nodeID holds a valid
// certificate for the normed name key.
func taken(b *Body, key, nodeID string, now time.Time) bool {
	cur, ok := b.Issued[key]
	return ok && cur.NodeID != nodeID && now.Before(cur.NotAfter)
}

// clusterSame reports whether b still holds the certificate authority
// whose certificate is raw.
func clusterSame(b *Body, raw []byte) bool {
	c, err := b.Cert()
	return err == nil && string(c.Raw) == string(raw)
}
