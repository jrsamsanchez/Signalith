package clustertls

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/jrsamsanchez/signalith/internal/shared"
	"github.com/jrsamsanchez/signalith/internal/tlsauto"
)

// LocalCA returns this server's own certificate authority, its key and
// the names it added (tlsauto.Manager.LocalPair), or nil when it has none
// to publish.
type LocalCA func() (*x509.Certificate, crypto.Signer, []string)

// ImporterOptions are what the tls importer needs.
type ImporterOptions struct {
	TLS *TLS
	// Local is the founder's own certificate authority.
	Local LocalCA
	// Servers lists the servers as their heartbeats say, for the
	// certificate authorities they use; an error when they cannot be read,
	// and then nothing is published.
	Servers func(context.Context) ([]Server, error)
	// Node is this server's name, for PublishedBy.
	Node string
	Log  *slog.Logger
	// Now is the clock; nil is time.Now.
	Now func() time.Time
}

// Importer publishes the founder's certificate authority as the
// cluster's, once the cluster reaches shared.LevelSharedTLS, when every
// server seen in the last day uses that one (or none of its own). With
// several, it publishes nothing and leaves the choice to an admin. It is
// recorded as done either way: an error stops the importers after it, so
// it never returns one just to wait. When the heartbeats cannot be read
// it cannot tell, so it publishes nothing and returns the error, and the
// import is tried again.
func Importer(o ImporterOptions) shared.Importer {
	log := o.Log
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	now := func() time.Time {
		if o.Now != nil {
			return o.Now()
		}
		return time.Now()
	}
	return shared.Importer{
		Name:     shared.ImportTLS,
		MinLevel: shared.LevelSharedTLS,
		Source: func() (string, error) {
			if o.Local == nil {
				return "", nil
			}
			ca, key, _ := o.Local()
			if ca == nil || key == nil {
				return "", nil
			}
			return tlsauto.Fingerprint(ca.Raw), nil
		},
		Run: func(ctx context.Context, by string) error {
			if _, ok := o.TLS.Get(); ok {
				return nil
			}
			ca, key, names := o.Local()
			if ca == nil || key == nil {
				return nil
			}
			fp := tlsauto.Fingerprint(ca.Raw)
			if o.Servers == nil {
				return errors.New("the servers' certificate authorities cannot be read")
			}
			servers, err := o.Servers(ctx)
			if err != nil {
				return fmt.Errorf("the servers' heartbeats cannot be read, so it is not known whether they use the same certificate authority: %w", err)
			}
			for _, root := range Roots(servers, now()) {
				if root != fp {
					log.Info("servers of the cluster use different certificate authorities, so an admin chooses which one to keep on the Servers page",
						"ca_sha256", fp, "other_sha256", root)
					return nil
				}
			}
			certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw})
			err = o.TLS.Publish(ctx, by, o.Node, certPEM, key, names)
			if errors.Is(err, ErrOtherCA) {
				return nil
			}
			if err != nil {
				return err
			}
			log.Info("published this server's certificate authority as the cluster's", "audit", true, "by", by, "ca_sha256", fp)
			return nil
		},
	}
}
