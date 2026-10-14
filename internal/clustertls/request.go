package clustertls

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"

	"github.com/jrsamsanchez/signalith/internal/shared"
	"github.com/jrsamsanchez/signalith/internal/tlsauto"
)

// RequestPublish asks the server that holds the certificate authority an
// admin chose to publish it as the cluster's.
const RequestPublish = "tls_publish"

// PublishArgs are the arguments of a tls_publish request.
type PublishArgs struct {
	// CASHA256 is the fingerprint of the certificate authority chosen.
	CASHA256 string `json:"ca_sha256"`
}

// PublishResult is what a tls_publish request did.
type PublishResult struct {
	CASHA256 string `json:"ca_sha256"`
	// Already is true when the cluster had that one already.
	Already bool `json:"already,omitempty"`
}

// Handler runs tls_publish requests on the server they name: it checks
// that its own certificate authority is still the one chosen, then
// publishes it.
func Handler(t *TLS, local LocalCA, node string, log *slog.Logger) shared.Handler {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return func(ctx context.Context, req *shared.Request) error {
		var a PublishArgs
		if err := json.Unmarshal(req.Args, &a); err != nil || a.CASHA256 == "" {
			return errors.New("the request names no certificate authority")
		}
		if b, ok := t.Get(); ok {
			if SameFingerprint(b.CASHA256, a.CASHA256) {
				_ = req.SetResult(PublishResult{CASHA256: b.CASHA256, Already: true})
				return nil
			}
			return ErrOtherCA
		}
		ca, key, names := local()
		if ca == nil || key == nil {
			return errors.New("this server no longer has a certificate authority of its own to publish")
		}
		fp := tlsauto.Fingerprint(ca.Raw)
		if !SameFingerprint(fp, a.CASHA256) {
			return fmt.Errorf("this server's certificate authority changed since it was chosen (it is now %s); choose again", fp)
		}
		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw})
		if err := t.Publish(ctx, req.RequestedBy, node, certPEM, key, names); err != nil {
			return err
		}
		_ = req.SetResult(PublishResult{CASHA256: fp})
		log.Info("published this server's certificate authority as the cluster's, as an admin chose", "audit", true,
			"by", req.RequestedBy, "request", req.ID, "ca_sha256", fp)
		return nil
	}
}
