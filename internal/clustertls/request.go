package clustertls

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"time"

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
	// Target is the node id of the server asked, By the admin who chose,
	// At when, and Nonce makes each choice unique.
	Target string    `json:"target"`
	By     string    `json:"by"`
	At     time.Time `json:"at"`
	Nonce  string    `json:"nonce"`
	// KeyID names the cluster key MAC was made with. Requests are not
	// signed documents, so the arguments carry their own MAC: only a
	// server with the cluster key (where an admin chose, on the Servers
	// page or with signalith cluster tls choose) can ask for a publish.
	KeyID string `json:"kid"`
	MAC   string `json:"mac"`
}

// publishMaxAge is how long a signed choice may wait to be run, and
// publishSkew how far ahead of this server's clock it may be dated.
const (
	publishMaxAge = time.Hour
	publishSkew   = 5 * time.Minute
)

// mac signs a's fields other than MAC with a key of its own, derived
// from the cluster key's MAC key.
func (a PublishArgs) mac(k *shared.ClusterKey) string {
	sub := hmac.New(sha256.New, k.MACKey())
	sub.Write([]byte("signalith tls_publish 1"))
	m := hmac.New(sha256.New, sub.Sum(nil))
	a.MAC = ""
	b, _ := json.Marshal(a)
	m.Write(b)
	return hex.EncodeToString(m.Sum(nil))
}

// SubmitPublish asks the server node to publish its certificate
// authority, whose fingerprint is fp, as the cluster's, as the admin by
// chose: a tls_publish request signed with the cluster key.
func (t *TLS) SubmitPublish(ctx context.Context, reqs *shared.Requests, node, fp, by string) (*shared.Request, error) {
	a, err := t.publishArgs(node, fp, by, time.Now())
	if err != nil {
		return nil, err
	}
	return reqs.Submit(ctx, RequestPublish, node, a, by)
}

// publishArgs are the signed arguments of a tls_publish request.
func (t *TLS) publishArgs(node, fp, by string, now time.Time) (PublishArgs, error) {
	h, _, err := t.parts()
	if err != nil {
		return PublishArgs{}, err
	}
	k := h.Keys().Active()
	if k == nil {
		return PublishArgs{}, errors.New("this server has no cluster key")
	}
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return PublishArgs{}, err
	}
	a := PublishArgs{CASHA256: fp, Target: node, By: by, At: now.UTC(), Nonce: hex.EncodeToString(nonce), KeyID: k.ID()}
	a.MAC = a.mac(k)
	return a, nil
}

// verify checks that a was signed with a cluster key for req, lately.
func (a PublishArgs) verify(keys *shared.KeySet, req *shared.Request, now time.Time) error {
	if a.MAC == "" {
		return errors.New("the request is not signed with the cluster key, so it is not run")
	}
	var k *shared.ClusterKey
	if keys != nil {
		k = keys.Get(a.KeyID)
	}
	if k == nil {
		return errors.New("the request is signed with a cluster key this server does not have, so it is not run")
	}
	if !hmac.Equal([]byte(a.mac(k)), []byte(a.MAC)) {
		return errors.New("the request's signature does not match, so it is not run")
	}
	if a.Target != req.Target || a.By != req.RequestedBy {
		return errors.New("the request was signed for another server or user, so it is not run")
	}
	if now.Sub(a.At) > publishMaxAge || a.At.Sub(now) > publishSkew {
		return errors.New("the choice is too old to run; choose again")
	}
	return nil
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
		h, _, err := t.parts()
		if err != nil {
			return err
		}
		if err := a.verify(h.Keys(), req, time.Now()); err != nil {
			log.Warn("refused a request to publish this server's certificate authority", "audit", true,
				"request", req.ID, "requested_by_unverified", req.RequestedBy, "err", err)
			return err
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
