package clusterpki

import (
	"context"
	"errors"
	"time"
)

// Credential is the OpenSearch credential a server joining the cluster
// gets from the server that answers it.
type Credential struct {
	// ClientCertPEM is its own certificate, issued from its certificate
	// request, and CAPEM OpenSearch's certificate authority.
	ClientCertPEM, CAPEM []byte
	// Managed is true: the cluster renews it (it goes in
	// config.ManagedOpenSearchFiles on the joining server).
	Managed bool
}

// ErrShared: the cluster keeps no OpenSearch certificate authority, so a
// joining server gets the answering server's own credential and shares
// it, as before.
var ErrShared = errors.New("the cluster keeps no OpenSearch certificate authority, so servers share one OpenSearch credential")

// JoinCredential issues the server joining as name, with node id nodeID,
// its own certificate from the key of csrPEM, which it made and keeps.
// Without an osca document it returns ErrShared, and the joining server
// gets the answering server's credential instead.
func (o *OSCA) JoinCredential(ctx context.Context, name, nodeID string, csrPEM []byte) (Credential, error) {
	b, ok := o.Get()
	if !ok {
		return Credential{}, ErrShared
	}
	cert, _, err := o.Issue(ctx, name, nodeID, csrPEM, time.Now())
	if err != nil {
		return Credential{}, err
	}
	return Credential{ClientCertPEM: cert, CAPEM: []byte(b.CACertPEM), Managed: true}, nil
}
