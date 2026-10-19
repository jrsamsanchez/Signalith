// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package shared

import (
	"crypto/ecdh"
	"fmt"
)

// How a server became a member, in KeyringMember.AddedBy, for the ways
// of joining that need no key file: an admin approved its fingerprint on
// the Servers page, or it joined with a one-use token (signalith join).
const (
	AddedByApproval = "approval"
	AddedByJoin     = "join"
)

// Agree runs an X25519 agreement of this server's node key with the
// public key peer, for a value sealed to it with more than the node key
// alone (a join bundle, which mixes in the join token's secret). The
// caller clears the result.
func (n *NodeKey) Agree(peer []byte) ([]byte, error) {
	p, err := ecdh.X25519().NewPublicKey(peer)
	if err != nil {
		return nil, fmt.Errorf("not an X25519 public key: %w", err)
	}
	return n.priv.ECDH(p)
}
