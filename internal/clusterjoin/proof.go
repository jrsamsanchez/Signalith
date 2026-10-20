// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package clusterjoin

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
)

// NonceSize is the size of the nonce a joining server picks for its
// proof, and NodePubSize of an X25519 node public key.
const (
	NonceSize   = 32
	NodePubSize = 32
)

// NewNonce makes a proof's nonce.
func NewNonce() ([]byte, error) {
	b := make([]byte, NonceSize)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

// Proof proves that the joining server holds the token's secret without
// sending it: HMAC-SHA256(secret, "join"|id|nonce|nodePub). It is bound to
// the node public key, so a replayed request can only ever get a bundle
// sealed to the server that made it. The id, nonce and key have fixed
// sizes, so the message reads one way only.
func Proof(secret []byte, id string, nonce, nodePub []byte) []byte {
	m := hmac.New(sha256.New, secret)
	m.Write([]byte("join|"))
	m.Write([]byte(id))
	m.Write([]byte("|"))
	m.Write(nonce)
	m.Write([]byte("|"))
	m.Write(nodePub)
	return m.Sum(nil)
}

// CheckProof reports, in constant time, whether proof is the proof for
// secret, id, nonce and nodePub. A nonce or key of the wrong size never
// passes.
func CheckProof(secret []byte, id string, nonce, nodePub, proof []byte) bool {
	if len(secret) != SecretSize || !ValidID(id) || len(nonce) != NonceSize || len(nodePub) != NodePubSize {
		return false
	}
	return hmac.Equal(Proof(secret, id, nonce, nodePub), proof)
}
