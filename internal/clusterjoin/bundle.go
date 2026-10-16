package clusterjoin

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// Bundle is what a joining server receives: everything it needs to start
// as a member. It travels only sealed (Seal).
type Bundle struct {
	ClusterID   string `json:"cluster_id"`
	ClusterName string `json:"cluster_name"`
	IndexPrefix string `json:"index_prefix"`
	// OpenSearch is how the new server reaches OpenSearch.
	OpenSearch OpenSearch `json:"opensearch"`
	// KID and ClusterKey are the cluster key that signs now (32 bytes).
	KID        string `json:"kid"`
	ClusterKey []byte `json:"cluster_key"`
	// ClusterCAPEM is the cluster's certificate authority and LeafPEM the
	// new server's certificate from it, for the key of the CSR it sent.
	// Both are empty when the cluster has none (files mode, or below the
	// level of one certificate authority): the server then makes its own.
	ClusterCAPEM string `json:"cluster_ca_pem,omitempty"`
	LeafPEM      string `json:"leaf_pem,omitempty"`
	// PublicURL is the cluster's server.public_url, NodeName the new
	// server's name, and Listen the web address copied from the issuer
	// (the new server's --listen wins).
	PublicURL string `json:"public_url,omitempty"`
	NodeName  string `json:"node_name"`
	Listen    string `json:"listen,omitempty"`
	// AgentListen is the issuer's server.agent_listen as it was set, ""
	// when it was not (the new server's --agent-listen wins).
	AgentListen string `json:"agent_listen,omitempty"`
	// Role is the role the token gives the new server: "" a cluster
	// server, or RoleScanner (cluster.role).
	Role string `json:"role,omitempty"`
	// Syslog is the issuer's syslog listeners, sent only for
	// --copy-syslog; nil leaves syslog off.
	Syslog *SyslogDefaults `json:"syslog,omitempty"`
	// IssuerVersion is the answering server's version, and Level the
	// cluster's level.
	IssuerVersion string `json:"issuer_version"`
	Level         int    `json:"level"`
	// Servers is how many servers the keyring lists with the new one; 0
	// when the answering server did not say.
	Servers int `json:"servers,omitempty"`
}

// OpenSearch is the OpenSearch part of a bundle.
type OpenSearch struct {
	URL  string   `json:"url"`
	URLs []string `json:"urls,omitempty"`
	// CAPEM is the certificate authority of OpenSearch's certificate.
	CAPEM    string `json:"ca_pem,omitempty"`
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	// ClientCertPEM is a client certificate for OpenSearch. With Managed,
	// it was issued for the key of the new server's own CSR, so no key
	// is sent; otherwise ClientKeyPEM is the issuer's key.
	ClientCertPEM string `json:"client_cert_pem,omitempty"`
	ClientKeyPEM  string `json:"client_key_pem,omitempty"`
	// Managed is true when Signalith keeps OpenSearch's certificates and
	// issued the new server its own; Shared when the new server uses the
	// issuer's credential, which removing a server then needs changed.
	Managed bool `json:"managed,omitempty"`
	Shared  bool `json:"shared,omitempty"`
}

// SyslogDefaults are the issuer's syslog listeners.
type SyslogDefaults struct {
	UDP string `json:"udp,omitempty"`
	TCP string `json:"tcp,omitempty"`
	TLS string `json:"tls,omitempty"`
}

// Clear overwrites the cluster key and the private key text the bundle
// can clear. Strings (the password, a key in PEM) cannot be overwritten in
// Go; they are dropped.
func (b *Bundle) Clear() {
	clear(b.ClusterKey)
	b.ClusterKey = nil
	b.OpenSearch.Password, b.OpenSearch.ClientKeyPEM = "", ""
}

// bundleInfo is the HKDF info of a bundle's key.
const bundleInfo = "signalith join bundle v1"

// bundlePrefix starts a sealed bundle.
const bundlePrefix = "j1:"

// maxSealed bounds a sealed bundle Open reads.
const maxSealed = 1 << 20

// ErrBundle is a sealed bundle that cannot be opened: it was not sealed
// to this node key with this token's secret, or it was changed.
var ErrBundle = errors.New("the answer cannot be opened with this server's key and this token: it was meant for another server or token, or it was changed")

// bundleAEAD derives a bundle's AES-256-GCM key from the X25519 shared
// secret and the token's secret, salted with the node id.
func bundleAEAD(shared, secret []byte, nodeID string) (cipher.AEAD, error) {
	ikm := make([]byte, 0, len(shared)+len(secret))
	ikm = append(append(ikm, shared...), secret...)
	defer clear(ikm)
	k, err := hkdf.Key(sha256.New, ikm, []byte(nodeID), bundleInfo, 32)
	if err != nil {
		return nil, err
	}
	defer clear(k)
	block, err := aes.NewCipher(k)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// bundleAD binds a sealed bundle to the token and the node.
func bundleAD(tokenID, nodeID string) []byte { return []byte(tokenID + "|" + nodeID) }

// Seal seals b for the server nodeID whose node public key is nodePub,
// with the secret of token tokenID: an ephemeral X25519 agreement with
// nodePub, HKDF-SHA256 over the shared secret and the token secret (salt
// the node id), then AES-256-GCM bound to the token and node ids. Someone
// who learned the token secret but has no node key cannot open it, nor
// can someone with the node key but not the secret.
func Seal(b *Bundle, nodePub []byte, nodeID, tokenID string, secret []byte) (string, error) {
	if len(secret) != SecretSize {
		return "", errors.New("a join token secret is 32 bytes")
	}
	if nodeID == "" || !ValidID(tokenID) {
		return "", errors.New("a bundle needs the node id and the token id")
	}
	peer, err := ecdh.X25519().NewPublicKey(nodePub)
	if err != nil {
		return "", fmt.Errorf("not a node key: %w", err)
	}
	eph, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	shared, err := eph.ECDH(peer)
	if err != nil {
		return "", err
	}
	defer clear(shared)
	aead, err := bundleAEAD(shared, secret, nodeID)
	if err != nil {
		return "", err
	}
	plain, err := json.Marshal(b)
	if err != nil {
		return "", err
	}
	defer clear(plain)
	out := eph.PublicKey().Bytes()
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	out = append(out, nonce...)
	out = aead.Seal(out, nonce, plain, bundleAD(tokenID, nodeID))
	return bundlePrefix + base64.RawURLEncoding.EncodeToString(out), nil
}

// Agreer runs an X25519 agreement with a node's private key;
// *shared.NodeKey is one.
type Agreer interface {
	Agree(peer []byte) ([]byte, error)
}

// Open opens a bundle Seal sealed to this server, nodeID with node key
// nk, with the secret of token tokenID.
func Open(nk Agreer, nodeID, tokenID string, secret []byte, sealed string) (*Bundle, error) {
	rest, ok := strings.CutPrefix(sealed, bundlePrefix)
	if !ok || len(rest) > maxSealed {
		return nil, ErrBundle
	}
	blob, err := base64.RawURLEncoding.DecodeString(rest)
	if err != nil || len(blob) < 32 {
		return nil, ErrBundle
	}
	shared, err := nk.Agree(blob[:32])
	if err != nil {
		return nil, ErrBundle
	}
	defer clear(shared)
	aead, err := bundleAEAD(shared, secret, nodeID)
	if err != nil {
		return nil, err
	}
	body := blob[32:]
	if len(body) < aead.NonceSize()+aead.Overhead() {
		return nil, ErrBundle
	}
	plain, err := aead.Open(nil, body[:aead.NonceSize()], body[aead.NonceSize():], bundleAD(tokenID, nodeID))
	if err != nil {
		return nil, ErrBundle
	}
	defer clear(plain)
	var b Bundle
	if err := json.Unmarshal(plain, &b); err != nil {
		return nil, ErrBundle
	}
	return &b, nil
}
