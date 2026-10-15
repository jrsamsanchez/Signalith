package clusterjoin

import (
	"encoding/base64"
	"errors"
	"strings"

	"github.com/jrsamsanchez/signalith/internal/config"
)

// Refused is the one text every refused join gets, whatever the reason
// (an unknown, used or expired token, or a wrong proof), so a caller
// learns nothing about which; the server log has the real reason.
const Refused = "This join token is not valid (wrong, used or expired). Make a new one on Servers → Add a server."

// MaxRequest bounds the body of POST /api/cluster/join.
const MaxRequest = 16 << 10

// MaxNames bounds Request.Names.
const MaxNames = 16

// Request is the body of POST /api/cluster/join. Binary values are
// base64url without padding.
type Request struct {
	TokenID string `json:"token_id"`
	Nonce   string `json:"nonce"`
	Proof   string `json:"proof"`
	NodeID  string `json:"node_id"`
	NodePub string `json:"node_pub"`
	Name    string `json:"name"`
	Version string `json:"version"`
	OS      string `json:"os"`
	Arch    string `json:"arch"`
	// LevelMax is the highest cluster level the joining version reads.
	LevelMax int `json:"level_max"`
	// CSRPEM asks for the new server's HTTPS certificate, OSCSRPEM for
	// its own OpenSearch client certificate.
	CSRPEM   string `json:"csr_pem"`
	OSCSRPEM string `json:"os_csr_pem,omitempty"`
	NodeURL  string `json:"node_url,omitempty"`
	// Names are more names for its HTTPS certificate (the machine's own
	// DNS names and addresses); the certificate carries those the
	// cluster's certificate authority may sign.
	Names []string `json:"names,omitempty"`
	// AllowVersionSkew lets a version other than the issuer's join
	// (signalith join --allow-version-skew); the level must still allow
	// it.
	AllowVersionSkew bool `json:"allow_version_skew,omitempty"`
	// CopySyslog asks for the answering server's syslog listeners
	// (signalith join --copy-syslog).
	CopySyslog bool `json:"copy_syslog,omitempty"`
}

// Reply is the body of a successful POST /api/cluster/join.
type Reply struct {
	Sealed string `json:"sealed"`
}

// NewRequest returns a request for token t from the server nodeID with
// node public key nodePub, with a new nonce and its proof. The caller
// fills in the rest.
func NewRequest(t Token, nodeID string, nodePub []byte) (*Request, error) {
	nonce, err := NewNonce()
	if err != nil {
		return nil, err
	}
	enc := base64.RawURLEncoding.EncodeToString
	return &Request{TokenID: t.ID, Nonce: enc(nonce), Proof: enc(Proof(t.Secret, t.ID, nonce, nodePub)),
		NodeID: nodeID, NodePub: enc(nodePub)}, nil
}

// Parsed are a request's binary values.
type Parsed struct {
	Nonce, Proof, NodePub []byte
}

// Check checks a request's format before anything reads OpenSearch, and
// returns its binary values. Its errors are for the server log; the
// caller answers Refused.
func (r *Request) Check() (Parsed, error) {
	var p Parsed
	if !ValidID(r.TokenID) {
		return p, errors.New("the token id is not one")
	}
	dec := base64.RawURLEncoding.DecodeString
	var err error
	if p.Nonce, err = dec(r.Nonce); err != nil || len(p.Nonce) != NonceSize {
		return p, errors.New("the nonce is not 32 bytes")
	}
	if p.Proof, err = dec(r.Proof); err != nil || len(p.Proof) != 32 {
		return p, errors.New("the proof is not 32 bytes")
	}
	if p.NodePub, err = dec(r.NodePub); err != nil || len(p.NodePub) != NodePubSize {
		return p, errors.New("the node key is not 32 bytes")
	}
	if !validNodeID(r.NodeID) {
		return p, errors.New("the node id is not one")
	}
	if !config.ValidNodeName(r.Name) {
		return p, errors.New("the server name is not one")
	}
	if r.LevelMax < 1 {
		return p, errors.New("the level is missing")
	}
	if r.Version == "" || len(r.Version) > 64 || len(r.OS) > 16 || len(r.Arch) > 16 || len(r.NodeURL) > 512 {
		return p, errors.New("a field is too long")
	}
	if len(r.Names) > MaxNames {
		return p, errors.New("too many names")
	}
	for _, n := range r.Names {
		if n == "" || len(n) > 253 {
			return p, errors.New("a name is empty or too long")
		}
	}
	return p, nil
}

// validNodeID reports whether id looks like a node id (cluster.Identity):
// n_ then letters, digits, '_' and '-', at most 64 in all.
func validNodeID(id string) bool {
	if !strings.HasPrefix(id, "n_") || len(id) < 3 || len(id) > 64 {
		return false
	}
	for _, c := range id {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}
