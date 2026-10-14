package shared

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
)

// A cluster setting set in signalith.yaml or the environment is applied
// to the shared value when it changes, not at every start, so an
// unchanged file never undoes a change made on a page. Each server
// records, per setting and source, a keyed hash of the value its files
// had at its previous start, in its nodecfg:<node_id> document. The hash
// is an HMAC under the cluster key, so a secret cannot be guessed from it.

// Sources of a setting's value outside the pages.
const (
	SourceYAML = "yaml"
	SourceEnv  = "env"
)

// NodeCfgKind is the kind of nodecfg documents.
const NodeCfgKind = "nodecfg"

// NodeCfgID returns the id of the nodecfg document of server nodeID.
func NodeCfgID(nodeID string) string { return NodeCfgKind + ":" + nodeID }

// NodeCfg is the body of a nodecfg:<node_id> document. Later versions
// add the server's own setting values to it.
type NodeCfg struct {
	// Seen holds, per setting and source, the hash of the value last
	// applied or recorded.
	Seen map[string]map[string]string `json:"seen"`
	// Applied is when this server first applied (only recorded) its
	// files' values as a member; until then every value is only
	// recorded.
	Applied string `json:"applied,omitempty"`
	// UsersApplied is the same for the settings of the users and
	// directory sign-in (auth.*), which apply only once users are shared:
	// until then they are only recorded.
	UsersApplied string `json:"users_applied,omitempty"`
	Extra        `json:"-"`
}

// SeenHash returns the hash of a setting's value as nodecfg records it:
// "h1:", the id of the cluster key, ":" and the HMAC of the setting's
// name and its value as JSON. The key id lets a hash made under another
// key (before reset-key or a key rotation) be told apart from a changed
// value.
func SeenHash(k *ClusterKey, key string, value any) (string, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(value); err != nil {
		return "", err
	}
	h := hmac.New(sha256.New, k.macKey)
	h.Write([]byte("sgl-seen-v1\x00" + key + "\x00"))
	h.Write(bytes.TrimSuffix(b.Bytes(), []byte("\n")))
	return "h1:" + k.ID() + ":" + base64.RawURLEncoding.EncodeToString(h.Sum(nil)), nil
}

// seenKID returns the id of the cluster key a SeenHash was made with.
func seenKID(hash string) string {
	rest, _ := strings.CutPrefix(hash, "h1:")
	kid, _, ok := strings.Cut(rest, ":")
	if !ok {
		return ""
	}
	return kid
}

// Changed reports whether the value of setting key from source, whose
// hash is hash, is to be applied to the shared value: it changed since
// it was recorded, or it was not set at the previous start. At a server's
// first start as a member (first), values are only recorded. A hash
// recorded under another cluster key cannot be compared, so that value is
// only recorded again too: after a new cluster key, an unchanged file
// must not undo the changes made on the pages.
func (n *NodeCfg) Changed(key, source, hash string, first bool) bool {
	if first {
		return false
	}
	old, ok := n.Seen[key][source]
	if ok && seenKID(old) != seenKID(hash) {
		return false
	}
	return !ok || old != hash
}

// Record records the hash of the value of setting key from source.
// A setting removed from a file is not forgotten: removing it changes
// nothing.
func (n *NodeCfg) Record(key, source, hash string) {
	if n.Seen == nil {
		n.Seen = map[string]map[string]string{}
	}
	if n.Seen[key] == nil {
		n.Seen[key] = map[string]string{}
	}
	n.Seen[key][source] = hash
}
