package shared

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"golang.org/x/crypto/scrypt"

	"github.com/jrsamsanchez/signalith/internal/secrets"
	"github.com/jrsamsanchez/signalith/internal/securefile"
)

// The cluster key is 32 random bytes every member keeps, sealed under its
// own master key, and never in OpenSearch in a usable form. Sub-keys made
// from it with HKDF-SHA256 sign the shared documents, encrypt the shared
// secrets (the same scheme as the master key's, so values look like
// enc:v1:<kid>:...), tag session cookies and encrypt archives. Its id is
// the same kind of fingerprint as a master key's.
//
// Each server also has a node key, an X25519 pair, so the cluster key can
// be handed to it (sealed to its public key) without trusting anything in
// OpenSearch.

// HKDF info strings of the cluster key's sub-keys.
const (
	infoMAC     = "signalith config mac v1"
	infoCookie  = "signalith session cookie v1"
	infoArchive = "signalith archive v1"
	infoSeal    = "signalith seal-to-node v1"
	infoBrowser = "signalith known browser v1"
	infoLocks   = "signalith sign-in locks v1"
)

const keySize = 32

// ClusterKey is the cluster key, ready to use.
type ClusterKey struct {
	raw     []byte
	secrets *secrets.Key
	macKey  []byte
}

// NewClusterKey makes a new cluster key.
func NewClusterKey() (*ClusterKey, error) {
	raw := make([]byte, keySize)
	defer clear(raw)
	if _, err := rand.Read(raw); err != nil {
		return nil, err
	}
	return ClusterKeyFrom(raw)
}

// ClusterKeyFrom returns the cluster key made of raw, 32 bytes. The caller
// may clear raw afterwards.
func ClusterKeyFrom(raw []byte) (*ClusterKey, error) {
	if len(raw) != keySize {
		return nil, fmt.Errorf("a cluster key is %d bytes, not %d", keySize, len(raw))
	}
	sk, err := secrets.NewKey(raw, "cluster key")
	if err != nil {
		return nil, err
	}
	mk, err := hkdf.Key(sha256.New, raw, nil, infoMAC, 32)
	if err != nil {
		return nil, err
	}
	return &ClusterKey{raw: bytes.Clone(raw), secrets: sk, macKey: mk}, nil
}

// KeyFromFile reads a cluster key file, as SIGNALITH_CLUSTER_KEY_FILE
// names one: one line of base64 of the 32 bytes, with optional # comment
// lines. The caller shows KeyFileWarning(path) with the master key's
// warnings.
func KeyFromFile(path string) (*ClusterKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	defer clear(data)
	raw, err := parseKeyText(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	defer clear(raw)
	return ClusterKeyFrom(raw)
}

// KeyFileWarning says what is wrong with who may read a cluster key file
// (on Unix: other accounts can, or another account owns it), or "". The
// file makes whoever reads it a member of the cluster, so it is worth
// more than the master key.
func KeyFileWarning(path string) string {
	return secrets.KeyFileWarning("The cluster key file", path)
}

// parseKeyText reads one line of base64, with optional # comment lines.
func parseKeyText(data []byte) ([]byte, error) {
	var line []byte
	n := 0
	for _, l := range bytes.Split(data, []byte("\n")) {
		l = bytes.TrimSpace(l)
		if len(l) == 0 || l[0] == '#' {
			continue
		}
		line = l
		n++
	}
	if n == 1 {
		for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
			b := make([]byte, enc.DecodedLen(len(line)))
			if n, err := enc.Decode(b, line); err == nil && n == keySize {
				return b[:n], nil
			}
			clear(b)
		}
	}
	return nil, errors.New("it does not hold a cluster key: one line of base64 of 32 bytes")
}

// ID returns the key's id, as in the MACs and values it makes.
func (k *ClusterKey) ID() string { return k.secrets.ID() }

// Text returns the key as a key file holds it: base64 of the 32 bytes.
func (k *ClusterKey) Text() string { return base64.StdEncoding.EncodeToString(k.raw) }

// SecretsKey encrypts the shared secrets.
func (k *ClusterKey) SecretsKey() *secrets.Key { return k.secrets }

// MACKey returns the key that signs the shared documents.
func (k *ClusterKey) MACKey() []byte { return bytes.Clone(k.macKey) }

// CookieKey returns the key that tags session cookies.
func (k *ClusterKey) CookieKey() []byte { return k.sub(infoCookie) }

// ArchiveKey returns the key that encrypts archives.
func (k *ClusterKey) ArchiveKey() []byte { return k.sub(infoArchive) }

// KnownBrowserKey returns the key that signs the known-browser cookies of
// the sign-in limiter, so a browser known on one member is known on all.
func (k *ClusterKey) KnownBrowserKey() []byte { return k.sub(infoBrowser) }

// LockKey returns the key the sign-in limiter keys the names of its
// locks with (auth.LockKey), so the lock documents of a cluster name no
// address or account anyone could read back.
func (k *ClusterKey) LockKey() []byte { return k.sub(infoLocks) }

func (k *ClusterKey) sub(info string) []byte {
	b, err := hkdf.Key(sha256.New, k.raw, nil, info, 32)
	if err != nil {
		panic(err)
	}
	return b
}

// KeySet holds the cluster keys whose MACs this server accepts: the
// active one, which signs, and during a key rotation the other one the
// signed keyring names (its next or, until every server has moved,
// previous key).
type KeySet struct {
	active *ClusterKey
	byID   map[string]*ClusterKey
	// cookie holds keys retired by the last rotation whose session
	// cookies still pass the cookie check (see WithCookieKeys).
	cookie map[string]*ClusterKey
}

// NewKeySet returns a set whose active key is active. others are only
// the keys the keyring accepts now: a retired key, which a removed server
// may still have, must not be passed, even though its file is kept to
// open old archives and secrets (KeyStore.ClusterKeys returns them all).
func NewKeySet(active *ClusterKey, others ...*ClusterKey) *KeySet {
	s := &KeySet{active: active, byID: map[string]*ClusterKey{}}
	for _, k := range append([]*ClusterKey{active}, others...) {
		if k != nil {
			s.byID[k.ID()] = k
		}
	}
	return s
}

// Active returns the key that signs, or nil.
func (s *KeySet) Active() *ClusterKey {
	if s == nil {
		return nil
	}
	return s.active
}

// Get returns the key with id kid, or nil.
func (s *KeySet) Get(kid string) *ClusterKey {
	if s == nil {
		return nil
	}
	return s.byID[kid]
}

// WithCookieKeys returns the set with old, keys a rotation retired, kept
// for the session cookie check only: a cookie they made still passes it,
// but nothing they sign verifies, so a cookie needs a session document
// signed with a key of the set to work.
func (s *KeySet) WithCookieKeys(old ...*ClusterKey) *KeySet {
	out := &KeySet{active: s.active, byID: s.byID, cookie: map[string]*ClusterKey{}}
	for _, k := range old {
		if k != nil && s.byID[k.ID()] == nil {
			out.cookie[k.ID()] = k
		}
	}
	return out
}

// CookieKey returns the key with id kid for the session cookie check: a
// key of the set, or one kept by WithCookieKeys; nil when there is none.
func (s *KeySet) CookieKey(kid string) *ClusterKey {
	if s == nil {
		return nil
	}
	if k := s.byID[kid]; k != nil {
		return k
	}
	return s.cookie[kid]
}

// IDs lists the ids of the keys, sorted.
func (s *KeySet) IDs() []string {
	if s == nil {
		return nil
	}
	var out []string
	for id := range s.byID {
		out = append(out, id)
	}
	slices.Sort(out)
	return out
}

// NodeKey is this server's X25519 key pair.
type NodeKey struct{ priv *ecdh.PrivateKey }

// NewNodeKey makes a node key.
func NewNodeKey() (*NodeKey, error) {
	p, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &NodeKey{priv: p}, nil
}

// Public returns the public key.
func (n *NodeKey) Public() []byte { return n.priv.PublicKey().Bytes() }

// PublicText returns the public key in base64, as the keyring holds it.
func (n *NodeKey) PublicText() string { return base64.StdEncoding.EncodeToString(n.Public()) }

// Fingerprint returns the public key's fingerprint, which people compare
// on both servers when approving one: "4F2A-91C0-...", eight groups.
func (n *NodeKey) Fingerprint() string { return Fingerprint(n.Public()) }

// Fingerprint returns the fingerprint of a node's public key.
func Fingerprint(pub []byte) string {
	sum := sha256.Sum256(pub)
	h := strings.ToUpper(hex.EncodeToString(sum[:16]))
	var parts []string
	for i := 0; i < len(h); i += 4 {
		parts = append(parts, h[i:i+4])
	}
	return strings.Join(parts, "-")
}

// sealPrefix starts a value sealed to a node key.
const sealPrefix = "n1:"

// sealKey derives the AES key of a value sealed to a node key.
func sealKey(shared []byte, nodeID string) (cipher.AEAD, error) {
	k, err := hkdf.Key(sha256.New, shared, []byte(nodeID), infoSeal, 32)
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

// SealToNode encrypts plain, such as the cluster key kid, so that only
// the server nodeID, whose node public key is pub, can open it: an
// ephemeral X25519 agreement with pub, HKDF-SHA256 (salt the node id),
// then AES-256-GCM bound to the node id and kid.
func SealToNode(pub []byte, nodeID, kid string, plain []byte) (string, error) {
	peer, err := ecdh.X25519().NewPublicKey(pub)
	if err != nil {
		return "", fmt.Errorf("not a node key: %w", err)
	}
	eph, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	secret, err := eph.ECDH(peer)
	if err != nil {
		return "", err
	}
	defer clear(secret)
	aead, err := sealKey(secret, nodeID)
	if err != nil {
		return "", err
	}
	out := eph.PublicKey().Bytes()
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	out = append(out, nonce...)
	out = aead.Seal(out, nonce, plain, []byte(nodeID+"|"+kid))
	return sealPrefix + base64.RawURLEncoding.EncodeToString(out), nil
}

// ErrNotForNode is a sealed value this node key cannot open: it was
// sealed to another server, for another key id, or changed.
var ErrNotForNode = errors.New("it was not sealed to this server's node key, or it was changed")

// OpenFromNode opens a value SealToNode sealed to this server.
func (n *NodeKey) OpenFromNode(nodeID, kid, sealed string) ([]byte, error) {
	rest, ok := strings.CutPrefix(sealed, sealPrefix)
	if !ok {
		return nil, ErrNotForNode
	}
	blob, err := base64.RawURLEncoding.DecodeString(rest)
	if err != nil || len(blob) < 32 {
		return nil, ErrNotForNode
	}
	eph, err := ecdh.X25519().NewPublicKey(blob[:32])
	if err != nil {
		return nil, ErrNotForNode
	}
	secret, err := n.priv.ECDH(eph)
	if err != nil {
		return nil, ErrNotForNode
	}
	defer clear(secret)
	aead, err := sealKey(secret, nodeID)
	if err != nil {
		return nil, err
	}
	rest2 := blob[32:]
	if len(rest2) < aead.NonceSize()+aead.Overhead() {
		return nil, ErrNotForNode
	}
	plain, err := aead.Open(nil, rest2[:aead.NonceSize()], rest2[aead.NonceSize():], []byte(nodeID+"|"+kid))
	if err != nil {
		return nil, ErrNotForNode
	}
	return plain, nil
}

// Sealer encrypts and decrypts values with this server's master key;
// *secrets.Keyring is one.
type Sealer interface {
	Seal(field, plain string) (string, error)
	Open(field, stored string) (string, error)
}

// Key files in the state folder.
const (
	nodeKeyField = "cluster.node_key"
	keysDir      = "keys"
	nodeKeyName  = "node.key"
)

// clusterKeyField is the field a cluster key is sealed under.
func clusterKeyField(kid string) string { return "cluster.key/" + kid }

// NodeKeyPath is where the node key is kept in the state folder.
func NodeKeyPath(stateDir string) string { return filepath.Join(stateDir, keysDir, nodeKeyName) }

// ClusterKeyPath is where the cluster key kid is kept in the state folder.
func ClusterKeyPath(stateDir, kid string) string {
	return filepath.Join(stateDir, keysDir, "cluster-"+kid+".key")
}

// ClusterKeyFiles lists the cluster key files in the state folder.
func ClusterKeyFiles(stateDir string) []string {
	out, _ := filepath.Glob(filepath.Join(stateDir, keysDir, "cluster-*.key"))
	slices.Sort(out)
	return out
}

// keyFile is a key file as stored: a small JSON object whose key is
// sealed under the master key.
type keyFile struct {
	Format  int       `json:"format"`
	KID     string    `json:"kid,omitempty"`
	Public  string    `json:"public,omitempty"`
	Key     string    `json:"key"`
	Created time.Time `json:"created_at"`
}

// KeyStore keeps the node key and the cluster keys in the state folder,
// each sealed under the master key.
type KeyStore struct {
	Dir    string
	Master Sealer
}

// NodeKey returns this server's node key, making it the first time.
func (s KeyStore) NodeKey() (*NodeKey, error) {
	n, err := s.LoadNodeKey()
	if !errors.Is(err, fs.ErrNotExist) {
		return n, err
	}
	n, err = NewNodeKey()
	if err != nil {
		return nil, err
	}
	sealed, err := s.Master.Seal(nodeKeyField, base64.StdEncoding.EncodeToString(n.priv.Bytes()))
	if err != nil {
		return nil, err
	}
	data, err := json.MarshalIndent(keyFile{Format: 1, Public: n.PublicText(), Key: sealed, Created: time.Now().UTC()}, "", "  ")
	if err != nil {
		return nil, err
	}
	path := NodeKeyPath(s.Dir)
	if err := securefile.MkdirPrivate(filepath.Dir(path)); err != nil {
		return nil, err
	}
	p, err := securefile.PreparePrivate(path, append(data, '\n'))
	if err != nil {
		return nil, err
	}
	// Another process may have made one at the same moment: use that one.
	if err := p.CommitNew(); errors.Is(err, fs.ErrExist) {
		return s.LoadNodeKey()
	} else if err != nil {
		return nil, err
	}
	return n, nil
}

// LoadNodeKey reads the node key; an error wrapping fs.ErrNotExist when
// there is none.
func (s KeyStore) LoadNodeKey() (*NodeKey, error) {
	path := NodeKeyPath(s.Dir)
	var f keyFile
	if err := readJSON(path, &f); err != nil {
		return nil, err
	}
	plain, err := s.Master.Open(nodeKeyField, f.Key)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	raw, err := base64.StdEncoding.DecodeString(plain)
	if err != nil {
		return nil, fmt.Errorf("%s: the node key is damaged", path)
	}
	defer clear(raw)
	p, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		return nil, fmt.Errorf("%s: the node key is damaged", path)
	}
	return &NodeKey{priv: p}, nil
}

// SaveClusterKey keeps k in the state folder.
func (s KeyStore) SaveClusterKey(k *ClusterKey) error {
	sealed, err := s.Master.Seal(clusterKeyField(k.ID()), k.Text())
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(keyFile{Format: 1, KID: k.ID(), Key: sealed, Created: time.Now().UTC()}, "", "  ")
	if err != nil {
		return err
	}
	path := ClusterKeyPath(s.Dir, k.ID())
	if err := securefile.MkdirPrivate(filepath.Dir(path)); err != nil {
		return err
	}
	p, err := securefile.PreparePrivate(path, append(data, '\n'))
	if err != nil {
		return err
	}
	return p.Commit()
}

// ClusterKeys reads the cluster keys kept in the state folder. A file
// that cannot be read is an error: a key that is there but cannot be
// opened must not pass for a missing one.
func (s KeyStore) ClusterKeys() ([]*ClusterKey, error) {
	var out []*ClusterKey
	for _, path := range ClusterKeyFiles(s.Dir) {
		var f keyFile
		if err := readJSON(path, &f); err != nil {
			return nil, err
		}
		plain, err := s.Master.Open(clusterKeyField(f.KID), f.Key)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		raw, err := base64.StdEncoding.DecodeString(plain)
		if err != nil {
			return nil, fmt.Errorf("%s: the cluster key is damaged", path)
		}
		k, err := ClusterKeyFrom(raw)
		clear(raw)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		if k.ID() != f.KID {
			return nil, fmt.Errorf("%s: it holds cluster key %s, not %s", path, k.ID(), f.KID)
		}
		out = append(out, k)
	}
	return out, nil
}

func readJSON(path string, v any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, v); err != nil {
		return fmt.Errorf("%s: not valid JSON: %w", path, err)
	}
	return nil
}

// resealKeyFile passes the key in a key file's text through fn.
func resealKeyFile(data []byte, fn secrets.Reseal, field func(keyFile) string, label func(keyFile) string) ([]byte, int, error) {
	var f keyFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, 0, fmt.Errorf("not valid JSON: %w", err)
	}
	v, err := fn(secrets.Stored{Field: field(f), Label: label(f), Value: f.Key})
	if err != nil || v == f.Key {
		return data, 0, err
	}
	f.Key = v
	out, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return nil, 0, err
	}
	return append(out, '\n'), 1, nil
}

// ResealNodeKeyFile passes the node key in the text of keys/node.key
// through fn, for "signalith secrets" (see config.SecretFile).
func ResealNodeKeyFile(data []byte, fn secrets.Reseal) ([]byte, int, error) {
	return resealKeyFile(data, fn, func(keyFile) string { return nodeKeyField },
		func(keyFile) string { return "node key" })
}

// ResealClusterKeyFile passes the cluster key in the text of a
// keys/cluster-<kid>.key file through fn.
func ResealClusterKeyFile(data []byte, fn secrets.Reseal) ([]byte, int, error) {
	return resealKeyFile(data, fn, func(f keyFile) string { return clusterKeyField(f.KID) },
		func(f keyFile) string { return "cluster key " + f.KID })
}

// Exported cluster keys are sealed under a passphrase: scrypt, then
// AES-256-GCM, bound to the key id.
type exportFile struct {
	Format string `json:"format"`
	KID    string `json:"kid"`
	KDF    struct {
		Name string `json:"name"`
		N    int    `json:"n"`
		R    int    `json:"r"`
		P    int    `json:"p"`
		Salt string `json:"salt"`
	} `json:"kdf"`
	Sealed string `json:"sealed"`
}

const exportFormat = "signalith-cluster-key-v1"

// scryptN is scrypt's cost for exports; tests lower it.
var scryptN = 1 << 17

func exportAEAD(pass, salt []byte, n, r, p int) (cipher.AEAD, error) {
	k, err := scrypt.Key(pass, salt, n, r, p, 32)
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

// ExportKey returns k sealed under passphrase, as text to keep in a
// password manager.
func ExportKey(k *ClusterKey, passphrase []byte) (string, error) {
	if len(passphrase) == 0 {
		return "", errors.New("the passphrase is empty")
	}
	var f exportFile
	f.Format, f.KID = exportFormat, k.ID()
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	f.KDF.Name, f.KDF.N, f.KDF.R, f.KDF.P, f.KDF.Salt = "scrypt", scryptN, 8, 1, base64.StdEncoding.EncodeToString(salt)
	aead, err := exportAEAD(passphrase, salt, f.KDF.N, f.KDF.R, f.KDF.P)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	f.Sealed = base64.StdEncoding.EncodeToString(aead.Seal(nonce, nonce, k.raw, []byte(exportFormat+":"+f.KID)))
	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data) + "\n", nil
}

// ErrPassphrase is an exported key that the passphrase does not open.
var ErrPassphrase = errors.New("the passphrase does not open this key, or the text was changed")

// ImportKey opens a key ExportKey sealed.
func ImportKey(text string, passphrase []byte) (*ClusterKey, error) {
	var f exportFile
	if err := json.Unmarshal([]byte(text), &f); err != nil || f.Format != exportFormat {
		return nil, errors.New("this is not a cluster key exported by signalith cluster export-key")
	}
	// The cost is read from the text, which may be damaged or made up:
	// near what ExportKey writes, scrypt needs at most 256 MiB.
	if f.KDF.Name != "scrypt" || f.KDF.N < 2 || f.KDF.N > 1<<18 || f.KDF.R < 1 || f.KDF.R > 8 || f.KDF.P < 1 || f.KDF.P > 2 {
		return nil, errors.New("the exported key names a key derivation this version does not use")
	}
	salt, err := base64.StdEncoding.DecodeString(f.KDF.Salt)
	if err != nil {
		return nil, ErrPassphrase
	}
	blob, err := base64.StdEncoding.DecodeString(f.Sealed)
	if err != nil {
		return nil, ErrPassphrase
	}
	aead, err := exportAEAD(passphrase, salt, f.KDF.N, f.KDF.R, f.KDF.P)
	if err != nil {
		return nil, err
	}
	if len(blob) < aead.NonceSize()+aead.Overhead() {
		return nil, ErrPassphrase
	}
	raw, err := aead.Open(nil, blob[:aead.NonceSize()], blob[aead.NonceSize():], []byte(exportFormat+":"+f.KID))
	if err != nil {
		return nil, ErrPassphrase
	}
	defer clear(raw)
	k, err := ClusterKeyFrom(raw)
	if err != nil {
		return nil, err
	}
	if k.ID() != f.KID {
		return nil, ErrPassphrase
	}
	return k, nil
}
