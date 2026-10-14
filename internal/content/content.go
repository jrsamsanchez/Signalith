// Package content makes, signs, checks and keeps detection content
// updates: the content packs (internal/detect/packs) as one signed bundle,
// so a server can take newer rules without a new Signalith release.
//
// A bundle is a gzipped tar file holding content.json (Manifest) and
// packs/<name>/ with each pack's manifest, rules, macros and licence, as
// in the source tree but without the test events. Its signature is an
// Ed25519 signature of the whole file, in a text file next to it. A server
// only installs a bundle signed by a key in TrustedKeys, in a format it
// reads, and newer than the one it has.
package content

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"testing/fstest"
	"time"

	"gopkg.in/yaml.v3"
)

// Format is the bundle format this build reads. A bundle with a higher
// one is refused.
const Format = 1

// Limits on a bundle, so a damaged or hostile file cannot fill memory.
const (
	MaxBundle = 64 << 20  // the gzipped file
	maxTotal  = 256 << 20 // all files unpacked
	maxFiles  = 20000
)

// VersionLayout is how a bundle's version is written: the UTC time it was
// made, so versions sort as strings.
const VersionLayout = "20060102150405"

// Manifest is content.json.
type Manifest struct {
	Format  int        `json:"format"`
	Version string     `json:"version"`
	Created time.Time  `json:"created"`
	Packs   []PackInfo `json:"packs"`
}

// PackInfo is one pack in a bundle.
type PackInfo struct {
	Name    string `json:"name"`
	Rules   int    `json:"rules"`
	Version string `json:"version"` // the upstream commit
}

// Bundle is a read bundle: its manifest and its files.
type Bundle struct {
	Manifest Manifest
	// FS holds packs/<name>/..., the layout internal/detect reads.
	FS fs.FS
	// Data and Signature are the file as signed and its signature.
	Data, Signature []byte
}

//go:embed trusted.keys
var trustedKeys string

// TrustedKeys are the public keys whose bundles this build installs: the
// lines of trusted.keys that are not comments, each a base64 Ed25519 key.
func TrustedKeys() []ed25519.PublicKey {
	keys, err := ParseKeys(trustedKeys)
	if err != nil {
		panic("content/trusted.keys: " + err.Error())
	}
	return keys
}

// ParseKeys reads public keys, one base64 key per line; # starts a comment.
func ParseKeys(s string) ([]ed25519.PublicKey, error) {
	var out []ed25519.PublicKey
	for _, line := range strings.Split(s, "\n") {
		line, _, _ = strings.Cut(line, "#")
		if line = strings.TrimSpace(line); line == "" {
			continue
		}
		k, err := base64.StdEncoding.DecodeString(line)
		if err != nil || len(k) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("%q is not a base64 Ed25519 public key", line)
		}
		out = append(out, ed25519.PublicKey(k))
	}
	return out, nil
}

// KeyID is a short name for a public key, to say which key signed a
// bundle.
func KeyID(k ed25519.PublicKey) string {
	sum := sha256.Sum256(k)
	return fmt.Sprintf("%x", sum[:6])
}

// NewKey makes a signing key: the private key (its seed) and the public
// key, both base64.
func NewKey() (private, public string, err error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	return base64.StdEncoding.EncodeToString(priv.Seed()), base64.StdEncoding.EncodeToString(pub), nil
}

// ParsePrivateKey reads a private key made by NewKey.
func ParsePrivateKey(s string) (ed25519.PrivateKey, error) {
	seed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, errors.New("the signing key is not a base64 Ed25519 key from signalith content keygen")
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// Sign signs a bundle file. The signature file is one line: the signing
// key's ID and the base64 signature.
func Sign(priv ed25519.PrivateKey, data []byte) []byte {
	sig := ed25519.Sign(priv, data)
	return []byte(KeyID(priv.Public().(ed25519.PublicKey)) + " " + base64.StdEncoding.EncodeToString(sig) + "\n")
}

// ErrNoKeys is returned when this build trusts no key, so it can install
// no bundle.
var ErrNoKeys = errors.New("this build of Signalith has no key to check content updates with")

// Verify checks a bundle file's signature against keys and returns the
// signing key's ID.
func Verify(keys []ed25519.PublicKey, data, sig []byte) (string, error) {
	if len(keys) == 0 {
		return "", ErrNoKeys
	}
	f := strings.Fields(string(sig))
	if len(f) != 2 {
		return "", errors.New("the signature file is not a Signalith content signature")
	}
	raw, err := base64.StdEncoding.DecodeString(f[1])
	if err != nil || len(raw) != ed25519.SignatureSize {
		return "", errors.New("the signature file is not a Signalith content signature")
	}
	for _, k := range keys {
		if KeyID(k) == f[0] && ed25519.Verify(k, data, raw) {
			return f[0], nil
		}
	}
	return "", errors.New("the signature does not match: the bundle was changed, or not signed by a key this build trusts")
}

// Build makes a bundle from a packs folder (internal/detect/packs).
func Build(packsDir string, now time.Time) ([]byte, *Manifest, error) {
	m := &Manifest{Format: Format, Version: now.UTC().Format(VersionLayout), Created: now.UTC().Truncate(time.Second)}
	type file struct {
		name string
		data []byte
	}
	var files []file
	dirs, err := os.ReadDir(packsDir)
	if err != nil {
		return nil, nil, err
	}
	for _, d := range dirs {
		if !d.IsDir() {
			continue
		}
		dir := filepath.Join(packsDir, d.Name())
		manifest, err := os.ReadFile(filepath.Join(dir, "pack.yaml"))
		if err != nil {
			return nil, nil, err
		}
		var pm struct {
			Version string     `yaml:"version"`
			Rules   []struct{} `yaml:"rules"`
		}
		if err := yaml.Unmarshal(manifest, &pm); err != nil {
			return nil, nil, fmt.Errorf("%s: %w", dir, err)
		}
		m.Packs = append(m.Packs, PackInfo{Name: d.Name(), Version: pm.Version, Rules: len(pm.Rules)})
		files = append(files, file{"packs/" + d.Name() + "/pack.yaml", manifest})
		var names []string
		for _, pat := range []string{"rules/*.yml", "macros/*.yml", "LICENSE*"} {
			got, err := filepath.Glob(filepath.Join(dir, filepath.FromSlash(pat)))
			if err != nil {
				return nil, nil, err
			}
			names = append(names, got...)
		}
		sort.Strings(names)
		for _, n := range names {
			data, err := os.ReadFile(n)
			if err != nil {
				return nil, nil, err
			}
			rel, _ := filepath.Rel(packsDir, n)
			files = append(files, file{"packs/" + filepath.ToSlash(rel), data})
		}
	}
	if len(m.Packs) == 0 {
		return nil, nil, fmt.Errorf("no packs in %s", packsDir)
	}
	head, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return nil, nil, err
	}
	files = append([]file{{"content.json", head}}, files...)

	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, f := range files {
		if err := tw.WriteHeader(&tar.Header{Name: f.name, Mode: 0o644, Size: int64(len(f.data)), ModTime: m.Created, Typeflag: tar.TypeReg, Format: tar.FormatPAX}); err != nil {
			return nil, nil, err
		}
		if _, err := tw.Write(f.data); err != nil {
			return nil, nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, nil, err
	}
	return buf.Bytes(), m, nil
}

// Read unpacks a bundle file after checking its signature with keys. It
// refuses a bundle in a newer format, and any file outside packs/.
func Read(keys []ed25519.PublicKey, data, sig []byte) (*Bundle, error) {
	if len(data) > MaxBundle {
		return nil, fmt.Errorf("the bundle is larger than %d MB", MaxBundle>>20)
	}
	if _, err := Verify(keys, data, sig); err != nil {
		return nil, err
	}
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("the bundle is not a gzipped tar file: %w", err)
	}
	tr := tar.NewReader(gz)
	files := fstest.MapFS{}
	var head []byte
	total := 0
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("reading the bundle: %w", err)
		}
		if h.Typeflag == tar.TypeDir {
			continue
		}
		name := h.Name
		if h.Typeflag != tar.TypeReg || !fs.ValidPath(name) || path.Clean(name) != name || (name != "content.json" && !strings.HasPrefix(name, "packs/")) {
			return nil, fmt.Errorf("the bundle has an unexpected entry %q", h.Name)
		}
		if len(files) >= maxFiles {
			return nil, errors.New("the bundle has too many files")
		}
		total += int(h.Size)
		if h.Size < 0 || total > maxTotal {
			return nil, errors.New("the bundle unpacks to too much data")
		}
		b, err := io.ReadAll(io.LimitReader(tr, h.Size))
		if err != nil {
			return nil, fmt.Errorf("reading the bundle: %w", err)
		}
		if name == "content.json" {
			head = b
			continue
		}
		files[name] = &fstest.MapFile{Data: b, Mode: 0o444, ModTime: h.ModTime}
	}
	if head == nil {
		return nil, errors.New("the bundle has no content.json")
	}
	b := &Bundle{FS: files, Data: data, Signature: sig}
	if err := json.Unmarshal(head, &b.Manifest); err != nil {
		return nil, fmt.Errorf("content.json: %w", err)
	}
	if b.Manifest.Format > Format || b.Manifest.Format < 1 {
		return nil, fmt.Errorf("the bundle is in format %d; this Signalith reads format %d, so update Signalith first", b.Manifest.Format, Format)
	}
	if _, err := time.Parse(VersionLayout, b.Manifest.Version); err != nil {
		return nil, fmt.Errorf("the bundle version %q is not valid", b.Manifest.Version)
	}
	return b, nil
}

// The files an installed bundle is kept in, in the store folder.
const (
	bundleFile = "content.tar.gz"
	sigFile    = "content.tar.gz.sig"
)

// Installed reads the bundle installed in dir, checking its signature
// again. It returns nil and no error when none is installed.
func Installed(dir string, keys []ed25519.PublicKey) (*Bundle, error) {
	data, err := os.ReadFile(filepath.Join(dir, bundleFile))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	sig, err := os.ReadFile(filepath.Join(dir, sigFile))
	if err != nil {
		return nil, err
	}
	return Read(keys, data, sig)
}

// Save keeps a bundle in dir as the installed one, replacing the old.
func Save(dir string, b *Bundle) error {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	parent := filepath.Dir(dir)
	if err := giveToFolderOwner(dir, parent); err != nil {
		return err
	}
	// Both are written in full before either replaces the old one. Should
	// Signalith stop between the two renames, the pair fails its check
	// and the rules built into Signalith are used until the next install.
	for _, f := range []struct {
		name string
		data []byte
	}{{sigFile + ".new", b.Signature}, {bundleFile + ".new", b.Data}} {
		if err := os.WriteFile(filepath.Join(dir, f.name), f.data, 0o640); err != nil {
			return err
		}
		if err := giveToFolderOwner(filepath.Join(dir, f.name), parent); err != nil {
			return err
		}
	}
	if err := os.Rename(filepath.Join(dir, bundleFile+".new"), filepath.Join(dir, bundleFile)); err != nil {
		return err
	}
	return os.Rename(filepath.Join(dir, sigFile+".new"), filepath.Join(dir, sigFile))
}

// Remove deletes the installed bundle, so the rules built into Signalith
// are used again.
func Remove(dir string) error {
	for _, f := range []string{bundleFile, sigFile} {
		if err := os.Remove(filepath.Join(dir, f)); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}
	return nil
}
