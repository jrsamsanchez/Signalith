package agentproto

import (
	"cmp"
	"crypto/ed25519"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Signed updates: a release's agent programs come with a manifest, the
// SHA-256 of each program and the version they are, signed with the
// release key (ManifestFile and SignatureFile, next to the programs on the
// server). An agent updates itself only to a program the manifest lists,
// signed by a key in ReleaseKeys, and only to a newer version: a server
// that was broken into can hand out neither a program of its own nor an
// older one.

// RouteManifest answers the signed manifest of the programs the server
// hands out (ManifestAnswer), 404 when it has none.
const RouteManifest = "/api/agent/manifest"

// Files next to the agent programs.
const (
	ManifestFile  = "manifest.json"
	SignatureFile = "manifest.json.sig"
)

// ManifestFormat is the manifest format this build reads.
const ManifestFormat = 1

// Limits on what is read, so a broken or hostile server cannot fill memory.
const (
	MaxManifestBytes = 16 << 10
	MaxProgramBytes  = 256 << 20
)

// Manifest is a release's agent programs.
type Manifest struct {
	Format int `json:"format"`
	// Version is the programs' version (0.4.0).
	Version string `json:"version"`
	// Programs are the SHA-256 (hex) of each program, by platform
	// (linux-amd64).
	Programs map[string]string `json:"programs"`
}

// ManifestAnswer is the answer to RouteManifest: the manifest as signed,
// and its signature file.
type ManifestAnswer struct {
	Manifest  string `json:"manifest"`
	Signature string `json:"signature"`
}

// Update is the part of a Config that offers the agent a newer version:
// the manifest's version and the SHA-256 of the program for the agent's
// platform. The agent checks both against the signed manifest.
type Update struct {
	Version string `json:"version"`
	SHA256  string `json:"sha256"`
}

//go:embed release.keys
var releaseKeys string

// ReleaseKeys are the public keys whose programs this build updates to:
// the lines of release.keys that are not comments. Tests replace them.
var ReleaseKeys = mustKeys(releaseKeys)

func mustKeys(s string) []ed25519.PublicKey {
	k, err := ParseKeys(s)
	if err != nil {
		panic("agentproto/release.keys: " + err.Error())
	}
	return k
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

// KeyID is a short name for a public key, to say which key signed.
func KeyID(k ed25519.PublicKey) string {
	sum := sha256.Sum256(k)
	return fmt.Sprintf("%x", sum[:6])
}

// SignManifest signs a manifest file. The signature file is one line: the
// signing key's ID and the base64 signature.
func SignManifest(priv ed25519.PrivateKey, data []byte) []byte {
	sig := ed25519.Sign(priv, data)
	return []byte(KeyID(priv.Public().(ed25519.PublicKey)) + " " + base64.StdEncoding.EncodeToString(sig) + "\n")
}

// ErrNoReleaseKey is returned when this build trusts no release key, so
// it updates to nothing.
var ErrNoReleaseKey = errors.New("this build of the Signalith Agent has no release key, so it does not update itself; run the install line again to update it")

var (
	sha256Hex   = regexp.MustCompile(`^[0-9a-f]{64}$`)
	versionNums = regexp.MustCompile(`^v?([0-9]{1,6})\.([0-9]{1,6})\.([0-9]{1,6})(?:-([0-9A-Za-z.-]{1,40}))?(?:\+[0-9A-Za-z.-]{1,40})?$`)
)

// VerifyManifest checks a manifest file's signature against keys and
// reads it.
func VerifyManifest(keys []ed25519.PublicKey, data, sig []byte) (*Manifest, error) {
	if len(keys) == 0 {
		return nil, ErrNoReleaseKey
	}
	if len(data) > MaxManifestBytes || len(sig) > 1024 {
		return nil, errors.New("the manifest is larger than any release makes")
	}
	f := strings.Fields(string(sig))
	if len(f) != 2 {
		return nil, errors.New("the manifest's signature file is not a Signalith signature")
	}
	raw, err := base64.StdEncoding.DecodeString(f[1])
	if err != nil || len(raw) != ed25519.SignatureSize {
		return nil, errors.New("the manifest's signature file is not a Signalith signature")
	}
	ok := false
	for _, k := range keys {
		if KeyID(k) == f[0] && ed25519.Verify(k, data, raw) {
			ok = true
			break
		}
	}
	if !ok {
		return nil, errors.New("the manifest's signature does not match: it was changed, or not signed by a release key this agent trusts")
	}
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("the manifest is not valid JSON: %w", err)
	}
	if m.Format != ManifestFormat {
		return nil, fmt.Errorf("the manifest is format %d; this agent reads format %d", m.Format, ManifestFormat)
	}
	if _, ok := parseVersion(m.Version); !ok {
		return nil, fmt.Errorf("the manifest's version %q is not a release version", m.Version)
	}
	for p, sum := range m.Programs {
		if !sha256Hex.MatchString(sum) {
			return nil, fmt.Errorf("the manifest's SHA-256 for %s is not valid", p)
		}
	}
	return &m, nil
}

// version is a parsed release version: major, minor, patch, and the
// pre-release part ("" for a final release).
type version struct {
	n   [3]int
	pre string
}

func parseVersion(s string) (version, bool) {
	m := versionNums.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return version{}, false
	}
	var v version
	for i := range 3 {
		v.n[i], _ = strconv.Atoi(m[i+1])
	}
	v.pre = m[4]
	return v, true
}

// Newer says whether version a is newer than version b. A version that
// is not a release version (dev) is never newer, and nothing is newer
// than it: a development build does not update itself. A pre-release is
// older than its final release; two pre-releases of the same version
// compare as semantic versioning says (rc.10 is newer than rc.9).
func Newer(a, b string) bool {
	va, ok := parseVersion(a)
	vb, ok2 := parseVersion(b)
	if !ok || !ok2 {
		return false
	}
	for i := range 3 {
		if va.n[i] != vb.n[i] {
			return va.n[i] > vb.n[i]
		}
	}
	switch {
	case va.pre == vb.pre:
		return false
	case va.pre == "":
		return true
	case vb.pre == "":
		return false
	}
	return comparePre(va.pre, vb.pre) > 0
}

// comparePre compares two pre-release parts by their dot-separated
// identifiers: numbers as numbers, below words, and words as text; with
// all equal, the one with more identifiers is newer.
func comparePre(a, b string) int {
	pa, pb := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < len(pa) && i < len(pb); i++ {
		na, errA := strconv.Atoi(pa[i])
		nb, errB := strconv.Atoi(pb[i])
		switch {
		case errA == nil && errB == nil:
			if na != nb {
				return cmp.Compare(na, nb)
			}
		case errA == nil:
			return -1
		case errB == nil:
			return 1
		default:
			if c := strings.Compare(pa[i], pb[i]); c != 0 {
				return c
			}
		}
	}
	return cmp.Compare(len(pa), len(pb))
}
