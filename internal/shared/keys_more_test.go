// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package shared

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/secrets"
)

func TestClusterKeyFromWrongSize(t *testing.T) {
	if _, err := ClusterKeyFrom(make([]byte, 16)); err == nil || !strings.Contains(err.Error(), "not 16") {
		t.Errorf("ClusterKeyFrom(16 bytes) = %v", err)
	}
	var none *KeySet
	if none.CookieKey("x") != nil || none.IDs() != nil {
		t.Error("a nil key set has keys")
	}
}

// A value sealed to a node opens only there, for that key id, unchanged.
func TestSealToNodeRefusals(t *testing.T) {
	nk, err := NewNodeKey()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := SealToNode([]byte("short"), "n_a", "kid1", []byte("x")); err == nil {
		t.Error("sealed to something that is not a node key")
	}
	sealed, err := SealToNode(nk.Public(), "n_a", "kid1", []byte("plain"))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := nk.OpenFromNode("n_a", "kid1", sealed); err != nil || string(got) != "plain" {
		t.Fatalf("open = %q, %v", got, err)
	}
	blob, _ := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(sealed, sealPrefix))
	for name, s := range map[string]string{
		"no prefix":     strings.TrimPrefix(sealed, sealPrefix),
		"not base64":    sealPrefix + "!!!",
		"too short":     sealPrefix + base64.RawURLEncoding.EncodeToString(blob[:20]),
		"no nonce":      sealPrefix + base64.RawURLEncoding.EncodeToString(blob[:40]),
		"changed":       sealPrefix + base64.RawURLEncoding.EncodeToString(append(bytes.Clone(blob[:len(blob)-1]), blob[len(blob)-1]^1)),
		"another kid":   "",
		"another node":  "",
		"another key":   "",
		"low-order key": sealPrefix + base64.RawURLEncoding.EncodeToString(append(make([]byte, 32), blob[32:]...)),
	} {
		var err error
		switch name {
		case "another kid":
			_, err = nk.OpenFromNode("n_a", "kid2", sealed)
		case "another node":
			_, err = nk.OpenFromNode("n_b", "kid1", sealed)
		case "another key":
			other, _ := NewNodeKey()
			_, err = other.OpenFromNode("n_a", "kid1", sealed)
		default:
			_, err = nk.OpenFromNode("n_a", "kid1", s)
		}
		if !errors.Is(err, ErrNotForNode) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// An exported key that is damaged, or made up, is refused.
func TestImportKeyRefusals(t *testing.T) {
	old := scryptN
	scryptN = 1 << 10
	defer func() { scryptN = old }()
	k, err := NewClusterKey()
	if err != nil {
		t.Fatal(err)
	}
	pass := []byte("correct horse battery staple")
	text, err := ExportKey(k, pass)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ExportKey(k, nil); err == nil {
		t.Error("exported with an empty passphrase")
	}
	change := func(fn func(m map[string]any)) string {
		var m map[string]any
		if err := json.Unmarshal([]byte(text), &m); err != nil {
			t.Fatal(err)
		}
		fn(m)
		out, _ := json.Marshal(m)
		return string(out)
	}
	kdf := func(m map[string]any) map[string]any { return m["kdf"].(map[string]any) }
	for name, c := range map[string]struct {
		text string
		want error
		msg  string
	}{
		"not json":     {text: "not json", msg: "not a cluster key exported"},
		"other format": {text: change(func(m map[string]any) { m["format"] = "other" }), msg: "not a cluster key exported"},
		"other kdf":    {text: change(func(m map[string]any) { kdf(m)["name"] = "argon2" }), msg: "key derivation"},
		"huge cost":    {text: change(func(m map[string]any) { kdf(m)["n"] = 1 << 30 }), msg: "key derivation"},
		"bad salt":     {text: change(func(m map[string]any) { kdf(m)["salt"] = "!!" }), want: ErrPassphrase},
		"bad sealed":   {text: change(func(m map[string]any) { m["sealed"] = "!!" }), want: ErrPassphrase},
		"short sealed": {text: change(func(m map[string]any) { m["sealed"] = "AAAA" }), want: ErrPassphrase},
		"other kid":    {text: change(func(m map[string]any) { m["kid"] = "0000aaaa" }), want: ErrPassphrase},
	} {
		_, err := ImportKey(c.text, pass)
		if c.want != nil && !errors.Is(err, c.want) || c.msg != "" && (err == nil || !strings.Contains(err.Error(), c.msg)) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := ImportKey(text, []byte("wrong")); !errors.Is(err, ErrPassphrase) {
		t.Errorf("wrong passphrase: %v", err)
	}
}

// The node key is made once and read back; key files that are damaged
// are errors, never a missing key.
func TestKeyStoreDamagedFiles(t *testing.T) {
	dir := t.TempDir()
	master := secrets.NewKeyring(dir)
	ks := KeyStore{Dir: dir, Master: master}
	n1, err := ks.NodeKey()
	if err != nil {
		t.Fatal(err)
	}
	n2, err := ks.NodeKey()
	if err != nil || n2.PublicText() != n1.PublicText() {
		t.Fatalf("the node key changed: %v", err)
	}
	write := func(path string, f keyFile) {
		t.Helper()
		data, _ := json.Marshal(f)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	seal := func(field, plain string) string {
		t.Helper()
		s, err := master.Seal(field, plain)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	for name, plain := range map[string]string{"not base64": "!!", "wrong size": base64.StdEncoding.EncodeToString([]byte("short"))} {
		write(NodeKeyPath(dir), keyFile{Format: 1, Key: seal(nodeKeyField, plain)})
		if _, err := ks.LoadNodeKey(); err == nil || !strings.Contains(err.Error(), "damaged") {
			t.Errorf("node key %s: %v", name, err)
		}
	}
	write(NodeKeyPath(dir), keyFile{Format: 1, Key: "enc:v1:nothing"})
	if _, err := ks.NodeKey(); err == nil {
		t.Error("a node key that cannot be opened was replaced")
	}

	k, _ := NewClusterKey()
	other, _ := NewClusterKey()
	path := ClusterKeyPath(dir, k.ID())
	for name, c := range map[string]struct {
		plain, want string
	}{
		"not base64":    {"!!", "damaged"},
		"wrong size":    {base64.StdEncoding.EncodeToString([]byte("short")), "bytes"},
		"another key":   {other.Text(), "holds cluster key " + other.ID()},
		"cannot open":   {"", ""},
		"not json file": {"", ""},
	} {
		switch name {
		case "cannot open":
			write(path, keyFile{Format: 1, KID: k.ID(), Key: "enc:v1:nothing"})
		case "not json file":
			if err := os.WriteFile(path, []byte("{"), 0o600); err != nil {
				t.Fatal(err)
			}
		default:
			write(path, keyFile{Format: 1, KID: k.ID(), Key: seal(clusterKeyField(k.ID()), c.plain)})
		}
		_, err := ks.ClusterKeys()
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("cluster key %s: %v", name, err)
		}
	}
}
