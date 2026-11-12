// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package shared

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/secrets"
)

func TestNodeKeyAgreement(t *testing.T) {
	a, err := NewNodeKey()
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewNodeKey()
	if err != nil {
		t.Fatal(err)
	}
	ab, err := a.Agree(b.Public())
	if err != nil {
		t.Fatal(err)
	}
	ba, err := b.Agree(a.Public())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ab, ba) || len(ab) != 32 {
		t.Errorf("the two sides agreed on different secrets")
	}
	if _, err := a.Agree([]byte("short")); err == nil || !strings.Contains(err.Error(), "not an X25519 public key") {
		t.Errorf("Agree with a bad key = %v", err)
	}
	if _, err := SealToNode([]byte("short"), "n_a", "kid", []byte("x")); err == nil || !strings.Contains(err.Error(), "not a node key") {
		t.Errorf("SealToNode to a bad key = %v", err)
	}
}

func TestCookieKeys(t *testing.T) {
	k1, _ := NewClusterKey()
	k2, _ := NewClusterKey()
	s := NewKeySet(k1).WithCookieKeys(k2)
	if s.CookieKey(k1.ID()) != k1 || s.CookieKey(k2.ID()) != k2 {
		t.Error("CookieKey missed a key")
	}
	if s.CookieKey("nope") != nil {
		t.Error("CookieKey found an unknown key")
	}
	var none *KeySet
	if none.CookieKey(k1.ID()) != nil {
		t.Error("a nil key set has a cookie key")
	}
}

// Verify tells a MAC it cannot read from one that does not match.
func TestVerifyBadMACs(t *testing.T) {
	k, _ := NewClusterKey()
	keys := NewKeySet(k)
	e := &Envelope{Kind: "x", ID: "d1", Format: 1, Rev: 1, Body: `{}`}
	if err := Sign(k, "d1", e); err != nil {
		t.Fatal(err)
	}
	if err := Verify(keys, "d1", e); err != nil {
		t.Fatalf("a signed document: %v", err)
	}
	good := e.MAC
	for name, m := range map[string]string{
		"no colon":     "m1:" + k.ID(),
		"not base64":   "m1:" + k.ID() + ":!!!",
		"another form": "x1:abc",
		"other text":   good[:len(good)-2] + "AA",
	} {
		c := *e
		c.MAC = m
		if err := Verify(keys, "d1", &c); !errors.Is(err, ErrBadMAC) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if err := Verify(keys, "d2", e); !errors.Is(err, ErrBadMAC) {
		t.Errorf("another document's MAC: %v", err)
	}
	if got := macKID("x1:abc"); got != "" {
		t.Errorf("macKID of another form = %q", got)
	}
	if got := macKID(good); got != k.ID() {
		t.Errorf("macKID = %q, want %q", got, k.ID())
	}
}

func TestExtraRefusals(t *testing.T) {
	if _, err := MergeExtra([]byte(`[1]`), Extra{"x": json.RawMessage(`1`)}); err == nil || !strings.Contains(err.Error(), "not a JSON object") {
		t.Errorf("MergeExtra of a list = %v", err)
	}
	if _, err := MergeExtra([]byte(`null`), Extra{"x": json.RawMessage(`1`)}); err == nil {
		t.Error("MergeExtra of null")
	}
	if _, err := SplitExtra([]byte(`[`), []byte(`{}`)); err == nil {
		t.Error("SplitExtra of broken JSON")
	}
	if _, err := SplitExtra([]byte(`{}`), []byte(`[`)); err == nil {
		t.Error("SplitExtra of broken known JSON")
	}
	if _, err := MarshalExtra(func() {}, nil); err == nil {
		t.Error("MarshalExtra of a func")
	}
	var v testFeed
	if _, err := UnmarshalExtra([]byte(`{"name": 5}`), &v); err == nil {
		t.Error("UnmarshalExtra of a wrong type")
	}
	if _, err := decodeBody[testBody](`{"name": `); err == nil {
		t.Error("decodeBody of broken JSON")
	}
	b, err := decodeBody[testBody](`{"name": "n", "later": true}`)
	if err != nil || b.Name != "n" || string(b.Extra["later"]) != "true" {
		t.Errorf("decodeBody = %+v, %v", b, err)
	}
}

func TestKeyFilesReseal(t *testing.T) {
	keep := func(s secrets.Stored) (string, error) { return s.Value, nil }
	change := func(s secrets.Stored) (string, error) { return "new-" + s.Value, nil }
	boom := errors.New("no")
	fail := func(secrets.Stored) (string, error) { return "", boom }

	data := []byte(`{"format": 1, "kid": "k1", "key": "sealed"}` + "\n")
	for name, fn := range map[string]func([]byte, secrets.Reseal) ([]byte, int, error){
		"node": ResealNodeKeyFile, "cluster": ResealClusterKeyFile, "cache": ResealCacheFile,
	} {
		if _, _, err := fn([]byte("not json"), keep); err == nil || !strings.Contains(err.Error(), "not valid JSON") {
			t.Errorf("%s: broken file = %v", name, err)
		}
		out, n, err := fn(data, keep)
		if err != nil || n != 0 || !bytes.Equal(out, data) {
			t.Errorf("%s: unchanged = %q %d %v", name, out, n, err)
		}
		if _, _, err := fn(data, fail); !errors.Is(err, boom) {
			t.Errorf("%s: failing reseal = %v", name, err)
		}
	}
	out, n, err := ResealClusterKeyFile(data, change)
	if err != nil || n != 1 || !strings.Contains(string(out), `"new-sealed"`) {
		t.Errorf("cluster key resealed = %q %d %v", out, n, err)
	}
	cache := []byte(`{"format": 1, "cluster_id": "c", "prefix": "p", "sealed": "abc"}`)
	out, n, err = ResealCacheFile(cache, change)
	if err != nil || n != 1 || !strings.Contains(string(out), `"new-abc"`) {
		t.Errorf("cache resealed = %q %d %v", out, n, err)
	}
}

func TestCacheFileRefusals(t *testing.T) {
	dir := t.TempDir()
	master := secrets.NewKeyring(dir)
	c := Cache{Path: filepath.Join(dir, "shared", "cache.enc"), Master: master, ClusterID: "c1", Prefix: "s"}
	now := time.Now()
	if _, err := c.Read(now); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("no cache = %v", err)
	}
	if err := c.Remove(); err != nil {
		t.Errorf("removing no cache = %v", err)
	}
	if err := c.Write(CacheData{IndexUUID: "u", WrittenAt: now}); err != nil {
		t.Fatal(err)
	}
	if d, err := c.Read(now); err != nil || d.IndexUUID != "u" {
		t.Fatalf("Read = %+v %v", d, err)
	}
	// Another cluster's, or another prefix's.
	other := c
	other.ClusterID = "c2"
	if _, err := other.Read(now); !errors.Is(err, ErrCacheOther) {
		t.Errorf("another cluster's cache = %v", err)
	}
	// A newer version's.
	raw, _ := os.ReadFile(c.Path)
	var f map[string]any
	_ = json.Unmarshal(raw, &f)
	f["format"] = 2
	newer, _ := json.Marshal(f)
	if err := os.WriteFile(c.Path, newer, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Read(now); err == nil || !strings.Contains(err.Error(), "newer version") {
		t.Errorf("a newer cache = %v", err)
	}
	// Sealed text that is not a cache.
	sealed, err := master.Seal(cacheField("c1", "s"), "not json")
	if err != nil {
		t.Fatal(err)
	}
	f["format"], f["sealed"] = 1, sealed
	damaged, _ := json.Marshal(f)
	if err := os.WriteFile(c.Path, damaged, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Read(now); err == nil || !strings.Contains(err.Error(), "is damaged") {
		t.Errorf("a damaged cache = %v", err)
	}
	// A file in the way of the cache's folder.
	block := filepath.Join(dir, "file")
	if err := os.WriteFile(block, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	bad := Cache{Path: filepath.Join(block, "cache.enc"), Master: master, ClusterID: "c1", Prefix: "s"}
	if err := bad.Write(CacheData{}); err == nil {
		t.Error("a cache written under a file")
	}
}

func TestKeyStoreUnderAFile(t *testing.T) {
	dir := t.TempDir()
	block := filepath.Join(dir, "file")
	if err := os.WriteFile(block, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	ks := KeyStore{Dir: block, Master: secrets.NewKeyring(dir)}
	if _, err := ks.NodeKey(); err == nil {
		t.Error("a node key made under a file")
	}
	k, _ := NewClusterKey()
	if err := ks.SaveClusterKey(k); err == nil {
		t.Error("a cluster key saved under a file")
	}
	good := KeyStore{Dir: dir, Master: secrets.NewKeyring(dir)}
	if _, err := good.ClusterKeyCreated("nope"); err == nil {
		t.Error("ClusterKeyCreated of a missing key")
	}
	if err := good.SaveClusterKey(k); err != nil {
		t.Fatal(err)
	}
	if at, err := good.ClusterKeyCreated(k.ID()); err != nil || time.Since(at) > time.Minute {
		t.Errorf("ClusterKeyCreated = %v %v", at, err)
	}
}

// The base64 the seal uses keeps nothing but what it was given.
func TestOpenFromNodeShortBlob(t *testing.T) {
	nk, _ := NewNodeKey()
	short := sealPrefix + base64.RawURLEncoding.EncodeToString(make([]byte, 40))
	if _, err := nk.OpenFromNode("n_a", "k", short); !errors.Is(err, ErrNotForNode) {
		t.Errorf("a short blob = %v", err)
	}
}
