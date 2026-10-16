package secrets

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestKeyAndChain(t *testing.T) {
	raw := bytes.Repeat([]byte{7}, keySize)
	k, err := NewKey(raw, "cluster key")
	if err != nil {
		t.Fatal(err)
	}
	m, _ := newMasterKey(raw)
	if k.ID() != m.id {
		t.Errorf("id %s, master key scheme %s", k.ID(), m.id)
	}
	sealed, err := k.Seal("intel.feeds[otx].password", "pw")
	if err != nil || !strings.HasPrefix(sealed, "enc:v1:"+k.ID()+":") {
		t.Fatalf("%q %v", sealed, err)
	}
	if again, _ := k.Seal("x", sealed); again != sealed {
		t.Error("sealed twice")
	}
	if plain, err := k.Open("intel.feeds[otx].password", sealed); plain != "pw" || err != nil {
		t.Errorf("open %q %v", plain, err)
	}
	if plain, err := k.Open("f", "plain text"); plain != "plain text" || err != nil {
		t.Errorf("plain %q %v", plain, err)
	}
	var oe *OpenError
	if _, err := k.Open("other.field", sealed); !errors.As(err, &oe) || oe.Reason == "" {
		t.Errorf("other field: %v", err)
	}
	if _, err := NewKey(raw[:5], "cluster key"); err == nil {
		t.Error("short key")
	}

	// A chain opens a value with the key that made it.
	dir := t.TempDir()
	ring := NewKeyring(dir)
	byMaster, err := ring.Seal("opensearch.password", "os-pw")
	if err != nil {
		t.Fatal(err)
	}
	ch := Chain(k, ring)
	if plain, err := ch.Open("intel.feeds[otx].password", sealed); plain != "pw" || err != nil {
		t.Errorf("cluster value %q %v", plain, err)
	}
	if plain, err := ch.Open("opensearch.password", byMaster); plain != "os-pw" || err != nil {
		t.Errorf("master value %q %v", plain, err)
	}
	// The opener is picked by the key id, whatever the order: a value of
	// the cluster key opens even when the master key file cannot be read.
	if plain, err := Chain(ring, k).Open("intel.feeds[otx].password", sealed); plain != "pw" || err != nil {
		t.Errorf("ring first: %q %v", plain, err)
	}
	broken := NewKeyring(t.TempDir())
	if err := os.MkdirAll(filepath.Dir(broken.DefaultPath()), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(broken.DefaultPath(), []byte("not a key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := broken.Open("opensearch.password", byMaster); err == nil || errors.As(err, new(*OpenError)) {
		t.Fatalf("a broken key file: %v", err)
	}
	if plain, err := Chain(broken, k).Open("intel.feeds[otx].password", sealed); plain != "pw" || err != nil {
		t.Errorf("broken ring first: %q %v", plain, err)
	}
	// One its key opens but finds changed is not tried further.
	if _, err := ch.Open("another.setting", sealed); !errors.As(err, &oe) || oe.Reason == "" {
		t.Errorf("changed: %v", err)
	}
	// Nobody has the key.
	other, _ := NewKey(bytes.Repeat([]byte{9}, keySize), "cluster key")
	foreign, _ := other.Seal("f", "v")
	_, err = ch.Open("f", foreign)
	if !errors.As(err, &oe) || oe.KeyID != other.ID() {
		t.Errorf("foreign: %v", err)
	}
	if !strings.Contains(err.Error(), other.ID()) {
		t.Errorf("message %q", err)
	}
	_, err = k.Open("f", foreign)
	if err == nil || !strings.Contains(err.Error(), "cluster key "+other.ID()) || !strings.Contains(err.Error(), "the cluster key here is "+k.ID()) {
		t.Errorf("message %v", err)
	}
}
