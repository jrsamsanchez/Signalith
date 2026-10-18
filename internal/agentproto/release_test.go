package agentproto

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"
)

func TestManifestSignature(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	data := []byte(`{"format":1,"version":"0.4.0","programs":{"linux-amd64":"` + strings.Repeat("a", 64) + `"}}`)
	sig := SignManifest(priv, data)
	m, err := VerifyManifest([]ed25519.PublicKey{other, pub}, data, sig)
	if err != nil || m.Version != "0.4.0" || m.Programs["linux-amd64"] != strings.Repeat("a", 64) {
		t.Fatalf("%+v %v", m, err)
	}
	if _, err := VerifyManifest(nil, data, sig); err != ErrNoReleaseKey {
		t.Errorf("no keys: %v", err)
	}
	if _, err := VerifyManifest([]ed25519.PublicKey{other}, data, sig); err == nil {
		t.Error("another key's signature accepted")
	}
	changed := []byte(strings.Replace(string(data), "0.4.0", "0.5.0", 1))
	if _, err := VerifyManifest([]ed25519.PublicKey{pub}, changed, sig); err == nil {
		t.Error("a changed manifest accepted")
	}
	for name, d := range map[string]string{
		"format":  `{"format":2,"version":"0.4.0","programs":{}}`,
		"version": `{"format":1,"version":"dev","programs":{}}`,
		"sha":     `{"format":1,"version":"0.4.0","programs":{"linux-amd64":"xyz"}}`,
		"json":    `{"format":1,`,
	} {
		if _, err := VerifyManifest([]ed25519.PublicKey{pub}, []byte(d), SignManifest(priv, []byte(d))); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := VerifyManifest([]ed25519.PublicKey{pub}, data, []byte("garbage")); err == nil {
		t.Error("garbage signature accepted")
	}
	keys, err := ParseKeys("# c\n" + base64.StdEncoding.EncodeToString(pub) + " # key\n")
	if err != nil || len(keys) != 1 || KeyID(keys[0]) != KeyID(pub) {
		t.Errorf("parse: %v %v", keys, err)
	}
	if _, err := ParseKeys("nope"); err == nil {
		t.Error("bad key parsed")
	}
	if len(mustKeys(releaseKeys)) != len(ReleaseKeys) {
		t.Error("release.keys")
	}
}

func TestNewer(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want bool
	}{
		{"0.4.0", "0.3.0", true}, {"0.3.0", "0.4.0", false}, {"0.3.0", "0.3.0", false},
		{"0.10.0", "0.9.9", true}, {"1.0.0", "0.99.99", true}, {"v0.4.0", "0.3.9", true},
		{"0.4.0", "0.4.0-rc.1", true}, {"0.4.0-rc.1", "0.4.0", false}, {"0.4.0-rc.2", "0.4.0-rc.1", true}, {"0.4.0-rc.10", "0.4.0-rc.9", true}, {"0.4.0-rc.9", "0.4.0-rc.10", false},
		{"0.4.0-rc", "0.4.0-beta", true}, {"0.4.0-rc.1", "0.4.0-rc", true}, {"0.4.0-rc.1", "0.4.0-1", true},
		{"0.4.0", "dev", false}, {"dev", "0.1.0", false}, {"0.4.0+abc", "0.3.0-next+123", true},
		{"0.3.0", "0.3.0-next+4a31d8b", true}, {"", "0.1.0", false},
	} {
		if got := Newer(c.a, c.b); got != c.want {
			t.Errorf("Newer(%q, %q) = %v", c.a, c.b, got)
		}
	}
}
