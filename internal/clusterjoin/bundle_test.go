// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package clusterjoin

import (
	"bytes"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/shared"
)

func testBundle(t *testing.T) *Bundle {
	t.Helper()
	k, err := shared.NewClusterKey()
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := base64.StdEncoding.DecodeString(k.Text())
	return &Bundle{ClusterID: "c_1", ClusterName: "Signalith", IndexPrefix: "signalith",
		OpenSearch: OpenSearch{URL: "https://os.plant.local:9200", URLs: []string{"https://os2.plant.local:9200"}, CAPEM: "-----BEGIN CERTIFICATE-----",
			Username: "signalith", Password: "pw-in-the-bundle", Shared: true},
		KID: k.ID(), ClusterKey: raw, NodeName: "siem-c", Listen: "0.0.0.0:8443",
		Syslog: &SyslogDefaults{UDP: "0.0.0.0:514"}, IssuerVersion: "1.5.0", Level: shared.LevelMax}
}

func TestBundleRoundTrip(t *testing.T) {
	tok := newToken(t)
	nk, _ := shared.NewNodeKey()
	b := testBundle(t)
	sealed, err := Seal(b, nk.Public(), "n_c", tok.ID, tok.Secret)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(sealed, "pw-in-the-bundle") || strings.Contains(sealed, "Signalith") {
		t.Error("the sealed bundle shows its contents")
	}
	got, err := Open(nk, "n_c", tok.ID, tok.Secret, sealed)
	if err != nil {
		t.Fatal(err)
	}
	if got.KID != b.KID || !bytes.Equal(got.ClusterKey, b.ClusterKey) || got.OpenSearch.Password != "pw-in-the-bundle" ||
		got.Syslog == nil || got.Syslog.UDP != "0.0.0.0:514" || len(got.OpenSearch.URLs) != 1 || !got.OpenSearch.Shared {
		t.Errorf("opened %+v", got)
	}
	k, err := shared.ClusterKeyFrom(got.ClusterKey)
	if err != nil || k.ID() != b.KID {
		t.Errorf("the cluster key in the bundle is %v, %v", k, err)
	}
	got.Clear()
	if got.ClusterKey != nil || got.OpenSearch.Password != "" {
		t.Error("Clear left secrets")
	}
	// Two seals of one bundle differ (ephemeral key, nonce).
	again, _ := Seal(b, nk.Public(), "n_c", tok.ID, tok.Secret)
	if again == sealed {
		t.Error("two seals are the same")
	}
}

func TestBundleOpenRefuses(t *testing.T) {
	tok := newToken(t)
	nk, _ := shared.NewNodeKey()
	other, _ := shared.NewNodeKey()
	sealed, err := Seal(testBundle(t), nk.Public(), "n_c", tok.ID, tok.Secret)
	if err != nil {
		t.Fatal(err)
	}
	wrongSecret, _ := NewSecret()
	otherID, _ := NewID()
	blob, _ := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(sealed, bundlePrefix))
	flipped := bytes.Clone(blob)
	flipped[len(flipped)-1] ^= 1
	cases := map[string]func() (*Bundle, error){
		"another node key": func() (*Bundle, error) { return Open(other, "n_c", tok.ID, tok.Secret, sealed) },
		"wrong secret":     func() (*Bundle, error) { return Open(nk, "n_c", tok.ID, wrongSecret, sealed) },
		"no secret":        func() (*Bundle, error) { return Open(nk, "n_c", tok.ID, nil, sealed) },
		"another node id":  func() (*Bundle, error) { return Open(nk, "n_d", tok.ID, tok.Secret, sealed) },
		"another token id": func() (*Bundle, error) { return Open(nk, "n_c", otherID, tok.Secret, sealed) },
		"changed": func() (*Bundle, error) {
			return Open(nk, "n_c", tok.ID, tok.Secret, bundlePrefix+base64.RawURLEncoding.EncodeToString(flipped))
		},
		"truncated": func() (*Bundle, error) { return Open(nk, "n_c", tok.ID, tok.Secret, sealed[:40]) },
		"no prefix": func() (*Bundle, error) {
			return Open(nk, "n_c", tok.ID, tok.Secret, strings.TrimPrefix(sealed, bundlePrefix))
		},
		"sealed to a node": func() (*Bundle, error) { return Open(nk, "n_c", tok.ID, tok.Secret, mustSealToNode(t, nk)) },
		"not base64":       func() (*Bundle, error) { return Open(nk, "n_c", tok.ID, tok.Secret, bundlePrefix+"***") },
		"empty":            func() (*Bundle, error) { return Open(nk, "n_c", tok.ID, tok.Secret, "") },
		"low order point": func() (*Bundle, error) {
			return Open(nk, "n_c", tok.ID, tok.Secret, bundlePrefix+base64.RawURLEncoding.EncodeToString(make([]byte, 80)))
		},
		"too long to read": func() (*Bundle, error) {
			return Open(nk, "n_c", tok.ID, tok.Secret, bundlePrefix+strings.Repeat("A", maxSealed+1))
		},
		"node key only, no": func() (*Bundle, error) { return Open(nk, "n_c", tok.ID, make([]byte, SecretSize), sealed) },
	}
	for name, open := range cases {
		if b, err := open(); !errors.Is(err, ErrBundle) || b != nil {
			t.Errorf("%s: Open = %v, %v", name, b, err)
		}
	}
	// Seal checks what it is given.
	if _, err := Seal(testBundle(t), nk.Public()[:31], "n_c", tok.ID, tok.Secret); err == nil {
		t.Error("sealed to a short key")
	}
	if _, err := Seal(testBundle(t), nk.Public(), "n_c", tok.ID, tok.Secret[:16]); err == nil {
		t.Error("sealed with a short secret")
	}
	if _, err := Seal(testBundle(t), nk.Public(), "", tok.ID, tok.Secret); err == nil {
		t.Error("sealed without a node id")
	}
}

// mustSealToNode seals a value to nk the way approval does, which is not
// a bundle.
func mustSealToNode(t *testing.T, nk *shared.NodeKey) string {
	t.Helper()
	s, err := shared.SealToNode(nk.Public(), "n_c", "kid", []byte("{}"))
	if err != nil {
		t.Fatal(err)
	}
	return s
}
