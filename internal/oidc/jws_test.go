// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"strings"
	"testing"
)

func enc(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func fixed(n *big.Int, size int) []byte {
	b := make([]byte, size)
	n.FillBytes(b)
	return b
}

// sign makes a compact JWS of payload with key by alg.
func sign(t *testing.T, alg, kid string, extra map[string]any, key crypto.Signer, payload string) string {
	t.Helper()
	h := map[string]any{"alg": alg, "kid": kid}
	for k, v := range extra {
		h[k] = v
	}
	hb, _ := json.Marshal(h)
	signed := enc(hb) + "." + enc([]byte(payload))
	hash, _ := hashFor(alg)
	sum := digest(hash, []byte(signed))
	var sig []byte
	var err error
	switch k := key.(type) {
	case *rsa.PrivateKey:
		if alg[:2] == "PS" {
			sig, err = rsa.SignPSS(rand.Reader, k, hash, sum, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
		} else {
			sig, err = rsa.SignPKCS1v15(rand.Reader, k, hash, sum)
		}
	case *ecdsa.PrivateKey:
		var r, s *big.Int
		r, s, err = ecdsa.Sign(rand.Reader, k, sum)
		size := (k.Curve.Params().BitSize + 7) / 8
		sig = append(fixed(r, size), fixed(s, size)...)
	}
	if err != nil {
		t.Fatal(err)
	}
	return signed + "." + enc(sig)
}

func rsaJWK(k *rsa.PrivateKey, kid, alg string) JWK {
	return JWK{Kty: "RSA", Kid: kid, Alg: alg, N: enc(k.N.Bytes()), E: enc(big.NewInt(int64(k.E)).Bytes())}
}

func ecJWK(k *ecdsa.PrivateKey, kid, crv string) JWK {
	size := (k.Curve.Params().BitSize + 7) / 8
	return JWK{Kty: "EC", Kid: kid, Crv: crv, X: enc(fixed(k.X, size)), Y: enc(fixed(k.Y, size))}
}

func TestVerifyJWSAlgorithms(t *testing.T) {
	rk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ecs := map[string]*ecdsa.PrivateKey{}
	for crv, c := range map[string]elliptic.Curve{"P-256": elliptic.P256(), "P-384": elliptic.P384(), "P-521": elliptic.P521()} {
		k, err := ecdsa.GenerateKey(c, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		ecs[crv] = k
	}
	set := JWKS{Keys: []JWK{
		{Kty: "RSA", Kid: "enc", Use: "enc", N: enc(rk.N.Bytes()), E: "AQAB"},
		rsaJWK(rk, "r1", ""),
		ecJWK(ecs["P-256"], "e256", "P-256"), ecJWK(ecs["P-384"], "e384", "P-384"), ecJWK(ecs["P-521"], "e521", "P-521"),
	}}
	for _, c := range []struct {
		alg, kid string
		key      crypto.Signer
	}{
		{"RS256", "r1", rk}, {"RS384", "r1", rk}, {"RS512", "r1", rk}, {"PS256", "r1", rk}, {"PS384", "r1", rk}, {"PS512", "r1", rk},
		{"ES256", "e256", ecs["P-256"]}, {"ES384", "e384", ecs["P-384"]}, {"ES512", "e521", ecs["P-521"]},
		// No key ID: every key is tried.
		{"ES384", "", ecs["P-384"]},
	} {
		got, err := VerifyJWS(sign(t, c.alg, c.kid, nil, c.key, `{"sub":"alice"}`), set, nil)
		if err != nil || string(got) != `{"sub":"alice"}` {
			t.Errorf("%s/%s: %q %v", c.alg, c.kid, got, err)
		}
	}

	good := sign(t, "RS256", "r1", nil, rk, `{}`)
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	for name, c := range map[string]struct {
		token string
		set   JWKS
		algs  []string
		want  string
	}{
		"not accepted here": {good, set, []string{"ES256"}, "not accepted"},
		"hmac":              {enc([]byte(`{"alg":"HS256"}`)) + ".e30.AA", set, nil, "not accepted"},
		"critical":          {sign(t, "RS256", "r1", map[string]any{"crit": []string{"exp"}}, rk, `{}`), set, nil, "critical"},
		"unknown kid":       {sign(t, "RS256", "r9", nil, rk, `{}`), set, nil, ErrUnknownKey.Error()},
		"wrong key":         {sign(t, "ES256", "e256", nil, other, `{}`), set, nil, "does not match"},
		"key for another":   {good, JWKS{Keys: []JWK{rsaJWK(rk, "r1", "RS512")}}, nil, "does not match"},
		"bad token":         {"a.b", set, nil, "not a signed JWT"},
	} {
		_, err := VerifyJWS(c.token, c.set, c.algs)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", name, err, c.want)
		}
	}
	if _, err := VerifyJWS(sign(t, "RS256", "r9", nil, rk, `{}`), set, nil); !errors.Is(err, ErrUnknownKey) {
		t.Errorf("unknown key = %v", err)
	}
}

func TestTokenAndKeyShapes(t *testing.T) {
	for _, c := range []struct{ token, want string }{
		{strings.Repeat("a", maxTokenSize+1), "too large"},
		{"***.e30.AA", "header is not base64url"},
		{enc([]byte("nope")) + ".e30.AA", "header is not JSON"},
		{"e30.***.AA", "payload is not base64url"},
		{"e30.e30.***", "signature is not base64url"},
	} {
		if _, _, _, _, err := splitToken(c.token); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%.20s: %v, want %q", c.token, err, c.want)
		}
	}
	rk, _ := rsa.GenerateKey(rand.Reader, 2048)
	for _, c := range []struct {
		k    JWK
		want string
	}{
		{JWK{Kty: "RSA", N: "***", E: "AQAB"}, "modulus"},
		{JWK{Kty: "RSA", N: enc(rk.N.Bytes()), E: enc([]byte{1, 0, 0, 0, 1})}, "exponent"},
		{JWK{Kty: "RSA", N: enc(rk.N.Bytes()), E: ""}, "exponent"},
		{JWK{Kty: "EC", Crv: "secp256k1"}, "unsupported curve"},
		{JWK{Kty: "OKP"}, "unsupported key type"},
	} {
		if _, err := c.k.publicKey(); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%+v: %v, want %q", c.k, err, c.want)
		}
	}

	ek, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	for _, c := range []struct {
		alg  string
		pub  crypto.PublicKey
		sig  []byte
		want string
	}{
		{"RS999", &rk.PublicKey, nil, "unsupported algorithm"},
		{"XX256", &rk.PublicKey, nil, "unsupported algorithm"},
		{"ES256", &rk.PublicKey, nil, "needs an EC key"},
		{"RS256", &ek.PublicKey, nil, "needs an RSA key"},
		{"ES384", &ek.PublicKey, nil, "needs a P-384 key"},
		{"ES256", &ek.PublicKey, []byte{1, 2, 3}, "wrong length"},
	} {
		if err := verifySignature(c.alg, c.pub, "a.b", c.sig); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", c.alg, err, c.want)
		}
	}
}

func TestSmallHelpers(t *testing.T) {
	if PresetFor("no-such").ID != Other || PresetFor(Presets[0].ID).ID != Presets[0].ID {
		t.Error("PresetFor")
	}
	inner := errors.New("timeout")
	e := &Error{Code: "token", Message: "the token request failed", Err: inner}
	if e.Error() != "the token request failed: timeout" || !errors.Is(e, inner) {
		t.Errorf("Error = %q", e.Error())
	}
	if (&Error{Message: "plain"}).Error() != "plain" {
		t.Error("plain error")
	}
	if err := noRedirects(nil, nil); err == nil || !strings.Contains(err.Error(), "redirect") {
		t.Errorf("noRedirects = %v", err)
	}
	if (&Client{}).http() != http.DefaultClient {
		t.Error("default client")
	}
	if endpointOK("https://user@id.example/token", "https://id.example") || endpointOK("://", "https://id.example") {
		t.Error("a bad endpoint was taken")
	}
}
