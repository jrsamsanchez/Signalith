// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package okta

import (
	"bytes"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"regexp"
	"strings"
)

// minRSABits is the smallest RSA key Signalith signs with.
const minRSABits = 2048

// maxKeyText caps the text of a private key: a 4096-bit RSA key as a JWK
// is about 3 KB.
const maxKeyText = 16 << 10

// signingKey is the private key of the service app, which signs the
// client assertion Okta checks with the public key it keeps for the app.
type signingKey struct {
	key crypto.Signer
	alg string // RS256 or ES256
	kid string // from a JWK; "" for PEM
}

// pemRe finds a PEM block in text whose line breaks may have been lost
// on the way, as a password field drops them.
var pemRe = regexp.MustCompile(`-----BEGIN ([A-Z ]+)-----([A-Za-z0-9+/=\s]*)-----END ([A-Z ]+)-----`)

// ParsePrivateKey reads the service app's private key: PEM (PKCS #8, or
// an RSA or EC key in its own format), as Okta's admin console shows it
// on its PEM tab, or a JSON Web Key, as it shows by default. An RSA key
// has at least 2,048 bits, and an EC key is on P-256. It returns the
// key's ID when a JWK names one.
func ParsePrivateKey(text string) (crypto.Signer, string, error) {
	k, err := parseKey(text)
	if err != nil {
		return nil, "", err
	}
	return k.key, k.kid, nil
}

func parseKey(text string) (*signingKey, error) {
	text = strings.TrimSpace(text)
	if text == "" {
		return nil, errors.New("no private key")
	}
	if len(text) > maxKeyText {
		return nil, fmt.Errorf("the private key is longer than %d KB", maxKeyText>>10)
	}
	if strings.HasPrefix(text, "{") {
		return parseJWK(text)
	}
	m := pemRe.FindStringSubmatch(text)
	if m == nil {
		return nil, errors.New("the private key is neither PEM (-----BEGIN PRIVATE KEY-----) nor a JSON Web Key ({\"kty\": ...})")
	}
	if m[1] != m[3] {
		return nil, errors.New("the private key's BEGIN and END lines do not match")
	}
	der, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(m[2]), ""))
	if err != nil {
		return nil, errors.New("the private key's PEM text is not valid base64")
	}
	var key any
	switch m[1] {
	case "PRIVATE KEY":
		key, err = x509.ParsePKCS8PrivateKey(der)
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(der)
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(der)
	case "ENCRYPTED PRIVATE KEY":
		return nil, errors.New("the private key is encrypted with a passphrase: enter it without one, as Okta generates it")
	case "PUBLIC KEY", "RSA PUBLIC KEY", "CERTIFICATE":
		return nil, errors.New("that is the public key or a certificate: enter the private key")
	default:
		return nil, fmt.Errorf("a PEM %s is not a private key", strings.ToLower(m[1]))
	}
	if err != nil {
		return nil, errors.New("the private key's PEM does not hold a valid key")
	}
	return checkKey(key, "")
}

// jwk is a private JSON Web Key.
type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	// RSA
	N, E, D, P, Q, DP, DQ, QI string
	// EC
	Crv, X, Y string
}

func (k *jwk) UnmarshalJSON(b []byte) error {
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return err
	}
	s := func(name string) string { v, _ := m[name].(string); return v }
	*k = jwk{Kty: s("kty"), Kid: s("kid"), N: s("n"), E: s("e"), D: s("d"), P: s("p"), Q: s("q"), DP: s("dp"),
		DQ: s("dq"), QI: s("qi"), Crv: s("crv"), X: s("x"), Y: s("y")}
	return nil
}

func b64int(s string) (*big.Int, error) {
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
	if err != nil || len(b) == 0 {
		return nil, errors.New("a number in the JSON Web Key is not valid base64url")
	}
	return new(big.Int).SetBytes(b), nil
}

func parseJWK(text string) (*signingKey, error) {
	var k jwk
	if err := json.Unmarshal([]byte(text), &k); err != nil {
		return nil, errors.New("the private key looks like a JSON Web Key but is not valid JSON")
	}
	if k.D == "" {
		return nil, errors.New("that JSON Web Key is a public key: enter the private key (it has a \"d\")")
	}
	nums := func(names ...string) ([]*big.Int, error) {
		vals := map[string]string{"n": k.N, "e": k.E, "d": k.D, "p": k.P, "q": k.Q, "x": k.X, "y": k.Y}
		var out []*big.Int
		for _, n := range names {
			v, err := b64int(vals[n])
			if err != nil {
				return nil, fmt.Errorf("the JSON Web Key's %q: %w", n, err)
			}
			out = append(out, v)
		}
		return out, nil
	}
	switch k.Kty {
	case "RSA":
		v, err := nums("n", "e", "d", "p", "q")
		if err != nil {
			return nil, err
		}
		if !v[1].IsInt64() || v[1].Int64() < 3 || v[1].Int64() > 1<<31-1 {
			return nil, errors.New("the JSON Web Key's exponent is not valid")
		}
		key := &rsa.PrivateKey{PublicKey: rsa.PublicKey{N: v[0], E: int(v[1].Int64())}, D: v[2], Primes: []*big.Int{v[3], v[4]}}
		if err := key.Validate(); err != nil {
			return nil, errors.New("the JSON Web Key is not a valid RSA key")
		}
		key.Precompute()
		return checkKey(key, k.Kid)
	case "EC":
		if k.Crv != "P-256" {
			return nil, fmt.Errorf("an EC key on %s is not supported: use RSA or P-256", k.Crv)
		}
		v, err := nums("x", "y", "d")
		if err != nil {
			return nil, err
		}
		if v[0].BitLen() > 256 || v[1].BitLen() > 256 || v[2].BitLen() > 256 {
			return nil, errors.New("the JSON Web Key is not a valid P-256 key")
		}
		d := make([]byte, 32)
		v[2].FillBytes(d)
		priv, err := ecdh.P256().NewPrivateKey(d)
		if err != nil {
			return nil, errors.New("the JSON Web Key is not a valid P-256 key")
		}
		// The private number must give the public point.
		pub := make([]byte, 65)
		pub[0] = 4
		v[0].FillBytes(pub[1:33])
		v[1].FillBytes(pub[33:])
		if !bytes.Equal(priv.PublicKey().Bytes(), pub) {
			return nil, errors.New("the JSON Web Key's private and public parts do not match")
		}
		key := &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: elliptic.P256(), X: v[0], Y: v[1]}, D: v[2]}
		return checkKey(key, k.Kid)
	}
	return nil, fmt.Errorf("a JSON Web Key of type %q is not supported: use RSA", k.Kty)
}

// checkKey makes a signing key of a parsed private key.
func checkKey(key any, kid string) (*signingKey, error) {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		if k.N.BitLen() < minRSABits {
			return nil, fmt.Errorf("the RSA key has %d bits: use one of at least %d", k.N.BitLen(), minRSABits)
		}
		return &signingKey{key: k, alg: "RS256", kid: kid}, nil
	case *ecdsa.PrivateKey:
		if k.Curve != elliptic.P256() {
			return nil, errors.New("an EC key not on P-256 is not supported: use RSA or P-256")
		}
		return &signingKey{key: k, alg: "ES256", kid: kid}, nil
	}
	return nil, errors.New("the private key is neither RSA nor EC")
}

// b64 is base64url without padding, as JWTs write their parts.
func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// randomID is a random identifier for a JWT (jti), so Okta can refuse one
// it has seen.
func randomID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

// signJWT returns the compact JWT of header and claims, signed with key
// by alg.
func signJWT(key crypto.Signer, alg string, header, claims map[string]any) (string, error) {
	header["alg"] = alg
	h, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	c, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signed := b64(h) + "." + b64(c)
	sum := sha256.Sum256([]byte(signed))
	var sig []byte
	switch k := key.(type) {
	case *rsa.PrivateKey:
		sig, err = rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, sum[:])
	case *ecdsa.PrivateKey:
		// JWS writes an ECDSA signature as r and s, 32 bytes each.
		r, s, e := ecdsa.Sign(rand.Reader, k, sum[:])
		if e != nil {
			return "", e
		}
		sig = make([]byte, 64)
		r.FillBytes(sig[:32])
		s.FillBytes(sig[32:])
	default:
		return "", errors.New("unsupported key")
	}
	if err != nil {
		return "", err
	}
	return signed + "." + b64(sig), nil
}

// publicJWK is an EC P-256 key's public part as a JWK, for a DPoP
// proof's header.
func publicJWK(k *ecdsa.PrivateKey) map[string]any {
	x, y := make([]byte, 32), make([]byte, 32)
	k.X.FillBytes(x)
	k.Y.FillBytes(y)
	return map[string]any{"kty": "EC", "crv": "P-256", "x": b64(x), "y": b64(y)}
}
