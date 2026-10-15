package oidc

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

// Algorithms lists the ID token signature algorithms Signalith accepts.
// Every one is asymmetric: "none" and the HMAC algorithms are refused, so
// a token cannot be signed with something the client also knows, such as
// its secret or the provider's public key.
var Algorithms = []string{"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512"}

// maxTokenSize bounds an ID token, which is far smaller in practice.
const maxTokenSize = 64 << 10

// minRSABits is the smallest RSA key a signature is checked with.
const minRSABits = 2048

// JWK is one key of a provider's JSON Web Key Set.
type JWK struct {
	Kty string `json:"kty"`
	Kid string `json:"kid,omitempty"`
	Use string `json:"use,omitempty"`
	Alg string `json:"alg,omitempty"`
	// RSA
	N string `json:"n,omitempty"`
	E string `json:"e,omitempty"`
	// EC
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
}

// JWKS is a JSON Web Key Set.
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// key is a usable public key from a JWK.
type key struct {
	kid string
	alg string // "" when the JWK does not name one
	pub crypto.PublicKey
}

// parseKeys turns a key set into the keys that can check signatures:
// RSA and EC keys not meant only for encryption. Others are skipped.
func parseKeys(set JWKS) []key {
	var out []key
	for _, k := range set.Keys {
		if k.Use != "" && k.Use != "sig" {
			continue
		}
		pub, err := k.publicKey()
		if err != nil {
			continue
		}
		out = append(out, key{kid: k.Kid, alg: k.Alg, pub: pub})
	}
	return out
}

func b64(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
}

func (k JWK) publicKey() (crypto.PublicKey, error) {
	switch k.Kty {
	case "RSA":
		n, err := b64(k.N)
		if err != nil || len(n) == 0 {
			return nil, errors.New("bad RSA modulus")
		}
		e, err := b64(k.E)
		if err != nil || len(e) == 0 || len(e) > 4 {
			return nil, errors.New("bad RSA exponent")
		}
		exp := 0
		for _, b := range e {
			exp = exp<<8 | int(b)
		}
		pub := &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: exp}
		if pub.N.BitLen() < minRSABits || exp < 3 || exp%2 == 0 {
			return nil, errors.New("RSA key too small or with a bad exponent")
		}
		return pub, nil
	case "EC":
		var curve elliptic.Curve
		switch k.Crv {
		case "P-256":
			curve = elliptic.P256()
		case "P-384":
			curve = elliptic.P384()
		case "P-521":
			curve = elliptic.P521()
		default:
			return nil, fmt.Errorf("unsupported curve %q", k.Crv)
		}
		x, err1 := b64(k.X)
		y, err2 := b64(k.Y)
		size := (curve.Params().BitSize + 7) / 8
		if err1 != nil || err2 != nil || len(x) != size || len(y) != size {
			return nil, errors.New("bad EC point")
		}
		// Uncompressed point form, which ecdsa.ParseUncompressedPublicKey
		// checks is on the curve.
		point := append(append([]byte{4}, x...), y...)
		return ecdsa.ParseUncompressedPublicKey(curve, point)
	}
	return nil, fmt.Errorf("unsupported key type %q", k.Kty)
}

// header is a JWS protected header.
type header struct {
	Alg  string   `json:"alg"`
	Kid  string   `json:"kid"`
	Typ  string   `json:"typ"`
	Crit []string `json:"crit"`
}

// splitToken decodes a compact JWS into its header, payload and
// signature, without checking anything.
func splitToken(token string) (header, []byte, []byte, string, error) {
	var h header
	if len(token) > maxTokenSize {
		return h, nil, nil, "", errors.New("the token is too large")
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return h, nil, nil, "", errors.New("the token is not a signed JWT")
	}
	hb, err := b64(parts[0])
	if err != nil {
		return h, nil, nil, "", errors.New("the token's header is not base64url")
	}
	if err := json.Unmarshal(hb, &h); err != nil {
		return h, nil, nil, "", errors.New("the token's header is not JSON")
	}
	payload, err := b64(parts[1])
	if err != nil {
		return h, nil, nil, "", errors.New("the token's payload is not base64url")
	}
	sig, err := b64(parts[2])
	if err != nil {
		return h, nil, nil, "", errors.New("the token's signature is not base64url")
	}
	return h, payload, sig, parts[0] + "." + parts[1], nil
}

// hashFor returns the hash an algorithm signs with.
func hashFor(alg string) (crypto.Hash, bool) {
	switch alg[len(alg)-3:] {
	case "256":
		return crypto.SHA256, true
	case "384":
		return crypto.SHA384, true
	case "512":
		return crypto.SHA512, true
	}
	return 0, false
}

func digest(h crypto.Hash, data []byte) []byte {
	switch h {
	case crypto.SHA384:
		s := sha512.Sum384(data)
		return s[:]
	case crypto.SHA512:
		s := sha512.Sum512(data)
		return s[:]
	}
	s := sha256.Sum256(data)
	return s[:]
}

// verifySignature checks sig over signed with pub for alg.
func verifySignature(alg string, pub crypto.PublicKey, signed string, sig []byte) error {
	h, ok := hashFor(alg)
	if !ok {
		return fmt.Errorf("unsupported algorithm %s", alg)
	}
	sum := digest(h, []byte(signed))
	switch alg[:2] {
	case "RS", "PS":
		rk, ok := pub.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("%s needs an RSA key", alg)
		}
		if alg[:2] == "RS" {
			return rsa.VerifyPKCS1v15(rk, h, sum, sig)
		}
		return rsa.VerifyPSS(rk, h, sum, sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
	case "ES":
		ek, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("%s needs an EC key", alg)
		}
		want := map[string]string{"ES256": "P-256", "ES384": "P-384", "ES512": "P-521"}[alg]
		if ek.Curve.Params().Name != want {
			return fmt.Errorf("%s needs a %s key", alg, want)
		}
		size := (ek.Curve.Params().BitSize + 7) / 8
		if len(sig) != 2*size {
			return errors.New("the signature has the wrong length")
		}
		r := new(big.Int).SetBytes(sig[:size])
		s := new(big.Int).SetBytes(sig[size:])
		if !ecdsa.Verify(ek, sum, r, s) {
			return errors.New("the signature does not match")
		}
		return nil
	}
	return fmt.Errorf("unsupported algorithm %s", alg)
}
