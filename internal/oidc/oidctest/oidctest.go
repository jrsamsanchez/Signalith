// Package oidctest is a small OpenID Connect provider for tests: discovery,
// an authorization endpoint that signs in whoever the test says, a token
// endpoint that checks the client secret and the PKCE verifier, a key set
// and userinfo. Tests can break any part of it to see Signalith refuse.
package oidctest

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// Provider is a running mock provider.
type Provider struct {
	*httptest.Server
	// Issuer is the provider's issuer, its server's address.
	Issuer       string
	ClientID     string
	ClientSecret string

	mu sync.Mutex
	// Claims are added to (or replace) the ID token's claims of the next
	// sign-ins; UserInfo is what the userinfo endpoint adds.
	Claims   map[string]any
	UserInfo map[string]any
	// Subject is the sub of the next sign-ins.
	Subject string
	// Break lists what to get wrong: "alg-none", "hs256", "wrong-key",
	// "wrong-issuer", "wrong-audience", "expired", "future", "no-nonce",
	// "wrong-nonce", "discovery-issuer", "no-s256", "token-error",
	// "userinfo-other".
	Break map[string]bool
	// AuthMethods is token_endpoint_auth_methods_supported.
	AuthMethods []string
	// Requests counts the requests to each path.
	Requests map[string]int
	// LastTokenForm is the last token request's form, and LastBasic its
	// Basic credentials.
	LastTokenForm url.Values
	LastBasic     [2]string

	key   *rsa.PrivateKey
	other *rsa.PrivateKey
	ec    *ecdsa.PrivateKey
	// UseEC signs with the EC key (ES256).
	UseEC bool
	codes map[string]grant
}

type grant struct {
	clientID, redirect, challenge, nonce string
}

var (
	keyOnce sync.Once
	keys    [2]*rsa.PrivateKey
)

// rsaKeys makes two RSA keys once per test binary: generating them is
// slow under -race.
func rsaKeys() [2]*rsa.PrivateKey {
	keyOnce.Do(func() {
		for i := range keys {
			k, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				panic(err)
			}
			keys[i] = k
		}
	})
	return keys
}

// New starts a provider over HTTPS, stopped when the test ends. Its
// Client() trusts it.
func New(t testing.TB) *Provider {
	t.Helper()
	ks := rsaKeys()
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p := &Provider{ClientID: "signalith-test", ClientSecret: "s3cret+/=&value", Subject: "00u1abcd",
		Claims: map[string]any{}, UserInfo: map[string]any{}, Break: map[string]bool{}, Requests: map[string]int{},
		key: ks[0], other: ks[1], ec: ec, codes: map[string]grant{}}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", p.discovery)
	mux.HandleFunc("GET /authorize", p.authorize)
	mux.HandleFunc("POST /token", p.token)
	mux.HandleFunc("GET /keys", p.jwks)
	mux.HandleFunc("GET /userinfo", p.userinfo)
	p.Server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.mu.Lock()
		p.Requests[r.URL.Path]++
		p.mu.Unlock()
		mux.ServeHTTP(w, r)
	}))
	t.Cleanup(p.Close)
	p.Issuer = p.URL
	return p
}

// Set changes the provider under its lock.
func (p *Provider) Set(fn func(p *Provider)) {
	p.mu.Lock()
	defer p.mu.Unlock()
	fn(p)
}

// Count returns how many requests a path had.
func (p *Provider) Count(path string) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.Requests[path]
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (p *Provider) discovery(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	defer p.mu.Unlock()
	iss := p.Issuer
	if p.Break["discovery-issuer"] {
		iss = "https://evil.example"
	}
	methods := []string{"S256"}
	if p.Break["no-s256"] {
		methods = []string{"plain"}
	}
	writeJSON(w, 200, map[string]any{
		"issuer": iss, "authorization_endpoint": p.URL + "/authorize", "token_endpoint": p.URL + "/token",
		"jwks_uri": p.URL + "/keys", "userinfo_endpoint": p.URL + "/userinfo",
		"response_types_supported": []string{"code"}, "code_challenge_methods_supported": methods,
		"id_token_signing_alg_values_supported": []string{"RS256", "ES256"},
		"token_endpoint_auth_methods_supported": p.AuthMethods,
	})
}

// authorize signs in at once and sends the browser back with a code.
func (p *Provider) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	p.mu.Lock()
	defer p.mu.Unlock()
	if q.Get("response_type") != "code" || q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" ||
		q.Get("client_id") != p.ClientID || !strings.Contains(" "+q.Get("scope")+" ", " openid ") {
		http.Error(w, "bad authorization request", http.StatusBadRequest)
		return
	}
	code := fmt.Sprintf("code-%d", len(p.codes)+1)
	p.codes[code] = grant{clientID: q.Get("client_id"), redirect: q.Get("redirect_uri"), challenge: q.Get("code_challenge"), nonce: q.Get("nonce")}
	back, _ := url.Parse(q.Get("redirect_uri"))
	bq := back.Query()
	bq.Set("code", code)
	bq.Set("state", q.Get("state"))
	back.RawQuery = bq.Encode()
	http.Redirect(w, r, back.String(), http.StatusFound)
}

func (p *Provider) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeJSON(w, 400, map[string]string{"error": "invalid_request"})
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.LastTokenForm = r.PostForm
	id, secret, basic := r.BasicAuth()
	if basic {
		id, _ = url.QueryUnescape(id)
		secret, _ = url.QueryUnescape(secret)
	} else {
		id, secret = r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
	}
	p.LastBasic = [2]string{}
	if basic {
		p.LastBasic = [2]string{id, secret}
	}
	g, ok := p.codes[r.PostForm.Get("code")]
	delete(p.codes, r.PostForm.Get("code"))
	sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
	switch {
	case p.Break["token-error"]:
		writeJSON(w, 400, map[string]string{"error": "invalid_grant", "error_description": "The code has expired."})
		return
	case id != p.ClientID || (p.ClientSecret != "" && secret != p.ClientSecret):
		writeJSON(w, 401, map[string]string{"error": "invalid_client"})
		return
	case !ok || g.redirect != r.PostForm.Get("redirect_uri") || base64.RawURLEncoding.EncodeToString(sum[:]) != g.challenge:
		writeJSON(w, 400, map[string]string{"error": "invalid_grant"})
		return
	}
	writeJSON(w, 200, map[string]any{"id_token": p.idToken(g.nonce), "access_token": "at-" + p.Subject, "token_type": "Bearer", "expires_in": 3600})
}

// IDToken returns an ID token as the provider would issue it now, with
// the nonce, for tests of the checks alone.
func (p *Provider) IDToken(nonce string) string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.idToken(nonce)
}

func (p *Provider) idToken(nonce string) string {
	now := time.Now()
	claims := map[string]any{"iss": p.Issuer, "sub": p.Subject, "aud": p.ClientID, "iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(), "nonce": nonce}
	for k, v := range p.Claims {
		claims[k] = v
	}
	switch {
	case p.Break["wrong-issuer"]:
		claims["iss"] = "https://evil.example"
	case p.Break["wrong-audience"]:
		claims["aud"] = "someone-else"
	case p.Break["expired"]:
		claims["exp"] = now.Add(-10 * time.Minute).Unix()
		claims["iat"] = now.Add(-70 * time.Minute).Unix()
	case p.Break["future"]:
		claims["iat"] = now.Add(10 * time.Minute).Unix()
	case p.Break["no-nonce"]:
		delete(claims, "nonce")
	case p.Break["wrong-nonce"]:
		claims["nonce"] = "not-the-nonce"
	}
	alg, kid, signer := "RS256", "rsa-1", crypto.Signer(p.key)
	if p.UseEC {
		alg, kid, signer = "ES256", "ec-1", p.ec
	}
	if p.Break["wrong-key"] {
		signer = p.other
	}
	head := map[string]any{"alg": alg, "kid": kid, "typ": "JWT"}
	switch {
	case p.Break["alg-none"]:
		head = map[string]any{"alg": "none", "typ": "JWT"}
	case p.Break["hs256"]:
		head = map[string]any{"alg": "HS256", "kid": kid, "typ": "JWT"}
	}
	return Sign(head, claims, signer)
}

// Sign makes a compact JWS of claims with header head, signed with k by
// its type (RSA PKCS #1 v1.5 or ECDSA P-256, with SHA-256) whatever the
// header says: an empty signature for alg "none", a junk one for an alg
// other than RS256 and ES256.
func Sign(head, claims map[string]any, k crypto.Signer) string {
	hb, _ := json.Marshal(head)
	cb, _ := json.Marshal(claims)
	signed := base64.RawURLEncoding.EncodeToString(hb) + "." + base64.RawURLEncoding.EncodeToString(cb)
	sum := sha256.Sum256([]byte(signed))
	var sig []byte
	switch key := k.(type) {
	case *rsa.PrivateKey:
		sig, _ = rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	case *ecdsa.PrivateKey:
		r, s, _ := ecdsa.Sign(rand.Reader, key, sum[:])
		sig = append(pad(r, 32), pad(s, 32)...)
	}
	switch head["alg"] {
	case "none":
		sig = nil
	case "RS256", "ES256":
	default:
		sig = sum[:]
	}
	return signed + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func pad(n *big.Int, size int) []byte {
	b := n.Bytes()
	return append(make([]byte, size-len(b)), b...)
}

func (p *Provider) jwks(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	defer p.mu.Unlock()
	pub := p.key.PublicKey
	e := big.NewInt(int64(pub.E)).Bytes()
	point, _ := p.ec.PublicKey.Bytes()
	writeJSON(w, 200, map[string]any{"keys": []map[string]any{
		{"kty": "RSA", "kid": "rsa-1", "use": "sig", "alg": "RS256", "n": base64.RawURLEncoding.EncodeToString(pub.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(e)},
		{"kty": "EC", "kid": "ec-1", "use": "sig", "crv": "P-256", "x": base64.RawURLEncoding.EncodeToString(point[1:33]), "y": base64.RawURLEncoding.EncodeToString(point[33:])},
	}})
}

func (p *Provider) userinfo(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if r.Header.Get("Authorization") != "Bearer at-"+p.Subject {
		writeJSON(w, 401, map[string]string{"error": "invalid_token"})
		return
	}
	out := map[string]any{"sub": p.Subject}
	if p.Break["userinfo-other"] {
		out["sub"] = "someone-else"
	}
	for k, v := range p.UserInfo {
		out[k] = v
	}
	writeJSON(w, 200, out)
}
