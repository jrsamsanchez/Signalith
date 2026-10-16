package okta

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/detect"
	"github.com/jrsamsanchez/signalith/internal/ingest"
)

func pemOf(t *testing.T, kind string, der []byte) string {
	t.Helper()
	return string(pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: der}))
}

func newRSA(t *testing.T, bits int) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func newEC(t *testing.T, c elliptic.Curve) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(c, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func pkcs8(t *testing.T, k any) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func num(b *big.Int, size int) string {
	out := make([]byte, size)
	b.FillBytes(out)
	return b64(out)
}

func TestParsePrivateKey(t *testing.T) {
	rk := newRSA(t, 2048)
	ek := newEC(t, elliptic.P256())
	sec1, err := x509.MarshalECPrivateKey(ek)
	if err != nil {
		t.Fatal(err)
	}
	rsaPEM := pemOf(t, "PRIVATE KEY", pkcs8(t, rk))
	rsaJWK, _ := json.Marshal(map[string]string{"kty": "RSA", "kid": "key-1", "n": b64(rk.N.Bytes()), "e": "AQAB",
		"d": b64(rk.D.Bytes()), "p": b64(rk.Primes[0].Bytes()), "q": b64(rk.Primes[1].Bytes())})
	ecJWK, _ := json.Marshal(map[string]string{"kty": "EC", "crv": "P-256", "x": num(ek.X, 32), "y": num(ek.Y, 32), "d": num(ek.D, 32)})
	good := []struct {
		name, text, alg, kid string
	}{
		{"pkcs8 rsa", rsaPEM, "RS256", ""},
		// A password field drops the line breaks.
		{"pkcs8 rsa on one line", strings.ReplaceAll(rsaPEM, "\n", ""), "RS256", ""},
		{"pkcs8 rsa with spaces", strings.ReplaceAll(rsaPEM, "\n", " "), "RS256", ""},
		{"pkcs1 rsa", pemOf(t, "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(rk)), "RS256", ""},
		{"pkcs8 ec", pemOf(t, "PRIVATE KEY", pkcs8(t, ek)), "ES256", ""},
		{"sec1 ec", pemOf(t, "EC PRIVATE KEY", sec1), "ES256", ""},
		{"rsa jwk", string(rsaJWK), "RS256", "key-1"},
		{"ec jwk", string(ecJWK), "ES256", ""},
	}
	for _, c := range good {
		k, err := parseKey(c.text)
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		if k.alg != c.alg || k.kid != c.kid {
			t.Errorf("%s: alg %s kid %q", c.name, k.alg, k.kid)
		}
	}

	small := newRSA(t, 1024)
	other := newEC(t, elliptic.P256())
	badEC, _ := json.Marshal(map[string]string{"kty": "EC", "crv": "P-256", "x": num(ek.X, 32), "y": num(ek.Y, 32), "d": num(other.D, 32)})
	pubDER, _ := x509.MarshalPKIXPublicKey(&rk.PublicKey)
	bad := []struct{ name, text, want string }{
		{"empty", "  ", "no private key"},
		{"too long", strings.Repeat("A", maxKeyText+1), "longer"},
		{"garbage", "not a key", "neither PEM"},
		{"public key", pemOf(t, "PUBLIC KEY", pubDER), "public key"},
		{"encrypted", pemOf(t, "ENCRYPTED PRIVATE KEY", []byte("x")), "passphrase"},
		{"small rsa", pemOf(t, "PRIVATE KEY", pkcs8(t, small)), "1024 bits"},
		{"p384", pemOf(t, "PRIVATE KEY", pkcs8(t, newEC(t, elliptic.P384()))), "P-256"},
		{"bad base64", "-----BEGIN PRIVATE KEY-----\n@@@@\n-----END PRIVATE KEY-----", "neither PEM"},
		{"bad der", "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----", "valid key"},
		{"mismatched", "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----", "do not match"},
		{"public jwk", `{"kty":"RSA","n":"AQAB","e":"AQAB"}`, "public key"},
		{"jwk mismatch", string(badEC), "do not match"},
		{"jwk oct", `{"kty":"oct","k":"AAAA","d":"AAAA"}`, "not supported"},
		{"jwk p384", `{"kty":"EC","crv":"P-384","x":"AA","y":"AA","d":"AA"}`, "P-384"},
	}
	for _, c := range bad {
		if _, err := parseKey(c.text); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", c.name, err, c.want)
		}
	}
	for _, c := range bad {
		// No error repeats the key it was given.
		if _, err := parseKey(c.text); err != nil && len(c.text) > 8 && strings.Contains(err.Error(), c.text) {
			t.Errorf("%s: the error repeats the key", c.name)
		}
	}
}

// verifyJWT checks a compact JWT's signature with pub and returns its
// header and claims.
func verifyJWT(t *testing.T, tok string, pub crypto.PublicKey) (map[string]any, map[string]any, error) {
	t.Helper()
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return nil, nil, errors.New("not a JWT")
	}
	var header, claims map[string]any
	for i, out := range []*map[string]any{&header, &claims} {
		b, err := base64.RawURLEncoding.DecodeString(parts[i])
		if err != nil {
			return nil, nil, err
		}
		if err := json.Unmarshal(b, out); err != nil {
			return nil, nil, err
		}
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, nil, err
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	switch k := pub.(type) {
	case *rsa.PublicKey:
		if header["alg"] != "RS256" {
			return nil, nil, fmt.Errorf("alg %v", header["alg"])
		}
		err = rsa.VerifyPKCS1v15(k, crypto.SHA256, sum[:], sig)
	case *ecdsa.PublicKey:
		if header["alg"] != "ES256" || len(sig) != 64 {
			return nil, nil, fmt.Errorf("alg %v, %d bytes", header["alg"], len(sig))
		}
		if !ecdsa.Verify(k, sum[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
			err = errors.New("bad signature")
		}
	}
	return header, claims, err
}

// jwkKey is the public key a DPoP proof's header carries.
func jwkKey(h map[string]any) (*ecdsa.PublicKey, error) {
	j, _ := h["jwk"].(map[string]any)
	if j == nil || j["kty"] != "EC" || j["crv"] != "P-256" || j["d"] != nil {
		return nil, fmt.Errorf("jwk %v", j)
	}
	x, err1 := base64.RawURLEncoding.DecodeString(fmt.Sprint(j["x"]))
	y, err2 := base64.RawURLEncoding.DecodeString(fmt.Sprint(j["y"]))
	if err1 != nil || err2 != nil {
		return nil, errors.New("jwk numbers")
	}
	return &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}, nil
}

// fakeOkta is an organization's token endpoint and System Log API.
type fakeOkta struct {
	t        *testing.T
	srv      *httptest.Server
	pub      crypto.PublicKey
	clientID string
	apiToken string
	dpop     bool
	nonce    string

	mu      sync.Mutex
	pages   [][]map[string]any
	tokens  int
	reads   []string
	limited int // how many reads answer 429
	refuse  int // how many reads answer 400
	jtis    map[string]bool
}

func newFakeOkta(t *testing.T, pub crypto.PublicKey) *fakeOkta {
	f := &fakeOkta{t: t, pub: pub, clientID: "0oaapp", apiToken: "ssws-test-token", jtis: map[string]bool{}}
	f.srv = httptest.NewTLSServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeOkta) domain() string { return strings.TrimPrefix(f.srv.URL, "https://") }

func (f *fakeOkta) oauth(key string) Settings {
	return Settings{Domain: f.domain(), ClientID: f.clientID, PrivateKey: key}
}

func oktaError(w http.ResponseWriter, status int, body map[string]any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(body)
}

// proof checks a DPoP proof for a request, and returns what is wrong
// with it.
func (f *fakeOkta) proof(r *http.Request, token string) string {
	p := r.Header.Get("DPoP")
	if p == "" {
		return "invalid_dpop_proof"
	}
	var h map[string]any
	head, _, _ := strings.Cut(p, ".")
	if b, err := base64.RawURLEncoding.DecodeString(head); err != nil || json.Unmarshal(b, &h) != nil {
		return "invalid_dpop_proof"
	}
	pub, err := jwkKey(h)
	if err != nil {
		return "invalid_dpop_proof"
	}
	h, c, err := verifyJWT(f.t, p, pub)
	if err != nil || h["typ"] != "dpop+jwt" || c["htm"] != r.Method || c["htu"] != f.srv.URL+r.URL.Path || c["jti"] == "" {
		return "invalid_dpop_proof"
	}
	if token != "" {
		sum := sha256.Sum256([]byte(token))
		if c["ath"] != b64(sum[:]) {
			return "invalid_dpop_proof"
		}
	}
	if f.nonce != "" && c["nonce"] != f.nonce {
		return "use_dpop_nonce"
	}
	return ""
}

func (f *fakeOkta) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	switch r.URL.Path {
	case "/oauth2/v1/token":
		f.token(w, r)
	case "/api/v1/logs":
		f.logs(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (f *fakeOkta) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil || r.Method != http.MethodPost || r.Form.Get("grant_type") != "client_credentials" ||
		r.Form.Get("scope") != Scope || r.Form.Get("client_assertion_type") != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" {
		oktaError(w, 400, map[string]any{"error": "invalid_request"})
		return
	}
	_, c, err := verifyJWT(f.t, r.Form.Get("client_assertion"), f.pub)
	jti := fmt.Sprint(c["jti"])
	if err != nil || c["iss"] != f.clientID || c["sub"] != f.clientID || c["aud"] != f.srv.URL+"/oauth2/v1/token" || f.jtis[jti] {
		oktaError(w, 401, map[string]any{"error": "invalid_client", "error_description": "The client_assertion signature is invalid."})
		return
	}
	exp, _ := c["exp"].(float64)
	iat, _ := c["iat"].(float64)
	if exp-iat != 300 {
		oktaError(w, 401, map[string]any{"error": "invalid_client", "error_description": "exp"})
		return
	}
	f.jtis[jti] = true
	kind := "Bearer"
	if f.dpop {
		switch e := f.proof(r, ""); e {
		case "use_dpop_nonce":
			w.Header().Set("DPoP-Nonce", f.nonce)
			oktaError(w, 400, map[string]any{"error": e, "error_description": "Authorization server requires nonce in DPoP proof."})
			return
		case "":
		default:
			oktaError(w, 400, map[string]any{"error": e, "error_description": "The DPoP proof JWT header is missing."})
			return
		}
		kind = "DPoP"
	}
	f.tokens++
	json.NewEncoder(w).Encode(map[string]any{"access_token": "access-" + strconv.Itoa(f.tokens), "token_type": kind, "expires_in": 3600, "scope": Scope})
}

func (f *fakeOkta) logs(w http.ResponseWriter, r *http.Request) {
	auth := r.Header.Get("Authorization")
	switch {
	case auth == "SSWS "+f.apiToken:
	case f.dpop && strings.HasPrefix(auth, "DPoP access-"):
		if e := f.proof(r, strings.TrimPrefix(auth, "DPoP ")); e != "" {
			oktaError(w, 401, map[string]any{"errorCode": "E0000011", "errorSummary": "Invalid token provided"})
			return
		}
	case !f.dpop && strings.HasPrefix(auth, "Bearer access-"):
	default:
		oktaError(w, 401, map[string]any{"errorCode": "E0000011", "errorSummary": "Invalid token provided"})
		return
	}
	f.reads = append(f.reads, r.URL.RawQuery)
	if f.limited > 0 {
		f.limited--
		w.Header().Set("X-Rate-Limit-Reset", strconv.FormatInt(time.Now().Add(30*time.Second).Unix(), 10))
		oktaError(w, 429, map[string]any{"errorCode": "E0000047", "errorSummary": "API call exceeded rate limit due to too many requests."})
		return
	}
	if f.refuse > 0 {
		f.refuse--
		oktaError(w, 400, map[string]any{"errorCode": "E0000001", "errorSummary": "Api validation failed: after"})
		return
	}
	if r.URL.Query().Get("sortOrder") != "ASCENDING" && r.URL.Query().Get("after") == "" {
		oktaError(w, 400, map[string]any{"errorCode": "E0000001", "errorSummary": "sortOrder"})
		return
	}
	n, _ := strconv.Atoi(r.URL.Query().Get("after"))
	var page []map[string]any
	if n < len(f.pages) {
		page = f.pages[n]
	}
	// Okta always gives a next link, so a poller can carry on from it,
	// and links of its own besides.
	w.Header().Add("Link", "<"+f.srv.URL+"/api/v1/logs?limit=1000>; rel=\"self\"")
	w.Header().Add("Link", "<"+f.srv.URL+"/api/v1/logs?after="+strconv.Itoa(min(n+1, len(f.pages)))+"&limit=1000>; rel=\"next\"")
	w.Header().Set("X-Rate-Limit-Remaining", "50")
	if page == nil {
		page = []map[string]any{}
	}
	json.NewEncoder(w).Encode(page)
}

func event(id string, at time.Time) map[string]any {
	return map[string]any{
		"uuid": id, "published": at.UTC().Format("2006-01-02T15:04:05.000Z"), "eventType": "user.session.start", "version": "0",
		"severity": "INFO", "displayMessage": "User login to Okta",
		"actor":   map[string]any{"id": "00u1", "type": "User", "alternateId": "alice@example.com", "displayName": "Alice"},
		"client":  map[string]any{"ipAddress": "198.51.100.7"},
		"outcome": map[string]any{"result": "SUCCESS"},
	}
}

func TestClientDPoP(t *testing.T) {
	ek := newEC(t, elliptic.P256())
	f := newFakeOkta(t, &ek.PublicKey)
	f.dpop, f.nonce = true, "nonce-1"
	f.pages = [][]map[string]any{{event("e1", time.Now().Add(-time.Minute))}}
	res, err := Check(context.Background(), f.oauth(pemOf(t, "PRIVATE KEY", pkcs8(t, ek))), f.srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	if res.Auth != "oauth" || !res.DPoP || res.Events != 1 || f.tokens != 1 {
		t.Errorf("result %+v, %d tokens", res, f.tokens)
	}
	q, _ := url.ParseQuery(f.reads[0])
	if q.Get("sortOrder") != "ASCENDING" || q.Get("limit") != "1000" || q.Get("since") == "" {
		t.Errorf("query %s", f.reads[0])
	}
}

func TestClientBearerAndToken(t *testing.T) {
	rk := newRSA(t, 2048)
	f := newFakeOkta(t, &rk.PublicKey)
	key := pemOf(t, "PRIVATE KEY", pkcs8(t, rk))
	c := &Client{S: f.oauth(key), HTTP: f.srv.Client()}
	for range 2 {
		if _, err := c.Read(context.Background(), c.FirstURL(time.Now().Add(-time.Hour))); err != nil {
			t.Fatal(err)
		}
	}
	// The token is used again while it is good.
	if f.tokens != 1 || len(f.reads) != 2 {
		t.Errorf("%d tokens, %d reads", f.tokens, len(f.reads))
	}

	// An API token is sent as SSWS.
	res, err := Check(context.Background(), Settings{Domain: f.domain(), APIToken: f.apiToken}, f.srv.Client())
	if err != nil || res.Auth != "token" {
		t.Errorf("token %+v %v", res, err)
	}
	_, err = Check(context.Background(), Settings{Domain: f.domain(), APIToken: "wrong"}, f.srv.Client())
	var ae *APIError
	if !errors.As(err, &ae) || ae.Code != "E0000011" || strings.Contains(err.Error(), "wrong") {
		t.Errorf("wrong token %v", err)
	}

	// A key Okta does not have for the app is refused.
	other := newRSA(t, 2048)
	_, err = Check(context.Background(), f.oauth(pemOf(t, "PRIVATE KEY", pkcs8(t, other))), f.srv.Client())
	if !errors.As(err, &ae) || ae.Code != "invalid_client" {
		t.Errorf("other key %v", err)
	}
}

func TestOwn(t *testing.T) {
	c := &Client{S: Settings{Domain: "example.okta.com"}}
	for _, u := range []string{"https://example.okta.com/api/v1/logs?after=1", "https://EXAMPLE.okta.com/api/v1/logs"} {
		if err := c.own(u); err != nil {
			t.Errorf("%s: %v", u, err)
		}
	}
	for _, u := range []string{
		"http://example.okta.com/api/v1/logs", "https://evil.example/api/v1/logs", "https://example.okta.com.evil.example/api/v1/logs",
		"https://example.okta.com/api/v1/users", "https://user:pass@example.okta.com/api/v1/logs", "https://example.okta.com:8443/api/v1/logs",
	} {
		if err := c.own(u); err == nil {
			t.Errorf("%s was taken", u)
		}
	}
	links := []string{`<https://example.okta.com/api/v1/logs?limit=1>; rel="self", <https://example.okta.com/api/v1/logs?after=x>; rel="next"`}
	if got := nextLink(links); got != "https://example.okta.com/api/v1/logs?after=x" {
		t.Errorf("next %q", got)
	}
	if got := nextLink([]string{`<https://example.okta.com/a>; rel="self"`, "garbage", "<unclosed; rel=next"}); got != "" {
		t.Errorf("no next %q", got)
	}
}

// sink keeps what the poller ingests.
type sink struct {
	mu   sync.Mutex
	recs []map[string]any
}

func (s *sink) ingest(_ context.Context, tag string, recs []map[string]any) (*ingest.Result, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if tag != ingest.OktaTag {
		return nil, fmt.Errorf("tag %s", tag)
	}
	s.recs = append(s.recs, recs...)
	return &ingest.Result{Received: len(recs)}, nil
}

func TestPoller(t *testing.T) {
	ek := newEC(t, elliptic.P256())
	f := newFakeOkta(t, &ek.PublicKey)
	now := time.Now().UTC().Truncate(time.Second)
	last := now.Add(-time.Minute)
	f.pages = [][]map[string]any{
		{event("e1", now.Add(-3*time.Hour)), event("e2", now.Add(-2*time.Hour))},
		{event("e3", last)},
	}
	s := f.oauth(pemOf(t, "EC PRIVATE KEY", func() []byte { b, _ := x509.MarshalECPrivateKey(ek); return b }()))
	runs := detect.NewMemoryRunStore()
	out := &sink{}
	p := &Poller{Settings: func() Settings { return s }, Store: runs, Index: "rt", Ingest: out.ingest, HTTP: f.srv.Client(),
		now: func() time.Time { return now }}
	p.Round(context.Background())
	st := p.Status()
	// A page of fewer than 1,000 events is caught up: the round stops,
	// and the next one carries on from the next link.
	if st.LastError != "" || !st.On || st.Records != 2 || len(out.recs) != 2 || out.recs[0]["uuid"] != "e1" {
		t.Fatalf("status %+v, %d records", st, len(out.recs))
	}
	q, _ := url.ParseQuery(f.reads[0])
	if since, _ := time.Parse(time.RFC3339, q.Get("since")); !since.Equal(now.Add(-firstLook)) {
		t.Errorf("first read since %s", q.Get("since"))
	}
	cur, found, err := CursorOf(context.Background(), runs, "rt", f.domain())
	if err != nil || !found || !strings.Contains(cur.Next, "after=1") || !cur.Until.Equal(now.Add(-2*time.Hour)) || cur.LastRecords != 2 {
		t.Fatalf("cursor %+v %v", cur, err)
	}

	now = now.Add(time.Minute)
	p.Round(context.Background())
	if len(out.recs) != 3 || out.recs[2]["uuid"] != "e3" || f.reads[1] != "after=1&limit=1000" {
		t.Errorf("%d records, reads %v", len(out.recs), f.reads)
	}

	// A rate limit holds the rounds back until it resets.
	f.limited = 1
	p.Round(context.Background())
	if st := p.Status(); !strings.Contains(st.LastError, "rate limit") {
		t.Errorf("limited %+v", st)
	}
	reads := len(f.reads)
	p.Round(context.Background())
	if len(f.reads) != reads {
		t.Errorf("read while the rate limit was reached")
	}
	now = now.Add(time.Minute)
	p.Round(context.Background())
	if st := p.Status(); st.LastError != "" || len(f.reads) != reads+1 {
		t.Errorf("after the reset %+v, %d reads", st, len(f.reads)-reads)
	}

	// A next link the API no longer takes starts again from the last
	// event read.
	f.refuse = 1
	now = now.Add(time.Minute)
	p.Round(context.Background())
	cur, _, _ = CursorOf(context.Background(), runs, "rt", f.domain())
	if cur.Next != "" || !strings.Contains(cur.LastError, "E0000001") {
		t.Errorf("refused cursor %+v", cur)
	}
	now = now.Add(time.Minute)
	p.Round(context.Background())
	q, _ = url.ParseQuery(f.reads[len(f.reads)-1])
	if since, _ := time.Parse(time.RFC3339, q.Get("since")); !since.Equal(last) {
		t.Errorf("restart query %s", f.reads[len(f.reads)-1])
	}

	// A server that lost the jobs does not write over the newer holder's
	// cursor.
	p2 := &Poller{Settings: func() Settings { return s }, Store: runs, Index: "rt", Ingest: out.ingest, HTTP: f.srv.Client(),
		now: func() time.Time { return now }, Epoch: func() int64 { return 2 }}
	p2.Round(context.Background())
	p.Round(context.Background())
	if st := p.Status(); !strings.Contains(st.LastError, ErrStale.Error()) {
		t.Errorf("stale status %+v", st)
	}

	// Without settings, nothing is read.
	s = Settings{}
	p.Round(context.Background())
	if st := p.Status(); st.On {
		t.Errorf("off status %+v", st)
	}
}
