package okta

import (
	"context"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/config"
)

func TestParsePrivateKeyMore(t *testing.T) {
	ek := newEC(t, elliptic.P256())
	if k, kid, err := ParsePrivateKey(pemOf(t, "PRIVATE KEY", pkcs8(t, ek))); err != nil || k == nil || kid != "" {
		t.Errorf("ParsePrivateKey = %v %q %v", k, kid, err)
	}
	if _, _, err := ParsePrivateKey("nope"); err == nil {
		t.Error("ParsePrivateKey took garbage")
	}
	rk := newRSA(t, 2048)
	other := newRSA(t, 2048)
	_, edKey, _ := ed25519.GenerateKey(rand.Reader)
	rsaJWK := func(mod func(m map[string]string)) string {
		m := map[string]string{"kty": "RSA", "n": b64(rk.N.Bytes()), "e": "AQAB", "d": b64(rk.D.Bytes()),
			"p": b64(rk.Primes[0].Bytes()), "q": b64(rk.Primes[1].Bytes())}
		mod(m)
		b, _ := json.Marshal(m)
		return string(b)
	}
	ecJWK := func(mod func(m map[string]string)) string {
		m := map[string]string{"kty": "EC", "crv": "P-256", "x": num(ek.X, 32), "y": num(ek.Y, 32), "d": num(ek.D, 32)}
		mod(m)
		b, _ := json.Marshal(m)
		return string(b)
	}
	for _, c := range []struct{ name, text, want string }{
		{"pem not base64", "-----BEGIN PRIVATE KEY-----\nAAA\n-----END PRIVATE KEY-----", "not valid base64"},
		{"dsa pem", "-----BEGIN DSA PRIVATE KEY-----\nAAAA\n-----END DSA PRIVATE KEY-----", "a PEM dsa private key is not a private key"},
		{"ed25519", pemOf(t, "PRIVATE KEY", pkcs8(t, edKey)), "neither RSA nor EC"},
		{"jwk not json", `{"kty": "RSA",`, "not valid JSON"},
		{"rsa bad number", rsaJWK(func(m map[string]string) { m["n"] = "***" }), `JSON Web Key's "n"`},
		{"rsa empty number", rsaJWK(func(m map[string]string) { m["p"] = "" }), `JSON Web Key's "p"`},
		{"rsa exponent", rsaJWK(func(m map[string]string) { m["e"] = "AQ" }), "exponent is not valid"},
		{"rsa wrong prime", rsaJWK(func(m map[string]string) { m["p"] = b64(other.Primes[0].Bytes()) }), "not a valid RSA key"},
		{"ec bad number", ecJWK(func(m map[string]string) { m["x"] = "***" }), `JSON Web Key's "x"`},
		{"ec too big", ecJWK(func(m map[string]string) { m["y"] = b64(append([]byte{1}, make([]byte, 32)...)) }), "not a valid P-256 key"},
		{"ec zero key", ecJWK(func(m map[string]string) { m["d"] = b64(make([]byte, 32)) }), "not a valid P-256 key"},
	} {
		if _, err := parseKey(c.text); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", c.name, err, c.want)
		}
	}

	if _, err := signJWT(edKey, "EdDSA", map[string]any{}, map[string]any{}); err == nil || err.Error() != "unsupported key" {
		t.Errorf("ed25519 signing = %v", err)
	}
	if _, err := signJWT(ek, "ES256", map[string]any{"bad": make(chan int)}, map[string]any{}); err == nil {
		t.Error("a header that is not JSON was signed")
	}
	if _, err := signJWT(ek, "ES256", map[string]any{}, map[string]any{"bad": make(chan int)}); err == nil {
		t.Error("claims that are not JSON were signed")
	}
}

func TestErrorReading(t *testing.T) {
	now := time.Now()
	read := func(status int, body string, h http.Header) *APIError {
		rec := httptest.NewRecorder()
		for k, v := range h {
			rec.Header()[k] = v
		}
		rec.WriteHeader(status)
		rec.WriteString(body)
		return readError(rec.Result(), now)
	}
	e := read(400, `{"errorCode":"E0000001","errorSummary":"Api validation failed","errorCauses":[{"errorSummary":"since: bad date"},{}]}`, nil)
	if e.Code != "E0000001" || e.Message != "Api validation failed since: bad date" {
		t.Errorf("causes = %+v", e)
	}
	if e := read(502, `<html>proxy</html>`, nil); e.Message != "Bad Gateway" || strings.Contains(e.Error(), "proxy") || e.Error() != "HTTP 502: Bad Gateway" {
		t.Errorf("other body = %+v %q", e, e.Error())
	}
	long := &APIError{Status: 400, Code: "E1", Message: strings.Repeat("m", 400)}
	if got := long.Error(); !strings.HasSuffix(got, "...") || len(got) > 330 {
		t.Errorf("long = %q", got)
	}
	reset := now.Add(20 * time.Second).Truncate(time.Second)
	if e := read(429, `{}`, http.Header{"X-Rate-Limit-Reset": {strconv.FormatInt(reset.Unix(), 10)}}); !e.RetryAt.Equal(reset) {
		t.Errorf("reset = %v, want %v", e.RetryAt, reset)
	}
	if e := read(429, `{}`, http.Header{"X-Rate-Limit-Reset": {strconv.FormatInt(now.Add(5*time.Hour).Unix(), 10)}}); !e.RetryAt.Equal(now.Add(time.Minute)) {
		t.Errorf("far reset = %v", e.RetryAt)
	}
}

func TestSignInAnswers(t *testing.T) {
	ctx := context.Background()
	rk := newRSA(t, 2048)
	key := pemOf(t, "PRIVATE KEY", pkcs8(t, rk))
	var answer func(w http.ResponseWriter, r *http.Request)
	var kids []string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth2/v1/token" {
			r.ParseForm()
			h, _, _ := verifyJWT(t, r.Form.Get("client_assertion"), &rk.PublicKey)
			kids = append(kids, func() string { s, _ := h["kid"].(string); return s }())
		}
		answer(w, r)
	}))
	t.Cleanup(srv.Close)
	domain := strings.TrimPrefix(srv.URL, "https://")

	// No token in the answer.
	answer = func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`{"token_type":"Bearer"}`)) }
	c := &Client{S: Settings{Domain: domain, ClientID: "app", PrivateKey: key, KeyID: "kid-7"}, HTTP: srv.Client()}
	if _, err := c.Read(ctx, c.FirstURL(time.Now())); err == nil || !strings.Contains(err.Error(), "no access token") {
		t.Errorf("no token = %v", err)
	}
	if len(kids) != 1 || kids[0] != "kid-7" {
		t.Errorf("kids = %v", kids)
	}

	// A token with an odd lifetime lasts an hour; a page that is not a
	// list fails the check.
	answer = func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth2/v1/token" {
			w.Write([]byte(`{"access_token":"a1","token_type":"Bearer","expires_in":-5}`))
			return
		}
		w.Write([]byte(`{"not":"a list"}`))
	}
	now := time.Now()
	c = &Client{S: Settings{Domain: domain, ClientID: "app", PrivateKey: key}, HTTP: srv.Client(), now: func() time.Time { return now }}
	if _, err := c.Read(ctx, c.FirstURL(now)); err != nil {
		t.Fatal(err)
	}
	if !c.expires.Equal(now.Add(time.Hour)) {
		t.Errorf("expires = %v", c.expires)
	}
	if _, err := Check(ctx, Settings{Domain: domain, ClientID: "app", PrivateKey: key}, srv.Client()); err == nil || !strings.Contains(err.Error(), "not a list of events") {
		t.Errorf("odd page = %v", err)
	}

	// A bad key fails before anything is sent, and again without trying.
	c = &Client{S: Settings{Domain: domain, ClientID: "app", PrivateKey: "nope"}, HTTP: srv.Client()}
	for range 2 {
		if _, err := c.Read(ctx, c.FirstURL(now)); err == nil || !strings.Contains(err.Error(), "neither PEM") {
			t.Errorf("bad key = %v", err)
		}
	}

	// A page from elsewhere is never asked for.
	c = &Client{S: Settings{Domain: domain, APIToken: "t"}, HTTP: srv.Client()}
	if _, err := c.Read(ctx, "https://evil.example/api/v1/logs"); err == nil {
		t.Error("read a page from another host")
	}
	srv.Close()
	if _, err := c.Read(ctx, c.FirstURL(now)); err == nil {
		t.Error("read from a closed server")
	}
}

func TestFromConfigAndRun(t *testing.T) {
	if s := FromConfig(&config.Config{}); s.Domain != "" || s.APIToken != "" {
		t.Errorf("off = %+v", s)
	}
	s := FromConfig(&config.Config{Okta: config.Okta{Domain: "Example.Okta.com", APIToken: "tok", ClientID: " app ", KeyID: " k1 "}})
	if s.Domain != "example.okta.com" || s.APIToken != "tok" || s.ClientID != "app" || s.KeyID != "k1" {
		t.Errorf("on = %+v", s)
	}
	if hc := NewHTTPClient(); hc.CheckRedirect(nil, nil) != http.ErrUseLastResponse {
		t.Error("redirects are followed")
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	rounds := 0
	p := &Poller{Allowed: func() bool { rounds++; return false }}
	done := make(chan struct{})
	go func() { p.Run(ctx); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not stop")
	}
	if rounds != 1 {
		t.Errorf("rounds = %d", rounds)
	}
}
