package oidc_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/oidc"
	"github.com/jrsamsanchez/signalith/internal/oidc/oidctest"
)

func client(p *oidctest.Provider) *oidc.Client {
	c := oidc.NewClient()
	c.HTTP = p.Client()
	c.HTTP.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return c
}

// signIn runs the whole flow against the mock provider and returns the
// checked claims.
func signIn(t *testing.T, p *oidctest.Provider, c *oidc.Client) (oidc.Claims, error) {
	t.Helper()
	ctx := context.Background()
	md, err := c.Discover(ctx, p.Issuer)
	if err != nil {
		return nil, err
	}
	s := oidc.Settings{Issuer: p.Issuer, ClientID: p.ClientID, ClientSecret: p.ClientSecret, RedirectURL: "https://siem.example/api/auth/oidc/callback", Scopes: []string{"email"}}
	req := oidc.NewRequest()
	resp, err := c.HTTP.Get(oidc.AuthURL(md, s, req))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	back, err := url.Parse(resp.Header.Get("Location"))
	if err != nil || back.Query().Get("state") != req.State {
		t.Fatalf("redirect %q", resp.Header.Get("Location"))
	}
	tok, err := c.Exchange(ctx, md, s, back.Query().Get("code"), req.Verifier)
	if err != nil {
		return nil, err
	}
	return c.Verify(ctx, md, p.ClientID, req.Nonce, tok.IDToken)
}

func TestSignIn(t *testing.T) {
	p := oidctest.New(t)
	p.Claims["email"] = "alice@example.com"
	claims, err := signIn(t, p, client(p))
	if err != nil {
		t.Fatal(err)
	}
	if claims.String("sub") != p.Subject || claims.String("email") != "alice@example.com" {
		t.Errorf("claims %v", claims)
	}
	// The secret went as HTTP Basic, form-encoded first.
	if p.LastBasic != [2]string{p.ClientID, p.ClientSecret} || p.LastTokenForm.Get("client_secret") != "" {
		t.Errorf("basic %v form %v", p.LastBasic, p.LastTokenForm)
	}
}

func TestSignInEC(t *testing.T) {
	p := oidctest.New(t)
	p.UseEC = true
	if _, err := signIn(t, p, client(p)); err != nil {
		t.Fatal(err)
	}
}

func TestSecretInFormWhenOnlyPostAllowed(t *testing.T) {
	p := oidctest.New(t)
	p.AuthMethods = []string{"client_secret_post"}
	if _, err := signIn(t, p, client(p)); err != nil {
		t.Fatal(err)
	}
	if p.LastBasic != [2]string{} || p.LastTokenForm.Get("client_secret") != p.ClientSecret {
		t.Errorf("basic %v form %v", p.LastBasic, p.LastTokenForm)
	}
}

func TestPublicClient(t *testing.T) {
	p := oidctest.New(t)
	p.ClientSecret = ""
	if _, err := signIn(t, p, client(p)); err != nil {
		t.Fatal(err)
	}
	if p.LastTokenForm.Get("client_id") != p.ClientID {
		t.Errorf("form %v", p.LastTokenForm)
	}
}

// Every way an ID token or the provider can be wrong is refused.
func TestRefused(t *testing.T) {
	for brk, want := range map[string]string{
		"alg-none":         "accepts only",
		"hs256":            "accepts only",
		"wrong-key":        "signature does not match",
		"wrong-issuer":     "not the issuer",
		"wrong-audience":   "another client",
		"expired":          "expired",
		"future":           "in the future",
		"no-nonce":         "nonce",
		"wrong-nonce":      "nonce",
		"discovery-issuer": "says its issuer is",
		"no-s256":          "PKCE",
		"token-error":      "The code has expired",
	} {
		t.Run(brk, func(t *testing.T) {
			p := oidctest.New(t)
			p.Break[brk] = true
			_, err := signIn(t, p, client(p))
			var oe *oidc.Error
			if !errors.As(err, &oe) || !strings.Contains(err.Error(), want) {
				t.Errorf("err %v, want %q", err, want)
			}
		})
	}
}

func TestClockSkew(t *testing.T) {
	p := oidctest.New(t)
	c := client(p)
	ctx := context.Background()
	md, err := c.Discover(ctx, p.Issuer)
	if err != nil {
		t.Fatal(err)
	}
	tok := p.IDToken("n1")
	// A minute behind the provider's clock, or 6 minutes ahead (the token
	// lasts 5): within the 2 minute skew.
	for _, d := range []time.Duration{-time.Minute, 6 * time.Minute} {
		c.Now = func() time.Time { return time.Now().Add(d) }
		if _, err := c.Verify(ctx, md, p.ClientID, "n1", tok); err != nil {
			t.Errorf("%v: %v", d, err)
		}
	}
	for _, d := range []time.Duration{-3 * time.Minute, 8 * time.Minute} {
		c.Now = func() time.Time { return time.Now().Add(d) }
		if _, err := c.Verify(ctx, md, p.ClientID, "n1", tok); err == nil {
			t.Errorf("%v: accepted", d)
		}
	}
}

func TestSeveralAudiencesNeedAZP(t *testing.T) {
	p := oidctest.New(t)
	c := client(p)
	ctx := context.Background()
	md, _ := c.Discover(ctx, p.Issuer)
	p.Claims["aud"] = []any{p.ClientID, "other"}
	if _, err := c.Verify(ctx, md, p.ClientID, "n", p.IDToken("n")); err == nil || !strings.Contains(err.Error(), "azp") {
		t.Errorf("err %v", err)
	}
	p.Claims["azp"] = p.ClientID
	if _, err := c.Verify(ctx, md, p.ClientID, "n", p.IDToken("n")); err != nil {
		t.Error(err)
	}
	p.Claims["azp"] = "other"
	if _, err := c.Verify(ctx, md, p.ClientID, "n", p.IDToken("n")); err == nil {
		t.Error("azp of another client accepted")
	}
}

// A token signed with a key that is not the provider's, even an EC key
// with the provider's kid, is refused; the key set is not fetched again
// for every such token.
func TestForgedKeyAndRefetchLimit(t *testing.T) {
	p := oidctest.New(t)
	c := client(p)
	ctx := context.Background()
	md, _ := c.Discover(ctx, p.Issuer)
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	now := time.Now().Unix()
	claims := map[string]any{"iss": p.Issuer, "sub": "x", "aud": p.ClientID, "iat": now, "exp": now + 60, "nonce": "n"}
	for i := 0; i < 5; i++ {
		tok := oidctest.Sign(map[string]any{"alg": "ES256", "kid": "ec-1"}, claims, k)
		if _, err := c.Verify(ctx, md, p.ClientID, "n", tok); err == nil {
			t.Fatal("forged token accepted")
		}
	}
	if n := p.Count("/keys"); n > 1 {
		t.Errorf("key set fetched %d times", n)
	}
	// An RS256 header over an EC key's kid does not use it.
	tok := oidctest.Sign(map[string]any{"alg": "RS256", "kid": "ec-1"}, claims, k)
	if _, err := c.Verify(ctx, md, p.ClientID, "n", tok); err == nil {
		t.Fatal("alg confusion accepted")
	}
}

func TestCheckIssuer(t *testing.T) {
	for issuer, ok := range map[string]bool{
		"https://login.microsoftonline.com/abc/v2.0": true,
		"https://accounts.google.com":                true,
		"http://localhost:8180/realms/x":             true,
		"http://127.0.0.1:9000":                      true,
		"http://idp.example.com":                     false,
		"https://idp.example.com/?x=1":               false,
		"https://user:pw@idp.example.com":            false,
		"ftp://idp.example.com":                      false,
		"idp.example.com":                            false,
	} {
		if got := oidc.CheckIssuer(issuer) == ""; got != ok {
			t.Errorf("%s: ok=%v", issuer, got)
		}
	}
}

func TestClaims(t *testing.T) {
	c := oidc.Claims{"groups": []any{"a", 2, "b"}, "realm_access": map[string]any{"roles": []any{"admin"}},
		"https://example.com/groups": []any{"x"}, "one": "solo", "email_verified": "true"}
	if g := c.Strings("groups"); strings.Join(g, ",") != "a,b" {
		t.Errorf("groups %v", g)
	}
	if g := c.Strings("realm_access.roles"); strings.Join(g, ",") != "admin" {
		t.Errorf("nested %v", g)
	}
	if g := c.Strings("https://example.com/groups"); strings.Join(g, ",") != "x" {
		t.Errorf("namespaced %v", g)
	}
	if g := c.Strings("one"); strings.Join(g, ",") != "solo" {
		t.Errorf("single %v", g)
	}
	if v, said := c.EmailVerified(); !v || !said {
		t.Error("email_verified string")
	}
}

func TestUserInfo(t *testing.T) {
	p := oidctest.New(t)
	c := client(p)
	ctx := context.Background()
	md, _ := c.Discover(ctx, p.Issuer)
	p.UserInfo["groups"] = []any{"soc"}
	claims, err := c.UserInfo(ctx, md, "at-"+p.Subject, p.Subject)
	if err != nil || claims.Strings("groups")[0] != "soc" {
		t.Fatalf("%v %v", claims, err)
	}
	p.Break["userinfo-other"] = true
	if _, err := c.UserInfo(ctx, md, "at-"+p.Subject, p.Subject); err == nil {
		t.Error("userinfo about someone else accepted")
	}
}

func TestDiscoveryCached(t *testing.T) {
	p := oidctest.New(t)
	c := client(p)
	for i := 0; i < 3; i++ {
		if _, err := c.Discover(context.Background(), p.Issuer); err != nil {
			t.Fatal(err)
		}
	}
	if n := p.Count("/.well-known/openid-configuration"); n != 1 {
		t.Errorf("fetched %d times", n)
	}
}
