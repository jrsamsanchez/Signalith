// Package oidc signs people in with an OpenID Connect identity provider,
// such as Microsoft Entra ID, Okta, Google or Keycloak: the authorization
// code flow with PKCE, for a confidential client (with a client secret)
// or a public one (without).
//
// Everything is checked before a sign-in is believed: the provider's
// discovery document must name the issuer that was set up, the ID token
// must be signed with one of the provider's published keys by an
// asymmetric algorithm, name that issuer, this client as its audience and
// the nonce of this sign-in, and be current (allowing ClockSkew either
// way). The state that ties the provider's answer to the browser that
// started the sign-in is checked by the caller (package api).
package oidc

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"
)

// Provider presets: the identity provider, which picks sensible defaults.
const (
	Entra    = "entra"
	Okta     = "okta"
	Google   = "google"
	Keycloak = "keycloak"
	Other    = "other"
)

// GoogleIssuer is Google's issuer, the same for every Google client.
const GoogleIssuer = "https://accounts.google.com"

// Preset is what a provider usually needs.
type Preset struct {
	ID    string `json:"id"`
	Label string `json:"label"`
	// Issuer is the issuer when it is the same for everyone (Google), and
	// IssuerExample what one looks like otherwise.
	Issuer        string   `json:"issuer,omitempty"`
	IssuerExample string   `json:"issuer_example"`
	Scopes        []string `json:"scopes"`
	UsernameClaim string   `json:"username_claim"`
	// GroupsClaim is "" for a provider that sends no groups (Google).
	GroupsClaim string `json:"groups_claim"`
}

// Presets lists the providers, in the order the page offers them.
var Presets = []Preset{
	{ID: Entra, Label: "Microsoft Entra ID", IssuerExample: "https://login.microsoftonline.com/<tenant ID>/v2.0",
		Scopes: []string{"openid", "profile", "email"}, UsernameClaim: "preferred_username", GroupsClaim: "groups"},
	{ID: Okta, Label: "Okta", IssuerExample: "https://<your org>.okta.com/oauth2/default",
		Scopes: []string{"openid", "profile", "email", "groups"}, UsernameClaim: "preferred_username", GroupsClaim: "groups"},
	{ID: Google, Label: "Google", Issuer: GoogleIssuer, IssuerExample: GoogleIssuer,
		Scopes: []string{"openid", "profile", "email"}, UsernameClaim: "email"},
	{ID: Keycloak, Label: "Keycloak", IssuerExample: "https://<keycloak host>/realms/<realm>",
		Scopes: []string{"openid", "profile", "email"}, UsernameClaim: "preferred_username", GroupsClaim: "groups"},
	{ID: Other, Label: "Other OpenID Connect provider", IssuerExample: "https://id.example.com",
		Scopes: []string{"openid", "profile", "email"}, UsernameClaim: "preferred_username", GroupsClaim: "groups"},
}

// PresetFor returns the preset of a provider, or Other's.
func PresetFor(id string) Preset {
	for _, p := range Presets {
		if p.ID == id {
			return p
		}
	}
	return Presets[len(Presets)-1]
}

// ClockSkew is how far the provider's clock and this server's may differ.
const ClockSkew = 2 * time.Minute

// Metadata is the part of a provider's discovery document Signalith uses.
type Metadata struct {
	Issuer                string   `json:"issuer"`
	AuthorizationEndpoint string   `json:"authorization_endpoint"`
	TokenEndpoint         string   `json:"token_endpoint"`
	UserinfoEndpoint      string   `json:"userinfo_endpoint,omitempty"`
	JWKSURI               string   `json:"jwks_uri"`
	ResponseTypes         []string `json:"response_types_supported,omitempty"`
	CodeChallengeMethods  []string `json:"code_challenge_methods_supported,omitempty"`
	TokenAuthMethods      []string `json:"token_endpoint_auth_methods_supported,omitempty"`
	SigningAlgs           []string `json:"id_token_signing_alg_values_supported,omitempty"`
	ScopesSupported       []string `json:"scopes_supported,omitempty"`
}

// Error is a failed step, with Code naming it for the log and the page:
// discovery, keys, token, id_token, userinfo.
type Error struct {
	Code    string
	Message string
	Err     error
}

func (e *Error) Error() string {
	if e.Err != nil {
		return e.Message + ": " + e.Err.Error()
	}
	return e.Message
}
func (e *Error) Unwrap() error { return e.Err }

func fail(code string, err error, format string, args ...any) *Error {
	return &Error{Code: code, Message: fmt.Sprintf(format, args...), Err: err}
}

// Client talks to identity providers, keeping their discovery documents
// and keys for an hour. One Client serves every provider setting, so a
// change of settings needs no new one.
type Client struct {
	// HTTP makes the requests; NewClient's refuses redirects, so a client
	// secret never follows one.
	HTTP *http.Client
	// Now is the clock (tests replace it).
	Now func() time.Time

	mu    sync.Mutex
	meta  map[string]cached[*Metadata]
	keys  map[string]cached[[]key]
	fetch map[string]time.Time // when each key set was last fetched
}

type cached[T any] struct {
	v  T
	at time.Time
}

// cacheFor is how long a discovery document or key set is kept;
// refetchAfter how soon an unknown key may have the set fetched again.
const (
	cacheFor     = time.Hour
	refetchAfter = 5 * time.Second
	maxBody      = 1 << 20
)

// NewClient returns a Client with its own HTTP client: TLS 1.2 or later,
// the system's trusted certificate authorities, the proxy from the
// environment, 15 second timeouts and no redirects.
func NewClient() *Client {
	tr := &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		DialContext:         (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout: 10 * time.Second,
		MaxIdleConns:        10,
		IdleConnTimeout:     90 * time.Second,
	}
	return &Client{HTTP: &http.Client{Transport: tr, Timeout: 15 * time.Second, CheckRedirect: noRedirects}}
}

func noRedirects(*http.Request, []*http.Request) error {
	return errors.New("the identity provider answered with a redirect, which Signalith does not follow")
}

func (c *Client) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

func (c *Client) http() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return http.DefaultClient
}

// CheckIssuer says what is wrong with an issuer address, or "": it must
// be https:// (http:// only on this computer, for testing), with no user
// name, query or fragment.
func CheckIssuer(issuer string) string {
	u, err := url.Parse(issuer)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return "enter the issuer address, like https://login.microsoftonline.com/<tenant ID>/v2.0, with nothing after its path"
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !loopback(u.Hostname()) {
			return "the issuer address must start with https://; http:// is only allowed on this computer, for testing"
		}
	default:
		return "the issuer address must start with https://"
	}
	return ""
}

func loopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// sameIssuer compares issuers as written and as the discovery document
// has them, which may differ only by a trailing slash.
func sameIssuer(a, b string) bool {
	return strings.TrimRight(a, "/") == strings.TrimRight(b, "/")
}

// endpointOK says whether a provider endpoint may be used with issuer:
// https://, or http:// on this computer when the issuer is too.
func endpointOK(endpoint, issuer string) bool {
	u, err := url.Parse(endpoint)
	if err != nil || u.Host == "" || u.User != nil {
		return false
	}
	if u.Scheme == "https" {
		return true
	}
	iu, _ := url.Parse(issuer)
	return u.Scheme == "http" && iu != nil && iu.Scheme == "http" && loopback(u.Hostname())
}

// getJSON fetches a JSON document of at most maxBody bytes.
func (c *Client) getJSON(ctx context.Context, address, bearer string, into any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := c.http().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return err
	}
	if len(body) > maxBody {
		return errors.New("the answer is larger than 1 MB")
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s answered %s", address, resp.Status)
	}
	if err := json.Unmarshal(body, into); err != nil {
		return fmt.Errorf("%s did not answer with JSON", address)
	}
	return nil
}

// Discover returns the provider's discovery document, from
// <issuer>/.well-known/openid-configuration, and checks it.
func (c *Client) Discover(ctx context.Context, issuer string) (*Metadata, error) {
	if p := CheckIssuer(issuer); p != "" {
		return nil, fail("discovery", nil, "%s", p)
	}
	c.mu.Lock()
	if e, ok := c.meta[issuer]; ok && c.now().Sub(e.at) < cacheFor {
		c.mu.Unlock()
		return e.v, nil
	}
	c.mu.Unlock()
	address := strings.TrimRight(issuer, "/") + "/.well-known/openid-configuration"
	var md Metadata
	if err := c.getJSON(ctx, address, "", &md); err != nil {
		return nil, fail("discovery", err, "could not read the provider's discovery document")
	}
	if !sameIssuer(md.Issuer, issuer) {
		return nil, fail("discovery", nil, "the provider says its issuer is %q, not %q; enter its issuer exactly", md.Issuer, issuer)
	}
	for name, v := range map[string]string{"authorization_endpoint": md.AuthorizationEndpoint, "token_endpoint": md.TokenEndpoint, "jwks_uri": md.JWKSURI} {
		if !endpointOK(v, issuer) {
			return nil, fail("discovery", nil, "the discovery document's %s %q is not an https:// address", name, v)
		}
	}
	if md.UserinfoEndpoint != "" && !endpointOK(md.UserinfoEndpoint, issuer) {
		md.UserinfoEndpoint = ""
	}
	if len(md.ResponseTypes) > 0 && !slices.Contains(md.ResponseTypes, "code") {
		return nil, fail("discovery", nil, "the provider does not offer the authorization code flow")
	}
	if len(md.CodeChallengeMethods) > 0 && !slices.Contains(md.CodeChallengeMethods, "S256") {
		return nil, fail("discovery", nil, "the provider does not offer PKCE with S256")
	}
	c.mu.Lock()
	if c.meta == nil {
		c.meta = map[string]cached[*Metadata]{}
	}
	c.meta[issuer] = cached[*Metadata]{v: &md, at: c.now()}
	c.mu.Unlock()
	return &md, nil
}

// Keys returns how many usable signing keys the provider publishes, for
// the settings test.
func (c *Client) Keys(ctx context.Context, md *Metadata) (int, error) {
	ks, err := c.keySet(ctx, md, true)
	return len(ks), err
}

// keySet returns the provider's signing keys; fresh fetches them again
// when they were not fetched within refetchAfter (a key rotated in since).
func (c *Client) keySet(ctx context.Context, md *Metadata, fresh bool) ([]key, error) {
	now := c.now()
	c.mu.Lock()
	e, ok := c.keys[md.JWKSURI]
	last := c.fetch[md.JWKSURI]
	c.mu.Unlock()
	if ok && now.Sub(e.at) < cacheFor && (!fresh || now.Sub(last) < refetchAfter) {
		return e.v, nil
	}
	var set JWKS
	err := c.getJSON(ctx, md.JWKSURI, "", &set)
	c.mu.Lock()
	if c.fetch == nil {
		c.fetch, c.keys = map[string]time.Time{}, map[string]cached[[]key]{}
	}
	c.fetch[md.JWKSURI] = now
	c.mu.Unlock()
	if err != nil {
		if ok {
			return e.v, nil
		}
		return nil, fail("keys", err, "could not read the provider's signing keys")
	}
	ks := parseKeys(set)
	if len(ks) == 0 {
		return nil, fail("keys", nil, "the provider publishes no RSA or EC signing key Signalith can use")
	}
	c.mu.Lock()
	c.keys[md.JWKSURI] = cached[[]key]{v: ks, at: now}
	c.mu.Unlock()
	return ks, nil
}

// Request is one sign-in on its way: what is sent to the provider and
// kept (in the browser's state cookie) to check its answer.
type Request struct {
	State    string
	Nonce    string
	Verifier string
}

// NewRequest makes the random values of a sign-in.
func NewRequest() Request {
	return Request{State: random(), Nonce: random(), Verifier: random() + random()}
}

func random() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// Challenge is the PKCE S256 challenge of a verifier.
func Challenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// Settings are what a sign-in needs from the provider settings.
type Settings struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	RedirectURL  string
	Scopes       []string
}

// AuthURL is where the browser is sent to sign in.
func AuthURL(md *Metadata, s Settings, req Request) string {
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", s.ClientID)
	q.Set("redirect_uri", s.RedirectURL)
	q.Set("scope", strings.Join(scopes(s.Scopes), " "))
	q.Set("state", req.State)
	q.Set("nonce", req.Nonce)
	q.Set("code_challenge", Challenge(req.Verifier))
	q.Set("code_challenge_method", "S256")
	sep := "?"
	if strings.Contains(md.AuthorizationEndpoint, "?") {
		sep = "&"
	}
	return md.AuthorizationEndpoint + sep + q.Encode()
}

// scopes always includes openid.
func scopes(list []string) []string {
	out := []string{"openid"}
	for _, s := range list {
		if s = strings.TrimSpace(s); s != "" && !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	return out
}

// Tokens is the token endpoint's answer.
type Tokens struct {
	IDToken     string `json:"id_token"`
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
}

// Exchange trades an authorization code for tokens, with the PKCE
// verifier and, for a confidential client, its secret: HTTP Basic unless
// the provider only accepts it in the form.
func (c *Client) Exchange(ctx context.Context, md *Metadata, s Settings, code, verifier string) (*Tokens, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", s.RedirectURL)
	form.Set("code_verifier", verifier)
	basic := s.ClientSecret != "" && (len(md.TokenAuthMethods) == 0 || slices.Contains(md.TokenAuthMethods, "client_secret_basic"))
	if !basic {
		form.Set("client_id", s.ClientID)
		if s.ClientSecret != "" {
			form.Set("client_secret", s.ClientSecret)
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, md.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fail("token", err, "could not ask for tokens")
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if basic {
		// RFC 6749 section 2.3.1: both are form-encoded first.
		req.SetBasicAuth(url.QueryEscape(s.ClientID), url.QueryEscape(s.ClientSecret))
	}
	resp, err := c.http().Do(req)
	if err != nil {
		return nil, fail("token", err, "could not reach the provider's token endpoint")
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return nil, fail("token", err, "could not read the provider's token answer")
	}
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Error       string `json:"error"`
			Description string `json:"error_description"`
		}
		_ = json.Unmarshal(body, &e)
		msg := cut(e.Error, 80)
		if d := cut(e.Description, 300); d != "" {
			msg += ": " + d
		}
		if msg == "" {
			msg = resp.Status
		}
		return nil, fail("token", nil, "the provider refused the sign-in code (%s)", msg)
	}
	var t Tokens
	if err := json.Unmarshal(body, &t); err != nil || t.IDToken == "" {
		return nil, fail("token", err, "the provider's token answer has no ID token; check that the openid scope is allowed")
	}
	return &t, nil
}

// cut shortens text from a provider for the log, keeping only printable
// characters.
func cut(s string, n int) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, strings.TrimSpace(s))
	if len(s) > n {
		s = s[:n] + "…"
	}
	return s
}

// Claims are the claims of a checked ID token (and the userinfo answer,
// when it was read).
type Claims map[string]any

// String returns a claim as a string, or "". A name with dots, such as
// realm_access.roles, also looks inside nested claims.
func (c Claims) String(name string) string {
	s, _ := c.lookup(name).(string)
	return s
}

// Strings returns a claim as a list of strings: a list's strings, or a
// single string.
func (c Claims) Strings(name string) []string {
	switch v := c.lookup(name).(type) {
	case string:
		if v == "" {
			return nil
		}
		return []string{v}
	case []any:
		out := make([]string, 0, len(v))
		for _, e := range v {
			if s, ok := e.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// Has reports whether a claim is there.
func (c Claims) Has(name string) bool { return c.lookup(name) != nil }

func (c Claims) lookup(name string) any {
	if name == "" {
		return nil
	}
	if v, ok := c[name]; ok {
		return v
	}
	var cur any = map[string]any(c)
	for _, part := range strings.Split(name, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		if cur, ok = m[part]; !ok {
			return nil
		}
	}
	return cur
}

// EmailVerified reports whether the provider says the email address is
// verified: email_verified true (a boolean, or "true" as some send it).
func (c Claims) EmailVerified() (verified, said bool) {
	switch v := c["email_verified"].(type) {
	case bool:
		return v, true
	case string:
		return strings.EqualFold(v, "true"), true
	}
	return false, false
}

// Verify checks an ID token: signed by one of the provider's keys with an
// accepted algorithm, from issuer (as the discovery document has it), for
// clientID, with this sign-in's nonce, and current. It returns its claims.
func (c *Client) Verify(ctx context.Context, md *Metadata, clientID, nonce, token string) (Claims, error) {
	h, payload, sig, signed, err := splitToken(token)
	if err != nil {
		return nil, fail("id_token", err, "the ID token could not be read")
	}
	if !slices.Contains(Algorithms, h.Alg) {
		return nil, fail("id_token", nil, "the ID token is signed with %q; Signalith accepts only %s", cut(h.Alg, 20), strings.Join(Algorithms, ", "))
	}
	if len(h.Crit) > 0 {
		return nil, fail("id_token", nil, "the ID token has critical header parameters Signalith does not know")
	}
	if err := c.checkSignature(ctx, md, h, signed, sig); err != nil {
		return nil, err
	}
	var claims Claims
	dec := json.NewDecoder(strings.NewReader(string(payload)))
	if err := dec.Decode(&claims); err != nil {
		return nil, fail("id_token", err, "the ID token's claims are not JSON")
	}
	if err := checkClaims(claims, md.Issuer, clientID, nonce, c.now()); err != nil {
		return nil, fail("id_token", nil, "%s", err)
	}
	return claims, nil
}

func (c *Client) checkSignature(ctx context.Context, md *Metadata, h header, signed string, sig []byte) error {
	verified := func(ks []key) bool {
		for _, k := range ks {
			if (h.Kid == "" || k.kid == h.Kid) && (k.alg == "" || k.alg == h.Alg) && verifySignature(h.Alg, k.pub, signed, sig) == nil {
				return true
			}
		}
		return false
	}
	ks, err := c.keySet(ctx, md, false)
	if err != nil {
		return err
	}
	if verified(ks) {
		return nil
	}
	// A key the provider rotated in since the set was read: read it again.
	if ks, err = c.keySet(ctx, md, true); err != nil {
		return err
	}
	if verified(ks) {
		return nil
	}
	if h.Kid != "" && !slices.ContainsFunc(ks, func(k key) bool { return k.kid == h.Kid }) {
		return fail("id_token", nil, "the ID token is signed with a key (%s) the provider does not publish", cut(h.Kid, 60))
	}
	return fail("id_token", nil, "the ID token's signature does not match the provider's keys")
}

// numeric returns a NumericDate claim.
func numeric(c Claims, name string) (time.Time, bool) {
	switch v := c[name].(type) {
	case float64:
		sec := int64(v)
		return time.Unix(sec, int64((v-float64(sec))*1e9)), true
	case json.Number:
		f, err := v.Float64()
		if err != nil {
			return time.Time{}, false
		}
		return time.Unix(int64(f), 0), true
	}
	return time.Time{}, false
}

// checkClaims checks the registered claims of an ID token.
func checkClaims(c Claims, issuer, clientID, nonce string, now time.Time) error {
	if iss := c.String("iss"); iss != issuer {
		return fmt.Errorf("the ID token is from %q, not the issuer %q", cut(iss, 200), issuer)
	}
	if c.String("sub") == "" {
		return errors.New("the ID token names no subject (sub)")
	}
	aud := c.Strings("aud")
	if !slices.Contains(aud, clientID) {
		return fmt.Errorf("the ID token is for another client (%s), not %s", cut(strings.Join(aud, ", "), 200), clientID)
	}
	azp := c.String("azp")
	if len(aud) > 1 && azp == "" {
		return errors.New("the ID token has several audiences but no authorized party (azp)")
	}
	if azp != "" && azp != clientID {
		return fmt.Errorf("the ID token was issued to another client (%s)", cut(azp, 200))
	}
	exp, ok := numeric(c, "exp")
	if !ok {
		return errors.New("the ID token has no expiry (exp)")
	}
	if !now.Before(exp.Add(ClockSkew)) {
		return fmt.Errorf("the ID token expired at %s; check that this server's clock is right", exp.UTC().Format(time.RFC3339))
	}
	iat, ok := numeric(c, "iat")
	if !ok {
		return errors.New("the ID token has no issue time (iat)")
	}
	if iat.After(now.Add(ClockSkew)) {
		return fmt.Errorf("the ID token was issued in the future (%s); check that this server's clock is right", iat.UTC().Format(time.RFC3339))
	}
	if nbf, ok := numeric(c, "nbf"); ok && nbf.After(now.Add(ClockSkew)) {
		return errors.New("the ID token is not valid yet; check that this server's clock is right")
	}
	got := c.String("nonce")
	if got == "" || subtle.ConstantTimeCompare([]byte(got), []byte(nonce)) != 1 {
		return errors.New("the ID token's nonce does not match this sign-in")
	}
	return nil
}

// UserInfo reads the userinfo endpoint with the access token, for claims
// a provider leaves out of the ID token. Its subject must be the ID
// token's.
func (c *Client) UserInfo(ctx context.Context, md *Metadata, accessToken, subject string) (Claims, error) {
	if md.UserinfoEndpoint == "" || accessToken == "" {
		return nil, nil
	}
	var claims Claims
	if err := c.getJSON(ctx, md.UserinfoEndpoint, accessToken, &claims); err != nil {
		return nil, fail("userinfo", err, "could not read the provider's userinfo")
	}
	if claims.String("sub") != subject {
		return nil, fail("userinfo", nil, "the userinfo answer is about someone else")
	}
	return claims, nil
}
