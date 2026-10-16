// Package okta reads an Okta organization's System Log from Okta's System
// Log API and hands its events to the ingest pipeline.
//
// Signalith signs in as an API service app in the organization, with the
// okta.logs.read scope, by a client assertion signed with the app's
// private key (OAuth 2.0 client credentials with private_key_jwt), and
// proves it holds a key of its own for each token when the app requires
// DPoP, as new apps do. An API token of an admin (SSWS) works too, but
// carries all of that admin's rights, so the app is the way the docs
// describe. Every minute the poller reads the events published since it
// last looked, in pages of up to 1,000 oldest first, following the API's
// next links. Where it got to is kept in the runtime index, so a restart,
// or another server taking over the jobs, carries on from there. Okta
// keeps 90 days of events.
package okta

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Scope is the OAuth scope the service app is granted: reading the
// System Log, and nothing else.
const Scope = "okta.logs.read"

// Settings are how to reach an organization's System Log.
type Settings struct {
	// Domain is the organization's Okta domain (example.okta.com).
	Domain string
	// ClientID and PrivateKey are the API service app's client ID and
	// private key; KeyID names the key when the app has several.
	ClientID, PrivateKey, KeyID string
	// APIToken is an admin's API token, used when no app is set.
	APIToken string
}

// OAuth reports whether the settings name a service app and its key.
func (s Settings) OAuth() bool { return s.ClientID != "" && s.PrivateKey != "" }

// On reports whether the settings name an organization and a way to sign
// in to it.
func (s Settings) On() bool { return s.Domain != "" && (s.OAuth() || s.APIToken != "") }

func (s Settings) base() string { return "https://" + s.Domain }

// TokenURL is the organization's token endpoint, which the client
// assertion is made out to.
func (s Settings) TokenURL() string { return s.base() + "/oauth2/v1/token" }

// LogsURL is the System Log API.
func (s Settings) LogsURL() string { return s.base() + "/api/v1/logs" }

// pageLimit is how many events one page holds, the API's most.
const pageLimit = 1000

// maxBody caps one page the API sends: 1,000 events are a few MB.
const maxBody = 64 << 20

// Client calls the System Log API for one organization.
type Client struct {
	S    Settings
	HTTP *http.Client

	mu      sync.Mutex
	key     *signingKey
	keyErr  error
	token   string
	kind    string // Bearer or DPoP
	expires time.Time
	// dpop is the key that proves a DPoP-bound token is Signalith's,
	// made for this client and never stored; useDPoP is set once Okta
	// asks for proofs, and nonce is the last nonce it gave.
	dpop    *ecdsa.PrivateKey
	useDPoP bool
	nonce   string
	now     func() time.Time
}

// NewHTTPClient is the client the poller calls Okta with: through the
// proxy the environment names, with time limits on each step. A call's
// whole time limit is its context's.
func NewHTTPClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			DialContext:           (&net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
			TLSHandshakeTimeout:   15 * time.Second,
			ResponseHeaderTimeout: 2 * time.Minute,
			MaxIdleConns:          4,
			IdleConnTimeout:       90 * time.Second,
		},
		// The API never redirects; a redirect could carry the token
		// elsewhere.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

func (c *Client) clock() time.Time {
	if c.now != nil {
		return c.now()
	}
	return time.Now()
}

// APIError is an error Okta answered with.
type APIError struct {
	Status int
	// Code is the API's errorCode (E0000011) or the token endpoint's
	// error (invalid_client).
	Code    string
	Message string
	// RetryAt is when a rate limit (HTTP 429) resets.
	RetryAt time.Time
}

func (e *APIError) Error() string {
	msg := e.Message
	if len(msg) > 300 {
		msg = msg[:300] + "..."
	}
	if e.Code != "" {
		return fmt.Sprintf("%s (HTTP %d): %s", e.Code, e.Status, msg)
	}
	return fmt.Sprintf("HTTP %d: %s", e.Status, msg)
}

// readError reads an error response: the API's {"errorCode",
// "errorSummary", "errorCauses"}, or the token endpoint's {"error",
// "error_description"}. now is the time a rate limit's reset is checked
// against.
func readError(resp *http.Response, now time.Time) *APIError {
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	e := &APIError{Status: resp.StatusCode}
	var api struct {
		ErrorCode    string `json:"errorCode"`
		ErrorSummary string `json:"errorSummary"`
		ErrorCauses  []struct {
			ErrorSummary string `json:"errorSummary"`
		} `json:"errorCauses"`
		Error string `json:"error"`
		Desc  string `json:"error_description"`
	}
	if json.Unmarshal(b, &api) == nil {
		switch {
		case api.ErrorCode != "":
			e.Code, e.Message = api.ErrorCode, api.ErrorSummary
			for _, c := range api.ErrorCauses {
				if c.ErrorSummary != "" {
					e.Message += " " + c.ErrorSummary
				}
			}
		case api.Error != "":
			e.Code, e.Message = api.Error, api.Desc
		}
	}
	if e.Message == "" && e.Code == "" {
		e.Message = strings.TrimSpace(string(b))
		if e.Message == "" {
			e.Message = http.StatusText(resp.StatusCode)
		}
	}
	if resp.StatusCode == http.StatusTooManyRequests {
		e.RetryAt = rateReset(resp.Header, now)
	}
	return e
}

// rateReset is when the rate limit a response names resets: its
// X-Rate-Limit-Reset, in Unix seconds, or a minute from now.
func rateReset(h http.Header, now time.Time) time.Time {
	if n, err := strconv.ParseInt(h.Get("X-Rate-Limit-Reset"), 10, 64); err == nil {
		t := time.Unix(n, 0)
		if t.After(now) && t.Before(now.Add(time.Hour)) {
			return t
		}
	}
	return now.Add(time.Minute)
}

// dpopProof is a DPoP proof for a request: the method, the address
// without its query, a fresh ID, and for an API call the hash of the
// token it carries.
func (c *Client) dpopProof(method, u, token string) (string, error) {
	if c.dpop == nil {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return "", err
		}
		c.dpop = k
	}
	parsed, err := url.Parse(u)
	if err != nil {
		return "", err
	}
	parsed.RawQuery, parsed.Fragment = "", ""
	claims := map[string]any{"htm": method, "htu": parsed.String(), "iat": c.clock().Unix(), "jti": randomID()}
	if c.nonce != "" {
		claims["nonce"] = c.nonce
	}
	if token != "" {
		sum := sha256.Sum256([]byte(token))
		claims["ath"] = b64(sum[:])
	}
	return signJWT(c.dpop, "ES256", map[string]any{"typ": "dpop+jwt", "jwk": publicJWK(c.dpop)}, claims)
}

// assertion is the client assertion the app signs in with: made out to
// the token endpoint, good for five minutes.
func (c *Client) assertion() (string, error) {
	if c.key == nil && c.keyErr == nil {
		c.key, c.keyErr = parseKey(c.S.PrivateKey)
	}
	if c.keyErr != nil {
		return "", c.keyErr
	}
	now := c.clock()
	header := map[string]any{"typ": "JWT"}
	if kid := c.S.KeyID; kid != "" {
		header["kid"] = kid
	} else if c.key.kid != "" {
		header["kid"] = c.key.kid
	}
	claims := map[string]any{
		"iss": c.S.ClientID, "sub": c.S.ClientID, "aud": c.S.TokenURL(),
		"iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(), "jti": randomID(),
	}
	return signJWT(c.key.key, c.key.alg, header, claims)
}

// accessToken signs the app in, or returns the token it has while it is
// good for another minute. Okta asks for DPoP proofs, and a nonce in
// them, by refusing the request: each is tried once.
func (c *Client) accessToken(ctx context.Context) (string, string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token != "" && c.clock().Before(c.expires.Add(-time.Minute)) {
		return c.token, c.kind, nil
	}
	for attempt := 0; ; attempt++ {
		tok, kind, secs, err := c.signIn(ctx)
		var ae *APIError
		if errors.As(err, &ae) && attempt < 3 {
			switch {
			case ae.Code == "invalid_dpop_proof" && !c.useDPoP:
				// The app requires DPoP.
				c.useDPoP = true
				continue
			case ae.Code == "use_dpop_nonce" && c.useDPoP:
				continue
			}
		}
		if err != nil {
			return "", "", fmt.Errorf("sign in to Okta: %w", err)
		}
		c.token, c.kind, c.expires = tok, kind, c.clock().Add(time.Duration(secs)*time.Second)
		return tok, kind, nil
	}
}

// signIn asks the token endpoint for a token.
func (c *Client) signIn(ctx context.Context) (string, string, int, error) {
	a, err := c.assertion()
	if err != nil {
		return "", "", 0, err
	}
	form := url.Values{
		"grant_type": {"client_credentials"}, "scope": {Scope},
		"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"}, "client_assertion": {a},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.S.TokenURL(), strings.NewReader(form.Encode()))
	if err != nil {
		return "", "", 0, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if c.useDPoP {
		proof, err := c.dpopProof(http.MethodPost, c.S.TokenURL(), "")
		if err != nil {
			return "", "", 0, err
		}
		req.Header.Set("DPoP", proof)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return "", "", 0, err
	}
	defer resp.Body.Close()
	if n := resp.Header.Get("DPoP-Nonce"); n != "" && len(n) < 1024 {
		c.nonce = n
	}
	if resp.StatusCode != http.StatusOK {
		return "", "", 0, readError(resp, c.clock())
	}
	var tok struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int    `json:"expires_in"`
		Scope       string `json:"scope"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&tok); err != nil || tok.AccessToken == "" {
		return "", "", 0, errors.New("the answer has no access token")
	}
	kind := "Bearer"
	if strings.EqualFold(tok.TokenType, "DPoP") {
		kind = "DPoP"
	}
	secs := tok.ExpiresIn
	if secs <= 0 || secs > 24*3600 {
		secs = 3600
	}
	return tok.AccessToken, kind, secs, nil
}

// get calls the API at u, which must be the System Log API on the
// organization's own domain, and returns the response, whose body the
// caller closes.
func (c *Client) get(ctx context.Context, u string) (*http.Response, error) {
	if err := c.own(u); err != nil {
		return nil, err
	}
	for attempt := 0; ; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Accept", "application/json")
		if c.S.OAuth() {
			tok, kind, err := c.accessToken(ctx)
			if err != nil {
				return nil, err
			}
			req.Header.Set("Authorization", kind+" "+tok)
			if kind == "DPoP" {
				c.mu.Lock()
				proof, err := c.dpopProof(http.MethodGet, u, tok)
				c.mu.Unlock()
				if err != nil {
					return nil, err
				}
				req.Header.Set("DPoP", proof)
			}
		} else {
			req.Header.Set("Authorization", "SSWS "+c.S.APIToken)
		}
		resp, err := c.HTTP.Do(req)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode/100 == 2 {
			return resp, nil
		}
		ae := readError(resp, c.clock())
		resp.Body.Close()
		if resp.StatusCode == http.StatusUnauthorized && c.S.OAuth() {
			c.mu.Lock()
			if n := resp.Header.Get("DPoP-Nonce"); n != "" && len(n) < 1024 && attempt == 0 &&
				strings.Contains(resp.Header.Get("WWW-Authenticate"), "use_dpop_nonce") {
				// The proof needs Okta's nonce: once more, with it.
				c.nonce = n
				c.mu.Unlock()
				continue
			}
			// A token Okta no longer takes is not used again.
			c.token = ""
			c.mu.Unlock()
		}
		return nil, ae
	}
}

// own checks an address is the organization's System Log API: the token
// is only ever sent there.
func (c *Client) own(u string) error {
	target, err := url.Parse(u)
	if err != nil {
		return err
	}
	if target.Scheme != "https" || !strings.EqualFold(target.Host, c.S.Domain) || target.Path != "/api/v1/logs" || target.User != nil {
		return fmt.Errorf("the API named an address that is not the organization's System Log (%s%s)", target.Host, target.Path)
	}
	return nil
}

// Page is one page of events: the events' JSON text (an array), the
// address of the next page, and how many calls the organization's rate
// limit for the System Log has left (X-Rate-Limit-Remaining).
type Page struct {
	Body      []byte
	Next      string
	Remaining int
}

// FirstURL is the address of the events published from since on, oldest
// first.
func (c *Client) FirstURL(since time.Time) string {
	q := url.Values{"since": {since.UTC().Format("2006-01-02T15:04:05.000Z")}, "sortOrder": {"ASCENDING"},
		"limit": {strconv.Itoa(pageLimit)}}
	return c.S.LogsURL() + "?" + q.Encode()
}

// Read reads one page of events at u.
func (c *Client) Read(ctx context.Context, u string) (*Page, error) {
	resp, err := c.get(ctx, u)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxBody {
		return nil, fmt.Errorf("a page of events is larger than %d MB", maxBody>>20)
	}
	p := &Page{Body: body, Remaining: pageLimit}
	if n, err := strconv.Atoi(resp.Header.Get("X-Rate-Limit-Remaining")); err == nil && n >= 0 {
		p.Remaining = n
	}
	if next := nextLink(resp.Header.Values("Link")); next != "" && c.own(next) == nil {
		p.Next = next
	}
	return p, nil
}

// nextLink is the address a Link header names as rel="next".
func nextLink(links []string) string {
	for _, h := range links {
		for _, l := range strings.Split(h, ",") {
			target, params, ok := strings.Cut(strings.TrimSpace(l), ";")
			target = strings.TrimSpace(target)
			if !ok || !strings.HasPrefix(target, "<") || !strings.HasSuffix(target, ">") {
				continue
			}
			for _, p := range strings.Split(params, ";") {
				k, v, _ := strings.Cut(strings.TrimSpace(p), "=")
				if strings.EqualFold(k, "rel") && strings.Trim(v, `"`) == "next" {
					return target[1 : len(target)-1]
				}
			}
		}
	}
	return ""
}

// CheckResult is what the Settings page's test found.
type CheckResult struct {
	// Auth is how Signalith signed in: "oauth" (the service app) or
	// "token" (an API token); DPoP is set when the app requires DPoP.
	Auth string `json:"auth"`
	DPoP bool   `json:"dpop"`
	// Events is how many events the last hour has, up to one page.
	Events int `json:"events"`
}

// Check signs in with the settings and reads the last hour's events, for
// the Test button: nil when Signalith can read the System Log.
func Check(ctx context.Context, s Settings, hc *http.Client) (*CheckResult, error) {
	if hc == nil {
		hc = NewHTTPClient()
	}
	c := &Client{S: s, HTTP: hc}
	p, err := c.Read(ctx, c.FirstURL(time.Now().Add(-time.Hour)))
	if err != nil {
		return nil, err
	}
	var events []json.RawMessage
	if err := json.Unmarshal(p.Body, &events); err != nil {
		return nil, errors.New("the System Log API's answer is not a list of events")
	}
	r := &CheckResult{Auth: "token", Events: len(events)}
	if s.OAuth() {
		r.Auth = "oauth"
		c.mu.Lock()
		r.DPoP = c.useDPoP
		c.mu.Unlock()
	}
	return r, nil
}
