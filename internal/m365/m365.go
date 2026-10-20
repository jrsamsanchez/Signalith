// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

// Package m365 reads Microsoft 365's audit log from the Office 365
// Management Activity API and hands its records to the ingest pipeline.
//
// An app registered in Entra ID, with the API's ActivityFeed.Read
// permission and a client secret, signs in for the tenant (OAuth client
// credentials). The API keeps a subscription per content type
// (Audit.AzureActiveDirectory, Audit.Exchange, Audit.SharePoint,
// Audit.General); the poller starts each once, then every few minutes
// lists the content blobs made available since it last looked and reads
// each one: a JSON array of audit records. Where it got to in each
// content type is kept in the runtime index, so a restart, or another
// server taking over the jobs, carries on from there. The API keeps
// content for 7 days.
package m365

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// ContentTypes are the audit logs read.
var ContentTypes = []string{"Audit.AzureActiveDirectory", "Audit.Exchange", "Audit.SharePoint", "Audit.General"}

// Settings are how to reach a tenant's audit log.
type Settings struct {
	TenantID, ClientID, ClientSecret string
	// TokenURL is the tenant's sign-in endpoint, APIURL the Management
	// Activity API (https://manage.office.com).
	TokenURL, APIURL string
}

// On reports whether the settings name a tenant, an app and its secret.
func (s Settings) On() bool { return s.TenantID != "" && s.ClientID != "" && s.ClientSecret != "" }

// maxBody caps one response the API sends: a content blob holds at most
// a few thousand records.
const maxBody = 64 << 20

// Client calls the Management Activity API for one tenant.
type Client struct {
	S    Settings
	HTTP *http.Client

	mu      sync.Mutex
	token   string
	expires time.Time
	now     func() time.Time
}

// NewHTTPClient is the client the poller calls Microsoft with: through
// the proxy the environment names, with time limits on each step. A
// call's whole time limit is its context's.
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

// APIError is an error the API or the sign-in service answered with.
type APIError struct {
	Status  int
	Code    string // such as AF20022 or invalid_client
	Message string
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

// readError reads an error response: the API's {"error": {"code",
// "message"}}, or the sign-in service's {"error", "error_description"}.
func readError(resp *http.Response) error {
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	e := &APIError{Status: resp.StatusCode}
	var api struct {
		Error json.RawMessage `json:"error"`
		Desc  string          `json:"error_description"`
	}
	if json.Unmarshal(b, &api) == nil && len(api.Error) > 0 {
		var inner struct{ Code, Message string }
		var code string
		if json.Unmarshal(api.Error, &inner) == nil && inner.Code != "" {
			e.Code, e.Message = inner.Code, inner.Message
		} else if json.Unmarshal(api.Error, &code) == nil {
			e.Code, e.Message = code, api.Desc
			// The sign-in service's description ends with trace IDs.
			if i := strings.Index(e.Message, "\r\nTrace ID"); i > 0 {
				e.Message = e.Message[:i]
			}
		}
	}
	if e.Message == "" {
		e.Message = strings.TrimSpace(string(b))
	}
	return e
}

// accessToken signs the app in, or returns the token it has while it is
// good for another minute.
func (c *Client) accessToken(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token != "" && c.clock().Before(c.expires.Add(-time.Minute)) {
		return c.token, nil
	}
	form := url.Values{
		"grant_type": {"client_credentials"}, "client_id": {c.S.ClientID}, "client_secret": {c.S.ClientSecret},
		"scope": {strings.TrimSuffix(c.S.APIURL, "/") + "/.default"},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.S.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return "", fmt.Errorf("sign in to Microsoft: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("sign in to Microsoft: %w", readError(resp))
	}
	var tok struct {
		AccessToken string          `json:"access_token"`
		ExpiresIn   json.RawMessage `json:"expires_in"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&tok); err != nil || tok.AccessToken == "" {
		return "", errors.New("sign in to Microsoft: the answer has no access token")
	}
	secs := 3600
	var n json.Number
	if json.Unmarshal(tok.ExpiresIn, &n) == nil {
		if v, err := n.Int64(); err == nil && v > 0 {
			secs = int(v)
		}
	} else {
		var s string
		if json.Unmarshal(tok.ExpiresIn, &s) == nil {
			fmt.Sscan(s, &secs)
		}
	}
	c.token, c.expires = tok.AccessToken, c.clock().Add(time.Duration(secs)*time.Second)
	return c.token, nil
}

// do calls the API at u, which must be on the API's host, and returns
// the response, whose body the caller closes.
func (c *Client) do(ctx context.Context, method, u string) (*http.Response, error) {
	api, err := url.Parse(c.S.APIURL)
	if err != nil {
		return nil, err
	}
	target, err := url.Parse(u)
	if err != nil {
		return nil, err
	}
	if !strings.EqualFold(target.Host, api.Host) || target.Scheme != api.Scheme {
		// The token is only ever sent to the API itself.
		return nil, fmt.Errorf("the API named an address on another host (%s)", target.Host)
	}
	tok, err := c.accessToken(ctx)
	if err != nil {
		return nil, err
	}
	var body io.Reader
	if method == http.MethodPost {
		body = bytes.NewReader(nil)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode/100 != 2 {
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusUnauthorized {
			// A token Microsoft no longer takes is not used again.
			c.mu.Lock()
			c.token = ""
			c.mu.Unlock()
		}
		return nil, readError(resp)
	}
	return resp, nil
}

// feed is the address of one of the tenant's activity feed calls.
func (c *Client) feed(call string, q url.Values) string {
	q.Set("PublisherIdentifier", c.S.TenantID)
	return strings.TrimSuffix(c.S.APIURL, "/") + "/api/v1.0/" + url.PathEscape(c.S.TenantID) +
		"/activity/feed/subscriptions/" + call + "?" + q.Encode()
}

// Subscriptions returns the content types the tenant has a subscription
// to, by whether it is enabled.
func (c *Client) Subscriptions(ctx context.Context) (map[string]bool, error) {
	resp, err := c.do(ctx, http.MethodGet, c.feed("list", url.Values{}))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var subs []struct {
		ContentType string `json:"contentType"`
		Status      string `json:"status"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&subs); err != nil {
		return nil, fmt.Errorf("list subscriptions: %w", err)
	}
	out := map[string]bool{}
	for _, s := range subs {
		out[s.ContentType] = strings.EqualFold(s.Status, "enabled")
	}
	return out, nil
}

// Start starts the tenant's subscription to a content type. One already
// on is not an error.
func (c *Client) Start(ctx context.Context, contentType string) error {
	resp, err := c.do(ctx, http.MethodPost, c.feed("start", url.Values{"contentType": {contentType}}))
	var ae *APIError
	if errors.As(err, &ae) && ae.Code == "AF20024" {
		return nil
	}
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

// Blob is one content blob the API lists.
type Blob struct {
	ContentURI     string `json:"contentUri"`
	ContentID      string `json:"contentId"`
	ContentCreated string `json:"contentCreated"`
}

// apiTime is how the API writes a time: UTC, to the second.
const apiTime = "2006-01-02T15:04:05"

// List lists the blobs of a content type made available from start to
// end (at most 24 hours apart), following the API's next pages.
func (c *Client) List(ctx context.Context, contentType string, start, end time.Time) ([]Blob, error) {
	u := c.feed("content", url.Values{
		"contentType": {contentType}, "startTime": {start.UTC().Format(apiTime)}, "endTime": {end.UTC().Format(apiTime)},
	})
	var out []Blob
	for page := 0; u != ""; page++ {
		if page >= 1000 {
			return nil, errors.New("list content: more than 1000 pages")
		}
		resp, err := c.do(ctx, http.MethodGet, u)
		if err != nil {
			return nil, err
		}
		var blobs []Blob
		err = json.NewDecoder(io.LimitReader(resp.Body, maxBody)).Decode(&blobs)
		next := resp.Header.Get("NextPageUri")
		resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("list content: %w", err)
		}
		out = append(out, blobs...)
		u = next
	}
	return out, nil
}

// Read reads one blob's records, as JSON text.
func (c *Client) Read(ctx context.Context, b Blob) ([]byte, error) {
	u := b.ContentURI
	if parsed, err := url.Parse(u); err == nil {
		q := parsed.Query()
		if q.Get("PublisherIdentifier") == "" {
			q.Set("PublisherIdentifier", c.S.TenantID)
			parsed.RawQuery = q.Encode()
			u = parsed.String()
		}
	}
	resp, err := c.do(ctx, http.MethodGet, u)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxBody {
		return nil, fmt.Errorf("content %s is larger than %d MB", b.ContentID, maxBody>>20)
	}
	return body, nil
}
