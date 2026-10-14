package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// maxResponse is the most read of one API answer.
const maxResponse = 32 << 20

// readOnlyPosts are the only API routes the client sends a POST to. Each
// only reads: searching runs a query, and parsing checks one.
var readOnlyPosts = map[string]bool{
	"/api/search": true,
	"/api/parse":  true,
}

// Client reads from a Signalith server's API as one Signalith user. It
// sends GET requests, and POST requests only to readOnlyPosts, so nothing
// it does can change Signalith, whatever the user's role allows.
type Client struct {
	// BaseURL is the server's web address, such as https://siem:8080.
	BaseURL  *url.URL
	User     string
	Password string
	HTTP     *http.Client
	// UserAgent names the client in the server's logs.
	UserAgent string
}

// APIError is an answer from the server that is not a success.
type APIError struct {
	Status int
	Code   string
	Msg    string
}

func (e *APIError) Error() string { return e.Msg }

// Get reads path with the query parameters q into out.
func (c *Client) Get(ctx context.Context, path string, q url.Values, out any) error {
	return c.do(ctx, http.MethodGet, path, q, nil, out)
}

// Post sends body to one of the read-only POST routes and reads the answer
// into out.
func (c *Client) Post(ctx context.Context, path string, body, out any) error {
	if !readOnlyPosts[path] {
		return fmt.Errorf("%s is not a read-only route", path)
	}
	return c.do(ctx, http.MethodPost, path, nil, body, out)
}

func (c *Client) do(ctx context.Context, method, path string, q url.Values, body, out any) error {
	if !strings.HasPrefix(path, "/api/") || strings.Contains(path, "..") {
		return fmt.Errorf("bad API path %q", path)
	}
	u := c.BaseURL.JoinPath(path)
	u.RawQuery = q.Encode()
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), rd)
	if err != nil {
		return err
	}
	req.SetBasicAuth(c.User, c.Password)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.UserAgent != "" {
		req.Header.Set("User-Agent", c.UserAgent)
	}
	hc := c.HTTP
	if hc == nil {
		hc = http.DefaultClient
	}
	resp, err := hc.Do(req)
	if err != nil {
		return fmt.Errorf("could not reach Signalith at %s: %w", c.BaseURL.Redacted(), err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse+1))
	if err != nil {
		return fmt.Errorf("reading Signalith's answer: %w", err)
	}
	if len(data) > maxResponse {
		return errors.New("Signalith's answer is too large; narrow the request")
	}
	if resp.StatusCode/100 != 2 {
		return apiError(resp.StatusCode, data)
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(data, out); err != nil {
		if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "json") {
			return fmt.Errorf("%s did not answer like a Signalith server (got %s); check the address", c.BaseURL.Redacted(), ct)
		}
		return fmt.Errorf("reading Signalith's answer: %w", err)
	}
	return nil
}

func apiError(status int, data []byte) error {
	var e struct {
		Error string `json:"error"`
		Code  string `json:"code"`
	}
	_ = json.Unmarshal(data, &e)
	msg := e.Error
	switch {
	case status == http.StatusUnauthorized:
		msg = "Signalith did not accept the username and password set for the MCP server (SIGNALITH_USER and SIGNALITH_PASSWORD)."
	case e.Code == "password_change_required":
		msg = "This Signalith user must choose a new password first. Sign in to Signalith in a browser once as this user, choose a password, and put it in the MCP server's settings."
	case msg == "":
		msg = fmt.Sprintf("Signalith answered %d %s", status, http.StatusText(status))
	}
	return &APIError{Status: status, Code: e.Code, Msg: msg}
}
