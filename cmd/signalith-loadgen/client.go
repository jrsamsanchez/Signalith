package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"os"
	"strings"
	"sync"
	"time"
)

// tlsConfig trusts the system's CAs plus the given CA files.
func tlsConfig(caFiles []string) (*tls.Config, error) {
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	for _, f := range caFiles {
		pem, err := os.ReadFile(f)
		if err != nil {
			return nil, fmt.Errorf("CA file: %w", err)
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("CA file %s holds no certificate", f)
		}
	}
	return &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}, nil
}

// newTransport is a transport for many simulated clients at once.
func newTransport(tc *tls.Config, dial func(ctx context.Context, network, addr string) (net.Conn, error)) *http.Transport {
	if dial == nil {
		dial = (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext
	}
	return &http.Transport{
		TLSClientConfig:     tc.Clone(),
		DialContext:         dial,
		MaxIdleConns:        0,
		MaxIdleConnsPerHost: 64,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
		ForceAttemptHTTP2:   false,
	}
}

// readSecret is the first line of a file.
func readSecret(path string) (string, error) {
	if path == "" {
		return "", errors.New("no file named")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	line, _, _ := strings.Cut(string(b), "\n")
	line = strings.TrimSpace(line)
	if line == "" {
		return "", fmt.Errorf("%s is empty", path)
	}
	return line, nil
}

// readLogin reads "user:password", or a password for admin.
func readLogin(path string) (user, password string, err error) {
	s, err := readSecret(path)
	if err != nil {
		return "", "", err
	}
	if u, p, ok := strings.Cut(s, ":"); ok && u != "" && !strings.ContainsAny(u, " \t") {
		return u, p, nil
	}
	return "admin", s, nil
}

// readUsers reads a CSV of username,password.
func readUsers(path string) ([][2]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out [][2]string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		u, p, ok := strings.Cut(line, ",")
		if !ok {
			return nil, fmt.Errorf("%s: each line is username,password", path)
		}
		if strings.EqualFold(u, "username") {
			continue
		}
		out = append(out, [2]string{strings.TrimSpace(u), strings.TrimSpace(p)})
	}
	return out, sc.Err()
}

// apiError is an answer other than the one expected.
type apiError struct {
	Status int
	Body   string
}

func (e *apiError) Error() string {
	return fmt.Sprintf("HTTP %d: %s", e.Status, strings.TrimSpace(e.Body))
}

func statusOf(err error) int {
	var ae *apiError
	if errors.As(err, &ae) {
		return ae.Status
	}
	return 0
}

// Session is one signed-in user on one server, with the session cookie
// a browser would keep.
type Session struct {
	Base     string
	User     string
	password string
	client   *http.Client
	mu       sync.Mutex
	signedIn bool
}

func newSession(base string, tr http.RoundTripper, user, password string) *Session {
	jar, _ := cookiejar.New(nil)
	return &Session{Base: strings.TrimRight(base, "/"), User: user, password: password,
		client: &http.Client{Transport: tr, Jar: jar, Timeout: 2 * time.Minute}}
}

// SignIn signs in as the page does.
func (s *Session) SignIn(ctx context.Context) error {
	body, _ := json.Marshal(map[string]string{"username": s.User, "password": s.password})
	err := s.raw(ctx, http.MethodPost, "/api/login", body, nil)
	s.mu.Lock()
	s.signedIn = err == nil
	s.mu.Unlock()
	return err
}

// SignOut ends the session.
func (s *Session) SignOut(ctx context.Context) error {
	err := s.raw(ctx, http.MethodPost, "/api/logout", nil, nil)
	s.mu.Lock()
	s.signedIn = false
	s.mu.Unlock()
	return err
}

// Do calls the API, signing in first when needed; out, when not nil,
// gets the JSON answer.
func (s *Session) Do(ctx context.Context, method, path string, in, out any) error {
	s.mu.Lock()
	signed := s.signedIn
	s.mu.Unlock()
	if !signed {
		if err := s.SignIn(ctx); err != nil {
			return err
		}
	}
	var body []byte
	if in != nil {
		var err error
		if body, err = json.Marshal(in); err != nil {
			return err
		}
	}
	err := s.raw(ctx, method, path, body, out)
	if statusOf(err) == http.StatusUnauthorized {
		s.mu.Lock()
		s.signedIn = false
		s.mu.Unlock()
	}
	return err
}

func (s *Session) raw(ctx context.Context, method, path string, body []byte, out any) error {
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, s.Base+path, rd)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	// As a page of the same site sends it, so the cross-site check passes
	// the way it does for a browser.
	req.Header.Set("Origin", s.Base)
	req.Header.Set("Accept", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return &apiError{Status: resp.StatusCode, Body: truncate(string(b), 300)}
	}
	if out != nil && len(b) > 0 {
		if err := json.Unmarshal(b, out); err != nil {
			return fmt.Errorf("%s %s: %w", method, path, err)
		}
	}
	return nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// clusterView is the part of GET /api/cluster the load generator uses.
type clusterView struct {
	Self  string `json:"self"`
	Lease struct {
		HolderName string `json:"holder_name"`
		Epoch      int64  `json:"epoch"`
		Mine       bool   `json:"mine"`
	} `json:"lease"`
	Servers []struct {
		Name    string `json:"name"`
		Self    bool   `json:"self"`
		State   string `json:"state"`
		Jobs    string `json:"jobs"`
		NodeURL string `json:"node_url"`
	} `json:"servers"`
}

// selfName is the name of the server that answered.
func (v clusterView) selfName() string {
	for _, s := range v.Servers {
		if s.Self {
			return s.Name
		}
	}
	return ""
}

// live lists the servers that are ready.
func (v clusterView) live() []string {
	var out []string
	for _, s := range v.Servers {
		if s.State == "ready" {
			out = append(out, s.Name)
		}
	}
	return out
}
