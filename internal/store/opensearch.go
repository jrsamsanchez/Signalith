// Package store talks to OpenSearch over its REST API using only net/http,
// so the server stays a single dependency-light binary on Windows and Linux.
package store

import (
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
	"net/http/httptrace"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jrsamsanchez/signalith/internal/redact"
	"github.com/jrsamsanchez/signalith/internal/secrets"
)

// Searcher runs a search request body against an index pattern.
type Searcher interface {
	Search(ctx context.Context, index string, body map[string]any) (map[string]any, error)
}

// Config holds connection settings.
type Config struct {
	// URL is the OpenSearch address. A user name and password in it are
	// used as Username and Password (when those are empty) and are never
	// shown in errors.
	URL      string
	Username string
	// Password shows as [redacted] when a Config is printed or logged.
	Password secrets.Secret
	// CAFile is a PEM file of certificate authorities to trust, in
	// addition to the system's, for an OpenSearch with a private CA.
	CAFile string
	// CertFile and KeyFile are a client certificate and its key to present
	// to OpenSearch. They are read again when they change on disk, so a
	// renewed certificate needs no restart.
	CertFile, KeyFile string
	// TLSSkipVerify turns certificate checks off. Anyone on the network
	// path can then read and change the traffic; for lab clusters only.
	TLSSkipVerify bool
	// Proxy is the proxy URL for OpenSearch traffic. Empty connects
	// directly: the HTTP_PROXY and HTTPS_PROXY environment variables are
	// deliberately ignored, because a proxy would see every event and the
	// OpenSearch password.
	Proxy   string
	Timeout time.Duration
	// MaxResponseBytes caps the size of one answer read into memory; 0
	// means no cap. A connection test sets a small one, since it may be
	// pointed at any address.
	MaxResponseBytes int64
}

// ErrResponseTooLarge is an answer larger than Config.MaxResponseBytes.
var ErrResponseTooLarge = errors.New("the answer is larger than OpenSearch sends here")

// Client is an OpenSearch REST client.
type Client struct {
	base string
	// shown is base as errors show it, with any secrets hidden.
	shown string
	cfg   Config
	http  *http.Client
	// setupErr is why the TLS or proxy settings could not be used; every
	// request then fails with it. config.Validate reports the same
	// problems before the server starts.
	setupErr error
	// proxyHint is added to connection errors when the environment names
	// a proxy that OpenSearch traffic does not use.
	proxyHint string
}

// New returns a client for one OpenSearch endpoint.
func New(cfg Config) *Client {
	if cfg.Timeout == 0 {
		cfg.Timeout = 60 * time.Second
	}
	if stripped, user, pw, ok := redact.Strip(cfg.URL); ok {
		cfg.URL = stripped
		if cfg.Username == "" {
			cfg.Username, cfg.Password = user, secrets.New("opensearch.password", pw)
		}
	}
	base := strings.TrimRight(cfg.URL, "/")
	tr, err := Transport(cfg)
	c := &Client{
		base:     base,
		shown:    redact.URL(base),
		cfg:      cfg,
		setupErr: err,
		http: &http.Client{Timeout: cfg.Timeout, Transport: tr,
			// A redirect is never part of the OpenSearch API, and following
			// one could send the credentials somewhere else.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}
	c.proxyHint = proxyHint(cfg, base)
	return c
}

// Endpoint is the OpenSearch address, as errors show it: without any
// password.
func (c *Client) Endpoint() string { return c.shown }

// CloseIdleConnections closes the connections kept open for the next
// request, for a client that is no longer used, such as the one of the
// settings in use before a restart.
func (c *Client) CloseIdleConnections() {
	if c.setupErr == nil {
		c.http.CloseIdleConnections()
	}
}

// Transport returns the HTTP transport for cfg: TLS 1.2 or newer, the
// system's certificate authorities plus cfg.CAFile, the client
// certificate if set, and no proxy unless cfg.Proxy is set. On an error
// it still returns a usable transport without the broken setting.
func Transport(cfg Config) (*http.Transport, error) {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.Proxy = nil
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	tr.TLSClientConfig = tlsCfg
	var errs []error
	if cfg.Proxy != "" {
		if u, err := url.Parse(cfg.Proxy); err != nil || u.Host == "" {
			errs = append(errs, fmt.Errorf("opensearch proxy %q is not a URL such as http://proxy:3128", redact.URL(cfg.Proxy)))
		} else {
			tr.Proxy = http.ProxyURL(u)
		}
	}
	if cfg.TLSSkipVerify {
		tlsCfg.InsecureSkipVerify = true //nolint:gosec // opt-in for lab clusters; warned about at startup
	}
	if cfg.CAFile != "" {
		pool, err := LoadCAFile(cfg.CAFile)
		if err != nil {
			errs = append(errs, err)
		} else {
			tlsCfg.RootCAs = pool
		}
	}
	if cfg.CertFile != "" || cfg.KeyFile != "" {
		kp := &keyPair{cert: cfg.CertFile, key: cfg.KeyFile}
		if _, err := kp.get(nil); err != nil {
			errs = append(errs, err)
		} else {
			tlsCfg.GetClientCertificate = kp.get
		}
	}
	return tr, errors.Join(errs...)
}

// proxyHint explains, for connection errors, that a proxy named in the
// environment is not used for OpenSearch: after an upgrade, an OpenSearch
// that was only reachable through HTTPS_PROXY otherwise fails with a bare
// dial or DNS error. It is empty when cfg.Proxy is set, OpenSearch is on
// this machine, or NO_PROXY covers its host.
func proxyHint(cfg Config, base string) string {
	if cfg.Proxy != "" {
		return ""
	}
	u, err := url.Parse(base)
	if err != nil || u.Hostname() == "" {
		return ""
	}
	host := strings.ToLower(u.Hostname())
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return ""
	}
	if a, err := netip.ParseAddr(host); err == nil && a.Unmap().IsLoopback() {
		return ""
	}
	names := []string{"HTTP_PROXY", "http_proxy"}
	if u.Scheme == "https" {
		names = []string{"HTTPS_PROXY", "https_proxy"}
	}
	for _, name := range names {
		if os.Getenv(name) == "" {
			continue
		}
		if noProxy(host) {
			return ""
		}
		return fmt.Sprintf(" (%s is set, but Signalith never sends OpenSearch traffic through proxies named in the environment; "+
			"if OpenSearch can only be reached through that proxy, set opensearch.proxy or SIGNALITH_OPENSEARCH_PROXY)", name)
	}
	return ""
}

// noProxy reports whether NO_PROXY names host (exactly, as a parent
// domain, as a CIDR holding it, or with "*").
func noProxy(host string) bool {
	list := os.Getenv("NO_PROXY")
	if list == "" {
		list = os.Getenv("no_proxy")
	}
	a, aErr := netip.ParseAddr(host)
	for _, e := range strings.Split(list, ",") {
		e = strings.ToLower(strings.TrimSpace(e))
		if e == "*" {
			return true
		}
		if p, err := netip.ParsePrefix(e); err == nil {
			if aErr == nil && p.Contains(a.Unmap()) {
				return true
			}
			continue
		}
		if h, _, err := net.SplitHostPort(e); err == nil {
			e = h
		}
		e = strings.TrimPrefix(strings.TrimPrefix(e, "*"), ".")
		if e != "" && (host == e || strings.HasSuffix(host, "."+e)) {
			return true
		}
	}
	return false
}

// LoadCAFile returns the system's certificate authorities plus those in
// the PEM file at path.
func LoadCAFile(path string) (*x509.CertPool, error) {
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("opensearch CA file: %w", err)
	}
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("opensearch CA file %s holds no PEM certificates (it should contain -----BEGIN CERTIFICATE-----)", path)
	}
	return pool, nil
}

// keyPair loads a client certificate, again whenever its files change.
type keyPair struct {
	cert, key string
	mu        sync.Mutex
	loaded    *tls.Certificate
	stamp     string
}

func (k *keyPair) get(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	stamp := ""
	for _, p := range []string{k.cert, k.key} {
		if st, err := os.Stat(p); err == nil {
			stamp += st.ModTime().String() + fmt.Sprint(st.Size())
		}
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.loaded != nil && stamp == k.stamp {
		return k.loaded, nil
	}
	c, err := tls.LoadX509KeyPair(k.cert, k.key)
	if err != nil {
		if k.loaded != nil {
			// Halfway through replacing the files: keep the old pair.
			return k.loaded, nil
		}
		return nil, fmt.Errorf("opensearch client certificate %s and key %s: %w", k.cert, k.key, err)
	}
	k.loaded, k.stamp = &c, stamp
	return k.loaded, nil
}

// Error is a non-2xx response from OpenSearch.
type Error struct {
	Status int
	Body   string
}

func (e *Error) Error() string {
	body := e.Body
	var parsed struct {
		Error struct {
			Type      string `json:"type"`
			Reason    string `json:"reason"`
			RootCause []struct {
				Reason string `json:"reason"`
			} `json:"root_cause"`
		} `json:"error"`
	}
	if json.Unmarshal([]byte(e.Body), &parsed) == nil && parsed.Error.Reason != "" {
		body = parsed.Error.Type + ": " + parsed.Error.Reason
		if len(parsed.Error.RootCause) > 0 && parsed.Error.RootCause[0].Reason != parsed.Error.Reason {
			body += " (" + parsed.Error.RootCause[0].Reason + ")"
		}
	}
	if len(body) > 500 {
		body = body[:500] + "..."
	}
	return fmt.Sprintf("opensearch returned %d: %s", e.Status, body)
}

// Do sends a request and decodes a JSON response into out (if non-nil).
func (c *Client) Do(ctx context.Context, method, path string, body any, out any) error {
	var rd io.Reader
	contentType := "application/json"
	switch b := body.(type) {
	case nil:
	case []byte:
		rd = bytes.NewReader(b)
		contentType = "application/x-ndjson"
	default:
		buf, err := json.Marshal(b)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(buf)
	}
	if c.setupErr != nil {
		return c.setupErr
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, rd)
	if err != nil {
		// The parse error would repeat the whole URL.
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return fmt.Errorf("opensearch request to %s: %w", c.shown, err)
	}
	if rd != nil {
		req.Header.Set("Content-Type", contentType)
	}
	if c.cfg.Username != "" {
		req.SetBasicAuth(c.cfg.Username, c.cfg.Password.Reveal())
	}
	// sent tells a request that timed out after it reached OpenSearch
	// (which is then too slow) from one that never got there. reused
	// marks one sent on a connection kept from an earlier request, which
	// may lead nowhere by now: see reachable.
	var sent, reused atomic.Bool
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), &httptrace.ClientTrace{
		GotConn: func(i httptrace.GotConnInfo) { reused.Store(i.Reused) },
		WroteRequest: func(i httptrace.WroteRequestInfo) {
			if i.Err == nil {
				sent.Store(true)
			}
		},
	}))
	resp, err := c.http.Do(req)
	if err != nil {
		// Go hides the password in the URL it repeats, but not the rest.
		var ue *url.Error
		if errors.As(err, &ue) {
			ue.URL = redact.URL(ue.URL)
		}
		if sent.Load() && timedOut(err) && (!reused.Load() || c.reachable()) {
			return &noAnswerError{msg: fmt.Sprintf("opensearch at %s did not answer in time: %v%s", c.shown, err, c.proxyHint), err: err}
		}
		return fmt.Errorf("opensearch unreachable at %s: %w%s", c.shown, err, c.proxyHint)
	}
	defer resp.Body.Close()
	var rd2 io.Reader = resp.Body
	if limit := c.cfg.MaxResponseBytes; limit > 0 {
		rd2 = io.LimitReader(resp.Body, limit+1)
	}
	data, err := io.ReadAll(rd2)
	if err != nil {
		return err
	}
	if limit := c.cfg.MaxResponseBytes; limit > 0 && int64(len(data)) > limit {
		return fmt.Errorf("%s at %s: %w", path, c.shown, ErrResponseTooLarge)
	}
	if resp.StatusCode/100 == 3 {
		return fmt.Errorf("opensearch at %s answered with a redirect (%d) to %q; Signalith does not follow redirects, so set opensearch.url to the address OpenSearch is really at",
			c.shown, resp.StatusCode, redact.URL(resp.Header.Get("Location")))
	}
	if resp.StatusCode/100 != 2 {
		return &Error{Status: resp.StatusCode, Body: string(data)}
	}
	if out != nil {
		dec := json.NewDecoder(bytes.NewReader(data))
		dec.UseNumber()
		return dec.Decode(out)
	}
	return nil
}

// Search implements Searcher.
func (c *Client) Search(ctx context.Context, index string, body map[string]any) (map[string]any, error) {
	var out map[string]any
	path := "/" + url.PathEscape(index) + "/_search?ignore_unavailable=true&allow_no_indices=true"
	err := c.Do(ctx, http.MethodPost, path, body, &out)
	return out, err
}

// reachable reports whether a new connection to OpenSearch can be made
// within a few seconds. A request on a kept connection that timed out
// proves little: when OpenSearch's computer was turned off or its network
// cut, the request is still written, into a connection that leads nowhere.
// So the request counts as one OpenSearch took but didn't answer only when
// OpenSearch still takes connections. It also drops the other kept
// connections, which may lead nowhere too. Through a proxy it can't tell,
// and reports true.
func (c *Client) reachable() bool {
	c.http.CloseIdleConnections()
	if c.cfg.Proxy != "" {
		return true
	}
	u, err := url.Parse(c.base)
	if err != nil || u.Hostname() == "" {
		return true
	}
	port := u.Port()
	if port == "" {
		port = "80"
		if u.Scheme == "https" {
			port = "443"
		}
	}
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(u.Hostname(), port), 3*time.Second)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// Health returns cluster health ("green", "yellow", "red").
func (c *Client) Health(ctx context.Context) (string, error) {
	var out struct {
		Status string `json:"status"`
	}
	err := c.Do(ctx, http.MethodGet, "/_cluster/health", nil, &out)
	return out.Status, err
}

// BulkItemError describes one rejected document in a bulk request.
type BulkItemError struct {
	Index  string
	Reason string
	// Pos is the document's position in the request, from 0, Type the
	// OpenSearch error type, such as mapper_parsing_exception, and Status
	// the item's HTTP status, such as 429 (0 when unknown).
	Pos    int    `json:"-"`
	Type   string `json:"-"`
	Status int    `json:"-"`
}

// Conflict reports whether OpenSearch refused the document because one
// with its ID is already stored.
func (e BulkItemError) Conflict() bool {
	return e.Status == http.StatusConflict || e.Type == "version_conflict_engine_exception"
}

// WithoutConflicts drops the errors saying a document sent with an
// explicit ID is already stored, and reports how many there were. Such a
// document is "already there" because an earlier send of the same write
// got it in (a retry after a lost answer, or another server writing the
// same thing), so the write succeeded. A conflict on a document without
// an ID, and every other error, is kept.
func WithoutConflicts(errs []BulkItemError, docs []IndexedDoc) ([]BulkItemError, int) {
	var out []BulkItemError
	n := 0
	for _, e := range errs {
		if e.Conflict() && e.Pos >= 0 && e.Pos < len(docs) && docs[e.Pos].ID != "" {
			n++
			continue
		}
		out = append(out, e)
	}
	return out, n
}

// Bulk indexes documents. docs maps each document to its target index.
func (c *Client) Bulk(ctx context.Context, docs []IndexedDoc) ([]BulkItemError, error) {
	if len(docs) == 0 {
		return nil, nil
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for _, d := range docs {
		meta := map[string]any{"_index": d.Index}
		if d.ID != "" {
			meta["_id"] = d.ID
		}
		if err := enc.Encode(map[string]any{"create": meta}); err != nil {
			return nil, err
		}
		if err := enc.Encode(d.Doc); err != nil {
			return nil, err
		}
	}
	var out struct {
		Errors bool `json:"errors"`
		Items  []map[string]struct {
			Index  string `json:"_index"`
			Status int    `json:"status"`
			Error  *struct {
				Type   string `json:"type"`
				Reason string `json:"reason"`
			} `json:"error"`
		} `json:"items"`
	}
	if err := c.Do(ctx, http.MethodPost, "/_bulk", buf.Bytes(), &out); err != nil {
		return nil, err
	}
	var errs []BulkItemError
	if out.Errors {
		for i, item := range out.Items {
			for _, r := range item {
				if r.Error != nil {
					errs = append(errs, BulkItemError{Index: r.Index, Reason: r.Error.Type + ": " + r.Error.Reason, Pos: i, Type: r.Error.Type, Status: r.Status})
				}
			}
		}
	}
	return errs, nil
}

// IndexedDoc is one document and the index it goes to.
type IndexedDoc struct {
	Index string
	// ID, when set, is the document's _id: writing the same one again is
	// refused as a conflict (409) instead of storing it twice.
	ID  string
	Doc map[string]any
}

// PutIndexTemplate creates or replaces a composable index template.
func (c *Client) PutIndexTemplate(ctx context.Context, name string, tmpl map[string]any) error {
	return c.Do(ctx, http.MethodPut, "/_index_template/"+url.PathEscape(name), tmpl, nil)
}

// ListIndices returns index names matching a pattern.
func (c *Client) ListIndices(ctx context.Context, pattern string) ([]string, error) {
	var out []struct {
		Index string `json:"index"`
	}
	err := c.Do(ctx, http.MethodGet, "/_cat/indices/"+url.PathEscape(pattern)+"?format=json&h=index&expand_wildcards=open", nil, &out)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(out))
	for _, o := range out {
		names = append(names, o.Index)
	}
	return names, nil
}

// DeleteIndex deletes one index.
func (c *Client) DeleteIndex(ctx context.Context, name string) error {
	return c.Do(ctx, http.MethodDelete, "/"+url.PathEscape(name), nil, nil)
}

// Mapping returns the merged field -> type map for an index pattern,
// flattening object fields to dotted names.
func (c *Client) Mapping(ctx context.Context, pattern string) (map[string]string, error) {
	var out map[string]struct {
		Mappings struct {
			Properties map[string]any `json:"properties"`
		} `json:"mappings"`
	}
	err := c.Do(ctx, http.MethodGet, "/"+url.PathEscape(pattern)+"/_mapping?ignore_unavailable=true&allow_no_indices=true", nil, &out)
	if err != nil {
		return nil, err
	}
	fields := map[string]string{}
	for _, idx := range out {
		flattenMapping("", idx.Mappings.Properties, fields)
	}
	return fields, nil
}

func flattenMapping(prefix string, props map[string]any, out map[string]string) {
	for name, v := range props {
		m, ok := v.(map[string]any)
		if !ok {
			continue
		}
		full := name
		if prefix != "" {
			full = prefix + "." + name
		}
		if sub, ok := m["properties"].(map[string]any); ok {
			flattenMapping(full, sub, out)
			continue
		}
		if t, ok := m["type"].(string); ok {
			out[full] = t
		}
	}
}
