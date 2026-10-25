// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

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
	"maps"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/netip"
	"net/url"
	"os"
	"slices"
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
	URL string
	// URLs are more addresses of the same OpenSearch cluster, separated
	// by commas, without user names or passwords. Requests are spread over
	// URL and these, and one that is down is skipped for a while. (A
	// string, not a slice, so that a Config can be compared with ==.)
	URLs     string
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
	// ManagedCertFile and ManagedKeyFile are the client certificate and
	// key the cluster issued this server (internal/clusterpki). Whenever
	// both are there and the certificate has not expired, they are
	// presented instead of CertFile and KeyFile; until then, and when
	// they cannot be read, CertFile and KeyFile are.
	ManagedCertFile, ManagedKeyFile string
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

// ErrResponseTooLarge is an answer larger than Config.MaxResponseBytes,
// or than the limit WithMaxResponse put on a request.
var ErrResponseTooLarge = errors.New("the answer is larger than OpenSearch sends here")

type maxResponseKey struct{}

// WithMaxResponse returns ctx with a cap on the size of each answer read
// for requests made with it, below Config.MaxResponseBytes if that is
// set: a request whose answer a sender's data can make huge (an
// aggregation over their values) fails instead of filling memory.
func WithMaxResponse(ctx context.Context, n int64) context.Context {
	return context.WithValue(ctx, maxResponseKey{}, n)
}

// maxResponse is the cap on one answer to a request made with ctx; 0 for
// none.
func (c *Client) maxResponse(ctx context.Context) int64 {
	limit := c.cfg.MaxResponseBytes
	if n, ok := ctx.Value(maxResponseKey{}).(int64); ok && n > 0 && (limit <= 0 || n < limit) {
		limit = n
	}
	return limit
}

// Client is an OpenSearch REST client.
type Client struct {
	// eps are the OpenSearch addresses; with only Config.URL set, one.
	eps  *endpointSet
	cfg  Config
	http *http.Client
	// setupErr is why the TLS or proxy settings could not be used; every
	// request then fails with it. config.Validate reports the same
	// problems before the server starts.
	setupErr error
}

// New returns a client for one OpenSearch cluster, at Config.URL and any
// Config.URLs. All addresses share one transport, and so one client
// certificate.
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
	bases, listErr := endpointList(cfg)
	tr, err := Transport(cfg)
	c := &Client{
		eps:      newEndpointSet(cfg, bases),
		cfg:      cfg,
		setupErr: errors.Join(err, listErr),
		http: &http.Client{Timeout: cfg.Timeout, Transport: tr,
			// A redirect is never part of the OpenSearch API, and following
			// one could send the credentials somewhere else.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}
	return c
}

// Endpoint is the (first) OpenSearch address, as errors show it: without
// any password.
func (c *Client) Endpoint() string { return c.eps.list[0].shown }

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
	// Ingest runs many bulk writes at once (ingest.DefaultMaxConcurrent);
	// the default of 2 idle connections per host would make most of them
	// open a new TLS connection each time.
	tr.MaxIdleConns = 128
	tr.MaxIdleConnsPerHost = 64
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
	if cfg.ManagedCertFile != "" && cfg.ManagedKeyFile != "" {
		m := &managedPair{managed: keyPair{cert: cfg.ManagedCertFile, key: cfg.ManagedKeyFile}, fallback: tlsCfg.GetClientCertificate}
		tlsCfg.GetClientCertificate = m.get
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

// managedPair presents the client certificate the cluster issued this
// server while it is there and valid, and the configured one (fallback)
// otherwise. Checked on each connection, so the switch needs no restart.
type managedPair struct {
	managed  keyPair
	fallback func(*tls.CertificateRequestInfo) (*tls.Certificate, error)
}

func (m *managedPair) get(info *tls.CertificateRequestInfo) (*tls.Certificate, error) {
	if _, err := os.Stat(m.managed.cert); err == nil {
		if c, err := m.managed.get(info); err == nil && c.Leaf != nil && time.Now().Before(c.Leaf.NotAfter) {
			return c, nil
		}
	}
	if m.fallback != nil {
		return m.fallback(info)
	}
	// No certificate: the same as not being asked for one.
	return &tls.Certificate{}, nil
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
// With several OpenSearch addresses, a request that could not be sent to
// one is tried on the next, and so is one that may have arrived, when
// sending it again is harmless (see resendable).
func (c *Client) Do(ctx context.Context, method, path string, body any, out any) error {
	var raw []byte
	contentType := "application/json"
	switch b := body.(type) {
	case nil:
	case []byte:
		raw = b
		contentType = "application/x-ndjson"
	default:
		buf, err := json.Marshal(b)
		if err != nil {
			return err
		}
		raw = buf
	}
	if c.setupErr != nil {
		return c.setupErr
	}
	eps := c.eps.pick()
	if len(eps) == 1 {
		err, _ := c.doOne(ctx, eps[0], method, path, raw, body != nil, contentType, out)
		return err
	}
	var last error
	var lastAt *endpoint
	tried := 0
	for i, e := range eps {
		if i > 0 && ctx.Err() != nil {
			break
		}
		err, fail := c.doOne(ctx, e, method, path, raw, body != nil, contentType, out)
		tried++
		if fail == failNone {
			c.eps.markUp(e)
			return err
		}
		c.eps.markDown(e, err)
		last, lastAt = err, e
		if fail == failAfterSend && !resendable(method, path, raw) {
			break
		}
	}
	if tried == 1 {
		return last
	}
	return &failedOverError{err: last, shown: lastAt.shown, others: tried - 1}
}

// failure says whether a request failed because of the address it was
// sent to, and whether it was sent first.
type failure int

const (
	// failNone: OpenSearch answered (possibly with an error).
	failNone failure = iota
	// failNotSent: no byte of the request was sent.
	failNotSent
	// failAfterSend: the request may have arrived, and then the
	// connection failed, the time ran out or a proxy in front of
	// OpenSearch answered 502, 503 or 504.
	failAfterSend
)

// doOne sends a request to one address.
func (c *Client) doOne(ctx context.Context, e *endpoint, method, path string, raw []byte, hasBody bool, contentType string, out any) (error, failure) {
	var rd io.Reader
	if hasBody {
		rd = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, e.base+path, rd)
	if err != nil {
		// The parse error would repeat the whole URL.
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return fmt.Errorf("opensearch request to %s: %w", e.shown, err), failNone
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
		fail := failNotSent
		if sent.Load() {
			fail = failAfterSend
		}
		// Go hides the password in the URL it repeats, but not the rest.
		var ue *url.Error
		if errors.As(err, &ue) {
			ue.URL = redact.URL(ue.URL)
		}
		if sent.Load() && timedOut(err) && (!reused.Load() || c.reachable(e)) {
			return &noAnswerError{msg: fmt.Sprintf("opensearch at %s did not answer in time: %v%s", e.shown, err, e.proxyHint), err: err}, fail
		}
		return &unreachableError{msg: fmt.Sprintf("opensearch unreachable at %s: %v%s", e.shown, err, e.proxyHint), err: err}, fail
	}
	defer resp.Body.Close()
	var rd2 io.Reader = resp.Body
	limit := c.maxResponse(ctx)
	if limit > 0 {
		rd2 = io.LimitReader(resp.Body, limit+1)
	}
	data, err := io.ReadAll(rd2)
	if err != nil {
		return err, failAfterSend
	}
	if limit > 0 && int64(len(data)) > limit {
		return fmt.Errorf("%s at %s: %w", path, e.shown, ErrResponseTooLarge), failNone
	}
	if resp.StatusCode/100 == 3 {
		return fmt.Errorf("opensearch at %s answered with a redirect (%d) to %q; Signalith does not follow redirects, so set opensearch.url to the address OpenSearch is really at",
			e.shown, resp.StatusCode, redact.URL(resp.Header.Get("Location"))), failNone
	}
	if resp.StatusCode/100 != 2 {
		fail := failNone
		if failsOver(resp.StatusCode) {
			fail = failAfterSend
		}
		return &Error{Status: resp.StatusCode, Body: string(data)}, fail
	}
	if out != nil {
		dec := json.NewDecoder(bytes.NewReader(data))
		dec.UseNumber()
		return dec.Decode(out), failNone
	}
	return nil, failNone
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
func (c *Client) reachable(e *endpoint) bool {
	c.http.CloseIdleConnections()
	if c.cfg.Proxy != "" {
		return true
	}
	u, err := url.Parse(e.base)
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

// WriteBlocks says, in sentences, what OpenSearch's blocks keep it from
// writing: a cluster-wide block (one an admin set, or cluster.blocks.
// create_index, which OpenSearch sets itself when every data disk passes
// its high watermark), and indices made read-only, as at the flood-stage
// watermark. It returns nothing when writes are not blocked. Cluster
// health stays green through all of these.
func (c *Client) WriteBlocks(ctx context.Context) ([]string, error) {
	type block struct {
		Description string   `json:"description"`
		Levels      []string `json:"levels"`
	}
	var out struct {
		Blocks struct {
			Global  map[string]block            `json:"global"`
			Indices map[string]map[string]block `json:"indices"`
		} `json:"blocks"`
	}
	if err := c.Do(ctx, http.MethodGet, "/_cluster/state/blocks", nil, &out); err != nil {
		return nil, err
	}
	writes := func(b block) bool {
		return slices.ContainsFunc(b.Levels, func(l string) bool { return l == "write" || l == "metadata_write" || l == "create_index" })
	}
	var says []string
	ids := slices.Sorted(maps.Keys(out.Blocks.Global))
	for _, id := range ids {
		b := out.Blocks.Global[id]
		switch {
		case !writes(b):
		case strings.Contains(b.Description, "create-index"):
			says = append(says, "OpenSearch refuses to create indices (cluster.blocks.create_index), as it does by itself when every data disk passes its high watermark (90% full by default), so new days' events, cases and detection state can't be stored.")
		default:
			says = append(says, "OpenSearch blocks writes to the whole cluster ("+b.Description+").")
		}
	}
	var readOnly []string
	for index, bs := range out.Blocks.Indices {
		for _, b := range bs {
			if writes(b) {
				readOnly = append(readOnly, index)
				break
			}
		}
	}
	if n := len(readOnly); n > 0 {
		slices.Sort(readOnly)
		what := readOnly[0]
		if n > 1 {
			what = fmt.Sprintf("%d indices, %s among them,", n, readOnly[0])
		}
		says = append(says, "OpenSearch made "+what+" read-only, as it does when a disk passes its flood-stage watermark (95% full by default).")
	}
	return says, nil
}

// AutoShards is number_of_shards in the event index settings when
// opensearch.shards is automatic: ingest.PutIndexTemplate replaces it
// with a number sized from the data nodes before the template is written.
const AutoShards = "auto"

// ShardRoom returns how many shard copies the cluster holds and how many
// it allows: cluster.max_shards_per_node (1,000 unless set) times the
// data nodes. OpenSearch refuses to create an index past that limit.
func (c *Client) ShardRoom(ctx context.Context) (used, limit int, err error) {
	var health struct {
		Nodes      int `json:"number_of_data_nodes"`
		Active     int `json:"active_shards"`
		Unassigned int `json:"unassigned_shards"`
	}
	if err := c.Do(ctx, http.MethodGet, "/_cluster/health", nil, &health); err != nil {
		return 0, 0, err
	}
	var set map[string]map[string]any
	err = c.Do(ctx, http.MethodGet, "/_cluster/settings?include_defaults=true&flat_settings=true&filter_path=*.cluster.max_shards_per_node", nil, &set)
	if err != nil {
		return 0, 0, err
	}
	per := 1000
	for _, scope := range []string{"transient", "persistent", "defaults"} {
		if v, ok := set[scope]["cluster.max_shards_per_node"]; ok {
			var n int
			if _, err := fmt.Sscan(fmt.Sprint(v), &n); err == nil && n > 0 {
				per = n
				break
			}
		}
	}
	return health.Active + health.Unassigned, per * max(health.Nodes, 1), nil
}

// DataNodes returns how many data nodes the cluster has.
func (c *Client) DataNodes(ctx context.Context) (int, error) {
	var out struct {
		N int `json:"number_of_data_nodes"`
	}
	err := c.Do(ctx, http.MethodGet, "/_cluster/health", nil, &out)
	return out.N, err
}

// SearchThreads returns the size of the search thread pool summed over
// the data nodes: how many searches OpenSearch runs at once.
func (c *Client) SearchThreads(ctx context.Context) (int, error) {
	var out struct {
		Nodes map[string]struct {
			ThreadPool struct {
				Search struct {
					Size int `json:"size"`
				} `json:"search"`
			} `json:"thread_pool"`
		} `json:"nodes"`
	}
	err := c.Do(ctx, http.MethodGet, "/_nodes/data:true/thread_pool?filter_path=nodes.*.thread_pool.search.size", nil, &out)
	n := 0
	for _, nd := range out.Nodes {
		n += nd.ThreadPool.Search.Size
	}
	return n, err
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
	body, err := encodeBulk(docs)
	if err != nil {
		return nil, err
	}
	return c.sendBulk(ctx, body)
}

// encodeBulk writes docs as a _bulk request body.
func encodeBulk(docs []IndexedDoc) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for _, d := range docs {
		meta := map[string]any{"_index": d.Index}
		if d.ID != "" {
			meta["_id"] = d.ID
		}
		action := "create"
		if d.Replace {
			action = "index"
		}
		if err := enc.Encode(map[string]any{action: meta}); err != nil {
			return nil, err
		}
		if err := enc.Encode(d.Doc); err != nil {
			return nil, err
		}
	}
	return buf.Bytes(), nil
}

// sendBulk sends a _bulk request body and returns its rejected documents.
func (c *Client) sendBulk(ctx context.Context, body []byte) ([]BulkItemError, error) {
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
	if err := c.Do(ctx, http.MethodPost, "/_bulk", body, &out); err != nil {
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
	// Replace writes the document over one stored with the same ID
	// instead of refusing it.
	Replace bool
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
