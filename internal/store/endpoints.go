package store

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jrsamsanchez/signalith/internal/redact"
)

// A server may know several addresses of one OpenSearch cluster
// (opensearch.url and opensearch.urls). Requests are spread over them in
// turn; an address that fails to answer is skipped for endpointDownFor,
// and a request that failed on one is tried on the next only when sending
// it twice cannot store anything twice or turn a write that went through
// into a false conflict.

// endpointDownFor is how long an address that failed is skipped.
var endpointDownFor = 30 * time.Second

// endpoint is one OpenSearch address.
type endpoint struct {
	base string
	// shown is base as errors show it, with any secrets hidden.
	shown string
	// proxyHint is added to connection errors when the environment names
	// a proxy that OpenSearch traffic does not use.
	proxyHint string
	// downUntil is when the address is tried in turn again, in Unix
	// nanoseconds; 0 when it is up.
	downUntil atomic.Int64
	mu        sync.Mutex
	reason    string
}

// EndpointStatus is one OpenSearch address and whether it is skipped.
type EndpointStatus struct {
	URL string `json:"url"`
	// Down is set while the address is skipped after a failure, until
	// Until; Reason is that failure.
	Down   bool      `json:"down"`
	Until  time.Time `json:"until,omitzero"`
	Reason string    `json:"reason,omitempty"`
}

// endpointSet is every address of the cluster, in the order configured.
type endpointSet struct {
	list []*endpoint
	next atomic.Uint64
	now  func() time.Time
}

// endpointList returns cfg.URL followed by cfg.URLs, each without a
// trailing slash, leaving out repeats. An entry of URLs with a user name
// or password in it is an error: only URL may carry them.
func endpointList(cfg Config) ([]string, error) {
	out := []string{strings.TrimRight(cfg.URL, "/")}
	seen := map[string]bool{out[0]: true}
	var errs []error
	for _, u := range strings.Split(cfg.URLs, ",") {
		u = strings.TrimRight(strings.TrimSpace(u), "/")
		if u == "" {
			continue
		}
		if _, _, _, ok := redact.Strip(u); ok {
			errs = append(errs, fmt.Errorf("opensearch address %s has a user name or password in it; set them in opensearch.username and opensearch.password", redact.URL(u)))
			continue
		}
		if !seen[u] {
			seen[u] = true
			out = append(out, u)
		}
	}
	return out, errors.Join(errs...)
}

func newEndpointSet(cfg Config, bases []string) *endpointSet {
	s := &endpointSet{now: time.Now}
	for _, b := range bases {
		s.list = append(s.list, &endpoint{base: b, shown: redact.URL(b), proxyHint: proxyHint(cfg, b)})
	}
	return s
}

func (e *endpoint) down(now time.Time) bool { return e.downUntil.Load() > now.UnixNano() }

// pick returns the addresses to try a request on, in order: the up ones,
// starting with the next in turn, then the down ones. When every address
// is down they are all still tried, in the order configured.
func (s *endpointSet) pick() []*endpoint {
	if len(s.list) == 1 {
		return s.list
	}
	now := s.now()
	var up, down []*endpoint
	for _, e := range s.list {
		if e.down(now) {
			down = append(down, e)
		} else {
			up = append(up, e)
		}
	}
	if len(up) > 1 {
		start := int(s.next.Add(1)-1) % len(up)
		up = append(up[start:len(up):len(up)], up[:start]...)
	}
	return append(up, down...)
}

// markDown skips e for endpointDownFor. With one address nothing is
// marked: there is nowhere else to go.
func (s *endpointSet) markDown(e *endpoint, reason error) {
	if len(s.list) == 1 {
		return
	}
	e.mu.Lock()
	e.reason = reason.Error()
	e.mu.Unlock()
	e.downUntil.Store(s.now().Add(endpointDownFor).UnixNano())
}

// markUp ends a skip after e answered.
func (s *endpointSet) markUp(e *endpoint) {
	if len(s.list) == 1 || e.downUntil.Load() == 0 {
		return
	}
	e.downUntil.Store(0)
	e.mu.Lock()
	e.reason = ""
	e.mu.Unlock()
}

// Status reports every address and whether it is skipped.
func (s *endpointSet) Status() []EndpointStatus {
	now := s.now()
	out := make([]EndpointStatus, 0, len(s.list))
	for _, e := range s.list {
		st := EndpointStatus{URL: e.shown}
		if until := e.downUntil.Load(); until > now.UnixNano() {
			st.Down, st.Until = true, time.Unix(0, until)
			e.mu.Lock()
			st.Reason = e.reason
			e.mu.Unlock()
		}
		out = append(out, st)
	}
	return out
}

// Endpoints reports this client's OpenSearch addresses, the first being
// Endpoint, and which are skipped after a failure.
func (c *Client) Endpoints() []EndpointStatus { return c.eps.Status() }

// failsOver reports whether an answer from OpenSearch says the address,
// not the request, is the trouble: a proxy or load balancer in front of a
// node that is gone, or a node that is unavailable. 429 and cluster blocks
// are the whole cluster's, so they do not count.
func failsOver(status int) bool {
	return status == http.StatusBadGateway || status == http.StatusServiceUnavailable || status == http.StatusGatewayTimeout
}

// resendable reports whether a request that may have reached OpenSearch
// can be sent again to another address without any harm: reads, and a
// bulk request whose every action names its document's _id (a document
// already stored is then refused as a conflict, which the caller drops
// with WithoutConflicts, or is written over with the same source). Other
// writes are not resent; the conditional ones in docs.go find out
// whether they went through by reading the document again, which goes to
// another address once this one is down.
func resendable(method, path string, body []byte) bool {
	if method == http.MethodGet || method == http.MethodHead {
		return true
	}
	if method != http.MethodPost {
		return false
	}
	p, _, _ := strings.Cut(path, "?")
	switch {
	case strings.HasSuffix(p, "/_search/scroll"):
		// Each call moves the scroll on: a resend would skip a page.
		return false
	case strings.HasSuffix(p, "/_search"), strings.HasSuffix(p, "/_count"), strings.HasSuffix(p, "/_mget"),
		strings.HasSuffix(p, "/_msearch"):
		return true
	case strings.HasSuffix(p, "/_bulk"):
		return bulkHasIDs(body)
	}
	return false
}

// bulkHasIDs reports whether every action of a bulk body is a create or
// index of a document with an explicit _id.
func bulkHasIDs(body []byte) bool {
	sc := bufio.NewScanner(bytes.NewReader(body))
	sc.Buffer(make([]byte, 0, 64*1024), len(body)+1)
	actions := 0
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var action map[string]struct {
			ID string `json:"_id"`
		}
		if json.Unmarshal(line, &action) != nil || len(action) != 1 {
			return false
		}
		for op, meta := range action {
			if (op != "create" && op != "index") || meta.ID == "" {
				return false
			}
		}
		actions++
		// The document's own line follows.
		if !sc.Scan() {
			return false
		}
	}
	return sc.Err() == nil && actions > 0
}

// failedOverError is the last error of a request every address failed.
type failedOverError struct {
	err    error
	shown  string
	others int
}

func (e *failedOverError) Error() string {
	msg := e.err.Error()
	var se *Error
	if errors.As(e.err, &se) {
		msg += " (at " + e.shown + ")"
	}
	addresses := "addresses"
	if e.others == 1 {
		addresses = "address"
	}
	return fmt.Sprintf("%s (%d other OpenSearch %s also failed)", msg, e.others, addresses)
}

func (e *failedOverError) Unwrap() error { return e.err }
