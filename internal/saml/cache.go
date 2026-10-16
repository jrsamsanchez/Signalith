package saml

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"
)

// Replays remembers the assertions used, until they expire, so each is
// used once. It is kept in memory, per server: across a cluster, the
// sign-in cookie still ties each assertion to the one browser that asked
// for it (InResponseTo), and that cookie is used up by the first try.
type Replays struct {
	mu   sync.Mutex
	seen map[string]time.Time
}

// maxReplays bounds the memory used: only assertions with a valid
// signature are remembered, so reaching it takes that many sign-ins
// within an assertion's lifetime.
const maxReplays = 100_000

// Use records the assertion id, valid until expires, and reports whether
// it is fresh: false when it was used before, or when too many are
// remembered to tell.
func (r *Replays) Use(id string, expires, now time.Time) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.seen == nil {
		r.seen = map[string]time.Time{}
	}
	if until, ok := r.seen[id]; ok && now.Before(until) {
		return false
	}
	if len(r.seen) >= maxReplays {
		for k, until := range r.seen {
			if !now.Before(until) {
				delete(r.seen, k)
			}
		}
		if len(r.seen) >= maxReplays {
			return false
		}
	}
	r.seen[id] = expires
	return true
}

// Metadata fetches identity provider metadata and keeps it for an hour,
// so a new signing certificate the provider publishes is picked up. When
// the provider cannot be reached, the last copy is used for up to a day.
type Metadata struct {
	HTTP *http.Client
	Now  func() time.Time

	mu    sync.Mutex
	cache map[string]metadataEntry
}

type metadataEntry struct {
	idp     *IdP
	fetched time.Time
}

const (
	metadataFresh = time.Hour
	metadataStale = 24 * time.Hour
)

// NewMetadata returns a fetcher with its own HTTP client: TLS 1.2 or
// later, no redirects, and time limits.
func NewMetadata() *Metadata {
	tr := &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		DialContext:         (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout: 10 * time.Second,
		IdleConnTimeout:     90 * time.Second,
	}
	return &Metadata{HTTP: &http.Client{Transport: tr, Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error {
		return errors.New("the metadata address answered with a redirect, which Signalith does not follow; use the address it redirects to")
	}}}
}

func (m *Metadata) now() time.Time {
	if m.Now != nil {
		return m.Now()
	}
	return time.Now()
}

// Get returns the identity provider described at url, from the cache
// when fresh. fresh skips the cache, for a test.
func (m *Metadata) Get(ctx context.Context, url string, fresh bool) (*IdP, error) {
	now := m.now()
	m.mu.Lock()
	e, ok := m.cache[url]
	m.mu.Unlock()
	if ok && !fresh && now.Sub(e.fetched) < metadataFresh {
		return e.idp, nil
	}
	idp, err := m.Fetch(ctx, url)
	if err != nil {
		if ok && !fresh && now.Sub(e.fetched) < metadataStale {
			return e.idp, nil
		}
		return nil, err
	}
	m.mu.Lock()
	if m.cache == nil {
		m.cache = map[string]metadataEntry{}
	}
	m.cache[url] = metadataEntry{idp: idp, fetched: now}
	m.mu.Unlock()
	return idp, nil
}

// Fetch reads and parses the metadata at url.
func (m *Metadata) Fetch(ctx context.Context, url string) (*IdP, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/samlmetadata+xml, application/xml, text/xml")
	resp, err := m.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("could not read the metadata: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("the metadata address answered %s", resp.Status)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, MaxMetadata+1))
	if err != nil {
		return nil, fmt.Errorf("could not read the metadata: %w", err)
	}
	return ParseMetadata(data)
}

// parsed keeps metadata pasted into the settings, parsed once.
var parsed struct {
	mu   sync.Mutex
	sum  [sha256.Size]byte
	idp  *IdP
	err  error
	have bool
}

// ParseMetadataCached is ParseMetadata, remembering the last document.
func ParseMetadataCached(data []byte) (*IdP, error) {
	sum := sha256.Sum256(data)
	parsed.mu.Lock()
	defer parsed.mu.Unlock()
	if parsed.have && parsed.sum == sum {
		return parsed.idp, parsed.err
	}
	parsed.idp, parsed.err = ParseMetadata(data)
	parsed.sum, parsed.have = sum, true
	return parsed.idp, parsed.err
}
