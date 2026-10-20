// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package okta

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/ingest"
	"github.com/jrsamsanchez/signalith/internal/store"
)

// Store keeps the poller's cursor: *store.Client in the runtime index.
type Store interface {
	Get(ctx context.Context, index, id string) (json.RawMessage, store.Version, bool, error)
	Create(ctx context.Context, index, id string, body any, refresh bool) (store.Version, error)
	PutIf(ctx context.Context, index, id string, body any, v store.Version, refresh bool) (store.Version, error)
}

const (
	// keep is how long Okta keeps events.
	keep = 90 * 24 * time.Hour
	// firstLook is how far back the System Log is first read.
	firstLook = 24 * time.Hour
	// maxPages is how many pages one round reads, so a poller that was
	// off for days catches up over a few rounds and leaves the
	// organization's rate limit room for its other apps.
	maxPages = 20
	// minRemaining is how many calls a round leaves of the rate limit
	// before it stops.
	minRemaining = 10
)

// cursorKind is the kind of the cursor documents in the runtime index.
const cursorKind = "oktacursor"

// Cursor is where the poller got to in an organization's System Log,
// kept in oktacursor:<domain>.
type Cursor struct {
	Kind   string `json:"kind"`
	Target string `json:"target"`
	Domain string `json:"domain"`
	// Next is the address of the next page to read, as the API gave it.
	Next string `json:"next,omitempty"`
	// Until is when the last event read was published.
	Until       time.Time `json:"until,omitzero"`
	LastRun     time.Time `json:"last_run,omitzero"`
	LastRecords int       `json:"last_records"`
	LastError   string    `json:"last_error,omitempty"`
	Epoch       int64     `json:"epoch"`
	Node        string    `json:"node,omitempty"`
}

func cursorID(domain string) string { return cursorKind + ":" + domain }

// ErrStale refuses a cursor write over one a newer job holder made.
var ErrStale = errors.New("another server now reads the Okta System Log")

// Poller reads the System Log every minute while the settings name an
// organization, on the server that runs the background jobs.
type Poller struct {
	// Settings are read before every round, so a change applies at once.
	Settings func() Settings
	HTTP     *http.Client
	Store    Store
	Index    string
	// Ingest writes a page's events.
	Ingest func(ctx context.Context, tag string, records []map[string]any) (*ingest.Result, error)
	// Allowed reports whether this server still runs the jobs; Epoch is
	// its job lease's epoch, NodeID its name.
	Allowed func() bool
	Epoch   func() int64
	NodeID  string
	Log     *slog.Logger
	// Every is the time between rounds (1 minute).
	Every time.Duration

	now func() time.Time

	mu     sync.Mutex
	client *Client
	// wait is when the organization's rate limit lets the next round
	// call again.
	wait   time.Time
	status Status
}

// Status is how the poller is doing, for the health page.
type Status struct {
	On        bool      `json:"on"`
	Domain    string    `json:"domain,omitempty"`
	LastRun   time.Time `json:"last_run,omitzero"`
	LastOK    time.Time `json:"last_ok,omitzero"`
	LastError string    `json:"last_error,omitempty"`
	// Records counts the events read since this server started.
	Records int64 `json:"records"`
}

// Status returns how the poller is doing.
func (p *Poller) Status() Status {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.status
}

func (p *Poller) clock() time.Time {
	if p.now != nil {
		return p.now()
	}
	return time.Now()
}

func (p *Poller) log() *slog.Logger {
	if p.Log != nil {
		return p.Log
	}
	return slog.Default()
}

func (p *Poller) allowed() bool { return p.Allowed == nil || p.Allowed() }

func (p *Poller) epoch() int64 {
	if p.Epoch != nil {
		return p.Epoch()
	}
	return 0
}

// Run reads the System Log until ctx ends.
func (p *Poller) Run(ctx context.Context) {
	every := p.Every
	if every <= 0 {
		every = time.Minute
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		p.Round(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Round reads the events published since the cursor, as far as maxPages.
func (p *Poller) Round(ctx context.Context) {
	if !p.allowed() {
		return
	}
	s := p.Settings()
	if !s.On() {
		p.mu.Lock()
		p.status = Status{}
		p.client = nil
		p.mu.Unlock()
		return
	}
	now := p.clock()
	p.mu.Lock()
	waiting := now.Before(p.wait)
	p.mu.Unlock()
	if waiting {
		return
	}
	c := p.clientFor(s)
	n, err := p.read(ctx, c, now)
	p.mu.Lock()
	p.status.On, p.status.Domain, p.status.LastRun = true, s.Domain, now
	p.status.Records += int64(n)
	p.status.LastError = ""
	if err != nil {
		p.status.LastError = err.Error()
	} else {
		p.status.LastOK = now
	}
	p.mu.Unlock()
	if err != nil && !errors.Is(err, context.Canceled) {
		p.log().Warn("could not read the Okta System Log", "domain", s.Domain, "error", err)
	}
}

// clientFor is the client for the settings, a new one when they changed.
func (p *Poller) clientFor(s Settings) *Client {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.client == nil || p.client.S != s {
		hc := p.HTTP
		if hc == nil {
			hc = NewHTTPClient()
		}
		p.client = &Client{S: s, HTTP: hc, now: p.now}
	}
	return p.client
}

// read reads pages from the cursor on, and returns the events read.
func (p *Poller) read(ctx context.Context, c *Client, now time.Time) (int, error) {
	id := cursorID(c.S.Domain)
	cur, ver, found, err := p.cursor(ctx, id)
	if err != nil {
		return 0, err
	}
	cur.Kind, cur.Target, cur.Domain = cursorKind, id, c.S.Domain
	u := cur.Next
	if u != "" && c.own(u) != nil {
		// A cursor for another address is started again.
		u = ""
	}
	if u == "" {
		since := now.Add(-firstLook)
		if !cur.Until.IsZero() {
			since = cur.Until
		}
		// The API refuses a start more than 90 days back; what is older
		// than that is gone.
		if oldest := now.Add(-keep + time.Hour); since.Before(oldest) {
			since = oldest
		}
		u = c.FirstURL(since)
	}
	records := 0
	var readErr error
	for range maxPages {
		if ctx.Err() != nil {
			readErr = ctx.Err()
			break
		}
		if !p.allowed() {
			readErr = ErrStale
			break
		}
		page, remaining, err := p.page(ctx, c, u)
		if err != nil {
			var ae *APIError
			if errors.As(err, &ae) && ae.Status == http.StatusBadRequest && cur.Next != "" {
				// The API no longer takes the stored next page (it is
				// past what Okta keeps): the next round starts from the
				// last event read.
				cur.Next = ""
			}
			readErr = err
			break
		}
		recs, err := ingest.OktaRecords(page.Body)
		if err != nil {
			readErr = fmt.Errorf("read a page of events: %w", err)
			break
		}
		if len(recs) > 0 {
			if _, err := p.Ingest(ctx, ingest.OktaTag, recs); err != nil {
				readErr = fmt.Errorf("store events: %w", err)
				break
			}
			if t, err := time.Parse(time.RFC3339Nano, fmt.Sprint(recs[len(recs)-1]["published"])); err == nil {
				cur.Until = t.UTC()
			}
		}
		records += len(recs)
		if page.Next == "" {
			// No next page (Okta gives one even at the end, for polling):
			// the next round starts from the last event read.
			cur.Next = ""
			break
		}
		u, cur.Next = page.Next, page.Next
		if len(recs) < pageLimit || remaining < minRemaining {
			// Caught up, or the rate limit is nearly used: the next
			// round carries on from the next page.
			break
		}
	}
	cur.LastRun, cur.LastRecords, cur.LastError = now, records, ""
	if readErr != nil {
		cur.LastError = readErr.Error()
	}
	cur.Epoch, cur.Node = p.epoch(), p.NodeID
	if err := p.saveCursor(ctx, id, cur, ver, found); err != nil {
		return records, errors.Join(readErr, err)
	}
	return records, readErr
}

// page reads one page, and returns how many calls the rate limit has
// left. A rate limit reached holds the next rounds back until it resets.
func (p *Poller) page(ctx context.Context, c *Client, u string) (*Page, int, error) {
	pg, err := c.Read(ctx, u)
	var ae *APIError
	if errors.As(err, &ae) && ae.Status == http.StatusTooManyRequests {
		p.mu.Lock()
		p.wait = ae.RetryAt
		p.mu.Unlock()
		return nil, 0, fmt.Errorf("Okta's rate limit is reached until %s: %w", ae.RetryAt.UTC().Format(time.RFC3339), err)
	}
	if err != nil {
		return nil, 0, err
	}
	return pg, pg.Remaining, nil
}

func (p *Poller) cursor(ctx context.Context, id string) (Cursor, store.Version, bool, error) {
	raw, ver, found, err := p.Store.Get(ctx, p.Index, id)
	if err != nil {
		return Cursor{}, store.Version{}, false, fmt.Errorf("read where it got to: %w", err)
	}
	var cur Cursor
	if found {
		if err := json.Unmarshal(raw, &cur); err != nil {
			// A cursor that does not read is started again.
			cur = Cursor{}
		}
		if cur.Epoch > p.epoch() {
			return Cursor{}, store.Version{}, false, ErrStale
		}
	}
	return cur, ver, found, nil
}

func (p *Poller) saveCursor(ctx context.Context, id string, cur Cursor, ver store.Version, found bool) error {
	var err error
	if found {
		_, err = p.Store.PutIf(ctx, p.Index, id, cur, ver, false)
	} else {
		_, err = p.Store.Create(ctx, p.Index, id, cur, false)
	}
	if errors.Is(err, store.ErrConflict) {
		return ErrStale
	}
	if err != nil {
		return fmt.Errorf("save where it got to: %w", err)
	}
	return nil
}

// Getter reads one document: *store.Client.
type Getter interface {
	Get(ctx context.Context, index, id string) (json.RawMessage, store.Version, bool, error)
}

// CursorOf returns where the poller got to in an organization's System
// Log, as any server reads it from the runtime index, or false when it
// has not read it yet.
func CursorOf(ctx context.Context, s Getter, index, domain string) (Cursor, bool, error) {
	raw, _, found, err := s.Get(ctx, index, cursorID(domain))
	if err != nil || !found {
		return Cursor{}, false, err
	}
	var c Cursor
	if err := json.Unmarshal(raw, &c); err != nil {
		return Cursor{}, false, err
	}
	return c, true, nil
}

// FromConfig is the settings the configuration names.
func FromConfig(c *config.Config) Settings {
	if !c.OktaOn() {
		return Settings{}
	}
	return Settings{Domain: c.OktaDomain(), ClientID: strings.TrimSpace(c.Okta.ClientID), PrivateKey: c.Okta.PrivateKey,
		KeyID: strings.TrimSpace(c.Okta.KeyID), APIToken: c.Okta.APIToken}
}
