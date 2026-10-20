// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package m365

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/ingest"
	"github.com/jrsamsanchez/signalith/internal/store"
)

// Store keeps the poller's cursors: *store.Client in the runtime index.
type Store interface {
	Get(ctx context.Context, index, id string) (json.RawMessage, store.Version, bool, error)
	Create(ctx context.Context, index, id string, body any, refresh bool) (store.Version, error)
	PutIf(ctx context.Context, index, id string, body any, v store.Version, refresh bool) (store.Version, error)
}

const (
	// keep is how long the API keeps content.
	keep = 7 * 24 * time.Hour
	// window is the longest time a listing may cover.
	window = 24 * time.Hour
	// overlap is how far before its cursor each listing starts, so a blob
	// listed late is still found. Its records are stored once, by their
	// Id, however often they are read.
	overlap = 10 * time.Minute
	// firstLook is how far back a content type is first read.
	firstLook = 24 * time.Hour
	// maxWindows is how many listings one round makes of a content type,
	// so a poller that was off for days catches up over a few rounds.
	maxWindows = 8
)

// cursorKind is the kind of the cursor documents in the runtime index.
const cursorKind = "m365cursor"

// Cursor is where the poller got to in one content type, kept in
// m365cursor:<tenant>:<content type>.
type Cursor struct {
	Kind        string    `json:"kind"`
	Target      string    `json:"target"`
	Tenant      string    `json:"tenant"`
	ContentType string    `json:"content_type"`
	Until       time.Time `json:"until"`
	LastRun     time.Time `json:"last_run,omitzero"`
	LastRecords int       `json:"last_records"`
	LastError   string    `json:"last_error,omitempty"`
	Epoch       int64     `json:"epoch"`
	Node        string    `json:"node,omitempty"`
}

func cursorID(tenant, contentType string) string {
	return cursorKind + ":" + tenant + ":" + contentType
}

// ErrStale refuses a cursor write over one a newer job holder made.
var ErrStale = errors.New("another server now reads the Microsoft 365 audit log")

// Poller reads the audit log every few minutes while the settings name a
// tenant, on the server that runs the background jobs.
type Poller struct {
	// Settings are read before every round, so a change applies at once.
	Settings func() Settings
	HTTP     *http.Client
	Store    Store
	Index    string
	// Ingest writes a blob's records.
	Ingest func(ctx context.Context, tag string, records []map[string]any) (*ingest.Result, error)
	// Allowed reports whether this server still runs the jobs; Epoch is
	// its job lease's epoch, NodeID its name.
	Allowed func() bool
	Epoch   func() int64
	NodeID  string
	Log     *slog.Logger
	// Every is the time between rounds (5 minutes).
	Every time.Duration

	now func() time.Time

	mu      sync.Mutex
	client  *Client
	started map[string]bool // content types started, for client's settings
	seen    map[string]time.Time
	status  Status
}

// Status is how the poller is doing, for the health page.
type Status struct {
	On        bool      `json:"on"`
	Tenant    string    `json:"tenant,omitempty"`
	LastRun   time.Time `json:"last_run,omitzero"`
	LastOK    time.Time `json:"last_ok,omitzero"`
	LastError string    `json:"last_error,omitempty"`
	// Records counts the records read since this server started.
	Records int64 `json:"records"`
	// Behind is how far the content type furthest behind is from now.
	Behind time.Duration `json:"behind_ns"`
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

// Run reads the audit log until ctx ends.
func (p *Poller) Run(ctx context.Context) {
	every := p.Every
	if every <= 0 {
		every = 5 * time.Minute
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

// Round reads what each content type has had since its cursor.
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
	c := p.clientFor(s)
	now := p.clock()
	var errs []error
	records, behind := 0, time.Duration(0)
	for _, ct := range ContentTypes {
		if ctx.Err() != nil || !p.allowed() {
			return
		}
		n, until, err := p.readType(ctx, c, ct, now)
		records += n
		if errors.Is(err, ErrStale) {
			errs = append(errs, err)
			break
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", ct, err))
		}
		if !until.IsZero() {
			behind = max(behind, now.Sub(until))
		}
	}
	err := errors.Join(errs...)
	p.mu.Lock()
	p.status.On, p.status.Tenant, p.status.LastRun = true, s.TenantID, now
	p.status.Records += int64(records)
	p.status.Behind = behind
	p.status.LastError = ""
	if err != nil {
		p.status.LastError = err.Error()
	} else {
		p.status.LastOK = now
	}
	p.mu.Unlock()
	if err != nil && !errors.Is(err, context.Canceled) {
		p.log().Warn("could not read the Microsoft 365 audit log", "tenant", s.TenantID, "error", err)
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
		p.started = map[string]bool{}
	}
	return p.client
}

// readType reads one content type from its cursor up to now, in
// listings of at most a day, and returns the records read and where its
// cursor is.
func (p *Poller) readType(ctx context.Context, c *Client, ct string, now time.Time) (int, time.Time, error) {
	p.mu.Lock()
	started := p.started[ct]
	p.mu.Unlock()
	if !started {
		if err := c.Start(ctx, ct); err != nil {
			return 0, time.Time{}, fmt.Errorf("start the subscription: %w", err)
		}
		p.mu.Lock()
		if p.client == c {
			p.started[ct] = true
		}
		p.mu.Unlock()
	}
	id := cursorID(c.S.TenantID, ct)
	cur, ver, found, err := p.cursor(ctx, id)
	if err != nil {
		return 0, time.Time{}, err
	}
	if !found {
		cur = Cursor{Until: now.Add(-firstLook)}
	}
	cur.Kind, cur.Target, cur.Tenant, cur.ContentType = cursorKind, id, c.S.TenantID, ct
	records := 0
	var readErr error
	for range maxWindows {
		start := cur.Until.Add(-overlap)
		// The API refuses a start more than 7 days back; what is older
		// than that is gone.
		if oldest := now.Add(-keep + 10*time.Minute); start.Before(oldest) {
			start = oldest
		}
		end := start.Add(window)
		if end.After(now) {
			end = now
		}
		if !end.After(start) {
			break
		}
		n, err := p.readWindow(ctx, c, ct, start, end)
		records += n
		if err != nil {
			readErr = err
			break
		}
		cur.Until = end
		if !end.Before(now) {
			break
		}
	}
	cur.LastRun, cur.LastRecords, cur.LastError = now, records, ""
	if readErr != nil {
		cur.LastError = readErr.Error()
	}
	cur.Epoch, cur.Node = p.epoch(), p.NodeID
	if err := p.saveCursor(ctx, id, cur, ver, found); err != nil {
		return records, cur.Until, errors.Join(readErr, err)
	}
	return records, cur.Until, readErr
}

// readWindow reads the blobs listed from start to end that it has not
// read already.
func (p *Poller) readWindow(ctx context.Context, c *Client, ct string, start, end time.Time) (int, error) {
	blobs, err := c.List(ctx, ct, start, end)
	if err != nil {
		return 0, fmt.Errorf("list content: %w", err)
	}
	records := 0
	for _, b := range blobs {
		if p.wasSeen(b.ContentID) {
			continue
		}
		if !p.allowed() {
			return records, ErrStale
		}
		body, err := c.Read(ctx, b)
		if err != nil {
			return records, fmt.Errorf("read content: %w", err)
		}
		recs, err := ingest.O365Records(body)
		if err != nil {
			return records, fmt.Errorf("read content %s: %w", b.ContentID, err)
		}
		if len(recs) > 0 {
			if _, err := p.Ingest(ctx, ingest.O365Tag, recs); err != nil {
				return records, fmt.Errorf("store records: %w", err)
			}
		}
		records += len(recs)
		p.markSeen(b.ContentID)
	}
	return records, nil
}

// wasSeen reports whether a blob was read in the last few rounds: the
// overlap lists it again.
func (p *Poller) wasSeen(id string) bool {
	if id == "" {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	_, ok := p.seen[id]
	return ok
}

func (p *Poller) markSeen(id string) {
	if id == "" {
		return
	}
	now := p.clock()
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.seen == nil {
		p.seen = map[string]time.Time{}
	}
	p.seen[id] = now
	for k, t := range p.seen {
		if now.Sub(t) > 2*overlap+time.Hour {
			delete(p.seen, k)
		}
	}
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

// Check signs in with the settings and lists the tenant's subscriptions,
// for the Test button: nil when the app can read the audit log.
func Check(ctx context.Context, s Settings, hc *http.Client) (map[string]bool, error) {
	if hc == nil {
		hc = NewHTTPClient()
	}
	c := &Client{S: s, HTTP: hc}
	return c.Subscriptions(ctx)
}

// Searcher finds documents: *store.Client.
type Searcher interface {
	SearchDocs(ctx context.Context, index string, query map[string]any) ([]store.Doc, error)
}

// Cursors returns where the poller got to in each content type of a
// tenant, as any server reads it from the runtime index.
func Cursors(ctx context.Context, s Searcher, index, tenant string) ([]Cursor, error) {
	docs, err := s.SearchDocs(ctx, index, map[string]any{"term": map[string]any{"kind": cursorKind}})
	if err != nil {
		return nil, err
	}
	var out []Cursor
	for _, d := range docs {
		var c Cursor
		if json.Unmarshal(d.Source, &c) == nil && c.Tenant == tenant && c.ContentType != "" {
			out = append(out, c)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ContentType < out[j].ContentType })
	return out, nil
}

// FromConfig is the settings the configuration names.
func FromConfig(c *config.Config) Settings {
	if !c.M365On() {
		return Settings{}
	}
	return Settings{TenantID: c.M365.TenantID, ClientID: c.M365.ClientID, ClientSecret: c.M365.ClientSecret,
		TokenURL: c.M365TokenURL(), APIURL: c.M365APIURL()}
}
