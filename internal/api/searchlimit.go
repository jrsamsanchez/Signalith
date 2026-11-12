// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/jrsamsanchez/signalith/internal/search"
)

// A search's result is written out after the search has freed its slot,
// so the routes that run searches a user writes are held to limits of
// their own as well (RT-02): each user may start only so many a minute
// (searchRate), only so many may be answering at once, for each user and
// for the whole server, until their response is written (searchGate), and
// a response that a client reads too slowly is cut off (searchWriteTimeout).
// The engine refuses a result over search.MaxResultBytes, and the Search
// page's result is written one row at a time (writeSearchResult).

// searchRunRoutes are the routes that run a search the user wrote, or a
// detection's search on demand.
var searchRunRoutes = []string{
	"POST /api/search",
	"POST /api/panels/run",
	"POST /api/dashboards/{id}/run",
	"POST /api/notebooks/{id}/run",
	"GET /api/fields/values",
	"POST /api/detections/test",
	"POST /api/detections/backtest",
	"POST /api/detections/{id}/run",
}

const (
	// searchBurst searches may start at once, and one more each
	// searchEvery after: a person on the Search page sends a few for
	// each search they run.
	searchBurst = 60
	searchEvery = time.Second
	// searchesPerUser of one user's searches may be running or
	// answering at once, as many as the search engine's share for one
	// user, and searchesInFlight of everyone's. The public demo's
	// visitors together get half of those, so signed-in users always
	// have room.
	searchesPerUser  = 4
	searchesInFlight = 16
	// searchWriteTimeout is how long a client has to read a search's
	// response once it starts.
	searchWriteTimeout = 2 * time.Minute
)

// searchQueueWait is how long a search waits for its turn before it is
// refused, as the engine waits for a slot; a variable for tests.
var searchQueueWait = 15 * time.Second

// searchLimits holds the state of searchGate.
type searchLimits struct {
	mu      sync.Mutex
	buckets map[string]*searchBucket
	users   map[string]*userTurns
	all     chan struct{}
	demo    chan struct{}
}

type searchBucket struct {
	tokens float64
	last   time.Time
}

// userTurns is one user's share of searchesInFlight, kept while the user
// has a search waiting or running.
type userTurns struct {
	ch   chan struct{}
	refs int
}

// take counts a search by key at now, or returns how long to wait.
func (l *searchLimits) take(key string, now time.Time) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	rate := 1 / searchEvery.Seconds()
	fill := func(b *searchBucket) float64 {
		return math.Min(searchBurst, b.tokens+now.Sub(b.last).Seconds()*rate)
	}
	if l.buckets == nil {
		l.buckets = map[string]*searchBucket{}
	}
	if len(l.buckets) > 4096 {
		// Users whose searches are all long refilled are forgotten.
		for k, b := range l.buckets {
			if fill(b) >= searchBurst {
				delete(l.buckets, k)
			}
		}
	}
	b := l.buckets[key]
	if b == nil {
		b = &searchBucket{tokens: searchBurst, last: now}
		l.buckets[key] = b
	}
	b.tokens, b.last = fill(b), now
	if b.tokens < 1 {
		return time.Duration((1 - b.tokens) / rate * float64(time.Second))
	}
	b.tokens--
	return 0
}

// turn waits for the key's and the server's share of searches in flight
// and returns the function that gives them back.
func (l *searchLimits) turn(r *http.Request, key string, demo bool) (func(), error) {
	l.mu.Lock()
	if l.all == nil {
		l.all = make(chan struct{}, searchesInFlight)
		l.demo = make(chan struct{}, searchesInFlight/2)
		l.users = map[string]*userTurns{}
	}
	u := l.users[key]
	if u == nil {
		u = &userTurns{ch: make(chan struct{}, searchesPerUser)}
		l.users[key] = u
	}
	u.refs++
	l.mu.Unlock()
	done := func() {
		l.mu.Lock()
		if u.refs--; u.refs <= 0 {
			delete(l.users, key)
		}
		l.mu.Unlock()
	}

	t := time.NewTimer(searchQueueWait)
	defer t.Stop()
	take := func(c chan struct{}, busy error) error {
		select {
		case c <- struct{}{}:
			return nil
		case <-t.C:
			return busy
		case <-r.Context().Done():
			return r.Context().Err()
		}
	}
	held := []chan struct{}{}
	giveBack := func() {
		for _, c := range held {
			<-c
		}
		done()
	}
	chans := []chan struct{}{u.ch, l.all}
	errs := []error{search.ErrUserBusy, search.ErrBusy}
	if demo {
		chans = append(chans, l.demo)
		errs = append(errs, search.ErrBusy)
	}
	for i, c := range chans {
		if err := take(c, errs[i]); err != nil {
			giveBack()
			return nil, err
		}
		held = append(held, c)
	}
	return giveBack, nil
}

func (s *Server) searchLimits() *searchLimits {
	s.searchLimitsOnce.Do(func() { s.searchLim = &searchLimits{} })
	return s.searchLim
}

// searchGate holds the routes of mux that run a user's search to the
// limits above. It runs after requireUser, before the route's own checks.
func (s *Server) searchGate(mux *http.ServeMux) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := principalOf(r)
		if _, pattern := mux.Handler(r); p == nil || !slices.Contains(searchRunRoutes, pattern) {
			mux.ServeHTTP(w, r)
			return
		}
		key := s.searchUser(r, p)
		lim := s.searchLimits()
		if wait := lim.take(key, time.Now()); wait > 0 {
			secs := int(math.Ceil(wait.Seconds()))
			w.Header().Set("Retry-After", fmt.Sprint(secs))
			writeJSON(w, http.StatusTooManyRequests, map[string]any{
				"error": fmt.Sprintf("You are running searches faster than this server allows; wait %d seconds, then try again.", secs),
				"code":  "search_rate"})
			return
		}
		release, err := lim.turn(r, key, p.Source == sourceDemo)
		if err != nil {
			if r.Context().Err() != nil {
				return
			}
			writeSearchError(w, err)
			return
		}
		// The turn is held until the response is written, and the
		// client has searchWriteTimeout to read it.
		defer release()
		mux.ServeHTTP(&deadlineWriter{ResponseWriter: w, d: searchWriteTimeout}, r)
	})
}

// deadlineWriter sets a write deadline of d from when the response starts.
type deadlineWriter struct {
	http.ResponseWriter
	d       time.Duration
	started bool
}

func (w *deadlineWriter) start() {
	if !w.started {
		w.started = true
		_ = http.NewResponseController(w.ResponseWriter).SetWriteDeadline(time.Now().Add(w.d))
	}
}

func (w *deadlineWriter) WriteHeader(code int) {
	w.start()
	w.ResponseWriter.WriteHeader(code)
}

func (w *deadlineWriter) Write(b []byte) (int, error) {
	w.start()
	return w.ResponseWriter.Write(b)
}

func (w *deadlineWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// maxSearchResponse is the most writeSearchResult writes before it gives
// up. The engine measures a result's text as it is (search.MaxResultBytes),
// and JSON can write a byte as up to six (\u00XX for a control
// character), so the cap is six times that, plus as much again for the
// quotes, names and separators around each value: a result the engine
// let through is never cut off part way. It bounds only what a client
// can make the server send, not memory: rows are written one at a time.
const maxSearchResponse = 7 * search.MaxResultBytes

// errResponseTooLarge stops writing a search result past maxSearchResponse.
var errResponseTooLarge = errors.New("search response too large")

// limitedWriter fails writes past n bytes.
type limitedWriter struct {
	w io.Writer
	n int
}

func (l *limitedWriter) Write(b []byte) (int, error) {
	if l.n -= len(b); l.n < 0 {
		return 0, errResponseTooLarge
	}
	return l.w.Write(b)
}

// writeSearchResult writes res as writeJSON would, one row at a time, so
// a client reading slowly holds a row's worth of encoded text rather than
// the whole result's (RT-02). The rows come first, then the other fields.
func writeSearchResult(w http.ResponseWriter, res *search.Result) {
	head := *res
	head.Rows = nil
	raw, err := json.Marshal(&head)
	var fields map[string]json.RawMessage
	if err == nil {
		err = json.Unmarshal(raw, &fields)
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	delete(fields, "rows")
	keys := make([]string, 0, len(fields))
	for k := range fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	bw := bufio.NewWriterSize(&limitedWriter{w: w, n: maxSearchResponse}, 32<<10)
	enc := json.NewEncoder(bw)
	enc.SetEscapeHTML(false)
	_, err = bw.WriteString(`{"rows":[`)
	for i, row := range res.Rows {
		if err != nil {
			break
		}
		if i > 0 {
			err = bw.WriteByte(',')
		}
		if err == nil {
			err = enc.Encode(row)
		}
	}
	if err == nil {
		_, err = bw.WriteString("]")
	}
	for _, k := range keys {
		if err != nil {
			break
		}
		name, _ := json.Marshal(k)
		_, err = fmt.Fprintf(bw, ",%s:%s", name, fields[k])
	}
	if err == nil {
		_, err = bw.WriteString("}\n")
	}
	if err == nil {
		err = bw.Flush()
	}
	if errors.Is(err, errResponseTooLarge) {
		// The status is sent; end the response so the client sees it
		// break off rather than take part of it for all.
		panic(http.ErrAbortHandler)
	}
}
