package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jrsamsanchez/signalith/internal/store"
)

// Defaults for SinkOptions.
const (
	DefaultMaxBytes = 50 << 20
	DefaultEvery    = 2 * time.Second
	// segmentBytes is the size past which the segment being written is
	// closed and a new one started.
	segmentBytes = 1 << 20
	// bulkSize is the most events sent in one bulk request.
	bulkSize = 500
)

// Bulker writes documents to OpenSearch, as store.Client.Bulk does: each
// document is sent as a create, so one whose ID is already stored is
// refused as a conflict.
type Bulker interface {
	Bulk(ctx context.Context, docs []store.IndexedDoc) ([]store.BulkItemError, error)
}

// SinkOptions configures a Sink.
type SinkOptions struct {
	// Dir is the spool directory, such as <state>/audit-spool. It is made
	// when missing.
	Dir string
	// MaxBytes bounds the spool's size on disk (50 MB when 0). When an
	// event would pass it, the oldest spooled events are dropped.
	MaxBytes int64
	// Client writes the events to OpenSearch; with none, they stay
	// spooled.
	Client Bulker
	// Prefix is the index prefix: events go to <prefix>_audit-YYYY.MM.
	Prefix string
	// Server and NodeID name this server in every event, and Epoch, when
	// set, gives the cluster epoch each event records. SetIdentity and
	// SetEpoch change them later.
	Server, NodeID string
	Epoch          func() int64
	// Every is how often Run flushes (2s when 0).
	Every time.Duration
	// Log, when set, gets the sink's own problems (never as audit lines).
	Log *slog.Logger
	// Now is the clock, for the events the sink makes itself.
	Now func() time.Time
}

// Stats describes a Sink's spool.
type Stats struct {
	// SpooledBytes is the size of the spool on disk and Segments the
	// number of its files.
	SpooledBytes int64
	Segments     int
	// Written counts the events stored in OpenSearch (or found already
	// there), Lost those dropped: by the spool's cap, or refused by
	// OpenSearch for good.
	Written int64
	Lost    int64
	// Errors counts failed writes to the spool, LastError is the last
	// problem with the spool or with OpenSearch ("" once a flush
	// succeeds), and LastFlush the time of the last successful flush.
	Errors    int64
	LastError string
	LastFlush time.Time
}

// Sink keeps audit events in an append-only spool on disk and writes
// them to OpenSearch from there. Adding an event only appends a line to a
// file, so it never waits for OpenSearch; the spool survives a restart,
// and is bounded, dropping the oldest events (and recording that it did)
// when full. Its methods are safe for concurrent use.
type Sink struct {
	dir      string
	max      int64
	segMax   int64
	client   Bulker
	prefix   string
	every    time.Duration
	log      *slog.Logger
	now      func() time.Time
	enabled  atomic.Bool
	seq      atomic.Int64
	flushing sync.Mutex

	mu        sync.Mutex
	server    string
	nodeID    string
	epoch     func() int64
	cur       *os.File
	curName   string
	curSize   int64
	curEvents int64
	counter   uint64
	closed    []segment
	total     int64
	written   int64
	lost      int64
	errs      int64
	lastErr   string
	lastFlush time.Time
	failing   bool
}

// segment is one closed spool file.
type segment struct {
	name   string
	size   int64
	events int64
}

// NewSink returns an enabled sink spooling to opts.Dir. Events already
// spooled there, by an earlier run, are written with the new ones.
func NewSink(opts SinkOptions) *Sink {
	s := &Sink{
		dir: opts.Dir, max: opts.MaxBytes, segMax: segmentBytes, client: opts.Client, prefix: opts.Prefix,
		every: opts.Every, log: opts.Log, now: opts.Now, server: opts.Server, nodeID: opts.NodeID, epoch: opts.Epoch,
	}
	if s.max <= 0 {
		s.max = DefaultMaxBytes
	}
	if s.every <= 0 {
		s.every = DefaultEvery
	}
	if s.log == nil {
		s.log = slog.New(slog.DiscardHandler)
	}
	if s.now == nil {
		s.now = time.Now
	}
	s.enabled.Store(true)
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		s.lastErr = err.Error()
		s.log.Warn("audit spool: cannot make its directory", "dir", s.dir, "err", err)
		return s
	}
	s.load()
	return s
}

// load picks up the segments already in the spool directory.
func (s *Sink) load() {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		s.lastErr = err.Error()
		return
	}
	for _, e := range entries {
		n, ok := segmentNumber(e.Name())
		if !ok || e.IsDir() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(s.dir, e.Name()))
		if err != nil {
			s.lastErr = err.Error()
			continue
		}
		s.closed = append(s.closed, segment{name: e.Name(), size: int64(len(data)), events: countLines(data)})
		s.total += int64(len(data))
		s.counter = max(s.counter, n)
	}
	sort.Slice(s.closed, func(i, j int) bool { return s.closed[i].name < s.closed[j].name })
}

func segmentName(n uint64) string { return fmt.Sprintf("seg-%020d.ndjson", n) }

func segmentNumber(name string) (uint64, bool) {
	if !strings.HasPrefix(name, "seg-") || !strings.HasSuffix(name, ".ndjson") {
		return 0, false
	}
	n, err := strconv.ParseUint(strings.TrimSuffix(strings.TrimPrefix(name, "seg-"), ".ndjson"), 10, 64)
	return n, err == nil
}

func countLines(data []byte) int64 {
	var n int64
	for line := range bytes.SplitSeq(data, []byte("\n")) {
		if len(bytes.TrimSpace(line)) > 0 {
			n++
		}
	}
	return n
}

// Enabled reports whether Add keeps events.
func (s *Sink) Enabled() bool { return s != nil && s.enabled.Load() }

// SetEnabled turns keeping events on or off. Events already spooled are
// still written while it is off.
func (s *Sink) SetEnabled(on bool) { s.enabled.Store(on) }

// SetIdentity sets the server name and node ID later events record.
func (s *Sink) SetIdentity(server, nodeID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.server, s.nodeID = server, nodeID
}

// SetTarget points the sink at another OpenSearch client and index
// prefix, such as after a restart in place with new settings. A nil
// client keeps the events spooled.
func (s *Sink) SetTarget(c Bulker, prefix string) {
	s.flushing.Lock()
	defer s.flushing.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.client, s.prefix = c, prefix
}

// SetEpoch sets the function giving the cluster epoch later events
// record; nil records none.
func (s *Sink) SetEpoch(f func() int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.epoch = f
}

// Add spools ev, filling in this server's name, node ID, the epoch and a
// sequence number where ev has none. It does nothing while the sink is
// disabled, and never fails: a spool it cannot write to is counted in
// Stats.
func (s *Sink) Add(ev Event) {
	if !s.Enabled() {
		return
	}
	s.mu.Lock()
	epoch := s.epoch
	s.mu.Unlock()
	// Outside the lock: the epoch function may itself log.
	var e int64
	if epoch != nil && ev.Epoch == 0 {
		e = epoch()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if ev.Epoch == 0 {
		ev.Epoch = e
	}
	s.addLocked(ev)
}

func (s *Sink) addLocked(ev Event) {
	if ev.Server == "" {
		ev.Server = s.server
	}
	if ev.NodeID == "" {
		ev.NodeID = s.nodeID
	}
	if ev.Seq == 0 {
		ev.Seq = s.seq.Add(1)
	}
	if ev.Time.IsZero() {
		ev.Time = s.now()
	}
	ev.Time = ev.Time.UTC()
	line, err := json.Marshal(ev)
	if err != nil {
		s.failLocked(err)
		return
	}
	line = append(line, '\n')
	if s.total+int64(len(line)) > s.max {
		lostEv := Event{Time: s.now().UTC(), Server: s.server, NodeID: s.nodeID, Epoch: ev.Epoch,
			Action: "audit.lost", Message: "audit records lost: the spool was full", Level: slog.LevelWarn.String(),
			Seq: s.seq.Add(1)}
		lostEv.Fields = map[string]string{"lost": "0"}
		probe, _ := json.Marshal(lostEv)
		n := s.dropLocked(int64(len(line)) + int64(len(probe)) + 32)
		if n > 0 {
			lostEv.Fields["lost"] = strconv.FormatInt(n, 10)
			ll, _ := json.Marshal(lostEv)
			s.writeLocked(append(ll, '\n'))
		}
		if s.total+int64(len(line)) > s.max {
			s.lost++
			return
		}
	}
	s.writeLocked(line)
}

// dropLocked closes the current segment and deletes the oldest ones
// until need more bytes fit, and returns how many events it dropped.
func (s *Sink) dropLocked(need int64) int64 {
	s.rotateLocked()
	var n int64
	for len(s.closed) > 0 && s.total+need > s.max {
		seg := s.closed[0]
		s.closed = s.closed[1:]
		s.total -= seg.size
		n += seg.events
		s.removeFile(seg.name)
	}
	s.lost += n
	return n
}

// writeLocked appends one line to the current segment, starting one when
// there is none, and closes it once it is large enough.
func (s *Sink) writeLocked(line []byte) {
	if s.cur == nil {
		if err := os.MkdirAll(s.dir, 0o700); err != nil {
			s.lost++
			s.failLocked(err)
			return
		}
		s.counter++
		name := segmentName(s.counter)
		f, err := os.OpenFile(filepath.Join(s.dir, name), os.O_CREATE|os.O_EXCL|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			s.lost++
			s.failLocked(err)
			return
		}
		s.cur, s.curName, s.curSize, s.curEvents = f, name, 0, 0
	}
	n, err := s.cur.Write(line)
	s.curSize += int64(n)
	s.total += int64(n)
	if err != nil {
		s.lost++
		s.failLocked(err)
		// A part written is skipped when read back.
		s.rotateLocked()
		return
	}
	s.curEvents++
	if s.curSize >= s.segMax {
		s.rotateLocked()
	}
}

// rotateLocked closes the current segment, if any, so it can be read and
// deleted (Windows deletes no file still open).
func (s *Sink) rotateLocked() {
	if s.cur == nil {
		return
	}
	if err := s.cur.Sync(); err != nil {
		s.failLocked(err)
	}
	if err := s.cur.Close(); err != nil {
		s.failLocked(err)
	}
	if s.curSize == 0 {
		s.removeFile(s.curName)
	} else {
		s.closed = append(s.closed, segment{name: s.curName, size: s.curSize, events: s.curEvents})
	}
	s.cur = nil
}

// removeFile deletes a closed segment, trying once more after a moment,
// as a file just read may still be held on Windows.
func (s *Sink) removeFile(name string) {
	p := filepath.Join(s.dir, name)
	err := os.Remove(p)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		time.Sleep(50 * time.Millisecond)
		err = os.Remove(p)
	}
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		s.failLocked(err)
	}
}

func (s *Sink) failLocked(err error) {
	s.errs++
	s.lastErr = err.Error()
}

// Close closes the segment being written, so everything spooled is on
// disk and the spool directory can be removed. Add starts a new segment
// after it.
func (s *Sink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rotateLocked()
	return nil
}

// Stats returns the spool's state.
func (s *Sink) Stats() Stats {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := len(s.closed)
	if s.cur != nil {
		n++
	}
	return Stats{SpooledBytes: s.total, Segments: n, Written: s.written, Lost: s.lost, Errors: s.errs,
		LastError: s.lastErr, LastFlush: s.lastFlush}
}

// Run flushes the spool every opts.Every until ctx ends, then once more
// with a few seconds to finish.
func (s *Sink) Run(ctx context.Context) {
	t := time.NewTicker(s.every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			fctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			_ = s.Flush(fctx)
			cancel()
			return
		case <-t.C:
			_ = s.Flush(ctx)
		}
	}
}

// Flush closes the segment being written and writes the spooled events
// to OpenSearch, oldest first, deleting each segment once all its events
// are stored. An event already stored (a replay) counts as written. When
// OpenSearch refuses writes for now (a cluster block, 429, a 5xx, or no
// answer), the segment is kept and the flush stops there, to try again
// later; an event refused for good, such as one OpenSearch cannot parse,
// is dropped and counted as lost.
func (s *Sink) Flush(ctx context.Context) error {
	s.flushing.Lock()
	defer s.flushing.Unlock()
	s.mu.Lock()
	if s.client == nil {
		s.mu.Unlock()
		return nil
	}
	s.rotateLocked()
	segs := append([]segment(nil), s.closed...)
	s.mu.Unlock()
	for _, seg := range segs {
		if err := s.flushSegment(ctx, seg); err != nil {
			s.mu.Lock()
			s.lastErr = err.Error()
			first := !s.failing
			s.failing = true
			s.mu.Unlock()
			if first {
				s.log.Warn("audit: cannot write the audit records to OpenSearch, keeping them spooled", "err", err)
			}
			return err
		}
		s.mu.Lock()
		for i, c := range s.closed {
			if c.name == seg.name {
				s.closed = append(s.closed[:i], s.closed[i+1:]...)
				s.total -= c.size
				s.removeFile(c.name)
				break
			}
		}
		s.mu.Unlock()
	}
	s.mu.Lock()
	if s.failing {
		s.log.Info("audit: writing the audit records to OpenSearch again")
	}
	s.failing = false
	s.lastErr = ""
	s.lastFlush = s.now()
	s.mu.Unlock()
	return nil
}

// flushSegment writes one segment's events. It returns nil once every
// event is stored or dropped for good.
func (s *Sink) flushSegment(ctx context.Context, seg segment) error {
	s.mu.Lock()
	client, prefix := s.client, s.prefix
	s.mu.Unlock()
	data, err := os.ReadFile(filepath.Join(s.dir, seg.name))
	if errors.Is(err, fs.ErrNotExist) {
		// Dropped by the cap meanwhile.
		return nil
	}
	if err != nil {
		return err
	}
	var docs []store.IndexedDoc
	var bad int64
	for line := range bytes.SplitSeq(data, []byte("\n")) {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		var ev Event
		if json.Unmarshal(line, &ev) != nil || ev.Time.IsZero() {
			bad++
			continue
		}
		docs = append(docs, store.IndexedDoc{Index: IndexName(prefix, ev.Time), ID: ev.ID(), Doc: ev.doc()})
	}
	for len(docs) > 0 {
		batch := docs[:min(bulkSize, len(docs))]
		docs = docs[len(batch):]
		errs, err := client.Bulk(ctx, batch)
		if err != nil {
			return err
		}
		var refused int64
		for _, e := range errs {
			switch {
			case e.Conflict():
			case retryable(e):
				return fmt.Errorf("opensearch refused an audit record for now: %s", e.Reason)
			default:
				refused++
				s.log.Warn("audit: OpenSearch refused an audit record, dropping it", "index", e.Index, "reason", e.Reason)
			}
		}
		s.mu.Lock()
		s.written += int64(len(batch)) - refused
		s.lost += refused
		s.mu.Unlock()
	}
	if bad > 0 {
		s.mu.Lock()
		s.lost += bad
		s.mu.Unlock()
	}
	return nil
}

// retryable reports whether OpenSearch refused a document only for now.
func retryable(e store.BulkItemError) bool {
	return e.Status == http.StatusTooManyRequests || e.Status >= 500 ||
		e.Type == "cluster_block_exception" || e.Type == "es_rejected_execution_exception" ||
		e.Status == 0 && e.Type == ""
}
