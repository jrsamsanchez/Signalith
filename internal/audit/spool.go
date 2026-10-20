// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

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
	"slices"
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

	// The chain (see chain.go): the key events are signed with now and
	// the function giving it, where the chain is, whether that changed
	// since it was saved, and the runs of records lost that no audit.lost
	// record names yet. curFirst and curLast are the first and last
	// chained events of the segment being written.
	keySrc    func() (string, []byte)
	kid       string
	key       []byte
	head      chainHead
	headDirty bool
	pending   []lostRange
	lostMarks []lostMark
	curFirst  chainRef
	curLast   chainRef
}

// segment is one closed spool file, with its first and last chained
// events.
type segment struct {
	name        string
	size        int64
	events      int64
	first, last chainRef
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
	s.loadHead()
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
		first, last := segmentRefs(data)
		s.closed = append(s.closed, segment{name: e.Name(), size: int64(len(data)), events: countLines(data), first: first, last: last})
		s.total += int64(len(data))
		s.counter = max(s.counter, n)
	}
	sort.Slice(s.closed, func(i, j int) bool { return s.closed[i].name < s.closed[j].name })
}

// loadHead picks up where the chain is: the head saved in the spool
// directory or, when the spool holds a later record (one added after the
// head was last saved), that record. Without either, the next record
// starts a new chain.
func (s *Sink) loadHead() {
	h, err := readHead(s.dir)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		s.log.Warn("audit spool: the chain head cannot be read, so the next audit record starts a new chain", "dir", s.dir, "err", err)
	}
	for i := len(s.closed) - 1; i >= 0; i-- {
		if l := s.closed[i].last; l.chain != "" {
			if l.chain != h.Chain || l.seq > h.Seq {
				h = chainHead{NodeID: l.node, Chain: l.chain, Seq: l.seq, Hash: l.hash}
			}
			break
		}
	}
	s.head = h
}

// segmentRefs returns the first and last chained events of a segment's
// lines; zero refs when it has none.
func segmentRefs(data []byte) (first, last chainRef) {
	lines := bytes.Split(data, []byte("\n"))
	ref := func(line []byte) (chainRef, bool) {
		var ev Event
		line = bytes.TrimSpace(line)
		if len(line) == 0 || json.Unmarshal(line, &ev) != nil || ev.Chain == "" {
			return chainRef{}, false
		}
		return chainRef{node: ev.NodeID, chain: ev.Chain, seq: ev.Seq, hash: ev.Hash()}, true
	}
	for _, l := range lines {
		if r, ok := ref(l); ok {
			first = r
			break
		}
	}
	for i := len(lines) - 1; i >= 0; i-- {
		if r, ok := ref(lines[i]); ok {
			last = r
			break
		}
	}
	return first, last
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

// SetKeySource sets the function giving the audit key later events are
// signed with and its id (shared.ClusterKey.AuditKey and ID), "" and nil
// while this server has none: its events are then chained but not
// signed. It is asked now and before every flush, never while the sink
// holds its lock, as it may take locks of its own and those may log.
func (s *Sink) SetKeySource(f func() (string, []byte)) {
	s.mu.Lock()
	s.keySrc = f
	s.mu.Unlock()
	s.refreshKey()
}

// refreshKey asks the key source for the key in use now.
func (s *Sink) refreshKey() {
	s.mu.Lock()
	f := s.keySrc
	s.mu.Unlock()
	var kid string
	var key []byte
	if f != nil {
		kid, key = f()
	}
	if kid == "" || len(key) == 0 {
		kid, key = "", nil
	}
	s.mu.Lock()
	s.kid, s.key = kid, key
	s.mu.Unlock()
}

// SetEpoch sets the function giving the cluster epoch later events
// record; nil records none.
func (s *Sink) SetEpoch(f func() int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.epoch = f
}

// Add spools ev, filling in this server's name, node ID, the epoch and the
// time where ev has none, and its place in the chain (Seq, Chain, Prev,
// and the MAC when there is a key). It does nothing while the sink is
// disabled, and never fails: a spool it cannot write to is counted in
// Stats, and the records lost are named in an audit.lost record.
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
	ev = s.fillLocked(ev)
	ev, err := normalized(ev)
	if err != nil {
		s.lost++
		s.failLocked(err)
		return
	}
	s.writeLostLocked(ev.Epoch)
	size := s.sizeLocked(ev)
	if s.total+size > s.max {
		probe := s.sizeLocked(s.fillLocked(lostEvent(lostRange{chain: strings.Repeat("0", 16), from: 1 << 62, to: 1 << 62,
			hash: strings.Repeat("0", 64), n: 1 << 62, reason: "the spool was full"})))
		// The audit.lost records written take room too, so this may
		// take more than one drop.
		for range 3 {
			ranges := s.dropLocked(size + probe*int64(len(s.pending)+1) + 32)
			if len(ranges) == 0 {
				break
			}
			s.pending = append(s.pending, ranges...)
			s.writeLostLocked(ev.Epoch)
			if s.total+size <= s.max {
				break
			}
		}
		if s.total+size > s.max {
			s.lost++
			s.pending = append(s.pending, lostRange{n: 1, reason: "the record did not fit in the spool"})
			return
		}
	}
	s.appendLocked(ev)
}

// lostMark is an audit.lost record still in the spool: its sequence
// number, and the first of the run it names. When the spool drops it
// too, the run of the audit.lost record that says so starts there, so
// the first run stays named.
type lostMark struct {
	chain     string
	seq, from int64
}

// fillLocked fills in this server's name and node ID, and the time, where
// ev has none.
func (s *Sink) fillLocked(ev Event) Event {
	if ev.Server == "" {
		ev.Server = s.server
	}
	if ev.NodeID == "" {
		ev.NodeID = s.nodeID
	}
	if ev.Time.IsZero() {
		ev.Time = s.now()
	}
	ev.Time = ev.Time.UTC()
	return ev
}

// sizeLocked returns about how many bytes ev takes in the spool once
// chained: a little more, never less.
func (s *Sink) sizeLocked(ev Event) int64 {
	ev.Chain, ev.Seq, ev.Prev, ev.ChainStart = strings.Repeat("0", 16), s.head.Seq+1, strings.Repeat("0", 64), false
	if s.key != nil {
		ev.KID, ev.MAC = s.kid, strings.Repeat("0", 64)
	}
	b, _ := json.Marshal(ev)
	return int64(len(b)) + 1 + 8
}

// sealLocked gives ev its place in the chain, a new chain when there is
// none for its node yet, and its MAC when there is a key, and moves the
// chain's head on to it.
func (s *Sink) sealLocked(ev *Event) chainRef {
	if s.head.Chain == "" || s.head.NodeID != ev.NodeID {
		s.head = chainHead{NodeID: ev.NodeID, Chain: newChainID()}
	}
	ev.Chain, ev.Seq, ev.Prev, ev.ChainStart = s.head.Chain, s.head.Seq+1, s.head.Hash, s.head.Seq == 0
	ev.KID, ev.MAC = "", ""
	if s.key != nil {
		ev.KID = s.kid
		ev.MAC = ev.sign(s.key)
	}
	h := ev.Hash()
	s.head.Seq, s.head.Hash = ev.Seq, h
	s.headDirty = true
	return chainRef{node: ev.NodeID, chain: ev.Chain, seq: ev.Seq, hash: h}
}

// appendLocked chains ev and writes it to the spool, and reports whether
// it was written. One that was not is lost: it is named in the next
// audit.lost record, as its sequence number is taken.
func (s *Sink) appendLocked(ev Event) (chainRef, bool) {
	ref := s.sealLocked(&ev)
	line, err := json.Marshal(ev)
	if err == nil && s.writeLocked(append(line, '\n'), ref) {
		return ref, true
	}
	if err != nil {
		s.lost++
		s.failLocked(err)
	}
	s.lostLocked(ref, "the spool could not be written")
	return ref, false
}

// lostLocked adds a chained record that will not reach OpenSearch to the
// runs of lost records the next audit.lost record names.
func (s *Sink) lostLocked(ref chainRef, reason string) {
	if n := len(s.pending); n > 0 {
		if p := &s.pending[n-1]; p.chain == ref.chain && p.reason == reason && p.to+1 == ref.seq {
			p.to, p.hash = ref.seq, ref.hash
			p.n++
			return
		}
	}
	s.pending = append(s.pending, lostRange{chain: ref.chain, from: ref.seq, to: ref.seq, hash: ref.hash, n: 1, reason: reason})
}

// writeLostLocked writes an audit.lost record for each run of records
// lost that none names yet. When one cannot be written either, it and
// the runs after it wait for the next time.
func (s *Sink) writeLostLocked(epoch int64) {
	runs := s.pending
	s.pending = nil
	for i, r := range runs {
		ev := s.fillLocked(lostEvent(r))
		ev.Time, ev.Epoch, ev.Level = s.now().UTC(), epoch, slog.LevelWarn.String()
		ref, ok := s.appendLocked(ev)
		if !ok {
			// The record that failed is in s.pending now, after these.
			s.pending = append(slices.Clone(runs[i:]), s.pending...)
			return
		}
		if r.chain != "" {
			s.lostMarks = append(s.lostMarks, lostMark{chain: r.chain, seq: ref.seq, from: r.from})
		}
	}
}

// dropLocked closes the current segment and deletes the oldest ones
// until need more bytes fit, and returns the runs of records it dropped.
func (s *Sink) dropLocked(need int64) []lostRange {
	s.rotateLocked()
	var runs []lostRange
	for len(s.closed) > 0 && s.total+need > s.max {
		seg := s.closed[0]
		s.closed = s.closed[1:]
		s.total -= seg.size
		s.lost += seg.events
		s.removeFile(seg.name)
		r := lostRange{n: seg.events, reason: "the spool was full"}
		if seg.last.chain != "" {
			r.chain, r.to, r.hash, r.from = seg.last.chain, seg.last.seq, seg.last.hash, 1
			if seg.first.chain == seg.last.chain {
				r.from = seg.first.seq
			}
			r.from = s.dropMarksLocked(r.chain, r.from, r.to)
		}
		if n := len(runs); n > 0 {
			if p := &runs[n-1]; p.chain == r.chain && (r.chain == "" || p.to+1 == r.from) {
				p.n += r.n
				if r.chain != "" {
					p.to, p.hash = r.to, r.hash
				}
				continue
			}
		}
		runs = append(runs, r)
	}
	return runs
}

// dropMarksLocked forgets the audit.lost records among the sequence
// numbers from to to of chain, which are dropped, and returns where the
// run dropped starts: at from, or at the first record one of them named.
func (s *Sink) dropMarksLocked(chain string, from, to int64) int64 {
	out := from
	kept := s.lostMarks[:0]
	for _, m := range s.lostMarks {
		if m.chain == chain && m.seq >= from && m.seq <= to {
			out = min(out, m.from)
			continue
		}
		kept = append(kept, m)
	}
	s.lostMarks = kept
	return out
}

// writeLocked appends one line, of the event ref names, to the current
// segment, starting one when there is none, and closes it once it is
// large enough. It reports whether the line was written.
func (s *Sink) writeLocked(line []byte, ref chainRef) bool {
	if s.cur == nil {
		if err := os.MkdirAll(s.dir, 0o700); err != nil {
			s.lost++
			s.failLocked(err)
			return false
		}
		s.counter++
		name := segmentName(s.counter)
		f, err := os.OpenFile(filepath.Join(s.dir, name), os.O_CREATE|os.O_EXCL|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			s.lost++
			s.failLocked(err)
			return false
		}
		s.cur, s.curName, s.curSize, s.curEvents = f, name, 0, 0
		s.curFirst, s.curLast = chainRef{}, chainRef{}
	}
	n, err := s.cur.Write(line)
	s.curSize += int64(n)
	s.total += int64(n)
	if err != nil {
		s.lost++
		s.failLocked(err)
		// A part written is skipped when read back.
		s.rotateLocked()
		return false
	}
	s.curEvents++
	if ref.chain != "" {
		if s.curFirst.chain == "" {
			s.curFirst = ref
		}
		s.curLast = ref
	}
	if s.curSize >= s.segMax {
		s.rotateLocked()
	}
	return true
}

// rotateLocked closes the current segment, if any, so it can be read and
// deleted (Windows deletes no file still open), and saves the chain head
// when it moved. Every segment is deleted after a rotation, so the head
// saved is never behind the records that have left the spool.
func (s *Sink) rotateLocked() {
	if s.headDirty && s.head.Chain != "" {
		if err := writeHead(s.dir, s.head); err != nil {
			s.failLocked(err)
		} else {
			s.headDirty = false
		}
	}
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
		s.closed = append(s.closed, segment{name: s.curName, size: s.curSize, events: s.curEvents, first: s.curFirst, last: s.curLast})
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
			s.refreshKey()
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
				if c.last.chain != "" {
					// The audit.lost records in it are in OpenSearch now.
					s.dropMarksLocked(c.last.chain, 0, c.last.seq)
				}
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
	var evs []Event
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
		evs = append(evs, ev)
	}
	for len(docs) > 0 {
		batch := docs[:min(bulkSize, len(docs))]
		batchEvs := evs[:len(batch)]
		docs, evs = docs[len(batch):], evs[len(batch):]
		errs, err := client.Bulk(ctx, batch)
		if err != nil {
			return err
		}
		var refused []Event
		for _, e := range errs {
			switch {
			case e.Conflict():
			case retryable(e):
				return fmt.Errorf("opensearch refused an audit record for now: %s", e.Reason)
			default:
				if e.Pos >= 0 && e.Pos < len(batchEvs) {
					refused = append(refused, batchEvs[e.Pos])
				}
				s.log.Warn("audit: OpenSearch refused an audit record, dropping it", "index", e.Index, "reason", e.Reason)
			}
		}
		s.mu.Lock()
		s.written += int64(len(batch) - len(refused))
		s.lost += int64(len(refused))
		// The records refused are named in an audit.lost record, so their
		// gap in the chain is not taken for a removal.
		for _, ev := range refused {
			if ev.Chain != "" {
				s.lostLocked(chainRef{node: ev.NodeID, chain: ev.Chain, seq: ev.Seq, hash: ev.Hash()}, "OpenSearch refused them")
			}
		}
		if len(refused) > 0 {
			s.writeLostLocked(0)
		}
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
