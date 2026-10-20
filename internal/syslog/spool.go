// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package syslog

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jrsamsanchez/signalith/internal/ingest"
	"github.com/jrsamsanchez/signalith/internal/securefile"
)

// DefaultSpoolBytes bounds the spool on disk when Config.SpoolMaxBytes is
// zero.
const DefaultSpoolBytes = 1 << 30

// How long the replay waits between tries while OpenSearch refuses
// writes: from replayMinWait, doubling each time, up to replayMaxWait.
const (
	replayMinWait = time.Second
	replayMaxWait = time.Minute
)

// spool keeps batches of syslog events that OpenSearch refused for now
// (it was down, too busy, or blocked writes) in a private folder, one
// file per batch, until they can be written again. Like the audit spool
// (internal/audit), it survives a restart and is bounded: when a batch
// does not fit, the oldest batches are dropped to make room, and counted,
// so the receiver never waits for it. Its methods are safe for
// concurrent use.
type spool struct {
	dir string
	max int64

	mu      sync.Mutex
	files   []spoolFile // oldest first
	total   int64
	events  int64
	counter uint64
	// busy is the file being replayed, which the cap leaves alone.
	busy                       string
	spooled, replayed, dropped int64

	// kick wakes the replay when a batch is added.
	kick chan struct{}
}

// spoolFile is one batch in the spool: batch-<number>-<events>.ndjson.
type spoolFile struct {
	name   string
	seq    uint64
	size   int64
	events int
}

func spoolName(seq uint64, events int) string {
	return fmt.Sprintf("batch-%020d-%d.ndjson", seq, events)
}

func parseSpoolName(name string) (seq uint64, events int, ok bool) {
	rest, found := strings.CutPrefix(name, "batch-")
	if !found {
		return 0, 0, false
	}
	rest, found = strings.CutSuffix(rest, ".ndjson")
	if !found {
		return 0, 0, false
	}
	a, b, found := strings.Cut(rest, "-")
	if !found {
		return 0, 0, false
	}
	seq, err1 := strconv.ParseUint(a, 10, 64)
	n, err2 := strconv.Atoi(b)
	return seq, n, err1 == nil && err2 == nil && n >= 0
}

// openSpool makes dir private (making it when missing) and picks up the
// batches an earlier run left there.
func openSpool(dir string, maxBytes int64) (*spool, error) {
	if maxBytes <= 0 {
		maxBytes = DefaultSpoolBytes
	}
	if err := securefile.MkdirPrivate(dir); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	s := &spool{dir: dir, max: maxBytes, kick: make(chan struct{}, 1)}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() {
			continue
		}
		if strings.HasPrefix(name, ".") && strings.HasSuffix(name, ".tmp") {
			// Half written when the server stopped.
			os.Remove(filepath.Join(dir, name))
			continue
		}
		seq, n, ok := parseSpoolName(name)
		if !ok {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		s.files = append(s.files, spoolFile{name: name, seq: seq, size: info.Size(), events: n})
		s.total += info.Size()
		s.events += int64(n)
		s.counter = max(s.counter, seq)
	}
	sort.Slice(s.files, func(i, j int) bool { return s.files[i].seq < s.files[j].seq })
	return s, nil
}

// spooledEvent is how an event is kept in the spool.
type spooledEvent struct {
	Time       time.Time      `json:"time"`
	Model      string         `json:"model"`
	Fields     map[string]any `json:"fields"`
	DeviceTime time.Time      `json:"device_time,omitzero"`
	Origin     ingest.Origin  `json:"origin,omitzero"`
	ID         string         `json:"id"`
}

// encode returns events as spool lines, and how many it could encode.
// Each event gets a document ID when it has none, so a batch written
// again after a write that may have arrived is stored once. The fields
// only Signalith sets are left out: the pipeline sets them again, from
// the event's origin, when the batch is written.
func encode(events []ingest.Event) ([]byte, int) {
	var buf bytes.Buffer
	n := 0
	for _, ev := range events {
		rec := spooledEvent{Time: ev.Time, Model: ev.Model, DeviceTime: ev.DeviceTime, Origin: ev.Origin, ID: ev.ID,
			Fields: make(map[string]any, len(ev.Fields))}
		for k, v := range ev.Fields {
			if !ingest.Reserved(k) {
				rec.Fields[k] = v
			}
		}
		if rec.ID == "" {
			rec.ID = rand.Text()
		}
		line, err := json.Marshal(rec)
		if err != nil {
			continue
		}
		buf.Write(line)
		buf.WriteByte('\n')
		n++
	}
	return buf.Bytes(), n
}

// decode reads spool lines back as events, and counts the lines it could
// not read.
func decode(data []byte) ([]ingest.Event, int) {
	var out []ingest.Event
	bad := 0
	for line := range bytes.SplitSeq(data, []byte("\n")) {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		var rec spooledEvent
		dec := json.NewDecoder(bytes.NewReader(line))
		dec.UseNumber()
		if dec.Decode(&rec) != nil || rec.Time.IsZero() {
			bad++
			continue
		}
		if rec.Fields == nil {
			rec.Fields = map[string]any{}
		}
		// Numbers come back as the integers or decimals they were.
		for k, v := range rec.Fields {
			if num, ok := v.(json.Number); ok {
				if i, err := num.Int64(); err == nil {
					rec.Fields[k] = i
				} else if f, err := num.Float64(); err == nil {
					rec.Fields[k] = f
				}
			}
		}
		out = append(out, ingest.Event{Time: rec.Time, Model: rec.Model, Fields: rec.Fields, DeviceTime: rec.DeviceTime, Origin: rec.Origin, ID: rec.ID})
	}
	return out, bad
}

// add spools a batch. When it does not fit, the oldest batches are
// dropped to make room; a batch larger than the whole spool is dropped
// itself. It returns how many events were dropped, and an error when the
// batch could not be written (the disk is full, say).
func (s *spool) add(events []ingest.Event) (dropped int, err error) {
	data, n := encode(events)
	if n == 0 {
		return 0, nil
	}
	size := int64(len(data))
	s.mu.Lock()
	defer s.mu.Unlock()
	if size > s.max {
		s.dropped += int64(n)
		return n, nil
	}
	for s.total+size > s.max {
		i := 0
		if len(s.files) > 0 && s.files[0].name == s.busy {
			i = 1
		}
		if i >= len(s.files) {
			break
		}
		f := s.files[i]
		s.files = append(s.files[:i], s.files[i+1:]...)
		s.removeLocked(f)
		s.dropped += int64(f.events)
		dropped += f.events
	}
	if s.total+size > s.max {
		// Only the batch being replayed is left, and this one does not
		// fit beside it.
		s.dropped += int64(n)
		return dropped + n, nil
	}
	s.counter++
	f := spoolFile{name: spoolName(s.counter, n), seq: s.counter, size: size, events: n}
	if err := securefile.Replace(filepath.Join(s.dir, f.name), data); err != nil {
		return dropped, err
	}
	s.files = append(s.files, f)
	s.total += size
	s.events += int64(n)
	s.spooled += int64(n)
	select {
	case s.kick <- struct{}{}:
	default:
	}
	return dropped, nil
}

// removeLocked deletes f's file and takes it off the totals; f is no
// longer in s.files.
func (s *spool) removeLocked(f spoolFile) {
	s.total -= f.size
	s.events -= int64(f.events)
	if err := os.Remove(filepath.Join(s.dir, f.name)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		// Windows may still hold a file just read: try once more.
		time.Sleep(50 * time.Millisecond)
		os.Remove(filepath.Join(s.dir, f.name))
	}
}

// next returns the oldest batch and marks it busy, so the cap leaves it
// alone while it is replayed; false when the spool is empty.
func (s *spool) next() (spoolFile, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.files) == 0 {
		return spoolFile{}, false
	}
	s.busy = s.files[0].name
	return s.files[0], true
}

// read returns a batch's events, and how many lines of it could not be
// read.
func (s *spool) read(f spoolFile) ([]ingest.Event, int, error) {
	data, err := os.ReadFile(filepath.Join(s.dir, f.name))
	if err != nil {
		return nil, 0, err
	}
	events, bad := decode(data)
	return events, bad, nil
}

// release leaves a busy batch in the spool, to try again later.
func (s *spool) release() {
	s.mu.Lock()
	s.busy = ""
	s.mu.Unlock()
}

// done takes a replayed batch out of the spool, counting replayed events
// as written, and keeps the events in rest, which OpenSearch refused for
// now, in its place to try again. It returns an error when rest could not
// be kept.
func (s *spool) done(f spoolFile, replayed int, rest []ingest.Event) error {
	var data []byte
	var n int
	if len(rest) > 0 {
		data, n = encode(rest)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.busy = ""
	s.replayed += int64(replayed)
	i := s.indexLocked(f.name)
	if i < 0 {
		return nil
	}
	var err error
	if n > 0 {
		// The same number, so it stays the oldest.
		nf := spoolFile{name: spoolName(f.seq, n), seq: f.seq, size: int64(len(data)), events: n}
		if nf.name == f.name {
			err = securefile.Replace(filepath.Join(s.dir, nf.name), data)
			if err == nil {
				s.total += nf.size - f.size
				s.events += int64(n - f.events)
				s.files[i] = nf
				return nil
			}
		} else if err = securefile.Replace(filepath.Join(s.dir, nf.name), data); err == nil {
			s.removeLocked(f)
			s.files[i] = nf
			s.total += nf.size
			s.events += int64(n)
			return nil
		}
	}
	s.files = append(s.files[:i], s.files[i+1:]...)
	s.removeLocked(f)
	return err
}

func (s *spool) indexLocked(name string) int {
	for i, f := range s.files {
		if f.name == name {
			return i
		}
	}
	return -1
}

// empty reports whether no batch is waiting.
func (s *spool) empty() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.files) == 0
}

// spoolStats is what the spool holds and has done, for Stats.
type spoolStats struct {
	spooled, replayed, dropped, events, bytes, max int64
}

func (s *spool) stats() spoolStats {
	if s == nil {
		return spoolStats{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return spoolStats{spooled: s.spooled, replayed: s.replayed, dropped: s.dropped, events: s.events, bytes: s.total, max: s.max}
}
