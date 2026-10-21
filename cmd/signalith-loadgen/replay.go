// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"math/rand/v2"
	"strconv"
	"sync"
	"time"

	"github.com/jrsamsanchez/signalith/internal/detect/packs"
	"github.com/jrsamsanchez/signalith/internal/sigmacheck"
)

// replayTag is the Fluent Bit tag of the replayed events: Windows event
// logs, Sysmon's included, as the agent's winevtlog input tags them.
const replayTag = "win.events"

// defaultAttackShare is ReplayLoad.AttackShare when it is not set: about
// one event in a thousand is an attack, so the detections fire now and
// then rather than on every batch.
const defaultAttackShare = 0.001

// replayEvent is one recorded event, rendered as the agent sends it,
// cut where the computer's name and the time go.
type replayEvent struct {
	// parts are the record before the name, between the name and the
	// time, and after the time; quiet is the same for the event with its
	// text rotated (quieted).
	parts, quiet [3][]byte
}

// replayCorpus is the recorded Windows and Sysmon events the packs carry
// as tests: the real events from SigmaHQ's regression data and Splunk's
// attack recordings, not the ones made up from the rules.
type replayCorpus struct {
	events []replayEvent
	// bytes is the size of all the recorded events together.
	bytes int64
}

var (
	corpusOnce sync.Once
	corpus     *replayCorpus
	corpusErr  error
)

// loadReplayCorpus reads the corpus once.
func loadReplayCorpus() (*replayCorpus, error) {
	corpusOnce.Do(func() { corpus, corpusErr = readCorpus(packs.Tests) })
	return corpus, corpusErr
}

// Placeholders the records are rendered with and then cut at.
const (
	replayHost = "\x00host"
	replayTime = "1970-01-01T00:00:00Z"
)

var (
	hostMark = []byte(`"Computer":"\u0000host"`)
	timeMark = []byte(`"TimeCreated":"` + replayTime + `"`)
)

func readCorpus(fsys fs.FS) (*replayCorpus, error) {
	files, err := fs.Glob(fsys, "*/tests/*.json")
	if err != nil {
		return nil, err
	}
	c := &replayCorpus{}
	t0 := time.Unix(0, 0)
	for _, name := range files {
		raw, err := fs.ReadFile(fsys, name)
		if err != nil {
			return nil, err
		}
		var tf sigmacheck.TestFile
		if err := json.Unmarshal(raw, &tf); err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		for _, cs := range tf.Cases {
			if cs.Source == "synthesized" {
				continue
			}
			cs.With, cs.Baseline, cs.Then, cs.Repeat, cs.Vary = nil, nil, nil, 0, nil
			tag, rec := cs.Record(replayHost, t0)
			if tag != replayTag {
				continue
			}
			parts, err := cutRecord(rec)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", name, err)
			}
			q := cs
			q.Data = quietData(cs.Data)
			_, qrec := q.Record(replayHost, t0)
			quiet, err := cutRecord(qrec)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", name, err)
			}
			c.events = append(c.events, replayEvent{parts: parts, quiet: quiet})
			c.bytes += int64(len(parts[0]) + len(parts[1]) + len(parts[2]))
		}
	}
	if len(c.events) == 0 {
		return nil, errors.New("the packs hold no recorded Windows events")
	}
	return c, nil
}

// cutRecord renders a record as JSON, cut at the name and the time.
func cutRecord(rec map[string]any) ([3][]byte, error) {
	var out [3][]byte
	b, err := json.Marshal(rec)
	if err != nil {
		return out, err
	}
	h, t := bytes.Index(b, hostMark), bytes.Index(b, timeMark)
	if h < 0 || t < 0 || t < h {
		return out, errors.New("a record has no computer name or time where expected")
	}
	nameAt := h + len(`"Computer":"`)
	timeAt := t + len(`"TimeCreated":"`)
	out[0] = b[:nameAt]
	out[1] = b[nameAt+len(`\u0000host`) : timeAt]
	out[2] = b[timeAt+len(replayTime):]
	return out, nil
}

// quietData is an event's data with the letters of its values rotated
// (ROT13): the same fields, sizes and shape, but no program, path or
// command line a detection looks for. The provider is kept, since it
// says how the event is read.
func quietData(data map[string]string) map[string]string {
	out := maps.Clone(data)
	for k, v := range out {
		if k == "Provider_Name" {
			continue
		}
		out[k] = rot13(v)
	}
	return out
}

func rot13(s string) string {
	b := []byte(s)
	for i, c := range b {
		switch {
		case c >= 'a' && c <= 'z':
			b[i] = 'a' + (c-'a'+13)%26
		case c >= 'A' && c <= 'Z':
			b[i] = 'A' + (c-'A'+13)%26
		}
	}
	return string(b)
}

// buildReplay makes the next batch of agent a from the corpus: each
// event a recorded one, with the agent's name and the time now, sent as
// recorded with probability share and quieted otherwise.
func (f *Fleet) buildReplay(a *simAgent, n int, share float64) *agentBatch {
	b := &agentBatch{first: a.next, last: a.next + int64(n) - 1, tag: replayTag}
	a.next += int64(n)
	host, _ := json.Marshal(a.host)
	host = host[1 : len(host)-1]
	now := time.Now().UTC()
	stamp := now.Format(time.RFC3339Nano)
	date := strconv.FormatFloat(float64(now.UnixNano())/1e9, 'f', 6, 64)
	var buf bytes.Buffer
	buf.Grow(n * 1200)
	buf.WriteByte('[')
	for seq := b.first; seq <= b.last; seq++ {
		if seq > b.first {
			buf.WriteByte(',')
		}
		// Each agent walks the corpus from its own place, so the agents
		// send different events at the same moment.
		ev := &f.corpus.events[(int64(a.id)*7919+seq)%int64(len(f.corpus.events))]
		parts := ev.quiet
		if share > 0 && rand.Float64() < share {
			parts = ev.parts
			b.attacks++
		}
		// Fluent Bit puts the time it read the record first (date).
		buf.WriteString(`{"date":`)
		buf.WriteString(date)
		buf.WriteByte(',')
		buf.Write(parts[0][1:])
		buf.Write(host)
		buf.Write(parts[1])
		buf.WriteString(stamp)
		buf.Write(parts[2])
	}
	buf.WriteByte(']')
	b.body = buf.Bytes()
	return b
}
