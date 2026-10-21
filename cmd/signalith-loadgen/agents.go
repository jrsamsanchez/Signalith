// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// pace calls fire rate times a second on a fixed schedule until ctx ends.
// The schedule does not wait for earlier calls to finish (open loop), so
// a slow server shows up as latency rather than as fewer requests; when
// the generator itself falls behind its schedule, the lag is recorded as
// generator_lag.
func pace(ctx context.Context, rate float64, m *Metrics, fire func(n int64)) {
	if rate <= 0 {
		<-ctx.Done()
		return
	}
	start := time.Now()
	timer := time.NewTimer(0)
	defer timer.Stop()
	var n int64
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		now := time.Now()
		due := int64(now.Sub(start).Seconds()*rate) + 1
		for ; n < due; n++ {
			if ctx.Err() != nil {
				return
			}
			sched := start.Add(time.Duration(float64(n) / rate * float64(time.Second)))
			if lag := time.Since(sched); lag > 50*time.Millisecond {
				m.Observe("generator_lag", lag)
			} else {
				m.Observe("generator_lag", 0)
			}
			fire(n)
		}
		next := start.Add(time.Duration(float64(n) / rate * float64(time.Second)))
		timer.Reset(max(time.Until(next), time.Millisecond))
	}
}

// seqRange is the sequence numbers first..last of one agent.
type seqRange struct{ First, Last int64 }

// agentBatch is one request an agent sends, kept byte for byte so a
// resend is the same request, as Fluent Bit resends a chunk.
type agentBatch struct {
	body        []byte
	first, last int64
	// tag is the Fluent Bit tag the batch is sent with; empty sends none.
	tag string
	// attacks are the replayed events in it sent as recorded.
	attacks int64
}

func (b *agentBatch) events() int64 { return b.last - b.first + 1 }

type simAgent struct {
	id     int
	host   string
	target int
	// home is the target the agent starts on, and left is when it last
	// switched away from it (see homeAfter).
	home  int
	left  time.Time
	queue chan *agentBatch
	// next is the next sequence number; only the scheduler uses it.
	next int64
	mu   sync.Mutex
	// acked are the batches the server said it stored.
	acked []seqRange
}

// agentQueue is how many batches one agent buffers before the generator
// drops new ones, as Fluent Bit stops reading when its buffer is full.
const agentQueue = 256

// homeAfter is how long an agent that switched targets on an error
// stays away before it tries its own target again, as an agent behind
// DNS round robin resolves the name again once its answer expires. So a
// server that restarts gets its agents back rather than leaving their
// load on the others for the rest of the run.
var homeAfter = time.Minute

// defaultBufferMB is AgentLoad.BufferMB when it is not set.
const defaultBufferMB = 512

// Fleet is the simulated Fluent Bit agents of a run. Each agent numbers
// its events from 1 and keeps the numbers across retries, so verify can
// tell exactly which stored events went missing or were stored twice.
type Fleet struct {
	run     string
	token   string
	targets []string
	client  *http.Client
	m       *Metrics
	// drain ends the agents' retries once the run's drain time is over
	// (see StopRetrying).
	drain context.Context
	stop  context.CancelFunc

	mu     sync.Mutex
	agents []*simAgent
	wg     sync.WaitGroup
	closed bool

	sent        atomic.Int64 // events put in batches
	stored      atomic.Int64 // events the server said it stored
	refused     atomic.Int64 // events in batches refused for good (4xx)
	rejected    atomic.Int64 // events refused inside a stored batch
	undelivered atomic.Int64 // events still unsent when the drain ended
	dropped     atomic.Int64 // events the generator could not queue
	pending     atomic.Int64 // events queued or being sent
	buffered    atomic.Int64 // bytes of batches queued or being sent

	switchOnError atomic.Bool
	// corpus is the recorded events a replay sends.
	corpus *replayCorpus
	// replayed is whether any phase replayed recorded events, which carry
	// no sequence numbers to verify.
	replayed atomic.Bool
}

func newFleet(run, token string, targets []string, client *http.Client, m *Metrics) *Fleet {
	f := &Fleet{run: run, token: token, targets: targets, client: client, m: m}
	f.drain, f.stop = context.WithCancel(context.Background())
	return f
}

// StopRetrying gives up every batch not yet stored; they count as
// undelivered.
func (f *Fleet) StopRetrying() { f.stop() }

func (f *Fleet) agent(i int) *simAgent {
	f.mu.Lock()
	defer f.mu.Unlock()
	for len(f.agents) <= i {
		id := len(f.agents)
		a := &simAgent{id: id, host: fmt.Sprintf("agent-%04d", id), target: id % len(f.targets),
			home: id % len(f.targets), queue: make(chan *agentBatch, agentQueue), next: 1}
		f.agents = append(f.agents, a)
		f.wg.Add(1)
		go f.sender(a)
	}
	return f.agents[i]
}

// Run sends load until ctx ends.
func (f *Fleet) Run(ctx context.Context, load AgentLoad) {
	if load.N <= 0 || load.Rate <= 0 {
		return
	}
	batch := load.Batch
	if batch <= 0 {
		// One flush a second per agent, like Fluent Bit's Flush 1.
		batch = max(1, int(load.Rate/float64(load.N)+0.5))
	}
	batch = min(batch, 20000)
	f.switchOnError.Store(load.SwitchOnError)
	bufferMB := load.BufferMB
	if bufferMB <= 0 {
		bufferMB = defaultBufferMB
	}
	limit := int64(bufferMB) << 20
	var share float64
	if load.Replay != nil {
		c, err := loadReplayCorpus()
		if err != nil {
			// The scenario check loads the corpus first, so this is a
			// broken build.
			f.m.Add("agent_replay_errors", 1)
			return
		}
		f.corpus, share = c, load.Replay.share()
		f.replayed.Store(true)
	}
	for i := range load.N {
		f.agent(i)
	}
	pace(ctx, load.Rate/float64(batch), f.m, func(n int64) {
		a := f.agent(int(n % int64(load.N)))
		// When the server falls behind, unsent batches pile up; without
		// a cap the generator runs out of memory before the run ends.
		if len(a.queue) >= cap(a.queue) || f.buffered.Load() >= limit {
			f.dropped.Add(int64(batch))
			f.m.Add("agent_events_dropped", int64(batch))
			return
		}
		var b *agentBatch
		if load.Replay != nil {
			b = f.buildReplay(a, batch, share)
			f.m.Add("agent_attack_events_sent", b.attacks)
		} else {
			b = f.build(a, batch, load.EventBytes)
		}
		f.m.Add("agent_bytes_sent", int64(len(b.body)))
		f.sent.Add(b.events())
		f.pending.Add(b.events())
		f.buffered.Add(int64(len(b.body)))
		f.m.Add("agent_events_sent", b.events())
		a.queue <- b
	})
}

// build makes the next batch of agent a.
func (f *Fleet) build(a *simAgent, n, size int) *agentBatch {
	b := &agentBatch{first: a.next, last: a.next + int64(n) - 1}
	a.next += int64(n)
	var buf bytes.Buffer
	buf.Grow(n * (160 + size))
	buf.WriteByte('[')
	now := float64(time.Now().UnixNano()) / 1e9
	pad := ""
	if size > 120 {
		pad = " " + strings.Repeat("x", size-120)
	}
	for seq := b.first; seq <= b.last; seq++ {
		if seq > b.first {
			buf.WriteByte(',')
		}
		buf.WriteString(`{"date":`)
		buf.WriteString(strconv.FormatFloat(now, 'f', 6, 64))
		buf.WriteString(`,"message":"loadgen event `)
		buf.WriteString(strconv.FormatInt(seq, 10))
		buf.WriteString(` from `)
		buf.WriteString(a.host)
		buf.WriteString(pad)
		buf.WriteString(`","host":"`)
		buf.WriteString(a.host)
		buf.WriteString(`","loadgen_run":"`)
		buf.WriteString(f.run)
		buf.WriteString(`","loadgen_agent":`)
		buf.WriteString(strconv.Itoa(a.id))
		buf.WriteString(`,"loadgen_seq":`)
		buf.WriteString(strconv.FormatInt(seq, 10))
		buf.WriteByte('}')
	}
	buf.WriteByte(']')
	b.body = buf.Bytes()
	return b
}

// sender sends an agent's batches in order, one at a time, each until it
// is stored, refused for good, or the drain ends.
func (f *Fleet) sender(a *simAgent) {
	defer f.wg.Done()
	for b := range a.queue {
		f.deliver(a, b)
		f.pending.Add(-b.events())
		f.buffered.Add(-int64(len(b.body)))
	}
}

// ingestAnswer is the part of POST /api/ingest's answer used here.
type ingestAnswer struct {
	Indexed  int `json:"indexed"`
	Rejected int `json:"rejected"`
}

func (f *Fleet) deliver(a *simAgent, b *agentBatch) {
	wait := time.Second
	for {
		if f.drain.Err() != nil {
			f.undelivered.Add(b.events())
			f.m.Add("agent_events_undelivered", b.events())
			return
		}
		if a.target != a.home && time.Since(a.left) >= homeAfter {
			a.target = a.home
		}
		target := a.target
		status, ans, err := f.send(a, b)
		switch {
		case err == nil && status/100 == 2:
			stored := b.events() - int64(ans.Rejected)
			f.stored.Add(stored)
			f.m.Add(targetCounter(target), stored)
			f.m.Add("agent_events_stored", stored)
			if ans.Rejected > 0 {
				f.rejected.Add(int64(ans.Rejected))
				f.m.Add("agent_events_rejected", int64(ans.Rejected))
			} else if b.tag == "" {
				// Replayed events carry no sequence numbers to verify, and
				// a week of their ranges would fill the generator's memory.
				a.mu.Lock()
				a.acked = append(a.acked, seqRange{b.first, b.last})
				a.mu.Unlock()
			}
			return
		case err == nil && retryable(status):
		case err == nil:
			// Refused for good: Fluent Bit drops the chunk.
			f.refused.Add(b.events())
			f.m.Add("agent_events_refused", b.events())
			return
		}
		if len(f.targets) > 1 && f.switchOnError.Load() {
			if a.target == a.home {
				a.left = time.Now()
			}
			a.target = (a.target + 1) % len(f.targets)
		}
		// Like Fluent Bit's scheduler: a growing wait with jitter.
		d := wait/2 + rand.N(wait/2+1)
		select {
		case <-time.After(d):
		case <-f.drain.Done():
		}
		wait = min(wait*2, 30*time.Second)
	}
}

func retryable(status int) bool {
	return status == http.StatusTooManyRequests || status == http.StatusRequestTimeout || status >= 500
}

func (f *Fleet) send(a *simAgent, b *agentBatch) (int, ingestAnswer, error) {
	var ans ingestAnswer
	ctx, cancel := context.WithTimeout(f.drain, 2*time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(f.targets[a.target], "/")+"/api/ingest", bytes.NewReader(b.body))
	if err != nil {
		return 0, ans, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+f.token)
	req.Header.Set("User-Agent", "Fluent-Bit")
	req.Header.Set("X-Signalith-Agent", a.host)
	if b.tag != "" {
		req.Header.Set("X-Signalith-Tag", b.tag)
	}
	start := time.Now()
	resp, err := f.client.Do(req)
	f.m.Add("ingest_requests", 1)
	if err != nil {
		f.m.Observe("ingest", time.Since(start))
		f.m.Add("ingest_errors", 1)
		f.m.Add("ingest_network_errors", 1)
		return 0, ans, err
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	resp.Body.Close()
	f.m.Observe("ingest", time.Since(start))
	if resp.StatusCode/100 != 2 {
		f.m.Add("ingest_errors", 1)
		f.m.Add("ingest_status_"+strconv.Itoa(resp.StatusCode), 1)
		return resp.StatusCode, ans, nil
	}
	_ = json.Unmarshal(body, &ans)
	return resp.StatusCode, ans, nil
}

// Close stops taking batches and waits until every queued batch is
// stored, refused, or given up when the drain ends.
func (f *Fleet) Close() {
	f.mu.Lock()
	if !f.closed {
		f.closed = true
		for _, a := range f.agents {
			close(a.queue)
		}
	}
	f.mu.Unlock()
	f.wg.Wait()
}

// targetCounter names the counter of events the target with this index
// said it stored, for ingest_share_min.
func targetCounter(i int) string { return "agent_events_stored_target_" + strconv.Itoa(i+1) }

// Acked is every agent's stored sequence numbers, by agent.
func (f *Fleet) Acked() map[int][]seqRange {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := map[int][]seqRange{}
	for _, a := range f.agents {
		a.mu.Lock()
		if len(a.acked) > 0 {
			out[a.id] = append([]seqRange(nil), a.acked...)
		}
		a.mu.Unlock()
	}
	return out
}
