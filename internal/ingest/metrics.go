// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package ingest

import (
	"net/http"
	"sync/atomic"
	"time"

	"github.com/jrsamsanchez/signalith/internal/metrics"
	"github.com/jrsamsanchez/signalith/internal/store"
)

// What every pipeline of this process has written, for GET /metrics:
// events by intake and outcome, why OpenSearch turned events or whole
// writes away, how long writes took, and how long batches waited for an
// ingest slot. Labels come only from the fixed lists below, never from
// what a sender sends.

// MetricIntakes are the intake label's values; anything else counts as
// "other".
var MetricIntakes = []string{IntakeAgent, IntakeOTLP, IntakeHEC, IntakeOsquery, IntakeSyslog, IntakeScanner, IntakeSignalith, "other"}

// Rejection reasons: why OpenSearch turned one event away.
const (
	RejectTooMany  = "too_many_requests" // 429, full queues or a tripped circuit breaker
	RejectShards   = "shard_limit"       // the cluster holds the most shards it allows
	RejectReadOnly = "read_only"         // a block, as at the flood-stage watermark
	RejectMapping  = "mapping"           // a field the index cannot map
	RejectUnavail  = "unavailable"       // another 5xx
	RejectOther    = "other"
)

// MetricRejections are the reason label's values for rejected events.
var MetricRejections = []string{RejectTooMany, RejectShards, RejectReadOnly, RejectMapping, RejectUnavail, RejectOther}

// MetricWriteFailures are the reason label's values for whole writes
// that failed: a store.Problem, or unreachable.
var MetricWriteFailures = []string{
	string(store.RefusedBusy), string(store.RefusedBlocked), string(store.RefusedSignIn), string(store.RefusedPermission),
	string(store.RefusedNotInitialized), string(store.RefusedUnavailable), string(store.RefusedOther), store.ProblemTimeout, "unreachable",
}

type pipelineMetrics struct {
	// events[intake][0 indexed, 1 rejected, 2 failed]
	events       [8][3]atomic.Int64
	rejections   [6]atomic.Int64
	failures     [9]atomic.Int64
	bulk         *metrics.Histogram
	slotWait     *metrics.Histogram
	slotTimeouts atomic.Int64
}

var pm = &pipelineMetrics{
	bulk:     metrics.NewHistogram(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60),
	slotWait: metrics.NewHistogram(0.001, 0.01, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 15),
}

func indexOf(list []string, v string) int {
	for i, x := range list {
		if x == v {
			return i
		}
	}
	return len(list) - 1
}

// intakeIndex is the position of an intake in MetricIntakes.
func intakeIndex(intake string) int { return indexOf(MetricIntakes, intake) }

// rejectionOf says why OpenSearch turned an event away.
func rejectionOf(e store.BulkItemError) string {
	switch {
	case shardLimit(e):
		return RejectShards
	case e.Type == "cluster_block_exception":
		return RejectReadOnly
	case e.Status == http.StatusTooManyRequests, e.Type == "es_rejected_execution_exception", e.Type == "circuit_breaking_exception":
		return RejectTooMany
	case fieldRejection(e.Type):
		return RejectMapping
	case e.Status >= 500, Temporary(e):
		return RejectUnavail
	}
	return RejectOther
}

// writeFailureOf says why a whole write failed.
func writeFailureOf(err error) string {
	if p := store.Problem(err); p != "" {
		return p
	}
	return "unreachable"
}

// observeBulk records one write to OpenSearch that took d and failed with
// err (nil when OpenSearch answered).
func observeBulk(d time.Duration, err error) {
	pm.bulk.Observe(d.Seconds())
	if err != nil {
		pm.failures[indexOf(MetricWriteFailures, writeFailureOf(err))].Add(1)
	}
}

// IntakeCount is what was written of one intake's events.
type IntakeCount struct {
	Intake                    string
	Indexed, Rejected, Failed int64
}

// MetricsSnapshot is what every pipeline of this process has done since
// it started.
type MetricsSnapshot struct {
	Events []IntakeCount
	// Rejections counts events OpenSearch turned away, by reason
	// (MetricRejections), and WriteFailures whole writes that failed
	// (MetricWriteFailures).
	Rejections    map[string]int64
	WriteFailures map[string]int64
	BulkSeconds   metrics.HistogramSnapshot
	// SlotWait is how long batches waited for an ingest slot, and
	// SlotTimeouts how many gave up waiting (answered "try again").
	SlotWait     metrics.HistogramSnapshot
	SlotTimeouts int64
}

// Metrics reads what every pipeline of this process has done.
func Metrics() MetricsSnapshot {
	s := MetricsSnapshot{Rejections: map[string]int64{}, WriteFailures: map[string]int64{}}
	for i, in := range MetricIntakes {
		s.Events = append(s.Events, IntakeCount{Intake: in, Indexed: pm.events[i][0].Load(), Rejected: pm.events[i][1].Load(), Failed: pm.events[i][2].Load()})
	}
	for i, r := range MetricRejections {
		s.Rejections[r] = pm.rejections[i].Load()
	}
	for i, r := range MetricWriteFailures {
		s.WriteFailures[r] = pm.failures[i].Load()
	}
	s.BulkSeconds = pm.bulk.Snapshot()
	s.SlotWait = pm.slotWait.Snapshot()
	s.SlotTimeouts = pm.slotTimeouts.Load()
	return s
}

// SlotUse is the ingest slots now: how many there are, how many are
// held and how many batches wait for one. Pipelines that share Limits
// (every tenant's) see the same.
func (p *Pipeline) SlotUse() (capacity, held, waiting int) {
	l := p.limits()
	l.slotsMu.Lock()
	defer l.slotsMu.Unlock()
	return l.slots.n, l.slots.held, len(l.slots.waiting)
}

// countFailed counts documents of a write that failed as a whole.
func countFailed(intakes []int) {
	for _, in := range intakes {
		if in >= 0 {
			pm.events[in][2].Add(1)
		}
	}
}

// countWritten counts the documents of a write: those in errs (by their
// position) as rejected, with why, and the others as indexed.
func countWritten(intakes []int, errs []store.BulkItemError) {
	rejected := make(map[int]bool, len(errs))
	for _, e := range errs {
		if e.Pos < 0 || e.Pos >= len(intakes) || rejected[e.Pos] {
			continue
		}
		rejected[e.Pos] = true
		if intakes[e.Pos] >= 0 {
			pm.rejections[indexOf(MetricRejections, rejectionOf(e))].Add(1)
		}
	}
	for i, in := range intakes {
		if in < 0 {
			continue
		}
		if rejected[i] {
			pm.events[in][1].Add(1)
		} else {
			pm.events[in][0].Add(1)
		}
	}
}
