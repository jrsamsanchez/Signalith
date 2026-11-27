// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package ingest

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jrsamsanchez/signalith/internal/datamodel"
	"github.com/jrsamsanchez/signalith/internal/store"
)

// RolloverEvery is how often Rollover.Run checks the size of the days
// being written. At a terabyte a day a shard gains well under a GB in
// that time, so a part ends close to its size.
const RolloverEvery = time.Minute

// Rollover splits a busy day's index of a data model into parts, so no
// shard grows past MaxShardBytes. Indices are daily, so a day is already
// the most age one holds; rollover bounds their size as well. A shard of
// hundreds of GB merges ever larger segments while it is written, which
// slows indexing with the CPUs mostly idle, and takes hours to move or
// recover.
//
// Once the newest part of a day passes MaxShardBytes per primary shard,
// events of that day go to the next part: signalith-network-2026.10.17,
// then -2, -3 and so on, up to datamodel.MaxPart. Each part gets the
// index template like any day's index. Searches cover every part
// (they read <prefix>-<model>-*), and retention, cold storage and the
// archive take each part as an index of that day.
//
// The state is what OpenSearch holds, so servers need not agree on
// anything else: each one lists the parts of the days being written and
// writes to the newest, or to the next one once the newest is full. A
// server that has not checked yet writes to the newest part it knows, or
// to the day's index, which then only grows a little more.
type Rollover struct {
	Client interface {
		Do(ctx context.Context, method, path string, body any, out any) error
	}
	// Prefix is the index prefix whose days it checks (a tenant's own).
	Prefix string
	// MaxShardBytes is the size per primary shard at which a day moves
	// to its next part.
	MaxShardBytes int64
	Now           func() time.Time
	Log           *slog.Logger

	// ByMonth reports whether a data model's events may go to monthly
	// indices (see IndexFor); nil stores every model by day.
	ByMonth func(model string) bool

	mu    sync.RWMutex
	write map[string]string // day index -> the part events of it go to
	// months are the months (YYYY.MM) the last check covered, and full the
	// monthly indices of them that take no more events: the rest of their
	// month goes to daily indices.
	months  map[string]bool
	full    map[string]bool
	checked bool
}

// IndexFor returns the index an event of model at t goes to, under
// prefix (its tenant's).
//
// A data model that ByMonth allows is stored by month: its events of a
// month go to one index, <prefix>-<model>-YYYY.MM, so OpenSearch holds
// one of its shards a month instead of one a day. Each day adds a shard
// per data model on every node, and OpenSearch refuses new indices once a
// node holds cluster.max_shards_per_node of them (1,000 by default), so
// daily indices of a dozen data models kept 90 days fill one node. A
// monthly index takes events until it holds MaxShardBytes per primary
// shard, or its mapping has many field names (see CloseMonth); the rest of
// that month then goes to daily indices, so a busy model is stored by day
// as before, and a monthly index is never much larger than a day's.
//
// Only the months the check covers (yesterday's, today's and tomorrow's)
// are written by month, and not one in which another server already
// wrote daily indices; an event of an older month goes to its day's
// index. Before the first check, events of those months go to their
// monthly index. A nil Rollover returns the day's index.
func (r *Rollover) IndexFor(prefix, model string, t time.Time) string {
	dayIndex := datamodel.IndexName(prefix, model, dayOf(t))
	if r == nil {
		return dayIndex
	}
	if r.ByMonth != nil && r.ByMonth(model) {
		month := datamodel.MonthOf(t)
		name := datamodel.MonthIndexName(prefix, model, month)
		r.mu.RLock()
		open := !r.full[name] && (r.months[month] || !r.checked && r.near(month))
		r.mu.RUnlock()
		if open {
			return name
		}
	}
	return r.Index(dayIndex)
}

// near reports whether month is one a check covers now.
func (r *Rollover) near(month string) bool {
	for _, d := range r.checkDays() {
		if datamodel.MonthOf(d) == month {
			return true
		}
	}
	return false
}

// checkDays are the days a check covers: yesterday, today and tomorrow,
// for events near midnight and clocks a little ahead.
func (r *Rollover) checkDays() []time.Time {
	now := time.Now()
	if r.Now != nil {
		now = r.Now()
	}
	return []time.Time{now.Add(-24 * time.Hour), now, now.Add(24 * time.Hour)}
}

// CloseMonth stops writing to the monthly index name, so the rest of its
// month goes to daily indices, and reports whether events went to it.
// The pipeline calls it once the index's mapping holds MonthFieldsClose
// fields: a daily index starts each day with room for the field names
// senders choose, and a month must not run out of it. Other servers see
// the daily indices at their next check, and stop too.
func (r *Rollover) CloseMonth(name string) bool {
	if r == nil {
		return false
	}
	if _, _, ok := datamodel.SplitMonth(name); !ok {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.full[name] {
		return false
	}
	if r.full == nil {
		r.full = map[string]bool{}
	}
	r.full[name] = true
	if r.Log != nil {
		r.Log.Info("a monthly index has many field names; the rest of its month goes to daily indices", "index", name)
	}
	return true
}

// Index returns the index to write events of a day's index to: its newest
// part, or the next one once that is full. A nil Rollover returns
// dayIndex.
func (r *Rollover) Index(dayIndex string) string {
	if r == nil {
		return dayIndex
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if n, ok := r.write[dayIndex]; ok {
		return n
	}
	return dayIndex
}

// RolloverWarnAfter is how long the checks must keep failing before Run
// warns: until then a busy day's index may only grow past the rollover
// size a little.
const RolloverWarnAfter = 10 * time.Minute

// Run checks at once and then every RolloverEvery until ctx ends. A check
// that fails is logged at debug level; checks failing for
// RolloverWarnAfter are warned about once, as busy days then stop rolling
// over.
func (r *Rollover) Run(ctx context.Context) {
	t := time.NewTicker(RolloverEvery)
	defer t.Stop()
	var fl rolloverFailures
	for {
		err := r.Check(ctx)
		if ctx.Err() == nil {
			fl.note(r, err, time.Now())
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// rolloverFailures is how long Run's checks have been failing.
type rolloverFailures struct {
	since  time.Time
	warned bool
}

// note logs the outcome of a check made at now: a failure at debug level
// until the checks have failed for RolloverWarnAfter, then once as a
// warning, and the first success after that warning.
func (f *rolloverFailures) note(r *Rollover, err error, now time.Time) {
	log := r.Log
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	if err == nil {
		if f.warned {
			log.Info("the size of today's indices can be checked again; busy days roll over", "prefix", r.Prefix)
		}
		*f = rolloverFailures{}
		return
	}
	if f.since.IsZero() {
		f.since = now
	}
	if !f.warned && now.Sub(f.since) >= RolloverWarnAfter {
		log.Warn("could not check the size of today's indices for a while, so a busy day's index is not split and keeps growing",
			"prefix", r.Prefix, "since", f.since.UTC().Format(time.RFC3339), "err", err)
		f.warned = true
		return
	}
	log.Debug("could not check the size of today's indices; tried again in a minute", "prefix", r.Prefix, "err", err)
}

// Check lists the parts of the days events are being written to
// (yesterday, today and tomorrow, for events near midnight and clocks a
// little ahead) and picks the part each day's events go to.
//
// It also lists the monthly indices of those days' months, to find the
// ones that are full (MaxShardBytes per primary shard). A data model with
// a daily index of those days stays daily for the rest of that month.
func (r *Rollover) Check(ctx context.Context) error {
	var pats, monthPats []string
	days, months := map[string]bool{}, map[string]bool{}
	for _, d := range r.checkDays() {
		days[dayOf(d)] = true
		pats = append(pats, url.PathEscape(r.Prefix+"-*-"+dayOf(d)+"*"))
		if m := datamodel.MonthOf(d); !months[m] {
			months[m] = true
			monthPats = append(monthPats, url.PathEscape(r.Prefix+"-*-"+m))
		}
	}
	pats = append(pats, monthPats...)
	var rows []catRow
	err := r.Client.Do(ctx, http.MethodGet, "/_cat/indices/"+strings.Join(pats, ",")+
		"?format=json&h=index,pri,pri.store.size&bytes=b&expand_wildcards=open", nil, &rows)
	var se *store.Error
	if errors.As(err, &se) && se.Status == http.StatusNotFound {
		rows, err = nil, nil
	}
	if err != nil {
		return err
	}
	type newest struct {
		n     int
		full  bool
		index string
	}
	parts := map[string]newest{}
	fullMonths, bySize := map[string]bool{}, map[string]bool{}
	for _, row := range rows {
		pri, _ := strconv.Atoi(row.Pri)
		size, err := strconv.ParseInt(row.Size, 10, 64)
		// An index whose size is unknown (a primary shard not assigned) is
		// not full: it is written to again once OpenSearch has it.
		full := err == nil && pri > 0 && r.MaxShardBytes > 0 && size/int64(pri) >= r.MaxShardBytes
		if stem, month, ok := datamodel.SplitMonth(row.Index); ok {
			if months[month] && strings.HasPrefix(stem, r.Prefix+"-") && full {
				fullMonths[row.Index], bySize[row.Index] = true, true
			}
			continue
		}
		day, n, ok := datamodel.SplitPart(row.Index)
		if !ok || !strings.HasPrefix(day, r.Prefix+"-") {
			continue
		}
		// A daily index of these days: that model is stored by day for the
		// rest of its month, as another server (or this one, earlier)
		// chose.
		ds := day[len(day)-len("2006.01.02"):]
		fullMonths[day[:len(day)-len(ds)]+ds[:len("2006.01")]] = true
		if !days[ds] {
			continue
		}
		if cur, seen := parts[day]; seen && cur.n >= n {
			continue
		}
		parts[day] = newest{n: n, full: full, index: row.Index}
	}
	write := map[string]string{}
	for day, nw := range parts {
		n := nw.n
		if nw.full && n < datamodel.MaxPart {
			n++
		}
		if n > 1 {
			write[day] = datamodel.PartName(day, n)
		}
	}
	r.mu.Lock()
	old, oldFull := r.write, r.full
	// A month this server closed itself (CloseMonth) stays closed until
	// the check sees the daily indices that follow it.
	for name := range oldFull {
		if _, m, ok := datamodel.SplitMonth(name); ok && months[m] {
			fullMonths[name] = true
		}
	}
	r.write, r.full, r.months, r.checked = write, fullMonths, months, true
	r.mu.Unlock()
	if r.Log != nil {
		for day, idx := range write {
			if old[day] != idx && parts[day].index != idx {
				r.Log.Info("a day's index reached the rollover size; that day's events continue in a new index",
					"full", parts[day].index, "next", idx, "gb_per_shard", r.MaxShardBytes>>30)
			}
		}
		for name := range bySize {
			if !oldFull[name] {
				r.Log.Info("a monthly index reached the rollover size; the rest of its month goes to daily indices",
					"full", name, "gb_per_shard", r.MaxShardBytes>>30)
			}
		}
	}
	return nil
}

// catRow is a row of _cat/indices as Check reads it.
type catRow struct {
	Index string `json:"index"`
	Pri   string `json:"pri"`
	Size  string `json:"pri.store.size"`
}
