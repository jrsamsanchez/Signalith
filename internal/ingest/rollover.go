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

	mu    sync.RWMutex
	write map[string]string // day index -> the part events of it go to
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

// Run checks at once and then every RolloverEvery until ctx ends.
func (r *Rollover) Run(ctx context.Context) {
	t := time.NewTicker(RolloverEvery)
	defer t.Stop()
	for {
		if err := r.Check(ctx); err != nil && ctx.Err() == nil && r.Log != nil {
			r.Log.Debug("could not check the size of today's indices; tried again in a minute", "prefix", r.Prefix, "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Check lists the parts of the days events are being written to
// (yesterday, today and tomorrow, for events near midnight and clocks a
// little ahead) and picks the part each day's events go to.
func (r *Rollover) Check(ctx context.Context) error {
	now := time.Now()
	if r.Now != nil {
		now = r.Now()
	}
	var pats []string
	for _, d := range []time.Time{now.Add(-24 * time.Hour), now, now.Add(24 * time.Hour)} {
		pats = append(pats, url.PathEscape(r.Prefix+"-*-"+dayOf(d)+"*"))
	}
	var rows []struct {
		Index string `json:"index"`
		Pri   string `json:"pri"`
		Size  string `json:"pri.store.size"`
	}
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
	days := map[string]newest{}
	for _, row := range rows {
		day, n, ok := datamodel.SplitPart(row.Index)
		if !ok || !strings.HasPrefix(day, r.Prefix+"-") {
			continue
		}
		if cur, seen := days[day]; seen && cur.n >= n {
			continue
		}
		pri, _ := strconv.Atoi(row.Pri)
		size, err := strconv.ParseInt(row.Size, 10, 64)
		// A part whose size is unknown (a primary shard not assigned) is
		// not full: it is written to again once OpenSearch has it.
		full := err == nil && pri > 0 && r.MaxShardBytes > 0 && size/int64(pri) >= r.MaxShardBytes
		days[day] = newest{n: n, full: full, index: row.Index}
	}
	write := map[string]string{}
	for day, nw := range days {
		n := nw.n
		if nw.full && n < datamodel.MaxPart {
			n++
		}
		if n > 1 {
			write[day] = datamodel.PartName(day, n)
		}
	}
	r.mu.Lock()
	old := r.write
	r.write = write
	r.mu.Unlock()
	if r.Log != nil {
		for day, idx := range write {
			if old[day] != idx && days[day].index != idx {
				r.Log.Info("a day's index reached the rollover size; that day's events continue in a new index",
					"full", days[day].index, "next", idx, "gb_per_shard", r.MaxShardBytes>>30)
			}
		}
	}
	return nil
}
