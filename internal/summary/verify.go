package summary

import (
	"context"
	"errors"
	"time"
)

// verify checks model's summaries against its events when a check is
// due: the last recentSpan every recentEvery, the whole range every
// fullEvery. A slot whose count differs is built again, if its day's
// event index still exists: events that arrived late, sample data added
// or removed, a day restored from an archive. A day retention deleted
// keeps its summaries.
func (b *Builder) verify(ctx context.Context, h *held, now time.Time) error {
	st := &h.st
	var from time.Time
	full := false
	switch {
	case now.Sub(st.CheckedAll) >= fullEvery:
		from, full = st.From, true
	case now.Sub(st.CheckedRecent) >= recentEvery:
		from = st.Through.Add(-recentSpan)
		if from.Before(st.From) {
			from = st.From
		}
	default:
		return nil
	}
	to := st.Through
	if !to.After(from) {
		st.CheckedRecent = now
		if full {
			st.CheckedAll = now
		}
		return b.save(ctx, h)
	}
	days, err := b.dayIndices(ctx, st.Model)
	if err != nil {
		return err
	}
	bad, err := b.mismatched(ctx, st.Model, from, to, "1d", func(t time.Time) bool { return days[t.UTC().Format("2006.01.02")] })
	if err != nil {
		return err
	}
	var ranges []Range
	for _, day := range bad {
		end := day.Add(24 * time.Hour)
		slots, err := b.mismatched(ctx, st.Model, maxTime(day, from), minTime(end, to), "5m", func(t time.Time) bool { return !inGaps(st.Gaps, t) })
		if err != nil {
			return err
		}
		for _, s := range slots {
			if n := len(ranges); n > 0 && ranges[n-1].To.Equal(s) {
				ranges[n-1].To = s.Add(Slot)
				continue
			}
			ranges = append(ranges, Range{From: s, To: s.Add(Slot)})
		}
	}
	if len(ranges) > maxRebuilds {
		// The rest wait for the next check.
		ranges, full = ranges[:maxRebuilds], false
	}
	for _, r := range ranges {
		if !b.allowed() {
			return errStaleEpoch
		}
		_, err := b.build(ctx, st.Model, r.From, r.To)
		switch {
		case errors.Is(err, errTooMany):
			st.Gaps = addGap(st.Gaps, Gap(r))
		case err != nil:
			return err
		}
		st.Rebuilt++
	}
	if len(ranges) > 0 {
		b.log().Info("summaries: rebuilt slots whose events changed", "datamodel", st.Model, "ranges", len(ranges))
	}
	st.CheckedRecent = now
	if full {
		st.CheckedAll = now
	}
	return b.save(ctx, h)
}

func maxTime(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}

func inGaps(gs []Gap, t time.Time) bool {
	for _, g := range gs {
		if !t.Before(g.From) && t.Before(g.To) {
			return true
		}
	}
	return false
}

// mismatched returns the buckets of interval ("1d" or "5m") in [from, to)
// where the events of model and its summary rows count differently, of
// those keep accepts.
func (b *Builder) mismatched(ctx context.Context, model string, from, to time.Time, interval string, keep func(time.Time) bool) ([]time.Time, error) {
	raw, err := b.histogram(ctx, rawPattern(b.Prefix, model), nil, from, to, interval, false)
	if err != nil {
		return nil, err
	}
	sum, err := b.histogram(ctx, IndexPattern(b.Prefix), map[string]any{"term": map[string]any{ModelField: model}}, from, to, interval, true)
	if err != nil {
		return nil, err
	}
	var out []time.Time
	seen := map[int64]bool{}
	for _, m := range []map[int64]int64{raw, sum} {
		for _, k := range sortedKeys(m) {
			if seen[k] {
				continue
			}
			seen[k] = true
			t := time.UnixMilli(k).UTC()
			if raw[k] != sum[k] && keep(t) {
				out = append(out, t)
			}
		}
	}
	return sortTimes(out), nil
}

func sortTimes(ts []time.Time) []time.Time {
	for i := 1; i < len(ts); i++ {
		for j := i; j > 0 && ts[j].Before(ts[j-1]); j-- {
			ts[j], ts[j-1] = ts[j-1], ts[j]
		}
	}
	return ts
}

// histogram counts index's documents per bucket in [from, to): events,
// or with summed, the events summary rows stand for.
func (b *Builder) histogram(ctx context.Context, index string, filter map[string]any, from, to time.Time, interval string, summed bool) (map[int64]int64, error) {
	fs := []any{timeRange(from, to)}
	if filter != nil {
		fs = append(fs, filter)
	}
	hist := map[string]any{"field": "@timestamp", "min_doc_count": 1}
	if interval == "1d" {
		hist["calendar_interval"] = "1d"
	} else {
		hist["fixed_interval"] = interval
	}
	agg := map[string]any{"date_histogram": hist}
	if summed {
		agg["aggs"] = map[string]any{"n": map[string]any{"sum": map[string]any{"field": CountField}}}
	}
	body := map[string]any{"size": 0, "track_total_hits": false, "query": map[string]any{"bool": map[string]any{"filter": fs}},
		"aggs": map[string]any{"h": agg}}
	resp, err := b.Client.Search(ctx, index, body)
	if err != nil {
		if isNotFound(err) {
			return map[int64]int64{}, nil
		}
		return nil, err
	}
	out := map[int64]int64{}
	buckets, _ := dig(resp, "aggregations", "h", "buckets").([]any)
	for _, x := range buckets {
		bk, _ := x.(map[string]any)
		k, ok := toFloat(bk["key"])
		if !ok {
			continue
		}
		var n float64
		if summed {
			n, _ = toFloat(dig(bk, "n", "value"))
		} else {
			n, _ = toFloat(bk["doc_count"])
		}
		if n != 0 {
			out[int64(k)] = int64(n)
		}
	}
	return out, nil
}
