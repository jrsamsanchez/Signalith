package detect

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"
	"unicode/utf8"

	"github.com/jrsamsanchez/signalith/internal/query"
	"github.com/jrsamsanchez/signalith/internal/search"
)

// Backtest limits. A backtest runs at most MaxBacktestRuns searches, each
// bounded by the search engine's own limits (MaxEvents, MaxBuckets, the
// evaluator's memory caps and the per-user share of search slots).
const (
	MaxBacktestWindow = 90 * 24 * time.Hour
	MaxBacktestRuns   = 60
	// backtestSamples is how many of the findings it would have raised a
	// backtest returns, newest first.
	backtestSamples = 20
	// backtestTop is how many values of each entity field it counts.
	backtestTop = 5
)

// Backtest is what a detection would have done over a past window.
type Backtest struct {
	Earliest time.Time `json:"earliest"`
	Latest   time.Time `json:"latest"`
	// Step is how much time each search covered. It is the lookback,
	// unless the window needed more than MaxBacktestRuns searches.
	Step string `json:"step"`
	// Approximate is set when a summary (stats, top, dedup...) searched
	// more time per run than the lookback, so its counts can be higher
	// than live runs would see.
	Approximate bool `json:"approximate,omitempty"`
	// Results are the rows the searches returned; Findings the findings
	// those rows would have raised after exceptions and throttling.
	Results    int `json:"results"`
	Findings   int `json:"findings"`
	Suppressed int `json:"suppressed"`
	Throttled  int `json:"throttled"`
	// Matched counts the events the searches matched, which can be more
	// than they returned (Capped).
	Matched int64 `json:"matched"`
	Capped  bool  `json:"capped,omitempty"`
	// Partial is set when the time ran out before every run: the counts
	// cover Earliest to PartialAt.
	Partial   bool       `json:"partial,omitempty"`
	PartialAt *time.Time `json:"partial_at,omitempty"`
	Buckets   []Bucket   `json:"buckets"`
	// Samples are the newest findings it would have raised.
	Samples []BacktestHit `json:"samples"`
	// Top counts the findings per user, system and so on, to spot one
	// noisy source worth an exception.
	Top map[string][]ValueCount `json:"top,omitempty"`
	// Searches is how many searches ran; TookMS how long they took.
	Searches int   `json:"searches"`
	TookMS   int64 `json:"took_ms"`
}

// Bucket is one run of a backtest.
type Bucket struct {
	Start    time.Time `json:"start"`
	End      time.Time `json:"end"`
	Results  int       `json:"results"`
	Findings int       `json:"findings"`
}

// BacktestHit is a finding a backtest would have raised.
type BacktestHit struct {
	Time  time.Time      `json:"time"`
	Title string         `json:"title"`
	Row   map[string]any `json:"row"`
}

// ValueCount is how many findings had a value.
type ValueCount struct {
	Value string `json:"value"`
	Count int    `json:"count"`
}

// BacktestStep works out how much time each backtest search covers: the
// lookback, or longer when the window would otherwise need more than
// MaxBacktestRuns searches.
func BacktestStep(d *Detection, window time.Duration) (time.Duration, error) {
	if window <= 0 || window > MaxBacktestWindow {
		return 0, fmt.Errorf("the backtest window must be between 1m and %s", "90d")
	}
	lb, err := ParseDuration(d.Lookback)
	if err != nil {
		return 0, err
	}
	step := max(lb, time.Minute)
	if need := (window + MaxBacktestRuns - 1) / MaxBacktestRuns; step < need {
		// Round up to a whole minute so buckets read cleanly.
		step = need.Truncate(time.Minute)
		if step < need {
			step += time.Minute
		}
	}
	return min(step, window), nil
}

// Backtest runs an unsaved detection over the window that ends now, the
// way its scheduled runs would have, and counts what it would have raised.
// Nothing is written: no findings, risk or throttle records. When ctx runs
// out after at least one search, the partial result is returned.
func (s *Scheduler) Backtest(ctx context.Context, d *Detection, window time.Duration) (*Backtest, error) {
	step, err := BacktestStep(d, window)
	if err != nil {
		return nil, err
	}
	q, err := query.Parse(d.Query)
	if err != nil {
		return nil, err
	}
	q.EventsOnly = true // as the scheduler runs it
	lb, _ := ParseDuration(d.Lookback)
	end := s.clusterNow().UTC().Truncate(time.Minute)
	start := end.Add(-window)
	bt := &Backtest{Earliest: start, Latest: end, Step: formatStep(step), Buckets: []Bucket{}, Samples: []BacktestHit{}}
	bt.Approximate = step > lb && !windowFree(q)
	tw := throttleWindow(d)
	last := map[string]time.Time{} // throttle key -> when it last raised
	top := map[string]map[string]int{}
	began := time.Now()
	for from := start; from.Before(end); from = from.Add(step) {
		to := from.Add(step)
		if to.After(end) {
			to = end
		}
		run := *q
		run.Earliest = from.Format(time.RFC3339)
		run.Latest = to.Format(time.RFC3339)
		res, err := s.Engine.Execute(ctx, &run)
		if err != nil {
			if bt.Searches > 0 && (errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded)) {
				bt.Partial = true
				at := from
				bt.PartialAt = &at
				break
			}
			return nil, err
		}
		bt.Searches++
		b := Bucket{Start: from, End: to, Results: len(res.Rows)}
		bt.Results += len(res.Rows)
		bt.Matched += res.Matched
		if res.Truncated || (res.Kind == "events" && res.Matched > int64(len(res.Rows))) {
			bt.Capped = true
		}
		// Rows come newest first; throttling goes oldest first.
		rows := append([]search.Row(nil), res.Rows...)
		sort.SliceStable(rows, func(i, j int) bool { return rowTime(rows[i], to).Before(rowTime(rows[j], to)) })
		seen := map[string]bool{}
		for _, row := range rows {
			at := rowTime(row, to)
			if d.Suppressing(row, at) != nil {
				bt.Suppressed++
				continue
			}
			key := GroupKey(d, row)
			if seen[key] {
				bt.Throttled++
				continue
			}
			seen[key] = true
			if t, ok := last[key]; ok && tw > 0 && at.Sub(t) < tw {
				bt.Throttled++
				continue
			}
			last[key] = at
			b.Findings++
			bt.Findings++
			bt.Samples = append(bt.Samples, BacktestHit{Time: at, Title: RenderTitle(d.Title, row), Row: trimRow(row, d.Throttle.Fields)})
			if len(bt.Samples) > backtestSamples {
				bt.Samples = bt.Samples[1:]
			}
			for _, f := range EntityFields {
				if v, ok := row[f]; ok && v != nil && fmt.Sprint(v) != "" {
					if top[f] == nil {
						top[f] = map[string]int{}
					}
					if len(top[f]) < 10000 || top[f][fmt.Sprint(v)] > 0 {
						top[f][fmt.Sprint(v)]++
					}
				}
			}
		}
		bt.Buckets = append(bt.Buckets, b)
	}
	// Newest first, as on the findings page.
	for i, j := 0, len(bt.Samples)-1; i < j; i, j = i+1, j-1 {
		bt.Samples[i], bt.Samples[j] = bt.Samples[j], bt.Samples[i]
	}
	for f, counts := range top {
		vs := make([]ValueCount, 0, len(counts))
		for v, n := range counts {
			vs = append(vs, ValueCount{Value: ShowHidden(v), Count: n})
		}
		sort.Slice(vs, func(i, j int) bool {
			if vs[i].Count != vs[j].Count {
				return vs[i].Count > vs[j].Count
			}
			return vs[i].Value < vs[j].Value
		})
		if bt.Top == nil {
			bt.Top = map[string][]ValueCount{}
		}
		bt.Top[f] = vs[:min(len(vs), backtestTop)]
	}
	bt.TookMS = time.Since(began).Milliseconds()
	return bt, nil
}

// maxSampleValue is the most text a backtest sample keeps of one value.
const maxSampleValue = 2000

// maxSampleFields is the most fields a backtest sample keeps.
const maxSampleFields = 200

// trimRow shortens long text values, such as _raw, in a sample row and
// keeps at most maxSampleFields fields (the time, the raw event, the
// entity and the grouping fields first), so a backtest's answer stays
// small.
func trimRow(row search.Row, keep []string) map[string]any {
	names := make([]string, 0, len(row))
	for k := range row {
		names = append(names, k)
	}
	first := map[string]bool{"_time": true, "_raw": true}
	for _, f := range EntityFields {
		first[f] = true
	}
	for _, f := range keep {
		first[f] = true
	}
	sort.SliceStable(names, func(i, j int) bool {
		if first[names[i]] != first[names[j]] {
			return first[names[i]]
		}
		return names[i] < names[j]
	})
	names = names[:min(len(names), maxSampleFields)]
	out := make(map[string]any, len(names))
	for _, k := range names {
		v := row[k]
		if s, ok := v.(string); ok && len(s) > maxSampleValue {
			cut := maxSampleValue
			for cut > 0 && !utf8.RuneStart(s[cut]) {
				cut--
			}
			v = s[:cut] + "…"
		}
		out[k] = v
	}
	return out
}

// rowTime is when a result happened: its _time, else the end of the run.
func rowTime(row search.Row, fallback time.Time) time.Time {
	switch v := row["_time"].(type) {
	case time.Time:
		return v
	case string:
		if t, err := time.Parse(time.RFC3339Nano, v); err == nil {
			return t
		}
	}
	return fallback
}

// windowFree says each result row of q depends only on its own event, so
// searching more time at once finds the same rows as several shorter
// searches would.
func windowFree(q *query.Query) bool {
	for _, c := range q.Commands {
		switch c.(type) {
		case *query.Where, *query.Table, *query.Rename, *query.Enrich, *query.Intel, *query.ThreatMatch,
			*query.Spath, *query.Rex, *query.Fillnull, *query.Lookup, *query.Regex, *query.FieldsRemove,
			*query.Convert, *query.Eval, *query.NoMV, *query.StrCat, *query.RangeMap, *query.ForEach,
			*query.FromJSON, *query.MVExpand, *query.MakeMV, *query.Sort, *query.Bin, *query.Reverse:
		default:
			return false
		}
	}
	return true
}

func formatStep(d time.Duration) string {
	switch {
	case d%(24*time.Hour) == 0:
		return fmt.Sprintf("%dd", d/(24*time.Hour))
	case d%time.Hour == 0:
		return fmt.Sprintf("%dh", d/time.Hour)
	case d%time.Minute == 0:
		return fmt.Sprintf("%dm", d/time.Minute)
	default:
		return d.String()
	}
}
