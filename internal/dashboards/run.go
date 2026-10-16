package dashboards

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"sync"
	"time"

	"github.com/jrsamsanchez/signalith/internal/query"
	"github.com/jrsamsanchez/signalith/internal/search"
)

// Executor runs parsed queries; *search.Engine implements it.
type Executor interface {
	Execute(ctx context.Context, q *query.Query) (*search.Result, error)
}

// DefaultConcurrency is how many panels run at once, so a large dashboard
// cannot flood OpenSearch.
const DefaultConcurrency = 4

// Runner runs dashboard panels.
type Runner struct {
	Engine Executor
	// Concurrency caps panels running at once (default 4).
	Concurrency int
	// Timeout caps one panel (default 60s).
	Timeout time.Duration
	// MaxRows caps the rows a panel returns to the browser (default 500).
	MaxRows int
}

// PanelResult is one panel's output. A failing panel has Error set and
// never affects the others.
type PanelResult struct {
	Index  int            `json:"index"`
	Result *search.Result `json:"result,omitempty"`
	// Value and Previous are set for single values.
	Value    any    `json:"value,omitempty"`
	Previous any    `json:"previous,omitempty"`
	Field    string `json:"field,omitempty"`
	Error    string `json:"error,omitempty"`
	// CompareNote says why a comparison could not be made.
	CompareNote string `json:"compare_note,omitempty"`
	// Earliest is the time range the panel searched, for Open in Search.
	Earliest string `json:"earliest,omitempty"`
	// Drill finds the events behind a number the panel shows.
	Drill *query.Drill `json:"drill,omitempty"`
}

// Run runs panels in parallel over a time range such as "24h" (empty or
// "0" for all time) and returns results in panel order.
func (r *Runner) Run(ctx context.Context, panels []Panel, timeRange string) []PanelResult {
	n := r.Concurrency
	if n <= 0 {
		n = DefaultConcurrency
	}
	out := make([]PanelResult, len(panels))
	sem := make(chan struct{}, n)
	var wg sync.WaitGroup
	for i, p := range panels {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			out[i] = r.RunPanel(ctx, p, timeRange)
			out[i].Index = i
		}()
	}
	wg.Wait()
	return out
}

// RunPanel runs one panel. Errors, including panics, end up in the result.
func (r *Runner) RunPanel(ctx context.Context, p Panel, timeRange string) (res PanelResult) {
	defer func() {
		if v := recover(); v != nil {
			res = PanelResult{Error: fmt.Sprintf("panel failed: %v", v)}
		}
	}()
	q, err := query.Parse(p.Query)
	if err != nil {
		return PanelResult{Error: queryErr(err)}
	}
	earliest := q.Earliest
	if earliest == "" {
		earliest = relative(timeRange)
		q.Earliest = earliest
	}
	res.Earliest = earliest
	res.Drill = q.Drilldown()
	timeout := r.Timeout
	if timeout <= 0 {
		timeout = time.Minute
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cur, err := r.Engine.Execute(cctx, q)
	if err != nil {
		res.Error = runErr(err)
		return res
	}
	max := r.MaxRows
	if max <= 0 {
		max = 500
	}
	if p.Viz == VizSingle {
		res.Field, res.Value = SingleValue(cur, p.Field)
		if p.Compare {
			res.Previous, res.CompareNote = r.previous(cctx, q, earliest, p.Field)
		}
	}
	if len(cur.Rows) > max {
		cur.Rows = cur.Rows[:max]
		cur.Truncated = true
	}
	res.Result = cur
	return res
}

// previous runs the query again over the period just before this one.
func (r *Runner) previous(ctx context.Context, q *query.Query, earliest, field string) (any, string) {
	if q.Latest != "" {
		return nil, "no comparison: the query sets latest="
	}
	prevEarliest, prevLatest, ok := PreviousPeriod(earliest)
	if !ok {
		return nil, "no comparison: needs a relative time range such as 24h"
	}
	pq := *q
	pq.Earliest, pq.Latest = prevEarliest, prevLatest
	prev, err := r.Engine.Execute(ctx, &pq)
	if err != nil {
		return nil, "previous period failed: " + runErr(err)
	}
	_, v := SingleValue(prev, field)
	if v == nil {
		v = int64(0)
	}
	return v, ""
}

func runErr(err error) string {
	if errors.Is(err, context.DeadlineExceeded) {
		return "timed out; try a shorter time range or a narrower search"
	}
	return queryErr(err)
}

var relPattern = regexp.MustCompile(`^-?(\d+)(s|m|h|d|w)$`)

// relative turns "24h" into the search time "-24h"; "" and "0" mean all
// time.
func relative(timeRange string) string {
	if timeRange == "" || timeRange == "0" {
		return "0"
	}
	if timeRange[0] == '-' {
		return timeRange
	}
	return "-" + timeRange
}

// PreviousPeriod returns the earliest and latest of the period of the same
// length just before a relative range: -24h gives -48h to -24h.
func PreviousPeriod(earliest string) (string, string, bool) {
	m := relPattern.FindStringSubmatch(earliest)
	if m == nil || earliest[0] != '-' {
		return "", "", false
	}
	n, err := strconv.Atoi(m[1])
	if err != nil || n == 0 {
		return "", "", false
	}
	return fmt.Sprintf("-%d%s", 2*n, m[2]), earliest, true
}

// SingleValue picks the number a single-value panel shows: the named
// column of the first row, or else its first numeric column. Rows with
// no numbers show the row count.
func SingleValue(res *search.Result, field string) (string, any) {
	if res == nil {
		return field, nil
	}
	if res.Kind == "events" && field == "" {
		// A plain search counts matching events.
		return "events", res.Matched
	}
	if len(res.Rows) == 0 {
		if field == "" {
			field = "count"
		}
		return field, int64(0)
	}
	row := res.Rows[0]
	if field != "" {
		return field, row[field]
	}
	for _, c := range res.Columns {
		if _, ok := toFloat(row[c]); ok {
			return c, row[c]
		}
	}
	if len(res.Rows) == 1 && len(res.Columns) > 0 {
		// One row and no number, such as a metric with no data: show it.
		return res.Columns[0], row[res.Columns[0]]
	}
	return "rows", int64(len(res.Rows))
}

func toFloat(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case int64:
		return float64(n), true
	case int:
		return float64(n), true
	}
	return 0, false
}
