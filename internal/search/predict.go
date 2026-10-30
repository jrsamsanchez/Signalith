// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package search

import (
	"context"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/jrsamsanchez/signalith/internal/query"
)

// setSearch runs set's two subsearches and keeps, by c.Op, the distinct
// rows of either, of only one, or of both. Rows are the same when they
// have the same fields with the same values.
func (e *Engine) setSearch(ctx context.Context, c *query.Set, outer *query.Query) (*Result, error) {
	ev := evaluatorFor(ctx)
	var subs [2]*Result
	for i, s := range c.Subs {
		sq := subsearch(s, outer)
		sq, err := e.resolveSubsearches(ctx, sq)
		if err != nil {
			return nil, err
		}
		p, err := e.compileSub(sq)
		if err != nil {
			return nil, err
		}
		if subs[i], err = e.run(ctx, sq, p); err != nil {
			return nil, err
		}
	}
	var keys [2][]string
	var in [2]map[string]bool
	// Rows with the same key share one string, charged once, so many
	// identical rows hold no more than one copy of their key.
	canon := map[string]string{}
	for i, sub := range subs {
		in[i] = map[string]bool{}
		for j, r := range sub.Rows {
			if j%checkEvery == 0 && ctx.Err() != nil {
				return nil, ctx.Err()
			}
			k, ok := rowKey(ev, r)
			if !ok {
				return nil, ev.err
			}
			if c, seen := canon[k]; seen {
				k = c
			} else {
				if !ev.charge(len(k) + fieldOverhead) {
					return nil, ev.err
				}
				canon[k] = k
			}
			in[i][k] = true
			keys[i] = append(keys[i], k)
		}
	}
	res := &Result{Kind: subs[0].Kind, Truncated: subs[0].Truncated || subs[1].Truncated, Matched: subs[0].Matched + subs[1].Matched}
	noteSampled(res, subs[0])
	noteSampled(res, subs[1])
	seen := map[string]bool{}
	for i, sub := range subs {
		if i == 1 && c.Op == "intersect" {
			break
		}
		var rows []Row
		for j, r := range sub.Rows {
			k := keys[i][j]
			if seen[k] {
				continue
			}
			other := in[1-i][k]
			if c.Op == "diff" && other || c.Op == "intersect" && !other {
				continue
			}
			seen[k] = true
			rows = append(rows, r)
		}
		appendRows(res, rows, sub.Columns, sub.Kind)
	}
	return res, nil
}

// rowKey writes r's fields and values as one text, the same for rows with
// the same fields and values in any order.
func rowKey(ev *evaluator, r Row) (string, bool) {
	var names []string
	for f := range r {
		if !strings.HasPrefix(f, "\x00") {
			names = append(names, f)
		}
	}
	sort.Strings(names)
	var b strings.Builder
	for _, f := range names {
		valueKey(&b, f)
		valueKey(&b, r[f])
	}
	// Writing a long row's key costs more than a step.
	return b.String(), ev.stepN(1 + b.Len()/16)
}

// applySetFields sets each of c's fields to its value on every row.
func applySetFields(ctx context.Context, res *Result, c *query.SetFields) error {
	ev := evaluatorFor(ctx)
	for i, r := range res.Rows {
		if i%checkEvery == 0 && ctx.Err() != nil {
			return ctx.Err()
		}
		for _, v := range c.Values {
			if !ev.newField(r, v.Field) || !ev.charge(len(v.Value)) {
				return ev.err
			}
			r[v.Field] = v.Value
		}
	}
	for _, v := range c.Values {
		addColumn(res, v.Field)
	}
	return nil
}

// maxPredictPeriodSearch bounds the season lengths predict tries when
// period= is not given.
const maxPredictPeriodSearch = 1000

// forecaster is an exponential smoothing model: a level, with LLT a trend
// and with a period a season, each moved toward each new value by its own
// share of the error.
type forecaster struct {
	alpha, beta, gamma float64
	trend              bool
	period             int

	level, slope float64
	season       []float64
	t            int
}

// start sets the model's first level, slope and season from ys, which
// holds at least two periods of numbers when it has a season.
func (m *forecaster) start(ys []float64) {
	m.level, m.slope, m.season, m.t = ys[0], 0, nil, 0
	if m.period == 0 {
		return
	}
	p := m.period
	first, second := 0.0, 0.0
	for i := range p {
		first += ys[i]
		second += ys[p+i]
	}
	first, second = first/float64(p), second/float64(p)
	m.level = first
	if m.trend {
		m.slope = (second - first) / float64(p)
	}
	for i := range p {
		m.season = append(m.season, ys[i]-first)
	}
}

// forecast is the model's value h steps after its last update.
func (m *forecaster) forecast(h int) float64 {
	f := m.level
	if m.trend {
		f += float64(h) * m.slope
	}
	if m.period > 0 {
		f += m.season[(m.t+h-1)%m.period]
	}
	return f
}

// update moves the model past the next value: y, or with ok false a
// missing one, which leaves the model where its forecast was.
func (m *forecaster) update(y float64, ok bool) float64 {
	f := m.forecast(1)
	e := 0.0
	if ok {
		e = y - f
	}
	var s float64
	if m.period > 0 {
		s = m.season[m.t%m.period]
	}
	level := m.level + m.slope + m.alpha*e
	if m.trend {
		m.slope += m.alpha * m.beta * e
	}
	if m.period > 0 {
		m.season[m.t%m.period] = s + m.gamma*(1-m.alpha)*e
	}
	m.level = level
	m.t++
	return e
}

// predictModel picks the smoothing shares that best forecast ys one step
// ahead, trying a grid of them, and returns the model trained on ys with
// the standard deviation of its one-step errors.
func predictModel(ev *evaluator, ys []float64, has []bool, trend bool, period int) (*forecaster, float64, bool) {
	alphas := []float64{0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9}
	betas := []float64{0}
	if trend {
		betas = []float64{0.01, 0.05, 0.1, 0.2, 0.4}
	}
	gammas := []float64{0}
	if period > 0 {
		gammas = []float64{0.05, 0.1, 0.2, 0.4}
	}
	// The model starts from the first value, or the first two periods;
	// a missing value there counts as the mean.
	fill := fillMissing(ys, has)
	warm := max(1, period)
	best, bestSSE := forecaster{}, math.Inf(1)
	for _, a := range alphas {
		for _, b := range betas {
			for _, g := range gammas {
				if !ev.stepN(len(ys)) {
					return nil, 0, false
				}
				m := forecaster{alpha: a, beta: b, gamma: g, trend: trend, period: period}
				m.start(fill)
				sse := 0.0
				for i, y := range ys {
					e := m.update(y, has[i])
					if i >= warm && has[i] {
						sse += e * e
					}
				}
				if finite(sse) && sse < bestSSE {
					best, bestSSE = forecaster{alpha: a, beta: b, gamma: g, trend: trend, period: period}, sse
				}
			}
		}
	}
	if math.IsInf(bestSSE, 1) {
		return nil, 0, true
	}
	n := 0
	for i := warm; i < len(ys); i++ {
		if has[i] {
			n++
		}
	}
	sigma := 0.0
	if n > 0 {
		sigma = math.Sqrt(bestSSE / float64(n))
	}
	best.start(fill)
	return &best, sigma, true
}

// fillMissing returns ys with missing values set to the mean of the rest.
func fillMissing(ys []float64, has []bool) []float64 {
	sum, n := 0.0, 0
	for i, y := range ys {
		if has[i] {
			sum += y
			n++
		}
	}
	mean := 0.0
	if n > 0 {
		mean = sum / float64(n)
	}
	var out []float64
	for i, y := range ys {
		if !has[i] {
			y = mean
		}
		out = append(out, y)
	}
	return out
}

// findPeriod returns the season length with the strongest
// autocorrelation in ys, or 0 when none is clear.
func findPeriod(ev *evaluator, ys []float64) (int, bool) {
	n := len(ys)
	mean := 0.0
	for _, y := range ys {
		mean += y
	}
	mean /= float64(n)
	variance := 0.0
	for _, y := range ys {
		variance += (y - mean) * (y - mean)
	}
	if variance == 0 || !finite(variance) {
		return 0, true
	}
	best, bestR := 0, 0.3
	for lag := 2; lag <= min(n/2, maxPredictPeriodSearch); lag++ {
		if !ev.stepN(n - lag) {
			return 0, false
		}
		r := 0.0
		for i := lag; i < n; i++ {
			r += (ys[i] - mean) * (ys[i-lag] - mean)
		}
		if r /= variance; r > bestR {
			best, bestR = lag, r
		}
	}
	return best, true
}

// applyPredict forecasts each of c's fields over the rows in order: each
// row gets the model's one-step forecast and its confidence bounds, the
// last c.Holdback rows are left out of the model, and rows are added past
// the end for forecasts beyond them.
func applyPredict(ctx context.Context, res *Result, c *query.Predict) error {
	ev := evaluatorFor(ctx)
	n := len(res.Rows)
	train := n - c.Holdback
	if train < 2 {
		return &QueryError{Msg: "predict needs at least two rows to learn from, after holdback"}
	}
	extra := max(0, c.FutureTimespan-c.Holdback)
	var times []any
	if extra > 0 {
		var err error
		if times, err = futureTimes(ctx, res, extra); err != nil {
			return err
		}
	}
	if !ev.charge((n + extra) * 64 * len(c.Fields)) {
		return ev.err
	}
	zUp := math.Sqrt2 * math.Erfinv(float64(c.Upper)/100)
	zLo := math.Sqrt2 * math.Erfinv(float64(c.Lower)/100)
	type forecast struct{ pred, up, lo []any }
	var outs []forecast
	for _, f := range c.Fields {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		var ys []float64
		var has []bool
		nums := 0
		if !ev.stepN(train) {
			return ev.err
		}
		for _, r := range res.Rows[:train] {
			x, ok := evNum(r[f.Field])
			ok = ok && finite(x)
			if !ok {
				x = 0
			} else {
				nums++
			}
			ys, has = append(ys, x), append(has, ok)
		}
		if nums < 2 {
			return &QueryError{Msg: fmt.Sprintf("predict needs at least two numbers in %s to learn from", f.Field)}
		}
		period := 0
		if c.Algorithm == "LLP" || c.Algorithm == "LLP5" {
			period = c.Period
			if period == 0 {
				var ok bool
				if period, ok = findPeriod(ev, fillMissing(ys, has)); !ok {
					return ev.err
				}
			}
			if period > 0 && train < 2*period {
				if c.Period > 0 {
					return &QueryError{Msg: fmt.Sprintf("predict period=%d needs at least %d rows to learn from", period, 2*period)}
				}
				period = 0
			}
		}
		trend := c.Algorithm == "LLT" || c.Algorithm == "LLP5"
		m, sigma, ok := predictModel(ev, ys, has, trend, period)
		if !ok {
			return ev.err
		}
		var out forecast
		emit := func(v, s float64) {
			if m == nil || !finite(v) {
				out.pred, out.up, out.lo = append(out.pred, nil), append(out.up, nil), append(out.lo, nil)
				return
			}
			out.pred = append(out.pred, numOut(v))
			out.up = append(out.up, numOut(v+zUp*s))
			out.lo = append(out.lo, numOut(v-zLo*s))
		}
		for i := range train {
			if m == nil {
				emit(0, 0)
				continue
			}
			emit(m.forecast(1), sigma)
			m.update(ys[i], has[i])
		}
		for h := 1; h <= c.Holdback+extra; h++ {
			if m == nil {
				emit(0, 0)
				continue
			}
			emit(m.forecast(h), sigma*math.Sqrt(float64(h)))
		}
		outs = append(outs, out)
	}
	for k := range extra {
		if !ev.charge(valueSize(times[k]) + fieldOverhead) {
			return ev.err
		}
		res.Rows = append(res.Rows, Row{"_time": times[k]})
	}
	for j, f := range c.Fields {
		name := f.PredictName()
		up, lo := c.BoundNames(f)
		for i, r := range res.Rows {
			if i%checkEvery == 0 && ctx.Err() != nil {
				return ctx.Err()
			}
			if outs[j].pred[i] == nil {
				continue
			}
			for _, w := range []struct {
				name string
				v    any
			}{{name, outs[j].pred[i]}, {up, outs[j].up[i]}, {lo, outs[j].lo[i]}} {
				if !ev.newField(r, w.name) {
					return ev.err
				}
				r[w.name] = w.v
			}
		}
		addColumn(res, name)
		addColumn(res, up)
		addColumn(res, lo)
	}
	return nil
}

// futureTimes returns the times of n rows after the last, a span apart:
// the shortest step between rows in time order. A row's time keeps the
// form the last row's has.
func futureTimes(ctx context.Context, res *Result, n int) ([]any, error) {
	var last time.Time
	var span int64
	have := false
	for i, r := range res.Rows {
		if i%checkEvery == 0 && ctx.Err() != nil {
			return nil, ctx.Err()
		}
		t, ok := toTime(r["_time"])
		if !ok {
			continue
		}
		if have {
			if d := t.Unix() - last.Unix(); d > 0 && (span == 0 || d < span) {
				span = d
			}
		}
		last, have = t, true
	}
	if span == 0 {
		return nil, &QueryError{Msg: "predict adds future rows only to rows with _time in order, such as a timechart's; use future_timespan=0 for other rows"}
	}
	_, text := res.Rows[len(res.Rows)-1]["_time"].(string)
	var out []any
	for k := 1; k <= n; k++ {
		at := last.Unix() + int64(k)*span
		if text {
			out = append(out, time.Unix(at, 0).UTC().Format(time.RFC3339))
		} else {
			out = append(out, at)
		}
	}
	return out, nil
}
