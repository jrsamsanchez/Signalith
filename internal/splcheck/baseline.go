package splcheck

import (
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jrsamsanchez/signalith/internal/query"
	"github.com/jrsamsanchez/signalith/internal/sigmacheck"
)

// Outlier rules count events by group and keep a group whose count
// stands out from the others' (above their average by some standard
// deviations): stats ... by _time, src, then eventstats avg(n), stdev(n)
// by _time and where n >= avg + 3 * stdev. Splunk compares the groups of
// its whole search, by default the hour that ended 10 minutes before
// each hourly run, so a comparison over the whole search depends on that
// window and is left out. One within each time bucket (bucket span=10m
// _time before the stats, eventstats ... by _time) does not, as long as
// each bucket is whole: Splunk's hourly windows start and end on ten
// minutes, so a bucket of a span that divides ten minutes is whole in
// one of them, and the detection keeps a bucket's rows only from a run
// whose window holds the whole bucket (PostCompared).

// windowCompare is why a comparison of counts over the whole search is
// left out.
const windowCompare = "a later eventstats across the whole search depends on Splunk's search window"

// windowStages are the later stages whose rows depend on the other rows
// of the search: Splunk runs them over its whole search window.
var windowStages = map[string]bool{
	"eventstats": true, "streamstats": true, "anomalydetection": true, "outlier": true, "predict": true,
	"trendline": true, "delta": true, "accum": true, "autoregress": true,
}

// splunkWindowStep is how far apart the edges of Splunk's default search
// windows are: each hourly run searches from 70 to 10 minutes before it.
const splunkWindowStep = 10 * time.Minute

// compareStages checks later stages that compare the groups of a count
// with each other (an eventstats after a stats), returning the span of
// the time buckets they compare within, or 0 when no stage compares
// counts.
func compareStages(cmds []query.Command) (time.Duration, error) {
	stats := -1
	compare := -1
	for i, c := range cmds {
		switch c.(type) {
		case *query.Stats:
			if compare < 0 {
				stats = i
			}
		case *query.EventStats:
			if stats >= 0 && compare < 0 {
				compare = i
			}
		}
	}
	// Other stages that compare rows with each other (a running count,
	// an anomaly or outlier model, an eventstats of the events) read the
	// whole search too. Only an eventstats after the stats may compare
	// within each bucket (checked below).
	for i, c := range cmds {
		if windowStages[c.Name()] && (compare < 0 || i < stats || c.Name() != "eventstats") {
			return 0, fmt.Errorf("a later %s across the whole search depends on Splunk's search window", c.Name())
		}
	}
	if compare < 0 {
		return 0, nil
	}
	var span time.Duration
	for _, c := range cmds[:stats] {
		switch c := c.(type) {
		case *query.Bin:
			if c.Field == "_time" && c.As == "" {
				if s, _, err := query.BinSpan(c.Span); err == nil && s > 0 {
					span = time.Duration(s) * time.Second
				}
			}
		case *query.Stats, *query.EventStats:
			return 0, fmt.Errorf("%s", windowCompare)
		}
	}
	st := cmds[stats].(*query.Stats)
	if span == 0 || !slices.Contains(st.By, "_time") {
		return 0, fmt.Errorf("%s", windowCompare)
	}
	if splunkWindowStep%span != 0 {
		return 0, fmt.Errorf("counts compared within time buckets of %s depend on Splunk's search window, which cuts them in parts", span)
	}
	counts := map[string]bool{}
	for _, a := range st.Aggs {
		counts[a.Column()] = a.Func == "count" || a.Func == "dc"
	}
	for _, c := range cmds[stats+1:] {
		text := query.CommandString(c)
		switch c := c.(type) {
		case *query.EventStats:
			if !slices.Contains(c.By, "_time") {
				return 0, fmt.Errorf("%s", windowCompare)
			}
			for _, a := range c.Aggs {
				if a.Func != "avg" && a.Func != "stdev" && a.Func != "var" || !counts[a.Field] {
					return 0, fmt.Errorf("a later eventstats of %s in a comparison of counts is not supported", a.Column())
				}
			}
			continue
		case *query.Eval, *query.Where, *query.Rename, *query.Fillnull:
		default:
			return 0, fmt.Errorf("a later %s after counts compared within each time bucket is not supported", c.Name())
		}
		if strings.Contains(text, "_time") {
			return 0, fmt.Errorf("a later stage that reads _time after counts compared within each time bucket is not supported: %s", firstWords(text))
		}
	}
	return span, nil
}

// stdevFix returns, for a later eventstats that takes the standard
// deviation (or variance) of a count an earlier stats made, the eval
// that makes it 0 for a group of one row, as Splunk's is ("" for none);
// Signalith's is null for one value. A row of the stats always has its
// count, so a null is one row's. counts are the count columns of the
// latest stats, which a stats stage resets.
func stdevFix(stage string, counts map[string]bool) string {
	q, err := query.Parse("* | " + stage)
	if err != nil || len(q.Commands) != 1 {
		return ""
	}
	switch c := q.Commands[0].(type) {
	case *query.Stats:
		clear(counts)
		for _, a := range c.Aggs {
			counts[a.Column()] = a.Func == "count" || a.Func == "dc"
		}
	case *query.EventStats:
		var fix []string
		for _, a := range c.Aggs {
			if (a.Func == "stdev" || a.Func == "var") && counts[a.Field] {
				f := quoteField(a.Column())
				fix = append(fix, f+"=coalesce("+f+", 0)")
			}
		}
		if len(fix) > 0 {
			return "eval " + strings.Join(fix, ", ")
		}
	}
	return ""
}

// baselineGroups are how many other groups a baseline is tried with,
// fewest first. With the sample standard deviation, one group of n
// stands out from the others by at most (n-1)/√n standard deviations, so
// three of them need ten others.
var baselineGroups = []int{1, 2, 3, 5, 10, 15, 20, 30}

// baselines returns, for a rule whose later stages compare counts
// (PostCompared) and a repeated case b they keep on its own, the same
// case with a baseline that it still stands out from (other groups at
// the same time, one event each), and baselines it does not stand out
// from: one of the other groups as high as the case's, and the next
// fewer other groups tried. The groups differ in one field of the event, the first
// whose other values the rule reads and counts apart.
func (r *Rule) baselines(b sigmacheck.Case) []sigmacheck.Case {
	if !r.PostCompared || !b.Expect || b.Repeat <= 1 {
		return nil
	}
	for _, k := range slices.Sorted(maps.Keys(b.Data)) {
		if slices.Contains(b.Vary, k) {
			continue
		}
		other := func(i int) sigmacheck.Case {
			o := b
			o.Expect, o.Repeat, o.Vary, o.Baseline = false, 0, nil, nil
			o.Data = maps.Clone(b.Data)
			o.Data[k] = otherValueN(b.Data[k], i)
			return o
		}
		if !reads(r, other(1)) {
			continue
		}
		groups := func(n int) []sigmacheck.Case {
			out := make([]sigmacheck.Case, n)
			for i := range out {
				out[i] = other(i + 1)
			}
			return out
		}
		for j, n := range baselineGroups {
			pos := b
			pos.Baseline = groups(n)
			if rows, err := r.runPost(storedAll(pos)); err != nil || len(rows) != 1 {
				continue
			}
			// Another group as high as the case's: neither stands out.
			twin := pos
			twin.Baseline = groups(n)
			twin.Baseline[0].Repeat, twin.Baseline[0].Vary = b.Repeat, b.Vary
			if r.KeepsAll(storedAll(twin)) {
				continue
			}
			twin.Expect = false
			out := []sigmacheck.Case{pos, twin}
			if j > 0 {
				fewer := pos
				fewer.Baseline = groups(baselineGroups[j-1])
				if !r.KeepsAll(storedAll(fewer)) {
					fewer.Expect = false
					out = append(out, fewer)
				}
			}
			return out
		}
	}
	return nil
}

// otherValueN is the i-th other value of an event's field: another
// documentation address for an address, else the value numbered.
func otherValueN(v string, i int) string {
	if a, err := netip.ParseAddr(v); err == nil && a.Is4() {
		o := "198.51.100." + strconv.Itoa(i)
		if o == v {
			o = "198.51.100." + strconv.Itoa(200+i)
		}
		return o
	}
	return v + "-other" + strconv.Itoa(i)
}

// storedAll is StoredAll without the model.
func storedAll(c sigmacheck.Case) []map[string]any {
	docs, _ := StoredAll(c)
	return docs
}

// StoredAll is StoredCopies with the case's baseline events, which
// happen at the same time.
func StoredAll(c sigmacheck.Case) ([]map[string]any, string) {
	docs, model := StoredCopies(c)
	for _, b := range c.Baseline {
		more, _ := StoredCopies(b)
		docs = append(docs, more...)
	}
	return docs, model
}
