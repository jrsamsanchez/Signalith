// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package search

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/query"
)

// budgetSample is a small result with a field of each kind the commands
// read: numbers, text, multivalues, JSON, XML and key=value text.
func budgetSample() *Result {
	now := time.Now().Unix()
	var rows []Row
	for i := 0; i < 6; i++ {
		rows = append(rows, Row{
			"_time": now - int64(i*3600),
			"_raw":  fmt.Sprintf(`user=u%d action=login n=%d <e a="x"><b>t%d</b></e> {"k":%d}`, i%2, i, i, i),
			"n":     int64(i),
			"m":     float64(i) * 1.5,
			"s":     fmt.Sprintf("v%d", i%3),
			"mv":    []any{"a", fmt.Sprintf("b%d", i)},
			"j":     fmt.Sprintf(`{"k":%d,"l":[1,2],"o":{"p":"q"}}`, i),
			"x":     fmt.Sprintf(`<e a="x"><b>t%d</b></e>`, i),
			"lat":   10.0 + float64(i),
			"lon":   20.0 + float64(i),
			"dur":   float64(i + 1),
			"ip":    "10.0.0.1",
		})
	}
	return &Result{Rows: rows, Columns: []string{"_time", "_raw", "n", "m", "s", "mv", "j", "x", "lat", "lon", "dur", "ip"}}
}

// budgetContexts are, in order: a plain search; a cancelled one; one
// whose value budget is spent; one whose step budget is spent; and one
// with a few hundred bytes of value budget left.
func budgetContexts() []context.Context {
	bg := context.Background()
	cancelled, cancel := context.WithCancel(bg)
	cancel()
	with := func(ev *evaluator) context.Context {
		ev.ctx, ev.now, ev.loc = bg, time.Now(), time.UTC
		return context.WithValue(bg, evaluatorKey{}, ev)
	}
	return []context.Context{
		bg,
		cancelled,
		with(&evaluator{produced: maxEvalTotal}),
		with(&evaluator{steps: maxEvalSteps}),
		with(&evaluator{produced: maxEvalTotal - 300}),
	}
}

func budgetOutcome(err error) string {
	switch {
	case err == nil:
		return "ok"
	case errors.Is(err, context.Canceled):
		return "cancel"
	case strings.Contains(err.Error(), "eval built more than"):
		return "bytes"
	case strings.Contains(err.Error(), "evaluated more than"):
		return "steps"
	}
	return "err:" + err.Error()
}

// Each command runs on a sample result, and stops with the search's
// error when the search is cancelled or its value or step budget is
// spent, rather than running on past it.
func TestCommandsStopWithinBudget(t *testing.T) {
	for _, c := range []struct {
		cmd  string
		want [5]string
	}{
		{`where n > 1`, [5]string{"ok", "cancel", "ok", "ok", "ok"}},
		{`where like(s, "v%")`, [5]string{"ok", "cancel", "ok", "steps", "ok"}},
		{`where match(s, "v")`, [5]string{"ok", "cancel", "ok", "steps", "ok"}},
		{`sort -n`, [5]string{"ok", "ok", "ok", "ok", "ok"}},
		{`head 2`, [5]string{"ok", "ok", "ok", "ok", "ok"}},
		{`table n s`, [5]string{"ok", "ok", "ok", "ok", "ok"}},
		{`transaction s`, [5]string{"ok", "cancel", "bytes", "ok", "bytes"}},
		{`rename n as nn`, [5]string{"ok", "cancel", "ok", "ok", "ok"}},
		{`rename * as p_*`, [5]string{"ok", "cancel", "ok", "ok", "ok"}},
		{`stats count, sum(n), avg(m), dc(s), values(s), list(mv) by s`, [5]string{"ok", "ok", "bytes", "ok", "bytes"}},
		{`stats count by mv`, [5]string{"ok", "ok", "bytes", "ok", "bytes"}},
		{`top s`, [5]string{"ok", "ok", "bytes", "ok", "bytes"}},
		{`rare s`, [5]string{"ok", "ok", "bytes", "ok", "bytes"}},
		{`top s by mv`, [5]string{"ok", "ok", "bytes", "ok", "bytes"}},
		{`eval y=n*2, z=upper(s), w=mvappend(mv, "c")`, [5]string{"ok", "cancel", "bytes", "ok", "bytes"}},
		{`eval y=mvmap(mv, upper(mv))`, [5]string{"ok", "cancel", "bytes", "ok", "bytes"}},
		{`eval y=mvfilter(len(mv)>1)`, [5]string{"ok", "cancel", "err:multivalue fields hold more", "ok", "bytes"}},
		{`rex field=s "(?<d>\d)"`, [5]string{"ok", "cancel", "bytes", "steps", "bytes"}},
		{`rex field=_raw max_match=0 "(?<kv>\w+)="`, [5]string{"ok", "cancel", "bytes", "steps", "bytes"}},
		{`rex field=s mode=sed "s/v/w/g"`, [5]string{"ok", "cancel", "bytes", "steps", "ok"}},
		{`dedup s`, [5]string{"ok", "cancel", "ok", "ok", "ok"}},
		{`fillnull value=0 q`, [5]string{"ok", "ok", "bytes", "ok", "ok"}},
		{`eventstats count, avg(n) by s`, [5]string{"ok", "cancel", "bytes", "ok", "bytes"}},
		{`streamstats count, sum(n) by s`, [5]string{"ok", "cancel", "bytes", "ok", "ok"}},
		{`streamstats window=2 avg(n)`, [5]string{"ok", "cancel", "bytes", "ok", "ok"}},
		{`bin _time span=1h`, [5]string{"ok", "cancel", "bytes", "ok", "ok"}},
		{`bin n span=2`, [5]string{"ok", "cancel", "bytes", "ok", "ok"}},
		{`regex s="v1"`, [5]string{"ok", "cancel", "ok", "steps", "ok"}},
		{`fields - s`, [5]string{"ok", "cancel", "ok", "steps", "ok"}},
		{`chart count over s by n`, [5]string{"ok", "cancel", "bytes", "ok", "bytes"}},
		{`xyseries s n m`, [5]string{"ok", "cancel", "bytes", "ok", "ok"}},
		{`untable s name value`, [5]string{"ok", "cancel", "bytes", "ok", "bytes"}},
		{`spath input=j`, [5]string{"ok", "cancel", "bytes", "steps", "bytes"}},
		{`spath input=j path=o.p output=op`, [5]string{"ok", "cancel", "bytes", "steps", "bytes"}},
		{`fromjson j`, [5]string{"ok", "cancel", "bytes", "steps", "bytes"}},
		{`nomv mv`, [5]string{"ok", "cancel", "bytes", "ok", "ok"}},
		{`mvcombine mv`, [5]string{"ok", "cancel", "bytes", "ok", "bytes"}},
		{`strcat s "-" n out`, [5]string{"ok", "cancel", "bytes", "ok", "ok"}},
		{`rangemap field=n low=0-2 high=3-9`, [5]string{"ok", "cancel", "bytes", "ok", "ok"}},
		{`foreach n m [eval <<FIELD>>=<<FIELD>>*2]`, [5]string{"ok", "cancel", "bytes", "steps", "ok"}},
		{`replace v1 with w1 in s`, [5]string{"ok", "cancel", "bytes", "steps", "ok"}},
		{`xmlkv x`, [5]string{"ok", "cancel", "bytes", "steps", "bytes"}},
		{`accum n`, [5]string{"ok", "cancel", "ok", "ok", "ok"}},
		{`delta n`, [5]string{"ok", "cancel", "bytes", "ok", "bytes"}},
		{`autoregress n p=1-2`, [5]string{"ok", "cancel", "bytes", "ok", "bytes"}},
		{`fieldsummary`, [5]string{"ok", "cancel", "bytes", "steps", "bytes"}},
		{`transpose`, [5]string{"ok", "cancel", "bytes", "steps", "bytes"}},
		{`filldown s`, [5]string{"ok", "cancel", "ok", "steps", "ok"}},
		{`trendline sma2(n) ema2(m) wma2(n)`, [5]string{"ok", "cancel", "bytes", "steps", "bytes"}},
		{`concurrency duration=dur`, [5]string{"ok", "cancel", "bytes", "steps", "bytes"}},
		{`contingency s n`, [5]string{"ok", "cancel", "bytes", "steps", "bytes"}},
		{`format`, [5]string{"ok", "cancel", "bytes", "steps", "bytes"}},
		{`return 3 s`, [5]string{"ok", "cancel", "bytes", "steps", "ok"}},
		{`makecontinuous n span=1`, [5]string{"ok", "cancel", "ok", "ok", "ok"}},
		{`geostats latfield=lat longfield=lon count`, [5]string{"ok", "cancel", "bytes", "ok", "bytes"}},
		{`extract`, [5]string{"ok", "cancel", "bytes", "steps", "bytes"}},
		{`outlier n m`, [5]string{"ok", "cancel", "bytes", "ok", "ok"}},
		{`gauge n 0 5 10`, [5]string{"ok", "ok", "bytes", "ok", "bytes"}},
		{`timewrap 1h`, [5]string{"ok", "cancel", "bytes", "ok", "bytes"}},
		{`cluster field=_raw`, [5]string{"ok", "cancel", "bytes", "steps", "bytes"}},
		{`xpath field=x "//b"`, [5]string{"ok", "cancel", "bytes", "steps", "bytes"}},
		{`abstract`, [5]string{"ok", "cancel", "ok", "ok", "ok"}},
		{`anomalydetection n m`, [5]string{"ok", "cancel", "bytes", "steps", "bytes"}},
		{`anomalydetection method=zscore n`, [5]string{"ok", "cancel", "ok", "ok", "ok"}},
		{`correlate n m`, [5]string{"ok", "cancel", "bytes", "steps", "ok"}},
		{`predict n`, [5]string{"err:predict adds future rows", "cancel", "err:predict adds future rows", "err:predict adds future rows", "err:predict adds future rows"}},
		{`setfields q=1`, [5]string{"ok", "cancel", "bytes", "ok", "bytes"}},
		{`kmeans k=2 n m`, [5]string{"ok", "cancel", "bytes", "steps", "bytes"}},
		{`highlight a`, [5]string{"ok", "ok", "ok", "ok", "ok"}},
		{`mvexpand mv`, [5]string{"ok", "cancel", "bytes", "ok", "bytes"}},
		{`makemv delim="," s`, [5]string{"ok", "cancel", "err:multivalue fields hold more", "ok", "ok"}},
		{`reverse`, [5]string{"ok", "ok", "ok", "ok", "ok"}},
		{`tail 2`, [5]string{"ok", "ok", "ok", "ok", "ok"}},
		{`uniq`, [5]string{"ok", "cancel", "ok", "ok", "ok"}},
		{`convert num(s) ctime(_time)`, [5]string{"ok", "cancel", "bytes", "steps", "ok"}},
		{`addtotals n m`, [5]string{"ok", "cancel", "bytes", "steps", "ok"}},
		{`addcoltotals n m`, [5]string{"ok", "cancel", "bytes", "steps", "ok"}},
		{`eval y=sha256(_raw), z=json_object("a", n), w=printf("%s-%d", s, n)`, [5]string{"ok", "cancel", "bytes", "ok", "bytes"}},
		{`eval y=spath(j, "o.p"), z=json_keys(j), w=json_array_to_mv(spath(j, "l"))`, [5]string{"ok", "cancel", "bytes", "steps", "bytes"}},
		{`eval y=replace(_raw, "\w", "x"), z=split(_raw, " "), w=mvjoin(mv, ",")`, [5]string{"ok", "cancel", "bytes", "steps", "err:multivalue fields hold more"}},
		{`eval y=substr(_raw, 2, 5), z=urldecode("%41"), w=tostring(n, "duration")`, [5]string{"ok", "cancel", "bytes", "ok", "bytes"}},
		{`eval y=strftime(_time, "%F %T"), z=relative_time(_time, "-1d@d")`, [5]string{"ok", "cancel", "bytes", "ok", "bytes"}},
		{`eval y=mvzip(mv, mv), z=mvdedup(mv), w=mvsort(mv)`, [5]string{"ok", "cancel", "err:multivalue fields hold more", "ok", "bytes"}},
		{`eval y=mvindex(mv, 0, 1), z=mvrange(0, 5), w=mvfind(mv, "b")`, [5]string{"ok", "cancel", "bytes", "steps", "err:multivalue fields hold more"}},
		{`eval y=lower(_raw) . upper(_raw)`, [5]string{"ok", "cancel", "bytes", "ok", "bytes"}},
		{`where cidrmatch("10.0.0.0/8", ip)`, [5]string{"ok", "cancel", "ok", "ok", "ok"}},
		{`where s IN ("v1", "v2")`, [5]string{"ok", "cancel", "ok", "ok", "ok"}},
		{`where NOT n=1 OR m>2`, [5]string{"ok", "cancel", "ok", "ok", "ok"}},
		{`sort _time | predict n`, [5]string{"ok", "cancel", "bytes", "steps", "bytes"}},
		{`sort _time | predict n future_timespan=0`, [5]string{"ok", "cancel", "bytes", "steps", "bytes"}},
		{`sort _time | predict n algorithm=LLT`, [5]string{"ok", "cancel", "bytes", "steps", "bytes"}},
		{`sort _time | predict n algorithm=LLP period=2`, [5]string{"ok", "cancel", "bytes", "steps", "bytes"}},
		{`sort _time | predict n algorithm=LLP5`, [5]string{"ok", "cancel", "bytes", "steps", "bytes"}},
		{`predict n future_timespan=0`, [5]string{"ok", "cancel", "bytes", "steps", "bytes"}},
		{`timewrap 1h series=short`, [5]string{"ok", "cancel", "bytes", "ok", "bytes"}},
		{`timewrap 1h align=now`, [5]string{"ok", "cancel", "bytes", "ok", "bytes"}},
		{`timewrap 1d`, [5]string{"ok", "cancel", "bytes", "ok", "bytes"}},
		{`cluster showcount=t labelonly=t`, [5]string{"ok", "cancel", "bytes", "steps", "bytes"}},
		{`cluster match=ngramset`, [5]string{"ok", "cancel", "bytes", "steps", "bytes"}},
		{`cluster match=termset t=0.5`, [5]string{"ok", "cancel", "bytes", "steps", "bytes"}},
		{`kmeans k=3 dt=l1 n`, [5]string{"ok", "cancel", "bytes", "steps", "bytes"}},
		{`kmeans dt=cos n m`, [5]string{"ok", "cancel", "bytes", "steps", "bytes"}},
		{`kmeans`, [5]string{"ok", "cancel", "bytes", "steps", "bytes"}},
		{`extract pairdelim=" " kvdelim="="`, [5]string{"ok", "cancel", "bytes", "steps", "bytes"}},
		{`spath`, [5]string{"ok", "cancel", "ok", "steps", "ok"}},
		{`spath input=_raw`, [5]string{"ok", "cancel", "ok", "steps", "ok"}},
		{`fromjson j prefix=p_`, [5]string{"ok", "cancel", "bytes", "steps", "bytes"}},
		{`outlier action=remove n`, [5]string{"ok", "cancel", "bytes", "ok", "ok"}},
		{`outlier mark=t uselower=t n`, [5]string{"ok", "cancel", "bytes", "ok", "ok"}},
		{`outlier`, [5]string{"ok", "cancel", "bytes", "ok", "ok"}},
		{`anomalydetection action=summary n`, [5]string{"ok", "cancel", "bytes", "steps", "bytes"}},
		{`anomalydetection action=annotate method=zscore n`, [5]string{"ok", "cancel", "bytes", "ok", "bytes"}},
		{`anomalydetection`, [5]string{"ok", "cancel", "bytes", "steps", "bytes"}},
		{`gauge 5`, [5]string{"ok", "ok", "bytes", "ok", "ok"}},
		{`format maxresults=2 mvsep="|"`, [5]string{"ok", "cancel", "bytes", "steps", "bytes"}},
		{`format "(" "(" "AND" ")" "OR" ")"`, [5]string{"ok", "cancel", "bytes", "steps", "bytes"}},
		{`contingency usetotal=f maxrows=1 maxcols=1 s n`, [5]string{"ok", "cancel", "bytes", "steps", "bytes"}},
		{`transpose 2 header_field=s`, [5]string{"ok", "cancel", "bytes", "steps", "bytes"}},
		{`fieldsummary maxvals=1 n s`, [5]string{"ok", "cancel", "bytes", "steps", "bytes"}},
		{`return $s`, [5]string{"ok", "cancel", "bytes", "steps", "ok"}},
		{`return 2 a=s`, [5]string{"ok", "cancel", "bytes", "steps", "ok"}},
		{`makecontinuous _time span=1h`, [5]string{"ok", "cancel", "ok", "ok", "ok"}},
		{`autoregress m p=2`, [5]string{"ok", "cancel", "bytes", "ok", "bytes"}},
		{`trendline ema3(m)`, [5]string{"ok", "cancel", "bytes", "steps", "bytes"}},
		{`concurrency duration=dur start=_time output=c`, [5]string{"ok", "cancel", "bytes", "steps", "bytes"}},
		{`strcat allrequired=t s q out`, [5]string{"ok", "cancel", "ok", "ok", "ok"}},
		{`rangemap field=m low=0-1 default=x`, [5]string{"ok", "cancel", "bytes", "ok", "ok"}},
		{`correlate`, [5]string{"ok", "cancel", "bytes", "steps", "bytes"}},
		{`xpath field=_raw "//b/@a" default=none`, [5]string{"ok", "cancel", "bytes", "steps", "bytes"}},
		{`xpath field=x "/e/@a" outfield=o`, [5]string{"ok", "cancel", "bytes", "steps", "bytes"}},
		{`xmlkv`, [5]string{"ok", "cancel", "bytes", "steps", "bytes"}},
		{`mvexpand mv limit=1`, [5]string{"ok", "cancel", "bytes", "ok", "bytes"}},
		{`eventstats dc(s) as d, values(mv) as v`, [5]string{"ok", "cancel", "bytes", "ok", "bytes"}},
		{`streamstats current=f window=1 last(n) as p`, [5]string{"ok", "cancel", "bytes", "ok", "ok"}},
		{`dedup 2 s sortby -n`, [5]string{"ok", "cancel", "ok", "ok", "ok"}},
		{`sort - s, +n`, [5]string{"ok", "ok", "ok", "ok", "ok"}},
		{`fillnull value=x`, [5]string{"ok", "ok", "ok", "ok", "ok"}},
		{`convert dur2sec(dur) memk(n) rmunit(s) rmcomma(s) mktime(s) auto(s) num(mv)`, [5]string{"ok", "cancel", "ok", "steps", "ok"}},
		{`addtotals fieldname=t label=L labelfield=s`, [5]string{"ok", "cancel", "bytes", "steps", "ok"}},
		{`transaction s maxspan=1h maxpause=30m maxevents=2`, [5]string{"ok", "cancel", "bytes", "ok", "bytes"}},
		{`transaction s startswith="login" endswith=(n>3)`, [5]string{"ok", "cancel", "bytes", "ok", "bytes"}},
		{`chart avg(n) over s`, [5]string{"ok", "ok", "bytes", "ok", "bytes"}},
		{`chart count by s`, [5]string{"ok", "ok", "bytes", "ok", "bytes"}},
		{`untable s nm vl`, [5]string{"ok", "cancel", "bytes", "ok", "bytes"}},
		{`eval y=case(n>3, "hi", n>1, "mid", true(), "lo")`, [5]string{"ok", "cancel", "bytes", "ok", "bytes"}},
		{`eval y=coalesce(q, s), z=if(isnull(q), 1, 0), w=nullif(s, "v1")`, [5]string{"ok", "cancel", "bytes", "ok", "bytes"}},
		{`eval y=tonumber(tostring(n)), z=round(m, 1), w=n % 2`, [5]string{"ok", "cancel", "bytes", "ok", "bytes"}},
	} {
		q, err := query.Parse("* | " + c.cmd)
		if err != nil {
			t.Errorf("%s: %v", c.cmd, err)
			continue
		}
		for i, ctx := range budgetContexts() {
			res := budgetSample()
			var err error
			for _, cmd := range q.Commands {
				if err = applyCommand(ctx, res, cmd); err != nil {
					break
				}
			}
			got, want := budgetOutcome(err), c.want[i]
			if strings.HasPrefix(want, "err:") && strings.HasPrefix(got, "err:") && strings.Contains(got, want[4:]) {
				continue
			}
			if got != want {
				t.Errorf("%s in context %d: %s, want %s", c.cmd, i, got, want)
			}
		}
	}
}
