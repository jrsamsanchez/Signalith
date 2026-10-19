// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package query

import (
	"reflect"
	"slices"
	"testing"
)

// roundTripCommands are one or more forms of each command, with their
// options.
var roundTripCommands = []string{
	`eval c=n+1, d=if(a="x", 1, 0)`,
	`anomalydetection n`,
	`anomalydetection method=zscore action=filter n m`,
	`correlate`,
	`append [search b=1 | head 2]`,
	`appendpipe [stats count]`,
	`xyseries a b n`,
	`untable a name value`,
	`fromjson j`,
	`fromjson j prefix=p_`,
	`extract`,
	`extract pairdelim=";" kvdelim=":"`,
	`kvform`,
	`nomv mv`,
	`mvcombine b`,
	`mvcombine delim="," b`,
	`strcat a " " b c`,
	`strcat allrequired=t a b c`,
	`rangemap field=n low=0-1 high=2-9 default=other`,
	`foreach n m [eval <<FIELD>>=<<FIELD>>*2]`,
	`kmeans k=2 x y`,
	`mvexpand mv`,
	`mvexpand mv limit=5`,
	`makemv delim=" " a`,
	`makemv tokenizer="(\w+)" allowempty=t a`,
	`addtotals`,
	`addtotals row=f col=t labelfield=l label=Sum n m`,
	`addcoltotals n`,
	`uniq`,
	`convert num(n) ctime(t) as tt`,
	`convert timeformat="%Y" ctime(t)`,
	`setfields z=1, w=two`,
	`xmlkv xml`,
	`xmlkv`,
	`trendline sma2(n) as s ema3(m)`,
	`accum n`,
	`accum n as total`,
	`delta n`,
	`delta n as d p=2`,
	`autoregress n p=2-3`,
	`autoregress n as m p=1`,
	`fieldsummary`,
	`fieldsummary maxvals=3 a b`,
	`contingency a b`,
	`contingency maxrows=5 maxcols=5 usetotal=f a b`,
	`streamstats count`,
	`streamstats window=5 current=f global=f reset_on_change=t avg(n) as a by b`,
	`bin n span=1`,
	`bin _time span=1h as t`,
	`bucket n bins=10`,
	`regex a="x"`,
	`regex a!="x"`,
	`abstract`,
	`abstract maxlines=3`,
	`cluster field=a`,
	`cluster t=0.5 showcount=t labelonly=t field=a`,
	`xpath field=xml outfield=o "//k"`,
	`rex field=a mode=sed "s/x/z/g"`,
	`rex field=a max_match=2 "(?<n>\d+)"`,
	`geostats latfield=lat longfield=lon count`,
	`geostats count by a`,
	`concurrency duration=n`,
	`concurrency duration=n start=s output=c`,
	`format`,
	`format maxresults=5 "(" "(" "AND" ")" "OR" ")"`,
	`timewrap 1h`,
	`timewrap 1d series=short`,
	`transpose`,
	`transpose 5 column_name=c header_field=h`,
	`reverse`,
	`tail 5`,
	`dedup 2 a b keepempty=t consecutive=t sortby -c`,
	`fillnull value=0 a b`,
	`fillnull`,
	`rare limit=3 a by b`,
	`eventstats count, avg(n) as m by a`,
	`spath input=j path=k output=o`,
	`spath`,
	`iplocation src`,
	`iplocation prefix=g_ allfields=t src`,
	`predict n`,
	`predict n as p future_timespan=5 holdback=1 algorithm=LLP`,
	`return a`,
	`return 2 $a b=c`,
	`outputlookup t.csv`,
	`outputlookup append=t t.csv`,
	`inputlookup t.csv`,
	`lookup t k OUTPUT v`,
	`lookup t k AS f OUTPUTNEW v AS w`,
	`sort - n, + a`,
	`head 3`,
	`head limit=3`,
	`fields - a, b`,
	`fields + a`,
	`table a, b*`,
	`rename a as b, c* as d*`,
	`where a > 1 AND like(b, "x%")`,
	`search a=1 OR b=2`,
	`top a`,
	`top limit=3 countfield=n percentfield=p showcount=f showperc=f useother=t otherstr=rest a by b`,
	`stats count by a`,
	`stats dc(a) as d, values(b), list(c), first(d), last(e), earliest(f), latest(g), p95(n), median(n), mode(n), range(n), var(n), stdev(n), sum(n), min(n), max(n) by h`,
	`chart count over a by b`,
	`chart avg(n) by a`,
	`timechart span=1h count by a`,
	`timechart limit=3 useother=f avg(n)`,
	`transaction a maxspan=5m maxpause=1m startswith="x" endswith="y"`,
	`map search="search a=$a$" maxsearches=3`,
	`join type=left max=0 a [search b=1]`,
	`join a b [search b=1]`,
	`enrich`,
	`enrich user, dest`,
	`intel src`,
	`threatmatch src`,
	`eventcount`,
	`gentimes start=-1`,
	`makeresults count=3`,
	`multisearch [search a=1] [search b=2]`,
	`union [search a=1]`,
	`set union [search a=1] [search b=2]`,
	`tstats count from datamodel=Endpoint by host`,
	`datamodel Endpoint search`,
	`from datamodel:Endpoint`,
	`sendemail to=a`,
	`collect index=x`,
	`addinfo`,
	`localize`,
	`highlight a`,
	`iconify a`,
	`typer`,
	`tags`,
	`reltime`,
	`replace "a" with "b" in c`,
	`replace "a*" with "b*", "x" with "y" in c, d`,
	`selfjoin a`,
	`sistats count`,
	`erex a examples="x"`,
	`audit`,
	`metadata type=hosts`,
	`loadjob x`,
	`savedsearch x`,
	`input add`,
	`outputcsv x`,
	`inputcsv x`,
	`script x`,
	`crawl`,
	`dbinspect`,
	`rest /services/x`,
	`history`,
	`overlap`,
	`x11 n`,
	`arules a b`,
	`associate a b`,
	`diff`,
	`gauge n 0 10`,
	`folderize attr=a`,
	`findtypes`,
	`mcollect index=x`,
	`meventcollect index=x`,
	`mstats count(x) WHERE index=y`,
	`mpreview`,
	`walklex`,
	`redistribute`,
	`require`,
	`scrub`,
	`searchtxn x`,
	`sichart count`,
	`sirare a`,
	`sitimechart count`,
	`sitop a`,
	`tscollect`,
	`fieldformat n=tostring(n)`,
	`filldown a`,
	`filldown`,
	`nokv`,
	`outlier n`,
	`outlier action=remove param=3 uselower=t n`,
	`rtorder`,
	`delete`,
}

// Each command that parses prints as text that parses back to the same
// command, and names itself as the search does.
func TestCommandsRoundTrip(t *testing.T) {
	parsed := 0
	for _, src := range roundTripCommands {
		q, err := Parse("* | " + src)
		if err != nil {
			continue
		}
		parsed++
		text := q.String()
		q2, err := Parse(text)
		if err != nil {
			t.Errorf("%s printed %q, which does not parse: %v", src, text, err)
			continue
		}
		if !reflect.DeepEqual(q, q2) {
			t.Errorf("%s printed %q, which parses to\n%#v\nnot\n%#v", src, text, q2, q)
			continue
		}
		for _, c := range q.Commands {
			// A command names itself as one of the commands the parser
			// reads (fieldformat runs as eval).
			if name := c.Name(); !slices.Contains(Commands, name) {
				t.Errorf("%s: %T is named %q", src, c, name)
			}
		}
	}
	if parsed < len(roundTripCommands)/2 {
		t.Errorf("only %d of %d commands parse", parsed, len(roundTripCommands))
	}
}
