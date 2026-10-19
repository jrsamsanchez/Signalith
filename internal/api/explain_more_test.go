// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/query"
)

// TestExplainEveryCommand walks Explain over at least one query per command
// it knows, so a change to a sentence or a missed case shows up here.
func TestExplainEveryCommand(t *testing.T) {
	cases := []struct {
		q    string
		want []string
	}{
		{`| inputlookup max=3 hosts where os="linux" | head 2`, []string{
			"Read the rows of the lookup table hosts", "where os is linux", "Keep the first 2 rows."}},
		{`| makeresults count=3 | eval a=1`, []string{"Make 3 rows, each holding only the current time.", "Set a to 1."}},
		{`| makeresults`, []string{"Make one row holding only the current time."}},
		{`| eventcount index=signalith-* summarize=false`, []string{
			"Count the events stored in the indexes matching signalith-*, whatever their time, one row per index."}},
		{`| eventcount`, []string{"Count the events stored in every index a search reads, whatever their time."}},
		{`| multisearch [search a=1 | head 2] [search b=2]`, []string{
			"Start with the rows of these subsearches together, newest first. Subsearch 1: Take all events where a is 1. Keep the first 2 rows. Subsearch 2: Take all events where b is 2."}},
		{`| set diff [search a=1 | fields user] [search b=2 | fields user]`, []string{
			"Start with the rows only one of them has of these two subsearches.", "Subsearch 2: Take all events where b is 2."}},
		{`index=signalith-* earliest=-24h@d latest=now`, []string{
			"Take events in indexes matching signalith-* between 24 hours ago, rounded down to the start of the day and now."}},
		{`earliest=0 latest=-1h (a=1 OR b!=2) NOT c<3 d<=4 e>5 f>=6 g=* h=ab* i!=x? "free text" j IN (x, y) k=~"ab.c"`, []string{
			"Take all events until 1 hour ago where (a is 1 or b is not 2) and not c is less than 3 and d is at most 4 and e is greater than 5 and f is at least 6 and g has any value and h matches ab* and i does not match x? and the raw event contains \"free text\" and j is one of x, y and k matches the regular expression ab.c."}},
		{`earliest=-15m user=x [search a=1 | fields user]`, []string{
			"from 15 minutes ago until now where user is x and the fields match a row of the subsearch ["}},
		{`earliest=-w`, []string{"Take all events from 1 week ago until now."}},
		{`latest=-3mon`, []string{"Take all events until 3 months ago."}},
		{`earliest=-2q`, []string{"Take all events from -2q until now."}},
		{`* | stats count, count(user), dc(user), sum(b), avg(b), min(b), max(b), var(b), range(b), mode(b), list(b), first(b), last(b), earliest(b), p2(b), p3(b), p11(b), p22(b), perc50(b)`, []string{
			"Calculate the number of events, the number of events with user, the number of distinct user values, the total b, the average b, the smallest b, the largest b, the variance of b, the range (largest minus smallest) of b, the most common b, every value of b, the newest b, the oldest b, the oldest b, the 2nd percentile of b, the 3rd percentile of b, the 11th percentile of b, the 22nd percentile of b, the 50th percentile of b."}},
		{`* | timechart count by severity`, []string{
			"Chart the number of events over time in buckets of an automatic interval, one line per severity."}},
		{`* | timechart span=1h count`, []string{"Chart the number of events over time in buckets of 1h."}},
		{`* | outputlookup users`, []string{"Write the rows to the lookup table users, which must not exist yet, and keep them as they are."}},
		{`* | outputlookup append=t max=10 users`, []string{"Write the rows to the lookup table users, after the rows it has, at most 10 rows, and keep them as they are."}},
		{`* | outputlookup append=f users`, []string{"Write the rows to the lookup table users, replacing what it holds"}},
		{`* | eval a=1, b=2 | fieldformat t=strftime(t, "%Y")`, []string{
			"Set a to 1, then b to 2.", `Set t to strftime(t, "%Y") (fieldformat runs as eval).`}},
		{`* | nomv a | mvcombine b | strcat allrequired=t src "-" dest pair | rangemap field=n low=-10--1 hi=0-1.5 default=x`, []string{
			"Join the values of a into one, a line each.",
			"Merge rows that differ only in b into one row holding all their b values.",
			`Join src, "-", dest into pair, only where every field has a value.`,
			"Set range by n: low for -10 to -1, hi for 0 to 1.5, otherwise x."}},
		{`* | replace a WITH b IN host | replace c WITH d | accum bytes | delta count AS d p=3 | autoregress c p=2-4`, []string{
			`Replace "a" with "b" in host.`, `Replace "c" with "d" in every field.`,
			"Set bytes to the running total of bytes.",
			"Set d to count minus its value 3 rows with a number earlier.",
			"Copy c from earlier rows into c_p2, c_p3, c_p4."}},
		{`* | transpose 7 column_name=col header_field=h | transpose | filldown | filldown a, b | addinfo | trendline sma5(x) ema10(y)`, []string{
			"Turn the first 7 rows into columns, one row per field with its name in col and columns named by h.",
			"Turn the first 5 rows into columns, one row per field with its name in column.",
			"Give each row missing a field that field's value in the last row that has it.",
			"Give each row missing a, b the value in the last row that has it.",
			"(info_min_time, info_max_time, info_search_time)",
			"Add the moving averages sma5(x), ema10(y)."}},
		{`* | concurrency duration=d | contingency x y | format | return 3 ip=dest | makecontinuous span=1h _time | fieldsummary`, []string{
			"Set concurrency to how many rows were in progress when each started, using _time as the start and d as the duration in seconds.",
			"Count each pair of x and y values in a table, one row per x and one column per y.",
			"Turn the rows into one search that matches them, in a field named search.",
			"Turn the first 3 rows with a value into search terms, in a field named search.",
			"Add an empty row for each 1h of _time that no row has, and sort the rows by _time.",
			"Describe each field:"}},
		{`* | map maxsearches=3 search="search user=$user$" | iplocation src | xmlkv Message | foreach b_* c [eval <<FIELD>>=1]`, []string{
			`For each of the first 3 rows, run the search "search user=$user$"`,
			"Add where the IP address in src is, from the GeoIP database: City, Region, Country, lat, lon.",
			"Extract the text of each XML element in Message as a field named by its tag.",
			"For each field matching b_*, c, run: eval <<FIELD>>=1."}},
		{`* | rex field=_raw mode=sed "s/a/b/g" | rex field=p "(?<a>x)(?<b>y)" | rex field=p max_match=3 "(?<a>x)"`, []string{
			"Change the text of _raw with the sed expression s/a/b/g.",
			"Extract a, b from p with the regular expression (?<a>x)(?<b>y).",
			"Extract a from p with the regular expression (?<a>x), keeping up to 3 matches."}},
		{`* | join type=left max=0 user [search a=1] | join max=1 user [search b=1] | join max=4 user [search c=1]`, []string{
			"(every match, up to 100), adding their fields; rows with no match are kept. The subsearch: Take all events where a is 1.",
			"(the first match), adding their fields; rows with no match are dropped.",
			"(up to 4 matches)"}},
		{`* | transaction host maxspan=10m maxpause=5m startswith=(a=1) endswith=(b=2) | transaction`, []string{
			"Group the events by host into transactions, oldest event first, each at most 600 seconds long, with at most 300 seconds between events, of at most 1000 events; an event where a is 1 starts one; an event where b is 2 ends one, and one that never ends is dropped.",
			"Group the events into transactions, oldest event first, each of at most 1000 events. Each gets duration (seconds) and eventcount."}},
		{`* | dedup consecutive=true user sortby -_time, +host | dedup user`, []string{
			"Keep only the first row for each user, dropping only repeats that follow each other; rows missing one of these fields are dropped; then sort by _time (highest first), then host (lowest first).",
			"Keep only the first row for each user; rows missing one of these fields are dropped."}},
		{`* | top limit=5 user by src | top 5 src countfield=c showcount=f showperc=f | top useother=t user`, []string{
			"List the 5 most common values of user with their count and percentage for each src.",
			"List the 5 most common values of src.",
			"and a row counting the rest as OTHER."}},
		{`* | where a=1 | search b=2 | mvexpand r limit=5 | mvexpand r | makemv delim="," a | makemv tokenizer="(\w+)" b | makemv c`, []string{
			"Keep only rows where a is 1.", "Keep only rows matching b is 2.",
			"Make one row for each value of r (up to 5 per row).", "Make one row for each value of r.",
			`Split a into values at each ",".`, `Split b into a value for each match of (\w+).`,
			"Split c into values at each space."}},
		{`* | reverse | tail 3 | uniq | convert ctime(a) AS b, num(c) | addtotals col=t fieldname=sum bytes_* | addtotals row=f col=t | addtotals`, []string{
			"Turn the order of the rows around.", "Keep the last 3 rows, last first.",
			"Drop rows that repeat the row before them exactly.", "Convert ctime(a) into b, num(c).",
			"Add up bytes_* of each row into sum and add a last row with each column's total.",
			"Add a last row with each column's total.", "Add up the numeric fields of each row into Total."}},
		{`* | sort -count, user | head 3 | table a, b | chart limit=3 sum(count) over index by sourcetype | chart count by host`, []string{
			"Sort by count (highest first), then user (lowest first).", "Show only the columns a, b.",
			"Chart the total count for each index, one column per sourcetype (the 3 largest).",
			"Chart the number of events for each host."}},
		{`* | xyseries host action count | untable host action count | spath | spath input=body output=u path=a.b | spath input=body path=a.c`, []string{
			"Make one row per host with one column per action, holding count.",
			"Make one row per cell: host, the column's name as action and its value as count.",
			"Extract every value from the JSON in _raw, each named by its path.",
			"Extract a.b from the JSON in body into u.", "Extract a.c from the JSON in body into a.c."}},
		{`* | fromjson body prefix=p_ | fromjson x | fields - a, b | streamstats current=f window=5 count by src | streamstats count`, []string{
			"Extract each top-level key of the JSON object in body as a field named p_ and the key.",
			"Extract each top-level key of the JSON object in x as a field of the same name.",
			"Remove the fields a, b.",
			"Add a running the number of events for each src to every row, over the rows before it, looking back at most 5 rows.",
			"Add a running the number of events to every row, over the rows before it and the row itself."}},
		{`* | bin span=1h _time AS t | bin span=10 x | regex process!="a" | regex process="b"`, []string{
			"Round _time down into buckets of 1h, writing the bucket to t.", "Round x down into buckets of 10.",
			"Keep only rows where process does not match the regular expression a.",
			"Keep only rows where process matches the regular expression b."}},
		{`* | append [search * | stats count by user] | extract | kv mv_add=t | outlier | outlier action=rm uselower=true bytes`, []string{
			"Add the rows of a subsearch after these. The subsearch: Take all events. Calculate the number of events for each user.",
			"Read up to 50 key=value pairs from the first 10240 characters of _raw",
			"; a repeated key gives a multivalue field.",
			"Set numbers in every field with numbers that are above the 75th percentile plus 2.5 times",
			"Remove rows whose numbers in bytes are outside the 25th to 75th percentiles by more than 2.5 times"}},
		{`* | gauge count 1 2 | geostats count by host | geostats count | anomalydetection method=zscore action=annotate a, b | anomalydetection action=filter | anomalydetection action=summary | correlate`, []string{
			"Make one row for a gauge: x is count",
			"Count the number of events in map squares of 22.5 by 45 degrees of lat and lon, one column per host.",
			"Count the number of events in map squares of 22.5 by 45 degrees of lat and lon.",
			"Find rows where a value of a, b is far from the field's mean (probability below 0.01) and mark every row with isOutlier",
			"Find rows where a value of every field few rows share (probability below 0.01) and keep only those.",
			"and count them.",
			"Show, for each pair of fields, the share of rows that have both."}},
		{`* | predict count | predict x algorithm=LL holdback=2 future_timespan=5 | predict x algorithm=LLT | predict x algorithm=LLP`, []string{
			"Forecast count with a level, trend and repeating season, with 95% and 95% bounds, and add 5 future rows.",
			"Forecast x with a moving level, with 95% and 95% bounds, learning from all but the last 2 rows, and add 3 future rows.",
			"Forecast x with a level and trend,", "Forecast x with a level and repeating season,"}},
		{`* | kmeans | kmeans k=5 showcentroid=t a b | setfields a=1, b=2 | xpath field=m outfield=o "//a" default="none" | xpath "//b"`, []string{
			"Group rows into 2 clusters by their numbers (k-means, l2 distance, best of 10 runs) and number them in CLUSTERNUM",
			"Group rows into 5 clusters by a, b", ", with each cluster's centre in centroid_ fields.",
			`Set a to "1", b to "2" on every row.`,
			`Set o to the text of //a in the XML of m, or "none" where it finds none.`,
			"Set xpath to the text of //b in the XML of _raw."}},
		{`* | abstract maxlines=2 | highlight a, b | timewrap 1d | timewrap 2h align=now | cluster | cluster field=m labelonly=t showcount=t`, []string{
			"Shorten each event's _raw to its 2 lines with the most words.",
			"Mark a, b in the results; the rows stay as they are.",
			"Lay each 1d of the chart side by side: one column per series and period, with the rows at the times of the latest period.",
			"of the latest period, which ends now.",
			"Group rows whose _raw is at least 0.8 alike (termlist) and number the groups in cluster_label, keeping the first row of each.",
			"Group rows whose m is at least 0.8 alike (termlist) and number the groups in cluster_label; cluster_count is each group's size."}},
		{`* | union [search a=1] [search b=2] | appendpipe [stats sum(count) as count] | rename a AS b, c AS d | lookup t host OUTPUT owner | lookup t2 host`, []string{
			"Add the rows of each subsearch after these. Subsearch 1: Take all events where a is 1. Subsearch 2: Take all events where b is 2.",
			"Run these steps over a copy of the rows and add the rows they give after them: Calculate the total count (as count).",
			"Rename a to b, c to d.",
			"Look up host in the lookup table t and add owner from the matching rows.",
			"Look up host in the lookup table t2 and add every other column from the matching rows."}},
		{`* | enrich | enrich user, dest | intel | intel src dest | threatmatch | threatmatch src, dest`, []string{
			"for user, src, dest and host fields.", "for user, dest.",
			"Check the IP, domain, URL, hash and email fields against threat intel",
			"Check src, dest against threat intel", "(as src_intel_source and so on).",
			"Keep only events where an IP, domain, URL, hash or email field matches a threat intel indicator",
			"Keep only events where any of src, dest matches a threat intel indicator"}},
	}
	for _, c := range cases {
		q, err := query.Parse(c.q)
		if err != nil {
			t.Errorf("Parse(%q): %v", c.q, err)
			continue
		}
		got := strings.Join(Explain(q), "\n")
		for _, w := range c.want {
			if !strings.Contains(got, w) {
				t.Errorf("Explain(%q) is missing %q in:\n%s", c.q, w, got)
			}
		}
	}
}

func TestExplainHelpers(t *testing.T) {
	for n, want := range map[int]string{1: "1st", 2: "2nd", 3: "3rd", 4: "4th", 11: "11th", 12: "12th", 13: "13th", 21: "21st", 101: "101st", 112: "112th"} {
		if got := ordinal(n); got != want {
			t.Errorf("ordinal(%d) = %q, want %q", n, got, want)
		}
	}
	for in, want := range map[string]string{
		"now": "now", "-1d": "1 day ago", "-d": "1 day ago", "-30s": "30 seconds ago", "-2y": "2 years ago",
		"-1h@h": "1 hour ago, rounded down to the start of the hour", "-5x": "-5x", "1700000000": "1700000000",
	} {
		if got := describeTime(in); got != want {
			t.Errorf("describeTime(%q) = %q, want %q", in, got, want)
		}
	}
	for in, want := range map[string]string{"LL": "a moving level", "LLT": "a level and trend", "LLP": "a level and repeating season", "": "a level, trend and repeating season"} {
		if got := predictAlgorithm(in); got != want {
			t.Errorf("predictAlgorithm(%q) = %q, want %q", in, got, want)
		}
	}
	// A rex whose pattern does not compile names no fields but still says
	// what it runs.
	if got := describeCommand(&query.Rex{Field: "f", Pattern: "(", MaxMatch: 1}); got != "Extract  from f with the regular expression (." {
		t.Errorf("rex with a bad pattern = %q", got)
	}
	// The aggregates fall back to their own text for a function Explain has
	// no words for.
	if got := describeAggs([]query.Agg{{Func: "bogus", Field: "x"}}); !strings.Contains(got, "bogus") {
		t.Errorf("describeAggs(bogus) = %q", got)
	}
}
