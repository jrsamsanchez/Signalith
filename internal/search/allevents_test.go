// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package search

import (
	"context"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/query"
)

// What a command needs of an event search's events.
const (
	// whole: its result depends on every matching event (it filters,
	// sorts, aggregates, totals, reshapes or runs to the last row), so
	// it must never run on just the newest DefaultEvents: the search
	// either aggregates inside OpenSearch or reads up to
	// search.max_events and is marked Sampled when more match.
	whole = iota
	// rowwise: each row's result depends only on that row, or on the
	// rows above it, so the newest events shown are right as they are.
	rowwise
	// source: it starts a search; its rows do not come from the events.
	source
	// inside: it only ever runs inside OpenSearch, over every event.
	inside
)

// commandNeeds has every command of the language, each with the searches
// that show its forms. A new command must be added here, which is where
// to decide whether it needs every event; if it does, add it to
// needsAllEvents too or this test fails.
var commandNeeds = map[string][]struct {
	cmd  string
	need int
}{
	"search":           {{`search user=a`, whole}},
	"stats":            {{`stats count by user`, whole}},
	"eventstats":       {{`eventstats count by user`, whole}},
	"timechart":        {{`timechart span=1h count`, whole}},
	"top":              {{`top user`, whole}},
	"rare":             {{`rare user`, whole}},
	"where":            {{`where bytes > 5`, whole}},
	"eval":             {{`eval x=1`, rowwise}},
	"rex":              {{`rex field=user "(?<first>\w)"`, rowwise}},
	"dedup":            {{`dedup user`, whole}},
	"fillnull":         {{`fillnull value=0 bytes`, rowwise}},
	"sort":             {{`sort user`, whole}},
	"head":             {{`head 5`, rowwise}},
	"table":            {{`table user`, rowwise}},
	"rename":           {{`rename user as u`, rowwise}},
	"lookup":           {{`lookup owners user`, rowwise}},
	"inputlookup":      {{`inputlookup append=t owners`, rowwise}},
	"transaction":      {{`transaction user`, whole}},
	"join":             {{`join user [search action=failure]`, whole}, {`join type=left user [search action=failure]`, rowwise}},
	"enrich":           {{`enrich`, rowwise}},
	"intel":            {{`intel`, rowwise}},
	"threatmatch":      {{`threatmatch`, inside}},
	"streamstats":      {{`streamstats count`, whole}},
	"bin":              {{`bin span=1h _time`, rowwise}},
	"bucket":           {{`bucket span=1h _time`, rowwise}},
	"fields":           {{`fields user`, rowwise}, {`fields - user`, rowwise}},
	"regex":            {{`regex user="a"`, whole}},
	"makeresults":      {{`makeresults`, source}},
	"append":           {{`append [search action=failure]`, rowwise}},
	"appendpipe":       {{`appendpipe [stats count]`, whole}},
	"tstats":           {{`tstats count`, source}},
	"chart":            {{`chart count by user`, whole}},
	"xyseries":         {{`xyseries user src bytes`, whole}},
	"untable":          {{`untable user name value`, whole}},
	"spath":            {{`spath`, rowwise}},
	"mvexpand":         {{`mvexpand user`, rowwise}},
	"makemv":           {{`makemv user`, rowwise}},
	"reverse":          {{`reverse`, whole}},
	"addtotals":        {{`addtotals bytes`, rowwise}, {`addtotals col=t bytes`, whole}},
	"addcoltotals":     {{`addcoltotals bytes`, whole}},
	"convert":          {{`convert num(bytes)`, rowwise}},
	"tail":             {{`tail 5`, whole}},
	"uniq":             {{`uniq`, whole}},
	"fromjson":         {{`fromjson user`, rowwise}},
	"nomv":             {{`nomv user`, rowwise}},
	"mvcombine":        {{`mvcombine user`, whole}},
	"strcat":           {{`strcat user src both`, rowwise}},
	"rangemap":         {{`rangemap field=bytes low=0-10`, rowwise}},
	"fieldformat":      {{`fieldformat bytes=tostring(bytes)`, rowwise}},
	"foreach":          {{`foreach bytes [eval <<FIELD>>=<<FIELD>>*2]`, rowwise}},
	"replace":          {{`replace a with b in user`, rowwise}},
	"xmlkv":            {{`xmlkv`, rowwise}},
	"iplocation":       {{`iplocation src`, rowwise}},
	"map":              {{`map search="search user=$user$"`, whole}},
	"accum":            {{`accum bytes as total`, whole}},
	"delta":            {{`delta bytes`, rowwise}},
	"autoregress":      {{`autoregress bytes`, rowwise}},
	"fieldsummary":     {{`fieldsummary`, whole}},
	"transpose":        {{`transpose`, whole}},
	"filldown":         {{`filldown user`, rowwise}},
	"addinfo":          {{`addinfo`, rowwise}},
	"trendline":        {{`trendline sma2(bytes) as s`, rowwise}},
	"concurrency":      {{`concurrency duration=bytes`, whole}},
	"contingency":      {{`contingency user src`, whole}},
	"format":           {{`format`, whole}},
	"return":           {{`return 5 user`, whole}},
	"makecontinuous":   {{`makecontinuous bytes span=1`, whole}},
	"union":            {{`union [search action=failure]`, rowwise}},
	"geostats":         {{`geostats count`, whole}},
	"extract":          {{`extract`, rowwise}},
	"outlier":          {{`outlier bytes`, whole}},
	"gauge":            {{`gauge bytes`, rowwise}},
	"multisearch":      {{`multisearch [search action=failure] [search action=lockout]`, source}},
	"timewrap":         {{`timechart span=1h count | timewrap 1d`, whole}},
	"cluster":          {{`cluster field=user`, whole}},
	"xpath":            {{`xpath "//k"`, rowwise}},
	"abstract":         {{`abstract`, rowwise}},
	"highlight":        {{`highlight error`, rowwise}},
	"anomalydetection": {{`anomalydetection bytes`, whole}},
	"correlate":        {{`correlate`, whole}},
	"predict":          {{`timechart span=1h count | predict count`, whole}},
	"set":              {{`set union [search action=failure | fields user] [search action=lockout | fields user]`, source}},
	"setfields":        {{`setfields z=1`, rowwise}},
	"kmeans":           {{`kmeans k=2 bytes`, whole}},
	"eventcount":       {{`eventcount`, source}},
	"outputlookup":     {{`outputlookup seen`, whole}},
	"from":             {{`from datamodel:Authentication`, source}},
}

// TestEveryCommandSaysWhichEventsItNeeds goes through every command of the
// language (SRCH-203, after SL-01 and SL-101): one that needs every event
// never runs on the newest DefaultEvents without a mark, wherever it
// stands, so a new command cannot bring the silent cap back.
func TestEveryCommandSaysWhichEventsItNeeds(t *testing.T) {
	const maxEvents = 5000
	e := lookupEngine(t)
	e.Opt.MaxEvents = maxEvents
	for _, table := range []string{"owners", "seen"} {
		if _, err := e.Lookups.Put(table, []byte("user,owner\na,b\n")); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range query.Commands {
		cases, ok := commandNeeds[name]
		if !ok {
			t.Errorf("%s is not in commandNeeds: say whether it needs every event", name)
			continue
		}
		for _, c := range cases {
			if c.need == source || c.need == inside {
				src := `| ` + c.cmd
				if c.need == inside {
					src = `* ` + src
				}
				if _, err := query.Parse(src); err != nil {
					t.Errorf("%s: %v", src, err)
				}
				continue
			}
			// Straight after the search, and after a command that
			// keeps OpenSearch from doing the work.
			for _, src := range []string{`* | ` + c.cmd, `* | eval zz=1 | ` + c.cmd} {
				q, err := query.Parse(src)
				if err != nil {
					t.Errorf("%s: %v", src, err)
					continue
				}
				p, err := e.Compile(q)
				if err != nil {
					t.Errorf("%s: %v", src, err)
					continue
				}
				if p.Mode != "events" || len(p.post) == 0 {
					// OpenSearch aggregates or filters over every
					// event; nothing runs on the rows it returns.
					continue
				}
				size, _ := p.Body["size"].(int)
				switch {
				case c.need == whole && (size != maxEvents || p.SampleLimit != maxEvents):
					t.Errorf("%s: reads %d events (sample limit %d); it needs them all, so want %d and the Sampled mark", src, size, p.SampleLimit, maxEvents)
				case c.need == rowwise && name != "head" && size != e.opts().DefaultEvents:
					t.Errorf("%s: reads %d events, want the newest %d; if it now needs them all, say so in commandNeeds", src, size, e.opts().DefaultEvents)
				}
			}
		}
	}
	for name := range commandNeeds {
		found := false
		for _, c := range query.Commands {
			found = found || c == name
		}
		if !found {
			t.Errorf("commandNeeds has %s, which is not a command", name)
		}
	}
}

// TestSubsearchesReadEveryEvent: every place a search runs another (a
// subsearch among the terms, map, and the commands SL-101 fixed) reads up
// to search.max_events events, and the outer result says when more matched.
func TestSubsearchesReadEveryEvent(t *testing.T) {
	const maxEvents = 5000
	const many = `{"hits":{"total":{"value":100000},"hits":[
		{"_source":{"@timestamp":"2026-10-15T11:00:00Z","user":"amy","src":"10.0.0.1","bytes":5}},
		{"_source":{"@timestamp":"2026-10-15T10:00:00Z","user":"bob","src":"10.0.0.2","bytes":7}}]}}`
	const stats = `{"hits":{"total":{"value":100000},"hits":[]},"aggregations":{"groups":{"buckets":[]}}}`
	for _, c := range []struct {
		q         string
		responses []string
		// subs is how many of the requests, from the first, are the
		// subsearches'.
		subs int
	}{
		{`action=allowed [search action=failure | fields src]`, []string{many}, 1},
		{`action=allowed [search action=failure | fields src] | stats count by src`, []string{many, stats}, 1},
		{`action=allowed [search action=failure | dedup src | fields src] | stats count by src`, []string{many, stats}, 1},
		{`action=allowed | where bytes > 1 | search [search action=failure | fields src]`, []string{many}, 1},
		{`action=allowed [search action=failure [search action=lockout | fields user] | fields src] | stats count by src`, []string{many, many, stats}, 2},
		{`| makeresults | eval user="amy" | map search="search action=failure user=$user$" | stats count by user`, []string{many}, 1},
		{`| makeresults | eval user="amy" | join user [search action=failure]`, []string{many}, 1},
		{`| makeresults | append [search action=failure]`, []string{many}, 1},
		{`| makeresults | union [search action=failure]`, []string{many}, 1},
		{`| multisearch [search action=failure] [search action=lockout]`, []string{many}, 2},
		{`| set union [search action=failure | fields user] [search action=lockout | fields user]`, []string{many}, 2},
	} {
		fs := &fakeStore{responses: c.responses}
		res, err := (&Engine{Store: fs, Opt: Options{MaxEvents: maxEvents}}).Run(context.Background(), c.q)
		if err != nil {
			t.Errorf("%s: %v", c.q, err)
			continue
		}
		if len(fs.bodies) < c.subs {
			t.Errorf("%s: %d requests, want at least %d", c.q, len(fs.bodies), c.subs)
			continue
		}
		for i, b := range fs.bodies[:c.subs] {
			if b["size"] != maxEvents {
				t.Errorf("%s: subsearch %d reads %v events, want %d", c.q, i+1, b["size"], maxEvents)
			}
		}
		// The fake store gives 2 events of 100,000.
		if res.Sampled != 2 {
			t.Errorf("%s: sampled = %d, want the 2 events the subsearch read of 100000", c.q, res.Sampled)
		}
	}
	// A subsearch that read everything leaves no mark.
	all := `{"hits":{"total":{"value":1},"hits":[{"_source":{"@timestamp":"2026-10-15T11:00:00Z","src":"10.0.0.1"}}]}}`
	fs := &fakeStore{responses: []string{all, stats}}
	res, err := (&Engine{Store: fs}).Run(context.Background(), `action=allowed [search action=failure | fields src] | stats count by src`)
	if err != nil || res.Sampled != 0 || res.Truncated {
		t.Errorf("complete subsearch: sampled %d truncated %v err %v", res.Sampled, res.Truncated, err)
	}
}

// TestTotalsAndReshapesReadEveryEvent runs the commands SRCH-203 names:
// each reads up to search.max_events events and is marked when more match.
func TestTotalsAndReshapesReadEveryEvent(t *testing.T) {
	const many = `{"hits":{"total":{"value":100000},"hits":[
		{"_source":{"@timestamp":"2026-10-15T11:00:00Z","user":"amy","src":"10.0.0.1","bytes":5}},
		{"_source":{"@timestamp":"2026-10-15T10:00:00Z","user":"bob","src":"10.0.0.2","bytes":7}}]}}`
	for _, q := range []string{
		`* | addcoltotals bytes`,
		`* | addtotals col=t bytes`,
		`* | uniq`,
		`* | reverse`,
		`* | accum bytes as total`,
		`* | transpose`,
		`* | untable user name value`,
		`* | xyseries user src bytes`,
		`* | return 5 user`,
	} {
		fs := &fakeStore{responses: []string{many}}
		res, err := (&Engine{Store: fs, Opt: Options{MaxEvents: 5000}}).Run(context.Background(), q)
		if err != nil {
			t.Errorf("%s: %v", q, err)
			continue
		}
		if fs.bodies[0]["size"] != 5000 || res.Sampled != 2 {
			t.Errorf("%s: read %v events, sampled %d; want 5000 and the mark", q, fs.bodies[0]["size"], res.Sampled)
		}
	}
	// A head first keeps a running total cheap: the newest rows' totals
	// do not depend on the rows below.
	fs := &fakeStore{responses: []string{many}}
	res, err := (&Engine{Store: fs, Opt: Options{MaxEvents: 5000}}).Run(context.Background(), `* | accum bytes as total | head 2`)
	if err != nil || fs.bodies[0]["size"] != 2 || res.Sampled != 0 {
		t.Errorf("accum | head 2: size %v sampled %d err %v", fs.bodies[0]["size"], res.Sampled, err)
	}
}
