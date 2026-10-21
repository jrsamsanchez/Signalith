// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package search

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
)

// semanticEvents are the events the semantic corpus runs over, newest
// first, as a search returns them. A missing value is a field the event
// does not have; a value with | is a multivalue field.
var semanticEvents = []map[string]string{
	{"_time": "1767243600", "user": "alice", "src": "10.0.0.1", "action": "failure", "bytes": "100", "dest": "web1", "tags": "a|b"},
	{"_time": "1767240000", "user": "alice", "src": "10.0.0.2", "action": "success", "bytes": "200", "dest": "web1", "tags": "b"},
	{"_time": "1767236400", "user": "bob", "src": "10.0.0.1", "action": "failure", "dest": "db1"},
	{"_time": "1767232800", "src": "10.0.0.3", "action": "failure", "bytes": "50", "dest": "web2", "tags": "a"},
	{"_time": "1767229200", "user": "carol", "src": "10.0.0.1", "action": "success", "bytes": "x", "dest": "db1"},
	{"_time": "1767225600", "user": "Bob", "src": "10.0.0.4", "action": "blocked", "bytes": "300", "tags": "c|a"},
}

// semanticFixture is a makeresults search that makes semanticEvents.
func semanticFixture() string {
	fields := []string{"_time", "user", "src", "action", "bytes", "dest", "tags"}
	var sets []string
	for _, f := range fields {
		var arms []string
		for i, e := range semanticEvents {
			v, ok := e[f]
			if !ok {
				continue
			}
			x := fmt.Sprintf("%q", v)
			switch {
			case f == "_time":
				x = v
			case strings.Contains(v, "|"):
				x = fmt.Sprintf("split(%q, \"|\")", v)
			case v == "100" || v == "200" || v == "50" || v == "300":
				x = v
			}
			arms = append(arms, fmt.Sprintf("n=%d, %s", i+1, x))
		}
		sets = append(sets, fmt.Sprintf("%s=case(%s)", f, strings.Join(arms, ", ")))
	}
	return fmt.Sprintf("| makeresults count=%d | streamstats count as n | eval %s | fields - n", len(semanticEvents), strings.Join(sets, ", "))
}

// semanticCases are searches with the rows Splunk gives for them over
// semanticEvents, as fmt prints the result rows. Each runs after the
// fixture, so the search command here is the one after a pipe.
var semanticCases = []struct{ q, want string }{
	{`stats count`, `[map[count:6]]`},
	{`stats count(bytes)`, `[map[count(bytes):5]]`},
	{`stats count(user) as c`, `[map[c:5]]`},
	{`stats sum(bytes)`, `[map[sum(bytes):650]]`},
	{`stats avg(bytes)`, `[map[avg(bytes):162.5]]`},
	{`stats min(_time) as lo, max(_time) as hi`, `[map[hi:1767243600 lo:1767225600]]`},
	{`stats count by user`, `[map[count:1 user:Bob] map[count:2 user:alice] map[count:1 user:bob] map[count:1 user:carol]]`},
	{`stats count by action`, `[map[action:blocked count:1] map[action:failure count:3] map[action:success count:2]]`},
	{`stats count by user, action`, `[map[action:blocked count:1 user:Bob] map[action:failure count:1 user:alice] map[action:success count:1 user:alice] map[action:failure count:1 user:bob] map[action:success count:1 user:carol]]`},
	{`stats dc(user) as users`, `[map[users:4]]`},
	{`stats dc(src) as srcs by action`, `[map[action:blocked srcs:1] map[action:failure srcs:2] map[action:success srcs:2]]`},
	{`stats values(user) as users`, `[map[users:[Bob alice bob carol]]]`},
	{`stats values(action) as a by dest`, `[map[a:[failure success] dest:db1] map[a:[failure success] dest:web1] map[a:failure dest:web2]]`},
	{`stats list(user) as users`, `[map[users:[alice alice bob carol Bob]]]`},
	{`stats first(user) as f, last(user) as l`, `[map[f:alice l:Bob]]`},
	{`stats count, sum(bytes) as b by dest`, `[map[b:<nil> count:2 dest:db1] map[b:300 count:2 dest:web1] map[b:50 count:1 dest:web2]]`},
	{`fillnull value=NULL user | stats count by user`, `[map[count:1 user:Bob] map[count:1 user:NULL] map[count:2 user:alice] map[count:1 user:bob] map[count:1 user:carol]]`},
	{`stats count by tags`, `[map[count:3 tags:a] map[count:2 tags:b] map[count:1 tags:c]]`},
	{`stats dc(tags) as t`, `[map[t:3]]`},
	{`stats count as c by action | where c > 1`, `[map[action:failure c:3] map[action:success c:2]]`},
	{`stats count as c by action | sort -c`, `[map[action:failure c:3] map[action:success c:2] map[action:blocked c:1]]`},
	{`stats range(bytes) as r`, `[map[r:250]]`},
	{`stats median(bytes) as m`, `[map[m:150]]`},
	{`stats stdev(bytes) as s`, `[map[s:110.86778913041725]]`},
	{`stats mode(src) as m`, `[map[m:10.0.0.1]]`},
	{`search tags=a | table user`, `[map[user:alice] map[] map[user:Bob]]`},
	{`search user=bob | table user`, `[map[user:bob] map[user:Bob]]`},
	{`search user!=alice | table user`, `[map[user:bob] map[user:carol] map[user:Bob]]`},
	{`search NOT user=alice | table user`, `[map[user:bob] map[] map[user:carol] map[user:Bob]]`},
	{`search user=* | stats count`, `[map[count:5]]`},
	{`search NOT user=* | table src`, `[map[src:10.0.0.3]]`},
	{`search bytes>100 bytes!=x | table bytes`, `[map[bytes:200] map[bytes:300]]`},
	{`search src=10.0.0.1 action=failure | table user`, `[map[user:alice] map[user:bob]]`},
	{`search action=failure OR action=blocked | stats count`, `[map[count:4]]`},
	{`search user=a* | table user`, `[map[user:alice] map[user:alice]]`},
	{`search tags!=a | table user`, `[map[user:alice]]`},
	{`where user!="alice" | table user`, `[map[user:bob] map[user:carol] map[user:Bob]]`},
	{`where isnull(user) | table src`, `[map[src:10.0.0.3]]`},
	{`where isnotnull(bytes) | stats count`, `[map[count:5]]`},
	{`where isnum(bytes) AND bytes > 100 | table bytes`, `[map[bytes:200] map[bytes:300]]`},
	{`where like(src, "10.0.0.%") | stats count`, `[map[count:6]]`},
	{`where cidrmatch("10.0.0.0/30", src) | stats count`, `[map[count:5]]`},
	{`where match(user, "^[A-Z]") | table user`, `[map[user:Bob]]`},
	{`where tags="a" | stats count`, `[map[count:3]]`},
	{`where action="failure" AND bytes>=50 | table bytes`, `[map[bytes:100] map[bytes:50]]`},
	{`where action="failure" OR isnull(bytes) | stats count`, `[map[count:3]]`},
	{`where NOT action="failure" | stats count`, `[map[count:3]]`},
	{`where in(action, "blocked", "success") | stats count`, `[map[count:3]]`},
	{`where _time >= 1767236400 | stats count`, `[map[count:3]]`},
	{`where lower(user)="bob" | stats count`, `[map[count:2]]`},
	{`where isnum(bytes) | sort -bytes | table bytes`, `[map[bytes:300] map[bytes:200] map[bytes:100] map[bytes:50]]`},
	{`where isnum(bytes) | sort bytes | table bytes`, `[map[bytes:50] map[bytes:100] map[bytes:200] map[bytes:300]]`},
	{`where isnotnull(user) | sort user | table user`, `[map[user:Bob] map[user:alice] map[user:alice] map[user:bob] map[user:carol]]`},
	{`sort 2 -_time | table user`, `[map[user:alice] map[user:alice]]`},
	{`sort _time | head 1 | table user`, `[map[user:Bob]]`},
	{`sort src, -_time | table src user`, `[map[src:10.0.0.1 user:alice] map[src:10.0.0.1 user:bob] map[src:10.0.0.1 user:carol] map[src:10.0.0.2 user:alice] map[src:10.0.0.3] map[src:10.0.0.4 user:Bob]]`},
	{`where isnotnull(user) | sort str(user) | table user`, `[map[user:Bob] map[user:alice] map[user:alice] map[user:bob] map[user:carol]]`},
	{`head 2 | table user`, `[map[user:alice] map[user:alice]]`},
	{`tail 1 | table user`, `[map[user:Bob]]`},
	{`reverse | head 1 | table user`, `[map[user:Bob]]`},
	{`dedup src | table src`, `[map[src:10.0.0.1] map[src:10.0.0.2] map[src:10.0.0.3] map[src:10.0.0.4]]`},
	{`dedup user | table user`, `[map[user:alice] map[user:bob] map[user:carol] map[user:Bob]]`},
	{`dedup user keepempty=true | stats count`, `[map[count:5]]`},
	{`dedup 2 src | stats count`, `[map[count:5]]`},
	{`dedup action sortby -bytes | table action bytes`, `[map[action:blocked bytes:300] map[action:success bytes:200] map[action:failure bytes:100]]`},
	{`top action | table action count percent`, `[map[action:failure count:3 percent:50] map[action:success count:2 percent:33.333333] map[action:blocked count:1 percent:16.666667]]`},
	{`top limit=1 src`, `[map[count:3 percent:50 src:10.0.0.1]]`},
	{`rare action limit=1 | table action count`, `[map[action:blocked count:1]]`},
	{`top tags | table tags count`, `[map[count:3 tags:a] map[count:2 tags:b] map[count:1 tags:c]]`},
	{`eventstats count as total | head 1 | table total`, `[map[total:6]]`},
	{`eventstats count as c by action | table action c`, `[map[action:failure c:3] map[action:success c:2] map[action:failure c:3] map[action:failure c:3] map[action:success c:2] map[action:blocked c:1]]`},
	{`eventstats sum(bytes) as b by user | table user b`, `[map[b:300 user:alice] map[b:300 user:alice] map[user:bob] map[] map[user:carol] map[b:300 user:Bob]]`},
	{`streamstats count as k | table k`, `[map[k:1] map[k:2] map[k:3] map[k:4] map[k:5] map[k:6]]`},
	{`streamstats count as k by src | table src k`, `[map[k:1 src:10.0.0.1] map[k:1 src:10.0.0.2] map[k:2 src:10.0.0.1] map[k:1 src:10.0.0.3] map[k:3 src:10.0.0.1] map[k:1 src:10.0.0.4]]`},
	{`streamstats sum(bytes) as run | table run`, `[map[run:100] map[run:300] map[run:300] map[run:350] map[run:350] map[run:650]]`},
	{`streamstats current=f count as k | table k`, `[map[k:0] map[k:1] map[k:2] map[k:3] map[k:4] map[k:5]]`},
	{`eval x=if(isnull(bytes), "none", "some") | stats count by x`, `[map[count:1 x:none] map[count:5 x:some]]`},
	{`eval u=coalesce(user, "unknown") | stats values(u) as u`, `[map[u:[Bob alice bob carol unknown]]]`},
	{`where isnum(bytes) OR isnull(bytes) | eval size=case(bytes>=200, "big", bytes>=100, "mid", true(), "small") | stats count by size`, `[map[count:2 size:big] map[count:1 size:mid] map[count:2 size:small]]`},
	{`eval c=mvcount(tags) | table c`, `[map[c:2] map[c:1] map[] map[c:1] map[] map[c:2]]`},
	{`eval j=mvjoin(tags, "+") | where isnotnull(j) | table j`, `[map[j:a+b] map[j:b] map[j:a] map[j:c+a]]`},
	{`eval f=mvindex(tags, 0) | stats values(f) as f`, `[map[f:[a b c]]]`},
	{`eval s=mvsort(tags) | head 1 | table s`, `[map[s:[a b]]]`},
	{`eval d=mvdedup(mvappend(tags, tags)) | head 1 | eval n=mvcount(d) | table n`, `[map[n:2]]`},
	{`eval h=strftime(_time, "%Y-%m-%d %H:%M") | head 1 | table h`, `[map[h:2026-01-01 05:00]]`},
	{`eval d=relative_time(_time, "@d") | head 1 | table d`, `[map[d:1767225600]]`},
	{`eval w=relative_time(_time, "@w0") | head 1 | table w`, `[map[w:1766880000]]`},
	{`eval m=relative_time(_time, "-1mon@mon") | head 1 | table m`, `[map[m:1764547200]]`},
	{`eval p=strptime("2026-01-02 03:04:05", "%Y-%m-%d %H:%M:%S") | head 1 | table p`, `[map[p:1767323045]]`},
	{`eval l=len("héllo"), s=substr("abcdef", 2, 3), u=upper("ab"), r=replace("a-b-c", "-", "+") | head 1 | table l s u r`, `[map[l:5 r:a+b+c s:bcd u:AB]]`},
	{`eval n=tonumber("1F", 16), t=tostring(1234567, "commas"), r=round(2.456, 1) | head 1 | table n t r`, `[map[n:31 r:2.5 t:1,234,567]]`},
	{`eval x=10/4, y=7%3, z=2+3 | head 1 | table x y z`, `[map[x:2.5 y:1 z:5]]`},
	{`eval s="a"."b".1 | head 1 | table s`, `[map[s:ab1]]`},
	{`eval t=typeof(bytes) | stats values(t) as t`, `[map[t:[Invalid Number String]]]`},
	{`eval b=bytes*2 | where isnotnull(b) | stats sum(b) as s`, `[map[s:1300]]`},
	{`eval x=null() | stats count(x) as c`, `[map[c:0]]`},
	{`rex field=src "\.(?<last>\d+)$" | stats values(last) as last`, `[map[last:[1 2 3 4]]]`},
	{`rex field=user "^(?<first>.)" | stats dc(first) as d`, `[map[d:4]]`},
	{`rename user as account | stats count by account | head 1`, `[map[account:Bob count:1]]`},
	{`fields user, src | head 1`, `[map[src:10.0.0.1 user:alice]]`},
	{`fillnull | table user bytes`, `[map[bytes:100 user:alice] map[bytes:200 user:alice] map[bytes:0 user:bob] map[bytes:50 user:0] map[bytes:x user:carol] map[bytes:300 user:Bob]]`},
	{`fillnull value="-" dest | stats count by dest`, `[map[count:1 dest:-] map[count:2 dest:db1] map[count:2 dest:web1] map[count:1 dest:web2]]`},
	{`mvexpand tags | stats count`, `[map[count:6]]`},
	{`mvexpand tags | stats count by tags`, `[map[count:3 tags:a] map[count:2 tags:b] map[count:1 tags:c]]`},
	{`makemv delim="." src | eval n=mvcount(src) | head 1 | table n`, `[map[n:4]]`},
	{`bin _time span=2h | stats count by _time`, `[map[_time:1767225600 count:2] map[_time:1767232800 count:2] map[_time:1767240000 count:2]]`},
	{`bin bytes span=100 | stats count by bytes`, `[map[bytes:0-100 count:1] map[bytes:100-200 count:1] map[bytes:200-300 count:1] map[bytes:300-400 count:1] map[bytes:x count:1]]`},
	{`join user [| makeresults | eval user="alice", team="red"] | table user team`, `[map[team:red user:alice] map[team:red user:alice]]`},
	{`join type=left user [| makeresults | eval user="alice", team="red"] | stats count(team) as t, count as c`, `[map[c:6 t:2]]`},
	{`append [| makeresults | eval user="dave"] | stats dc(user) as d`, `[map[d:5]]`},
	{`where isnotnull(user) | transaction user | stats count`, `[map[count:4]]`},
	{`where user="alice" | transaction user | table eventcount duration`, `[map[duration:3600 eventcount:2]]`},
	{`addtotals fieldname=t bytes | where isnotnull(t) | stats sum(t) as s`, `[map[s:650]]`},
	{`accum bytes as running | where isnum(running) | stats max(running) as m`, `[map[m:650]]`},
	{`delta _time as gap | head 2 | table gap`, `[map[] map[gap:-3600]]`},
	{`uniq | stats count`, `[map[count:6]]`},
	{`strcat user "@" dest who | head 1 | table who`, `[map[who:alice@web1]]`},
	{`rangemap field=bytes low=0-99 high=100-1000 | stats count by range`, `[map[count:2 range:None] map[count:3 range:high] map[count:1 range:low]]`},
	{`stats count | eval label="total"`, `[map[count:6 label:total]]`},
	{`stats count as c | appendpipe [eval c=c*2]`, `[map[c:6] map[c:12]]`},
}

// semanticDifferences are searches whose rows differ from Splunk's on
// purpose, each documented in docs/query-language.md: splunk is what
// Splunk gives, want what Signalith gives. docs/compatibility.md lists
// them.
var semanticDifferences = []struct{ q, splunk, want string }{
	// A plain where comparison ignores case, so it can run in OpenSearch
	// as a search term does; an expression compares case-sensitively.
	{`where user="bob" | table user`, `[map[user:bob]]`, `[map[user:bob] map[user:Bob]]`},
	{`where user="bob" AND len(user) > 0 | table user`, `[map[user:bob]]`, `[map[user:bob]]`},
}

// TestSemanticCorpus checks searches give the rows Splunk gives, not
// only that they run: the Splunk corpus test counts searches accepted.
// SEMANTIC_DUMP=1 prints every result.
func TestSemanticCorpus(t *testing.T) {
	fixture := semanticFixture()
	cases := semanticCases
	for _, d := range semanticDifferences {
		cases = append(cases, struct{ q, want string }{d.q, d.want})
	}
	for _, c := range cases {
		res, err := (&Engine{}).Run(context.Background(), fixture+" | "+c.q)
		got := ""
		if err != nil {
			got = "error: " + err.Error()
		} else {
			got = fmt.Sprint(res.Rows)
		}
		if os.Getenv("SEMANTIC_DUMP") != "" {
			fmt.Printf("{%q, %q},\n", c.q, got)
			continue
		}
		if got != c.want {
			t.Errorf("%s\n got %s\nwant %s", c.q, got, c.want)
		}
	}
}
