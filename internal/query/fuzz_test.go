package query

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

var fuzzSeeds = []string{
	`datamodel=Authentication action=failure earliest=-24h latest=now`,
	`a=1 b=2 OR c=3`,
	`NOT user=root src IN (10.0.0.1, "10.0.0.2") "failed password" ssh*`,
	"datamodel=Authentication action=failure\n| stats count, dc(user) as users by src, dest\n| where count > 20 AND users >= 2\n| sort -count, src\n| head 5\n| rename src as source\n| table source, count",
	`* | timechart span=1h count by action`,
	`* | top limit=3 user by host`,
	`* | top 5 src`,
	`process_path="C:\Windows\System32\cmd.exe" process="say \"hi\" \\ bye"`,
	`index=signalith-* (user=admin OR user=root) NOT host="web 01"`,
	`process=~"(?i)curl .*://[0-9]{1,3}\\." | threatmatch src, dest | intel`,
	`* | enrich user, dest | fields _time, "a b" | limit 3`,
	`src=10.0.0.0/8 dest=fe80::/10 _time>=-1d@d bytes>1e3`,
	`a=1 | where NOT (x=1 OR y!=2) AND z<3 | sort 10 +dc(user), -max(bytes)`,
	`* | stats distinct_count(user) as u, mean(bytes) by src | rename "a b" as c, d as "e f"`,
	`"AND" "*" "" OR=1`,
	`* | stats median(a), p95(b) as x, perc1(c), stdev(d), var(e), range(f), mode(g), values(h), list(i), first(j), last(k), earliest(l), latest(m) by n | sort -perc1(c)`,
	`a==b c<=d e>f g!=h`,
	`(a=1`, `a="x`, `a=1 | bogus`, `a=1 | head 5 6`, `a ! b`,
	"\xff\xfe(\x00",
	"* | eval kb=round(bytes/1024, 2), u=lower(user) . \"@\" . domain, x=if(a>1 AND NOT b=\"x\", -5, -(3))\n| where len(process) > 100 OR like(user, \"adm%\")",
	`* | rex field=process max_match=0 "(?<flag>-\w+)" | dedup 2 user, host keepempty=true consecutive=true | fillnull value=none a, b`,
	`* | eventstats avg(bytes) as ab by src | rare limit=5 process_name by host`,
	`* | where 'my field' = other_field | eval 'a b'=case(x=1, "one", x=2, "two"), y=coalesce(a, b, "d") XOR c LIKE "a_%"`,
	`x | where name=O'Brien | where (a) = 1 | eval n=-x * 2 - -3 % 4, s=substr(cmd, -5, 2), t=strftime(_time, "%Y-%m-%d")`,
	`* | eval a=`, `* | rex "(?<x"`, `* | dedup`, `* | where NOT`, `* | eval 'x|y'=1 | head 2`,
	`* | where substr("abc", 1, "NaN") = "" OR replace(s, "", s) != s`,
	`* | lookup owners host AS dest, "output" OUTPUTNEW owner AS "as", team | lookup t a`,
	`| inputlookup max=20 owners | where isnull(owner) | lookup owners user OUTPUT team`,
}

// FuzzParse checks that Parse never panics, that its errors carry a
// position inside the query, and that a query it accepts prints as text
// that parses back to the same query.
func FuzzParse(f *testing.F) {
	for _, s := range fuzzSeeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, src string) {
		q, err := Parse(src)
		if err != nil {
			var pe *Error
			if !errors.As(err, &pe) {
				t.Fatalf("Parse(%q) error is %T, want *Error", src, err)
			}
			if pe.Pos < 0 || pe.Pos > len(src) {
				t.Fatalf("Parse(%q) error position %d is outside the query", src, pe.Pos)
			}
			return
		}
		text := q.String()
		q2, err := Parse(text)
		if err != nil {
			t.Fatalf("Parse(%q) printed %q, which does not parse: %v", src, text, err)
		}
		if got := q2.String(); got != text {
			t.Fatalf("round trip unstable for %q:\n%s\n---\n%s", src, text, got)
		}
		if !reflect.DeepEqual(q, q2) {
			t.Fatalf("round trip changed the query for %q:\n%#v\n---\n%#v", src, q, q2)
		}

		// A query the builder can show builds back into text that parses
		// to the same builder model.
		s, ok := FromQuery(q)
		if !ok {
			return
		}
		btext := Build(s).String()
		q3, err := Parse(btext)
		if err != nil {
			t.Fatalf("FromQuery(%q) built %q, which does not parse: %v", src, btext, err)
		}
		// The builder trims the free text, as typed in its box, and
		// counts events, not a field's values.
		want := s
		want.Text = strings.TrimSpace(want.Text)
		if want.AggFunc == "count" {
			want.AggField = ""
		}
		if s3, ok := FromQuery(q3); !ok || !reflect.DeepEqual(s3, want) {
			t.Fatalf("builder round trip for %q via %q:\n got %+v (%v)\nwant %+v", src, btext, s3, ok, want)
		}
	})
}
