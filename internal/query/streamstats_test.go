package query

import (
	"reflect"
	"strings"
	"testing"
)

func TestParseRoundThreeCommands(t *testing.T) {
	for src, want := range map[string]Command{
		`* | streamstats count`:                                 &StreamStats{Aggs: []Agg{{Func: "count"}}, Current: true},
		`* | streamstats current=f window=3 sum(b) as s by src`: &StreamStats{Aggs: []Agg{{Func: "sum", Field: "b", Alias: "s"}}, By: []string{"src"}, Window: 3},
		`* | bin span=1h _time`:                                 &Bin{Field: "_time", Span: "1h"},
		`* | bucket _time span=5m AS slot`:                      &Bin{Field: "_time", Span: "5m", As: "slot"},
		`* | bin bytes span=100`:                                &Bin{Field: "bytes", Span: "100"},
		`* | regex "^a"`:                                        &Regex{Field: "_raw", Pattern: "^a"},
		`* | regex process!="(?i)enc"`:                          &Regex{Field: "process", Pattern: "(?i)enc", Negate: true},
		`* | regex user=adm.*`:                                  &Regex{Field: "user", Pattern: "adm.*"},
		`* | fields - _raw, tmp_*`:                              &FieldsRemove{Fields: []string{"_raw", "tmp_*"}},
		`* | fields + a, b`:                                     &Table{Fields: []string{"a", "b"}},
		`| makeresults`:                                         &MakeResults{Count: 1},
		`| makeresults count=5`:                                 &MakeResults{Count: 5},
	} {
		q, err := Parse(src)
		if err != nil {
			t.Fatalf("Parse(%q): %v", src, err)
		}
		if got := q.Commands[len(q.Commands)-1]; !reflect.DeepEqual(got, want) {
			t.Errorf("Parse(%q) = %#v, want %#v", src, got, want)
		}
		if _, err := Parse(q.String()); err != nil {
			t.Errorf("%q printed %q: %v", src, q.String(), err)
		}
	}
}

func TestParseAppend(t *testing.T) {
	q, err := Parse(`* | append [search datamodel=Change | stats count by user] | appendpipe [| stats sum(count) as count | eval user="TOTAL"]`)
	if err != nil {
		t.Fatal(err)
	}
	a, ok := q.Commands[0].(*Append)
	if !ok || a.Sub.Datamodel != "Change" || len(a.Sub.Commands) != 1 {
		t.Fatalf("append = %#v", q.Commands[0])
	}
	p, ok := q.Commands[1].(*AppendPipe)
	if !ok || len(p.Commands) != 2 {
		t.Fatalf("appendpipe = %#v", q.Commands[1])
	}
	if got, want := CommandString(p), `appendpipe [stats sum(count) as count | eval user="TOTAL"]`; got != want {
		t.Errorf("printed %q, want %q", got, want)
	}
}

func TestParseRoundThreeErrors(t *testing.T) {
	for src, want := range map[string]string{
		`* | streamstats median(x)`:               "streamstats runs",
		`* | streamstats window=20000 count`:      "at most 10000",
		`* | streamstats reset_on_change=t count`: "unknown streamstats option",
		`* | bin _time`:                           "needs span=",
		`* | bin span=1mon _time`:                 "not a span",
		`* | bin span=1.5h _time`:                 "whole number",
		`* | bin span=0 x`:                        "not a span",
		`* | bin span=1h`:                         "needs a field",
		`* | bin bins=10 _time`:                   "unknown bin option",
		`* | regex`:                               "regex expects",
		`* | regex x="(?=a)"`:                     "regex pattern",
		`x | makeresults`:                         "starts the search",
		`| makeresults count=0`:                   "1 to 10000",
		`| makeresults annotate=t`:                "unknown makeresults option",
		`* | append x [search *]`:                 "only a subsearch",
		`* | append`:                              "needs a subsearch",
		`* | appendpipe [inputlookup t]`:          "cannot run inside appendpipe",
		`* | appendpipe [timechart count]`:        "cannot run inside appendpipe",
		`* | appendpipe [makeresults]`:            "cannot run inside appendpipe",
		`* | appendpipe []`:                       "expected a command",
		`* | appendpipe [head 1 head]`:            "unexpected",
		"* " + strings.Repeat("| append [search * ", 4) + strings.Repeat("]", 4): "at most 3 deep",
		"* " + strings.Repeat("| append [search *] ", 11):                        "at most 10 subsearches",
	} {
		_, err := Parse(src)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("Parse(%q) = %v, want %q", src, err, want)
		}
	}
}
