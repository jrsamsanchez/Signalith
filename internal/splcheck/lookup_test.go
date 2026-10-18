package splcheck

import (
	"fmt"
	"strings"
	"testing"
)

const pipesMeta = `name: pipes
lookup_type: csv
match_type:
    - WILDCARD(pipe)
min_matches: 1
case_sensitive_match: false
`

const pipesCSV = "pipe,tool\n*-stderr,PsExec\n*\\PSEXESVC*,PsExec\n*CyberGhost*,CyberGhost\n"

func testLookups(t *testing.T, tables ...[2]string) map[string]*Lookup {
	t.Helper()
	out := map[string]*Lookup{}
	for _, tb := range tables {
		l, err := ParseLookup([]byte(tb[0]), []byte(tb[1]))
		if err != nil {
			t.Fatal(err)
		}
		out[l.Name] = l
	}
	return out
}

func TestParseLookup(t *testing.T) {
	l := testLookups(t, [2]string{pipesMeta, pipesCSV})["pipes"]
	if l.Table.Name != "splunk-pipes" || !l.Table.IgnoreCase || len(l.Table.Wildcard) != 1 || l.Table.Wildcard[0] != "pipe" || l.Table.Pack != "splunk" {
		t.Errorf("table %+v", l.Table.Info())
	}
	if l.MaxMatches != splunkMaxMatches || l.HasDefault {
		t.Errorf("max %d default %v", l.MaxMatches, l.HasDefault)
	}
	for meta, want := range map[string]string{
		"name: a\nlookup_type: csv\nmatch_type:\n  - CIDR(ip)\n":       "match_type",
		"name: a\nlookup_type: kvstore\n":                              "not a CSV",
		"name: a\nlookup_type: csv\nfilter: x=1\n":                     "not supported",
		"name: a\nlookup_type: csv\nmin_matches: 2\n":                  "min_matches",
		"name: a\nlookup_type: csv\nmax_matches: 0\n":                  "max_matches",
		"name: a\nlookup_type: csv\nmatch_type:\n  - WILDCARD(nope)\n": "nope",
	} {
		if _, err := ParseLookup([]byte(meta), []byte("pipe,tool\nx,y\n")); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: err = %v, want %q", meta, err, want)
		}
	}
}

// A lookup stage runs on the pack's copy of the table, matching as the
// yml says, and its test events hold a value of a table row.
func TestLookupStage(t *testing.T) {
	lookups := testLookups(t, [2]string{pipesMeta, pipesCSV})
	src := rule("`sysmon` EventCode=17 | stats count by dest pipe_name | lookup local=t pipes pipe AS pipe_name OUTPUT tool | where isnotnull(tool)")
	r, err := ParseWith(src, testMacros, ParseOptions{Lookups: lookups})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(r.Post, "lookup splunk-pipes pipe AS pipe_name OUTPUT tool") || len(r.Lookups) != 1 || r.Lookups[0] != "pipes" {
		t.Fatalf("post:\n%s\nlookups %v", r.Post, r.Lookups)
	}
	for pipe, keep := range map[string]bool{`\\.\pipe\psexesvc-1`: true, `\x-STDERR`: true, `\other`: false} {
		if got := r.Keeps(map[string]any{"dest": "h", "pipe_name": pipe}); got != keep {
			t.Errorf("%s: keeps %v, want %v", pipe, got, keep)
		}
	}
	found := false
	for _, c := range Cases(r) {
		found = found || c.Expect
	}
	if !found {
		t.Error("no test event comes through the lookup")
	}
	// Without the table, the rule does not convert.
	if _, err := ParseWith(src, testMacros, ParseOptions{}); err == nil || !strings.Contains(err.Error(), "does not ship") {
		t.Errorf("no table: err = %v", err)
	}
}

// A stats grouping by an output several rows give splits the row by
// each value first, as Splunk's stats does.
func TestLookupStageGroups(t *testing.T) {
	lookups := testLookups(t, [2]string{pipesMeta, "pipe,tool\n*a*,A\n*b*,B\n"})
	r, err := ParseWith(rule("`sysmon` EventCode=17 | stats count by dest pipe_name | lookup pipes pipe AS pipe_name OUTPUT tool | where isnotnull(tool) | stats count by tool"), testMacros, ParseOptions{Lookups: lookups})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(r.Post, "mvexpand tool") {
		t.Errorf("post:\n%s", r.Post)
	}
	rows, err := r.runPost([]map[string]any{{"dest": "h", "pipe_name": "ab"}})
	if err != nil || len(rows) != 2 {
		t.Errorf("rows %v, %v; want one for each tool", rows, err)
	}
}

func TestLookupStageRefuses(t *testing.T) {
	first := "name: first\nlookup_type: csv\nmatch_type:\n  - WILDCARD(pipe)\nmax_matches: 1\n"
	var many strings.Builder
	many.WriteString("pipe,tool\n")
	for i := range maxPatternRows + 1 {
		fmt.Fprintf(&many, "*p%d*,t\n", i)
	}
	lookups := testLookups(t,
		[2]string{pipesMeta, pipesCSV},
		// A pattern row before a row it matches, which Signalith takes
		// first and Splunk second.
		[2]string{first, "pipe,tool\n*x*,a\nax,b\n"},
		[2]string{"name: many\nlookup_type: csv\nmatch_type:\n  - WILDCARD(pipe)\n", many.String()},
	)
	for search, want := range map[string]string{
		"| lookup pipes pipe AS pipe_name OUTPUT tool | where isnotnull(tool)":               "",
		"| lookup first pipe AS pipe_name OUTPUT tool | where isnotnull(tool)":               "another order",
		"| lookup many pipe AS pipe_name OUTPUT tool | where isnotnull(tool)":                "rows with patterns",
		"| lookup pipes pipe AS pipe_name OUTPUT tool | where tool=\"PsExec\"":               "can give several values",
		"| lookup pipes pipe AS pipe_name OUTPUT dest | where isnotnull(dest)":               "no column",
		"| lookup pipes pipe AS pipe_name OUTPUT tool AS dest | where isnotnull(dest)":       "earlier stage",
		"| eval tool=1 | lookup pipes pipe AS pipe_name OUTPUT tool | where isnotnull(tool)": "earlier stage",
	} {
		src := rule("`sysmon` EventCode=17 | stats count by dest pipe_name " + search)
		_, err := ParseWith(src, testMacros, ParseOptions{Lookups: lookups})
		switch {
		case want == "" && err != nil:
			t.Errorf("%s: %v", search, err)
		case want != "" && (err == nil || !strings.Contains(err.Error(), want)):
			t.Errorf("%s: err = %v, want %q", search, err, want)
		}
	}
}

// A large table without patterns is checked quickly: rows are compared
// by key, not two by two.
func TestLookupShapeLargeExact(t *testing.T) {
	var b strings.Builder
	b.WriteString("k,v\n")
	for i := range 200_000 {
		fmt.Fprintf(&b, "k%d,v%d\n", i, i%7)
	}
	b.WriteString("k1,other\n")
	l := testLookups(t, [2]string{"name: big\nlookup_type: csv\n", b.String()})["big"]
	sh := l.shape([]string{"k"})
	if sh.err != nil || sh.bound != 2 || !sh.differ["v"] || !sh.tableOrder {
		t.Errorf("shape %+v", sh)
	}
}
