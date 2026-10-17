package query

import (
	"reflect"
	"strings"
	"testing"
)

func mustParse(t *testing.T, src string) *Query {
	t.Helper()
	q, err := Parse(src)
	if err != nil {
		t.Fatalf("Parse(%q): %v", src, err)
	}
	return q
}

func TestParseSpecialTerms(t *testing.T) {
	q := mustParse(t, `datamodel=Authentication action=failure earliest=-24h latest=now`)
	if q.Datamodel != "Authentication" || q.Earliest != "-24h" || q.Latest != "now" {
		t.Fatalf("special terms not extracted: %+v", q)
	}
	c, ok := q.Search.(*Compare)
	if !ok || c.Field != "action" || c.Op != "=" || c.Value != "failure" {
		t.Fatalf("search = %#v", q.Search)
	}
}

func TestSearchPrecedenceFollowsSPL(t *testing.T) {
	// OR binds tighter than the implicit AND.
	q := mustParse(t, `a=1 b=2 OR c=3`)
	and, ok := q.Search.(*And)
	if !ok || len(and.Children) != 2 {
		t.Fatalf("want And of 2, got %s", q.Search)
	}
	if _, ok := and.Children[1].(*Or); !ok {
		t.Fatalf("second child should be Or, got %s", and.Children[1])
	}
}

func TestParseNotInAndText(t *testing.T) {
	q := mustParse(t, `NOT user=root src IN (10.0.0.1, "10.0.0.2") "failed password" ssh*`)
	and := q.Search.(*And)
	if len(and.Children) != 4 {
		t.Fatalf("children = %d: %s", len(and.Children), q.Search)
	}
	if _, ok := and.Children[0].(*Not); !ok {
		t.Errorf("child 0 = %s", and.Children[0])
	}
	in := and.Children[1].(*In)
	if in.Field != "src" || len(in.Values) != 2 || in.Values[1] != "10.0.0.2" {
		t.Errorf("in = %#v", in)
	}
	if tx := and.Children[2].(*Text); tx.Value != "failed password" {
		t.Errorf("text = %#v", tx)
	}
}

func TestParseStatsPipeline(t *testing.T) {
	q := mustParse(t, `datamodel=Authentication action=failure
| stats count, dc(user) as users by src, dest
| where count > 20 AND users >= 2
| sort -count, src
| head 5
| rename src as source
| table source, count`)
	if len(q.Commands) != 6 {
		t.Fatalf("commands = %d", len(q.Commands))
	}
	st := q.Commands[0].(*Stats)
	if len(st.Aggs) != 2 || st.Aggs[1].Column() != "users" || st.Aggs[0].Column() != "count" {
		t.Errorf("aggs = %+v", st.Aggs)
	}
	if strings.Join(st.By, ",") != "src,dest" {
		t.Errorf("by = %v", st.By)
	}
	so := q.Commands[2].(*Sort)
	if !so.Keys[0].Desc || so.Keys[0].Field != "count" || so.Keys[1].Desc {
		t.Errorf("sort = %+v", so.Keys)
	}
	if q.Commands[3].(*Head).N != 5 {
		t.Errorf("head")
	}
}

func TestParseTimechartAndTop(t *testing.T) {
	q := mustParse(t, `* | timechart span=1h count by action`)
	tc := q.Commands[0].(*Timechart)
	if tc.Span != "1h" || tc.By != "action" || tc.Aggs[0].Func != "count" {
		t.Errorf("timechart = %+v", tc)
	}
	q = mustParse(t, `* | top limit=3 user by host`)
	top := q.Commands[0].(*Top)
	if top.Limit != 3 || top.Fields[0] != "user" || top.By[0] != "host" {
		t.Errorf("top = %+v", top)
	}
	q = mustParse(t, `* | top 5 src`)
	if q.Commands[0].(*Top).Limit != 5 {
		t.Errorf("top shorthand limit")
	}
}

func TestParseErrorsArePositioned(t *testing.T) {
	cases := map[string]string{
		`a=1 | bogus`:         "unknown command",
		`a=1 | stats avg`:     "avg needs a field",
		`a=1 | stats foo(x)`:  "unknown function",
		`(a=1`:                "unmatched",
		`a="x`:                "unterminated",
		`a=1 | where`:         "expected",
		`a=1 | sort`:          "sort needs",
		`a=1 | stats count x`: "unknown function",
		`a=1 | head 5 6`:      "unexpected",
	}
	for src, want := range cases {
		_, err := Parse(src)
		if err == nil {
			t.Errorf("Parse(%q): want error containing %q", src, want)
			continue
		}
		if !strings.Contains(err.Error(), want) {
			t.Errorf("Parse(%q) = %v, want %q", src, err, want)
		}
		if _, ok := err.(*Error); !ok {
			t.Errorf("Parse(%q) error is %T, want *Error", src, err)
		}
	}
}

func TestRoundTrip(t *testing.T) {
	srcs := []string{
		`datamodel=Authentication action=failure (user=admin OR user=root) earliest=-24h
| stats count, dc(src) as sources by user
| where count > 5 OR sources > 2
| sort -count
| head 10`,
		`NOT host="web 01" src IN (1.2.3.4, 5.6.7.8)
| timechart span=1h count by action`,
		`"failed password"
| top limit=5 src by host
| rename src as source
| table source, count`,
	}
	for _, src := range srcs {
		q1 := mustParse(t, src)
		text := q1.String()
		q2 := mustParse(t, text)
		if q2.String() != text {
			t.Errorf("round trip unstable:\n%s\n---\n%s", text, q2.String())
		}
	}
}

func TestBackslashesInQuotedStrings(t *testing.T) {
	q, err := Parse(`process_path="C:\Windows\System32\cmd.exe" process="say \"hi\" \\ bye"`)
	if err != nil {
		t.Fatal(err)
	}
	and := q.Search.(*And)
	if v := and.Children[0].(*Compare).Value; v != `C:\Windows\System32\cmd.exe` {
		t.Errorf("path = %q", v)
	}
	if v := and.Children[1].(*Compare).Value; v != `say "hi" \ bye` {
		t.Errorf("escapes = %q", v)
	}
	q2, err := Parse(q.String())
	if err != nil || q2.String() != q.String() {
		t.Errorf("round trip: %v %s", err, q2)
	}
}

// Queries FuzzParse found printing as text that parses to something else,
// or not at all.
func TestRoundTripFuzzFindings(t *testing.T) {
	for _, src := range []string{
		`* | fields _time, "a b"`, // a column name with a space
		`* | stats count as "a b" | rename "a b" as "c d", dc(x) as e`,
		`"*"`,                         // a quoted * is a search term
		`* | top 0 0`,                 // limit 0 is no limit, not the default
		`* | top limit=0 x`,           // the same
		`0="~"`,                       // not =~
		`* | sort ++, +-x, --y`,       // a second sign is part of the name
		`(* a) OR b`,                  // * inside parentheses
		`* | table dc(user), "max(x"`, // a stats column stays bare
	} {
		q := mustParse(t, src)
		text := q.String()
		q2, err := Parse(text)
		if err != nil {
			t.Errorf("%s printed %q, which does not parse: %v", src, text, err)
			continue
		}
		if !reflect.DeepEqual(q, q2) {
			t.Errorf("%s printed %q, which parses to\n%#v\nnot\n%#v", src, text, q2, q)
		}
	}
	if got := mustParse(t, `* | table dc(user)`).String(); got != "*\n| table dc(user)" {
		t.Errorf("table dc(user) printed %q", got)
	}
}

func TestParseStarTerms(t *testing.T) {
	if q := mustParse(t, `a OR *`); q.Search != nil {
		t.Errorf("a OR * = %s, want every event", q.Search)
	}
	if q := mustParse(t, `(*) a`); q.Search.String() != "a" {
		t.Errorf("(*) a = %s", q.Search)
	}
	for _, src := range []string{`NOT *`, `OR>0 x`, `a OR=1`, `OR IN (1)`, `IN>0 x`} {
		if _, err := Parse(src); err == nil {
			t.Errorf("Parse(%q): want an error", src)
		}
	}
}

// A form feed or vertical tab once made the lexer loop forever.
func TestLexAllASCIISpaces(t *testing.T) {
	q := mustParse(t, "a\fb\vc")
	if and, ok := q.Search.(*And); !ok || len(and.Children) != 3 {
		t.Errorf("search = %s", q.Search)
	}
}

func TestSearchStarKeepsEveryRow(t *testing.T) {
	for src, want := range map[string]string{
		`* | search * | stats count`:                         "*\n| stats count",
		`* | stats count by user | search *`:                 "*\n| stats count by user",
		`* | search * user=x`:                                "*\n| search user=x",
		`* | stats count | appendpipe [search * | eval a=1]`: "*\n| stats count\n| appendpipe [eval a=1]",
	} {
		q, err := Parse(src)
		if err != nil {
			t.Fatalf("Parse(%q): %v", src, err)
		}
		if got := q.String(); got != want {
			t.Errorf("Parse(%q) = %q, want %q", src, got, want)
		}
	}
}

func TestSplunkSyntaxForms(t *testing.T) {
	for src, want := range map[string]string{
		`* | rename "All_Traffic".* as *`:                      "*\n| rename All_Traffic.* as *",
		`"requestParameters.masterUserPassword"=* x=1`:         "requestParameters.masterUserPassword=* x=1",
		`"query_type{}" IN (SIG,KEY)`:                          "query_type{} IN (SIG, KEY)",
		`process IN ("a", "b",)`:                               "process IN (a, b)",
		`* | sort - count, + user`:                             "*\n| sort -count, user",
		`* | eval s=if(type IN ("A", "B") AND res="ok", 1, 0)`: "*\n| eval s=if(in(type, \"A\", \"B\") AND res = \"ok\", 1, 0)",
		`* | where NOT x IN (1, 2)`:                            "*\n| where NOT x IN (1, 2)",
		`* | inputlookup append=t max=5 owners`:                "*\n| inputlookup append=true max=5 owners",
		`| makeresults | inputlookup b append=t`:               "*\n| makeresults\n| inputlookup append=true b",
		`user=x NOT [inputlookup t | fields a]`:                "user=x NOT [search *\n| inputlookup t\n| table a]",
		`| inputlookup a | inputlookup append=true b`:          "*\n| inputlookup a\n| inputlookup append=true b",
	} {
		q, err := Parse(src)
		if err != nil {
			t.Errorf("Parse(%q): %v", src, err)
			continue
		}
		if got := q.String(); got != want {
			t.Errorf("Parse(%q) = %q, want %q", src, got, want)
		}
		if _, err := Parse(q.String()); err != nil {
			t.Errorf("Parse(%q) does not read back: %v", q.String(), err)
		}
	}
	for _, bad := range []string{`user=x | inputlookup owners`, `user=x | inputlookup append=false owners`, "| makeresults" + strings.Repeat(" | inputlookup append=t t", 11), `* | transaction user startswith=( [ | makeresults | eval a=1 ] )`, `* | transaction user endswith=(NOT [inputlookup t])`, `* | sort -`, `* | stats count | appendpipe [inputlookup append=t x]`} {
		if _, err := Parse(bad); err == nil {
			t.Errorf("%s parsed", bad)
		}
	}
}
