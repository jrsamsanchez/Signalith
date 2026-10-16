package search

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/query"
)

func evalOn(t *testing.T, src string, r Row) any {
	t.Helper()
	e, err := query.ParseEvalExpr(src)
	if err != nil {
		t.Fatalf("ParseEvalExpr(%q): %v", src, err)
	}
	ev := newEvaluator(context.Background())
	ev.now = time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	v := ev.eval(e, r)
	if ev.err != nil {
		t.Fatalf("eval(%q): %v", src, ev.err)
	}
	return v
}

func TestEvalFunctions(t *testing.T) {
	r := Row{
		"user": "Alice", "bytes_in": int64(200), "bytes_out": int64(5000), "port": "443",
		"cmd":   `powershell.exe -nop -enc SQBFAFgA`,
		"src":   "10.1.2.3",
		"_time": "2026-10-15T08:30:05.123Z",
		"mv":    []any{"b", "a", "b"},
		"pi":    3.14159,
		"empty": "",
	}
	for src, want := range map[string]any{
		`bytes_out / bytes_in`:   int64(25),
		`round(bytes_in / 3, 2)`: 66.67,
		`round(pi)`:              int64(3),
		`bytes_in + port`:        int64(643),
		`"a" + "b"`:              "ab",
		`user . ":" . port`:      "Alice:443",
		`user . missing`:         nil,
		`1 / 0`:                  nil,
		`7 % 3`:                  int64(1),
		`-bytes_in`:              int64(-200),
		`lower(user)`:            "alice",
		`upper(user)`:            "ALICE",
		`len(user)`:              int64(5),
		`substr(user, 2, 3)`:     "lic",
		`substr(user, -3)`:       "ice",
		`substr(user, 1)`:        "Alice",
		`replace(cmd, "-enc (\S+)", "-enc <\1>")`:              `powershell.exe -nop -enc <SQBFAFgA>`,
		`if(bytes_out > bytes_in, "up", "down")`:               "up",
		`case(port = 80, "http", port = 443, "tls")`:           "tls",
		`case(port = 80, "http")`:                              nil,
		`coalesce(missing, empty, user)`:                       "",
		`coalesce(missing, user)`:                              "Alice",
		`mvcount(mv)`:                                          int64(3),
		`mvcount(user)`:                                        int64(1),
		`mvcount(missing)`:                                     nil,
		`mvindex(mv, -1)`:                                      "b",
		`mvindex(mv, 0, 1)`:                                    []any{"b", "a"},
		`mvjoin(mvsort(mvdedup(mv)), ",")`:                     "a,b",
		`split("a,b,c", ",")`:                                  []any{"a", "b", "c"},
		`mvappend(user, mv)`:                                   []any{"Alice", "b", "a", "b"},
		`tonumber("0x1F", 16)`:                                 int64(31),
		`tonumber(port)`:                                       int64(443),
		`tonumber("abc")`:                                      nil,
		`tostring(1234567, "commas")`:                          "1,234,567",
		`tostring(3725, "duration")`:                           "01:02:05",
		`tostring(255, "hex")`:                                 "0xFF",
		`tostring(bytes_in)`:                                   "200",
		`cidrmatch("10.0.0.0/8", src)`:                         true,
		`cidrmatch("192.168.0.0/16", src)`:                     false,
		`match(cmd, "(?i)-EnC\s")`:                             true,
		`like(user, "Al%")`:                                    true,
		`like(user, "al%")`:                                    false,
		`user LIKE "A_ice"`:                                    true,
		`in(port, 80, 443)`:                                    true,
		`isnull(missing) AND isnotnull(user)`:                  true,
		`isnum(bytes_in) AND isstr(user) AND NOT isnum(port)`:  true,
		`typeof(pi) . typeof(user) . typeof(missing)`:          "NumberStringInvalid",
		`nullif(user, "Alice")`:                                nil,
		`min(3, bytes_in, 7)`:                                  int64(3),
		`max(mv)`:                                              "b",
		`abs(-2.5) + floor(1.9) + ceil(1.1)`:                   5.5,
		`pow(2, 10)`:                                           int64(1024),
		`sqrt(-1)`:                                             nil,
		`log(1000)`:                                            int64(3),
		`trim("  x  ")`:                                        "x",
		`ltrim("xxa", "x")`:                                    "a",
		`urldecode("a%20b+c")`:                                 "a b c",
		`md5("abc")`:                                           "900150983cd24fb0d6963f7d28e17f72",
		`sha256("")`:                                           "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		`strftime(_time, "%Y-%m-%d %H:%M:%S.%3N %Z")`:          "2026-10-15 08:30:05.123 UTC",
		`strftime(0, "%F %T")`:                                 "1970-01-01 00:00:00",
		`strptime("2026-10-15 08:30:05", "%Y-%m-%d %H:%M:%S")`: int64(1792053005),
		`now()`: int64(1792065600),
		`now() - strptime("2026-10-15", "%Y-%m-%d") > 3600`: true,
		`user = "alice"`:            false,
		`mv = "a"`:                  true,
		`missing = 1`:               nil,
		`NOT missing = 1`:           nil,
		`bytes_in < "1000"`:         true,
		`"abc" < "abd" XOR false()`: true,
	} {
		got := evalOn(t, src, r)
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s = %#v, want %#v", src, got, want)
		}
	}
}

func TestEvalLimits(t *testing.T) {
	ev := newEvaluator(context.Background())
	e, _ := query.ParseEvalExpr(`s . s`)
	r := Row{"s": strings.Repeat("x", maxEvalValue/2+1)}
	ev.eval(e, r)
	var qe *QueryError
	if !errors.As(ev.err, &qe) || !strings.Contains(qe.Msg, "longer than") {
		t.Errorf("err = %v", ev.err)
	}
	ev = newEvaluator(context.Background())
	e, _ = query.ParseEvalExpr(`split(s, "")`)
	ev.eval(e, Row{"s": strings.Repeat("x", maxMultiValues+1)})
	if ev.err == nil {
		t.Error("split into too many values should fail")
	}
	ev = newEvaluator(context.Background())
	e, _ = query.ParseEvalExpr(`match(s, "(")`)
	ev.eval(e, Row{"s": "x"})
	if !errors.As(ev.err, &qe) {
		t.Errorf("bad regex err = %v", ev.err)
	}
}

const evalEvents = `{"hits":{"total":{"value":4},"hits":[
	{"_source":{"@timestamp":"2026-10-11T10:00:00Z","user":"bob","host":"h1","bytes_in":100,"bytes_out":900,"message":"login user=bob from=10.0.0.5 flags=-a -b"}},
	{"_source":{"@timestamp":"2026-10-11T09:00:00Z","user":"amy","host":"h1","bytes_in":100,"bytes_out":50,"message":"login user=amy from=10.0.0.6"}},
	{"_source":{"@timestamp":"2026-10-11T08:00:00Z","user":"bob","host":"h2","bytes_in":10,"bytes_out":10,"message":"logout user=bob"}},
	{"_source":{"@timestamp":"2026-10-11T07:00:00Z","host":"h2","bytes_in":10,"message":"noise"}}]}}`

func runEvents(t *testing.T, src string) (*Result, *fakeStore) {
	t.Helper()
	fs := &fakeStore{responses: []string{evalEvents}}
	res, err := (&Engine{Store: fs}).Run(context.Background(), src)
	if err != nil {
		t.Fatalf("Run(%q): %v", src, err)
	}
	return res, fs
}

func TestEvalCommand(t *testing.T) {
	res, _ := runEvents(t, `* | eval ratio=round(bytes_out/bytes_in, 1), kind=if(ratio > 1, "out", "in"), user=coalesce(user, "unknown") | table user, ratio, kind`)
	want := []Row{
		{"user": "bob", "ratio": int64(9), "kind": "out"},
		{"user": "amy", "ratio": 0.5, "kind": "in"},
		{"user": "bob", "ratio": int64(1), "kind": "in"},
		{"user": "unknown", "kind": "in"},
	}
	if !reflect.DeepEqual(res.Rows, want) {
		t.Errorf("rows = %v", res.Rows)
	}
}

func TestEvalAddsColumnsBeforeRaw(t *testing.T) {
	res, _ := runEvents(t, `* | eval kb=bytes_in/1024`)
	if n := len(res.Columns); res.Columns[n-1] != RawField || res.Columns[n-2] != "kb" {
		t.Errorf("columns = %v", res.Columns)
	}
}

func TestRexCommand(t *testing.T) {
	res, _ := runEvents(t, `* | rex "user=(?<who>\w+)(?: from=(?<from>\S+))?" | rex max_match=0 "(?<flag>-\w)" | table who, from, flag`)
	want := []Row{
		{"who": "bob", "from": "10.0.0.5", "flag": []any{"-a", "-b"}},
		{"who": "amy", "from": "10.0.0.6"},
		{"who": "bob"},
		{},
	}
	if !reflect.DeepEqual(res.Rows, want) {
		t.Errorf("rows = %v", res.Rows)
	}
	res, _ = runEvents(t, `* | rex field=host "h(?<n>\d)" | stats count by n`)
	if len(res.Rows) != 2 || res.Rows[0]["n"] != "1" || res.Rows[0]["count"] != int64(2) {
		t.Errorf("rows = %v", res.Rows)
	}
}

func TestDedupCommand(t *testing.T) {
	res, fs := runEvents(t, `* | dedup user | table user, host`)
	if fs.bodies[0]["size"] != 10000 {
		t.Errorf("size = %v, want every event for dedup", fs.bodies[0]["size"])
	}
	want := []Row{{"user": "bob", "host": "h1"}, {"user": "amy", "host": "h1"}}
	if !reflect.DeepEqual(res.Rows, want) {
		t.Errorf("rows = %v", res.Rows)
	}
	res, _ = runEvents(t, `* | dedup user keepempty=true | table host`)
	if len(res.Rows) != 3 {
		t.Errorf("keepempty rows = %v", res.Rows)
	}
	res, _ = runEvents(t, `* | dedup 2 host | table host`)
	if len(res.Rows) != 4 {
		t.Errorf("dedup 2 rows = %v", res.Rows)
	}
	res, _ = runEvents(t, `* | dedup host consecutive=true | table host`)
	if !reflect.DeepEqual(res.Rows, []Row{{"host": "h1"}, {"host": "h2"}}) {
		t.Errorf("consecutive rows = %v", res.Rows)
	}
}

func TestFillnullCommand(t *testing.T) {
	res, _ := runEvents(t, `* | fillnull bytes_out | fillnull value=NA user | table user, bytes_out`)
	if got := res.Rows[3]; got["user"] != "NA" || got["bytes_out"] != int64(0) {
		t.Errorf("row = %v", got)
	}
	res, _ = runEvents(t, `* | table user, host | fillnull value=-`)
	if res.Rows[3]["user"] != "-" {
		t.Errorf("row = %v", res.Rows[3])
	}
}

func TestEventStatsCommand(t *testing.T) {
	res, _ := runEvents(t, `* | eventstats count as n, sum(bytes_in) as total by host | where bytes_in * 2 >= total | table user, host, n, total`)
	want := []Row{
		{"user": "bob", "host": "h1", "n": int64(2), "total": int64(200)},
		{"user": "amy", "host": "h1", "n": int64(2), "total": int64(200)},
		{"user": "bob", "host": "h2", "n": int64(2), "total": int64(20)},
		{"host": "h2", "n": int64(2), "total": int64(20)},
	}
	if !reflect.DeepEqual(res.Rows, want) {
		t.Errorf("rows = %v", res.Rows)
	}
}

func TestRareListsLeastCommonFirst(t *testing.T) {
	fs := &fakeStore{responses: []string{`{"hits":{"total":{"value":10}},"aggregations":{"groups":{"buckets":[
		{"key":{"k0":"a"},"doc_count":2},{"key":{"k0":"b"},"doc_count":6},{"key":{"k0":"c"},"doc_count":1}]}}}`}}
	res, err := (&Engine{Store: fs}).Run(context.Background(), `* | rare limit=2 user`)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Rows) != 2 || res.Rows[0]["user"] != "c" || res.Rows[1]["user"] != "a" {
		t.Errorf("rows = %v", res.Rows)
	}
}

func TestWhereExpressionRunsInServer(t *testing.T) {
	res, fs := runEvents(t, `* | where bytes_out > bytes_in AND like(user, "b%") | table user`)
	if q := asJSON(fs.bodies[0]["query"]); strings.Contains(q, "bytes_out") {
		t.Errorf("the expression was sent to OpenSearch: %s", q)
	}
	if !reflect.DeepEqual(res.Rows, []Row{{"user": "bob"}}) {
		t.Errorf("rows = %v", res.Rows)
	}
	// A plain filter before it still runs in OpenSearch.
	_, fs = runEvents(t, `* | where user=bob | where len(user) = 3`)
	if q := asJSON(fs.bodies[0]["query"]); !strings.Contains(q, `"user"`) {
		t.Errorf("the plain where did not reach OpenSearch: %s", q)
	}
}

func TestEvalBadRegexIsAQueryError(t *testing.T) {
	fs := &fakeStore{responses: []string{evalEvents}}
	_, err := (&Engine{Store: fs}).Run(context.Background(), `* | eval x=replace(user, "(", "")`)
	var qe *QueryError
	if !errors.As(err, &qe) {
		t.Errorf("err = %v, want a QueryError", err)
	}
}

func TestEvalStopsWhenCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res := &Result{Rows: []Row{{"a": int64(1)}}}
	c := &query.Eval{Assigns: []query.Assign{{Field: "b", Expr: &query.Field{Name: "a"}}}}
	if err := applyCommand(ctx, res, c); !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v", err)
	}
}

func evalErr(t *testing.T, ev *evaluator, src string, r Row) error {
	t.Helper()
	e, err := query.ParseEvalExpr(src)
	if err != nil {
		t.Fatalf("ParseEvalExpr(%q): %v", src, err)
	}
	ev.eval(e, r)
	return ev.err
}

func TestEvalMultivalueBytesCount(t *testing.T) {
	// A list of copies shares memory, but writing it out copies each value,
	// so its bytes count against the limits.
	s := strings.Repeat("x", 200<<10)
	err := evalErr(t, newEvaluator(context.Background()), `mvappend(s, s, s, s, s, s)`, Row{"s": s})
	if err == nil || !strings.Contains(err.Error(), "longer than") {
		t.Errorf("err = %v, want the value size limit", err)
	}
	// Nesting does not get around it.
	err = evalErr(t, newEvaluator(context.Background()), `mvappend(mvappend(s, s, s), mvappend(s, s, s))`, Row{"s": s})
	if err == nil {
		t.Error("nested mvappend past the limit should fail")
	}
}

func TestEvalBudgetCoversTheWholeSearch(t *testing.T) {
	// Each eval stays under the budget; together they do not.
	s := strings.Repeat("x", 100<<10)
	rows := make([]Row, 160)
	for i := range rows {
		rows[i] = Row{"s": s}
	}
	res := &Result{Rows: rows}
	ctx := withEvaluator(context.Background())
	c := &query.Eval{Assigns: []query.Assign{{Field: "m", Expr: mustEval(t, `mvappend(s, s, s, s, s, s, s, s, s)`)}}}
	if err := applyCommand(ctx, res, c); err != nil {
		t.Fatalf("first eval: %v", err)
	}
	if err := applyCommand(ctx, res, c); err == nil || !strings.Contains(err.Error(), "MB of values") {
		t.Errorf("second eval err = %v, want the search budget", err)
	}
	if evaluatorFor(ctx) != evaluatorFor(ctx) {
		t.Error("one search should share one evaluator")
	}
}

func mustEval(t *testing.T, src string) query.EvalExpr {
	t.Helper()
	e, err := query.ParseEvalExpr(src)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func TestEvalReplaceChecksSizeAsItGrows(t *testing.T) {
	s := strings.Repeat("ab", 1<<10)
	start := time.Now()
	err := evalErr(t, newEvaluator(context.Background()), `replace(s, "", s)`, Row{"s": s})
	if err == nil || !strings.Contains(err.Error(), "longer than") {
		t.Errorf("err = %v, want the value size limit", err)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("took %v", d)
	}
	err = evalErr(t, newEvaluator(context.Background()), `mvjoin(split(s, ""), s)`, Row{"s": s})
	if err == nil || !strings.Contains(err.Error(), "longer than") {
		t.Errorf("mvjoin err = %v, want the value size limit", err)
	}
	// Results match regexp's own ReplaceAllString.
	for _, c := range [][3]string{
		{"aXbXc", "X", "-"}, {"abc", "", "-"}, {"abab", "(a)(b)", "${2}${1}"}, {"xyz", "q*", "!"},
		{"héllo", "", "."}, {"aaa", "a*", "b"}, {"a.b", `\.`, "$$"},
	} {
		re := regexp.MustCompile(c[1])
		got := newEvaluator(context.Background()).replace(re, c[0], c[2])
		if want := re.ReplaceAllString(c[0], c[2]); got != want {
			t.Errorf("replace(%q, %q, %q) = %v, want %q", c[0], c[1], c[2], got, want)
		}
	}
}

func TestEvalSubstrRejectsNaN(t *testing.T) {
	r := Row{"n": "NaN", "mv": []any{"a", "b"}}
	for _, src := range []string{
		`substr("abc", 1, "NaN")`, `substr("abc", "NaN")`, `substr("abc", n, n)`, `substr("abc", 1, "Inf")`,
		`mvindex(mv, "NaN")`, `mvindex(mv, 0, "Inf")`,
	} {
		if got := evalOn(t, src, r); got != nil {
			t.Errorf("%s = %#v, want null", src, got)
		}
	}
	for src, want := range map[string]any{
		`substr("abc", 1e300)`: "", `substr("abc", -1e300)`: "abc", `substr("abc", 2, 1e300)`: "bc",
	} {
		if got := evalOn(t, src, r); got != want {
			t.Errorf("%s = %#v, want %#v", src, got, want)
		}
	}
}

func TestEvalRecoversFromPanics(t *testing.T) {
	// A call with fewer arguments than the parser allows reaches past the
	// end of its arguments; the search fails instead of the server.
	res := &Result{Rows: []Row{{"a": int64(1)}}}
	c := &query.Eval{Assigns: []query.Assign{{Field: "b", Expr: &query.Call{Func: "mvcount"}}}}
	err := applyCommand(context.Background(), res, c)
	var qe *QueryError
	if !errors.As(err, &qe) {
		t.Errorf("err = %v, want a QueryError", err)
	}
}

func TestEvalStopsWithinARow(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	mv := make([]any, 1000)
	for i := range mv {
		mv[i] = "value"
	}
	err := evalErr(t, newEvaluator(ctx), `match(mv, "^nope$")`, Row{"mv": mv})
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled", err)
	}
}

// FuzzEvalCommands checks that eval, where expressions, rex, dedup,
// fillnull and eventstats never panic on queries Parse accepts, whatever
// the rows hold.
func FuzzEvalCommands(f *testing.F) {
	for _, s := range []string{
		`* | eval x=round(a/b, 2), y=lower(s) . "-" . substr(s, -2), z=if(a > b, mvindex(split(s, ","), -1), null())`,
		`* | where len(s) > 2 OR like(s, "%b_") XOR cidrmatch("10.0.0.0/8", ip)`,
		`* | rex field=s max_match=0 "(?<w>\w+)" | dedup 2 w keepempty=true | fillnull value=0`,
		`* | eventstats count, dc(s) as d, avg(a) by s | eval t=strftime(a, "%F %T %3N"), u=strptime(s, "%Y-%m-%d")`,
		`* | eval m=mvappend(s, s, a), n=mvjoin(mvsort(mvdedup(m)), ";"), h=sha256(n), c=tostring(a, "commas")`,
		`* | eval r=replace(s, "(a)(b)?", "\2\1$1"), p=pow(a, b), l=log(a, b), q=tonumber(s, 36)`,
		`* | eval x=substr("abc", 1, "NaN"), y=substr(s, a), z=mvindex(s, "NaN"), w=substr(s, 1e300, -1e300)`,
		`* | eval x=replace(s, "", s) | eval y=mvjoin(mvappend(x, x, x), x)`,
		`* | eval p=printf("%-5s|%05.1f|%x|%c|%%", s, a, a, a), r=relative_time(a, s), m=mvrange(a, b, 0.5), j=json_object(s, a, "m", mvrange(0, b)), k=json_keys(j), v=spath(j, s), w=json_array_to_mv(json_array(s, a)), i=validate(isint(a), s)`,
	} {
		f.Add(s, "a,b,10.1.2.3", 3.5)
	}
	f.Fuzz(func(t *testing.T, src, s string, a float64) {
		q, err := query.Parse(src)
		if err != nil {
			return
		}
		res := &Result{Kind: "events", Columns: []string{"s", "a"}, Rows: []Row{
			{"s": s, "a": a, "b": int64(2), "ip": s},
			{"s": []any{s, "x"}, "a": s},
			{},
		}}
		ctx := withEvaluator(context.Background())
		for _, c := range q.Commands {
			switch c.(type) {
			case *query.Enrich, *query.Intel, *query.ThreatMatch, *query.Timechart:
				continue
			}
			if err := applyCommand(ctx, res, c); err != nil {
				// A recovered panic is still a bug.
				if strings.Contains(err.Error(), "an expression failed") {
					t.Fatalf("%q: %v", src, err)
				}
				return
			}
		}
	})
}

func TestEvalChargesCopiedValues(t *testing.T) {
	// Copying a field builds nothing new, but every copy is written out
	// with the result, so it counts against the search's budget.
	s := strings.Repeat("x", 900<<10)
	rows := make([]Row, 40)
	for i := range rows {
		rows[i] = Row{"s": s}
	}
	res := &Result{Rows: rows}
	assigns := make([]query.Assign, 10)
	for i := range assigns {
		assigns[i] = query.Assign{Field: fmt.Sprintf("c%d", i), Expr: mustEval(t, `if(true(), s, s)`)}
	}
	err := applyCommand(withEvaluator(context.Background()), res, &query.Eval{Assigns: assigns})
	if err == nil || !strings.Contains(err.Error(), "MB of values") {
		t.Errorf("err = %v, want the search budget", err)
	}
	// A value the expression built is counted once, with the new field t.
	ev := newEvaluator(context.Background())
	res = &Result{Rows: []Row{{"s": "abc"}}}
	if err := applyEval(context.WithValue(context.Background(), evaluatorKey{}, ev), res, &query.Eval{Assigns: []query.Assign{{Field: "t", Expr: mustEval(t, `s."def"`)}}}); err != nil || ev.produced != 6+1+fieldOverhead {
		t.Errorf("err = %v, produced = %d, want %d", err, ev.produced, 6+1+fieldOverhead)
	}
}

func TestEventStatsChargesEachRow(t *testing.T) {
	// 300 rows of 20 KB: values() gives every row 100 of them, 600 MB in
	// all, past the search's budget.
	rows := make([]Row, 300)
	for i := range rows {
		rows[i] = Row{"m": fmt.Sprint(i) + strings.Repeat("x", 20<<10)}
	}
	res := &Result{Rows: rows}
	c := &query.EventStats{Aggs: []query.Agg{{Func: "values", Field: "m", Alias: "v"}}}
	err := applyCommand(withEvaluator(context.Background()), res, c)
	if err == nil || !strings.Contains(err.Error(), "MB of values") {
		t.Errorf("err = %v, want the search budget", err)
	}
	// Small results are unchanged.
	res = &Result{Rows: []Row{{"m": "a"}, {"m": "b"}}}
	if err := applyCommand(withEvaluator(context.Background()), res, c); err != nil || !reflect.DeepEqual(res.Rows[0]["v"], []any{"a", "b"}) {
		t.Errorf("err = %v, rows = %v", err, res.Rows)
	}
}

func TestCommandsCannotGrowResultsWithoutLimit(t *testing.T) {
	// Each command shares one 4 KB value among 10,000 rows, which costs
	// nothing to build but 40 MB to write out; ten of them pass the limit.
	wide := strings.Repeat("x", 4000)
	for name, cmd := range map[string]string{
		"fillnull": `fillnull value="` + wide + `" a%d`,
		"rex":      `rex field=s "(?<a%d>.*)"`,
	} {
		t.Run(name, func(t *testing.T) {
			q := `| makeresults count=10000 | eval s="` + wide + `"`
			for i := range 10 {
				q += " | " + fmt.Sprintf(cmd, i)
			}
			e := &Engine{Store: &fakeStore{}}
			_, err := e.Run(context.Background(), q)
			var qe *QueryError
			if !errors.As(err, &qe) || !strings.Contains(err.Error(), "MB") {
				t.Fatalf("err = %v", err)
			}
			// Fewer of them are fine.
			q = `| makeresults count=10000 | eval s="` + wide + `" | ` + fmt.Sprintf(cmd, 0)
			if _, err := e.Run(context.Background(), q); err != nil {
				t.Fatal(err)
			}
		})
	}
}
