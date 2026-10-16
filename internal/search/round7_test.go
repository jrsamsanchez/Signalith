package search

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/query"
)

func TestEvalDottedFieldNames(t *testing.T) {
	events := `{"hits":{"total":{"value":1},"hits":[{"_source":{"@timestamp":"2026-10-15T11:00:00Z","userIdentity":{"userName":"alice","type":"IAMUser"}}}]}}`
	e := &Engine{Store: &fakeStore{responses: []string{events}}}
	res, err := e.Run(context.Background(), `* | head 1 | eval u=userIdentity.userName, j=userIdentity.userName . "@" . userIdentity.type | where userIdentity.type != 'u'`)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Rows) != 1 || res.Rows[0]["u"] != "alice" || res.Rows[0]["j"] != "alice@IAMUser" {
		t.Errorf("rows = %v", res.Rows)
	}
}

func TestWhereComparesQuotedFields(t *testing.T) {
	res := runRound5(t, `* | head 100 | eval other="a" | where user != 'other' | table user`)
	if got := rowsOf(res, "user"); !reflect.DeepEqual(got, []string{"b", "c", "d"}) {
		t.Errorf("rows = %q", got)
	}
	res = runRound5(t, `* | head 100 | eval other="a" | where user = 'other' | table user`)
	if got := rowsOf(res, "user"); !reflect.DeepEqual(got, []string{"a", "a"}) {
		t.Errorf("rows = %q", got)
	}
}

func TestMultivalueFunctions(t *testing.T) {
	src := `| makeresults | eval e=split("a@corp.com,b@x.org,c@corp.com", ","), n=split("1,2,3", ","), k=split("x,y", ",")`
	cases := map[string]any{
		`mvfind(e, "x\\.org$")`:              int64(1),
		`mvfind(e, "^z")`:                    nil,
		`mvzip(k, n)`:                        []any{"x,1", "y,2"},
		`mvzip(k, n, "=")`:                   []any{"x=1", "y=2"},
		`mvfilter(match(e, "@corp\\.com$"))`: []any{"a@corp.com", "c@corp.com"},
		`mvfilter(e="none")`:                 nil,
		`mvmap(n, n * 10)`:                   []any{int64(10), int64(20), int64(30)},
		`mvcount(mvmap(e, if(match(e, "corp"), e, null())))`: int64(2),
	}
	for expr, want := range cases {
		res, err := (&Engine{Store: &fakeStore{}}).Run(context.Background(), src+" | eval r="+expr)
		if err != nil {
			t.Errorf("%s: %v", expr, err)
			continue
		}
		if got := res.Rows[0]["r"]; !reflect.DeepEqual(got, want) {
			t.Errorf("%s = %#v, want %#v", expr, got, want)
		}
		// The field mvmap and mvfilter go through keeps its values.
		if got := res.Rows[0]["n"]; !reflect.DeepEqual(got, []any{"1", "2", "3"}) {
			t.Errorf("%s changed n to %#v", expr, got)
		}
	}
	for _, bad := range []string{`mvfilter(match(e, k))`, `mvmap("x", 1)`} {
		if _, err := (&Engine{Store: &fakeStore{}}).Run(context.Background(), src+" | eval r="+bad); err == nil {
			t.Errorf("%s succeeded", bad)
		}
	}
}

func TestStatsOverEval(t *testing.T) {
	res := runRound5(t, `* | head 100 | stats count(eval(bytes_in>20)) as big, values(eval(upper(user))) as users, sum(eval(bytes_in*2)) as dbl by host`)
	got := rowsOf(res, "host", "big", "dbl")
	if !reflect.DeepEqual(got, []string{"h1 2 220", "h2 1 80"}) {
		t.Errorf("rows = %q", got)
	}
	if v := res.Rows[0]["users"]; !reflect.DeepEqual(v, []any{"A", "B", "D"}) {
		t.Errorf("users = %#v", v)
	}
	if want := []string{"host", "big", "users", "dbl"}; !reflect.DeepEqual(res.Columns, want) {
		t.Errorf("columns = %v", res.Columns)
	}
}

func TestFromJSON(t *testing.T) {
	src := `| makeresults | eval body="{\"user\":\"alice\",\"n\":3,\"ok\":true,\"tags\":[\"a\",\"b\"],\"actor\":{\"id\":7},\"none\":null,\"items\":[{\"x\":1}]}"`
	res, err := (&Engine{Store: &fakeStore{}}).Run(context.Background(), src+" | fromjson body")
	if err != nil {
		t.Fatal(err)
	}
	r := res.Rows[0]
	want := map[string]any{"user": "alice", "n": int64(3), "ok": "true", "tags": []any{"a", "b"}, "actor": `{"id":7}`, "items": `[{"x":1}]`}
	for k, v := range want {
		if !reflect.DeepEqual(r[k], v) {
			t.Errorf("%s = %#v, want %#v", k, r[k], v)
		}
	}
	if _, ok := r["none"]; ok {
		t.Error("null key became a field")
	}
	res, err = (&Engine{Store: &fakeStore{}}).Run(context.Background(), src+" | fromjson body prefix=b_ | table b_user, user")
	if err != nil {
		t.Fatal(err)
	}
	if res.Rows[0]["b_user"] != "alice" || res.Rows[0]["user"] != nil {
		t.Errorf("prefix rows = %v", res.Rows)
	}
	// Text that is not a JSON object leaves the row alone.
	res, err = (&Engine{Store: &fakeStore{}}).Run(context.Background(), `| makeresults | eval body="[1,2]" | fromjson body | fromjson missing`)
	if err != nil || len(res.Rows[0]) > 2 {
		t.Errorf("rows = %v, err %v", res.Rows, err)
	}
	for _, bad := range []string{"fromjson", "fromjson a b", "fromjson a prefix=", "fromjson a other=x"} {
		if _, err := (&Engine{Store: &fakeStore{}}).Run(context.Background(), "| makeresults | "+bad); err == nil {
			t.Errorf("%s parsed", bad)
		}
	}
}

// Nested mvmap over different fields multiplies its work, so the values
// it goes through are capped per search.
func TestNestedMVMapIsCapped(t *testing.T) {
	vals := make([]any, 10000)
	for i := range vals {
		vals[i] = int64(i)
	}
	q, err := query.Parse(`* | eval y=mvmap(x, if(isnull(mvmap(z, if(isnull(mvmap(w, null())), null(), null()))), null(), null()))`)
	if err != nil {
		t.Fatal(err)
	}
	res := &Result{Rows: []Row{{"x": vals, "z": vals, "w": vals}}}
	start := time.Now()
	err = applyEval(withEvaluator(context.Background()), res, q.Commands[0].(*query.Eval))
	if err == nil || !strings.Contains(err.Error(), "10 million values") {
		t.Fatalf("err = %v", err)
	}
	if d := time.Since(start); d > 30*time.Second {
		t.Errorf("took %v", d)
	}
}

func TestFieldCommands(t *testing.T) {
	run := func(q string) *Result {
		t.Helper()
		res, err := (&Engine{Store: &fakeStore{}}).Run(context.Background(), q)
		if err != nil {
			t.Fatalf("%s: %v", q, err)
		}
		return res
	}
	res := run(`| makeresults count=4 | streamstats count as n | eval host="h" . (n % 2), user=if(n < 3, "a", "b") | fields - _time, n | mvcombine user`)
	if len(res.Rows) != 2 || !reflect.DeepEqual(res.Rows[0]["user"], []any{"a", "b"}) || res.Rows[0]["host"] != "h1" {
		t.Errorf("mvcombine rows = %v", res.Rows)
	}
	res = run(`| makeresults | eval r=split("a,b", ",") | nomv r`)
	if res.Rows[0]["r"] != "a\nb" {
		t.Errorf("nomv = %#v", res.Rows[0]["r"])
	}
	res = run(`| makeresults | eval src="10.0.0.1", port=22 | strcat src ":" port addr | strcat allrequired=t src missing other | strcat src missing third`)
	if r := res.Rows[0]; r["addr"] != "10.0.0.1:22" || r["other"] != nil || r["third"] != "10.0.0.1" {
		t.Errorf("strcat row = %v", r)
	}
	res = run(`| makeresults count=3 | streamstats count as n | eval n=n*10 - 15 | rangemap field=n neg=-100--1 low=0-5 mid=5-10 | table n, range`)
	got := []any{res.Rows[0]["range"], res.Rows[1]["range"], res.Rows[2]["range"]}
	if !reflect.DeepEqual(got, []any{"neg", []any{"low", "mid"}, "None"}) {
		t.Errorf("rangemap = %#v", got)
	}
	res = run(`| makeresults | eval bytes_in=2048, bytes_out=4096, other=1 | foreach bytes_* [eval <<FIELD>>=<<FIELD>>/1024 | eval kb_<<MATCHSTR>>=<<FIELD>>] | fieldformat other=other+1`)
	if r := res.Rows[0]; r["bytes_in"] != int64(2) || r["kb_out"] != int64(4) || r["other"] != int64(2) {
		t.Errorf("foreach row = %v", r)
	}
	for _, bad := range []string{"strcat a", `strcat a "x"`, "rangemap field=n", "rangemap field=n a=5-1", "rangemap field=n a=1-2 a=2-3", "foreach a [stats count]", "foreach [eval x=1]", "foreach a**b [eval x=1]", "nomv", "mvcombine"} {
		if _, err := (&Engine{Store: &fakeStore{}}).Run(context.Background(), "| makeresults | "+bad); err == nil {
			t.Errorf("%s parsed", bad)
		}
	}
}
