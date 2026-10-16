package search

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/query"
)

func TestMoreEvalFunctions(t *testing.T) {
	src := `| makeresults | eval j="{\"a\":{\"b\":[1,2]},\"s\":\"x\",\"n\":3}", arr="[\"p\",\"q\"]", t=1792051200`
	cases := map[string]any{
		`spath(j, "s")`:                                   "x",
		`spath(j, "a.b{}")`:                               []any{int64(1), int64(2)},
		`json_extract(j, "n")`:                            int64(3),
		`json_extract(j, "missing")`:                      nil,
		`json_keys(j)`:                                    `["a","n","s"]`,
		`json_valid(j)`:                                   true,
		`json_valid("{")`:                                 false,
		`json_array_to_mv(arr)`:                           []any{"p", "q"},
		`json_object("k", 1, "m", split("a,b", ","))`:     `{"k":1,"m":["a","b"]}`,
		`json_array("x", null(), 2.5)`:                    `["x",null,2.5]`,
		`relative_time(t, "-1d@d")`:                       int64(1791936000),
		`relative_time(t, "@w")`:                          int64(1791676800),
		`relative_time(t, "+2h")`:                         int64(1792058400),
		`relative_time(t, "bad")`:                         nil,
		`mvrange(1, 7, 2)`:                                []any{int64(1), int64(3), int64(5)},
		`printf("%-4s|%05.1f|%x|%%", "ab", 3.14159, 255)`: "ab  |003.1|ff|%",
		`isint(4.0)`:                                      true,
		`isint(4.5)`:                                      false,
		`validate(t > 0, "neg", isnull(j), "has j")`:      "has j",
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
	}
	if res, err := (&Engine{Store: &fakeStore{}}).Run(context.Background(), `| makeresults | eval r=relative_time(now(), "-100000y@y"), m=mvrange(0, 5, 0/0)`); err != nil || res.Rows[0]["r"] != nil {
		t.Errorf("far relative_time: %v %v", res, err)
	}
	for _, bad := range []string{`printf("%1001s", "x")`, `printf("%n", 1)`, `mvrange(0, 100000)`, `json_object("a")`, `validate(true())`} {
		if _, err := (&Engine{Store: &fakeStore{}}).Run(context.Background(), src+" | eval r="+bad); err == nil {
			t.Errorf("%s succeeded", bad)
		}
	}
	// A large start does not stop mvrange from moving on.
	res, err := (&Engine{Store: &fakeStore{}}).Run(context.Background(), `| makeresults | eval r=mvcount(mvrange(100000000000000000, 100000000000000100, 1))`)
	if err != nil || res.Rows[0]["r"] == nil {
		t.Errorf("large mvrange: %v %v", res, err)
	}
}

// Decoding JSON counts toward the step budget by its size, so calls on
// large values cannot run to the search timeout; repeated calls on the
// same value decode it once.
func TestJSONFunctionsCountTheirInput(t *testing.T) {
	defer func(n int) { maxEvalSteps = n }(maxEvalSteps)
	maxEvalSteps = 2_000_000
	big := func(c string) string {
		var b strings.Builder
		b.WriteString("[")
		for b.Len() < 1<<20 {
			b.WriteString(`"` + c + `",`)
		}
		b.WriteString(`"end"]`)
		return b.String()
	}
	rows := make([]Row, 200)
	j, k := big("a"), big("b")
	for i := range rows {
		rows[i] = Row{"j": j, "k": k}
	}
	run := func(src string) error {
		q, err := query.Parse(src)
		if err != nil {
			t.Fatal(err)
		}
		return applyEval(withEvaluator(context.Background()), &Result{Rows: rows}, q.Commands[0].(*query.Eval))
	}
	var same, alternating []string
	for i := 0; i < 50; i++ {
		same = append(same, fmt.Sprintf("x%d=spath(j, \"x\")", i))
		f := "j"
		if i%2 == 1 {
			f = "k"
		}
		alternating = append(alternating, fmt.Sprintf("x%d=json_keys(%s)", i, f))
	}
	if err := run("* | eval " + strings.Join(alternating, ", ")); err == nil || !strings.Contains(err.Error(), "million expressions") {
		t.Errorf("alternating: err = %v", err)
	}
	// One decode for each row's j: about 21 million steps for 20 rows,
	// where 50 decodes each would be a billion.
	maxEvalSteps = 30_000_000
	rows = rows[:20]
	for i := range rows {
		rows[i] = Row{"j": j}
	}
	if err := run("* | eval " + strings.Join(same, ", ")); err != nil {
		t.Errorf("same field: %v", err)
	}
}

// A cancelled search stops at the next JSON decode.
func TestJSONFunctionsStopWhenCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	ev := newEvaluator(ctx)
	if v, _ := ev.callMore("json_keys", []any{`{"a":1}`}); v != nil || ev.err != context.Canceled {
		t.Errorf("v = %v, err = %v", v, ev.err)
	}
}
