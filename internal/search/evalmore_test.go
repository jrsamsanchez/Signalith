package search

import (
	"context"
	"reflect"
	"testing"
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
