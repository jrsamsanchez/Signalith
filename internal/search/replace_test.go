package search

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/query"
)

func TestReplace(t *testing.T) {
	res, err := (&Engine{Store: &fakeStore{}}).Run(context.Background(), `| makeresults | eval src="::ffff:10.0.0.1", op=split("Patch,Create,Other", ","), code="%%8448", _hidden="Patch" | replace "::ffff:*" WITH * IN src | replace "Patch" WITH "updated", "Create", WITH "created", "%%8448" WITH "Success removed"`)
	if err != nil {
		t.Fatal(err)
	}
	r := res.Rows[0]
	if r["src"] != "10.0.0.1" || !reflect.DeepEqual(r["op"], []any{"updated", "created", "Other"}) || r["code"] != "Success removed" || r["_hidden"] != "Patch" {
		t.Errorf("row = %v", r)
	}
	for _, bad := range []string{`replace "a"`, `replace "a" WITH`, `replace "a" WITH "*b"`, `replace "a" WITH "b" IN`, `replace "a" WITH "b" x`} {
		if _, err := (&Engine{Store: &fakeStore{}}).Run(context.Background(), "| makeresults | "+bad); err == nil {
			t.Errorf("%s parsed", bad)
		}
	}
}

func TestXMLKV(t *testing.T) {
	res, err := (&Engine{Store: &fakeStore{}}).Run(context.Background(), `| makeresults | eval Message="<Task><Name>upd&amp;ate</Name><Command attr='1'>cmd.exe</Command><Arg>a</Arg><Arg>b</Arg><Empty/></Task>" | xmlkv Message`)
	if err != nil {
		t.Fatal(err)
	}
	r := res.Rows[0]
	if r["Name"] != "upd&ate" || r["Command"] != "cmd.exe" || !reflect.DeepEqual(r["Arg"], []any{"a", "b"}) || r["Task"] != nil {
		t.Errorf("row = %v", r)
	}
	// Text full of < without > is read in one pass.
	start := time.Now()
	got := xmlElements(strings.Repeat("<", 1<<20)+">", 10)
	if len(got) != 0 || time.Since(start) > 2*time.Second {
		t.Errorf("got %v in %v", got, time.Since(start))
	}
	start = time.Now()
	xmlElements(strings.Repeat("<a ", 1<<18)+">", 10)
	if time.Since(start) > 2*time.Second {
		t.Errorf("took %v", time.Since(start))
	}
}

func TestBitFunctions(t *testing.T) {
	cases := map[string]any{
		`bit_and(12, 10)`:                   int64(8),
		`bit_and(15, 7, 3)`:                 int64(3),
		`bit_or(12, 10)`:                    int64(14),
		`bit_xor(12, 10)`:                   int64(6),
		`bit_not(5, 15)`:                    int64(10),
		`bit_shift_left(1, 4)`:              int64(16),
		`bit_shift_right(256, 4)`:           int64(16),
		`bit_and(-1, 3)`:                    nil,
		`bit_and(1.5, 3)`:                   nil,
		`bit_shift_left(1, 60)`:             nil,
		`bit_and("0x10", 16)`:               nil,
		`bit_and(tonumber("0x10", 16), 16)`: int64(16),
	}
	for expr, want := range cases {
		res, err := (&Engine{Store: &fakeStore{}}).Run(context.Background(), "| makeresults | eval r="+expr)
		if err != nil {
			t.Errorf("%s: %v", expr, err)
			continue
		}
		if got := res.Rows[0]["r"]; !reflect.DeepEqual(got, want) {
			t.Errorf("%s = %#v, want %#v", expr, got, want)
		}
	}
}

// FuzzXMLElements checks that xmlElements never panics and that each pair
// it gives is a tag and text found in the input.
func FuzzXMLElements(f *testing.F) {
	for _, s := range []string{"<a>b</a>", "<Data Name='x'>1</Data><b/>", "<<a>>", "<a><b>c</b></a>", "&lt;<x>&amp;</x>"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		for _, kv := range xmlElements(s, 100) {
			if !strings.Contains(s, "<"+kv[0]) || !strings.Contains(s, "</"+kv[0]+">") {
				t.Fatalf("%q from %q", kv, s)
			}
		}
	})
}

func TestReplaceWildcardScanCountsSteps(t *testing.T) {
	defer func(n int) { maxEvalSteps = n }(maxEvalSteps)
	maxEvalSteps = 10_000_000
	rows := make([]Row, 20)
	big := strings.Repeat("0123456789", 60_000)
	for i := range rows {
		rows[i] = Row{"s": big}
	}
	pairs := make([]string, 0, 100)
	for i := 0; i < 100; i++ {
		pairs = append(pairs, fmt.Sprintf(`"*01234567x%d*" WITH "x"`, i))
	}
	q, err := query.Parse("* | replace " + strings.Join(pairs, ", ") + " IN s")
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	err = applyReplace(withEvaluator(context.Background()), &Result{Rows: rows}, q.Commands[0].(*query.Replace))
	if err == nil || !strings.Contains(err.Error(), "million expressions") {
		t.Fatalf("err = %v", err)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("took %v", d)
	}
}
