package search

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/lookuptables"
	"github.com/jrsamsanchez/signalith/internal/query"
)

type testWriter struct {
	refuse error
	wrote  []string
}

func (w *testWriter) Allowed() error { return w.refuse }
func (w *testWriter) Wrote(table string, rows, total int, mode string) {
	w.wrote = append(w.wrote, table+" "+mode+" "+strings.Repeat("r", rows)+" "+strings.Repeat("t", total))
}

func TestOutputLookup(t *testing.T) {
	st, err := lookuptables.Open("")
	if err != nil {
		t.Fatal(err)
	}
	e := &Engine{Lookups: st}
	run := func(ctx context.Context, src string) (*Result, error) {
		t.Helper()
		return e.Run(ctx, src)
	}
	if _, err := run(context.Background(), `| makeresults | eval user="amy" | outputlookup users`); err == nil || !strings.Contains(err.Error(), "presses Run") {
		t.Fatalf("without a writer: %v", err)
	}
	w := &testWriter{}
	ctx := WithLookupWriter(context.Background(), w)
	res, err := run(ctx, `| makeresults count=2 | eval user=mvappend("amy","bob"), _hidden=1 | outputlookup max=1 users.csv | eval after=1`)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Rows) != 2 || res.Rows[0]["after"] == nil {
		t.Errorf("rows after outputlookup = %v", res.Rows)
	}
	tb, _ := st.Get("users")
	if tb == nil || !reflect.DeepEqual(tb.Columns, []string{"_time", "user"}) || len(tb.Rows) != 1 || tb.Rows[0][1] != "amy\nbob" {
		t.Fatalf("table = %+v", tb)
	}
	if _, err := run(ctx, `| makeresults | eval user="cat" | outputlookup users`); err == nil || !strings.Contains(err.Error(), "append=t") {
		t.Errorf("over an existing table: %v", err)
	}
	if _, err := run(ctx, `| makeresults | eval user="cat" | table user | outputlookup append=t users`); err != nil {
		t.Fatal(err)
	}
	if tb, _ = st.Get("users"); len(tb.Rows) != 2 || tb.Rows[1][1] != "cat" {
		t.Errorf("appended = %v", tb.Rows)
	}
	// No rows: append and override_if_empty=f leave the table, append=f
	// empties it, and create_empty=f makes none.
	for _, src := range []string{`| makeresults | where 1=2 | outputlookup append=t users`, `| makeresults | where 1=2 | outputlookup append=f override_if_empty=f users`} {
		if _, err := run(ctx, src); err != nil {
			t.Fatal(err)
		}
		if tb, _ = st.Get("users"); len(tb.Rows) != 2 {
			t.Errorf("%s: rows = %v", src, tb.Rows)
		}
	}
	if _, err := run(ctx, `| makeresults | where 1=2 | outputlookup append=f users`); err != nil {
		t.Fatal(err)
	}
	if tb, _ = st.Get("users"); len(tb.Rows) != 0 {
		t.Errorf("emptied = %v", tb.Rows)
	}
	if _, err := run(ctx, `| makeresults | where 1=2 | outputlookup create_empty=f none`); err != nil {
		t.Fatal(err)
	}
	if _, ok := st.Get("none"); ok {
		t.Error("create_empty=f made a table")
	}
	if want := []string{"users create r t", "users append r tt", "users replace  "}; !reflect.DeepEqual(w.wrote, want) {
		t.Errorf("audited %q, want %q", w.wrote, want)
	}
	// Tables cannot change while several servers share the data.
	w.refuse = errors.New("several servers")
	if _, err := run(ctx, `| makeresults | outputlookup append=t users`); err == nil || !strings.Contains(err.Error(), "several servers") {
		t.Errorf("refused writer: %v", err)
	}
	// A query's commands outside the post-processing path cannot write.
	if _, err := RunCommands(WithLookupWriter(context.Background(), &testWriter{}), []map[string]any{{"a": 1}}, []query.Command{&query.OutputLookup{Table: "x"}}); err == nil {
		t.Error("post rows wrote a table")
	}
}

func TestOutputLookupParse(t *testing.T) {
	for _, bad := range []string{"* | outputlookup", "* | outputlookup Bad", "* | outputlookup append=maybe t", "* | outputlookup key_field=a t", "* | outputlookup t extra", "* | outputlookup max=0 t"} {
		if _, err := query.Parse(bad); err == nil {
			t.Errorf("%s parsed", bad)
		}
	}
	q, err := query.Parse(`* | outputlookup append=t create_empty=f max=5 "users.csv"`)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.ReplaceAll(q.String(), "\n", " "); got != "* | outputlookup append=true create_empty=false max=5 users" {
		t.Errorf("String = %q", got)
	}
	for src, want := range map[string]bool{
		"* | stats count by user":                                         false,
		"* | outputlookup t":                                              true,
		"* | append [search x | outputlookup t]":                          true,
		"* | appendpipe [outputlookup t]":                                 true,
		`* | map search="search user=$user$ | outputLookup t"`:            true,
		"| multisearch [search a] [search b | outputlookup t]":            true,
		"* | join user [search x | stats count by user | outputlookup t]": true,
	} {
		q, err := query.Parse(src)
		if err != nil {
			t.Fatalf("%s: %v", src, err)
		}
		if got := query.WritesLookups(q); got != want {
			t.Errorf("WritesLookups(%s) = %v", src, got)
		}
	}
}

func TestOutputLookupDrilldown(t *testing.T) {
	q, err := query.Parse("* | eval a=1 | outputlookup append=f x | stats count by user")
	if err != nil {
		t.Fatal(err)
	}
	if d := q.Drilldown(); strings.Contains(d.Pipe, "outputlookup") || !strings.Contains(d.Pipe, "eval a=1") {
		t.Errorf("drill pipe = %q", d.Pipe)
	}
}
