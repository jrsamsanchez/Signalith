package search

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/lookuptables"
)

func lookupEngine(t *testing.T) *Engine {
	t.Helper()
	st, _ := lookuptables.Open("")
	for name, csv := range map[string]string{
		"owners": "user,owner,team\nbob,Ana,Web\namy,Sam,Data\namy,Kim,Data\n",
		"hosts":  "host,user,site\nh1,bob,Dallas\nh2,bob,Austin\n",
	} {
		if _, err := st.Put(name, []byte(csv)); err != nil {
			t.Fatal(err)
		}
	}
	return &Engine{Store: &fakeStore{responses: []string{evalEvents}}, Lookups: st}
}

func runLookup(t *testing.T, src string) *Result {
	t.Helper()
	res, err := lookupEngine(t).Run(context.Background(), src)
	if err != nil {
		t.Fatalf("Run(%q): %v", src, err)
	}
	return res
}

func TestLookupCommand(t *testing.T) {
	res := runLookup(t, `* | lookup owners user OUTPUT owner, team AS owner_team`)
	got := map[string][2]any{}
	for _, r := range res.Rows {
		if u, ok := r["user"].(string); ok {
			got[u] = [2]any{r["owner"], r["owner_team"]}
		} else if r["owner"] != nil {
			t.Errorf("a row without user got owner %v", r["owner"])
		}
	}
	// amy matches two rows: both owners, and Data twice.
	want := map[string][2]any{"bob": {"Ana", "Web"}, "amy": {[]any{"Sam", "Kim"}, []any{"Data", "Data"}}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
	for _, c := range []string{"owner", "owner_team"} {
		found := false
		for _, col := range res.Columns {
			found = found || col == c
		}
		if !found {
			t.Errorf("columns %v miss %s", res.Columns, c)
		}
	}
}

func TestLookupForms(t *testing.T) {
	// No OUTPUT adds every other column; several keys must all match.
	res := runLookup(t, `* | lookup hosts host, user`)
	for _, r := range res.Rows {
		want := map[string]any{"h1/bob": "Dallas", "h2/bob": "Austin"}[r["host"].(string)+"/"+anyStr(r["user"])]
		if r["site"] != want {
			t.Errorf("%v/%v site = %v, want %v", r["host"], r["user"], r["site"], want)
		}
	}
	// AS matches another field; OUTPUTNEW keeps what is there.
	res = runLookup(t, `* | eval site="known" | lookup hosts host AS host, user AS user OUTPUTNEW site`)
	for _, r := range res.Rows {
		if r["site"] != "known" {
			t.Errorf("OUTPUTNEW replaced site with %v", r["site"])
		}
	}
	res = runLookup(t, `* | eval site="known" | lookup hosts host OUTPUT site`)
	for _, r := range res.Rows {
		want := map[string]any{"h1": "Dallas", "h2": "Austin"}[r["host"].(string)]
		if r["site"] != want {
			t.Errorf("host %v site = %v, want %v", r["host"], r["site"], want)
		}
	}
	// A multivalue field looks up each value; it works after stats too.
	res = runLookup(t, `* | eval users=split("amy,bob", ",") | lookup owners user AS users OUTPUT team`)
	for _, r := range res.Rows {
		if !reflect.DeepEqual(r["team"], []any{"Data", "Data", "Web"}) {
			t.Errorf("team = %#v", r["team"])
		}
	}
}

func anyStr(v any) string {
	s, _ := v.(string)
	return s
}

func TestLookupErrors(t *testing.T) {
	e := lookupEngine(t)
	for src, want := range map[string]string{
		`* | lookup nope user`:               "no lookup table named nope",
		`* | lookup owners nope`:             `no column "nope"`,
		`* | lookup owners user OUTPUT nope`: `no column "nope"`,
	} {
		_, err := e.Run(context.Background(), src)
		var qe *QueryError
		if !errors.As(err, &qe) || !strings.Contains(err.Error(), want) {
			t.Errorf("Run(%q) err = %v, want a QueryError mentioning %q", src, err, want)
		}
	}
	_, err := (&Engine{Store: &fakeStore{responses: []string{evalEvents}}}).Run(context.Background(), `* | lookup owners user`)
	if err == nil || !strings.Contains(err.Error(), "not available") {
		t.Errorf("no store err = %v", err)
	}
}

func TestInputLookup(t *testing.T) {
	e := lookupEngine(t)
	res, err := e.Run(context.Background(), `| inputlookup owners | stats count by team | sort team`)
	if err != nil {
		t.Fatal(err)
	}
	want := []Row{{"team": "Data", "count": int64(2)}, {"team": "Web", "count": int64(1)}}
	if !reflect.DeepEqual(res.Rows, want) {
		t.Errorf("rows = %v", res.Rows)
	}
	res, err = e.Run(context.Background(), `| inputlookup max=2 owners | lookup hosts user OUTPUT site`)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Rows) != 2 || res.Truncated || res.Matched != 3 || !reflect.DeepEqual(res.Columns[:3], []string{"user", "owner", "team"}) {
		t.Errorf("res = %+v", res)
	}
	if res.Rows[0]["site"] == nil || res.Rows[1]["site"] != nil {
		t.Errorf("rows = %v", res.Rows)
	}
	if fs := e.Store.(*fakeStore); len(fs.bodies) != 0 {
		t.Errorf("inputlookup asked OpenSearch: %v", fs.bodies)
	}
	e.Opt.MaxEvents = 1
	if res, err = e.Run(context.Background(), `| inputlookup owners`); err != nil || len(res.Rows) != 1 || !res.Truncated {
		t.Errorf("res = %+v, %v", res, err)
	}
	var qe *QueryError
	if _, err := e.Run(context.Background(), `| inputlookup nope`); !errors.As(err, &qe) || !strings.Contains(err.Error(), "no lookup table named nope") {
		t.Errorf("err = %v", err)
	}
	if _, err := (&Engine{}).Run(context.Background(), `| inputlookup owners`); !errors.As(err, &qe) {
		t.Errorf("err = %v", err)
	}
}

func TestInputLookupSkipsEmptyCells(t *testing.T) {
	st, _ := lookuptables.Open("")
	if _, err := st.Put("t", []byte("a,b\n1,\n,2\n")); err != nil {
		t.Fatal(err)
	}
	res, err := (&Engine{Lookups: st}).Run(context.Background(), `| inputlookup t | where isnull(a)`)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(res.Rows, []Row{{"b": "2"}}) {
		t.Errorf("rows = %v", res.Rows)
	}
}

func TestLookupCountsAgainstTheBudget(t *testing.T) {
	st, _ := lookuptables.Open("")
	if _, err := st.Put("wide", []byte("k,v\na,"+strings.Repeat("x", 1<<20-100)+"\n")); err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	b.WriteString(`{"hits":{"total":{"value":300},"hits":[`)
	for i := range 300 {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(`{"_source":{"@timestamp":"2026-10-15T10:00:00Z","k":"a"}}`)
	}
	b.WriteString(`]}}`)
	e := &Engine{Store: &fakeStore{responses: []string{b.String()}}, Lookups: st}
	_, err := e.Run(context.Background(), `* | sort k | lookup wide k OUTPUT v`)
	var qe *QueryError
	if !errors.As(err, &qe) || !strings.Contains(err.Error(), "MB") {
		t.Fatalf("err = %v", err)
	}
}
