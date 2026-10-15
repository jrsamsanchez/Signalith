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
