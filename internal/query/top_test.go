package query

import (
	"reflect"
	"strings"
	"testing"
)

func TestParseTopOptions(t *testing.T) {
	q, err := Parse(`* | top 5 countfield=n showperc=f useother=t otherstr=rest user by host`)
	if err != nil {
		t.Fatal(err)
	}
	want := &Top{Limit: 5, Fields: []string{"user"}, By: []string{"host"}, CountField: "n", NoPercent: true, UseOther: true, OtherStr: "rest"}
	if got := q.Commands[0]; !reflect.DeepEqual(got, want) {
		t.Errorf("top = %#v", got)
	}
	// Options may follow the fields, and defaults read as no option.
	q, err = Parse(`* | top user limit=3 countfield=count otherstr=OTHER`)
	if err != nil {
		t.Fatal(err)
	}
	if got := q.Commands[0]; !reflect.DeepEqual(got, &Top{Limit: 3, Fields: []string{"user"}}) {
		t.Errorf("top = %#v", got)
	}
	if got := CommandString(q.Commands[0]); got != "top limit=3 user" {
		t.Errorf("printed %q", got)
	}
	for _, bad := range []string{
		`* | top bogus=1 user`,
		`* | top countfield=percent user`,
		`* | top showperc=maybe user`,
		`* | top limit=3`,
	} {
		if _, err := Parse(bad); err == nil {
			t.Errorf("Parse(%q) succeeded", bad)
		}
	}
}

func TestParseSearchCommand(t *testing.T) {
	q, err := Parse(`search index=* user=adm* | stats count by user | search count>2 OR user=root`)
	if err != nil {
		t.Fatal(err)
	}
	if q.Index != "*" || q.Search == nil {
		t.Errorf("leading search not read: %#v", q)
	}
	w, ok := q.Commands[1].(*Where)
	if !ok || !w.Search || w.Name() != "search" {
		t.Fatalf("command = %#v", q.Commands[1])
	}
	if got := CommandString(w); got != "search count>2 OR user=root" {
		t.Errorf("printed %q", got)
	}
	// A field named search is still a field.
	if q, err := Parse(`search=x`); err != nil || q.Search == nil {
		t.Errorf("search=x: %v %#v", err, q)
	}
	for _, bad := range []string{`* | search`, `* | search index=main`, `* | search earliest=-1d x`} {
		if _, err := Parse(bad); err == nil {
			t.Errorf("Parse(%q) succeeded", bad)
		}
	}
}

func TestRenameWildcardsAndSpaces(t *testing.T) {
	q, err := Parse(`* | rename *_ip as * a as b, c AS d`)
	if err != nil {
		t.Fatal(err)
	}
	want := [][2]string{{"*_ip", "*"}, {"a", "b"}, {"c", "d"}}
	if got := q.Commands[0].(*Rename).Pairs; !reflect.DeepEqual(got, want) {
		t.Errorf("pairs = %v", got)
	}
	for _, c := range []struct {
		pair      [2]string
		name, out string
		ok        bool
	}{
		{[2]string{"*_ip", "*"}, "src_ip", "src", true},
		{[2]string{"*_ip", "*"}, "src_ip_x", "", false},
		{[2]string{"Processes.*", "*"}, "Processes.dest", "dest", true},
		{[2]string{"*.*", "*_*"}, "a.b.c", "a_b.c", true},
		{[2]string{"a*a", "b*"}, "a", "", false},
		{[2]string{"a*a", "b*"}, "aa", "b", true},
		{[2]string{"x", "y"}, "x", "y", true},
		{[2]string{"x", "y"}, "xx", "y", false},
	} {
		out, ok := RenameField(c.pair, c.name)
		if ok != c.ok || ok && out != c.out {
			t.Errorf("RenameField(%v, %q) = %q, %v", c.pair, c.name, out, ok)
		}
	}
	for _, bad := range []string{`* | rename *_ip as x`, `* | rename a as *`, `* | rename ** as *`, `* | rename a as b c`} {
		if _, err := Parse(bad); err == nil {
			t.Errorf("Parse(%q) succeeded", bad)
		}
	}
}

func TestParseMultivalueCommands(t *testing.T) {
	q, err := Parse(`* | makemv delim="," r | mvexpand r limit=5 | reverse | addtotals col=t labelfield=host bytes_* | addcoltotals label=All`)
	if err != nil {
		t.Fatal(err)
	}
	want := []Command{
		&MakeMV{Field: "r", Delim: ","},
		&MVExpand{Field: "r", Limit: 5},
		&Reverse{},
		&AddTotals{Fields: []string{"bytes_*"}, Col: true, LabelField: "host"},
		&AddTotals{NoRow: true, Col: true, Label: "All"},
	}
	if !reflect.DeepEqual(q.Commands, want) {
		t.Errorf("commands = %#v", q.Commands)
	}
	if got := CommandString(q.Commands[4]); got != "addtotals row=f col=t label=All" {
		t.Errorf("printed %q", got)
	}
	for _, bad := range []string{
		`* | mvexpand`,
		`* | mvexpand a b`,
		`* | mvexpand a limit=100000`,
		`* | makemv delim=, tokenizer=x a`,
		`* | makemv tokenizer="a*" f`,
		`* | makemv tokenizer="(" f`,
		`* | addtotals row=f`,
		`* | addcoltotals col=t`,
		`* | reverse x`,
	} {
		if _, err := Parse(bad); err == nil {
			t.Errorf("Parse(%q) succeeded", bad)
		} else if strings.Contains(err.Error(), "unknown command") {
			t.Errorf("Parse(%q): %v", bad, err)
		}
	}
}

func TestDrilldownRound5(t *testing.T) {
	q, _ := Parse(`* | stats count by src_ip, user | rename *_ip as * user as src`)
	// user, renamed to src, replaces the src that src_ip became.
	if got := q.Drilldown().Fields; !reflect.DeepEqual(got, map[string]string{"src": "user"}) {
		t.Errorf("rename fields = %v", got)
	}
	q, _ = Parse(`* | top useother=t user by host`)
	if got := q.Drilldown().Fields; !reflect.DeepEqual(got, map[string]string{"host": "host"}) {
		t.Errorf("useother fields = %v", got)
	}
	q, _ = Parse(`* | stats count by host, user | addtotals col=t labelfield=host | mvexpand user`)
	if got := q.Drilldown().Fields; len(got) != 0 {
		t.Errorf("addtotals fields = %v", got)
	}
}
