package query

import (
	"reflect"
	"strings"
	"testing"
)

func TestParseLookup(t *testing.T) {
	for src, want := range map[string]*Lookup{
		`* | lookup owners host`: {Table: "owners", Keys: []LookupField{{Column: "host"}}},
		`* | lookup owners host AS dest OUTPUT owner, team AS owner_team`: {Table: "owners",
			Keys: []LookupField{{Column: "host", As: "dest"}}, Outputs: []LookupField{{Column: "owner"}, {Column: "team", As: "owner_team"}}},
		`* | lookup ports port proto as transport outputnew name`: {Table: "ports",
			Keys: []LookupField{{Column: "port"}, {Column: "proto", As: "transport"}}, Outputs: []LookupField{{Column: "name"}}, New: true},
		`* | lookup t "output" AS "my field" OUTPUT "as", b`: {Table: "t",
			Keys: []LookupField{{Column: "output", As: "my field"}}, Outputs: []LookupField{{Column: "as"}, {Column: "b"}}},
	} {
		q, err := Parse(src)
		if err != nil {
			t.Errorf("Parse(%q): %v", src, err)
			continue
		}
		if got := q.Commands[0]; !reflect.DeepEqual(got, want) {
			t.Errorf("Parse(%q) = %+v, want %+v", src, got, want)
		}
		back, err := Parse(q.String())
		if err != nil || !reflect.DeepEqual(back.Commands, q.Commands) {
			t.Errorf("%q printed as %q, which reads back as %+v (%v)", src, q.String(), back, err)
		}
	}
	if got := mustParse(t, `* | lookup owners host as dest output owner`).String(); got != "*\n| lookup owners host AS dest OUTPUT owner" {
		t.Errorf("String() = %q", got)
	}
	for src, want := range map[string]string{
		`* | lookup`:                     "table name",
		`* | lookup Owners host`:         "not a lookup table name",
		`* | lookup owners`:              "column to match",
		`* | lookup owners OUTPUT owner`: "column to match",
		`* | lookup owners host OUTPUT`:  "OUTPUT needs",
		`* | lookup owners host AS`:      `after "as"`,
		`* | lookup owners host = 1`:     "unexpected",
	} {
		_, err := Parse(src)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("Parse(%q) err = %v, want one mentioning %q", src, err, want)
		}
	}
}
