// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package query

import (
	"reflect"
	"strings"
	"testing"
)

func TestParseJoin(t *testing.T) {
	sub := func(src string) *Query { return mustParse(t, src) }
	for src, want := range map[string]*Join{
		`* | join user [search datamodel=Change | stats count as changes by user]`: {Fields: []string{"user"}, Max: 1,
			Sub: sub(`datamodel=Change | stats count as changes by user`)},
		`* | join type=left max=0 host, "my user" [ action=failure "a [b]" | where x="]" ] | head 2`: {Fields: []string{"host", "my user"},
			Left: true, Sub: sub(`action=failure "a [b]" | where x="]"`)},
		`* | JOIN type=inner max=5 src [search]`:                      {Fields: []string{"src"}, Max: 5, Sub: sub(`*`)},
		`* | join a [search * | join b [search c=1 | inputlookup t]]`: nil, // checked below
		"* | join a [search\t| inputlookup t]":                        {Fields: []string{"a"}, Max: 1, Sub: sub(`| inputlookup t`)},
	} {
		q, err := Parse(src)
		if want == nil {
			if err == nil || !strings.Contains(err.Error(), "starts the search") {
				t.Errorf("Parse(%q) = %v", src, err)
			}
			continue
		}
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
	nested := mustParse(t, `* | join a [search * | join b [search c=1 | head 1]] | stats count`)
	if j := nested.Commands[0].(*Join); len(nested.Commands) != 2 || len(j.Sub.Commands) != 1 {
		t.Errorf("nested = %+v", nested.Commands)
	}
	for src, want := range map[string]string{
		`* | join user`:                      "subsearch in [ ]",
		`* | join user [search a`:            "subsearch in [ ]",
		`* | join [search a]`:                "fields to match",
		`* | join type=full user [search a]`: "inner or left",
		`* | join max=101 user [search a]`:   "join max",
		`* | join usertype=x u [search a]`:   "unknown join option",
		`* | join user [search a] extra`:     "unexpected",
		`* | join user [search a=]`:          "",
		`* | join a [search | join b [search | join c [search | join d [search x]]]]`: "at most 3 deep",
		`* | join "a[" [search x]`:                       "cannot hold",
		"*" + strings.Repeat(` | join a [search x]`, 11): "at most 10 subsearches",
	} {
		_, err := Parse(src)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("Parse(%q) = %v, want an error with %q", src, err, want)
		}
	}
	if _, err := Parse(`* | join user [search a=]`); err != nil {
		if pe, ok := err.(*Error); !ok || pe.Pos < len(`* | join user [search a`) {
			t.Errorf("error position = %v", err)
		}
	}
}
