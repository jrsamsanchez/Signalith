// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package query

import (
	"reflect"
	"testing"
)

func TestParseSed(t *testing.T) {
	for in, want := range map[string]Sed{
		`s/a/b/`:           {Find: "a", Replace: "b"},
		`s/a/b/g`:          {Find: "a", Replace: "b", Global: true},
		`s/a/b/3`:          {Find: "a", Replace: "b", Nth: 3},
		`s/a/b/1`:          {Find: "a", Replace: "b"},
		`s|/x|\||`:         {Find: "/x", Replace: "|"},
		`s/(\w+)@/\1 at /`: {Find: `(\w+)@`, Replace: `\1 at `},
		`y/abc/xyz/`:       {Y: true, Find: "abc", Replace: "xyz"},
	} {
		got, err := ParseSed(in)
		if err != nil {
			t.Errorf("ParseSed(%q): %v", in, err)
			continue
		}
		if !reflect.DeepEqual(*got, want) {
			t.Errorf("ParseSed(%q) = %#v", in, *got)
		}
	}
	for _, bad := range []string{``, `s/a/`, `x/a/b/`, `sa/b/c/`, `s//b/`, `s/(/b/`, `s/a/b/q`, `s/a/b/0`, `y/ab/x/`, `y/a/b/g`,
		`s/a/` + "\\1\\1\\1\\1\\1\\1\\1\\1\\1\\1\\1" + `/`} {
		if _, err := ParseSed(bad); err == nil {
			t.Errorf("ParseSed(%q) succeeded", bad)
		}
	}
	s, _ := ParseSed(`s/(a)(b)/[\2&\&\\$]/`)
	if got := s.GoTemplate(); got != `[${2}${0}&\$$]` {
		t.Errorf("GoTemplate = %q", got)
	}
}

func TestParseRexSedConvertTailUniq(t *testing.T) {
	q, err := Parse(`* | rex field=user mode=sed "s/^CORP\\\\//" | convert timeformat="%Y" ctime(_time) AS year, num(*_count), none(x_count) | tail 5 | uniq`)
	if err != nil {
		t.Fatal(err)
	}
	want := []Command{
		&Rex{Field: "user", MaxMatch: 1, Sed: `s/^CORP\\//`},
		&Convert{TimeFormat: "%Y", Funcs: []ConvertFunc{{"ctime", "_time", "year"}, {"num", "*_count", ""}, {"none", "x_count", ""}}},
		&Tail{N: 5},
		&Uniq{},
	}
	if !reflect.DeepEqual(q.Commands, want) {
		t.Errorf("commands = %#v", q.Commands)
	}
	if q, _ := Parse(`* | tail`); !reflect.DeepEqual(q.Commands[0], &Tail{N: 10}) {
		t.Errorf("tail default = %#v", q.Commands[0])
	}
	for _, bad := range []string{
		`* | rex mode=sed field=a`,
		`* | rex mode=sed "s/a/b/" max_match=2`,
		`* | rex mode=perl "s/a/b/"`,
		`* | convert`,
		`* | convert bogus(a)`,
		`* | convert ctime(a*) AS b`,
		`* | convert none(a) AS b`,
		`* | convert ctime(a`,
		`* | tail 0`,
		`* | tail x`,
		`* | uniq x`,
	} {
		if _, err := Parse(bad); err == nil {
			t.Errorf("Parse(%q) succeeded", bad)
		}
	}
}

func TestDrilldownConvert(t *testing.T) {
	q, _ := Parse(`* | stats count by firstTime, lastTime, user | convert ctime(*Time), none(lastTime)`)
	if got := q.Drilldown().Fields; !reflect.DeepEqual(got, map[string]string{"user": "user"}) {
		t.Errorf("fields = %v", got)
	}
}
