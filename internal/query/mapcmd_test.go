package query

import (
	"strings"
	"testing"
)

func TestParseMap(t *testing.T) {
	q, err := Parse(`* | map maxsearches=20 search="search EventCode=4624 TargetLogonId=$TargetLogonId$ | head 5"`)
	if err != nil {
		t.Fatal(err)
	}
	m := q.Commands[0].(*Map)
	if m.Max != 20 || m.Search != "search EventCode=4624 TargetLogonId=$TargetLogonId$ | head 5" {
		t.Errorf("map = %+v", m)
	}
	if got := q.String(); !strings.Contains(got, `map maxsearches=20 search="search EventCode=4624`) {
		t.Errorf("String = %s", got)
	}
	if q, _ := Parse(`* | map search="| tstats count from datamodel=Authentication where Authentication.src=\"$src$\" by Authentication.user"`); q == nil || q.Commands[0].(*Map).Max != 10 {
		t.Errorf("tstats map: %v", q)
	}
	for _, bad := range []string{
		`* | map`,
		`* | map search=foo`,
		`* | map maxsearches=0 search="x"`,
		`* | map maxsearches=101 search="x"`,
		`* | map search="x=$a"`,
		`* | map search="x | nosuchcommand"`,
		`* | map search="x | join a [search y]"`,
		`* | map search="x | map search=\"y\""`,
		`* | map search="x" search="y"`,
		`* | map maxsearches=60 search="x=$a$" | map maxsearches=60 search="y=$b$"`,
	} {
		if _, err := Parse(bad); err == nil {
			t.Errorf("%s parsed", bad)
		}
	}
}

func TestSubstituteMap(t *testing.T) {
	vals := map[string]string{
		"id": "0x3e7", "n": "42", "neg": "-1.5", "name": "alice", "ip": "10.0.0.1", "kw": "OR",
		"evil": `a" OR user=* | delete "`, "tilde": "~.*", "sq": `it's'`, "pipe": "x | y", "plus": "a+b", "empty": "",
	}
	get := func(n string) (string, bool) { v, ok := vals[n]; return v, ok }
	for in, want := range map[string]string{
		`user=$name$ n>$n$ x=$neg$`:  `user=alice n>42 x=-1.5`,
		`id=$id$ ip=$ip$`:            `id=0x3e7 ip="10.0.0.1"`,
		`a=$kw$ b=$tilde$ c=$empty$`: `a="OR" b="~.*" c=""`,
		`user=$evil$`:                `user="a\" OR user=* | delete \""`,
		`user="pre $evil$ post"`:     `user="pre a\" OR user=* | delete \" post"`,
		`| eval x='$sq$'`:            `| eval x='it\'s\''`,
		`| eval x=$plus$, y=$pipe$`:  `| eval x="a+b", y="x | y"`,
		`cost=$$5 and $name$`:        `cost=$5 and alice`,
		`say="it's $name$"`:          `say="it's alice"`,
		`a="\"$name$\""`:             `a="\"alice\""`,
	} {
		got, err := SubstituteMap(in, get)
		if err != nil || got != want {
			t.Errorf("%s: got %s, %v; want %s", in, got, err, want)
		}
	}
	if _, err := SubstituteMap(`x=$missing$`, get); err != ErrMapField {
		t.Errorf("missing: %v", err)
	}
	big := strings.Repeat("v", MaxMapSearchText)
	if _, err := SubstituteMap(`x=$big$`, func(string) (string, bool) { return big, true }); err == nil {
		t.Error("over 64 KB accepted")
	}
	// Whatever the values, the search keeps its one condition.
	for _, v := range vals {
		text, err := SubstituteMap(`user=$v$`, func(string) (string, bool) { return v, true })
		if err != nil {
			t.Fatal(err)
		}
		q, err := ParseMapSearch(text)
		if err != nil {
			t.Errorf("%q: %v", v, err)
			continue
		}
		if len(q.Commands) != 0 {
			t.Errorf("%q added commands: %s", v, q.String())
		}
		if c, ok := q.Search.(*Compare); !ok || c.Field != "user" || c.Op != "=" || c.Value != v {
			t.Errorf("%q: search = %#v", v, q.Search)
		}
	}
}

// FuzzSubstituteMap checks that no value can change what map's search
// does besides the value it compares with, in or out of quotes.
func FuzzSubstituteMap(f *testing.F) {
	for _, s := range []string{"alice", `a" OR b=* | delete "`, "~x", "it's", `\`, `\"`, "$", "OR", "1e5", "a+b", ""} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, v string) {
		if len(v) > 1000 {
			return
		}
		for _, tmpl := range []string{`user=$v$`, `user="$v$"`} {
			text, err := SubstituteMap(tmpl, func(string) (string, bool) { return v, true })
			if err != nil {
				t.Fatal(err)
			}
			q, err := ParseMapSearch(text)
			if err != nil {
				// A value can fail to parse, as a lone \ in quotes can not.
				continue
			}
			c, ok := q.Search.(*Compare)
			if len(q.Commands) != 0 || !ok || c.Field != "user" || c.Op != "=" || c.Value != v {
				t.Fatalf("%s with %q gave %s", tmpl, v, q.String())
			}
		}
	})
}
