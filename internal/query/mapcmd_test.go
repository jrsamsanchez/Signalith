package query

import (
	"fmt"
	"reflect"
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
		`| eval x='$name$'`:          `| eval x='alice'`,
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
	// A value that needs quotes cannot go where its quotes would not
	// keep it one value.
	for _, in := range []string{`user='$evil$'`, `user=a$evil$`, `user=$evil$b`, `| eval a='$sq$'`, `a="b"$evil$`, `$evil$"c"`} {
		if _, err := SubstituteMap(in, get); err == nil || err == ErrMapField {
			t.Errorf("%s: err = %v", in, err)
		}
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

// mapTemplates are map searches the fuzz test fills in, each with $v$.
var mapTemplates = []string{
	`user=$v$`, `user="$v$"`, `user='$v$'`, `a'$v$'`, `"$v$"x`, `x=1 $v$ y=2`, `user IN ($v$, b)`,
	`* | eval a='$v$'`, `* | eval a=$v$, b=1`, `* | where a='$v$'`, `* | where a=$v$ | table a`,
	`* | eval a="pre $v$ post" | stats count by a`, `* | search a=$v$ | head 1`,
}

// shape writes q's structure without its text values: the commands, the
// kinds of conditions and the count of each list, so two queries with the
// same shape do the same things with different values.
func shape(v reflect.Value, b *strings.Builder) {
	switch v.Kind() {
	case reflect.Pointer, reflect.Interface:
		if v.IsNil() {
			b.WriteString("nil ")
			return
		}
		if v.Kind() == reflect.Pointer {
			b.WriteString(v.Type().String() + " ")
		}
		shape(v.Elem(), b)
	case reflect.Struct:
		b.WriteString("{")
		for i := 0; i < v.NumField(); i++ {
			shape(v.Field(i), b)
		}
		b.WriteString("}")
	case reflect.Slice, reflect.Map:
		fmt.Fprintf(b, "[%d ", v.Len())
		if v.Kind() == reflect.Slice {
			for i := 0; i < v.Len(); i++ {
				shape(v.Index(i), b)
			}
		}
		b.WriteString("]")
	case reflect.String:
		b.WriteString("s ")
	default:
		b.WriteString(v.Kind().String() + " ")
	}
}

// FuzzSubstituteMap checks that no value changes the structure of map's
// search, in or out of quotes: it parses to the same shape as with a
// value of the same kind, or does not run.
func FuzzSubstituteMap(f *testing.F) {
	for _, s := range []string{"alice", `a" OR b=* | delete "`, "~x", "it's", `\`, `\"`, "$", "OR", "1e5", "a+b", "", "x OR user=* OR a=b", "x | head 1 | rename a as b", "x' , b=1, c='"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, v string) {
		if len(v) > 1000 {
			return
		}
		// A value of the same kind: bare for a plain name or number, and
		// quoted otherwise.
		like := "x y"
		if mapValue(v) == v {
			like = v
		}
		for _, tmpl := range mapTemplates {
			text, err := SubstituteMap(tmpl, func(string) (string, bool) { return v, true })
			if err != nil {
				continue
			}
			q, err := ParseMapSearch(text)
			if err != nil {
				continue
			}
			base, _ := SubstituteMap(tmpl, func(string) (string, bool) { return like, true })
			bq, err := ParseMapSearch(base)
			if err != nil {
				t.Fatalf("%s with %q: %v", tmpl, like, err)
			}
			var got, want strings.Builder
			shape(reflect.ValueOf(q), &got)
			shape(reflect.ValueOf(bq), &want)
			if got.String() != want.String() {
				t.Fatalf("%s with %q gave %s\nwant the shape of %s", tmpl, v, q.String(), bq.String())
			}
		}
	})
}
