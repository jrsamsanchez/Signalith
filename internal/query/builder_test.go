package query

import (
	"reflect"
	"testing"
)

func TestBuildStats(t *testing.T) {
	q := Build(Spec{
		Datamodel: "Authentication",
		Filters:   []Filter{{Field: "action", Op: "=", Value: "failure"}, {Field: "user", Op: "!=", Value: "svc backup"}},
		Earliest:  "-24h",
		Mode:      "stats", AggFunc: "dc", AggField: "user", By: []string{"src"},
		Sort: "-dc(user)", Limit: 10,
	})
	want := "datamodel=Authentication action=failure user!=\"svc backup\" earliest=-24h\n| stats dc(user) by src\n| sort -dc(user)\n| head 10"
	if got := q.String(); got != want {
		t.Fatalf("got:\n%s\nwant:\n%s", got, want)
	}
}

func TestBuilderRoundTrip(t *testing.T) {
	specs := []Spec{
		{Datamodel: "Authentication", Mode: "events", Text: "failed password", Fields: []string{"_time", "user"}, Limit: 50},
		{Datamodel: "Network_Traffic", Mode: "stats", AggFunc: "sum", AggField: "bytes", By: []string{"src", "dest"}, Sort: "-sum(bytes)", Limit: 5,
			Filters: []Filter{{Field: "dest_port", Op: ">", Value: "1024"}}},
		{Mode: "timechart", AggFunc: "count", Span: "1h", By: []string{"action"}},
		{Datamodel: "Authentication", Mode: "latest", By: []string{"user", "dest"}, Fields: []string{"_time", "user", "src"}, Limit: 20},
	}
	for _, s := range specs {
		text := Build(s).String()
		q, err := Parse(text)
		if err != nil {
			t.Fatalf("Parse(%q): %v", text, err)
		}
		got, ok := FromQuery(q)
		if !ok {
			t.Fatalf("FromQuery(%q) not ok", text)
		}
		if !reflect.DeepEqual(got, s) {
			t.Errorf("round trip:\n got %+v\nwant %+v\n(%s)", got, s, text)
		}
	}
}

// One leading sign is the sort order; FuzzParse found a field named
// "-x" losing its sign.
func TestBuilderSortSigns(t *testing.T) {
	s, ok := FromQuery(mustParse(t, `* | sort +-x`))
	if !ok || s.Sort != "+-x" {
		t.Fatalf("FromQuery = %+v %v", s, ok)
	}
	if got := Build(s).String(); got != "*\n| sort +-x" {
		t.Errorf("Build = %q", got)
	}
	if got := Build(Spec{Sort: "-"}).String(); got != "*" {
		t.Errorf("Build with no sort field = %q", got)
	}
}

func TestFromQueryRejectsComplexQueries(t *testing.T) {
	for _, src := range []string{
		`a=1 OR b=2`,
		`NOT a=1`,
		`a=1 | where x > 1`,
		`a=1 | stats count, dc(x)`,
	} {
		q := mustParse(t, src)
		if _, ok := FromQuery(q); ok {
			t.Errorf("FromQuery(%q) should not be representable", src)
		}
	}
}
