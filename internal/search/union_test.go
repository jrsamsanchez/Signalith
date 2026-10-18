package search

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/query"
)

func TestUnion(t *testing.T) {
	e, fs := joinEngine(joinMain, joinSub, joinSub)
	got := runRows(t, e, `* earliest=-7d | table user | union [search datamodel=Change | stats count as changes by user] [search datamodel=Change | stats count as n by user | eval user="x"]`, "user", "changes", "n")
	want := []string{"amy <nil> <nil>", "bob <nil> <nil>", "cat <nil> <nil>", "<nil> <nil> <nil>", "amy 5 <nil>", "bob 2 <nil>", "x <nil> 5", "x <nil> 2"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("union:\n got %v\nwant %v", got, want)
	}
	// Each subsearch searched the outer time range.
	if len(fs.bodies) != 3 || !strings.Contains(asJSON(fs.bodies[2]), `"gte":"now-7d"`) {
		t.Errorf("subsearches = %v", fs.bodies)
	}

	// Every subsearch compiles before any search runs.
	e, fs = joinEngine(joinMain)
	if _, err := e.Run(context.Background(), `* | union [search a] [search * | threatmatch]`); !errors.Is(err, errIntelOff) || len(fs.bodies) != 0 {
		t.Errorf("err = %v, searches = %d", err, len(fs.bodies))
	}

	for _, bad := range []string{"union", "union x [a]", "union [a] x", "union [a] [b] [c] [d] [e] [f] [g] [h] [i] [j] [k]", "union [a] [b"} {
		if _, err := (&Engine{Store: &fakeStore{}}).Run(context.Background(), "* | "+bad); err == nil {
			t.Errorf("%s parsed", bad)
		}
	}
	q, err := query.Parse("* | union [search a]")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := RunCommands(context.Background(), nil, q.Commands); err == nil {
		t.Error("RunCommands ran a union")
	}
}
