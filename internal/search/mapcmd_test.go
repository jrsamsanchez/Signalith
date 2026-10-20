// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package search

import (
	"context"
	"strings"
	"testing"
)

func TestMap(t *testing.T) {
	hit := func(user string) string {
		return `{"hits":{"total":{"value":1},"hits":[{"_source":{"@timestamp":"2026-10-15T11:00:00Z","user":"` + user + `","EventCode":"4624"}}]}}`
	}
	fs := &fakeStore{responses: []string{hit("amy"), hit("odd")}}
	e := &Engine{Store: fs}
	res, err := e.Run(context.Background(), `| makeresults count=3 | streamstats count as n | eval u=case(n=1, "amy", n=2, "b\" OR user=* | delete \"", n=3, null()) | map search="search earliest=-2d EventCode=4624 user=$u$"`)
	if err != nil {
		t.Fatal(err)
	}
	// The third row has no u, so it runs no search.
	if len(fs.bodies) != 2 {
		t.Fatalf("ran %d searches", len(fs.bodies))
	}
	if len(res.Rows) != 2 || res.Rows[0]["user"] != "amy" || res.Rows[1]["user"] != "odd" || res.Matched != 2 {
		t.Errorf("rows = %v, matched %d", res.Rows, res.Matched)
	}
	if b := asJSON(fs.bodies[0]); !strings.Contains(b, `"amy"`) || !strings.Contains(b, `"gte":"now-2d"`) {
		t.Errorf("first search = %s", b)
	}
	// The second value is searched for as it is, not run as commands.
	if b := asJSON(fs.bodies[1]); !strings.Contains(b, `b\" OR user=* | delete \"`) {
		t.Errorf("second search = %s", b)
	}

	fs = &fakeStore{responses: []string{hit("x")}}
	e = &Engine{Store: fs}
	res, err = e.Run(context.Background(), `| makeresults count=5 | eval u="x" | map maxsearches=2 search="user=$u$"`)
	if err != nil {
		t.Fatal(err)
	}
	if len(fs.bodies) != 2 || len(res.Rows) != 2 || !res.Truncated {
		t.Errorf("maxsearches: %d searches, %d rows, truncated %v", len(fs.bodies), len(res.Rows), res.Truncated)
	}
}
