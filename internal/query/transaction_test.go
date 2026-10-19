// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package query

import (
	"reflect"
	"strings"
	"testing"
)

func TestParseTransaction(t *testing.T) {
	for src, want := range map[string]*Transaction{
		`* | transaction host`: {Fields: []string{"host"}, MaxEvents: DefaultMaxEvents},
		`* | transaction host, user maxspan=10m maxpause=30 maxevents=5`: {Fields: []string{"host", "user"},
			MaxSpan: 600, MaxPause: 30, MaxEvents: 5},
		`* | transaction user startswith="Accepted password" endswith=(action=logoff OR signature_id=4634)`: {Fields: []string{"user"},
			MaxEvents: DefaultMaxEvents, StartsWith: &Text{Value: "Accepted password"},
			EndsWith: &Or{Children: []Expr{&Compare{Field: "action", Op: "=", Value: "logoff"}, &Compare{Field: "signature_id", Op: "=", Value: "4634"}}}},
		`* | transaction maxspan=1d startswith=opened`: {MaxSpan: 86400, MaxEvents: DefaultMaxEvents, StartsWith: &Text{Value: "opened"}},
		`* | transaction "my field" endswith=(a=1 b=2)`: {Fields: []string{"my field"}, MaxEvents: DefaultMaxEvents,
			EndsWith: &And{Children: []Expr{&Compare{Field: "a", Op: "=", Value: "1"}, &Compare{Field: "b", Op: "=", Value: "2"}}}},
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
	for src, want := range map[string]string{
		`* | transaction host maxspan=soon`:   "maxspan takes a time",
		`* | transaction host maxspan=0s`:     "maxspan takes a time",
		`* | transaction host maxspan=99999d`: "maxspan takes a time",
		`* | transaction host maxevents=0`:    "at least 1",
		`* | transaction host keepevicted=t`:  "unknown transaction option",
		`* | transaction host startswith=(*)`: "matches every event",
		`* | transaction host startswith=""`:  "needs text",
		`* | transaction host endswith=,`:     "endswith takes text",
	} {
		_, err := Parse(src)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("Parse(%q) = %v, want an error with %q", src, err, want)
		}
	}
}
