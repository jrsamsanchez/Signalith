// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package search

import (
	"context"
	"strings"
	"testing"
)

// Commands that need every event, run over fewer than matched, mark the
// result sampled (SL-01).
func TestSampledWhenEventsAreCapped(t *testing.T) {
	three := `{"hits":{"total":{"value":100000},"hits":[
		{"_source":{"@timestamp":"2026-10-11T10:00:00Z","user":"a"}},
		{"_source":{"@timestamp":"2026-10-11T09:00:00Z","user":"a"}},
		{"_source":{"@timestamp":"2026-10-11T08:00:00Z","user":"b"}}]}}`
	for src, sampled := range map[string]bool{
		`* | eval x=1 | stats count by user`:           true,
		`* | rename user as u | stats count by u`:      true,
		`* | dedup user`:                               true,
		`* | bin span=1h _time | stats count by _time`: true,
		`* | head 3 | stats count`:                     false,
		`* | stats count by user`:                      false,
		`* | eval x=1`:                                 false,
	} {
		fs := &fakeStore{responses: []string{three}}
		res, err := (&Engine{Store: fs, Opt: Options{MaxEvents: 3}}).Run(context.Background(), src)
		if err != nil {
			t.Fatalf("%s: %v", src, err)
		}
		if got := res.Sampled == 3; got != sampled {
			t.Errorf("%s: sampled %d, want %v", src, res.Sampled, sampled)
		}
	}
	fs := &fakeStore{responses: []string{strings.Replace(three, "100000", "3", 1)}}
	if res, _ := (&Engine{Store: fs, Opt: Options{MaxEvents: 3}}).Run(context.Background(), `* | dedup user`); res.Sampled != 0 {
		t.Errorf("every event was read, yet sampled %d", res.Sampled)
	}
}
