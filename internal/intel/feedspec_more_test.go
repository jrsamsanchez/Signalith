// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package intel

import (
	"strings"
	"testing"
)

func TestFeedSpecMoreProblems(t *testing.T) {
	old := lookupEnv
	lookupEnv = func(k string) string {
		if k == "SET_KEY" {
			return "x"
		}
		return ""
	}
	t.Cleanup(func() { lookupEnv = old })
	base := func() FeedSpec {
		return FeedSpec{Name: "feodo", URL: "https://feeds.example.com/ips.txt"}
	}
	for _, c := range []struct {
		field, msg string
		env        bool
		change     func(*FeedSpec)
	}{
		{"name", `"manual" is reserved`, false, func(s *FeedSpec) { s.Name = ManualSource }},
		{"url", "API root", false, func(s *FeedSpec) { s.Kind, s.URL, s.Collection = KindTAXII, "ftp://x", "c1" }},
		{"type", "must be one of", false, func(s *FeedSpec) { s.Type = "phone" }},
		{"format", "always STIX", false, func(s *FeedSpec) { s.Kind, s.Format, s.Collection = KindTAXII, FormatCSV, "c1" }},
		{"column", "only applies to format: csv", false, func(s *FeedSpec) { s.Kind, s.Column, s.Collection = KindTAXII, "2", "c1" }},
		{"collection", "only applies to kind: taxii", false, func(s *FeedSpec) { s.Collection = "c1" }},
		{"column", "csv feeds need a column", false, func(s *FeedSpec) { s.Format = FormatCSV }},
		{"column", "only applies to format: csv", false, func(s *FeedSpec) { s.Column = "2" }},
		{"interval", "interval:", false, func(s *FeedSpec) { s.Interval = "soon" }},
		{"max_age", "max_age:", false, func(s *FeedSpec) { s.MaxAge = "forever" }},
		{"max_age", "at least the interval", false, func(s *FeedSpec) { s.Interval, s.MaxAge = "2d", "1d" }},
		{"headers", "may only use letters", false, func(s *FeedSpec) { s.Headers = map[string]string{"Bad Name": "v"} }},
		{"headers", "cannot be set", false, func(s *FeedSpec) { s.Headers = map[string]string{"Host": "v"} }},
		{"headers", "line break", false, func(s *FeedSpec) { s.Headers = map[string]string{"X-Key": "a\nb"} }},
		{"headers", "has no value", false, func(s *FeedSpec) { s.Headers = map[string]string{"X-Key": " "} }},
		{"headers", "${MISSING_KEY}, which is not set", true, func(s *FeedSpec) { s.Headers = map[string]string{"X-Key": "${MISSING_KEY}"} }},
		{"password", "${MISSING_PW}, which is not set", true, func(s *FeedSpec) { s.Username, s.Password = "u", "${MISSING_PW}" }},
	} {
		s := base()
		c.change(&s)
		s.Defaults()
		found := false
		for _, p := range s.Problems(c.env) {
			if p.Field == c.field && strings.Contains(p.String(), c.msg) {
				found = true
			}
		}
		if !found {
			t.Errorf("%s %q: %v", c.field, c.msg, s.Problems(c.env))
		}
	}
	// Variables that are set are fine.
	s := base()
	s.Headers = map[string]string{"X-Key": "${SET_KEY}"}
	s.Username, s.Password = "u", "${SET_KEY}"
	s.Defaults()
	if p := s.Problems(true); len(p) != 0 {
		t.Errorf("set variables: %v", p)
	}
	for in, want := range map[string]string{"": "", " é bad ": "É bad.", "Done.": "Done."} {
		if got := sentence(in); got != want {
			t.Errorf("sentence(%q) = %q", in, got)
		}
	}
}
