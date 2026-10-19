// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package query

import (
	"strings"
	"testing"
)

// TestIndexMustStayInsideSignalith reproduces injection-index-pattern-breakout
// and authz-index-param-reads-any-index: index= went to OpenSearch as typed,
// so a comma list, an exclusion, a system index, another cluster or date
// math reached any index the server's OpenSearch account could read. The
// parser now refuses those, with the position of the value; the search
// engine then requires the configured prefix.
func TestIndexMustStayInsideSignalith(t *testing.T) {
	for _, ok := range []string{
		"signalith-*", "signalith-authentication-*", "signalith-authentication-2026.10.11",
		"Signalith-Endpoint-2026.10.*", "signalith-risk-*", "sig_2-other-*", "signalith-*-2026.10.*", "*",
	} {
		q, err := Parse("index=" + ok + " user=bob")
		if err != nil {
			t.Errorf("index=%s: %v", ok, err)
		} else if q.Index != ok {
			t.Errorf("index=%s parsed as %q", ok, q.Index)
		}
	}
	for src, want := range map[string]string{
		`index="signalith-*,.security*"`:              "lists several indices",
		`index="signalith-*, signalith-x"`:            "lists several indices",
		`index=*signalith-x`:                          "must start with the index prefix",
		`index="*,-signalith-*"`:                      "lists several indices",
		`index=-signalith-x`:                          "must start with the index prefix",
		`index=.opendistro_security`:                  "must start with the index prefix",
		`index=_all`:                                  "must start with the index prefix",
		`index=.kibana_1`:                             "must start with the index prefix",
		`index=signalith*`:                            "must start with the index prefix and \"-\"",
		`index=s*-x`:                                  "must start with the index prefix and \"-\"",
		`index=signalith`:                             "must start with the index prefix and \"-\"",
		`index=other:signalith-*`:                     "names another cluster",
		`index="<signalith-{now/d}>"`:                 "uses date math",
		`index="signalith-%3Cx%3E"`:                   "cannot contain",
		`index="signalith-a b"`:                       "cannot contain",
		`index="signalith-a/../_search"`:              "cannot contain",
		`index=""`:                                    "is empty",
		`index=signalith-` + strings.Repeat("a", 300): "is too long",
		`datamodel=Bogus`:                             "unknown data model",
		`datamodel="Authentication,x"`:                "unknown data model",
		`datamodel=../../_cat`:                        "unknown data model",
	} {
		_, err := Parse("user=bob " + src)
		e, ok := err.(*Error)
		if !ok {
			t.Errorf("%s: error %v (%T), want *Error", src, err, err)
			continue
		}
		if !strings.Contains(e.Msg, want) {
			t.Errorf("%s: %q, want it to contain %q", src, e.Msg, want)
		}
		if at := strings.Index(src, "=") + 1 + len("user=bob "); e.Pos != at {
			t.Errorf("%s: error at %d, want %d (the value)", src, e.Pos, at)
		}
	}
	// Unquoted, a comma ends the value, and what follows is not a term.
	if _, err := Parse("index=signalith-*,.security*"); err == nil {
		t.Error("unquoted index list parsed")
	}
	// Unquoted, a comma ends the value, and what follows is not a term.
	if _, err := Parse("index=signalith-*,.security*"); err == nil {
		t.Error("unquoted index list parsed")
	}
	for _, ok := range []string{"Authentication", "network_traffic", "Risk", "Other"} {
		if _, err := Parse("datamodel=" + ok); err != nil {
			t.Errorf("datamodel=%s: %v", ok, err)
		}
	}
}
