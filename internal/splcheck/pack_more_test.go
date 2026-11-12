// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package splcheck_test

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/detect"
	"github.com/jrsamsanchez/signalith/internal/query"
	"github.com/jrsamsanchez/signalith/internal/sigmacheck"
	"github.com/jrsamsanchez/signalith/internal/splcheck"
)

// quickSlowCases are rules TestShippedRulesSynthesizeAgreeingCases
// leaves out as slow whose events are quick enough to make here: their
// cases are checked as that test checks the others.
var quickSlowCases = []string{"suspicious_kerberos_service_ticket_request.yml"}

func TestQuickSlowRulesSynthesizeAgreeingCases(t *testing.T) {
	p, macros, lookups := readPack(t)
	checked := 0
	for _, pr := range p.Rules {
		if !slices.Contains(quickSlowCases, pr.File) {
			continue
		}
		src, err := os.ReadFile(filepath.Join(packDir, "rules", pr.File))
		if err != nil {
			t.Fatal(err)
		}
		r, err := splcheck.ParseWith(src, macros, splcheck.ParseOptions{Network: detect.SplunkNetworkRule(pr.Path), Lookups: lookups})
		if err != nil {
			t.Fatalf("%s: %v", pr.ID, err)
		}
		d, err := detect.PackDetection(p, pr, src)
		if err != nil {
			t.Fatalf("%s: %v", pr.ID, err)
		}
		q, err := query.Parse(d.Query)
		if err != nil {
			t.Fatalf("%s: %v", pr.ID, err)
		}
		cs := splcheck.Cases(r)
		if !slices.ContainsFunc(cs, func(c sigmacheck.Case) bool { return c.Expect }) {
			t.Errorf("%s: no event the rule finds: %s", pr.ID, splcheck.NoEventsReason(r, cs))
		}
		if errs := splcheck.Verify(r, q, &sigmacheck.TestFile{Rule: r.ID, Cases: cs}); len(errs) > 0 {
			t.Errorf("%s: %v", pr.ID, errs[0])
		}
		checked++
	}
	if checked != len(quickSlowCases) {
		t.Errorf("checked %d of %d rules", checked, len(quickSlowCases))
	}
}
