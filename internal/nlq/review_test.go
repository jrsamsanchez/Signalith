// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package nlq

import (
	"strings"
	"testing"
)

// The questions the October 2026 review found translated to confident
// wrong queries (SL-13): each now gives the right query, or a confidence
// low enough that the Search page does not run it on its own and an AI
// model, when one is set up, is asked instead.
func TestReviewQuestions(t *testing.T) {
	const autoRun = 0.8 // api.aiThreshold
	right := map[string]string{
		"accounts locked out today":          `signature_id=4740 earliest=@d | stats count by user | sort -count`,
		"file deletions on fileserver1":      `datamodel=Filesystem action=deleted dest=fileserver1`,
		"users added to domain admins":       `datamodel=Change action=modified object_category=group`,
		"dns queries for evil.com":           `datamodel=Network_Resolution query=evil.com`,
		"web requests with status 500":       `datamodel=Web status=500`,
		"alerts from suricata":               `datamodel=Intrusion_Detection`,
		"wazuh alerts on dc01":               `datamodel=Alerts dest=dc01`,
		"registry changes by powershell":     `datamodel=Registry process_name=powershell.exe`,
		"self-signed certificates":           `datamodel=Certificates ssl_self_signed=true`,
		"top alert signatures from suricata": `datamodel=Intrusion_Detection | top limit=10 signature`,
	}
	for in, want := range right {
		r, err := Translate(in, hints{})
		if err != nil {
			t.Errorf("%q: %v", in, err)
			continue
		}
		if got := strings.ReplaceAll(r.Query, "\n", " "); got != want {
			t.Errorf("%q\n got %s\nwant %s", in, got, want)
		}
		if r.Confidence < autoRun {
			t.Errorf("%q: confidence %.2f unknown %v", in, r.Confidence, r.Unknown)
		}
	}
	// Not understood well enough to run on their own.
	for in, unknown := range map[string]string{
		"service account logins from workstations": "service account workstations",
		"disabled accounts":                        "accounts",
		"kerberos ticket requests":                 "kerberos ticket requests",
		"lateral movement":                         "lateral movement",
		"certificates expiring soon":               "expiring soon",
	} {
		r, err := Translate(in, hints{})
		if err != nil {
			t.Errorf("%q: %v", in, err)
			continue
		}
		if r.Confidence >= autoRun || strings.Join(r.Unknown, " ") != unknown {
			t.Errorf("%q = %s: confidence %.2f unknown %v, want below %.1f with %q", in, r.Query, r.Confidence, r.Unknown, autoRun, unknown)
		}
	}
}
