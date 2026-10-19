// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package query

import (
	"strings"
	"testing"
)

func TestFrom(t *testing.T) {
	for src, want := range map[string]string{
		"| from datamodel:Authentication | stats count by user":     "datamodel=Authentication\n| stats count by user",
		`| from datamodel:"Endpoint.Processes"`:                     "datamodel=Endpoint",
		"| from datamodel Network_Traffic.All_Traffic | head 2":     "datamodel=Network_Traffic\n| head 2",
		"| from datamodel:Authentication.Failed_Authentication":     "datamodel=Authentication action=failure",
		"| from datamodel:Authentication.Successful_Authentication": "datamodel=Authentication action=success",
		"| from datamodel:Filesystem":                               "datamodel=Filesystem",
		"| from lookup:owners.csv | stats count by team":            "*\n| inputlookup owners\n| stats count by team",
		"| from inputlookup:owners":                                 "*\n| inputlookup owners",
	} {
		q, err := Parse(src)
		if err != nil {
			t.Errorf("%s: %v", src, err)
			continue
		}
		if got := q.String(); got != want {
			t.Errorf("%s = %q, want %q", src, got, want)
		}
	}
	for _, bad := range []string{
		"user=x | from datamodel:Authentication", "| stats count | from datamodel:Web", "| from", "| from datamodel:", "| from datamodel:Nope",
		"| from datamodel:Authentication.Nope", "| from savedsearch:x", "| from lookup:Bad", "| from datamodel:Web extra",
		"| stats count | appendpipe [from datamodel:Web]", "| from datamodel: Web",
	} {
		if _, err := Parse(bad); err == nil {
			t.Errorf("%s parsed", bad)
		} else if strings.Contains(err.Error(), "internal") {
			t.Errorf("%s: %v", bad, err)
		}
	}
}
