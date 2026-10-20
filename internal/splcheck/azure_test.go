// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package splcheck

import (
	"slices"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/sigmacheck"
)

func TestAzureRule(t *testing.T) {
	// A list's values by Splunk's name, and renames before stats.
	r, err := Parse(rule("`azure_monitor_aad` operationName=\"Add member to role\" properties.targetResources{}.modifiedProperties{}.newValue=\"*Global Administrator*\"\n"+
		"| rename properties.* as *\n| rename initiatedBy.user.userPrincipalName as initiatedBy\n| fillnull\n"+
		"| stats count min(_time) as firstTime max(_time) as lastTime by dest user src vendor_account vendor_product initiatedBy signature"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if r.Node != AzureNode {
		t.Fatalf("node %s", r.Node)
	}
	ok := map[string]string{"sourcetype": "azure:monitor:aad", "operationName": "Add member to role",
		"properties.targetResources{}.modifiedProperties{}.newValue": `"Global Administrator"`}
	if !Eval(r.Where, ok) {
		t.Errorf("%v does not match", ok)
	}
	ok["sourcetype"] = "azure:monitor:activity"
	if Eval(r.Where, ok) {
		t.Error("another sourcetype matches")
	}
	pos, neg := 0, 0
	for _, c := range Cases(r) {
		if c.Channel != sigmacheck.AzureChannel || c.EventID != "auditlogs" {
			t.Errorf("case %s %s", c.Channel, c.EventID)
		}
		if c.Expect {
			pos++
		} else {
			neg++
		}
	}
	if pos == 0 || neg == 0 {
		t.Errorf("%d positive and %d negative cases", pos, neg)
	}

	// A search after rename properties.* as * reads the old names, and a
	// count groups by them; a CIM field keeps its name.
	r, err = Parse(rule("`azure_monitor_aad` category=SignInLogs operationName=\"Sign-in activity\"\n| rename properties.* as *\n"+
		"| search status.errorCode=500121 status.additionalDetails=\"MFA denied; user declined the authentication\"\n"+
		"| bucket span=10m _time\n| rename userAgent as user_agent\n| fillnull\n"+
		"| stats count dc(appId) as apps values(src) as src by user status.additionalDetails user_agent vendor_account vendor_product _time\n| where count > 9"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if !Eval(r.Where, map[string]string{"sourcetype": "azure:monitor:aad", "category": "SignInLogs", "operationName": "Sign-in activity",
		"properties.status.errorCode": "500121", "properties.status.additionalDetails": "MFA denied; user declined the authentication"}) {
		t.Errorf("where %#v", r.Where)
	}
	th := r.Threshold
	if th == nil || th.Span != 10*time.Minute || !slices.Equal(th.By, []string{"user", "properties.status.additionalDetails", "properties.userAgent", "vendor_account"}) ||
		th.Aggs[1].Field != "properties.appId" {
		t.Fatalf("threshold %+v", th)
	}
	for _, c := range Cases(r) {
		if c.Expect && (c.EventID != "signinlogs" || c.Data["properties.status.errorCode"] != "500121") {
			t.Errorf("positive %s %v", c.EventID, c.Data)
		}
	}

	// A bucket without a count by _time counts over the whole search.
	r, err = Parse(rule("`azure_monitor_aad` category=SignInLogs properties.authenticationDetails{}.succeeded=true\n| rename properties.* as *\n"+
		"| bucket span=30m _time\n| stats count dc(src) AS unique_ips by user vendor_account\n| where unique_ips > 1"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if r.Threshold == nil || r.Threshold.Span != 0 {
		t.Fatalf("threshold %+v", r.Threshold)
	}

	for _, s := range []string{
		"`azure_monitor_aad` operationName=x nosuchfield=1",
		"`azure_monitor_aad` operationName=x | search nosuchfield=1",
		"`azure_monitor_aad` operationName=x | rename properties.* as *.*",
	} {
		if _, err := Parse(rule(s), nil); err == nil {
			t.Errorf("%s parsed", s)
		}
	}
}

func TestAzureUnrename(t *testing.T) {
	rs, err := parseRename("rename properties.* as *, initiatedBy.app.displayName as src_user userAgent as user_agent")
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{
		"src_user":               "properties.initiatedBy.app.displayName",
		"user_agent":             "properties.userAgent",
		"status.errorCode":       "properties.status.errorCode",
		"targetResources{}.type": "properties.targetResources{}.type",
		"user":                   "user",
		"category":               "category",
	} {
		if got := azureUnrename(name, rs); got != want {
			t.Errorf("%s: %s, want %s", name, got, want)
		}
	}
}
