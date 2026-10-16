package splcheck

import (
	"slices"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/sigmacheck"
)

func TestO365Rule(t *testing.T) {
	// The record's own fields and CIM fields, and renames before stats.
	r, err := Parse(rule("`o365_management_activity` Workload=AzureActiveDirectory Operation=\"*Add service principal*\" OR (Operation = \"*principal*\" AND action = \"created\")\n"+
		"| rename UserId as user object as src_user\n| fillnull\n"+
		"| stats count min(_time) as firstTime max(_time) as lastTime BY signature dest user src vendor_account vendor_product src_user"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if r.Node != O365Node {
		t.Fatalf("node %s", r.Node)
	}
	ok := map[string]string{"sourcetype": "o365:management:activity", "Workload": "AzureActiveDirectory", "Operation": "Add service principal."}
	if !Eval(r.Where, ok) {
		t.Errorf("%v does not match", ok)
	}
	ok["sourcetype"] = "azure:monitor:aad"
	if Eval(r.Where, ok) {
		t.Error("another sourcetype matches")
	}
	// The second branch's positives are changes, whose operation starts
	// with a verb.
	pos, created, neg := 0, 0, 0
	for _, c := range Cases(r) {
		if c.Channel != sigmacheck.O365Channel {
			t.Errorf("case %s %s", c.Channel, c.EventID)
		}
		if c.Expect {
			pos++
			doc, _ := Stored(c)
			if View(doc)["action"] == "created" {
				created++
			}
		} else {
			neg++
		}
	}
	if pos == 0 || created == 0 || neg == 0 {
		t.Errorf("%d positive (%d created) and %d negative cases", pos, created, neg)
	}

	// A search after a rename reads the old name, and a count groups by
	// the stored fields: src_ip is src, and UserAgent the user agent
	// Signalith keeps from a sign-in's extended properties.
	r, err = Parse(rule("`o365_management_activity` Workload=AzureActiveDirectory Operation=UserLoginFailed\n| rename LogonError as error\n| search error=*Sso*\n"+
		"| bucket span=5m _time\n| stats dc(_raw) AS failed_attempts dc(UserAgent) as agents values(user) as user BY _time, src_ip\n| where failed_attempts > 10 AND agents > 2"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if !Eval(r.Where, map[string]string{"sourcetype": "o365:management:activity", "Workload": "AzureActiveDirectory", "Operation": "UserLoginFailed", "LogonError": "SsoArtifactExpiredDueToConditionalAccess"}) {
		t.Errorf("where %#v", r.Where)
	}
	th := r.Threshold
	if th == nil || th.Span != 5*time.Minute || !slices.Equal(th.By, []string{"src"}) || th.Aggs[1].Field != "user_agent" {
		t.Fatalf("threshold %+v", th)
	}
	for _, c := range Cases(r) {
		doc, model := Stored(c)
		if c.Expect && (model != "Authentication" || View(doc)["src"] == "" || View(doc)["user_agent"] == "") {
			t.Errorf("positive %s %v", model, View(doc))
		}
	}

	for _, s := range []string{
		// An Exchange cmdlet's parameter is not a field by its own name.
		"`o365_management_activity` Workload=Exchange Operation=New-ManagementRoleAssignment Role=ApplicationImpersonation",
		"`o365_management_activity` Operation=x | search nosuchfield=1",
		"`o365_management_activity` Operation=x | rename Item.* as *",
	} {
		if _, err := Parse(rule(s), nil); err == nil {
			t.Errorf("%s parsed", s)
		}
	}
}

func TestO365Record(t *testing.T) {
	// An alert's fields make an alert of the Security & Compliance
	// Center, and a mailbox read a record of Exchange's.
	for _, tc := range []struct {
		ev                          map[string]string
		workload, recordType, model string
	}{
		{map[string]string{"Category": "ThreatManagement", "Name": "eDiscovery search started or exported"}, "SecurityComplianceCenter", "SecurityComplianceAlerts", "Alerts"},
		{map[string]string{"Workload": "Exchange", "Operation": "MailItemsAccessed"}, "Exchange", "ExchangeItemAggregated", "Other"},
		{map[string]string{"action": "failure", "reason": "InvalidUserNameOrPassword"}, "AzureActiveDirectory", "AzureActiveDirectoryStsLogon", "Authentication"},
	} {
		doc, model := Stored(o365Record(tc.ev))
		v := View(doc)
		if v["Workload"] != tc.workload || v["record_type"] != tc.recordType || model != tc.model {
			t.Errorf("%v: %s %s %s", tc.ev, v["Workload"], v["record_type"], model)
		}
	}
}
