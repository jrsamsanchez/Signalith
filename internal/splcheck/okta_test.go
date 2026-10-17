package splcheck

import (
	"testing"

	"github.com/jrsamsanchez/signalith/internal/sigmacheck"
)

// oktaRule is a rule whose only data source is Okta.
func oktaRule(search string) []byte {
	return []byte("name: Test rule\nid: 11111111-2222-3333-4444-555555555555\ntype: TTP\nstatus: production\ndata_source:\n- Okta\nsearch: |\n" +
		indent(search) + "\n")
}

func TestOktaRule(t *testing.T) {
	r, err := Parse(rule("`okta` eventType=user.mfa.factor.deactivate outcome.result=SUCCESS\n"+
		"| stats count min(_time) as firstTime max(_time) as lastTime by user src eventType"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if r.Node != OktaNode {
		t.Fatalf("node %s", r.Node)
	}
	ok := map[string]string{"sourcetype": "OktaIM2:log", "eventType": "user.mfa.factor.deactivate", "outcome.result": "SUCCESS"}
	if !Eval(r.Where, ok) {
		t.Errorf("%v does not match", ok)
	}
	ok["sourcetype"] = "o365:management:activity"
	if Eval(r.Where, ok) {
		t.Error("another sourcetype matches")
	}
	pos := 0
	for _, c := range Cases(r) {
		if c.Channel != sigmacheck.OktaChannel {
			t.Errorf("case %s %s", c.Channel, c.EventID)
		}
		if c.Expect {
			pos++
		}
	}
	if pos == 0 {
		t.Error("no positive cases")
	}
}

func TestOktaTstats(t *testing.T) {
	search := "| tstats summariesonly=false count from datamodel=Change where All_Changes.command=user.mfa.factor.deactivate " +
		"All_Changes.result=SUCCESS by All_Changes.user All_Changes.src | `drop_dm_object_name(\"All_Changes\")`"
	r, err := Parse(oktaRule(search), nil)
	if err != nil {
		t.Fatal(err)
	}
	if r.Node != OktaChangeNode {
		t.Fatalf("node %s", r.Node)
	}
	ok := map[string]string{"sourcetype": "OktaIM2:log", "command": "user.mfa.factor.deactivate", "result": "SUCCESS"}
	if !Eval(r.Where, ok) {
		t.Errorf("%v does not match", ok)
	}
	// Only Okta's events: a change from another source does not match.
	ok["sourcetype"] = "WinEventLog"
	if Eval(r.Where, ok) {
		t.Error("another sourcetype matches")
	}
	// The same search of a rule with other data sources is not read as
	// Okta's.
	if r, err := Parse(rule(search), nil); err == nil && IsOktaTstatsNode(r.Node) {
		t.Errorf("a rule without Okta as its data source read as %s", r.Node)
	}
	auth := "| tstats count from datamodel=Authentication where Authentication.action=failure Authentication.signature=user.authentication.auth_via_mfa " +
		"by Authentication.user Authentication.src"
	if r, err := Parse(oktaRule(auth), nil); err != nil || r.Node != OktaAuthNode {
		t.Errorf("authentication: %v %v", r, err)
	}
}

// TestOktaAggsOutsideTheModel: a tstats aggregation of a field the
// Authentication data model does not have reads nothing, so it is left
// out, unless a later stage names its result.
func TestOktaAggsOutsideTheModel(t *testing.T) {
	fields := Nodes[OktaAuthNode]
	aggs := "values(Authentication.app) as app values(Authentication.method) as method count"
	got, err := oktaAggs(aggs, fields, []string{"stats dc(app) as apps by user"})
	if err != nil || got != "values(Authentication.app) as app  count" {
		t.Errorf("got %q, %v", got, err)
	}
	if _, err := oktaAggs(aggs, fields, []string{"where isnotnull(method)"}); err == nil {
		t.Error("a later stage reads method")
	}
}
