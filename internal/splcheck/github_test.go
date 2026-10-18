package splcheck

import (
	"testing"

	"github.com/jrsamsanchez/signalith/internal/sigmacheck"
)

func TestGitHubRule(t *testing.T) {
	for _, tc := range []struct{ search, field string }{
		{"`github_enterprise` action=audit_log_streaming.update reason=\"User initiated pause\"", "vendor_action"},
		{"`github_organizations` vendor_action=audit_log_streaming.update reason=\"User initiated pause\"", "vendor_action"},
	} {
		r, err := Parse(rule(tc.search+"\n| fillnull\n| stats count min(_time) as firstTime max(_time) as lastTime BY actor, actor_id, "+
			"actor_location.country_code, business, user, user_agent, action\n| eval user=actor"), nil)
		if err != nil {
			t.Fatal(err)
		}
		if r.Node != GitHubNode {
			t.Fatalf("node %s", r.Node)
		}
		ok := map[string]string{"sourcetype": "github:cloud:audit", tc.field: "audit_log_streaming.update", "github_reason": "User initiated pause"}
		if !Eval(r.Where, ok) {
			t.Errorf("%v does not match %s", ok, tc.search)
		}
		ok["sourcetype"] = "OktaIM2:log"
		if Eval(r.Where, ok) {
			t.Error("another sourcetype matches")
		}
		pos := 0
		for _, c := range Cases(r) {
			if c.Channel != sigmacheck.GitHubChannel {
				t.Errorf("case %s %s", c.Channel, c.EventID)
			}
			if c.Expect {
				pos++
				if c.Data["action"] != "audit_log_streaming.update" || c.Data["reason"] != "User initiated pause" {
					t.Errorf("positive case %v", c.Data)
				}
			}
		}
		if pos == 0 {
			t.Error("no positive cases")
		}
	}
	// In the add-on's events, action is the CIM field.
	r, err := Parse(rule("`github_organizations` action=deleted vendor_action=repo.destroy | stats count by actor"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if !Eval(r.Where, map[string]string{"sourcetype": "github:cloud:audit", "action": "deleted", "vendor_action": "repo.destroy"}) {
		t.Errorf("CIM action: %v", r.Where)
	}
	// GitHub's user (whom an action was about) and actor (who did it)
	// are GitHub's, not the CIM user.
	r, err = Parse(rule("`github_enterprise` action=org.add_member user=mona actor=octocat src=203.0.113.7 | stats count by actor"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if !Eval(r.Where, map[string]string{"sourcetype": "github:cloud:audit", "vendor_action": "org.add_member", "github_user": "mona",
		"github_actor": "octocat", "src": "203.0.113.7"}) {
		t.Errorf("GitHub's names: %v", r.Where)
	}
}
