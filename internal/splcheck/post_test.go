package splcheck

import (
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/query"
	"github.com/jrsamsanchez/signalith/internal/sigmacheck"
)

func TestPostStages(t *testing.T) {
	// A tstats search's later stages run after its own grouping.
	r, err := Parse(rule("| tstats count from datamodel=Endpoint.Filesystem where Filesystem.file_path=\"*\\\\Drivers\\\\*\" by Filesystem.dest Filesystem.file_name\n"+
		"| `drop_dm_object_name(Filesystem)`\n| rex field=\"file_name\" \"\\.(?<extension>[^\\.]*$)\"\n| where isnull(extension)\n| `test_rule_filter`"), testMacros)
	if err != nil {
		t.Fatal(err)
	}
	want := "fillnull value=unknown dest file_name\n| stats count by dest file_name\n| rex field=\"file_name\" \"\\.(?<extension>[^\\.]*$)\"\n| where isnull(extension)"
	if r.Post != want {
		t.Fatalf("post:\n%s\nwant:\n%s", r.Post, want)
	}
	for name, keep := range map[string]bool{"payload": true, "driver.sys": false} {
		if got := r.Keeps(map[string]any{"file_name": name, "file_path": `C:\Windows\System32\Drivers\` + name}); got != keep {
			t.Errorf("%s: keeps %v", name, got)
		}
	}
	found := false
	for _, c := range Cases(r) {
		found = found || c.Expect
	}
	if !found {
		t.Error("no test event comes through the later stages")
	}
	if g := r.PostGroups(); strings.Join(g, ",") != "dest,file_name" {
		t.Errorf("groups %v", g)
	}

	// A raw search's fields are copied to Splunk's names first, and a
	// later search is a where of the same terms.
	r, err = Parse(rule("`wineventlog_security` EventCode=4768 Status=0x6 | bucket span=2m _time | stats dc(TargetUserName) AS n BY _time, src_ip | search n>=1"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(r.Post, "eval TargetUserName=user, src_ip=src\n| bucket span=2m _time") || !strings.HasSuffix(r.Post, "| where n>=1") {
		t.Errorf("post:\n%s", r.Post)
	}
	if !r.Keeps(map[string]any{"user": "alice", "src": "10.0.0.5", "@timestamp": "2026-01-01T12:00:00Z"}) {
		t.Error("a counted event is not kept")
	}
	if r.Keeps(map[string]any{"user": "alice", "@timestamp": "2026-01-01T12:00:00Z"}) {
		t.Error("an event with no address is kept")
	}
}

func TestPostRefuses(t *testing.T) {
	for search, want := range map[string]string{
		// Splunk's where compares two fields; Signalith's would compare
		// with the text.
		"| tstats count from datamodel=Endpoint.Processes where Processes.process_name=a.exe by Processes.dest Processes.process_name Processes.user | where process_name != user": "reads differently",
		"`wineventlog_security` EventCode=4768 Status=0x6 | where TargetUserName IN (a, b)":                                                                                        "reads differently",
		"`wineventlog_security` EventCode=4768 Status=0x6 | where TargetUserName=\"adm*\"":                                                                                         "reads differently",
		// Lookups need Splunk's tables.
		"`wineventlog_security` EventCode=4768 Status=0x6 | lookup local=t accounts user OUTPUT owner":                                   "later stage",
		"| tstats count from datamodel=Endpoint.Processes where Processes.process_name=a.exe by _time span=1h Processes.dest | eval x=1": "grouped by time",
	} {
		if _, err := Parse(rule(search), testMacros); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: err = %v, want %q", search, err, want)
		}
	}
	// Numbers and quoted text without a wildcard read the same way.
	for _, search := range []string{
		"`wineventlog_security` EventCode=4768 Status=0x6 | stats count by src | where count > 5",
		"`wineventlog_security` EventCode=4768 Status=0x6 | where TargetUserName=\"admin\"",
	} {
		if _, err := Parse(rule(search), nil); err != nil {
			t.Errorf("%s: %v", search, err)
		}
	}
}

func TestQuoteDotted(t *testing.T) {
	for in, want := range map[string]string{
		`if(match(userIdentity.userName, requestParameters.userName), 1, 0)`: `if(match('userIdentity.userName', 'requestParameters.userName'), 1, 0)`,
		`mvindex('Actor{}.ID', 0) . "a.b" . x`:                               `mvindex('Actor{}.ID', 0) . "a.b" . x`,
		`round(x * 1.5, 2)`:                                                  `round(x * 1.5, 2)`,
	} {
		if got := quoteDotted(in); got != want {
			t.Errorf("%s: got %s", in, got)
		}
	}
}

func TestPostBursts(t *testing.T) {
	// A count of distinct accounts over 5 needs 6 events, each for
	// another account.
	r, err := Parse(rule("`wineventlog_security` EventCode=4768 Status=0x6 | eval x=1 | stats dc(TargetUserName) as accounts by src_ip | where accounts > 5"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if r.Post == "" {
		t.Fatal("no later stages")
	}
	var pos, neg *sigmacheck.Case
	for _, c := range Cases(r) {
		if c.Repeat > 1 {
			if c.Expect {
				pos = &c
			} else {
				neg = &c
			}
		}
	}
	if pos == nil || neg == nil {
		t.Fatal("no repeated test events")
	}
	if pos.Repeat != 6 || neg.Repeat != 4 || len(pos.Vary) != 1 || pos.Vary[0] != "TargetUserName" {
		t.Errorf("repeats %d and %d, varying %v", pos.Repeat, neg.Repeat, pos.Vary)
	}
	copies, at := pos.Copies()
	if len(copies) != 6 || copies[0].Data["TargetUserName"] == copies[1].Data["TargetUserName"] || at[5] >= sigmacheck.RepeatSpan {
		t.Errorf("copies %v at %v", copies, at)
	}
	tf := &sigmacheck.TestFile{Cases: []sigmacheck.Case{*pos, *neg}}
	filter := &query.And{Children: []query.Expr{
		&query.Compare{Field: "signature_id", Op: "=", Value: "4768"},
		&query.Compare{Field: "kerberos_status", Op: "=", Value: "0x6"},
	}}
	if errs := Verify(r, "Authentication", filter, tf); len(errs) > 0 {
		t.Error(errs)
	}
}
