package splcheck

import (
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestParseThreshold(t *testing.T) {
	for _, c := range []struct {
		search string
		want   Threshold
	}{
		{
			"| tstats `security_content_summariesonly` count min(_time) as firstTime values(Processes.process) as process from datamodel=Endpoint.Processes where Processes.process_name=\"taskkill.exe\" by Processes.parent_process_name Processes.dest Processes.user _time span=1m | where count >=10 | `drop_dm_object_name(Processes)`",
			Threshold{Span: time.Minute, By: []string{"parent_process_name", "dest", "user"}, Aggs: []Agg{{"count", "count", ""}}, Limits: []Limit{{"count", ">=", 10}}},
		},
		{
			"| tstats distinct_count(Processes.process) as n from datamodel=Endpoint.Processes where Processes.process_name=\"sc.exe\" by Processes.dest, _time span=30m | where n > 7",
			Threshold{Span: 30 * time.Minute, By: []string{"dest"}, Aggs: []Agg{{"n", "dc", "process"}}, Limits: []Limit{{"n", ">", 7}}},
		},
		{
			"`wineventlog_security` EventCode=4768 Status=0x6 | bucket span=5m _time | stats dc(TargetUserName) AS unique_accounts values(dest) as dest BY _time, IpAddress | where unique_accounts > 30",
			Threshold{Span: 5 * time.Minute, By: []string{"src"}, Aggs: []Agg{{"unique_accounts", "dc", "user"}}, Limits: []Limit{{"unique_accounts", ">", 30}}},
		},
		{
			// No span: the scheduled search's hour. Fields that only
			// restate the event are not grouped by.
			"`sysmon` EventCode IN (\"23\",\"26\") TargetFilename=\"*.doc\" | stats count min(_time) as firstTime, max(_time) as lastTime by action dest dvc signature signature_id user user_id vendor_product | where count >=100",
			Threshold{By: []string{"action", "dest", "signature_id", "user"}, Aggs: []Agg{{"count", "count", ""}}, Limits: []Limit{{"count", ">=", 100}}},
		},
	} {
		r, err := Parse(rule(c.search), nil)
		if err != nil {
			t.Errorf("%s: %v", c.search, err)
			continue
		}
		if r.Threshold == nil || !reflect.DeepEqual(*r.Threshold, c.want) {
			t.Errorf("%s:\n got %+v\nwant %+v", c.search, r.Threshold, c.want)
		}
	}
	for search, want := range map[string]string{
		// A count by _time needs a span, and a bucket a count.
		"`wineventlog_security` EventCode=4768 | stats dc(TargetUserName) AS n BY _time, IpAddress | where n > 30": "span",
		"`wineventlog_security` EventCode=4768 | bucket span=5m _time":                                             "bucket",
		// The limit must read a count of the search.
		"| tstats count from datamodel=Endpoint.Processes where Processes.process_name=\"a.exe\" by Processes.dest | where other >= 3": "reads no count",
		// Fields Signalith does not keep cannot be grouped by.
		"| tstats count from datamodel=Endpoint.Processes where Processes.process_name=\"a.exe\" by Processes.vendor_product | where count >= 3": "no Signalith mapping",
		// Counts against an average (eventstats) are not thresholds.
		"`wineventlog_security` EventCode=4768 | bucket span=2m _time | stats dc(TargetUserName) AS n BY _time, IpAddress | eventstats avg(n) as a BY IpAddress": "eventstats",
	} {
		if _, err := Parse(rule(search), nil); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: got %v, want an error about %s", search, err, want)
		}
	}
}

func TestThresholdReaches(t *testing.T) {
	th := &Threshold{By: []string{"src"}, Aggs: []Agg{{"n", "dc", "user"}}, Limits: []Limit{{"n", ">=", 2}}}
	views := []map[string]string{{"src": "a", "user": "x"}, {"src": "a", "user": "x"}, {"src": "b", "user": "x"}, {"user": "y"}}
	if th.reaches(views) {
		t.Error("one user from a reaches 2")
	}
	views = append(views, map[string]string{"src": "b", "user": "y"})
	if !th.reaches(views) {
		t.Error("two users from b do not reach 2")
	}
	th.Limits[0].Op = ">"
	if th.reaches(views) {
		t.Error("two users pass > 2")
	}
}

func TestDropPlatform(t *testing.T) {
	r, err := Parse(rule(`| tstats count from datamodel=Endpoint.Processes where NOT Processes.os="Linux" Processes.process_name=nxc.exe by Processes.dest`), nil)
	if err != nil {
		t.Fatal(err)
	}
	if c, ok := r.Where.(*Cmp); !ok || c.Field != "process_name" {
		t.Errorf("where = %#v", r.Where)
	}
	for _, s := range []string{
		// The rule's own platform, a positive test, != and wildcards say
		// something about the event, so they are refused.
		`NOT Processes.os="Microsoft Windows" Processes.process_name=a.exe`,
		`Processes.os="Linux" Processes.process_name=a.exe`,
		`Processes.os!="Linux" Processes.process_name=a.exe`,
		`NOT Processes.os="*nux" Processes.process_name=a.exe`,
		`Processes.process_name=a.exe OR NOT Processes.os="Linux"`,
	} {
		if _, err := Parse(rule("| tstats count from datamodel=Endpoint.Processes where "+s+" by Processes.dest"), nil); err == nil {
			t.Errorf("%s: accepted", s)
		}
	}
	if _, err := Parse(rule(`| tstats count from datamodel=Endpoint.Processes where Processes.process="*\/..\/*" by Processes.dest`), nil); err == nil {
		t.Error(`\/ accepted`)
	}
}

func TestParseEventCodes(t *testing.T) {
	r, err := Parse(rule("`wineventlog_security` EventCode=4625 OR EventCode=4624 Logon_Type=3 TargetUserName=Administrator | bucket span=5m _time | stats dc(Computer) AS unique_targets BY _time, IpAddress, TargetUserName, EventCode, action, app | where unique_targets > 30"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if r.Node != "Logon" || !reflect.DeepEqual(r.Threshold.By, []string{"src", "user", "signature_id", "action"}) {
		t.Errorf("node %s, by %v", r.Node, r.Threshold.By)
	}
	for code, want := range map[string]bool{"4624": true, "4625": true, "4634": false} {
		ev := map[string]string{"signature_id": code, "logon_type": "3", "user": "Administrator"}
		if Eval(r.Where, ev) != want {
			t.Errorf("%s: want %v", code, want)
		}
	}
}
