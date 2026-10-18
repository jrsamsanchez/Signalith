package splcheck

import (
	"strings"
	"testing"
	"time"
)

// Counts compared with each other run only within each time bucket; over
// the whole search, or across buckets, they depend on Splunk's window.
func TestCompareStages(t *testing.T) {
	head := "`wineventlog_security` EventCode=4768 Status=0x6 | bucket span=2m _time | stats dc(TargetUserName) AS n BY _time, src_ip"
	for search, want := range map[string]string{
		head + " | eventstats avg(n) as a, stdev(n) as s BY _time | eval u=a+s*3 | where n > 10 AND n >= u":        "",
		head + " | eventstats avg(n) as a, stdev(n) as s BY src_ip | eval u=a+s*3 | where n > 10 AND n >= u":       "search window",
		"`wineventlog_security` EventCode=4768 | stats dc(TargetUserName) AS n BY src_ip | eventstats avg(n) as a": "search window",
		strings.Replace(head, "2m", "15m", 1) + " | eventstats avg(n) as a BY _time | where n > a":                 "cuts them in parts",
		head + " | eventstats median(n) as a BY _time | where n > a":                                               "not supported",
		head + " | eventstats avg(n) as a BY _time | sort - n":                                                     "not supported",
		// Rows compared with the search's other rows, counted or not.
		head + " | anomalydetection n": "anomalydetection across the whole search",
		"`wineventlog_security` EventCode=4768 | eventstats dc(TargetUserName) as d by src_ip | where d > 2":                                                                     "eventstats across the whole search",
		"`wineventlog_security` EventCode=4768 | streamstats count as c by src_ip | where c > 2":                                                                                 "streamstats across the whole search",
		"| tstats count from datamodel=Endpoint.Processes where Processes.process_name=a.exe by Processes.dest Processes.process | eventstats avg(count) as a | where count > a": "eventstats across the whole search",
	} {
		r, err := Parse(rule(search), testMacros)
		if want == "" {
			if err != nil {
				t.Errorf("%s: %v", search, err)
				continue
			}
			if !r.PostCompared || r.PostSpan != 2*time.Minute || strings.Contains(r.Post, "coalesce") {
				t.Errorf("%s: compared %v span %v post:\n%s", search, r.PostCompared, r.PostSpan, r.Post)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v, want %q", search, err, want)
		}
	}
}

// The test events of a comparison of counts: the repeat on its own, among
// other groups' ordinary counts, and among a baseline it does not stand
// out from.
func TestBaselineCases(t *testing.T) {
	r, err := Parse(rule("`wineventlog_security` EventCode=4768 Status=0x6 | bucket span=2m _time | stats dc(TargetUserName) AS n BY _time, src_ip"+
		" | eventstats avg(n) as a, stdev(n) as s BY _time | eval u=a+s*3 | where n > 10 AND n >= u"), nil)
	if err != nil {
		t.Fatal(err)
	}
	var pos, neg int
	for _, c := range Cases(r) {
		if len(c.Baseline) == 0 {
			continue
		}
		docs := storedAll(c)
		if got := r.KeepsAll(docs); got != c.Expect {
			t.Errorf("case with %d baseline groups: keeps %v, expect %v", len(c.Baseline), got, c.Expect)
		}
		if c.Expect {
			pos++
			if len(c.Baseline) < 10 {
				t.Errorf("a repeat stands out of %d others by three standard deviations", len(c.Baseline))
			}
		} else {
			neg++
		}
	}
	if pos == 0 || neg == 0 {
		t.Errorf("%d positive and %d negative cases with a baseline", pos, neg)
	}
}
