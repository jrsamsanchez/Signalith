package splcheck

import (
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/query"
	"github.com/jrsamsanchez/signalith/internal/sigmacheck"
)

const spnHead = "`wineventlog_security` EventCode=5136 AttributeLDAPDisplayName=servicePrincipalName" +
	" | transaction ObjectDN AttributeValue startswith=(EventCode=5136 OperationType=\"%%14674\") endswith=(EventCode=5136 OperationType=\"%%14675\")"

// A later transaction runs when what it finds depends on its own events
// alone (startswith= and endswith=) and the rule keeps only short ones,
// which a run's window holds whole.
func TestTransactionStages(t *testing.T) {
	for search, want := range map[string]string{
		spnHead + " | eval short_lived=case((duration<300),\"TRUE\") | search short_lived = TRUE | rename ObjectDN as user": "",
		spnHead + " | where duration<300":                              "",
		strings.Replace(spnHead, "endswith", "maxspan=2m endswith", 1): "",
		spnHead:                           "no maxspan=",
		spnHead + " | where duration>300": "no maxspan=",
		spnHead + " | where duration<300 OR eventcount>2":                                                  "no maxspan=",
		spnHead + " | eval short_lived=case((duration<300),\"TRUE\") | search short_lived = FALSE":         "no maxspan=",
		strings.Replace(spnHead, " endswith=(EventCode=5136 OperationType=\"%%14675\")", " maxspan=2m", 1): "without endswith=",
		"`wineventlog_security` EventCode=5136 | transaction ObjectDN maxpause=5m | where eventcount>=5":   "without startswith=",
		spnHead + " | where duration<300 | eval x=lower(OperationType)":                                    "eval of OperationType",
		spnHead + " | where duration<300 AND OperationType=\"%%14674\"":                                    "where of OperationType",
		spnHead + " | where duration<300 | sort - duration":                                                "sort after a transaction",
		spnHead + " | where duration<7200":                                                                 "longer than",
	} {
		r, err := Parse(rule(search), testMacros)
		if want == "" {
			if err != nil {
				t.Errorf("%s: %v", search, err)
			} else if r.PostSpan <= 0 || r.PostSpan > 5*time.Minute {
				t.Errorf("%s: span %v", search, r.PostSpan)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v, want %q", search, err, want)
		}
	}
}

// A stats grouped by a field a transaction makes multivalue groups each
// transaction under each of its values, as Splunk's does.
func TestTransactionStats(t *testing.T) {
	r, err := Parse(rule(spnHead+" maxspan=2m | stats count by ObjectDN OperationType"), testMacros)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(r.Post, "mvexpand OperationType\n| stats") || strings.Contains(r.Post, "mvexpand ObjectDN") {
		t.Errorf("post:\n%s", r.Post)
	}
	for _, c := range Cases(r) {
		if !c.Expect || len(c.Then) == 0 {
			continue
		}
		rows, err := r.runPost(storedAll(c))
		if err != nil || len(rows) != 2 {
			t.Errorf("%d rows (%v), want one for each operation", len(rows), err)
		}
		return
	}
	t.Error("no test run of events comes through")
}

// The test events of a later transaction: a start and its end, which it
// keeps, and runs it does not: the end too late, before the start,
// alone, or of another object.
func TestTransactionCases(t *testing.T) {
	r, err := Parse(rule(spnHead+" | eval short_lived=case((duration<300),\"TRUE\") | search short_lived = TRUE"), testMacros)
	if err != nil {
		t.Fatal(err)
	}
	cases := Cases(r)
	var pos, neg int
	for _, c := range cases {
		if len(c.Then) == 0 {
			continue
		}
		if got := r.readsAll(c); got != c.Expect {
			t.Errorf("run of events then %d s later: reads %v, expect %v", c.Then[0].Later, got, c.Expect)
		}
		if c.Expect {
			pos++
		} else {
			neg++
		}
	}
	if pos != 1 || neg < 3 {
		t.Errorf("%d runs found, %d not; want 1 and at least 3", pos, neg)
	}
	tf := &sigmacheck.TestFile{Rule: r.ID, Cases: cases}
	q, err := query.Parse("datamodel=Change (sourcetype=WinEventLog:* AND signature_id IN (5136)) (signature_id=5136 AND ad_attribute=servicePrincipalName)")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range Verify(r, q, tf) {
		t.Error(e)
	}
}
