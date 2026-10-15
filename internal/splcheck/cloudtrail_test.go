package splcheck

import (
	"testing"

	"github.com/jrsamsanchez/signalith/internal/sigmacheck"
)

func TestCloudTrailRule(t *testing.T) {
	r, err := Parse(rule("`cloudtrail` eventName = StopLogging eventSource = cloudtrail.amazonaws.com userAgent !=console.amazonaws.com errorCode = success\n"+
		"| rename user_name as user\n| stats count min(_time) as firstTime max(_time) as lastTime by signature dest user user_agent src vendor_account vendor_region vendor_product"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if r.Node != CloudTrailNode {
		t.Fatalf("node %s", r.Node)
	}
	// errorCode=success is a record without an error code.
	ok := map[string]string{"eventName": "StopLogging", "eventSource": "cloudtrail.amazonaws.com", "userAgent": "aws-cli/2.15.0"}
	failed := map[string]string{"errorCode": "AccessDenied"}
	for k, v := range ok {
		failed[k] = v
	}
	if !Eval(r.Where, ok) || Eval(r.Where, failed) {
		t.Error("errorCode=success should read a record without an error code")
	}
	pos, neg := 0, 0
	for _, c := range Cases(r) {
		if c.Channel != sigmacheck.CloudTrailChannel {
			t.Errorf("channel %s", c.Channel)
		}
		if c.Expect {
			pos++
			if c.Data["eventName"] != "StopLogging" || c.Data["errorCode"] != "" {
				t.Errorf("positive %v", c.Data)
			}
		} else {
			neg++
		}
	}
	if pos == 0 || neg == 0 {
		t.Errorf("%d positive and %d negative cases", pos, neg)
	}

	// A count of failed sign-ins, by CIM fields and a quoted CloudTrail
	// field; each failure is its own raw event.
	r, err = Parse(rule("`cloudtrail` eventName=ConsoleLogin action=failure \"additionalEventData.MFAUsed\"=Yes\n"+
		"| bucket span=10m _time\n| rename user_name as user\n| stats dc(_raw) AS failed_attempts values(src) as src by _time, user, vendor_account\n| where failed_attempts > 20"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if r.Threshold == nil || r.Threshold.Aggs[0].Func != "count" || r.Threshold.Aggs[0].Name != "failed_attempts" {
		t.Fatalf("threshold %+v", r.Threshold)
	}
	for _, c := range Cases(r) {
		if c.Expect && (c.Data["responseElements.ConsoleLogin"] != "Failure" || c.Data["eventSource"] != "signin.amazonaws.com") {
			t.Errorf("positive %v", c.Data)
		}
	}
	if _, err := Parse(rule("`cloudtrail` eventName=x requestParameters.items{}.userId=*"), nil); err == nil {
		t.Error("a field CloudTrail records do not have parsed")
	}
}
