package splcheck

import (
	"errors"
	"slices"
	"strings"

	"github.com/jrsamsanchez/signalith/internal/ingest"
	"github.com/jrsamsanchez/signalith/internal/sigmacheck"
)

// CloudTrailNode is the node of AWS CloudTrail records (the cloudtrail
// macro). A search names no event code. Its fields are CloudTrail's own
// (eventName, userIdentity.type, requestParameters.*), which Signalith
// keeps by the same names, and the CIM fields Splunk's AWS add-on gives
// each record, which Signalith sets too.
const CloudTrailNode = "CloudTrail"

// cloudTrailCIM are the CIM fields of a CloudTrail record, with the
// Signalith field each is stored as.
var cloudTrailCIM = map[string]string{
	"action": "action", "status": "status", "user": "user", "user_name": "user_name", "src": "src",
	"src_ip": "src", "signature": "signature", "command": "command", "dest": "dest", "app": "app",
	"user_agent": "user_agent", "vendor_account": "vendor_account", "vendor_region": "vendor_region",
	"vendor_product": "vendor_product", "reason": "reason", "user_type": "userIdentity.type",
	"aws_account_id": "vendor_account", "user_arn": "userIdentity.arn",
}

// cloudTrailField is the stored field of a CloudTrail search's field.
func cloudTrailField(name string) (string, bool) {
	if f, ok := cloudTrailCIM[name]; ok {
		return f, true
	}
	return name, ingest.CloudTrailField(name)
}

// cloudTrailRecord turns a field-level event into the CloudTrail record
// that carries it: CIM fields back to the record fields they come from.
// A failed console sign-in says so in its response; any other failed
// call has an error code.
func cloudTrailRecord(ev map[string]string) sigmacheck.Case {
	data := map[string]string{}
	set := func(k, v string) {
		if v != "" && data[k] == "" {
			data[k] = v
		}
	}
	for k, v := range ev {
		if ingest.CloudTrailField(k) {
			data[k] = v
		}
	}
	set("eventName", ev["signature"])
	set("eventName", ev["command"])
	set("eventSource", ev["dest"])
	set("sourceIPAddress", ev["src"])
	set("sourceIPAddress", ev["src_ip"])
	set("userAgent", ev["user_agent"])
	set("userIdentity.userName", ev["user_name"])
	set("userIdentity.userName", ev["user"])
	set("userIdentity.type", ev["user_type"])
	set("recipientAccountId", ev["vendor_account"])
	set("recipientAccountId", ev["aws_account_id"])
	set("awsRegion", ev["vendor_region"])
	set("errorMessage", ev["reason"])
	if data["eventName"] == "ConsoleLogin" {
		set("eventSource", "signin.amazonaws.com")
	}
	failed := strings.EqualFold(ev["action"], "failure") || strings.EqualFold(ev["status"], "failure")
	if data["eventSource"] == "signin.amazonaws.com" {
		if failed {
			set("responseElements.ConsoleLogin", "Failure")
		} else if strings.EqualFold(ev["action"], "success") {
			set("responseElements.ConsoleLogin", "Success")
		}
	} else if failed {
		set("errorCode", "AccessDenied")
	}
	// What every record has, so a count can group its test records.
	set("eventSource", "ec2.amazonaws.com")
	set("eventName", "DescribeInstances")
	set("sourceIPAddress", "203.0.113.7")
	set("userAgent", "aws-cli/2.15.0")
	set("userIdentity.type", "IAMUser")
	set("userIdentity.userName", "tester")
	set("recipientAccountId", "111122223333")
	set("awsRegion", "us-east-1")
	return sigmacheck.Case{Channel: sigmacheck.CloudTrailChannel, EventID: "AwsApiCall", Data: data}
}

// cloudTrailSuccess reads errorCode=success as a record without an error
// code: Splunk's AWS add-on fills in success for a call that worked,
// which Signalith stores as CloudTrail wrote it, with none.
func cloudTrailSuccess(e Expr) (Expr, error) {
	switch x := e.(type) {
	case *And:
		for i, k := range x.Kids {
			n, err := cloudTrailSuccess(k)
			if err != nil {
				return nil, err
			}
			x.Kids[i] = n
		}
	case *Or:
		for i, k := range x.Kids {
			n, err := cloudTrailSuccess(k)
			if err != nil {
				return nil, err
			}
			x.Kids[i] = n
		}
	case *Not:
		n, err := cloudTrailSuccess(x.Kid)
		if err != nil {
			return nil, err
		}
		x.Kid = n
	case *Cmp:
		if x.Field != "errorCode" || !slices.ContainsFunc(x.Values, func(v string) bool { return strings.EqualFold(v, "success") }) {
			return e, nil
		}
		if len(x.Values) != 1 || x.Regex {
			return nil, errors.New("errorCode=success with other error codes is not supported")
		}
		present := &Cmp{Field: "errorCode", Values: []string{"*"}}
		if x.Neg {
			return present, nil
		}
		return &Not{Kid: present}, nil
	}
	return e, nil
}
