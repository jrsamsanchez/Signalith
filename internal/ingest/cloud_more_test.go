// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package ingest

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"
)

func TestO365Helpers(t *testing.T) {
	if got := O365RecordType("AzureActiveDirectoryStsLogon"); got != "15" {
		t.Errorf("O365RecordType(AzureActiveDirectoryStsLogon) = %q, want 15", got)
	}
	if got := O365RecordType("NoSuchType"); got != "" {
		t.Errorf("O365RecordType(NoSuchType) = %q", got)
	}
	for v, want := range map[any]string{"s": "s", true: "true", json.Number("12"): "12", 1.5: "1.5", int64(7): "7", 8: "8", nil: ""} {
		if got := o365Text(v); got != want {
			t.Errorf("o365Text(%#v) = %q, want %q", v, got, want)
		}
	}
	for op, want := range map[string]string{
		"New-InboxRule": "created", "Remove-MailboxPermission": "deleted", "Disable-Thing": "deleted",
		"Set-Mailbox": "modified", "Consent to application.": "modified", "Reset user password.": "modified",
		"MailItemsAccessed": "",
	} {
		if got := O365ChangeAction(op); got != want {
			t.Errorf("O365ChangeAction(%q) = %q, want %q", op, got, want)
		}
	}
	for _, c := range []struct {
		name, want string
		ok         bool
	}{
		{"eventSource", "Workload", true}, {"RequestType", "ExtendedProperties{}.Value", true},
		{"Operation", "Operation", true}, {"lowercase", "", false}, {"", "", false},
	} {
		if got, ok := O365SigmaField(c.name); got != c.want || ok != c.ok {
			t.Errorf("O365SigmaField(%q) = %q %v, want %q %v", c.name, got, ok, c.want, c.ok)
		}
	}
}

func TestTestList(t *testing.T) {
	for _, c := range []struct {
		v  string
		ok bool
		n  int
	}{
		{`[{"Name": "a"}, {"Name": "b"}]`, true, 2},
		{`not a list`, false, 0},
		{`[{"Name": "a"}] trailing`, false, 0},
		{`[{"Name": "a"}, 3]`, false, 0},
		{`[{"Name": `, false, 0},
	} {
		l, ok := testList(c.v)
		if ok != c.ok || len(l) != c.n {
			t.Errorf("testList(%q) = %v %v", c.v, l, ok)
		}
	}
}

func TestO365TestRecords(t *testing.T) {
	r := O365Record(now, "Exchange", map[string]string{
		"ModifiedProperties": `[{"Name": "Forward", "NewValue": "x@evil.example"}]`,
		"Parameters{}.Name":  "ForwardTo",
		"Tags{}":             "one",
	})
	if l, ok := r["ModifiedProperties"].([]any); !ok || len(l) != 1 {
		t.Errorf("ModifiedProperties = %#v", r["ModifiedProperties"])
	}
	if l, ok := r["Parameters"].([]any); !ok || l[0].(map[string]any)["Name"] != "ForwardTo" {
		t.Errorf("Parameters = %#v", r["Parameters"])
	}
	if l, ok := r["Tags"].([]any); !ok || !reflect.DeepEqual(l, []any{"one"}) {
		t.Errorf("Tags = %#v", r["Tags"])
	}

	// Sigma's older field names: a non-alert operation, a request type,
	// no status (so no result), and other fields kept.
	r = O365SigmaRecord("h1", now, map[string]string{"eventSource": "Exchange", "eventName": "Set-Mailbox",
		"RequestType": "Login:login", "ClientIP": "192.0.2.1"})
	if r["Operation"] != "Set-Mailbox" || r["ClientIP"] != "192.0.2.1" || r["hostname"] != "h1" {
		t.Errorf("sigma record = %v", r)
	}
	if _, ok := r["ResultStatus"]; ok {
		t.Errorf("a record without status has a result: %v", r["ResultStatus"])
	}
	ext, _ := r["ExtendedProperties"].([]any)
	if len(ext) != 1 || ext[0].(map[string]any)["Value"] != "Login:login" {
		t.Errorf("ExtendedProperties = %#v", r["ExtendedProperties"])
	}
	r = O365SigmaRecord("h1", now, map[string]string{"eventSource": "SecurityComplianceCenter", "eventName": "Alert", "status": "success"})
	if r["Operation"] != "AlertTriggered" || r["ResultStatus"] != "Succeeded" {
		t.Errorf("alert record = %v", r)
	}
	// Two records of different data have different IDs.
	a := O365SigmaRecord("h1", now, map[string]string{"x": "1"})
	b := O365SigmaRecord("h1", now, map[string]string{"x": "2"})
	if a["Id"] == b["Id"] {
		t.Error("two test records share an Id")
	}
}

// A record field named as one of Signalith's own is not kept.
func TestO365SkipsOwnFieldNames(t *testing.T) {
	r := O365Record(now, "Exchange", nil)
	r["datamodel"] = "spoof"
	ev := Normalize(O365Tag, r, now)
	if ev.Fields["datamodel"] == "spoof" {
		t.Errorf("a record set datamodel: %v", ev.Fields["datamodel"])
	}
}

func TestCloudTrailHelpers(t *testing.T) {
	if got := CloudTrailList("requestParameters.containerDefinitions.image"); got != "requestParameters.containerDefinitions" {
		t.Errorf("CloudTrailList = %q", got)
	}
	if got := CloudTrailList("requestParameters.bucketName"); got != "" {
		t.Errorf("CloudTrailList(other) = %q", got)
	}
	out := map[string]any{}
	flattenCloudTrail("p", map[string]any{
		"empty": []any{}, "n": json.Number("3"), "f": json.Number("1.5"), "w": 2.0, "x": 2.5,
		"i": int64(4), "j": 5,
	}, out)
	want := map[string]any{"p.n": int64(3), "p.f": 1.5, "p.w": int64(2), "p.x": 2.5, "p.i": int64(4), "p.j": int64(5)}
	for k, v := range want {
		if out[k] != v {
			t.Errorf("%s = %#v, want %#v", k, out[k], v)
		}
	}
	if _, ok := out["p.empty"]; ok {
		t.Error("an empty list was kept")
	}
	if cloudTrailText(`{"eventVersion": "1.09"}`) != nil || cloudTrailText(`{`) != nil {
		t.Error("cloudTrailText took what is not a record")
	}
	if isCloudTrailOTLP(map[string]any{"other": 1}) {
		t.Error("an OTLP record without an event ID is CloudTrail")
	}
}

func TestCloudTrailUserAndParameters(t *testing.T) {
	r := CloudTrailRecord("h1", now, map[string]string{
		"eventSource": "s3.amazonaws.com", "eventName": "PutBucketAcl", "eventID": "e1", "awsRegion": "us-east-1",
		"userIdentity.type": "AssumedRole", "userIdentity.arn": "arn:aws:sts::1:assumed-role/Admin/session-x",
		"requestParameters.containerDefinitions.image": "evil:latest",
		"requestParameters.grants":                     `[{"grantee": "AllUsers"}]`,
	})
	defs, _ := r["requestParameters"].(map[string]any)["containerDefinitions"].([]any)
	if len(defs) != 1 || defs[0].(map[string]any)["image"] != "evil:latest" {
		t.Errorf("containerDefinitions = %#v", r["requestParameters"])
	}
	r["responseElements"] = "plain text"
	ev := Normalize(CloudTrailTag, r, now)
	expect(t, ev.Fields, map[string]any{"user": "session-x", "response_elements": "plain text"})
}

func TestCloudTrailFromOTLPExtras(t *testing.T) {
	attrs := map[string]any{
		"aws.cloudtrail.event_id": "e1", "rpc.method": "ec2.amazonaws.com/StartInstances",
		"aws.session.console": true,
		"aws.resources":       []any{map[string]any{"account.id": "1", "type": "AWS::EC2::Instance", "arn": "arn:x"}},
	}
	r := cloudTrailFromOTLP(attrs, map[string]any{"cloud.region": "eu-west-1"}, time.Time{})
	if r["eventName"] != "StartInstances" || r["eventSource"] != "ec2.amazonaws.com" || r["sessionCredentialFromConsole"] != "true" {
		t.Errorf("record = %v", r)
	}
	res, _ := r["resources"].([]any)
	if len(res) != 1 || res[0].(map[string]any)["ARN"] != "arn:x" {
		t.Errorf("resources = %#v", r["resources"])
	}
	if _, ok := r["eventTime"]; ok {
		t.Error("a zero time was written")
	}
}
