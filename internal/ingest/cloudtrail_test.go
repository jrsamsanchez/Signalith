package ingest

import (
	"fmt"
	"strings"
	"testing"
)

// A call that changes something, as CloudTrail writes it.
const cloudTrailCreateUser = `{
	"eventVersion": "1.09", "eventTime": "2026-10-11T11:58:01Z", "eventSource": "iam.amazonaws.com",
	"eventName": "CreateAccessKey", "awsRegion": "us-east-1", "sourceIPAddress": "203.0.113.7",
	"userAgent": "aws-cli/2.15.0", "eventType": "AwsApiCall", "readOnly": false, "managementEvent": true,
	"eventCategory": "Management", "recipientAccountId": "111122223333", "eventID": "e1",
	"userIdentity": {"type": "AssumedRole", "principalId": "AROAEXAMPLE:alice", "arn": "arn:aws:sts::111122223333:assumed-role/Admin/alice",
		"accountId": "111122223333", "accessKeyId": "ASIAEXAMPLE",
		"sessionContext": {"sessionIssuer": {"type": "Role", "arn": "arn:aws:iam::111122223333:role/Admin", "userName": "Admin"},
			"attributes": {"mfaAuthenticated": "false", "creationDate": "2026-10-11T11:00:00Z"}}},
	"requestParameters": {"userName": "backdoor", "tags": [{"key": "a", "value": "b"}], "limits": {"max": 5}},
	"responseElements": {"accessKey": {"accessKeyId": "AKIAEXAMPLE", "status": "Active"}}
}`

func TestCloudTrailChange(t *testing.T) {
	ev := Normalize(CloudTrailTag, decode(t, cloudTrailCreateUser), now)
	expect(t, ev.Document(), map[string]any{
		"datamodel": "Change", "sourcetype": "aws:cloudtrail", "vendor_product": "AWS CloudTrail",
		"eventName": "CreateAccessKey", "eventSource": "iam.amazonaws.com", "readOnly": false,
		"userIdentity.type": "AssumedRole", "userIdentity.sessionContext.sessionIssuer.type": "Role",
		"userIdentity.sessionContext.attributes.mfaAuthenticated": "false",
		"requestParameters.userName":                              "backdoor", "requestParameters.limits.max": int64(5),
		"requestParameters.tags":                 `[{"key":"a","value":"b"}]`,
		"responseElements.accessKey.accessKeyId": "AKIAEXAMPLE",
		"signature":                              "CreateAccessKey", "command": "CreateAccessKey", "action": "created", "status": "success",
		"user": "Admin", "user_name": "Admin", "src": "203.0.113.7", "user_agent": "aws-cli/2.15.0",
		"vendor_account": "111122223333", "vendor_region": "us-east-1", "dest": "iam.amazonaws.com",
		"object_category": "iam", "change_type": "AWS API Call", "@timestamp": "2026-10-11T11:58:01Z",
	})
	if !strings.Contains(ev.Fields["message"].(string), `"backdoor"`) {
		t.Errorf("message = %v", ev.Fields["message"])
	}
	for k := range ev.Fields {
		if !KnownField(k) && !strings.HasPrefix(k, "requestParameters.") && !strings.HasPrefix(k, "responseElements.") {
			t.Errorf("field %s is not mapped in the index template", k)
		}
	}
}

func TestCloudTrailSignInAndReads(t *testing.T) {
	// A failed sign-in to the console.
	ev := Normalize(CloudTrailTag, decode(t, `{"eventVersion": "1.08", "eventTime": "2026-10-11T11:00:00Z",
		"eventSource": "signin.amazonaws.com", "eventName": "ConsoleLogin", "sourceIPAddress": "198.51.100.4",
		"userIdentity": {"type": "IAMUser", "userName": "bob", "accountId": "111122223333"},
		"errorMessage": "Failed authentication", "responseElements": {"ConsoleLogin": "Failure"},
		"additionalEventData": {"MFAUsed": "No"}, "recipientAccountId": "111122223333"}`), now)
	expect(t, ev.Document(), map[string]any{
		"datamodel": "Authentication", "action": "failure", "user": "bob", "src": "198.51.100.4",
		"app": "aws:console", "dest": "aws:111122223333", "reason": "Failed authentication",
		"additionalEventData.MFAUsed": "No",
	})
	// The root account, and a call that only reads: Other, found by any
	// tag since the record says what it is.
	ev = Normalize("http", decode(t, `{"eventVersion": "1.08", "eventTime": "2026-10-11T11:00:00Z",
		"eventSource": "s3.amazonaws.com", "eventName": "ListBuckets", "readOnly": true,
		"userIdentity": {"type": "Root", "arn": "arn:aws:iam::111122223333:root"}, "errorCode": "AccessDenied"}`), now)
	expect(t, ev.Document(), map[string]any{
		"datamodel": "Other", "sourcetype": "aws:cloudtrail", "user": "root", "status": "failure", "reason": "AccessDenied",
	})
	if cloudTrailAction("Describe") != "modified" || cloudTrailAction("Delete") != "deleted" || cloudTrailAction("Stopped") != "modified" ||
		cloudTrailAction("PutBucketPolicy") != "created" || cloudTrailAction("Addition") != "modified" {
		t.Error("cloudTrailAction")
	}
}

func TestCloudTrailTestRecord(t *testing.T) {
	ev := Normalize(CloudTrailTag, CloudTrailRecord("case-1", now, map[string]string{"eventName": "StopLogging", "eventSource": "cloudtrail.amazonaws.com", "userIdentity.type": "Root"}), now)
	expect(t, ev.Document(), map[string]any{"host": "case-1", "eventName": "StopLogging", "userIdentity.type": "Root", "user": "root"})
}

func TestCloudTrailCapsFields(t *testing.T) {
	var b strings.Builder
	b.WriteString(`{"eventVersion": "1.08", "eventSource": "ec2.amazonaws.com", "eventName": "RunInstances", "requestParameters": {`)
	for i := range 300 {
		if i > 0 {
			b.WriteString(",")
		}
		fmt.Fprintf(&b, `"k%03d": "v"`, i)
	}
	b.WriteString(`, "a": {"b": {"c": {"d": {"e": {"f": 1}}}}}, "bad.name": "x"}}`)
	ev := Normalize(CloudTrailTag, decode(t, b.String()), now)
	n := 0
	for k := range ev.Fields {
		if strings.HasPrefix(k, "requestParameters.") {
			n++
		}
	}
	if n != cloudTrailMaxLeaves {
		t.Errorf("%d parameter fields, want %d", n, cloudTrailMaxLeaves)
	}
	if v := ev.Fields["requestParameters.a.b.c.d"]; v != `{"e":{"f":1}}` {
		t.Errorf("deep object = %v", v)
	}
	if _, ok := ev.Fields["requestParameters.bad.name"]; ok {
		t.Error("a key with a dot became a field")
	}
}

func TestOTLPCloudTrail(t *testing.T) {
	// As the Collector's aws_logs_encoding extension decodes it, with
	// semantic conventions 1.40 (a qualified rpc.method).
	docs := otlpDocs(t, tRes{attrs: []tKV{{"cloud.provider", "aws"}, {"cloud.region", "eu-west-1"}, {"cloud.account.id", "111122223333"}},
		recs: []tRec{{
			time: uint64(now.UnixNano()),
			attrs: []tKV{
				{"aws.cloudtrail.event_version", "1.08"}, {"aws.cloudtrail.event_id", "e2"},
				{"rpc.method", "s3.amazonaws.com/PutBucketVersioning"}, {"rpc.system.name", "AwsApiCall"},
				{"aws.event.read_only", false}, {"source.address", "203.0.113.7"}, {"user_agent.original", "Boto3/1.34"},
				{"user.name", "alice"}, {"aws.principal.type", "IAMUser"}, {"aws.principal.arn", "arn:aws:iam::111122223333:user/alice"},
				{"aws.user_identity.session_context.attributes.mfa_authenticated", false},
				{"aws.request.parameters", []tKV{{"bucketName", "logs"}, {"VersioningConfiguration", []tKV{{"Status", "Suspended"}}}}},
				{"aws.error.code", "AccessDenied"}, {"tls.protocol.version", "1.3"},
			},
		}}})
	expect(t, docs[0], map[string]any{
		"datamodel": "Change", "sourcetype": "aws:cloudtrail", "eventName": "PutBucketVersioning", "eventSource": "s3.amazonaws.com",
		"eventType": "AwsApiCall", "awsRegion": "eu-west-1", "recipientAccountId": "111122223333", "userIdentity.type": "IAMUser",
		"userIdentity.userName": "alice", "userIdentity.sessionContext.attributes.mfaAuthenticated": "false",
		"requestParameters.bucketName": "logs", "requestParameters.VersioningConfiguration.Status": "Suspended",
		"errorCode": "AccessDenied", "status": "failure", "user": "alice", "tlsDetails.tlsVersion": "TLSv1.3",
		"@timestamp": "2026-10-11T12:00:00Z",
	})
	// The older conventions: the service in rpc.service.
	docs = otlpDocs(t, tRes{recs: []tRec{{attrs: []tKV{{"aws.cloudtrail.event_id", "e3"}, {"rpc.method", "ConsoleLogin"},
		{"rpc.service", "signin.amazonaws.com"}, {"rpc.system", "AwsConsoleSignIn"}, {"aws.user_identity.principal.type", "Root"},
		{"aws.response.elements", []tKV{{"ConsoleLogin", "Success"}}}}}}})
	expect(t, docs[0], map[string]any{"datamodel": "Authentication", "action": "success", "user": "root", "eventType": "AwsConsoleSignIn"})
	// A record as JSON text, as CloudWatch Logs passes it on.
	docs = otlpDocs(t, tRes{recs: []tRec{{body: strings.ReplaceAll(cloudTrailCreateUser, "\n", "")}}})
	expect(t, docs[0], map[string]any{"datamodel": "Change", "eventName": "CreateAccessKey", "requestParameters.userName": "backdoor"})
}
