package ingest

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

// An Admin Activity entry: a firewall rule deleted, as a log sink
// publishes it to Pub/Sub.
const gcpFirewallDelete = `{"protoPayload": {"@type": "type.googleapis.com/google.cloud.audit.AuditLog",
	"status": {}, "authenticationInfo": {"principalEmail": "alice@example.com"},
	"requestMetadata": {"callerIp": "203.0.113.7", "callerSuppliedUserAgent": "google-cloud-sdk gcloud/500.0.0",
		"requestAttributes": {"time": "2026-10-11T11:58:01.000Z", "auth": {}}, "destinationAttributes": {}},
	"serviceName": "compute.googleapis.com", "methodName": "v1.compute.firewalls.delete",
	"authorizationInfo": [{"permission": "compute.firewalls.delete", "granted": true,
		"resourceAttributes": {"service": "compute", "name": "projects/prod-1/global/firewalls/allow-ssh", "type": "compute.firewalls"}}],
	"resourceName": "projects/prod-1/global/firewalls/allow-ssh",
	"request": {"@type": "type.googleapis.com/compute.firewalls.delete"},
	"response": {"@type": "type.googleapis.com/operation", "status": "RUNNING", "id": "123"}},
	"insertId": "-abc123e1", "resource": {"type": "gce_firewall_rule",
		"labels": {"project_id": "prod-1", "firewall_rule_id": "456"}},
	"timestamp": "2026-10-11T11:58:01.123456Z", "severity": "NOTICE",
	"logName": "projects/prod-1/logs/cloudaudit.googleapis.com%2Factivity",
	"operation": {"id": "operation-1", "producer": "compute.googleapis.com", "first": true},
	"labels": {"team": "net", "cost.center": "1"},
	"receiveTimestamp": "2026-10-11T11:58:02.000Z"}`

// A Data Access entry: a bucket listed, which was denied.
const gcpBucketListDenied = `{"protoPayload": {"@type": "type.googleapis.com/google.cloud.audit.AuditLog",
	"status": {"code": 7, "message": "PERMISSION_DENIED"},
	"authenticationInfo": {"principalEmail": "bob@example.com"},
	"requestMetadata": {"callerIp": "198.51.100.4"},
	"serviceName": "storage.googleapis.com", "methodName": "storage.buckets.list",
	"authorizationInfo": [{"permission": "storage.buckets.list", "granted": false}, {"permission": "storage.buckets.get"}],
	"resourceName": "projects/_/buckets/backups"},
	"insertId": "x1", "resource": {"type": "gcs_bucket", "labels": {"project_id": "prod-1", "bucket_name": "backups", "location": "us"}},
	"timestamp": "2026-10-11T11:00:00Z", "severity": "ERROR",
	"logName": "projects/prod-1/logs/cloudaudit.googleapis.com%2Fdata_access"}`

func TestGCPAdminActivity(t *testing.T) {
	ev := Normalize(GCPTag, decode(t, gcpFirewallDelete), now)
	expect(t, ev.Document(), map[string]any{
		"datamodel": "Change", "sourcetype": "google:gcp:pubsub:message", "vendor_product": "Google Cloud",
		"logName": "projects/prod-1/logs/cloudaudit.googleapis.com%2Factivity", "log_id": "cloudaudit.googleapis.com/activity",
		"insertId": "-abc123e1", "severity": "NOTICE", "resource.type": "gce_firewall_rule", "resource.labels.project_id": "prod-1",
		"resource.labels.firewall_rule_id": "456",
		"protoPayload.methodName":          "v1.compute.firewalls.delete", "protoPayload.serviceName": "compute.googleapis.com",
		"protoPayload.authenticationInfo.principalEmail": "alice@example.com",
		"protoPayload.requestMetadata.callerIp":          "203.0.113.7",
		"protoPayload.resourceName":                      "projects/prod-1/global/firewalls/allow-ssh",
		"operation.id":                                   "operation-1", "operation.first": true,
		"labels": `{"cost.center":"1","team":"net"}`,
		"action": "deleted", "status": "success", "user": "alice@example.com", "src_user": "alice@example.com",
		"src": "203.0.113.7", "signature": "v1.compute.firewalls.delete", "app": "compute.googleapis.com",
		"object": "allow-ssh", "object_category": "gce_firewall_rule", "vendor_account": "prod-1",
		"http_user_agent": "google-cloud-sdk gcloud/500.0.0", "change_type": "GCP API Call",
		"request_parameters": `{"@type":"type.googleapis.com/compute.firewalls.delete"}`,
		"@timestamp":         "2026-10-11T11:58:01.123456Z",
	})
	// A list's values, by Splunk's names, as text.
	expectLists(t, ev, map[string][]any{
		"protoPayload.authorizationInfo{}.permission": {"compute.firewalls.delete"},
		"protoPayload.authorizationInfo{}.granted":    {"true"},
	})
	if ev.ID == "" {
		t.Error("no document ID: the same entry delivered twice would be stored twice")
	}
	for k := range ev.Fields {
		if strings.HasPrefix(k, "labels.") {
			t.Errorf("caller-chosen label %s became a field", k)
		}
	}
}

func TestGCPDataAccess(t *testing.T) {
	ev := Normalize(GCPTag, decode(t, gcpBucketListDenied), now)
	expect(t, ev.Document(), map[string]any{
		"datamodel": "Other", "log_id": "cloudaudit.googleapis.com/data_access", "status": "failure",
		"reason": "PERMISSION_DENIED", "protoPayload.status.code": int64(7), "vendor_region": "us", "user": "bob@example.com",
	})
	expectLists(t, ev, map[string][]any{"protoPayload.authorizationInfo{}.permission": {"storage.buckets.list", "storage.buckets.get"}})
	// Without a tag: an entry is known by its shape.
	ev = Normalize("", decode(t, gcpBucketListDenied), now)
	if ev.Fields["sourcetype"] != GCPSourcetype {
		t.Errorf("untagged sourcetype = %v", ev.Fields["sourcetype"])
	}
}

func TestGCPAction(t *testing.T) {
	for method, want := range map[string]string{
		"v1.compute.instances.insert": "created", "google.iam.admin.v1.CreateServiceAccount": "created",
		"io.k8s.core.v1.secrets.delete": "deleted", "SetIamPolicy": "modified", "storage.buckets.update": "modified",
		"google.iam.admin.v1.DisableServiceAccount": "disabled", "v1.compute.instances.stop": "stopped", "": "modified",
	} {
		if got := GCPAction(method); got != want {
			t.Errorf("GCPAction(%q) = %q, want %q", method, got, want)
		}
	}
}

// A Pub/Sub push subscription posts the message, with the entry in its
// data as base64; a pull returns the same message with an ackId.
func TestGCPPubSubMessage(t *testing.T) {
	data := base64.StdEncoding.EncodeToString([]byte(gcpFirewallDelete))
	for _, msg := range []string{
		`{"message": {"data": "` + data + `", "messageId": "1", "publishTime": "2026-10-11T11:58:03Z"}, "subscription": "projects/prod-1/subscriptions/signalith"}`,
		`{"ackId": "a1", "message": {"data": "` + data + `", "messageId": "1"}}`,
		// As Splunk's add-on stores it.
		`{"data": ` + gcpFirewallDelete + `, "publish_time": 1}`,
	} {
		ev := Normalize(GCPTag, decode(t, msg), now)
		expect(t, ev.Document(), map[string]any{"datamodel": "Change", "protoPayload.methodName": "v1.compute.firewalls.delete",
			"@timestamp": "2026-10-11T11:58:01.123456Z"})
	}
	// A message whose data is not an entry is kept as it came.
	ev := Normalize(GCPTag, decode(t, `{"message": {"data": "bm90IGpzb24="}}`), now)
	if ev.Fields["sourcetype"] == GCPSourcetype {
		t.Errorf("fields = %v", ev.Fields)
	}
}

// The googlecloudpubsub receiver with the text encoding passes each
// message's data on as the body's text.
func TestGCPFromOTLP(t *testing.T) {
	published := uint64(now.Add(-time.Minute).UnixNano())
	docs := otlpDocs(t, tRes{attrs: []tKV{{"host.name", "collector1"}}, recs: []tRec{
		{observed: published, body: strings.ReplaceAll(gcpFirewallDelete, "\n", "")},
		{observed: published, body: `{"logName": "x"}`},
	}})
	if len(docs) != 2 {
		t.Fatalf("%d documents, want 2", len(docs))
	}
	expect(t, docs[0], map[string]any{"datamodel": "Change", "sourcetype": GCPSourcetype, "host": "collector1",
		"protoPayload.methodName": "v1.compute.firewalls.delete", "@timestamp": "2026-10-11T11:58:01.123456Z"})
	if docs[1]["sourcetype"] == GCPSourcetype {
		t.Errorf("not an entry: %v", docs[1])
	}
}

func TestGCPFieldsKept(t *testing.T) {
	for _, s := range []string{gcpFirewallDelete, gcpBucketListDenied} {
		ev := Normalize(GCPTag, decode(t, s), now)
		for k := range ev.Fields {
			if !KnownField(k) && !GCPField(k) {
				t.Errorf("field %s is neither mapped in the index template nor a log entry's", k)
			}
		}
	}
}

// Sigma's names for an entry's fields build a test entry that keeps them.
func TestGCPRecord(t *testing.T) {
	data := map[string]string{
		"gcp.audit.method_name": "io.k8s.core.v1.pods.create", "data.protoPayload.resource.type": "k8s_cluster",
		"data.protoPayload.logName": "cloudaudit.googleapis.com/activity", "data.protoPayload.request": "image-policy.k8s.io/break-glass",
		"data.protoPayload.authorizationInfo.permission": "container.pods.create", "data.protoPayload.authorizationInfo.granted": "true",
	}
	ev := Normalize(GCPTag, GCPRecord("h1", now, data), now)
	expect(t, ev.Document(), map[string]any{
		"host": "h1", "protoPayload.methodName": "io.k8s.core.v1.pods.create", "resource.type": "k8s_cluster",
		"log_id": "cloudaudit.googleapis.com/activity", "datamodel": "Change", "action": "created",
	})
	expectLists(t, ev, map[string][]any{
		"protoPayload.authorizationInfo{}.permission": {"container.pods.create"},
		"protoPayload.authorizationInfo{}.granted":    {"true"},
	})
	if !strings.Contains(ev.Fields["request_parameters"].(string), "image-policy.k8s.io/break-glass") {
		t.Errorf("request_parameters = %v", ev.Fields["request_parameters"])
	}
	other := Normalize(GCPTag, GCPRecord("h1", now, map[string]string{"gcp.audit.method_name": "x"}), now)
	if other.ID == ev.ID {
		t.Error("two test entries share a document ID")
	}
}
