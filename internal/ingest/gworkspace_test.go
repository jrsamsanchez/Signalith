package ingest

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// A Google Workspace admin's change, as Cloud Logging has it when the
// organization shares its Workspace logs with Google Cloud: a user
// granted an admin role.
const gwsGrantAdmin = `{"protoPayload": {"@type": "type.googleapis.com/google.cloud.audit.AuditLog",
	"authenticationInfo": {"principalEmail": "admin@example.com"},
	"requestMetadata": {"callerIp": "203.0.113.9", "requestAttributes": {}, "destinationAttributes": {}},
	"serviceName": "admin.googleapis.com", "methodName": "google.admin.AdminService.grantAdminPrivilege",
	"resourceName": "organizations/123456789012",
	"metadata": {"@type": "type.googleapis.com/ccc_hosted_reporting.ActivityProto",
		"activityId": {"timeUsec": "1791720000000000", "uniqQualifier": "-8243"},
		"event": [{"eventType": "USER_SETTINGS", "eventName": "GRANT_ADMIN_PRIVILEGE",
			"parameter": [{"type": "TYPE_STRING", "name": "USER_EMAIL", "value": "mallory@example.com"},
				{"type": "TYPE_STRING", "name": "ROLE_NAME", "value": "_SEED_ADMIN_ROLE"}]}]}},
	"insertId": "q1", "resource": {"type": "audited_resource",
		"labels": {"service": "admin.googleapis.com", "method": "google.admin.AdminService.grantAdminPrivilege"}},
	"timestamp": "2026-10-11T11:00:00.000001Z", "severity": "NOTICE",
	"logName": "organizations/123456789012/logs/cloudaudit.googleapis.com%2Factivity",
	"receiveTimestamp": "2026-10-11T11:00:01Z"}`

// A sign-in that failed, from the Login log.
const gwsLoginFailure = `{"protoPayload": {"@type": "type.googleapis.com/google.cloud.audit.AuditLog",
	"authenticationInfo": {"principalEmail": "bob@example.com"},
	"requestMetadata": {"callerIp": "198.51.100.23"},
	"serviceName": "login.googleapis.com", "methodName": "google.login.LoginService.loginFailure",
	"resourceName": "organizations/123456789012",
	"metadata": {"@type": "type.googleapis.com/ccc_hosted_reporting.ActivityProto",
		"event": [{"eventType": "login", "eventName": "login_failure",
			"parameter": [{"type": "TYPE_STRING", "name": "login_type", "value": "google_password"},
				{"type": "TYPE_STRING", "name": "login_challenge_method", "multiStrValue": ["password", "google_authenticator"]},
				{"type": "TYPE_STRING", "name": "login_failure_type", "value": "login_failure_invalid_password"},
				{"type": "TYPE_BOOL", "name": "is_suspicious", "boolValue": false}]}]}},
	"insertId": "q2", "resource": {"type": "audited_resource", "labels": {"service": "login.googleapis.com"}},
	"timestamp": "2026-10-11T11:05:00Z", "severity": "NOTICE",
	"logName": "organizations/123456789012/logs/cloudaudit.googleapis.com%2Fdata_access"}`

func TestWorkspaceAdmin(t *testing.T) {
	ev := Normalize(GCPTag, decode(t, gwsGrantAdmin), now)
	expect(t, ev.Document(), map[string]any{
		"datamodel": "Change", "sourcetype": GCPSourcetype, "vendor_product": "Google Workspace",
		"protoPayload.serviceName": "admin.googleapis.com", "protoPayload.methodName": "google.admin.AdminService.grantAdminPrivilege",
		"event_name": "GRANT_ADMIN_PRIVILEGE", "event_parameters.user_email": "mallory@example.com",
		"event_parameters.role_name": "_SEED_ADMIN_ROLE",
		"signature":                  "GRANT_ADMIN_PRIVILEGE", "command": "GRANT_ADMIN_PRIVILEGE", "status": "success",
		"user": "admin@example.com", "src": "203.0.113.9", "object": "mallory@example.com",
		"object_category": "USER_SETTINGS", "change_type": "Google Workspace", "vendor_account": "123456789012",
		"log_id": "cloudaudit.googleapis.com/activity",
	})
}

func TestWorkspaceLogin(t *testing.T) {
	ev := Normalize(GCPTag, decode(t, gwsLoginFailure), now)
	expect(t, ev.Document(), map[string]any{
		"datamodel": "Authentication", "vendor_product": "Google Workspace", "event_name": "login_failure",
		"action": "failure", "status": "failure", "app": "google:login", "user": "bob@example.com", "src": "198.51.100.23",
		"authentication_method": "google_password", "reason": "login_failure_invalid_password",
		"event_parameters.is_suspicious": "false", "signature": "login_failure",
	})
	expectLists(t, ev, map[string][]any{"event_parameters.login_challenge_method": {"password", "google_authenticator"}})
}

// An entry without the event in its metadata is named after its method.
func TestWorkspaceEventName(t *testing.T) {
	for _, c := range [][3]string{
		{"admin.googleapis.com", "google.admin.AdminService.createRole", "CREATE_ROLE"},
		{"admin.googleapis.com", "google.admin.AdminService.removeApplicationFromWhitelist", "REMOVE_APPLICATION_FROM_WHITELIST"},
		{"login.googleapis.com", "google.login.LoginService.loginFailure", "login_failure"},
	} {
		if got := WorkspaceEventName(c[0], c[1]); got != c[2] {
			t.Errorf("WorkspaceEventName(%q) = %q, want %q", c[1], got, c[2])
		}
		if got := workspaceMethod(c[0], c[2]); got != c[1] {
			t.Errorf("workspaceMethod(%q) = %q, want %q", c[2], got, c[1])
		}
	}
	ev := Normalize(GCPTag, decode(t, `{"logName": "organizations/1/logs/cloudaudit.googleapis.com%2Factivity",
		"resource": {"type": "audited_resource"}, "protoPayload": {"serviceName": "admin.googleapis.com",
		"methodName": "google.admin.AdminService.deleteRole"}}`), now)
	expect(t, ev.Document(), map[string]any{"event_name": "DELETE_ROLE", "datamodel": "Change", "action": "deleted"})
	// A Google Cloud entry is not Workspace's.
	ev = Normalize(GCPTag, decode(t, gcpFirewallDelete), now)
	if ev.Fields["event_name"] != nil || ev.Fields["vendor_product"] != "Google Cloud" {
		t.Errorf("Google Cloud entry read as Workspace's: %v", ev.Fields)
	}
}

func TestWorkspaceFieldsKept(t *testing.T) {
	for _, s := range []string{gwsGrantAdmin, gwsLoginFailure} {
		ev := Normalize(GCPTag, decode(t, s), now)
		for k := range ev.Fields {
			if !KnownField(k) && !GCPField(k) && !WorkspaceField(k) {
				t.Errorf("field %s is neither mapped in the index template nor a log entry's", k)
			}
		}
	}
}

// Sigma's names for a Workspace event's fields build a test entry that
// keeps them.
func TestWorkspaceRecord(t *testing.T) {
	data := map[string]string{"eventService": "admin.googleapis.com", "eventName": "ENFORCE_STRONG_AUTHENTICATION", "new_value": "false"}
	ev := Normalize(GCPTag, WorkspaceRecord("h1", now, data), now)
	expect(t, ev.Document(), map[string]any{
		"host": "h1", "datamodel": "Change", "event_name": "ENFORCE_STRONG_AUTHENTICATION", "event_parameters.new_value": "false",
		"protoPayload.methodName": "google.admin.AdminService.enforceStrongAuthentication",
	})
	data = map[string]string{"protoPayload.serviceName": "login.googleapis.com", "protoPayload.metadata.event.eventName": "suspicious_login"}
	ev = Normalize(GCPTag, WorkspaceRecord("h1", now, data), now)
	expect(t, ev.Document(), map[string]any{"datamodel": "Authentication", "event_name": "suspicious_login",
		"log_id": "cloudaudit.googleapis.com/data_access"})
	for _, c := range [][2]string{
		{"eventService", "protoPayload.serviceName"}, {"eventName", "event_name"}, {"setting_name", "event_parameters.setting_name"},
		{"protoPayload.metadata.event.eventName", "event_name"}, {"data.protoPayload.serviceName", "protoPayload.serviceName"},
	} {
		if f, ok := WorkspaceSigmaField(c[0]); !ok || f != c[1] {
			t.Errorf("WorkspaceSigmaField(%q) = %q, %v, want %q", c[0], f, ok, c[1])
		}
	}
	if f, ok := WorkspaceSigmaField("Some.Field"); ok {
		t.Errorf("WorkspaceSigmaField(Some.Field) = %q", f)
	}
}

// gwsManyEvents is a Workspace entry with n events, each named apart and
// with one parameter of n values.
func gwsManyEvents(n int) string {
	var events, values []string
	for i := range n {
		values = append(values, fmt.Sprintf(`"v%d"`, i))
	}
	for i := range n {
		events = append(events, fmt.Sprintf(`{"eventName": "E%d", "parameter": [{"name": "p", "multiStrValue": [%s]}]}`, i, strings.Join(values[:min(n, 3)], ",")))
	}
	events[0] = `{"eventName": "E0", "parameter": [{"name": "many", "multiStrValue": [` + strings.Join(values, ",") + `]}]}`
	return `{"protoPayload": {"@type": "type.googleapis.com/google.cloud.audit.AuditLog", "serviceName": "admin.googleapis.com",
	"methodName": "google.admin.AdminService.changeApplicationSetting",
	"metadata": {"@type": "type.googleapis.com/ccc_hosted_reporting.ActivityProto", "event": [` + strings.Join(events, ",") + `]}},
	"insertId": "q3", "resource": {"type": "audited_resource"}, "timestamp": "2026-10-11T11:00:00Z",
	"logName": "organizations/123456789012/logs/cloudaudit.googleapis.com%2Factivity"}`
}

// An entry with many events keeps only its first few, a parameter keeps a
// bounded number of values, and reading it costs about as much as decoding
// its JSON. The bound is relative to the decode so a slow runner or the
// race detector, which slow both alike, don't fail it.
func TestWorkspaceManyEvents(t *testing.T) {
	entry := gwsManyEvents(45000)
	start := time.Now()
	r := decode(t, entry)
	decoded := time.Since(start)
	start = time.Now()
	ev := Normalize(GCPTag, r, now)
	if d := time.Since(start); d > 2*time.Second && d > 10*decoded {
		t.Errorf("took %v, decoding took %v", d, decoded)
	}
	if names, _ := ev.Fields["event_name"].([]any); len(names) != workspaceMaxEvents {
		t.Errorf("event_name has %d values", len(names))
	}
	if many, _ := ev.Fields[workspaceParamPrefix+"many"].([]any); len(many) != workspaceMaxValues {
		t.Errorf("a parameter kept %d values", len(many))
	}
}
