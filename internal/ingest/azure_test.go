package ingest

import (
	"encoding/base64"
	"slices"
	"strings"
	"testing"
	"time"
)

// A failed Entra ID sign-in, as diagnostic settings send it to an event
// hub.
const azureSignInRecord = `{"time": "2026-10-11T11:58:01.1234567Z", "resourceId": "/tenants/t1/providers/Microsoft.aadiam",
	"operationName": "Sign-in activity", "operationVersion": "1.0", "category": "SignInLogs",
	"tenantId": "t1", "resultType": "500121", "resultSignature": "None",
	"resultDescription": "Authentication failed during strong authentication request.", "durationMs": 0,
	"callerIpAddress": "203.0.113.7", "correlationId": "c1", "identity": "Alice Smith", "Level": 4, "location": "US",
	"properties": {"id": "s1", "userPrincipalName": "alice@example.com", "appDisplayName": "Azure Portal",
		"ipAddress": "203.0.113.7", "clientAppUsed": "Browser", "userAgent": "Mozilla/5.0",
		"status": {"errorCode": 500121, "failureReason": "Authentication failed during strong authentication request.",
			"additionalDetails": "MFA denied; user declined the authentication"},
		"deviceDetail": {"deviceId": "", "operatingSystem": "Windows10", "isCompliant": false, "trustType": ""},
		"authenticationRequirement": "multiFactorAuthentication", "conditionalAccessStatus": "notApplied",
		"networkLocationDetails": [], "resourceDisplayName": "Windows Azure Service Management API",
		"authenticationDetails": [{"authenticationMethod": "Password", "succeeded": true}]}}`

// An Entra ID audit record: a user added to a role.
const azureAuditRecord = `{"time": "2026-10-11T11:30:00Z", "resourceId": "/tenants/t1/providers/Microsoft.aadiam",
	"operationName": "Add member to role", "operationVersion": "1.0", "category": "AuditLogs", "tenantId": "t1",
	"resultSignature": "None", "durationMs": 0, "callerIpAddress": "<null>", "correlationId": "c2", "Level": 4,
	"properties": {"id": "a1", "category": "RoleManagement", "result": "success", "activityDisplayName": "Add member to role",
		"loggedByService": "Core Directory", "operationType": "Assign",
		"initiatedBy": {"user": {"userPrincipalName": "admin@example.com", "ipAddress": "198.51.100.4"}},
		"targetResources": [{"type": "User", "userPrincipalName": "bob@example.com",
			"modifiedProperties": [{"displayName": "Role.DisplayName", "newValue": "\"Global Administrator\""}]}]}}`

// An Azure activity log record: a key vault deleted.
const azureActivityRecord = `{"time": "2026-10-11T10:00:00.0000000Z",
	"resourceId": "/SUBSCRIPTIONS/AAAA-BBBB/RESOURCEGROUPS/RG1/PROVIDERS/MICROSOFT.KEYVAULT/VAULTS/VAULT1",
	"operationName": "MICROSOFT.KEYVAULT/VAULTS/DELETE", "category": "Administrative", "resultType": "Success",
	"resultSignature": "Succeeded.OK", "durationMs": "812", "callerIpAddress": "203.0.113.9", "correlationId": "c3",
	"identity": {"authorization": {"scope": "/subscriptions/aaaa-bbbb/resourceGroups/rg1", "action": "Microsoft.KeyVault/vaults/delete"},
		"claims": {"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn": "carol@example.com", "appid": "app1"}},
	"level": "Information", "location": "global",
	"properties": {"statusCode": "OK", "eventCategory": "Administrative", "message": "Microsoft.KeyVault/vaults/delete"}}`

func TestAzureSignIn(t *testing.T) {
	ev := Normalize(AzureTag, decode(t, azureSignInRecord), now)
	expect(t, ev.Document(), map[string]any{
		"datamodel": "Authentication", "sourcetype": "azure:monitor:aad", "vendor_product": "Microsoft Entra ID",
		"category": "SignInLogs", "operationName": "Sign-in activity", "resultType": "500121", "identity.name": "Alice Smith",
		"properties.userPrincipalName": "alice@example.com", "properties.status.errorCode": int64(500121),
		"properties.deviceDetail.isCompliant": false, "properties.networkLocationDetails": "[]",
		"properties.authenticationRequirement": "multiFactorAuthentication",
		"signin_status":                        "Failure: MFA denied; user declined the authentication",
		"action":                               "failure", "user": "alice@example.com", "app": "Azure Portal", "src": "203.0.113.7",
		"dest": "Windows Azure Service Management API", "authentication_method": "Password",
		"reason": "Authentication failed during strong authentication request.", "vendor_account": "t1",
		"@timestamp": "2026-10-11T11:58:01.1234567Z",
	})
	// A list's values, by Splunk's names, as text.
	expectLists(t, ev, map[string][]any{
		"properties.authenticationDetails{}.succeeded":            {"true"},
		"properties.authenticationDetails{}.authenticationMethod": {"Password"},
	})
	for _, k := range []string{"properties.deviceDetail.deviceId", "properties.deviceDetail.trustType"} {
		if _, ok := ev.Fields[k]; ok {
			t.Errorf("empty %s kept", k)
		}
	}
	if !strings.Contains(ev.Fields["message"].(string), "MFA denied") {
		t.Errorf("message = %v", ev.Fields["message"])
	}
	// A sign-in that went through.
	ev = Normalize(AzureTag, decode(t, `{"time": "2026-10-11T11:00:00Z", "category": "NonInteractiveUserSignInLogs",
		"operationName": "Sign-in activity", "tenantId": "t1", "resultType": "0",
		"properties": {"userPrincipalName": "bob@example.com", "status": {"errorCode": 0}}}`), now)
	expect(t, ev.Document(), map[string]any{"datamodel": "Authentication", "action": "success", "signin_status": "Success", "user": "bob@example.com"})
}

func TestAzureAuditAndActivity(t *testing.T) {
	ev := Normalize(AzureTag, decode(t, azureAuditRecord), now)
	expect(t, ev.Document(), map[string]any{
		"datamodel": "Change", "sourcetype": "azure:monitor:aad", "operationName": "Add member to role",
		"properties.category": "RoleManagement", "properties.result": "success",
		"properties.initiatedBy.user.userPrincipalName": "admin@example.com",
		"action": "created", "status": "success", "user": "admin@example.com", "src": "198.51.100.4", "src_user_type": "user",
		"object": "bob@example.com", "object_category": "user", "command": "Add member to role", "dest": "entra:t1",
		"change_type": "Entra ID RoleManagement", "src_user": "admin@example.com",
	})
	expectLists(t, ev, map[string][]any{
		"properties.targetResources{}.type":                          {"User"},
		"properties.targetResources{}.modifiedProperties{}.newValue": {`"Global Administrator"`},
	})
	if s, _ := ev.Fields["properties.targetResources"].(string); !strings.Contains(s, "Global Administrator") {
		t.Errorf("properties.targetResources = %q", s)
	}

	ev = Normalize("", decode(t, azureActivityRecord), now)
	expect(t, ev.Document(), map[string]any{
		"datamodel": "Change", "sourcetype": "azure:monitor:activity", "vendor_product": "Azure Activity Log",
		"operationName": "MICROSOFT.KEYVAULT/VAULTS/DELETE", "properties.message": "Microsoft.KeyVault/vaults/delete",
		"identity.authorization.action": "Microsoft.KeyVault/vaults/delete", "identity.claims.appid": "app1",
		"action": "deleted", "status": "success", "user": "carol@example.com", "src": "203.0.113.9",
		"object": "VAULT1", "object_category": "microsoft.keyvault/vaults", "vendor_account": "aaaa-bbbb",
		"vendor_region": "global", "change_type": "Azure Resource Manager",
	})
	for k := range ev.Fields {
		if strings.Contains(k, "schemas.xmlsoap") {
			t.Errorf("claim URL kept as a field name: %s", k)
		}
	}
}

func TestAzureRiskDetection(t *testing.T) {
	ev := Normalize(AzureTag, decode(t, `{"time": "2026-10-11T11:00:00Z", "category": "UserRiskEvents",
		"operationName": "User Risk Detection", "tenantId": "t1",
		"properties": {"id": "r1", "riskEventType": "unfamiliarFeatures", "riskLevel": "Medium", "riskState": "atRisk",
			"userPrincipalName": "dan@example.com", "ipAddress": "192.0.2.4"}}`), now)
	expect(t, ev.Document(), map[string]any{
		"datamodel": "Alerts", "app": "Microsoft Entra ID Protection", "type": "unfamiliarFeatures",
		"description": "unfamiliarFeatures", "severity": "medium", "user": "dan@example.com", "src": "192.0.2.4",
		"properties.riskEventType": "unfamiliarFeatures",
	})
}

// The azure_event_hub receiver's format raw passes each Event Hub message
// on whole, as bytes: each of its records becomes an event.
func TestAzureFromOTLP(t *testing.T) {
	msg := `{"records": [` + azureSignInRecord + `, ` + azureActivityRecord + `, {"time": "x"}]}`
	enqueued := uint64(now.Add(-time.Minute).UnixNano())
	docs := otlpDocs(t, tRes{attrs: []tKV{{"host.name", "collector1"}}, recs: []tRec{
		{time: enqueued, body: []byte(msg)},
		// The same message as text, as another pipeline may pass it on.
		{time: enqueued, body: msg},
	}})
	if len(docs) != 4 {
		t.Fatalf("%d documents, want 4", len(docs))
	}
	for i, want := range []string{"SignInLogs", "Administrative", "SignInLogs", "Administrative"} {
		if docs[i]["category"] != want || docs[i]["host"] != "collector1" {
			t.Errorf("document %d: category %v, host %v", i, docs[i]["category"], docs[i]["host"])
		}
	}
	if docs[0]["@timestamp"] != "2026-10-11T11:58:01.1234567Z" {
		t.Errorf("@timestamp = %v, want the record's own", docs[0]["@timestamp"])
	}
	// Other bytes are left as they are.
	docs = otlpDocs(t, tRes{attrs: host, recs: []tRec{{time: enqueued, body: []byte(`{"hello": "records"}`)}}})
	if len(docs) != 1 || docs[0]["message"] != base64.StdEncoding.EncodeToString([]byte(`{"hello": "records"}`)) {
		t.Errorf("docs = %v", docs)
	}
}

func TestAzureFieldsKept(t *testing.T) {
	for _, s := range []string{azureSignInRecord, azureAuditRecord, azureActivityRecord} {
		ev := Normalize(AzureTag, decode(t, s), now)
		for k := range ev.Fields {
			if !KnownField(k) && !azureField(k) {
				t.Errorf("field %s is neither mapped in the index template nor an Azure record's", k)
			}
		}
	}
}

// expectLists checks an event's list fields.
func expectLists(t *testing.T, ev Event, want map[string][]any) {
	t.Helper()
	for k, v := range want {
		if got, _ := ev.Fields[k].([]any); !slices.Equal(got, v) {
			t.Errorf("%s = %#v, want %#v", k, ev.Fields[k], v)
		}
	}
}

// azureField reports whether a field is one of an Azure record's own.
func azureField(k string) bool {
	if _, ok := AzureSigmaField("activitylogs", k); ok {
		return true
	}
	return k == "identity" || strings.HasPrefix(k, "identity.")
}

func TestAzureTestRecord(t *testing.T) {
	// A Sigma rule's fields, by Sentinel's names, become the record's.
	r := AzureRecord("h1", now, "signinlogs", map[string]string{
		"Status": "Success", "AuthenticationRequirement": "singleFactorAuthentication", "DeviceDetail.trusttype": "",
		"NetworkLocationDetails": "[]",
	})
	ev := Normalize(AzureTag, r, now)
	expect(t, ev.Document(), map[string]any{
		"host": "h1", "signin_status": "Success", "properties.authenticationRequirement": "singleFactorAuthentication",
		"properties.networkLocationDetails": "[]", "datamodel": "Authentication",
	})
	if _, ok := ev.Fields["properties.deviceDetail.trustType"]; ok {
		t.Error("empty trustType kept")
	}
	r = AzureRecord("h1", now, "auditlogs", map[string]string{"properties.message": "Add user", "Status": "Success"})
	ev = Normalize(AzureTag, r, now)
	expect(t, ev.Document(), map[string]any{"operationName": "Add user", "properties.result": "Success", "datamodel": "Change"})
}
