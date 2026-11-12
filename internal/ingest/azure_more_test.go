// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package ingest

import (
	"encoding/base64"
	"encoding/json"
	"reflect"
	"testing"
)

// flattenAzure keeps each kind of value as itself, numbers whole when
// they are whole.
func TestFlattenAzureValueKinds(t *testing.T) {
	out := map[string]any{}
	flattenAzure("p", map[string]any{
		"whole": 3.0, "frac": 2.5, "huge": 1e300, "i64": int64(7), "i": 8,
		"num": json.Number("9"), "numf": json.Number("1.5"), "bad": json.Number("x"),
		"empty": "", "s": "v", "b": true, "": "skipped", "a.b": "skipped",
		"list": []any{json.Number("1"), 2.5, int64(3), 4, "five", true, "", nil},
	}, out)
	want := map[string]any{
		"p.whole": int64(3), "p.frac": 2.5, "p.huge": 1e300, "p.i64": int64(7), "p.i": int64(8),
		"p.num": int64(9), "p.numf": 1.5, "p.s": "v", "p.b": true,
	}
	for k, v := range want {
		if out[k] != v {
			t.Errorf("%s = %#v, want %#v", k, out[k], v)
		}
	}
	for _, k := range []string{"p.empty", "p.", "p.a.b", "p.bad"} {
		if _, ok := out[k]; ok {
			t.Errorf("%s kept: %#v", k, out[k])
		}
	}
	if got, want := out["p.list{}"], []any{"1", "2.5", "3", "4", "five", "true", ""}; !reflect.DeepEqual(got, want) {
		t.Errorf("list values = %#v, want %#v", got, want)
	}
	if out["p.list"] != `["1",2.5,3,4,"five",true,"",null]` && out["p.list"] != `[1,2.5,3,4,"five",true,"",null]` {
		t.Errorf("list text = %#v", out["p.list"])
	}
}

// azureListValue follows objects and lists inside a list, and caps how
// many values a list field keeps.
func TestAzureListValueNested(t *testing.T) {
	out := map[string]any{}
	azureListValue("x{}", map[string]any{"k": "v", "a.b": "skip", "n": []any{"m"}}, out)
	if got := out["x{}.k"]; !reflect.DeepEqual(got, []any{"v"}) {
		t.Errorf("x{}.k = %#v", got)
	}
	if got := out["x{}.n{}"]; !reflect.DeepEqual(got, []any{"m"}) {
		t.Errorf("x{}.n{} = %#v", got)
	}
	if _, ok := out["x{}.a.b"]; ok {
		t.Error("a dotted key was kept")
	}
	for i := 0; i < azureMaxListValues+10; i++ {
		azureListValue("cap", "v", out)
	}
	if l := out["cap"].([]any); len(l) != azureMaxListValues {
		t.Errorf("a list kept %d values, want %d", len(l), azureMaxListValues)
	}
}

// Event Hub messages reach the OTLP path as text, base64 bytes or a map.
func TestAzureFromOTLPForms(t *testing.T) {
	rec := `{"time": "2026-10-11T11:00:00Z", "category": "AuditLogs", "operationName": "Update user", "tenantId": "t1"}`
	msg := `{"records": [` + rec + `, {"not": "azure"}]}`
	if got := azureFromOTLP(msg); len(got) != 1 {
		t.Errorf("text message: %d records", len(got))
	}
	if got := azureFromOTLP(base64.StdEncoding.EncodeToString([]byte(msg))); len(got) != 1 {
		t.Errorf("base64 message: %d records", len(got))
	}
	// Base64 of something else, and base64 that breaks past its start.
	if got := azureFromOTLP(base64.StdEncoding.EncodeToString([]byte(`{"other": 1, "padding": "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"}`))); got != nil {
		t.Errorf("other base64: %v", got)
	}
	broken := base64.StdEncoding.EncodeToString([]byte(msg)) + "!!"
	if got := azureFromOTLP(broken); got != nil {
		t.Errorf("broken base64: %v", got)
	}
	if got := azureFromOTLP("ey!!"); got != nil {
		t.Errorf("bad base64 head: %v", got)
	}
	m := decode(t, msg)
	if got := azureFromOTLP(m); len(got) != 1 {
		t.Errorf("map message: %d records", len(got))
	}
	if got := azureFromOTLP(map[string]any{"records": "no"}); got != nil {
		t.Errorf("map without a list: %v", got)
	}
	if got := azureFromOTLP(42); got != nil {
		t.Errorf("a number: %v", got)
	}
	// A message whose records are not a list does not decode.
	if got := AzureRecords([]byte(`{"records": 5}`)); got != nil {
		t.Errorf("records not a list: %v", got)
	}
}

func TestAzureFieldNames(t *testing.T) {
	for _, c := range []struct {
		name string
		want bool
	}{
		{"time", true}, {"identity", false}, {"properties.x", true}, {"identity.claims", true},
		{"other", false}, {"properties.", false},
	} {
		if got := AzureField(c.name); got != c.want {
			t.Errorf("AzureField(%q) = %v, want %v", c.name, got, c.want)
		}
	}
	if f, ok := AzureSigmaField("activitylogs", "properties.message"); !ok || f != "properties.message" {
		t.Errorf("activitylogs properties.message = %q %v", f, ok)
	}
	if _, ok := AzureSigmaField("signinlogs", "nothing"); ok {
		t.Error("an unknown field was kept")
	}
}

// Test records of each service, with nested and list paths.
func TestAzureRecordServices(t *testing.T) {
	r := AzureRecord("h1", now, "activitylogs", map[string]string{"properties.message": "deploy"})
	if r["operationName"] != "MICROSOFT.RESOURCES/DEPLOYMENTS/WRITE" || r["resultType"] != "Success" {
		t.Errorf("activity record = %v", r)
	}
	ev := Normalize(AzureTag, r, now)
	expect(t, ev.Fields, map[string]any{"action": "modified", "status": "success", "vendor_account": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"})

	r = AzureRecord("h1", now, "riskdetection", nil)
	if r["operationName"] != "User Risk Detection" || r["category"] != "UserRiskEvents" {
		t.Errorf("risk record = %v", r)
	}

	// A failed sign-in by default; a rule's status and result type decide.
	r = AzureRecord("h1", now, "signinlogs", nil)
	if r["resultType"] != "50126" {
		t.Errorf("default sign-in = %v", r)
	}
	r = AzureRecord("h1", now, "signinlogs", map[string]string{"Status": "MFA denied", "ResultType": "50074"})
	st := r["properties"].(map[string]any)["status"].(map[string]any)
	// Status comes after ResultType, so its failure code wins.
	if st["additionalDetails"] != "MFA denied" || st["errorCode"] != json.Number("500121") {
		t.Errorf("failed sign-in status = %v", st)
	}
	r = AzureRecord("h1", now, "signinlogs", map[string]string{"ResultType": "50074"})
	if st := r["properties"].(map[string]any)["status"].(map[string]any); st["errorCode"] != json.Number("50074") {
		t.Errorf("result type status = %v", st)
	}

	// Lists of objects, a JSON list, and a number field.
	r = AzureRecord("h1", now, "auditlogs", map[string]string{
		"TargetResources": `[{"type": "User"}]`,
	})
	if l, ok := r["properties"].(map[string]any)["targetResources"].([]any); !ok || len(l) != 1 {
		t.Errorf("target resources = %#v", r["properties"])
	}
	r = AzureRecord("h1", now, "auditlogs", map[string]string{"TargetResources": "not json"})
	if r["properties"].(map[string]any)["targetResources"] != "not json" {
		t.Errorf("text target resources = %#v", r["properties"])
	}
	r = AzureRecord("h1", now, "signinlogs", map[string]string{"properties.status.errorCode": "7", "properties.a{}.b": "x", "properties.c{}": "y"})
	p := r["properties"].(map[string]any)
	if p["status"].(map[string]any)["errorCode"] != json.Number("7") {
		t.Errorf("errorCode = %#v", p["status"])
	}
	if a := p["a"].([]any); len(a) != 1 || a[0].(map[string]any)["b"] != "x" {
		t.Errorf("a{}.b = %#v", p["a"])
	}
	if c := p["c"].([]any); len(c) != 1 || c[0] != "y" {
		t.Errorf("c{} = %#v", p["c"])
	}
	r = AzureRecord("h1", now, "signinlogs", map[string]string{"properties.status.errorCode": "abc", "ResultType": "x"})
	if r["properties"].(map[string]any)["status"].(map[string]any)["errorCode"] != "abc" {
		t.Errorf("text errorCode = %#v", r["properties"])
	}
}

// An audit record a service principal made, deleting something, and an
// activity record that failed.
func TestAzureAuditAndActivityBranches(t *testing.T) {
	ev := Normalize(AzureTag, decode(t, `{"time": "2026-10-11T11:30:00Z", "category": "AuditLogs", "tenantId": "t1",
		"operationName": "Delete application", "resourceId": "/tenants/t1/providers/Microsoft.aadiam",
		"properties": {"category": "ApplicationManagement", "result": "success", "operationType": "Delete",
			"initiatedBy": {"app": {"displayName": "Automation"}}}}`), now)
	expect(t, ev.Fields, map[string]any{"action": "deleted", "user": "Automation", "src_user_type": "servicePrincipal"})

	ev = Normalize(AzureTag, decode(t, `{"time": "2026-10-11T10:00:00Z", "category": "Administrative",
		"resourceId": "/SUBSCRIPTIONS/S1/RESOURCEGROUPS/RG/PROVIDERS/MICROSOFT.COMPUTE/VIRTUALMACHINES/VM1",
		"operationName": "MICROSOFT.COMPUTE/VIRTUALMACHINES/WRITE", "resultType": "Failure", "resultSignature": "Conflict"}`), now)
	expect(t, ev.Fields, map[string]any{"action": "modified", "status": "failure", "reason": "Conflict", "object": "VM1"})
}
