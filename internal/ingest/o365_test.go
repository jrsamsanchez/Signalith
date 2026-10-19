// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package ingest

import (
	"strings"
	"testing"
	"time"
)

// Microsoft 365 audit records as the Management Activity API serves
// them: a failed sign-in, an inbox rule made through Exchange and an
// alert.
const (
	o365LoginFailed = `{"Actor": [{"ID": "c0282018-2447-42b4-88a5-fe4ddf5f4c9f", "Type": 0}, {"ID": "jo@example.com", "Type": 5}],
		"ActorIpAddress": "73.15.72.101", "ApplicationId": "c44b4083-3bb0-49c1-b47d-974e53cbdf3c", "AzureActiveDirectoryEventType": 1,
		"ClientIP": "73.15.72.101", "CreationTime": "2020-12-16T23:30:29",
		"DeviceProperties": [{"Name": "BrowserType", "Value": "Chrome"}, {"Name": "OS", "Value": "Windows10"}],
		"ExtendedProperties": [{"Name": "UserAgent", "Value": "Mozilla/5.0"}, {"Name": "RequestType", "Value": "Login:login"}],
		"Id": "fbe233c2-d5fc-4238-9ac5-27febb528700", "LogonError": "IdsLocked", "ModifiedProperties": [],
		"ObjectId": "797f4846-ba00-4fd7-ba43-dac1f8f63013", "Operation": "UserLoginFailed",
		"OrganizationId": "0e8108b1-18e9-41a4-961b-dfcddf92ef08", "RecordType": 15, "ResultStatus": "Failed",
		"UserId": "jo@example.com", "UserKey": "jo@example.com", "UserType": 0, "Version": 1, "Workload": "AzureActiveDirectory"}`
	o365InboxRule = `{"AppAccessContext": {"IssuedAtTime": "2024-03-28T18:52:13", "UniqueTokenId": "0l26eXfIIkSUMZPlP5IFAA"},
		"CreationTime": "2024-03-28T19:02:56", "Id": "dff4af7b-d0c8-4cbd-353f-08dc4f59adb2", "Operation": "New-InboxRule",
		"OrganizationId": "75243ab2-44f8-435c-a7a6-b479385df6d4", "RecordType": 1, "ResultStatus": "True", "UserType": 2,
		"Workload": "Exchange", "ClientIP": "120.1.121.43:61275", "ObjectId": "2d2f9e2c\\legit_rule", "UserId": "user15@example.com",
		"ExternalAccess": false, "Parameters": [{"Name": "BodyContainsWords", "Value": "paystub"}, {"Name": "Name", "Value": "legit_rule"},
			{"Name": "ForwardAsAttachmentTo", "Value": "attacker@evil.example"}]}`
	o365Alert = `{"AlertId": "fd8314d8-2d10-c4a3-1400-08dc32914b9d", "AlertLinks": [{"AlertLinkHref": ""}], "Category": "ThreatManagement",
		"CreationTime": "2024-02-21T04:02:26", "Id": "0abe7b12-4879-4ea3-fd8a-08dc3291eab2", "ListBaseType": 1,
		"Name": "A potentially malicious URL click was detected", "ObjectId": "https://tinyurl.example/57594h4h",
		"Operation": "AlertEntityGenerated", "OrganizationId": "6915b1e0-b081-4829-8866-f1a3e883a9ae", "RecordType": 40,
		"ResultStatus": "Succeeded", "Severity": "High", "Status": "Active", "UserId": "SecurityComplianceAlerts", "UserType": 4,
		"Workload": "SecurityComplianceCenter"}`
)

func TestO365SignIn(t *testing.T) {
	ev := Normalize(O365Tag, decode(t, o365LoginFailed), now)
	expect(t, ev.Document(), map[string]any{
		"datamodel": "Authentication", "sourcetype": "o365:management:activity", "vendor_product": "Microsoft 365",
		"Operation": "UserLoginFailed", "Workload": "AzureActiveDirectory", "RecordType": "15", "UserType": "0",
		"record_type": "AzureActiveDirectoryStsLogon", "action": "failure", "status": "failure", "user": "jo@example.com",
		"src": "73.15.72.101", "user_agent": "Mozilla/5.0", "reason": "IdsLocked", "signature": "UserLoginFailed",
		"authentication_method": "Login:login", "vendor_account": "0e8108b1-18e9-41a4-961b-dfcddf92ef08",
		"ModifiedProperties": "[]", "@timestamp": "2020-12-16T23:30:29Z",
		// The operating system, one of the device properties, as
		// Splunk's add-on reads it.
		"os": "Windows10",
	})
	expectLists(t, ev, map[string][]any{
		"Actor{}.ID":                {"c0282018-2447-42b4-88a5-fe4ddf5f4c9f", "jo@example.com"},
		"Actor{}.Type":              {"0", "5"},
		"ExtendedProperties{}.Name": {"UserAgent", "RequestType"},
		"DeviceProperties{}.Name":   {"BrowserType", "OS"},
		"DeviceProperties{}.Value":  {"Chrome", "Windows10"},
	})
	// A record whose device properties name no OS has none.
	noOS := decode(t, o365LoginFailed)
	noOS["DeviceProperties"] = []any{map[string]any{"Name": "BrowserType", "Value": "Chrome"}}
	if v, ok := Normalize(O365Tag, noOS, now).Fields["os"]; ok {
		t.Errorf("os = %#v without an OS device property", v)
	}
	// A test record's OS is a device property.
	if v := Normalize(O365Tag, O365Record(now, "", map[string]string{"Operation": "UserLoggedIn", "OS": "MacOs"}), now).Fields["os"]; v != "MacOs" {
		t.Errorf("test record's OS = %#v", v)
	}
	if ev.ID == "" {
		t.Error("no document ID from the record's Id")
	}
	// The same record found by its own shape, without the tag.
	if again := Normalize("", decode(t, o365LoginFailed), now); again.ID != ev.ID || again.Model != "Authentication" {
		t.Errorf("untagged record: %s %s", again.Model, again.ID)
	}
	// A changed copy with the record's Id is stored as its own.
	forged := decode(t, o365LoginFailed)
	forged["ClientIP"] = "192.0.2.99"
	if Normalize(O365Tag, forged, now).ID == ev.ID {
		t.Error("a changed copy took the record's ID")
	}
}

func TestO365ChangeAndAlert(t *testing.T) {
	ev := Normalize(O365Tag, decode(t, o365InboxRule), now)
	expect(t, ev.Document(), map[string]any{
		"datamodel": "Change", "Operation": "New-InboxRule", "Workload": "Exchange", "action": "created", "status": "success",
		"src": "120.1.121.43", "ClientIP": "120.1.121.43:61275", "user": "user15@example.com", "ExternalAccess": "false",
		"AppAccessContext.UniqueTokenId": "0l26eXfIIkSUMZPlP5IFAA", "record_type": "ExchangeAdmin", "change_type": "Exchange",
	})
	expectLists(t, ev, map[string][]any{
		"Parameters{}.Name":  {"BodyContainsWords", "Name", "ForwardAsAttachmentTo"},
		"Parameters{}.Value": {"paystub", "legit_rule", "attacker@evil.example"},
	})
	if s, _ := ev.Fields["Parameters"].(string); !strings.Contains(s, "ForwardAsAttachmentTo") {
		t.Errorf("Parameters = %v", ev.Fields["Parameters"])
	}

	ev = Normalize(O365Tag, decode(t, o365Alert), now)
	expect(t, ev.Document(), map[string]any{
		"datamodel": "Alerts", "type": "A potentially malicious URL click was detected", "severity": "high",
		"signature": "A potentially malicious URL click was detected", "Operation": "AlertEntityGenerated",
		"ListBaseType": "1", "record_type": "SecurityComplianceAlerts", "id": "fd8314d8-2d10-c4a3-1400-08dc32914b9d",
	})
	// An activity that changes nothing is Other.
	ev = Normalize(O365Tag, decode(t, `{"CreationTime": "2024-03-28T19:02:56", "Id": "x1", "Operation": "MailItemsAccessed",
		"OrganizationId": "o1", "RecordType": 50, "Workload": "Exchange", "UserId": "a@example.com", "ClientIP": "[2001:db8::1]:443"}`), now)
	expect(t, ev.Document(), map[string]any{"datamodel": "Other", "src": "2001:db8::1", "record_type": "ExchangeItemAggregated"})
}

func TestO365FieldsKept(t *testing.T) {
	for _, s := range []string{o365LoginFailed, o365InboxRule, o365Alert} {
		ev := Normalize(O365Tag, decode(t, s), now)
		for k := range ev.Fields {
			if !KnownField(k) && !O365Field(k) {
				t.Errorf("field %s is neither mapped in the index template nor a Microsoft 365 record's", k)
			}
		}
	}
}

func TestO365Records(t *testing.T) {
	recs, err := O365Records([]byte("[" + o365LoginFailed + "," + o365Alert + ", null]"))
	if err != nil || len(recs) != 2 {
		t.Fatalf("%d records, %v", len(recs), err)
	}
	if _, err := O365Records([]byte(`{"error": {"code": "AF20055"}}`)); err == nil {
		t.Error("an error parsed as records")
	}
	// A Sigma rule's fields become the record's.
	r := O365Record(now, "Exchange", map[string]string{"Operation": "Add-FederatedDomain", "Parameters{}.Name": "DomainName", "Item.ParentFolder.Path": `\Inbox`})
	ev := Normalize(O365Tag, r, now)
	expect(t, ev.Document(), map[string]any{"Workload": "Exchange", "Operation": "Add-FederatedDomain", "Item.ParentFolder.Path": `\Inbox`, "datamodel": "Change"})
	expectLists(t, ev, map[string][]any{"Parameters{}.Name": {"DomainName"}})
	if !ev.Time.Equal(now.Truncate(time.Second)) {
		t.Errorf("time %v, want %v", ev.Time, now)
	}
}

func TestO365SigmaRecord(t *testing.T) {
	a := Normalize(O365Tag, O365SigmaRecord("case-1", now, map[string]string{"eventSource": "SecurityComplianceCenter", "eventName": "Impossible travel activity", "status": "success"}), now)
	b := Normalize(O365Tag, O365SigmaRecord("case-2", now, map[string]string{"eventSource": "SecurityComplianceCenter", "eventName": "Impossible travel activity", "status": "success"}), now)
	expect(t, a.Document(), map[string]any{"host": "case-1", "Workload": "SecurityComplianceCenter", "signature": "Impossible travel activity",
		"status": "success", "datamodel": "Alerts"})
	if a.ID == b.ID {
		t.Error("two test records share an ID, so only one is stored")
	}
}
