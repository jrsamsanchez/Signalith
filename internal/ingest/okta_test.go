package ingest

import (
	"context"
	"strings"
	"testing"
	"time"
)

// A user's sign-in to Okta, which failed, as the System Log API returns
// it.
const oktaSignInFailed = `{"actor": {"id": "00u1a2b3c4d5e6f7g8h9", "type": "User", "alternateId": "jdoe@example.com",
	"displayName": "Jane Doe", "detailEntry": null},
	"client": {"userAgent": {"rawUserAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)", "os": "Windows 10", "browser": "CHROME"},
		"zone": "null", "device": "Computer", "id": null, "ipAddress": "203.0.113.7",
		"geographicalContext": {"city": "Springfield", "state": "Illinois", "country": "United States", "postalCode": "62701",
			"geolocation": {"lat": 39.7817, "lon": -89.6501}}},
	"device": null,
	"authenticationContext": {"authenticationProvider": null, "credentialProvider": null, "credentialType": null,
		"issuer": null, "interface": null, "authenticationStep": 0, "externalSessionId": "102xyzabc"},
	"displayMessage": "User login to Okta", "eventType": "user.session.start",
	"outcome": {"result": "FAILURE", "reason": "INVALID_CREDENTIALS"},
	"published": "2026-10-11T09:12:31.415Z",
	"securityContext": {"asNumber": 64496, "asOrg": "example isp", "isp": "example isp", "domain": "example.net", "isProxy": false},
	"severity": "INFO",
	"debugContext": {"debugData": {"requestId": "Zx1abc", "requestUri": "/idp/idx/identify", "url": "/idp/idx/identify?",
		"threatSuspected": "false", "behaviors": "{New Geo-Location=NEGATIVE, New Device=POSITIVE, New IP=POSITIVE}"}},
	"legacyEventType": "core.user_auth.login_failed",
	"transaction": {"type": "WEB", "id": "Zx1abc", "detail": {}},
	"uuid": "5b7c8a3e-6c7f-11f0-9f3a-0b1c2d3e4f50", "version": "0",
	"request": {"ipChain": [{"ip": "203.0.113.7", "geographicalContext": {"city": "Springfield"}, "version": "V4", "source": null}]},
	"target": []}`

// An admin deactivated a user's MFA factor.
const oktaFactorDeactivated = `{"actor": {"id": "00uadmin", "type": "User", "alternateId": "admin@example.com", "displayName": "Admin"},
	"client": {"ipAddress": "198.51.100.4", "userAgent": {"rawUserAgent": "okta-sdk"}},
	"displayMessage": "Reset factor for user", "eventType": "user.mfa.factor.deactivate",
	"outcome": {"result": "SUCCESS"}, "published": "2026-10-11T10:00:00.000Z", "severity": "INFO",
	"uuid": "6b7c8a3e-6c7f-11f0-9f3a-0b1c2d3e4f51", "version": "0",
	"target": [{"id": "00u1a2b3c4d5e6f7g8h9", "type": "User", "alternateId": "jdoe@example.com", "displayName": "Jane Doe"},
		{"id": "opf1", "type": "Factor", "alternateId": "unknown", "displayName": "Okta Verify", "detailEntry": {"methodTypeUsed": "Push"}}]}`

// Okta ThreatInsight saw a request from a suspicious address.
const oktaThreat = `{"actor": {"id": "unknown", "type": "PublicClientApp", "alternateId": "unknown", "displayName": "unknown"},
	"client": {"ipAddress": "192.0.2.10"}, "displayMessage": "Request from suspicious actor",
	"eventType": "security.threat.detected", "outcome": {"result": "DENY", "reason": "Password Spray"},
	"published": "2026-10-11T11:00:00Z", "severity": "WARN", "uuid": "7b7c8a3e-6c7f-11f0-9f3a-0b1c2d3e4f52",
	"securityContext": {"isProxy": true}, "target": []}`

func TestOktaSignIn(t *testing.T) {
	ev := Normalize(OktaTag, decode(t, oktaSignInFailed), now)
	expect(t, ev.Document(), map[string]any{
		"datamodel": "Authentication", "sourcetype": "OktaIM2:log", "vendor_product": "Okta",
		"eventType": "user.session.start", "legacyEventType": "core.user_auth.login_failed", "displayMessage": "User login to Okta",
		"uuid": "5b7c8a3e-6c7f-11f0-9f3a-0b1c2d3e4f50", "severity": "INFO", "version": "0",
		"actor.alternateId": "jdoe@example.com", "actor.type": "User", "outcome.result": "FAILURE",
		"outcome.reason": "INVALID_CREDENTIALS", "client.ipAddress": "203.0.113.7",
		"client.userAgent.rawUserAgent":              "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
		"client.geographicalContext.city":            "Springfield",
		"client.geographicalContext.geolocation.lat": "39.7817",
		"securityContext.isProxy":                    "false", "securityContext.asNumber": "64496",
		"authenticationContext.externalSessionId": "102xyzabc", "authenticationContext.authenticationStep": "0",
		"debugContext.debugData.requestUri": "/idp/idx/identify",
		"debugContext.debugData.behaviors":  "{New Geo-Location=NEGATIVE, New Device=POSITIVE, New IP=POSITIVE}",
		"action":                            "failure", "status": "failure", "result": "FAILURE", "user": "jdoe@example.com", "src_user": "jdoe@example.com",
		"src_user_id": "00u1a2b3c4d5e6f7g8h9", "src_user_type": "User", "src": "203.0.113.7", "reason": "INVALID_CREDENTIALS",
		"signature": "user.session.start", "command": "user.session.start", "description": "User login to Okta",
		"app": "Okta", "dest": "Okta", "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
		"@timestamp": "2026-10-11T09:12:31.415Z",
	})
	expectLists(t, ev, map[string][]any{"request.ipChain{}.ip": {"203.0.113.7"}})
	for _, k := range []string{"device", "actor.detailEntry", "client.id", "authenticationContext.issuer"} {
		if _, ok := ev.Fields[k]; ok {
			t.Errorf("null %s became a field", k)
		}
	}
	if ev.ID == "" {
		t.Error("no document ID: the same event read twice would be stored twice")
	}
	if again := Normalize(OktaTag, decode(t, oktaSignInFailed), now.Add(time.Hour)); again.ID != ev.ID {
		t.Error("the same event read twice has two document IDs")
	}
}

func TestOktaChangeAndAlert(t *testing.T) {
	ev := Normalize(OktaTag, decode(t, oktaFactorDeactivated), now)
	expect(t, ev.Document(), map[string]any{
		"datamodel": "Change", "action": "modified", "status": "success", "change_type": "AAA", "object": "jdoe@example.com",
		"object_category": "User", "user": "admin@example.com", "command": "user.mfa.factor.deactivate",
	})
	expectLists(t, ev, map[string][]any{
		"target{}.detailEntry.methodTypeUsed": {"Push"},
		"target{}.alternateId":                {"jdoe@example.com", "unknown"}, "target{}.type": {"User", "Factor"},
		"target{}.displayName": {"Jane Doe", "Okta Verify"},
	})
	if s, _ := ev.Fields["target"].(string); !strings.HasPrefix(s, `[{"alternateId":"jdoe@example.com"`) {
		t.Errorf("target = %v", ev.Fields["target"])
	}
	ev = Normalize(OktaTag, decode(t, oktaThreat), now)
	expect(t, ev.Document(), map[string]any{
		"datamodel": "Alerts", "type": "security.threat.detected", "signature": "security.threat.detected",
		"description": "Request from suspicious actor", "severity": "WARN", "status": "failure", "securityContext.isProxy": "true",
		"reason": "Password Spray", "src": "192.0.2.10",
	})
}

func TestOktaModel(t *testing.T) {
	for typ, want := range map[string][2]string{
		"user.session.start":                                 {"Authentication", ""},
		"user.authentication.auth_via_mfa":                   {"Authentication", ""},
		"app.generic.unauth_app_access_attempt":              {"Authentication", ""},
		"user.lifecycle.create":                              {"Change", "created"},
		"system.api_token.create":                            {"Change", "created"},
		"group.user_membership.remove":                       {"Change", "deleted"},
		"application.policy.sign_on.rule.delete":             {"Change", "deleted"},
		"user.account.lock":                                  {"Change", "lockout"},
		"iam.resourceset.bindings.add":                       {"Change", "created"},
		"zone.deactivate":                                    {"Change", "modified"},
		"policy.lifecycle.update":                            {"Change", "modified"},
		"policy.evaluate_sign_on":                            {"Other", ""},
		"system.push.send_factor_verify_push":                {"Other", ""},
		"security.threat.detected":                           {"Alerts", ""},
		"user.account.report_suspicious_activity_by_enduser": {"Alerts", ""},
		"app.oauth2.as.token.grant":                          {"Change", "modified"},
		"user.session.end":                                   {"Other", ""},
	} {
		if got := OktaModel(typ); got != want[0] {
			t.Errorf("OktaModel(%s) = %s, want %s", typ, got, want[0])
		}
		if want[1] != "" && OktaChangeAction(typ) != want[1] {
			t.Errorf("OktaChangeAction(%s) = %s, want %s", typ, OktaChangeAction(typ), want[1])
		}
	}
}

// A page of the System Log API is a JSON array of events; one sent with
// the okta tag is read the same way.
func TestOktaRecords(t *testing.T) {
	page := "[" + oktaSignInFailed + ",\n" + oktaThreat + `, {"not": "an event"}, null]`
	recs, err := OktaRecords([]byte(page))
	if err != nil || len(recs) != 2 {
		t.Fatalf("%d records, %v", len(recs), err)
	}
	if recs, err := OktaRecords([]byte(oktaThreat)); err != nil || len(recs) != 1 {
		t.Fatalf("one event: %d records, %v", len(recs), err)
	}
	for _, bad := range []string{"", "x", `"text"`, "[" + strings.Repeat("[", MaxDepth+2) + strings.Repeat("]", MaxDepth+2) + "]"} {
		if _, err := OktaRecords([]byte(bad)); err == nil {
			t.Errorf("%.40q was read", bad)
		}
	}
	fb := &fakeBulk{}
	p := &Pipeline{Store: fb, Prefix: "sig", Now: func() time.Time { return now }}
	if _, err := p.IngestBody(context.Background(), OktaTag, []byte(strings.TrimSuffix(page, ", null]")+"]")); err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, d := range fb.docs {
		if d.Doc["sourcetype"] == OktaSourcetype {
			n++
		}
	}
	if n != 2 {
		t.Errorf("%d Okta events, want 2", n)
	}
}

// The Collector passes an event on as the body's text, or as a map.
func TestOktaFromOTLP(t *testing.T) {
	docs := otlpDocs(t, tRes{attrs: []tKV{{"host.name", "collector1"}}, recs: []tRec{
		{observed: uint64(now.UnixNano()), body: strings.ReplaceAll(oktaThreat, "\n", "")},
		{observed: uint64(now.UnixNano()), body: "[" + strings.ReplaceAll(oktaFactorDeactivated+","+oktaThreat, "\n", "") + "]"},
		{observed: uint64(now.UnixNano()), body: `{"eventType": "x", "uuid": "y"}`},
	}})
	if len(docs) != 4 {
		t.Fatalf("%d documents, want 4", len(docs))
	}
	expect(t, docs[0], map[string]any{"datamodel": "Alerts", "sourcetype": OktaSourcetype, "host": "collector1",
		"@timestamp": "2026-10-11T11:00:00Z"})
	expect(t, docs[1], map[string]any{"datamodel": "Change", "sourcetype": OktaSourcetype})
	if docs[3]["sourcetype"] == OktaSourcetype {
		t.Errorf("not an event: %v", docs[3])
	}
	deep := `{"eventType": "x", "uuid": "y", "published": "z", "actor": ` + strings.Repeat(`{"a": `, 1000) + "1" + strings.Repeat("}", 1000) + `}`
	if oktaFromOTLP(deep) != nil {
		t.Error("a 1,000-deep OTLP body was read")
	}
}

func TestOktaFieldsKept(t *testing.T) {
	for _, s := range []string{oktaSignInFailed, oktaFactorDeactivated, oktaThreat} {
		ev := Normalize(OktaTag, decode(t, s), now)
		for k := range ev.Fields {
			if !KnownField(k) && !OktaField(k) {
				t.Errorf("field %s is neither mapped in the index template nor an event's", k)
			}
		}
	}
	// A top-level field the LogEvent schema does not have stays in the
	// message: it could otherwise take one of Signalith's own names.
	r := decode(t, oktaThreat)
	r["user"] = "mallory"
	if ev := Normalize(OktaTag, r, now); ev.Fields["user"] != "unknown" {
		t.Errorf("user = %v", ev.Fields["user"])
	}
}

// Sigma's names for an event's fields build a test event that keeps them.
func TestOktaRecord(t *testing.T) {
	data := map[string]string{
		"eventType": "policy.evaluate_sign_on", "target.displayName": "Okta Admin Console",
		"debugContext.debugData.behaviors": "New Device=POSITIVE", "securityContext.isProxy": "true",
		"actor.alternateid": "x@example.com",
	}
	ev := Normalize(OktaTag, OktaRecord("h1", now, data), now)
	expect(t, ev.Document(), map[string]any{
		"host": "h1", "eventType": "policy.evaluate_sign_on", "debugContext.debugData.behaviors": "New Device=POSITIVE",
		"securityContext.isProxy": "true", "actor.alternateId": "x@example.com", "datamodel": "Other",
	})
	expectLists(t, ev, map[string][]any{"target{}.displayName": {"Okta Admin Console"}})
	other := Normalize(OktaTag, OktaRecord("h1", now, map[string]string{"eventType": "x"}), now)
	if other.ID == ev.ID {
		t.Error("two test events share a document ID")
	}
	for name, want := range map[string]string{
		"eventtype": "eventType", "displaymessage": "displayMessage", "target.alternateId": "target{}.alternateId",
		"debugContext.debugData.logOnlySecurityData": "debugContext.debugData.logOnlySecurityData",
		"client.geographicalContext.geolocation.lat": "client.geographicalContext.geolocation.lat",
	} {
		if got, ok := OktaSigmaField(name); !ok || got != want {
			t.Errorf("OktaSigmaField(%s) = %s, %v", name, got, ok)
		}
	}
	if f, ok := OktaSigmaField("CommandLine"); ok {
		t.Errorf("CommandLine is %s", f)
	}
}
