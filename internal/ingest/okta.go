package ingest

import (
	"bytes"
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"
)

// Okta records what users and admins do in an Okta organization in its
// System Log: sign-ins and MFA, sessions, changes to users, groups,
// apps and policies, API tokens, and the threats Okta ThreatInsight
// detects. The System Log API (GET /api/v1/logs) serves each one as a
// LogEvent (internal/okta reads it). Each event becomes an event with
// the LogEvent's own field names flattened with dots (eventType,
// actor.alternateId, outcome.result, client.ipAddress,
// debugContext.debugData.requestUri), as Splunk's add-on for Okta
// Identity Cloud keeps them (sourcetype OktaIM2:log), and a list's values
// by Splunk's names for them (target{}.alternateId), plus the CIM fields
// that add-on gives it: a sign-in is an Authentication event, an admin
// change a Change event, a threat Okta detected or a user reported an
// Alerts event, and the rest Other.
//
// Every value is kept as text, as Okta's debug data names keys of its
// own whose values one index's mapping could not hold as one type.
//
// LogEvents also come under the okta tag as JSON (one object, or a JSON
// array as the API returns them), or through the OpenTelemetry Collector
// as a log record whose body is one (see oktaFromOTLP).

// OktaTag is the tag of Okta System Log events sent as JSON.
const OktaTag = "okta"

// OktaSourcetype is Splunk's sourcetype for these events.
const OktaSourcetype = "OktaIM2:log"

// OktaVendor is the vendor_product of Okta events.
const OktaVendor = "Okta"

// OktaChannel names Okta System Log events in test events
// (sigmacheck.Case), as a Windows channel names Windows events.
const OktaChannel = "okta"

// OktaService is the Sigma service (and product) of Okta's System Log,
// whose rules Signalith converts.
const OktaService = "okta"

// oktaMaxLeaves caps the fields one event's nested objects and lists
// become, beyond oktaFields; the rest stay in the message.
const oktaMaxLeaves = 150

// oktaTop are a LogEvent's top-level fields, kept by name when set.
var oktaTop = []string{"uuid", "published", "eventType", "version", "severity", "legacyEventType", "displayMessage"}

// oktaObjects are a LogEvent's objects and lists, whose fields are kept
// each as its own field (actor.alternateId, target{}.type).
var oktaObjects = []string{
	"actor", "client", "device", "authenticationContext", "securityContext", "outcome", "target", "transaction",
	"debugContext", "request",
}

// oktaStored is the name an event keeps a LogEvent object's fields
// under: its own, but okta_device for device, as Signalith's device
// field holds text and cannot also hold an object.
func oktaStored(obj string) string {
	if obj == "device" {
		return "okta_device"
	}
	return obj
}

// oktaFields are the fields of an event kept by name whenever it has
// them, before the rest of its objects' fields (oktaMaxLeaves).
var oktaFields = []string{
	"actor.id", "actor.type", "actor.alternateId", "actor.displayName",
	"client.ipAddress", "client.device", "client.zone", "client.id", "client.userAgent.rawUserAgent",
	"client.userAgent.os", "client.userAgent.browser", "client.geographicalContext.city",
	"client.geographicalContext.state", "client.geographicalContext.country", "client.geographicalContext.postalCode",
	"outcome.result", "outcome.reason",
	"authenticationContext.authenticationProvider", "authenticationContext.credentialProvider",
	"authenticationContext.credentialType", "authenticationContext.externalSessionId",
	"authenticationContext.interface", "authenticationContext.authenticationStep",
	"securityContext.asNumber", "securityContext.asOrg", "securityContext.isp", "securityContext.domain",
	"securityContext.isProxy",
	"transaction.type", "transaction.id",
	"debugContext.debugData.requestId", "debugContext.debugData.requestUri", "debugContext.debugData.url",
	"debugContext.debugData.dtHash", "debugContext.debugData.behaviors", "debugContext.debugData.logOnlySecurityData",
	"debugContext.debugData.risk", "debugContext.debugData.threatSuspected", "debugContext.debugData.factor",
	"debugContext.debugData.tunnels", "debugContext.debugData.deviceFingerprint",
	"target", "target{}.id", "target{}.type", "target{}.alternateId", "target{}.displayName",
	"request.ipChain", "request.ipChain{}.ip",
}

// oktaMapped are the fields the index template maps (see knownFields):
// what an Okta search reads first. The rest are mapped as they come.
var oktaMapped = []string{
	"uuid", "published", "legacyEventType", "displayMessage", "actor.id", "actor.type", "actor.alternateId",
	"actor.displayName", "client.ipAddress", "client.userAgent.rawUserAgent", "outcome.result", "outcome.reason",
	"target{}.id", "target{}.type", "target{}.alternateId", "target{}.displayName",
	"authenticationContext.externalSessionId", "securityContext.isProxy", "debugContext.debugData.requestUri",
	"src_user_id",
}

// IsOktaRecord reports whether a decoded object is an Okta System Log
// LogEvent: it has an ID, a time, an event type and an actor.
func IsOktaRecord(r map[string]any) bool {
	_, actor := r["actor"].(map[string]any)
	return actor && str(r, "uuid") != "" && str(r, "published") != "" && str(r, "eventType") != ""
}

// maxOktaBody caps the JSON text of the events read at once: a page of
// the System Log API holds at most 1,000 events.
const maxOktaBody = 64 << 20

// OktaRecords decodes Okta LogEvents from JSON text: one object, or an
// array of them as the System Log API returns a page. Objects that are
// not LogEvents are left out; text that is neither is an error.
func OktaRecords(b []byte) ([]map[string]any, error) {
	b = bytes.TrimSpace(b)
	if len(b) == 0 || len(b) > maxOktaBody {
		return nil, fmt.Errorf("an Okta System Log answer must be 1 byte to %d MB of JSON", maxOktaBody>>20)
	}
	if b[0] != '{' && b[0] != '[' {
		return nil, errors.New("not a JSON object or array")
	}
	// An array of events is one level deeper than an event.
	if depth(b) > MaxDepth+1 {
		return nil, fmt.Errorf("the JSON nests more than %d levels deep", MaxDepth)
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	var list []map[string]any
	if b[0] == '{' {
		var r map[string]any
		if err := d.Decode(&r); err != nil {
			return nil, err
		}
		list = []map[string]any{r}
	} else if err := d.Decode(&list); err != nil {
		return nil, err
	}
	out := list[:0]
	for _, r := range list {
		if r != nil && IsOktaRecord(r) {
			out = append(out, r)
		}
	}
	return out, nil
}

// oktaFromOTLP returns the Okta LogEvents of an OTLP log record whose body
// is one, or an array of them: text, as an http or file receiver passes
// it on, or a map.
func oktaFromOTLP(body any) []map[string]any {
	switch b := body.(type) {
	case string:
		if len(b) > MaxRecordBytes || !strings.Contains(b, `"eventType"`) || !strings.Contains(b, `"uuid"`) {
			return nil
		}
		// The text sat inside a string, past the body's own depth check;
		// OktaRecords checks it.
		recs, err := OktaRecords([]byte(b))
		if err != nil || len(recs) == 0 {
			return nil
		}
		return recs
	case map[string]any:
		if IsOktaRecord(b) {
			return []map[string]any{b}
		}
	}
	return nil
}

// ParseOkta maps an Okta System Log LogEvent (decoded JSON) onto an event.
func ParseOkta(r map[string]any) Event {
	if !IsOktaRecord(r) {
		return parseGeneric(r)
	}
	flat := map[string]any{}
	for _, k := range oktaTop {
		if v, ok := r[k]; ok {
			flattenO365(k, v, flat)
		}
	}
	for _, k := range oktaObjects {
		if v, ok := r[k]; ok {
			flattenO365(oktaStored(k), v, flat)
		}
	}
	f := map[string]any{"sourcetype": OktaSourcetype, "vendor_product": OktaVendor}
	// The top-level fields and oktaFields, then the rest in order, as far
	// as oktaMaxLeaves.
	leaves := 0
	for _, k := range slices.Sorted(maps.Keys(flat)) {
		switch {
		case !validFieldName(k):
		case slices.Contains(oktaTop, k) || slices.Contains(oktaFields, k):
			f[k] = flat[k]
		case leaves < oktaMaxLeaves:
			f[k] = flat[k]
			leaves++
		}
	}
	raw, rawErr := json.Marshal(r)
	if rawErr == nil {
		f["message"] = truncateUTF8(string(raw), MaxRecordBytes)
	}
	set := func(k, v string) {
		if v != "" {
			f[k] = CapValue(v)
		}
	}
	// The machine that sent the event, when it says (Okta itself has no
	// host).
	if h, ok := r["hostname"].(string); ok {
		set("host", h)
	}
	actor, _ := r["actor"].(map[string]any)
	client, _ := r["client"].(map[string]any)
	agent, _ := client["userAgent"].(map[string]any)
	outcome, _ := r["outcome"].(map[string]any)
	auth, _ := r["authenticationContext"].(map[string]any)
	debug, _ := r["debugContext"].(map[string]any)
	debugData, _ := debug["debugData"].(map[string]any)
	eventType := str(r, "eventType")
	result := strings.ToUpper(o365Text(outcome["result"]))
	set("signature", eventType)
	set("command", eventType)
	set("description", str(r, "displayMessage"))
	set("id", str(r, "uuid"))
	// Who acted, as Splunk's add-on names them: user and src_user are the
	// actor's sign-in name.
	who := cmp.Or(o365Text(actor["alternateId"]), o365Text(actor["displayName"]), o365Text(actor["id"]))
	set("user", who)
	set("src_user", who)
	set("src_user_id", o365Text(actor["id"]))
	set("src_user_type", o365Text(actor["type"]))
	set("src", o365Address(o365Text(client["ipAddress"])))
	set("user_agent", o365Text(agent["rawUserAgent"]))
	set("http_user_agent", o365Text(agent["rawUserAgent"]))
	set("reason", o365Text(outcome["reason"]))
	set("result", result)
	// The app it was about, when an app is one of its targets, else Okta
	// itself.
	app := OktaVendor
	targets, _ := r["target"].([]any)
	var first map[string]any
	for _, t := range targets {
		m, ok := t.(map[string]any)
		if !ok {
			continue
		}
		if first == nil {
			first = m
		}
		if o365Text(m["type"]) == "AppInstance" && o365Text(m["displayName"]) != "" {
			app = o365Text(m["displayName"])
			break
		}
	}
	set("app", app)
	set("dest", app)
	status := ""
	switch result {
	case "SUCCESS", "ALLOW":
		status = "success"
	case "FAILURE", "DENY":
		status = "failure"
	}
	set("status", status)

	ev := Event{Fields: f, Model: "Other"}
	if t, err := time.Parse(time.RFC3339Nano, str(r, "published")); err == nil {
		ev.Time = t.UTC()
	}
	// The same event, read twice from the API, is stored once. The ID
	// covers the whole event, not just its uuid, so an event sent with a
	// real event's uuid before the poller reads it cannot take its place.
	if id := str(r, "uuid"); id != "" && rawErr == nil {
		ev.ID = sensorDocID("okta", id+"\n"+string(raw))
	}
	switch m := OktaModel(eventType); m {
	case "Authentication":
		ev.Model = m
		switch result {
		case "SUCCESS", "ALLOW":
			f["action"] = "success"
		case "FAILURE", "DENY":
			f["action"] = "failure"
		case "CHALLENGE":
			f["action"] = "pending"
		default:
			f["action"] = "unknown"
		}
		set("authentication_method", cmp.Or(o365Text(auth["credentialType"]), o365Text(debugData["factor"])))
	case "Alerts":
		ev.Model = m
		set("type", eventType)
	case "Change":
		ev.Model = m
		f["action"] = OktaChangeAction(eventType)
		set("change_type", "AAA")
		if first != nil {
			set("object", cmp.Or(o365Text(first["alternateId"]), o365Text(first["displayName"]), o365Text(first["id"])))
			set("object_category", o365Text(first["type"]))
		}
	}
	return ev
}

// OktaModel is the data model of an Okta event type: sign-ins and MFA
// are Authentication, threats Okta detected and activity a user reported
// Alerts, admin changes (users, groups, apps, policies, network zones,
// API tokens, identity providers, devices) Change, and the rest Other.
func OktaModel(eventType string) string {
	e := strings.ToLower(eventType)
	has := func(prefixes ...string) bool {
		return slices.ContainsFunc(prefixes, func(p string) bool { return strings.HasPrefix(e, p) })
	}
	switch {
	case has("user.session.start", "user.authentication.", "user.session.access_admin_app", "app.generic.unauth_app_access_attempt"):
		return "Authentication"
	case has("security.", "user.account.report_suspicious_activity_by_enduser", "user.risk."):
		return "Alerts"
	case has("system.push.", "system.email.", "system.sms.", "system.voice.", "policy.evaluate_sign_on", "policy.auth_reevaluate"):
		// Factors sent and policies evaluated: not changes.
		return "Other"
	case has("user.lifecycle.", "user.account.", "user.mfa.factor.", "user.credential.", "group.", "application.",
		"app.oauth2.", "app.user_management", "policy.", "system.", "zone.", "iam.", "device.", "user.mfa.attempt_bypass"):
		return "Change"
	}
	return "Other"
}

// OktaChangeAction is what an Okta change did, by the words of its event
// type: created (user.lifecycle.create, system.api_token.create), deleted
// (zone.delete, group.user_membership.remove), lockout
// (user.account.lock), or modified (user.mfa.factor.deactivate, and
// anything else).
func OktaChangeAction(eventType string) string {
	words := strings.Split(strings.ToLower(eventType), ".")
	for _, w := range words[min(1, len(words)):] {
		switch w {
		case "create", "add":
			return "created"
		case "delete", "remove":
			return "deleted"
		case "lock":
			return "lockout"
		}
	}
	return "modified"
}

// oktaSchema are the fields of an Okta LogEvent that Sigma's and
// Splunk's rules may name, by Okta's own names, which a rule may also
// write in lower case (actor.alternateid). A list's values are by Splunk's
// names for them (target{}.displayName).
var oktaSchema = func() map[string]string {
	m := map[string]string{}
	for _, k := range oktaTop {
		m[strings.ToLower(k)] = k
	}
	for _, k := range oktaFields {
		m[strings.ToLower(k)] = k
	}
	return m
}()

// OktaField reports whether an Okta event keeps a field of a LogEvent by
// its own name: a top-level field (eventType), or one under the
// LogEvent's objects (outcome.result, debugContext.debugData.behaviors,
// target{}.alternateId, okta_device.name).
func OktaField(name string) bool {
	if slices.Contains(oktaTop, name) {
		return true
	}
	return validFieldName(name) &&
		slices.ContainsFunc(oktaObjects, func(obj string) bool {
			obj = oktaStored(obj)
			return strings.HasPrefix(name, obj+".") || strings.HasPrefix(name, obj+"{}.") || name == obj
		})
}

// OktaSigmaField returns the field an Okta event keeps for a field of a
// Sigma rule of product okta, or false when it keeps none. Sigma names
// Okta's fields as Okta does, and a list's fields without its {}
// (target.displayName), in any case.
func OktaSigmaField(name string) (string, bool) {
	if f, ok := oktaSchema[strings.ToLower(name)]; ok {
		return f, true
	}
	if rest, ok := strings.CutPrefix(name, "device."); ok {
		name = oktaStored("device") + "." + rest
	}
	for _, list := range []string{"target", "request.ipChain"} {
		if rest, ok := strings.CutPrefix(name, list+"."); ok {
			name = list + "{}." + rest
			if f, ok := oktaSchema[strings.ToLower(name)]; ok {
				return f, true
			}
			break
		}
	}
	if OktaField(name) {
		return name, true
	}
	return "", false
}

// OktaRecord is an Okta System Log LogEvent with the fields data names,
// by a rule's names for them (eventType, outcome.result,
// target.displayName), for test events (Normalize with OktaTag), as host
// sent it: unless data says otherwise, a user signing out of Okta in a
// browser, which no rule is about.
func OktaRecord(host string, t time.Time, data map[string]string) map[string]any {
	r := map[string]any{
		"published": t.UTC().Format("2006-01-02T15:04:05.000Z"), "version": "0", "severity": "INFO",
		"eventType": "user.session.end", "legacyEventType": "core.user_auth.logout_success",
		"displayMessage": "User logout from Okta", "hostname": host,
		"actor": map[string]any{"id": "00u1a2b3c4d5e6f7g8h9", "type": "User", "alternateId": "jdoe@example.com", "displayName": "Jane Doe"},
		"client": map[string]any{
			"ipAddress": "203.0.113.7", "device": "Computer",
			"userAgent":           map[string]any{"rawUserAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)", "os": "Windows 10", "browser": "CHROME"},
			"geographicalContext": map[string]any{"city": "Springfield", "state": "Illinois", "country": "United States"},
		},
		"outcome":               map[string]any{"result": "SUCCESS"},
		"authenticationContext": map[string]any{"credentialType": "PASSWORD", "externalSessionId": "102abcdefghijklmnop"},
		"securityContext":       map[string]any{"isProxy": false, "asOrg": "example isp", "isp": "example isp"},
		"debugContext":          map[string]any{"debugData": map[string]any{"requestUri": "/idp/idx/identify", "requestId": "abc123"}},
		"transaction":           map[string]any{"type": "WEB", "id": "abc123"},
		"target":                []any{},
	}
	for _, k := range slices.Sorted(maps.Keys(data)) {
		f, ok := OktaSigmaField(k)
		if !ok {
			continue
		}
		v := data[k]
		var val any = v
		if f == "securityContext.isProxy" && (v == "true" || v == "false") {
			val = v == "true"
		}
		gcpPut(r, f, val)
	}
	// Each test event its own uuid, as the same uuid is stored once.
	h := sha256.New()
	fmt.Fprintln(h, host, t.UnixNano())
	for _, k := range slices.Sorted(maps.Keys(data)) {
		fmt.Fprintln(h, k, data[k])
	}
	sum := hex.EncodeToString(h.Sum(nil))
	r["uuid"] = sum[:8] + "-" + sum[8:12] + "-" + sum[12:16] + "-" + sum[16:20] + "-" + sum[20:32]
	return r
}
