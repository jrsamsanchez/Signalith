// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package ingest

import (
	"cmp"
	"encoding/json"
	"maps"
	"math"
	"slices"
	"strconv"
	"strings"
	"time"
)

// AWS CloudTrail records every call made to an AWS account's APIs. Each
// record becomes an event with CloudTrail's own field names (eventName,
// userIdentity.arn, requestParameters.bucketName), as Splunk's AWS add-on
// keeps them, so Sigma's and Splunk's CloudTrail rules search them as
// written, plus the data model fields of the call: a sign-in to the
// console is an Authentication event, a call that changes something a
// Change event, and a call that only reads Other.
//
// Records come from the OpenTelemetry Collector's aws_s3 receiver, which
// reads the files CloudTrail writes to an S3 bucket and decodes them with
// the aws_logs_encoding extension (see cloudTrailFromOTLP), or as JSON
// records under the aws.cloudtrail tag.

// CloudTrailTag is the tag of CloudTrail records sent as JSON.
const CloudTrailTag = "aws.cloudtrail"

// CloudTrailSourcetype is the sourcetype of CloudTrail events, Splunk's.
const CloudTrailSourcetype = "aws:cloudtrail"

// CloudTrailChannel names CloudTrail records in test events
// (sigmacheck.Case), as a Windows channel names Windows events.
const CloudTrailChannel = "aws:cloudtrail"

// cloudTrailMaxLeaves caps the fields one record's nested objects
// (requestParameters, responseElements, ...) become; the rest stay in the
// message.
const cloudTrailMaxLeaves = 120

// cloudTrailFields are the record's fields kept by name when set: its
// top-level fields and its caller's identity. The fields of a call's
// parameters and response depend on the call.
var cloudTrailFields = []string{
	"eventVersion", "eventSource", "eventName", "eventType", "eventCategory", "eventID", "awsRegion",
	"sourceIPAddress", "userAgent", "errorCode", "errorMessage", "requestID", "recipientAccountId",
	"sharedEventID", "vpcEndpointId", "vpcEndpointAccountId", "apiVersion", "sessionCredentialFromConsole",
	"readOnly", "managementEvent",
	"userIdentity.type", "userIdentity.arn", "userIdentity.principalId", "userIdentity.accountId",
	"userIdentity.accessKeyId", "userIdentity.userName", "userIdentity.invokedBy", "userIdentity.identityStoreArn",
	"userIdentity.sessionContext.sourceIdentity",
	"userIdentity.sessionContext.attributes.mfaAuthenticated", "userIdentity.sessionContext.attributes.creationDate",
	"userIdentity.sessionContext.sessionIssuer.type", "userIdentity.sessionContext.sessionIssuer.arn",
	"userIdentity.sessionContext.sessionIssuer.principalId", "userIdentity.sessionContext.sessionIssuer.accountId",
	"userIdentity.sessionContext.sessionIssuer.userName",
	"tlsDetails.tlsVersion", "tlsDetails.cipherSuite", "tlsDetails.clientProvidedHostHeader",
}

// cloudTrailMapped are the fields of cloudTrailFields the index template
// maps (see knownFields): what a CloudTrail search reads first, which an
// event keeps even when its index's mapping is full. The rest are mapped
// as they come, like any other name, so that they do not take room in
// every index.
var cloudTrailMapped = []string{
	"eventSource", "eventName", "eventType", "eventID", "awsRegion", "sourceIPAddress", "userAgent",
	"errorCode", "errorMessage", "recipientAccountId",
	"userIdentity.type", "userIdentity.arn", "userIdentity.principalId", "userIdentity.accountId", "userIdentity.userName",
}

// cloudTrailLists are lists of objects in calls' parameters that rules
// name fields inside (requestParameters.containerDefinitions.command). A
// list is kept as JSON text under its own name, so a rule's field
// inside one reads the list's text.
var cloudTrailLists = []string{"requestParameters.containerDefinitions"}

// CloudTrailList returns the list of objects a field name passes through
// (cloudTrailLists), or "".
func CloudTrailList(name string) string {
	for _, l := range cloudTrailLists {
		if strings.HasPrefix(name, l+".") {
			return l
		}
	}
	return ""
}

// cloudTrailCallerKeyed are the objects in a call's parameters and
// response whose keys the caller chooses: tags, Lambda's and ECS's
// environment, SSM's and CloudFormation's parameters, Glue's
// defaultArguments.
var cloudTrailCallerKeyed = map[string]bool{"tags": true, "parameters": true, "defaultarguments": true, "environment": true}

// cloudTrailObjects are a record's objects whose fields are kept, each as
// its own field (requestParameters.bucketName), as far as cloudTrailMaxLeaves.
var cloudTrailObjects = []string{"requestParameters", "responseElements", "additionalEventData", "serviceEventDetails"}

// IsCloudTrailRecord reports whether a decoded object is a CloudTrail
// record: it has eventVersion, eventSource and eventName.
func IsCloudTrailRecord(r map[string]any) bool {
	return has(r, "eventVersion") && has(r, "eventSource") && has(r, "eventName")
}

// ParseCloudTrail maps a CloudTrail record (decoded JSON) onto an event.
func ParseCloudTrail(r map[string]any) Event {
	f := map[string]any{
		"sourcetype":     CloudTrailSourcetype,
		"vendor_product": "AWS CloudTrail",
	}
	flat := map[string]any{}
	flattenCloudTrail("", r, flat)
	for _, k := range cloudTrailFields {
		if v, ok := flat[k]; ok {
			f[k] = v
		}
	}
	leaves := 0
	for _, obj := range cloudTrailObjects {
		var keys []string
		for k := range flat {
			if strings.HasPrefix(k, obj+".") {
				keys = append(keys, k)
			}
		}
		slices.Sort(keys)
		for _, k := range keys {
			if leaves >= cloudTrailMaxLeaves {
				break
			}
			if validFieldName(k) {
				f[k] = flat[k]
				leaves++
			}
		}
	}
	for obj, field := range map[string]string{"requestParameters": "request_parameters", "responseElements": "response_elements"} {
		switch v := r[obj].(type) {
		case map[string]any, []any:
			if b, err := json.Marshal(v); err == nil {
				f[field] = truncateUTF8(string(b), MaxRecordBytes)
			}
		case string:
			if v != "" {
				f[field] = v
			}
		}
	}
	if raw, err := json.Marshal(r); err == nil {
		f["message"] = truncateUTF8(string(raw), MaxRecordBytes)
	}

	name := wstr(f["eventName"])
	source := wstr(f["eventSource"])
	user := cloudTrailUser(f)
	set := func(k, v string) {
		if v != "" {
			f[k] = CapValue(v)
		}
	}
	set("signature", name)
	set("command", name)
	set("app", source)
	set("dest", source)
	set("user", user)
	// The machine that sent the record, when it says (CloudTrail itself
	// has no host).
	if h, ok := r["hostname"].(string); ok {
		set("host", h)
	}
	set("user_name", user)
	set("src", wstr(f["sourceIPAddress"]))
	set("user_agent", wstr(f["userAgent"]))
	set("vendor_account", cmp.Or(wstr(f["recipientAccountId"]), wstr(f["userIdentity.accountId"])))
	set("vendor_region", wstr(f["awsRegion"]))
	status := "success"
	if wstr(f["errorCode"]) != "" {
		status = "failure"
		set("reason", cmp.Or(wstr(f["errorMessage"]), wstr(f["errorCode"])))
	}

	ev := Event{Fields: f}
	if t, err := time.Parse(time.RFC3339, str(r, "eventTime")); err == nil {
		ev.Time = t.UTC()
	}
	switch {
	case source == "signin.amazonaws.com":
		// A sign-in to the console, or a step of one.
		ev.Model = "Authentication"
		if v, ok := f["responseElements.ConsoleLogin"].(string); ok && !strings.EqualFold(v, "Success") {
			status = "failure"
			set("reason", cmp.Or(wstr(f["errorMessage"]), v))
		}
		f["action"] = status
		f["status"] = status
		f["app"] = "aws:console"
		f["dest"] = "aws:" + wstr(f["vendor_account"])
		if f["dest"] == "aws:" {
			delete(f, "dest")
		}
	case f["readOnly"] == true:
		ev.Model = "Other"
		f["status"] = status
	default:
		ev.Model = "Change"
		f["status"] = status
		f["action"] = cloudTrailAction(name)
		f["object_category"] = strings.TrimSuffix(source, ".amazonaws.com")
		f["change_type"] = "AWS API Call"
	}
	return ev
}

// cloudTrailUser is the account that made a call: an IAM user's name, the
// role behind a role's session, root, or the last part of its ARN.
func cloudTrailUser(f map[string]any) string {
	if u := wstr(f["userIdentity.userName"]); u != "" {
		return u
	}
	if u := wstr(f["userIdentity.sessionContext.sessionIssuer.userName"]); u != "" {
		return u
	}
	if wstr(f["userIdentity.type"]) == "Root" {
		return "root"
	}
	if arn := wstr(f["userIdentity.arn"]); arn != "" {
		return arn[strings.LastIndexAny(arn, "/:")+1:]
	}
	return cmp.Or(wstr(f["userIdentity.principalId"]), wstr(f["userIdentity.invokedBy"]))
}

// cloudTrailAction is the Change data model's action of a call, from the
// verb of its name.
func cloudTrailAction(name string) string {
	for _, p := range [][2]string{
		{"Create", "created"}, {"Add", "created"}, {"Put", "created"}, {"Run", "created"}, {"Import", "created"},
		{"Attach", "created"}, {"Register", "created"}, {"Upload", "created"}, {"Allocate", "created"},
		{"Delete", "deleted"}, {"Remove", "deleted"}, {"Detach", "deleted"}, {"Terminate", "deleted"},
		{"Deregister", "deleted"}, {"Disassociate", "deleted"}, {"Revoke", "deleted"}, {"Release", "deleted"},
		{"Stop", "stopped"}, {"Disable", "disabled"}, {"Enable", "enabled"}, {"Start", "started"},
	} {
		if rest, ok := strings.CutPrefix(name, p[0]); ok && (rest == "" || rest[0] >= 'A' && rest[0] <= 'Z') {
			return p[1]
		}
	}
	return "modified"
}

// flattenCloudTrail puts the record's values in out under dotted names
// (userIdentity.arn): strings, booleans and numbers (whole numbers as
// integers) as themselves, lists, and objects nested past the deepest
// field name, as JSON text.
func flattenCloudTrail(prefix string, v any, out map[string]any) {
	depth := strings.Count(prefix, ".") + 1
	switch x := v.(type) {
	case map[string]any:
		if prefix != "" && depth >= maxFieldDepth {
			if b, err := json.Marshal(x); err == nil {
				out[prefix] = CapValue(string(b))
			}
			return
		}
		for k, e := range x {
			if k == "" || strings.Contains(k, ".") {
				continue
			}
			name := k
			if prefix != "" {
				name = prefix + "." + k
			}
			if _, keyed := e.(map[string]any); keyed && prefix != "" && cloudTrailCallerKeyed[strings.ToLower(k)] {
				// Its keys are the caller's own (a resource's tags, a
				// function's environment variables): kept as one field of
				// JSON text, so they can't use up the index's field names.
				if b, err := json.Marshal(e); err == nil {
					out[name] = CapValue(string(b))
				}
				continue
			}
			flattenCloudTrail(name, e, out)
		}
	case []any:
		if len(x) == 0 {
			return
		}
		if b, err := json.Marshal(x); err == nil {
			out[prefix] = CapValue(string(b))
		}
	case string:
		if x != "" {
			out[prefix] = CapValue(x)
		}
	case bool:
		out[prefix] = x
	case json.Number:
		if n, err := x.Int64(); err == nil {
			out[prefix] = n
		} else if d, err := x.Float64(); err == nil {
			out[prefix] = d
		}
	case float64:
		if x == math.Trunc(x) && math.Abs(x) < 1<<53 {
			out[prefix] = int64(x)
		} else {
			out[prefix] = x
		}
	case int64:
		out[prefix] = x
	case int:
		out[prefix] = int64(x)
	}
}

// cloudTrailOTLP maps the attributes the Collector's aws_logs_encoding
// extension gives a CloudTrail record (format cloudtrail) back to the
// record's own fields. Both spellings of the caller's identity are read:
// aws.principal.* and, with the extension's user identity prefix,
// aws.user_identity.principal.*.
var cloudTrailOTLP = map[string]string{
	"aws.cloudtrail.event_version":         "eventVersion",
	"aws.cloudtrail.event_id":              "eventID",
	"aws.cloudtrail.api_version":           "apiVersion",
	"aws.request_id":                       "requestID",
	"aws.event.category":                   "eventCategory",
	"aws.event.read_only":                  "readOnly",
	"aws.event.management":                 "managementEvent",
	"source.address":                       "sourceIPAddress",
	"user_agent.original":                  "userAgent",
	"aws.error.code":                       "errorCode",
	"aws.error.message":                    "errorMessage",
	"aws.shared_event_id":                  "sharedEventID",
	"aws.request.parameters":               "requestParameters",
	"aws.response.elements":                "responseElements",
	"aws.cloudtrail.additional_event_data": "additionalEventData",
	"aws.insight_details":                  "insightDetails",
	"user.id":                              "userIdentity.userId",
	"user.name":                            "userIdentity.userName",
	"aws.user_identity.account_id":         "userIdentity.accountId",
	"aws.access_key.id":                    "userIdentity.accessKeyId",
	"aws.user_identity.access_key.id":      "userIdentity.accessKeyId",
	"aws.identity_store.arn":               "userIdentity.identityStoreArn",
	"aws.user_identity.identity_store.arn": "userIdentity.identityStoreArn",
	"aws.user_identity.invoked_by":         "userIdentity.invokedBy",
	"aws.principal.id":                     "userIdentity.principalId",
	"aws.user_identity.principal.id":       "userIdentity.principalId",
	"aws.principal.arn":                    "userIdentity.arn",
	"aws.user_identity.principal.arn":      "userIdentity.arn",
	"aws.principal.type":                   "userIdentity.type",
	"aws.user_identity.principal.type":     "userIdentity.type",
	"aws.user_identity.session_context.attributes.creation_date": "userIdentity.sessionContext.attributes.creationDate",
	"aws.user_identity.session_context.issuer.type":              "userIdentity.sessionContext.sessionIssuer.type",
	"aws.user_identity.session_context.issuer.principal_id":      "userIdentity.sessionContext.sessionIssuer.principalId",
	"aws.user_identity.session_context.issuer.arn":               "userIdentity.sessionContext.sessionIssuer.arn",
	"aws.user_identity.session_context.issuer.account_id":        "userIdentity.sessionContext.sessionIssuer.accountId",
	"aws.user_identity.session_context.issuer.user_name":         "userIdentity.sessionContext.sessionIssuer.userName",
	"tls.cipher":     "tlsDetails.cipherSuite",
	"server.address": "tlsDetails.clientProvidedHostHeader",
}

// isCloudTrailOTLP reports whether an OTLP log record is a CloudTrail
// record the aws_logs_encoding extension decoded (not a digest record).
func isCloudTrailOTLP(attrs map[string]any) bool {
	return has(attrs, "aws.cloudtrail.event_id")
}

// cloudTrailFromOTLP rebuilds the CloudTrail record of an OTLP log record
// the aws_logs_encoding extension decoded, with the region and account its
// resource names, and its time.
func cloudTrailFromOTLP(attrs, resource map[string]any, t time.Time) map[string]any {
	r := map[string]any{}
	put := func(path string, v any) {
		parts := strings.Split(path, ".")
		m := r
		for _, p := range parts[:len(parts)-1] {
			next, ok := m[p].(map[string]any)
			if !ok {
				next = map[string]any{}
				m[p] = next
			}
			m = next
		}
		m[parts[len(parts)-1]] = v
	}
	for k, name := range cloudTrailOTLP {
		if v, ok := attrs[k]; ok && v != nil {
			put(name, v)
		}
	}
	// The call: rpc.method is the event's name, or, with semantic
	// conventions 1.40, its service and name (ec2.amazonaws.com/StartInstances).
	method := str(attrs, "rpc.method")
	service := str(attrs, "rpc.service")
	if s, n, ok := strings.Cut(method, "/"); ok {
		service, method = cmp.Or(service, s), n
	}
	if method != "" {
		r["eventName"] = method
	}
	if service != "" {
		r["eventSource"] = service
	}
	if v := cmp.Or(str(attrs, "rpc.system.name"), str(attrs, "rpc.system")); v != "" {
		r["eventType"] = v
	}
	if v, _ := attrs["aws.session.console"].(bool); v {
		r["sessionCredentialFromConsole"] = "true"
	}
	if v, ok := attrs["aws.user_identity.session_context.attributes.mfa_authenticated"].(bool); ok {
		put("userIdentity.sessionContext.attributes.mfaAuthenticated", strconv.FormatBool(v))
	}
	if v := str(attrs, "tls.protocol.version"); v != "" {
		put("tlsDetails.tlsVersion", "TLSv"+v)
	}
	if v, ok := attrs["aws.resources"].([]any); ok {
		var list []any
		for _, e := range v {
			m, _ := e.(map[string]any)
			list = append(list, map[string]any{"accountId": m["account.id"], "type": m["type"], "ARN": m["arn"]})
		}
		r["resources"] = list
	}
	if v := str(resource, "cloud.region"); v != "" {
		r["awsRegion"] = v
	}
	if v := str(resource, "cloud.account.id"); v != "" {
		r["recipientAccountId"] = v
	}
	if !t.IsZero() {
		r["eventTime"] = t.UTC().Format(time.RFC3339)
	}
	return r
}

// cloudTrailText decodes a CloudTrail record from JSON text, or returns
// nil when the text is not one.
func cloudTrailText(s string) map[string]any {
	if len(s) > MaxRecordBytes {
		return nil
	}
	d := json.NewDecoder(strings.NewReader(s))
	d.UseNumber()
	var r map[string]any
	if err := d.Decode(&r); err != nil || !IsCloudTrailRecord(r) {
		return nil
	}
	return r
}

// CloudTrailField reports whether ParseCloudTrail keeps a CloudTrail
// field by its name: one of the record's own fields or its caller's, or a
// field of the call's parameters, response or extra data.
func CloudTrailField(name string) bool {
	if slices.Contains(cloudTrailFields, name) {
		return true
	}
	for _, obj := range cloudTrailObjects {
		if strings.HasPrefix(name, obj+".") {
			// CloudTrail's lists are kept as JSON text, not by Splunk's
			// names for their values (items{}.userId).
			return validFieldName(name) && !strings.Contains(name, "{") && strings.Count(name, ".") < maxFieldDepth
		}
	}
	return false
}

// CloudTrailRecord is a CloudTrail record with fields by their dotted
// names (userIdentity.type), for test events (Normalize with
// CloudTrailTag), as host sent it.
func CloudTrailRecord(host string, t time.Time, data map[string]string) map[string]any {
	r := map[string]any{"eventVersion": "1.09", "eventTime": t.UTC().Format(time.RFC3339), "hostname": host}
	keys := slices.Sorted(maps.Keys(data))
	for _, k := range keys {
		parts := strings.Split(k, ".")
		m := r
		for i, p := range parts[:len(parts)-1] {
			if list := strings.Join(parts[:i+1], "."); slices.Contains(cloudTrailLists, list) {
				// A list of objects: the fields go in its first one.
				l, _ := m[p].([]any)
				if len(l) == 0 {
					l = []any{map[string]any{}}
					m[p] = l
				}
				m = l[0].(map[string]any)
				continue
			}
			next, ok := m[p].(map[string]any)
			if !ok {
				next = map[string]any{}
				m[p] = next
			}
			m = next
		}
		if l, ok := testList(data[k]); ok {
			// A whole list (a bucket's grants, a scan's findings),
			// written as JSON.
			m[parts[len(parts)-1]] = l
			continue
		}
		m[parts[len(parts)-1]] = data[k]
	}
	return r
}
