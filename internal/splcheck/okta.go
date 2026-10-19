// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package splcheck

import (
	"cmp"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/jrsamsanchez/signalith/internal/ingest"
	"github.com/jrsamsanchez/signalith/internal/sigmacheck"
)

// OktaNode is the node of Okta System Log events (the okta macro). A
// search names no event code. Its fields are the LogEvent's own
// (eventType, outcome.result, debugContext.debugData.factor,
// target{}.displayName), which Signalith keeps by the same names, and the
// CIM fields Splunk's add-on for Okta Identity Cloud gives each event,
// which Signalith sets too.
const OktaNode = "Okta"

// oktaSource is the macro of Okta System Log events.
const oktaSource = "okta"

// The nodes of tstats searches over the Authentication and Change data
// models whose only data source is Okta: their fields are the CIM fields
// Splunk's add-on gives an Okta event, and their test events are Okta
// events, read only from Okta (sourcetype OktaIM2:log).
const (
	OktaAuthNode   = "Okta_Authentication"
	OktaChangeNode = "Okta_Change"
)

// IsOktaTstatsNode reports whether a node is one of a tstats search over
// Okta's events.
func IsOktaTstatsNode(node string) bool { return node == OktaAuthNode || node == OktaChangeNode }

// tstatsOktaRe is a tstats search over the Authentication or Change data
// model.
var tstatsOktaRe = regexp.MustCompile(`(?is)^\|\s*tstats\s+(.*?)\s*\bfrom\s+datamodel\s*=\s*(Authentication|Change)(?:\.(Authentication|All_Changes))?\s+where\s+(.*?)\s+by\s+([^|]*)$`)

// oktaTstatsNode returns the node of a tstats search of a rule whose only
// data source is Okta, with the parts tstatsRe returns.
func oktaTstatsNode(first string, sources []string) ([]string, bool) {
	if !slices.Equal(sources, []string{"Okta"}) {
		return nil, false
	}
	m := tstatsOktaRe.FindStringSubmatch(first)
	if m == nil {
		return nil, false
	}
	node, prefix := OktaAuthNode, "Authentication"
	if strings.EqualFold(m[2], "Change") {
		node, prefix = OktaChangeNode, "All_Changes"
	}
	if m[3] != "" && !strings.EqualFold(m[3], prefix) {
		return nil, false
	}
	return []string{m[0], m[1], m[2], node, m[4], m[5]}, true
}

func init() {
	// The CIM fields an Okta sign-in and an Okta change carry, as
	// Signalith stores them.
	Nodes[OktaAuthNode] = []string{
		"action", "app", "dest", "src", "user", "signature", "reason", "authentication_method", "user_agent", "src_user",
	}
	Nodes[OktaChangeNode] = []string{
		"action", "change_type", "command", "object", "object_category", "result", "status", "src", "dest", "user",
	}
	nodePrefixes[OktaAuthNode] = "Authentication"
	nodePrefixes[OktaChangeNode] = "All_Changes"
	NodeModel[OktaAuthNode] = "Authentication"
	NodeModel[OktaChangeNode] = "Change"
	NodeEvents[OktaAuthNode] = []string{"log"}
	NodeEvents[OktaChangeNode] = []string{"log"}
}

// oktaCIM are the CIM fields of an Okta event, with the Signalith field
// each is stored as. The add-on's src_ip is the client's address, which
// Signalith keeps as src.
var oktaCIM = map[string]string{
	"action": "action", "status": "status", "result": "result", "user": "user", "src_user": "src_user",
	"src_user_id": "src_user_id", "src_user_type": "src_user_type", "src": "src", "src_ip": "src", "dest": "dest",
	"signature": "signature", "command": "command", "app": "app", "user_agent": "user_agent",
	"http_user_agent": "http_user_agent", "reason": "reason", "description": "description",
	"authentication_method": "authentication_method", "object": "object", "object_category": "object_category",
	"change_type": "change_type", "vendor_product": "vendor_product", "sourcetype": "sourcetype",
}

// oktaField is the stored field of an Okta search's field.
func oktaField(name string) (string, bool) {
	if f, ok := oktaCIM[name]; ok {
		return f, true
	}
	// Okta's device object is stored as okta_device, as device is a
	// field of other events (ingest.OktaSigmaField).
	if rest, ok := strings.CutPrefix(name, "device."); ok {
		name = "okta_device." + rest
	}
	return name, ingest.OktaField(name)
}

// oktaRecord turns a field-level event into the Okta LogEvent that
// carries it: CIM fields back to the LogEvent's fields they come from. A
// sign-in's action success or failure is its outcome, and an app it names
// is one of its targets.
func oktaRecord(ev map[string]string) sigmacheck.Case {
	data := map[string]string{}
	set := func(k, v string) {
		if v != "" && data[k] == "" {
			data[k] = v
		}
	}
	for k, v := range ev {
		if _, cim := oktaCIM[k]; !cim && ingest.OktaField(k) {
			data[k] = v
		}
	}
	set("eventType", ev["signature"])
	set("eventType", ev["command"])
	set("actor.alternateId", ev["user"])
	set("actor.alternateId", ev["src_user"])
	set("actor.id", ev["src_user_id"])
	set("actor.type", ev["src_user_type"])
	set("client.ipAddress", ev["src"])
	set("client.ipAddress", ev["src_ip"])
	set("client.userAgent.rawUserAgent", ev["user_agent"])
	set("client.userAgent.rawUserAgent", ev["http_user_agent"])
	set("outcome.reason", ev["reason"])
	set("outcome.result", strings.ToUpper(ev["result"]))
	set("displayMessage", ev["description"])
	set("authenticationContext.credentialType", ev["authentication_method"])
	for _, s := range []string{ev["action"], ev["status"]} {
		switch strings.ToLower(s) {
		case "success":
			set("outcome.result", "SUCCESS")
		case "failure":
			set("outcome.result", "FAILURE")
		}
	}
	if app := cmp.Or(ev["app"], ev["dest"]); app != "" && !strings.EqualFold(app, ingest.OktaVendor) {
		// The app is the event's target.
		set("target{}.type", "AppInstance")
		set("target{}.displayName", app)
	}
	set("target{}.alternateId", ev["object"])
	set("target{}.type", ev["object_category"])
	// What most events have, so a later stage that reads a target finds
	// one: the app signed in to.
	set("target{}.type", "AppInstance")
	set("target{}.displayName", "Example App")
	return sigmacheck.Case{Channel: sigmacheck.OktaChannel, EventID: "log", Data: data}
}

// oktaAggRe is an aggregation of a tstats search over Okta's events,
// with the field it reads and the name it gives the result.
var oktaAggRe = regexp.MustCompile(`(?i)\b\w+\((?:Authentication|All_Changes)\.(\w+)\)(?:\s+as\s+(\w+))?`)

// oktaAggs returns a tstats search's aggregations over Okta's events
// without those of a field the data model does not have (values of
// Authentication.method, which is not a CIM field): Splunk's tstats reads
// no value of it, so the result is not there. One whose result a later
// stage names is refused.
func oktaAggs(aggs string, fields, later []string) (string, error) {
	var err error
	out := oktaAggRe.ReplaceAllStringFunc(aggs, func(a string) string {
		m := oktaAggRe.FindStringSubmatch(a)
		if slices.Contains(fields, m[1]) {
			return a
		}
		name := cmp.Or(m[2], m[0])
		word := regexp.MustCompile(`(^|[^\w.])` + regexp.QuoteMeta(name) + `([^\w.]|$)`)
		for _, s := range later {
			if word.MatchString(postMacros.ReplaceAllString(s, "")) {
				err = fmt.Errorf("field %s is not a field of Okta's events in the data model", m[1])
			}
		}
		return ""
	})
	return out, err
}
