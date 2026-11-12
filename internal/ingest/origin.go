// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package ingest

import (
	"context"
	"strings"
)

// Fields that record where an event came from. Signalith sets them on
// every event it receives; a sender can never set them (see reserved).
const (
	// IntakeField is how the event arrived: agent (an agent's POST to
	// /api/ingest), otlp, hec (a sender built for Splunk's HTTP Event
	// Collector), osquery, syslog, scanner (Signalith's own
	// vulnerability scans) or signalith (what Signalith notices itself,
	// such as a network sensor gone silent).
	IntakeField = "signalith_intake"
	// TokenField is the name of the agent token the event came with, as
	// it was then (never the token itself). Renaming the token later
	// leaves stored events as they are. An event sent with a computer's
	// own key (Origin.Host) names that computer too, as "<token> @
	// <computer>", and one whose host is not the computer that sent it is
	// marked with HostMismatch (see Origin.stampHost).
	TokenField = "signalith_token"
	// TokenIDField is that token's ID.
	TokenIDField = "signalith_token_id"
	// SenderField is the address that sent the event, without a port:
	// the client behind a trusted reverse proxy, not the proxy.
	SenderField = "signalith_sender"
	// TokenPurposeField is what that agent token was made for (linux,
	// windows, otel, osquery, sensor), when it was made for one. What
	// only a network sensor may say (the hosts of the asset list it
	// discovered) is believed only with purpose sensor, so another
	// agent's token cannot claim to be a sensor by naming a Zeek log.
	TokenPurposeField = "signalith_token_purpose"
	// ReceivedField is when an event arrived, on each event filed under
	// a time the sender gave it (see Event.Received), as Splunk's
	// _indextime: a sender may date its events up to ingest.max_event_age
	// back or an hour ahead, and this tells that time from the arrival.
	ReceivedField = "signalith_received"
)

// Intakes, the values of IntakeField.
const (
	IntakeAgent   = "agent"
	IntakeOTLP    = "otlp"
	IntakeHEC     = "hec"
	IntakeOsquery = "osquery"
	IntakeSyslog  = "syslog"
	IntakeScanner = "scanner"
	// IntakeSignalith is what Signalith writes about itself, such as a
	// silent network sensor's event.
	IntakeSignalith = "signalith"
)

// Origin is where events came from: how they arrived, the agent token
// they came with and the address that sent them. Empty parts are not
// recorded.
type Origin struct {
	Intake    string
	TokenID   string
	TokenName string
	Sender    string
	// Purpose is the agent token's purpose; empty for a shared token.
	Purpose string
	// Host is the enrolled computer whose own key sent the events (see
	// agenttokens.Identity.Host); "" when a token sent them.
	Host string
}

// IsZero reports whether o says nothing.
func (o Origin) IsZero() bool { return o == Origin{} }

type originKey struct{}

// WithOrigin returns ctx with the origin of the events a request carries.
// The pipeline records it on every event written with ctx that has no
// Origin of its own.
func WithOrigin(ctx context.Context, o Origin) context.Context {
	return context.WithValue(ctx, originKey{}, o)
}

// OriginFrom returns the origin WithOrigin put in ctx.
func OriginFrom(ctx context.Context) Origin {
	o, _ := ctx.Value(originKey{}).(Origin)
	return o
}

// stamp writes o into an event's fields.
func (o Origin) stamp(f map[string]any) {
	for k, v := range map[string]string{IntakeField: o.Intake, TokenField: o.TokenName, TokenIDField: o.TokenID, SenderField: o.Sender, TokenPurposeField: o.Purpose} {
		if v != "" {
			f[k] = v
		}
	}
}

// HostMismatch ends TokenField on an event whose host is not the computer
// that sent it: one sent with a computer's own key that names another
// host, or one sent with a token (not a computer's key) that names a
// computer that has a key of its own (ING-03). The event is stored as
// sent; the mark says its host is the sender's word, not proven:
// signalith_token="*(host mismatch)" finds them. The known-field budget
// is spent, so the mark reuses TokenField instead of a field of its own.
const HostMismatch = " (host mismatch)"

type enrolledKey struct{}

// WithEnrolled returns ctx with how to tell whether a computer has a key
// of its own, for HostMismatch on events sent with a token.
func WithEnrolled(ctx context.Context, enrolled func(host string) bool) context.Context {
	return context.WithValue(ctx, enrolledKey{}, enrolled)
}

// enrolledFrom returns what WithEnrolled put in ctx, or nil.
func enrolledFrom(ctx context.Context) func(string) bool {
	f, _ := ctx.Value(enrolledKey{}).(func(string) bool)
	return f
}

// cachedEnrolled is enrolled with each name's answer kept, for the events
// of one write, which mostly name the same few hosts. nil stays nil.
func cachedEnrolled(enrolled func(string) bool) func(string) bool {
	if enrolled == nil {
		return nil
	}
	seen := map[string]bool{}
	return func(host string) bool {
		v, ok := seen[host]
		if !ok {
			v = enrolled(host)
			if len(seen) < 1000 {
				seen[host] = v
			}
		}
		return v
	}
}

// stampHost names, in TokenField, the computer whose key sent an event,
// and marks an event whose host is not the computer that sent it (see
// HostMismatch). enrolled may be nil. It runs after stamp.
func (o Origin) stampHost(f map[string]any, enrolled func(string) bool) {
	if o.TokenName == "" {
		return
	}
	host, _ := f["host"].(string)
	host = strings.ToLower(strings.TrimSpace(host))
	switch {
	case o.Host != "":
		v := o.TokenName + " @ " + o.Host
		if host != "" && !sameHost(host, strings.ToLower(o.Host)) {
			v += HostMismatch
		}
		f[TokenField] = v
	case host != "" && enrolled != nil && (enrolled(host) || enrolled(shortHost(host))):
		f[TokenField] = o.TokenName + HostMismatch
	}
}

// sameHost reports whether two lower-case host names are the same
// computer: equal, or one is the other's short name (web-01 and
// web-01.corp.example).
func sameHost(a, b string) bool {
	return a == b || shortHost(a) == b || a == shortHost(b)
}

// shortHost is a host name up to its first dot.
func shortHost(h string) string {
	if i := strings.IndexByte(h, '.'); i > 0 {
		return h[:i]
	}
	return h
}

// reservedNames are the fields Signalith sets on events itself, which a
// sender must not choose: the event time and data model (from where the
// event is filed), and device_time and dropped_fields (what ingest did to
// the event). Every field named signalith, or starting with signalith_
// or signalith., is Signalith's too: the sample-data marker
// (datamodel.SampleField) and the origin fields above, and any added
// later. Names are compared without regard to case, and a dotted name
// counts by its first part (datamodel.x, signalith_sample.y), since
// OpenSearch would store it as an object of that name.
var reservedNames = []string{"@timestamp", "datamodel", "device_time", "dropped_fields"}

// Reserved reports whether a sender may not set the field name.
func Reserved(name string) bool {
	k := strings.ToLower(name)
	if i := strings.IndexByte(k, '.'); i >= 0 {
		if k[:i] == "signalith" {
			return true
		}
		k = k[:i]
	}
	if k == "signalith" || strings.HasPrefix(k, "signalith_") {
		return true
	}
	for _, r := range reservedNames {
		if k == r {
			return true
		}
	}
	return false
}
