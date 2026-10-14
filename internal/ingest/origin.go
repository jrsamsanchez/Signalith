package ingest

import (
	"context"
	"strings"
)

// Fields that record where an event came from. Signalith sets them on
// every event it receives; a sender can never set them (see reserved).
const (
	// IntakeField is how the event arrived: agent (an agent's POST to
	// /api/ingest), otlp, osquery, syslog or scanner (Signalith's own
	// vulnerability scans).
	IntakeField = "signalith_intake"
	// TokenField is the name of the agent token the event came with, as
	// it was then (never the token itself). Renaming the token later
	// leaves stored events as they are.
	TokenField = "signalith_token"
	// TokenIDField is that token's ID.
	TokenIDField = "signalith_token_id"
	// SenderField is the address that sent the event, without a port:
	// the client behind a trusted reverse proxy, not the proxy.
	SenderField = "signalith_sender"
)

// Intakes, the values of IntakeField.
const (
	IntakeAgent   = "agent"
	IntakeOTLP    = "otlp"
	IntakeOsquery = "osquery"
	IntakeSyslog  = "syslog"
	IntakeScanner = "scanner"
)

// Origin is where events came from: how they arrived, the agent token
// they came with and the address that sent them. Empty parts are not
// recorded.
type Origin struct {
	Intake    string
	TokenID   string
	TokenName string
	Sender    string
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
	for k, v := range map[string]string{IntakeField: o.Intake, TokenField: o.TokenName, TokenIDField: o.TokenID, SenderField: o.Sender} {
		if v != "" {
			f[k] = v
		}
	}
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
