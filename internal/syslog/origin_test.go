package syslog

import (
	"context"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/datamodel"
	"github.com/jrsamsanchez/signalith/internal/ingest"
)

// TestSyslogOrigin: syslog events record how they arrived and the device
// that sent them, no token, and a CEF extension can't set the sample-data
// marker or any other field only Signalith sets.
func TestSyslogOrigin(t *testing.T) {
	m := Parse([]byte(`<134>CEF:0|Acme|FW|1.0|100|blocked|5|src=10.0.0.1 signalith_sample=x signalith_token=forged`), now)
	ev := m.Event(sender, now, 0)
	if ev.Origin != (ingest.Origin{Intake: ingest.IntakeSyslog, Sender: "192.0.2.50"}) {
		t.Fatalf("origin = %+v", ev.Origin)
	}
	c := &capture{}
	p := &ingest.Pipeline{Store: c, Prefix: "sig"}
	if _, err := p.IngestEvents(context.Background(), []ingest.Event{ev}); err != nil {
		t.Fatal(err)
	}
	doc := c.all()[0].Doc
	// CEF keeps unknown extensions under cef_, out of Signalith's names.
	if doc["cef_signalith_sample"] != "x" {
		t.Errorf("doc = %v", doc)
	}
	if doc[ingest.IntakeField] != "syslog" || doc[ingest.SenderField] != "192.0.2.50" {
		t.Errorf("doc = %v", doc)
	}
	for _, k := range []string{datamodel.SampleField, ingest.TokenField, ingest.TokenIDField} {
		if _, ok := doc[k]; ok {
			t.Errorf("%s = %v", k, doc[k])
		}
	}
}
