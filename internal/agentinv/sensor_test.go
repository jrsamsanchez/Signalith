package agentinv

import (
	"context"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cluster/ostest"
	"github.com/jrsamsanchez/signalith/internal/ingest"
	"github.com/jrsamsanchez/signalith/internal/store"
)

// A sensor's status line stays on its row while its Zeek and Suricata
// batches arrive in between, survives a write to OpenSearch, and across
// servers the line that arrived last wins. A line dated in the future (a
// clock that ran ahead) is kept as dated when it arrived, and does not
// hold its place against the lines after it.
func TestSensorStatusKept(t *testing.T) {
	fos := ostest.New(t)
	c := store.New(store.Config{URL: fos.URL})
	clk := &clock{t: time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)}
	n1, n2 := newInv(c, "n1", clk, pinA), newInv(c, "n2", clk, pinA)
	ctx := context.Background()
	contact := Contact{Name: "nsm-01", Address: "192.0.2.20", Tag: "sensor.status", Intake: "agent", TLS: true, TokenID: "tok1", Events: 1}

	ahead := &ingest.SensorStatus{At: time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC), Interface: "eth1", DropPercent: 0.5}
	contact.Sensor = ahead
	n1.Note(contact)
	n2.Note(contact)
	if s := list(t, n1)[0].Sensor; s == nil || !s.At.Equal(clk.now()) {
		t.Errorf("a line dated 2099 is kept as dated %v: %+v", clk.now(), s)
	}
	// Zeek's batch next: no status line in it.
	clk.add(time.Minute)
	contact.Sensor, contact.Tag, contact.Events = nil, "zeek.conn", 300
	n1.Note(contact)
	// The next line (its clock now fixed, and a minute behind) replaces it.
	clk.add(4 * time.Minute)
	honest := &ingest.SensorStatus{At: clk.now().Add(-time.Minute), Interface: "eth1", DropPercent: 7}
	contact.Sensor, contact.Tag, contact.Events = honest, "sensor.status", 1
	n1.Note(contact)
	n1.FlushNow(ctx)
	n2.FlushNow(ctx)

	agents := list(t, newInv(c, "n3", clk, pinA))
	if len(agents) != 1 {
		t.Fatalf("agents: %+v", agents)
	}
	if s := agents[0].Sensor; s == nil || !s.At.Equal(honest.At) || s.DropPercent != 7 || s.Interface != "eth1" {
		t.Errorf("sensor: %+v", s)
	}
	// An agent that is not a sensor has none.
	n1.Note(Contact{Name: "web-01", Address: "192.0.2.30", Tag: "win.security", Intake: "agent", TokenID: "tok2", Events: 1})
	for _, a := range list(t, n1) {
		if a.Name == "web-01" && a.Sensor != nil {
			t.Errorf("web-01: %+v", a.Sensor)
		}
	}
}
