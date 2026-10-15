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
// servers the newest line wins.
func TestSensorStatusKept(t *testing.T) {
	fos := ostest.New(t)
	c := store.New(store.Config{URL: fos.URL})
	clk := &clock{t: time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)}
	n1, n2 := newInv(c, "n1", clk, pinA), newInv(c, "n2", clk, pinA)
	ctx := context.Background()
	contact := Contact{Name: "nsm-01", Address: "192.0.2.20", Tag: "sensor.status", Intake: "agent", TLS: true, TokenID: "tok1", Events: 1}

	older := &ingest.SensorStatus{At: clk.now().Add(-5 * time.Minute), Interface: "eth1", DropPercent: 0.5}
	newer := &ingest.SensorStatus{At: clk.now(), Interface: "eth1", DropPercent: 7}
	contact.Sensor = newer
	n1.Note(contact)
	// Zeek's batch next: no status line in it.
	contact.Sensor, contact.Tag, contact.Events = nil, "zeek.conn", 300
	n1.Note(contact)
	// An older line reaching n1 late does not replace the newer one.
	contact.Sensor, contact.Tag = older, "sensor.status"
	n1.Note(contact)
	// n2 got only the older one.
	n2.Note(contact)
	n1.FlushNow(ctx)
	n2.FlushNow(ctx)

	agents := list(t, newInv(c, "n3", clk, pinA))
	if len(agents) != 1 {
		t.Fatalf("agents: %+v", agents)
	}
	if s := agents[0].Sensor; s == nil || !s.At.Equal(newer.At) || s.DropPercent != 7 || s.Interface != "eth1" {
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
