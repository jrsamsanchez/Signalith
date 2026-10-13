package ingest

import (
	"context"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/datamodel"
)

// TestSenderCannotMarkSampleData: an event a sender marks as sample data
// is stored without the marker, so live detections still see it and
// removing the sample data does not delete it. The event itself is kept,
// and the field it lost is counted like any other left out.
func TestSenderCannotMarkSampleData(t *testing.T) {
	fb := &fakeBulk{}
	p := &Pipeline{Store: fb, Prefix: "sig", Now: func() time.Time { return now }}
	body := `[{"date": 1791720000, "user": "svc-backup", "action": "failure", "app": "vpn", "src": "203.0.113.9", "signalith_sample": "x"}]`
	res, err := p.IngestBody(context.Background(), "app.vpn", []byte(body))
	if err != nil || res.Indexed != 1 || res.FieldsDropped != 1 {
		t.Fatalf("res = %+v, err = %v; want the event stored with one field left out", res, err)
	}
	doc := fb.docs[0].Doc
	if _, ok := doc[datamodel.SampleField]; ok {
		t.Errorf("the sender's sample marker was stored: %v", doc)
	}
	expect(t, doc, map[string]any{"user": "svc-backup", "src": "203.0.113.9", "dropped_fields": int64(1)})
	if s := p.Stats(); s.FieldsDropped != 1 {
		t.Errorf("stats = %+v", s)
	}
}

// TestReservedFieldsComeFromSignalith: a sender cannot set the event time,
// data model, device_time or dropped_fields with fields of those names:
// they always say what Signalith did with the event.
func TestReservedFieldsComeFromSignalith(t *testing.T) {
	fb := &fakeBulk{}
	p := &Pipeline{Store: fb, Prefix: "sig", Now: func() time.Time { return now }}
	body := `[{"date": 1791716400, "@timestamp": "1999-01-01T00:00:00Z", "datamodel": "Risk", "device_time": "forged",
		"dropped_fields": "none", "signalith_sample": "sample-20261011-110000", "msg": "hello"}]`
	res, err := p.IngestBody(context.Background(), "app.custom", []byte(body))
	if err != nil || res.Indexed != 1 {
		t.Fatalf("res = %+v, err = %v", res, err)
	}
	d := fb.docs[0]
	if d.Index != "sig-other-2026.10.11" {
		t.Errorf("index = %s", d.Index)
	}
	// The record's date is its time; datamodel, device_time,
	// dropped_fields and the marker were left out (4 fields).
	expect(t, d.Doc, map[string]any{"@timestamp": "2026-10-11T11:00:00Z", "datamodel": "Other", "msg": "hello", "dropped_fields": int64(4)})
	for _, k := range []string{"device_time", datamodel.SampleField} {
		if v, ok := d.Doc[k]; ok {
			t.Errorf("%s = %v, want it left out", k, v)
		}
	}
	if res.FieldsDropped != 4 {
		t.Errorf("fields dropped = %d, want 4", res.FieldsDropped)
	}
}

// TestJSONTimestampIsTheEventTime: a JSON record with no date (a script, or
// another log shipper) has its @timestamp as its time, within the same
// window as every event time: one too old is filed under the time it
// arrived, with its own time in device_time.
func TestJSONTimestampIsTheEventTime(t *testing.T) {
	fb := &fakeBulk{}
	p := &Pipeline{Store: fb, Prefix: "sig", Now: func() time.Time { return now }}
	body := `[{"@timestamp": "2026-10-11T10:30:00Z", "msg": "recent"}, {"@timestamp": "2020-01-01T00:00:00Z", "msg": "too old"}]`
	res, err := p.IngestBody(context.Background(), "app.custom", []byte(body))
	if err != nil || res.Indexed != 2 || res.FieldsDropped != 0 {
		t.Fatalf("res = %+v, err = %v", res, err)
	}
	expect(t, fb.docs[0].Doc, map[string]any{"@timestamp": "2026-10-11T10:30:00Z", "msg": "recent"})
	expect(t, fb.docs[1].Doc, map[string]any{"@timestamp": "2026-10-11T12:00:00Z", "device_time": "2020-01-01T00:00:00Z", "msg": "too old"})
	if fb.docs[1].Index != "sig-other-2026.10.11" {
		t.Errorf("an old event went to %s", fb.docs[1].Index)
	}
	for _, d := range fb.docs {
		if _, ok := d.Doc["dropped_fields"]; ok {
			t.Errorf("the time a record gives is not a field left out: %v", d.Doc)
		}
	}
}

// TestEventsCannotCarryReservedFields: events that are already normalized
// (the syslog receiver, or anything else that calls IngestEvents) lose
// reserved fields too. Only the sample-data loader's pipeline marks
// events, with its own load's ID whatever the event says.
func TestEventsCannotCarryReservedFields(t *testing.T) {
	fb := &fakeBulk{}
	p := &Pipeline{Store: fb, Prefix: "sig", Now: func() time.Time { return now }}
	ev := Event{Time: now, Model: "Authentication", Fields: map[string]any{
		"user": "bob", datamodel.SampleField: "sample-x", "datamodel": "Risk", "@timestamp": "1999-01-01T00:00:00Z"}}
	if _, err := p.IngestEvents(context.Background(), []Event{ev}); err != nil {
		t.Fatal(err)
	}
	doc := fb.docs[0].Doc
	expect(t, doc, map[string]any{"user": "bob", "datamodel": "Authentication", "@timestamp": "2026-10-11T12:00:00Z", "dropped_fields": int64(3)})
	if _, ok := doc[datamodel.SampleField]; ok {
		t.Errorf("an event kept a sample marker: %v", doc)
	}

	sample := &Pipeline{Store: fb, Prefix: "sig", Now: func() time.Time { return now }, SampleMark: "sample-20261011-120000"}
	evs := []Event{
		{Time: now, Model: "Authentication", Fields: map[string]any{"user": "alice", datamodel.SampleField: "sample-20261011-120000"}},
		{Time: now, Model: "Other", Fields: map[string]any{"user": "carol", datamodel.SampleField: "something-else"}},
		{Time: now, Model: "Other", Fields: map[string]any{"user": "dan"}},
	}
	res, err := sample.IngestEvents(context.Background(), evs)
	if err != nil || res.Indexed != 3 || res.FieldsDropped != 0 {
		t.Fatalf("res = %+v, err = %v", res, err)
	}
	for _, d := range fb.docs[1:] {
		if d.Doc[datamodel.SampleField] != "sample-20261011-120000" || d.Doc["dropped_fields"] != nil {
			t.Errorf("sample event = %v, want it marked with the load's ID and nothing left out", d.Doc)
		}
	}
}

// TestDocumentTakesTimeAndModelFromEvent: whatever an event's fields hold,
// its document's time, data model and device time are the event's own.
func TestDocumentTakesTimeAndModelFromEvent(t *testing.T) {
	ev := Event{Time: now, Model: "Endpoint", Fields: map[string]any{
		"@timestamp": "1999-01-01T00:00:00Z", "datamodel": "Risk", "device_time": "forged", "user": "bob"}}
	doc := ev.Document()
	expect(t, doc, map[string]any{"@timestamp": "2026-10-11T12:00:00Z", "datamodel": "Endpoint", "user": "bob"})
	if _, ok := doc["device_time"]; ok {
		t.Errorf("device_time = %v, want none", doc["device_time"])
	}
}
