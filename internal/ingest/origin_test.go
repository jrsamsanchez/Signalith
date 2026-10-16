package ingest

import (
	"context"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/datamodel"
)

func TestReserved(t *testing.T) {
	for _, k := range []string{"@timestamp", "datamodel", "device_time", "dropped_fields", "signalith_sample", "Signalith_Sample",
		"SIGNALITH_TOKEN", "signalith", "signalith.x", "signalith_token_id", "signalith_sender", "signalith_intake",
		"signalith_future", "datamodel.x", "signalith_sample.y", "Device_Time", "@Timestamp.a"} {
		if !Reserved(k) {
			t.Errorf("%s is not reserved", k)
		}
	}
	for _, k := range []string{"user", "signalithx", "my_signalith_sample", "src", "message", "data_model", "host"} {
		if Reserved(k) {
			t.Errorf("%s is reserved", k)
		}
	}
}

var forged = map[string]any{
	"signalith_sample": "x", "Signalith_Sample": "y", "signalith.x": "z", "signalith_token": "Admins",
	"signalith_sender": "10.0.0.1", "signalith_intake": "syslog", "signalith_token_id": "000000000000", "datamodel.x": "w",
}

// TestSendersCannotSetOriginFields: on every intake, every field only
// Signalith sets is dropped and counted, and the origin of the request is
// recorded instead.
func TestSendersCannotSetOriginFields(t *testing.T) {
	o := Origin{Intake: IntakeAgent, TokenID: "3f9c0a1b2c4d", TokenName: "Linux servers", Sender: "203.0.113.7"}
	want := map[string]any{IntakeField: "agent", TokenField: "Linux servers", TokenIDField: "3f9c0a1b2c4d", SenderField: "203.0.113.7",
		"dropped_fields": int64(len(forged))}
	check := func(name string, doc map[string]any) {
		t.Helper()
		expect(t, doc, want)
		for k := range forged {
			if _, ok := doc[k]; ok && !KnownField(k) {
				t.Errorf("%s: %s kept: %v", name, k, doc)
			}
		}
		if _, ok := doc[datamodel.SampleField]; ok {
			t.Errorf("%s: sample marker kept", name)
		}
	}
	ctx := WithOrigin(context.Background(), o)

	fb := &fakeBulk{}
	p := &Pipeline{Store: fb, Prefix: "sig", Now: func() time.Time { return now }}
	rec := map[string]any{"msg": "hello"}
	for k, v := range forged {
		rec[k] = v
	}
	if _, err := p.Ingest(ctx, "app.custom", []map[string]any{rec}); err != nil {
		t.Fatal(err)
	}
	check("Ingest", fb.docs[0].Doc)

	fb = &fakeBulk{}
	p = &Pipeline{Store: fb, Prefix: "sig", Now: func() time.Time { return now }}
	body := `[{"msg":"hello","signalith_sample":"x","Signalith_Sample":"y","signalith.x":"z","signalith_token":"Admins",` +
		`"signalith_sender":"10.0.0.1","signalith_intake":"syslog","signalith_token_id":"000000000000","datamodel.x":"w"}]`
	res, err := p.IngestBody(ctx, "app.custom", []byte(body))
	if err != nil || res.Indexed != 1 || res.FieldsDropped != len(forged) {
		t.Fatalf("IngestBody: %+v %v", res, err)
	}
	check("IngestBody", fb.docs[0].Doc)

	fb = &fakeBulk{}
	p = &Pipeline{Store: fb, Prefix: "sig", Now: func() time.Time { return now }}
	f := map[string]any{"msg": "hello"}
	for k, v := range forged {
		f[k] = v
	}
	if _, err := p.IngestEvents(ctx, []Event{{Fields: f}}); err != nil {
		t.Fatal(err)
	}
	check("IngestEvents", fb.docs[0].Doc)
}

// TestOTLPAttributesCannotSetOriginFields: an OTLP attribute or resource
// attribute named signalith.* or signalith_* is dropped.
func TestOTLPAttributesCannotSetOriginFields(t *testing.T) {
	o := Origin{Intake: IntakeOTLP, TokenID: "abcdefabcdef", TokenName: "Collector", Sender: "198.51.100.2"}
	rs := tRes{attrs: []tKV{{"host.name", "web1"}, {"signalith.sample", "r"}, {"signalith_token", "forged"}},
		recs: []tRec{{time: uint64(now.UnixNano()), body: "hello", attrs: []tKV{{"signalith.token", "forged"}, {"signalith_sample", "a"}, {"Signalith.Sender", "1.1.1.1"}}}}}
	for _, isJSON := range []bool{false, true} {
		fb := &fakeBulk{}
		p := &Pipeline{Store: fb, Prefix: "sig", Now: func() time.Time { return now }}
		body := encodeProto(rs)
		if isJSON {
			body = encodeJSON(rs)
		}
		res, err := p.IngestOTLP(WithOrigin(context.Background(), o), body, isJSON)
		if err != nil || res.Indexed != 1 {
			t.Fatalf("json=%v: %+v %v", isJSON, res, err)
		}
		doc := fb.docs[0].Doc
		expect(t, doc, map[string]any{IntakeField: "otlp", TokenField: "Collector", TokenIDField: "abcdefabcdef", SenderField: "198.51.100.2"})
		if _, ok := doc[datamodel.SampleField]; ok {
			t.Errorf("json=%v: marker kept: %v", isJSON, doc)
		}
		if n, _ := doc["dropped_fields"].(int64); n == 0 {
			t.Errorf("json=%v: nothing counted as dropped: %v", isJSON, doc)
		}
		for k := range doc {
			if Reserved(k) && !KnownField(k) {
				t.Errorf("json=%v: %s kept", isJSON, k)
			}
		}
	}
}

// TestEventOriginBeatsContext: an event's own origin (syslog) wins over
// the request's.
func TestEventOriginBeatsContext(t *testing.T) {
	fb := &fakeBulk{}
	p := &Pipeline{Store: fb, Prefix: "sig", Now: func() time.Time { return now }}
	ctx := WithOrigin(context.Background(), Origin{Intake: IntakeAgent, TokenName: "x", TokenID: "y", Sender: "1.2.3.4"})
	_, err := p.IngestEvents(ctx, []Event{
		{Fields: map[string]any{"msg": "a"}, Origin: Origin{Intake: IntakeSyslog, Sender: "192.0.2.1"}},
		{Fields: map[string]any{"msg": "b"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	expect(t, fb.docs[0].Doc, map[string]any{IntakeField: "syslog", SenderField: "192.0.2.1", TokenField: nil, TokenIDField: nil})
	expect(t, fb.docs[1].Doc, map[string]any{IntakeField: "agent", SenderField: "1.2.3.4", TokenField: "x", TokenIDField: "y"})
}

// TestNoOriginNoStamp: without an origin nothing is recorded, and the
// sample-data pipeline records none.
func TestNoOriginNoStamp(t *testing.T) {
	fb := &fakeBulk{}
	p := &Pipeline{Store: fb, Prefix: "sig", Now: func() time.Time { return now }}
	if _, err := p.IngestEvents(context.Background(), []Event{{Fields: map[string]any{"msg": "a"}}}); err != nil {
		t.Fatal(err)
	}
	fb2 := &fakeBulk{}
	sp := &Pipeline{Store: fb2, Prefix: "sig", Now: func() time.Time { return now }, SampleMark: "sample-1"}
	ctx := WithOrigin(context.Background(), Origin{Intake: IntakeAgent, TokenName: "x"})
	if _, err := sp.IngestEvents(ctx, []Event{{Fields: map[string]any{"msg": "a", datamodel.SampleField: "gen"}}}); err != nil {
		t.Fatal(err)
	}
	for _, d := range []map[string]any{fb.docs[0].Doc, fb2.docs[0].Doc} {
		for _, k := range []string{IntakeField, TokenField, TokenIDField, SenderField} {
			if _, ok := d[k]; ok {
				t.Errorf("%s recorded: %v", k, d)
			}
		}
	}
	expect(t, fb2.docs[0].Doc, map[string]any{datamodel.SampleField: "sample-1"})
	if _, ok := fb2.docs[0].Doc["dropped_fields"]; ok {
		t.Errorf("sample marker counted as dropped")
	}
}

// TestOriginSurvivesKnownOnlyRetry: the origin fields are known, so the
// retry with only known fields keeps them.
func TestOriginSurvivesKnownOnlyRetry(t *testing.T) {
	f := map[string]any{"junk": 1}
	Origin{Intake: IntakeAgent, TokenName: "n", TokenID: "i", Sender: "s"}.stamp(f)
	onlyKnown(f)
	for _, k := range []string{IntakeField, TokenField, TokenIDField, SenderField} {
		if f[k] == nil {
			t.Errorf("%s lost", k)
		}
	}
}
