// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package ingest

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/store"
)

// Regression tests for the ingest findings of the 2026-11-12 red team
// (ING-02 to ING-09).

// The events a record is split into count against MaxRecords one by one,
// and a request over it is refused before anything is written (ING-02).
func TestOTLPSplitEventsCountAgainstMaxRecords(t *testing.T) {
	// Each message stays under MaxRecordBytes; together they hold more
	// than MaxRecords records.
	const per = 12000 // under 1 MB in JSON too, where its quotes are escaped
	msg := azureMessage(per)
	if len(msg) > MaxRecordBytes {
		t.Fatalf("the message is %d bytes", len(msg))
	}
	req := tRes{recs: make([]tRec, MaxRecords/per+1)}
	for i := range req.recs {
		req.recs[i] = tRec{body: msg}
	}
	for _, isJSON := range []bool{false, true} {
		body := encodeProto(req)
		if isJSON {
			body = encodeJSON(req)
		}
		b := &sizedBulk{}
		p := &Pipeline{Store: b, Now: func() time.Time { return now }}
		_, err := p.IngestOTLP(context.Background(), body, isJSON)
		var bad *BodyError
		if !errors.As(err, &bad) || bad.Status != http.StatusRequestEntityTooLarge || !strings.Contains(bad.Msg, "log records") {
			t.Fatalf("json=%v: err = %v", isJSON, err)
		}
		if b.calls != 0 {
			t.Errorf("json=%v: %d bulk requests were written for a refused request", isJSON, b.calls)
		}
	}
}

// failAfterBulk takes its first ok bulk requests and fails the rest.
type failAfterBulk struct {
	ok, calls int
}

func (b *failAfterBulk) Bulk(_ context.Context, docs []store.IndexedDoc) ([]store.BulkItemError, error) {
	b.calls++
	if b.calls > b.ok {
		return nil, errors.New("opensearch is down")
	}
	return nil, nil
}

// When OpenSearch fails part way, what was stored comes back with the
// error, so the handler credits the token with it (ING-02).
func TestPartialWriteIsReturned(t *testing.T) {
	recs := make([]tRec, batchEvents+10)
	for i := range recs {
		recs[i] = tRec{body: "line"}
	}
	p := &Pipeline{Store: &failAfterBulk{ok: 1}, Now: func() time.Time { return now }}
	res, err := p.IngestOTLP(context.Background(), encodeProto(tRes{recs: recs}), false)
	if err == nil || res == nil || res.Indexed != batchEvents {
		t.Fatalf("OTLP: res %+v err %v", res, err)
	}
	lines := strings.Repeat(`{"message":"line"}`+"\n", batchEvents+10)
	p = &Pipeline{Store: &failAfterBulk{ok: 1}, Now: func() time.Time { return now }}
	res, err = p.IngestBody(context.Background(), "app", []byte(lines))
	if err == nil || res == nil || res.Indexed != batchEvents {
		t.Fatalf("body: res %+v err %v", res, err)
	}
}

// A Google Cloud entry's ID covers the whole entry, so another entry with
// the same log name, insertId and time is not taken for it (ING-06).
func TestGCPIDCoversTheEntry(t *testing.T) {
	a := ParseGCP(decode(t, gcpFirewallDelete))
	again := ParseGCP(decode(t, gcpFirewallDelete))
	forged := ParseGCP(decode(t, strings.Replace(gcpFirewallDelete, "alice@example.com", "mallory@example.com", 1)))
	if a.ID == "" || a.ID != again.ID {
		t.Fatalf("the same entry has IDs %q and %q", a.ID, again.ID)
	}
	if forged.ID == a.ID {
		t.Error("an entry with another body took the real entry's ID")
	}
}

// The same body from two agent tokens gives two sets of document IDs on
// /api/ingest, as on OTLP (ING-06).
func TestIngestBodyIDsDependOnToken(t *testing.T) {
	body := []byte(`{"message":"same"}`)
	b := &idBulk{}
	p := &Pipeline{Store: b, Now: func() time.Time { return now }}
	for _, tok := range []string{"tok-a", "tok-b"} {
		ctx := WithOrigin(context.Background(), Origin{Intake: IntakeAgent, TokenID: tok})
		res, err := p.IngestBody(ctx, "app", body)
		if err != nil || res.Indexed != 1 || res.Duplicates != 0 {
			t.Fatalf("%s: %+v %v", tok, res, err)
		}
	}
	if len(b.ids) != 2 || b.ids[0] == b.ids[1] {
		t.Errorf("ids = %q", b.ids)
	}
}

// A field typed as a number by its first value is reported, once, when
// another sender's text cannot be indexed under it (ING-07).
func TestFieldTypeClashIsReported(t *testing.T) {
	var b fieldBudget
	const ix, day = "sig-other-2026.10.11", "2026.10.11"
	b.limitTo(ix, day, "", "token:first", map[string]any{"foo": int64(1), "bar": "text"}, 1000, false)
	b.limitTo(ix, day, "", "token:other", map[string]any{"foo": "12", "bar": int64(3)}, 1000, false)
	if c := b.takeClashes(); len(c) != 0 {
		t.Fatalf("values that fit were reported: %+v", c)
	}
	f := map[string]any{"foo": "not a number"}
	if n := b.limitTo(ix, day, "", "token:other", f, 1000, false); n != 0 || f["foo"] == nil {
		t.Fatalf("the value was dropped (%d): %v", n, f)
	}
	b.limitTo(ix, day, "", "token:third", map[string]any{"foo": "again"}, 1000, false)
	c := b.takeClashes()
	if len(c) != 1 || c[0] != (TypeClash{Index: ix, Field: "foo", First: "token:first", Sender: "token:other"}) {
		t.Fatalf("clashes = %+v", c)
	}
}

// A record of many tiny values is rejected on its own before it is
// decoded (ING-08).
func TestOTLPJSONCapsValuesPerRecord(t *testing.T) {
	// {} is an AnyValue with nothing set: 3 bytes each.
	tiny := strings.TrimSuffix(strings.Repeat("{},", maxJSONRecordNodes), ",")
	body := []byte(`{"resourceLogs":[{"scopeLogs":[{"logRecords":[{"body":{"arrayValue":{"values":[` + tiny +
		`]}}},{"body":{"stringValue":"fine"}}]}]}]}`)
	p := &Pipeline{Store: &fakeBulk{}, Now: func() time.Time { return now }}
	res, err := p.IngestOTLP(context.Background(), body, true)
	if err != nil || res.Rejected != 1 || res.Indexed != 1 || !strings.Contains(res.Errors[0].Reason, "values") {
		t.Fatalf("res %+v err %v", res, err)
	}
	if n := jsonNodes([]byte(`{"a":"x,{[","b":[1,2,{}]}`)); n != 6 {
		t.Errorf("jsonNodes = %d, want 6", n)
	}
}

// Azure and CloudTrail text bodies are checked for depth like the other
// text bodies (ING-09).
func TestTextBodiesCheckDepth(t *testing.T) {
	deep := strings.Repeat(`{"a":`, MaxDepth+5) + "1" + strings.Repeat("}", MaxDepth+5)
	azure := `{"records":[{"time":1,"category":1,"operationName":1,"tenantId":1,"properties":` + deep + `}]}`
	if AzureRecords([]byte(azure)) != nil {
		t.Error("a deeply nested Azure message was decoded")
	}
	if AzureRecords([]byte(azureMessage(2))) == nil {
		t.Error("a plain Azure message was not decoded")
	}
	trail := `{"eventVersion":"1.08","eventSource":"s3.amazonaws.com","eventName":"GetObject","awsRegion":"us-east-1","eventTime":"2026-10-11T11:00:00Z","requestParameters":` + deep + `}`
	if cloudTrailText(trail) != nil {
		t.Error("a deeply nested CloudTrail record was decoded")
	}
}

// Events sent with a computer's own key name the computer, and events
// whose host is not the computer that sent them are marked (ING-03).
func TestHostMismatchMarked(t *testing.T) {
	enrolled := func(h string) bool { return h == "dc-01" }
	for _, tc := range []struct {
		name string
		o    Origin
		host any
		want string
	}{
		{"key, own host", Origin{TokenName: "Line", Host: "web-01"}, "WEB-01", "Line @ web-01"},
		{"key, own FQDN", Origin{TokenName: "Line", Host: "web-01"}, "web-01.corp.example", "Line @ web-01"},
		{"key, no host", Origin{TokenName: "Line", Host: "web-01"}, nil, "Line @ web-01"},
		{"key, other host", Origin{TokenName: "Line", Host: "web-01"}, "dc-01", "Line @ web-01" + HostMismatch},
		{"token, enrolled host", Origin{TokenName: "Line"}, "dc-01.corp.example", "Line" + HostMismatch},
		{"token, other host", Origin{TokenName: "Line"}, "web-02", "Line"},
	} {
		f := map[string]any{}
		if tc.host != nil {
			f["host"] = tc.host
		}
		tc.o.stamp(f)
		tc.o.stampHost(f, enrolled)
		if f[TokenField] != tc.want {
			t.Errorf("%s: %s = %v, want %q", tc.name, TokenField, f[TokenField], tc.want)
		}
	}

	// Through the pipeline, with the check from the request's context.
	fb := &fakeBulk{}
	p := &Pipeline{Store: fb, Now: func() time.Time { return now }}
	ctx := WithEnrolled(WithOrigin(context.Background(), Origin{Intake: IntakeAgent, TokenID: "t1", TokenName: "Line"}), enrolled)
	if _, err := p.IngestBody(ctx, "app", []byte(`{"host":"dc-01","message":"x"}`+"\n"+`{"host":"web-02","message":"y"}`)); err != nil {
		t.Fatal(err)
	}
	if len(fb.docs) != 2 || fb.docs[0].Doc[TokenField] != "Line"+HostMismatch || fb.docs[1].Doc[TokenField] != "Line" {
		t.Fatalf("docs = %+v", fb.docs)
	}
}
