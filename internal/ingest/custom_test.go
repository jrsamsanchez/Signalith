package ingest

import (
	"context"
	"testing"
	"time"
)

// fakeCustom is a custom parser named "acme": it reads the line as the
// user, drops "header" lines, and panics on "boom".
type fakeCustom struct{}

func (fakeCustom) ParseCustom(name string, r map[string]any, now time.Time) (Event, bool, bool) {
	if name != "acme" {
		return Event{}, false, false
	}
	line, _ := r["log"].(string)
	switch line {
	case "boom":
		panic("crafted record")
	case "header":
		return Event{}, true, true
	}
	return Event{Model: "Authentication", Fields: map[string]any{"user": line, "message": line, "sourcetype": "acme:auth"}}, false, true
}

func TestCustomParsers(t *testing.T) {
	fb := &fakeBulk{}
	p := &Pipeline{Store: fb, Prefix: "sig", Now: func() time.Time { return now }, Custom: fakeCustom{}}
	res, err := p.Ingest(context.Background(), "custom.acme", []map[string]any{
		{"log": "header", "file": "/var/log/acme.log"},
		{"log": "bob", "file": "/var/log/acme.log"},
		{"log": "boom"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Indexed != 2 || len(fb.docs) != 2 {
		t.Fatalf("result %+v, docs %v", res, fb.docs)
	}
	bob := fb.docs[0].Doc
	if bob["user"] != "bob" || bob["datamodel"] != "Authentication" || bob["sourcetype"] != "acme:auth" || bob["source"] != "/var/log/acme.log" {
		t.Errorf("parsed event %v", bob)
	}
	// The record that crashed the parser is stored as the built-in
	// parsers read it.
	if boom := fb.docs[1].Doc; boom["datamodel"] != "Other" || boom["user"] != nil {
		t.Errorf("crashed record %v", boom)
	}

	// A tag no parser has, and records of other tags, are read as before.
	fb.docs = nil
	if _, err := p.Ingest(context.Background(), "custom.other", []map[string]any{{"log": "bob"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Ingest(context.Background(), "app.acme", []map[string]any{{"log": "header"}}); err != nil {
		t.Fatal(err)
	}
	if len(fb.docs) != 2 || fb.docs[0].Doc["user"] != nil || fb.docs[1].Doc["message"] != "header" {
		t.Errorf("other tags %v", fb.docs)
	}

	// A batch of only dropped lines stores nothing.
	fb.docs = nil
	if res, err := p.Ingest(context.Background(), "custom.acme", []map[string]any{{"log": "header"}}); err != nil || res.Indexed != 0 || len(fb.docs) != 0 {
		t.Errorf("header only: %+v %v %v", res, err, fb.docs)
	}
}
