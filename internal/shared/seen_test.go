package shared

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// A server's own settings count their revisions across resets, so a page
// that read a value before a reset never names a revision saved after it.
func TestNodeCfgRevisions(t *testing.T) {
	var n NodeCfg
	if n.ValueRev("search.max_events") != 0 {
		t.Error("a revision for a value never set")
	}
	if n.ResetValue("search.max_events", From{Source: "page"}) != 0 {
		t.Error("a reset of a value at its default")
	}
	at := time.Now().UTC().Add(-time.Hour)
	if rev := n.SetValue("search.max_events", PageValue{Value: json.RawMessage(`500`), From: From{Source: "page", By: "sam", At: at}}); rev != 1 {
		t.Errorf("first set at rev %d", rev)
	}
	if rev := n.SetValue("search.max_events", PageValue{Value: json.RawMessage(`600`), From: From{Source: "page", By: "bob"}}); rev != 2 {
		t.Errorf("second set at rev %d", rev)
	}
	if f := n.ValueFrom("search.max_events"); f.By != "bob" {
		t.Errorf("from %+v", f)
	}
	rev := n.ResetValue("search.max_events", From{Source: "page", By: "ann"})
	if rev != 3 || n.ValueRev("search.max_events") != 3 || n.ValueFrom("search.max_events").By != "ann" {
		t.Errorf("reset at %d, rev %d, from %+v", rev, n.ValueRev("search.max_events"), n.ValueFrom("search.max_events"))
	}
	if _, ok := n.Values["search.max_events"]; ok {
		t.Error("the value is kept after its reset")
	}
	if rev := n.SetValue("search.max_events", PageValue{Value: json.RawMessage(`700`)}); rev != 4 {
		t.Errorf("set after the reset at rev %d", rev)
	}
	if _, ok := n.Reset["search.max_events"]; ok {
		t.Error("the reset mark is kept after a new value")
	}
}

// The marks and values keep fields a later version adds.
func TestSeenTypesKeepUnknownFields(t *testing.T) {
	check := func(name string, in string, v any, marshal func() ([]byte, error)) {
		t.Helper()
		if err := json.Unmarshal([]byte(in), v); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		out, err := marshal()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !strings.Contains(string(out), `"later":{"x":1}`) {
			t.Errorf("%s lost the unknown field: %s", name, out)
		}
	}
	var m ResetMark
	check("ResetMark", `{"rev":3,"from":{"source":"page"},"later":{"x":1}}`, &m, func() ([]byte, error) { return json.Marshal(m) })
	if m.Rev != 3 || m.From.Source != "page" {
		t.Errorf("ResetMark = %+v", m)
	}
	var r Refusal
	check("Refusal", `{"hash":"h","reason":"bad","later":{"x":1}}`, &r, func() ([]byte, error) { return json.Marshal(r) })
	if r.Hash != "h" || r.Reason != "bad" {
		t.Errorf("Refusal = %+v", r)
	}
	var p PageValue
	check("PageValue", `{"value":5,"rev":2,"from":{"source":"yaml"},"later":{"x":1}}`, &p, func() ([]byte, error) { return json.Marshal(p) })
	if string(p.Value) != "5" || p.Rev != 2 {
		t.Errorf("PageValue = %+v", p)
	}
	var bad ResetMark
	if err := json.Unmarshal([]byte(`{"rev":"not a number"}`), &bad); err == nil {
		t.Error("a ResetMark with a bad rev was read")
	}
}
