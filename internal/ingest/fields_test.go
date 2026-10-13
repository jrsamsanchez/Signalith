package ingest

import (
	"context"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/store"
)

func TestValidFieldName(t *testing.T) {
	for name, want := range map[string]bool{
		"level":                      true,
		"http.status":                true,
		"kubernetes.labels.app-name": true,
		"@version":                   true,
		"user_name":                  true,
		"ns:attr":                    true,
		"größe":                      true,
		"a.b.c.d.e":                  true,
		"a.b.c.d.e.f":                false, // too deep
		strings.Repeat("a", 128):     true,
		strings.Repeat("a", 129):     false,
		"":                           false,
		"_id":                        false,
		"_source":                    false,
		".hidden":                    false,
		"a..b":                       false,
		"a.":                         false,
		"a b":                        false,
		"a*":                         false,
		"a\"b":                       false,
		"a\x00b":                     false,
		"a.-b":                       false,
		"\xff":                       false,
	} {
		if got := validFieldName(name); got != want {
			t.Errorf("validFieldName(%.40q) = %v, want %v", name, got, want)
		}
	}
}

// TestJunkFieldsCannotSinkEvents reproduces injection-ingest-mapping-explosion-dos
// and dos-4: generic JSON records with thousands of invented keys used to
// add every key to the day's mapping until OpenSearch refused all new
// fields, legitimate ones included. Now each event keeps at most
// maxFieldsPerEvent fields, each index gains at most maxNewNamesPerIndex
// names, and every dropped field is counted.
func TestJunkFieldsCannotSinkEvents(t *testing.T) {
	b := &countingBulk{keep: true}
	p := &Pipeline{Store: b, Prefix: "sig", Now: func() time.Time { return now }}

	// One event with 5000 keys.
	wide := map[string]any{"user": "alice", "action": "failure"}
	for i := range 5000 {
		wide[fmt.Sprintf("k%04d", i)] = i
	}
	res, err := p.Ingest(context.Background(), "app", []map[string]any{wide})
	if err != nil || res.Indexed != 1 {
		t.Fatalf("res %+v err %v", res, err)
	}
	doc := b.docs[0].Doc
	if len(doc) > maxFieldsPerEvent+3 { // @timestamp, datamodel and dropped_fields are added
		t.Errorf("event kept %d fields", len(doc))
	}
	if doc["user"] != "alice" || doc["action"] != "failure" || doc["message"] == nil {
		t.Errorf("known fields lost: user %v action %v message %v", doc["user"], doc["action"], doc["message"] != nil)
	}
	if !strings.Contains(doc["message"].(string), `"k4999":4999`) {
		t.Error("dropped values should stay in the raw message")
	}
	dropped := doc["dropped_fields"].(int64)
	kept := 0
	for k := range doc {
		if strings.HasPrefix(k, "k") {
			kept++
		}
	}
	if want := 5000 - kept; int(dropped) != want || res.FieldsDropped != want {
		t.Errorf("dropped_fields %d, result %d, want %d", dropped, res.FieldsDropped, want)
	}

	// Many events, each with new names: the index stops gaining names at
	// the budget, while known fields keep landing.
	b.docs = nil
	var recs []map[string]any
	for i := range 100 {
		r := map[string]any{"user": fmt.Sprintf("u%d", i), "src": "192.0.2.1"}
		for j := range 50 {
			r[fmt.Sprintf("junk_%d_%d", i, j)] = "x"
		}
		recs = append(recs, r)
	}
	res, err = p.Ingest(context.Background(), "app", recs)
	if err != nil || res.Indexed != 100 || res.Rejected != 0 {
		t.Fatalf("res %+v err %v", res, err)
	}
	names := map[string]bool{}
	for i, d := range b.docs {
		if d.Doc["user"] != fmt.Sprintf("u%d", i) || d.Doc["src"] != "192.0.2.1" {
			t.Fatalf("doc %d lost known fields", i)
		}
		for k := range d.Doc {
			if !KnownField(k) {
				names[k] = true
			}
		}
	}
	if len(names) > maxNewNamesPerIndex {
		t.Errorf("index gained %d names", len(names))
	}
	if res.FieldsDropped == 0 || p.Stats().FieldsDropped != int64(res.FieldsDropped+int(dropped)) {
		t.Errorf("dropped: result %d, stats %d", res.FieldsDropped, p.Stats().FieldsDropped)
	}

	// Names already in the index cost nothing, so a regular sender's
	// fields keep landing after the budget is spent.
	b.docs = nil
	if _, err := p.Ingest(context.Background(), "app", []map[string]any{{"junk_0_0": "y", "level": "warn"}}); err != nil {
		t.Fatal(err)
	}
	if d := b.docs[0].Doc; d["junk_0_0"] != "y" || d["level"] != nil || d["dropped_fields"] != int64(1) {
		t.Errorf("after budget: %v", d)
	}

	// A different day's index has its own budget.
	b.docs = nil
	next := now.Add(-24 * time.Hour)
	if _, err := p.Ingest(context.Background(), "app", []map[string]any{{"date": float64(next.Unix()), "level": "warn"}}); err != nil {
		t.Fatal(err)
	}
	if d := b.docs[0]; d.Doc["level"] != "warn" || d.Index != "sig-other-2026.10.10" {
		t.Errorf("other day: %s %v", d.Index, d.Doc)
	}
}

func TestFieldNameClashes(t *testing.T) {
	var b fieldBudget
	run := func(f map[string]any) map[string]any {
		b.limit("i", "2026.10.11", "2026.10.01", f)
		return f
	}
	if f := run(map[string]any{"a": 1, "a.b": 2}); f["a"] != 1 || f["a.b"] != nil {
		t.Errorf("value and object in one event: %v", f)
	}
	if f := run(map[string]any{"a.c": 3}); f["a.c"] != nil {
		t.Errorf("object under an existing value: %v", f)
	}
	if f := run(map[string]any{"x.y": 1}); f["x.y"] != 1 {
		t.Errorf("new object: %v", f)
	}
	if f := run(map[string]any{"x": 2}); f["x"] != nil {
		t.Errorf("value where an object exists: %v", f)
	}
	if f := run(map[string]any{"user.name": "bob", "user": "bob"}); f["user.name"] != nil || f["user"] != "bob" {
		t.Errorf("object under a known field: %v", f)
	}
	if f := run(map[string]any{"bad name": 1, "_id": 2, "ok": 3}); len(f) != 1 || f["ok"] != 3 {
		t.Errorf("invalid names: %v", f)
	}
	// Budgets of days no event can reach any more are forgotten.
	b.limit("old", "2026.09.01", "2026.09.01", map[string]any{"z": 1})
	b.limit("new", "2026.10.11", "2026.10.05", map[string]any{"z": 1})
	if _, ok := b.indices["old"]; ok {
		t.Error("old index budget kept")
	}
}

// TestRejectedEventsAreRetriedWithKnownFields covers what the budget
// cannot see: names added before a restart, or a type clash. An event
// OpenSearch turns away because of a field is written again with only the
// fields Signalith produces, so it is never lost to junk.
func TestRejectedEventsAreRetriedWithKnownFields(t *testing.T) {
	b := &countingBulk{keep: true}
	b.reject = func(d store.IndexedDoc) *store.BulkItemError {
		switch {
		case d.Doc["weird"] != nil:
			return &store.BulkItemError{Index: d.Index, Type: "illegal_argument_exception", Reason: "Limit of total fields [2000] has been exceeded"}
		case d.Doc["user"] == "overloaded":
			return &store.BulkItemError{Index: d.Index, Type: "es_rejected_execution_exception", Reason: "queue full"}
		case d.Doc["port"] != nil:
			return &store.BulkItemError{Index: d.Index, Type: "mapper_parsing_exception", Reason: "failed to parse field [port]"}
		}
		return nil
	}
	p := &Pipeline{Store: b, Prefix: "sig", Now: func() time.Time { return now }}
	res, err := p.Ingest(context.Background(), "app", []map[string]any{
		{"user": "a", "weird": "1", "level": "x"},
		{"user": "overloaded"},
		{"user": "c"},
		{"user": "d", "port": "ssh"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Indexed != 3 || res.Rejected != 1 || len(res.Errors) != 1 || res.Errors[0].Pos != 1 {
		t.Fatalf("res %+v", res)
	}
	byUser := map[string]map[string]any{}
	for _, d := range b.docs {
		byUser[d.Doc["user"].(string)] = d.Doc
	}
	if d := byUser["a"]; d == nil || d["weird"] != nil || d["level"] != nil || d["dropped_fields"] != int64(2) || d["message"] == nil {
		t.Errorf("retried doc a: %v", d)
	}
	if d := byUser["d"]; d == nil || d["port"] != nil || d["dropped_fields"] != int64(1) {
		t.Errorf("retried doc d: %v", d)
	}
	if res.FieldsDropped != 3 || p.Stats().FieldsDropped != 3 {
		t.Errorf("fields dropped: result %d, stats %d", res.FieldsDropped, p.Stats().FieldsDropped)
	}
	if len(b.calls) != 2 || b.calls[1] != 2 {
		t.Errorf("bulk calls %v", b.calls)
	}

	// An event of known fields only is not retried: nothing would change.
	b.calls = nil
	b.reject = func(store.IndexedDoc) *store.BulkItemError {
		return &store.BulkItemError{Type: "mapper_parsing_exception", Reason: "x"}
	}
	res, err = p.Ingest(context.Background(), "app", []map[string]any{{"user": "e"}})
	if err != nil || res.Rejected != 1 || len(b.calls) != 1 {
		t.Errorf("res %+v err %v calls %v", res, err, b.calls)
	}
}

func TestIndexTemplate(t *testing.T) {
	tpl := IndexTemplate("sig", 0)
	inner := tpl["template"].(map[string]any)
	mapping := inner["settings"].(map[string]any)["mapping"].(map[string]any)
	limit := mapping["total_fields"].(map[string]any)["limit"].(int)
	if limit < len(knownFields)+maxNewNamesPerIndex+200 {
		t.Errorf("total_fields.limit %d leaves too little room over %d known fields and a budget of %d", limit, len(knownFields), maxNewNamesPerIndex)
	}
	if mapping["ignore_malformed"] != true {
		t.Error("ignore_malformed not set")
	}
	mappings := inner["mappings"].(map[string]any)
	if mappings["date_detection"] != false {
		t.Error("date_detection not off")
	}
	props := mappings["properties"].(map[string]any)
	for name, want := range map[string]string{
		"@timestamp": "date", "message": "text", "user": "keyword", "src": "keyword",
		"src_port": "long", "bytes": "long", "risk_score": "double", "device_time": "keyword", "dropped_fields": "long",
	} {
		p, _ := props[name].(map[string]any)
		if p == nil || p["type"] != want {
			t.Errorf("%s mapped as %v, want %s", name, p, want)
		}
	}
}

// TestParsersEmitKnownFields keeps knownFields in step with the parsers:
// every field name the Windows and Linux parsers set must be mapped by the
// template and exempt from the budget.
func TestParsersEmitKnownFields(t *testing.T) {
	fset := token.NewFileSet()
	for _, file := range []string{"windows.go", "linux.go", "ingest.go", "defender.go", "clamav.go", "malware.go"} {
		f, err := parser.ParseFile(fset, file, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			var keys []ast.Expr
			switch n := n.(type) {
			case *ast.AssignStmt:
				for _, lhs := range n.Lhs {
					if ix, ok := lhs.(*ast.IndexExpr); ok {
						if id, ok := ix.X.(*ast.Ident); ok && (id.Name == "f" || id.Name == "fields") {
							keys = append(keys, ix.Index)
						}
					}
				}
			case *ast.CompositeLit:
				if m, ok := n.Type.(*ast.MapType); ok {
					if v, ok := m.Value.(*ast.Ident); ok && v.Name == "any" {
						for _, e := range n.Elts {
							if kv, ok := e.(*ast.KeyValueExpr); ok {
								keys = append(keys, kv.Key)
							}
						}
					}
				}
			}
			for _, k := range keys {
				lit, ok := k.(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					continue
				}
				name, _ := strconv.Unquote(lit.Value)
				if name != "v" && !KnownField(name) { // "v" is a lookup helper in windows.go
					t.Errorf("%s: field %q is not in knownFields", fset.Position(lit.Pos()), name)
				}
			}
			return true
		})
	}
}
