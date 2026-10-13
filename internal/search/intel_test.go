package search

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/intel"
	"github.com/jrsamsanchez/signalith/internal/query"
)

func intelStore(t *testing.T) *intel.Store {
	t.Helper()
	s := intel.NewStore(intel.NewMemory())
	err := s.Add(context.Background(), []intel.Indicator{
		{Type: intel.TypeIP, Value: "203.0.113.9", Source: "feodo", Weight: 2, Description: "Emotet C2"},
		{Type: intel.TypeIP, Value: "203.0.113.9", Source: intel.ManualSource, Weight: 1},
		{Type: intel.TypeCIDR, Value: "198.51.100.0/24", Source: "drop", Weight: 1},
		{Type: intel.TypeDomain, Value: "evil.example", Source: "urlhaus", Weight: 1},
		{Type: intel.TypeSHA256, Value: strings.Repeat("c", 64), Source: intel.ManualSource, Weight: 3},
	})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestThreatMatchCompilesToTermsFilters(t *testing.T) {
	e := &Engine{Opt: Options{DefaultEarliest: "-24h"}, Intel: intelStore(t)}
	q, _ := query.Parse(`datamodel=Network_Traffic | threatmatch src, dest, process_sha256 | head 5`)
	p, err := e.Compile(q)
	if err != nil {
		t.Fatal(err)
	}
	body := asJSON(p.Body)
	for _, want := range []string{
		`{"terms":{"src":["203.0.113.9"]}}`,
		`{"prefix":{"src":{"value":"198.51.100."}}}`,
		`{"terms":{"dest":["evil.example"]}}`,
		`{"terms":{"process_sha256":["` + strings.Repeat("c", 64) + `","` + strings.Repeat("C", 64) + `"]}}`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("body lacks %s:\n%s", want, body)
		}
	}
	if strings.Contains(body, `"src":["evil.example"]`) {
		t.Error("domains must not be matched against src")
	}
	if p.Body["size"] != 5 {
		t.Errorf("head after threatmatch should set size, got %v", p.Body["size"])
	}
	// threatmatch must come first: it is a filter.
	q, _ = query.Parse(`* | stats count by src | threatmatch`)
	if _, err := e.Compile(q); err == nil || !strings.Contains(err.Error(), "right after the search") {
		t.Errorf("late threatmatch = %v", err)
	}
	// No indicators: nothing matches, cheaply.
	empty := &Engine{Intel: intel.NewStore(intel.NewMemory())}
	q, _ = query.Parse(`* | threatmatch`)
	p, _ = empty.Compile(q)
	if !strings.Contains(asJSON(p.Body), `"must_not":[{"match_all":{}}]`) {
		t.Errorf("empty intel body = %s", asJSON(p.Body))
	}
	if _, err := (&Engine{}).Compile(q); err == nil {
		t.Error("threatmatch without intel should explain it is not available")
	}
}

func TestThreatMatchTermsAreBatched(t *testing.T) {
	s := intel.NewStore(intel.NewMemory())
	var inds []intel.Indicator
	for i := 0; i < 25000; i++ {
		inds = append(inds, intel.Indicator{Type: intel.TypeIP, Value: fmt.Sprintf("10.%d.%d.%d", i/65536, (i/256)%256, i%256), Source: "big"})
	}
	if err := s.Add(context.Background(), inds); err != nil {
		t.Fatal(err)
	}
	e := &Engine{Intel: s}
	q, _ := query.Parse(`* | threatmatch src`)
	p, err := e.Compile(q)
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(asJSON(p.Body), `{"terms":{"src":[`); n != 3 {
		t.Errorf("25000 values should be 3 terms clauses, got %d", n)
	}
}

func TestThreatMatchAnnotatesEvents(t *testing.T) {
	fs := &fakeStore{responses: []string{`{"hits":{"total":{"value":3},"hits":[
		{"_source":{"@timestamp":"2026-10-11T10:00:00Z","src":"203.0.113.9","dest":"web1","user":"oracle"}},
		{"_source":{"@timestamp":"2026-10-11T09:00:00Z","src":"10.0.0.5","dest":"198.51.100.20","host":"WS1","process_sha256":"` + strings.Repeat("C", 64) + `"}},
		{"_source":{"@timestamp":"2026-10-11T08:00:00Z","src":"10.0.0.6","dest":"10.0.0.7"}}]}}`}}
	e := &Engine{Store: fs, Intel: intelStore(t)}
	res, err := e.Run(context.Background(), `* | threatmatch`)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Rows) != 2 {
		t.Fatalf("an unconfirmed row should be dropped: %v", res.Rows)
	}
	r := res.Rows[0]
	if r["threat_match_field"] != "src" || r["threat_match_value"] != "203.0.113.9" || r["threat_source"] != "feodo, manual" ||
		r["threat_weight"] != int64(2) || r["threat_target"] != "web1" || r["threat_description"] != "Emotet C2" {
		t.Errorf("row 0 = %v", r)
	}
	// The hash (weight 3) beats the network (weight 1); the target is the
	// source of the connection.
	r = res.Rows[1]
	if r["threat_match_field"] != "process_sha256" || r["threat_type"] != "sha256" || r["threat_source"] != "manual" || r["threat_target"] != "10.0.0.5" {
		t.Errorf("row 1 = %v", r)
	}
	if res.Columns[0] != "_time" || res.Columns[1] != "threat_match_field" {
		t.Errorf("columns = %v", res.Columns)
	}
}

func TestIntelCommandAddsColumns(t *testing.T) {
	fs := &fakeStore{responses: []string{`{"hits":{"total":{"value":0}},"aggregations":{"groups":{"buckets":[
		{"key":{"k0":"203.0.113.9"},"doc_count":12},{"key":{"k0":"10.1.1.1"},"doc_count":3}]}}}`}}
	e := &Engine{Store: fs, Intel: intelStore(t)}
	res, err := e.Run(context.Background(), `* | stats count by src | intel src`)
	if err != nil {
		t.Fatal(err)
	}
	if r := res.Rows[0]; r["src_intel_source"] != "feodo, manual" || r["src_intel_type"] != "ip" || r["src_intel_weight"] != int64(2) || r["src_intel_description"] != "Emotet C2" {
		t.Errorf("row = %v", r)
	}
	if _, ok := res.Rows[1]["src_intel_source"]; ok {
		t.Errorf("no match should add nothing: %v", res.Rows[1])
	}
	if strings.Join(res.Columns, ",") != "src,src_intel_source,src_intel_type,src_intel_weight,src_intel_description,count" {
		t.Errorf("columns = %v", res.Columns)
	}
	if _, err := (&Engine{Store: fs}).Run(context.Background(), `* | intel`); err == nil {
		t.Error("intel without a store should fail")
	}
}

func TestThreatMatchFileHash(t *testing.T) {
	fs := &fakeStore{responses: []string{`{"hits":{"total":{"value":1},"hits":[
		{"_source":{"@timestamp":"2026-10-11T10:00:00Z","datamodel":"Malware","src":"10.0.0.9","dest":"ws-fin-07","host":"ws-fin-07","file_sha256":"` + strings.Repeat("c", 64) + `"}}]}}`}}
	e := &Engine{Store: fs, Intel: intelStore(t)}
	res, err := e.Run(context.Background(), `datamodel=Malware | threatmatch`)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Rows) != 1 {
		t.Fatalf("rows = %v", res.Rows)
	}
	if r := res.Rows[0]; r["threat_match_field"] != "file_sha256" || r["threat_type"] != "sha256" || r["threat_target"] != "ws-fin-07" {
		t.Errorf("row = %v", r)
	}
	if body := asJSON(fs.bodies[0]); !strings.Contains(body, `{"terms":{"file_sha256":["`+strings.Repeat("c", 64)) {
		t.Errorf("no file_sha256 filter in %s", body)
	}
}
