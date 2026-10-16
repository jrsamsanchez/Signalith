package search

import (
	"context"
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/query"
)

// The index an event is stored in is the field index, as in Splunk:
// OpenSearch keeps it as _index, outside the event's own fields.
func TestIndexFieldCompilesToIndexMetadata(t *testing.T) {
	cases := map[string]string{
		`* | stats count by index`:                    `"sources":[{"k0":{"terms":{"field":"_index"}}}]`,
		`* | top index`:                               `"sources":[{"k0":{"terms":{"field":"_index"}}}]`,
		`* | timechart count by index`:                `"terms":{"field":"_index","size":10}`,
		`* | stats dc(index) values(index)`:           `"cardinality":{"field":"_index"}`,
		`* | where index="Signalith-Auth-2026.10.15"`: `{"term":{"_index":{"value":"signalith-auth-2026.10.15"}}}`,
		`(index=signalith-web-* OR host=a)`:           `{"wildcard":{"_index":{"value":"signalith-web-*"}}}`,
		`NOT index=*`:                                 `{"match_all":{}}`,
		`index IN (signalith-a-1, signalith-b-1)`:     `{"term":{"_index":{"value":"signalith-b-1"}}}`,
	}
	for src, want := range cases {
		p := compile(t, src)
		if got := asJSON(p.Body); !strings.Contains(got, want) {
			t.Errorf("%s: missing %s\nin %s", src, want, got)
		}
	}
}

func TestIndexFieldRefusesWhatIndexMetadataCannotDo(t *testing.T) {
	for _, src := range []string{
		`* | where index > "a"`,
		`* | where index =~ "sig.*"`,
		`* | stats sum(index)`,
		`* | stats list(index)`,
	} {
		q, err := query.Parse(src)
		if err != nil {
			t.Fatalf("%s: %v", src, err)
		}
		e := &Engine{Opt: Options{DefaultEarliest: "-24h"}}
		if _, err := e.Compile(q); err == nil || !strings.Contains(err.Error(), "index") {
			t.Errorf("%s: err = %v", src, err)
		}
	}
}

func TestEventsCarryTheirIndex(t *testing.T) {
	fs := &fakeStore{responses: []string{`{"hits":{"total":{"value":2},"hits":[
		{"_index":"signalith-authentication-2026.10.15","_source":{"@timestamp":"2026-10-15T10:00:00Z","user":"bob","index":"spoofed"}},
		{"_index":"signalith-web-2026.10.15","_source":{"@timestamp":"2026-10-15T09:00:00Z","user":"amy"}}]}}`}}
	e := &Engine{Store: fs}
	res, err := e.Run(context.Background(), `* | table _time index user`)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Rows) != 2 || res.Rows[0]["index"] != "signalith-authentication-2026.10.15" || res.Rows[1]["index"] != "signalith-web-2026.10.15" {
		t.Errorf("rows = %v", res.Rows)
	}
}

func TestStatsByIndexReadsBuckets(t *testing.T) {
	fs := &fakeStore{responses: []string{
		`{"hits":{"total":{"value":7}},"aggregations":{"groups":{"after_key":{"k0":"signalith-web-2026.10.15"},"buckets":[
			{"key":{"k0":"signalith-authentication-2026.10.15"},"doc_count":4},
			{"key":{"k0":"signalith-web-2026.10.15"},"doc_count":3}]}}}`,
		`{"hits":{"total":{"value":7}},"aggregations":{"groups":{"buckets":[]}}}`,
	}}
	e := &Engine{Store: fs}
	res, err := e.Run(context.Background(), `index=signalith-* | stats count by index`)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Rows) != 2 || res.Rows[0]["index"] != "signalith-authentication-2026.10.15" {
		t.Errorf("rows = %v", res.Rows)
	}
}
