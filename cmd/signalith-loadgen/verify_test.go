package main

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/cluster/ostest"
)

// bulk writes documents into the fake OpenSearch the way ingest stores
// them: numbers kept as strings, in the day's events index.
func bulk(t *testing.T, url string, docs [][3]any) {
	t.Helper()
	var b bytes.Buffer
	for i, d := range docs {
		fmt.Fprintf(&b, `{"index":{"_index":"signalith-other-2026.10.14","_id":"doc%04d"}}`+"\n", i)
		fmt.Fprintf(&b, `{"message":"x","loadgen_run":%q,"loadgen_agent":"%v","loadgen_seq":"%v"}`+"\n", d[0], d[1], d[2])
	}
	resp, err := http.Post(url+"/_bulk", "application/x-ndjson", &b)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("bulk: %d", resp.StatusCode)
	}
}

func TestVerifyCountsLostAndDuplicated(t *testing.T) {
	fake := ostest.New(t)
	var docs [][3]any
	// Agent 0 sent 1-10: 4 is missing and 7 is stored twice.
	for seq := 1; seq <= 10; seq++ {
		if seq != 4 {
			docs = append(docs, [3]any{"r1", 0, seq})
		}
	}
	docs = append(docs, [3]any{"r1", 0, 7})
	// Agent 1 sent 1-5, all stored, and 6 arrived although its answer was
	// lost.
	for seq := 1; seq <= 6; seq++ {
		docs = append(docs, [3]any{"r1", 1, seq})
	}
	// Another run's events are not counted.
	docs = append(docs, [3]any{"r2", 0, 4})
	bulk(t, fake.URL, docs)

	old := verifyPage
	verifyPage = 4 // several pages, so search_after paging is used
	defer func() { verifyPage = old }()
	r, err := newOSReader(OpenSearch{URL: fake.URL})
	if err != nil {
		t.Fatal(err)
	}
	stored, total, err := r.storedCounts(context.Background(), "r1")
	if err != nil {
		t.Fatal(err)
	}
	if total != 16 {
		t.Errorf("read %d copies, want 16", total)
	}
	acked := map[int][]seqRange{0: {{1, 5}, {6, 10}}, 1: {{1, 5}}}
	v := compare(acked, stored)
	if v.Acked != 15 || v.Lost != 1 || v.Duplicated != 1 || v.Unacked != 1 || v.Stored != 16 {
		t.Errorf("verdict %+v", v)
	}
	if len(v.Examples) != 2 {
		t.Errorf("examples %v", v.Examples)
	}
}

func TestNumber(t *testing.T) {
	for _, v := range []any{"42", 42.0} {
		if n, ok := number(v); !ok || n != 42 {
			t.Errorf("number(%#v) = %d %v", v, n, ok)
		}
	}
	if _, ok := number("x"); ok {
		t.Error("number of x")
	}
}
