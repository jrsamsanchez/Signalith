// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package search

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// Two groups fit; the composite's first page, in key order, holds the
// two smallest.
const firstByName = `{"hits":{"total":{"value":1000}},"aggregations":{"groups":{"after_key":{"k0":"b"},"buckets":[
	{"key":{"k0":"a"},"doc_count":1},{"key":{"k0":"b"},"doc_count":2}]}}}`

const byCount = `{"hits":{"total":{"value":1000}},"aggregations":{"groups":{"sum_other_doc_count":97,"buckets":[
	{"key":"z","doc_count":600},{"key":"y","doc_count":300}]}}}`

func runRanked(t *testing.T, src string, responses ...string) (*Result, *fakeStore) {
	t.Helper()
	fs := &fakeStore{responses: responses}
	res, err := (&Engine{Store: fs, Opt: Options{MaxBuckets: 2}}).Run(context.Background(), src)
	if err != nil {
		t.Fatalf("Run(%q): %v", src, err)
	}
	return res, fs
}

func bodyOf(fs *fakeStore, i int) string {
	b, _ := json.Marshal(fs.bodies[i])
	return string(b)
}

// With more groups than the server keeps, sort -count | head N keeps the
// largest groups, not the first by name (SL-03).
func TestStatsSortHeadRanksInOpenSearch(t *testing.T) {
	res, fs := runRanked(t, `* | stats count by user | sort -count | head 2`, firstByName, byCount)
	if got := fmt.Sprint(res.Rows); got != "[map[count:600 user:z] map[count:300 user:y]]" {
		t.Errorf("rows = %s", got)
	}
	if res.Truncated || !res.Ranked {
		t.Errorf("truncated %v, ranked %v", res.Truncated, res.Ranked)
	}
	if b := bodyOf(fs, 1); !strings.Contains(b, `"order":{"_count":"desc"}`) || !strings.Contains(b, `"size":2`) {
		t.Errorf("ranked request = %s", b)
	}
}

func TestStatsSortByMetricRanksByIt(t *testing.T) {
	_, fs := runRanked(t, `* | stats count, sum(bytes) as total by user | sort -total | head 2`, firstByName, byCount)
	if b := bodyOf(fs, 1); !strings.Contains(b, `"order":{"m1":"desc"}`) {
		t.Errorf("ranked request = %s", b)
	}
	_, fs = runRanked(t, `* | stats values(x) as v, count by user | sort v | head 2`, firstByName)
	if len(fs.bodies) != 1 {
		t.Error("values() cannot be ranked in OpenSearch, so nothing should be asked again")
	}
}

// Without a head, the groups kept are those with the most events, and
// the result is still truncated.
func TestStatsThresholdKeepsTheLargest(t *testing.T) {
	res, _ := runRanked(t, `* | stats count by user | where count > 100`, firstByName, byCount)
	if got := fmt.Sprint(res.Rows); got != "[map[count:600 user:z] map[count:300 user:y]]" {
		t.Errorf("rows = %s", got)
	}
	if !res.Truncated || !res.Ranked {
		t.Errorf("truncated %v, ranked %v", res.Truncated, res.Ranked)
	}
}

// top keeps the most frequent values, with percentages of every event
// with the field, other values included.
func TestTopRanksInOpenSearch(t *testing.T) {
	res, fs := runRanked(t, `* | top limit=2 user`, firstByName, byCount)
	if got := fmt.Sprint(res.Rows); got != "[map[count:600 percent:60.180542 user:z] map[count:300 percent:30.090271 user:y]]" {
		t.Errorf("rows = %s", got)
	}
	if res.Truncated || !res.Ranked {
		t.Errorf("truncated %v, ranked %v", res.Truncated, res.Ranked)
	}
	if b := bodyOf(fs, 1); !strings.Contains(b, `"terms":{"field":"user"`) {
		t.Errorf("ranked request = %s", b)
	}
	_, fs = runRanked(t, `* | rare limit=2 user`, firstByName, byCount)
	if b := bodyOf(fs, 1); !strings.Contains(b, `"order":{"_count":"asc"}`) {
		t.Errorf("rare request = %s", b)
	}
	res, _ = runRanked(t, `* | top limit=2 useother=t user`, firstByName, byCount)
	if got := fmt.Sprint(res.Rows[len(res.Rows)-1]); !strings.Contains(got, "count:97") {
		t.Errorf("other row = %s", got)
	}
}

func TestTopOfTwoFieldsUsesMultiTerms(t *testing.T) {
	multi := `{"aggregations":{"groups":{"sum_other_doc_count":0,"buckets":[{"key":["z","h1"],"doc_count":5}]}}}`
	res, fs := runRanked(t, `* | top limit=1 user, host`, firstByName, multi)
	if b := bodyOf(fs, 1); !strings.Contains(b, `"multi_terms"`) {
		t.Errorf("ranked request = %s", b)
	}
	if got := fmt.Sprint(res.Rows); !strings.Contains(got, "host:h1") || !strings.Contains(got, "user:z") {
		t.Errorf("rows = %s", got)
	}
}
