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

// A where comparison with a bare name compares with that field when the
// row has one, as in Splunk (SL-02), and with the text otherwise.
func TestWhereComparesWithAField(t *testing.T) {
	for _, tc := range []struct {
		src  string
		rows int
	}{
		{`| makeresults | eval a=5, b=3 | where a > b`, 1},
		{`| makeresults | eval a=10, b=3 | where a < b`, 0},
		{`| makeresults | eval failures=7, successes=2 | where failures > successes`, 1},
		{`| makeresults | eval user="admin", admin="x" | where user=admin`, 0},
		{`| makeresults | eval user="admin", admin="x" | where user!=admin`, 1},
		{`| makeresults | eval user="admin", other="admin" | where user=other`, 1},
		// No such field: the name is text, as before.
		{`| makeresults | eval user="admin" | where user=admin`, 1},
		{`| makeresults | eval user="Admin" | where user=admin`, 1},
		// Quoted, the value is always text.
		{`| makeresults | eval user="admin", admin="x" | where user="admin"`, 1},
		{`| makeresults | eval user="admin", admin="x" | where user=adm*`, 1},
		{`| makeresults | eval a=5, b=3 | where NOT a <= b AND (a >= b OR a=b)`, 1},
	} {
		res, err := (&Engine{}).Run(context.Background(), tc.src)
		if err != nil {
			t.Fatalf("%s: %v", tc.src, err)
		}
		if len(res.Rows) != tc.rows {
			t.Errorf("%s: %d rows, want %d", tc.src, len(res.Rows), tc.rows)
		}
	}
}

// OpenSearch cannot compare two fields, so a where right after the
// search that names a known field runs over the events it returns; one
// whose bare value is no field is still searched for there.
func TestWhereFieldCompareRunsOverEvents(t *testing.T) {
	res, fs := runEvents(t, `* | where bytes_out > bytes_in | table user`)
	if fmt.Sprint(res.Rows) != "[map[user:bob]]" {
		t.Errorf("rows = %v", res.Rows)
	}
	if body, _ := json.Marshal(fs.bodies[0]); strings.Contains(string(body), "bytes_in") {
		t.Errorf("field comparison sent to OpenSearch: %s", body)
	}

	_, fs = runEvents(t, `* | where action=blocked`)
	if body, _ := json.Marshal(fs.bodies[0]); !strings.Contains(string(body), "blocked") {
		t.Errorf("text filter not sent to OpenSearch: %s", body)
	}
}

// A multivalue field matches when one of its values does, in where and
// search alike (SL-07).
func TestWhereMatchesAnyValue(t *testing.T) {
	for src, rows := range map[string]int{
		`| makeresults | eval u=split("alice,bob", ",") | where u=alice`:           1,
		`| makeresults | eval u=split("alice,bob", ",") | search u=alice`:          1,
		`| makeresults | eval u=split("alice,bob", ",") | where u!=alice`:          0,
		`| makeresults | eval u=split("alice,bob", ",") | where u!=carol`:          1,
		`| makeresults | eval u=split("alice,bob", ",") | where u IN (carol, bob)`: 1,
		`| makeresults | eval n=split("1,20", ",") | where n > 10`:                 1,
		`| makeresults | eval n=split("1,2", ",") | where n > 10`:                  0,
		`| makeresults | eval u=split("alice,bob", ",") | where u=al*`:             1,
	} {
		res, err := (&Engine{}).Run(context.Background(), src)
		if err != nil {
			t.Fatalf("%s: %v", src, err)
		}
		if len(res.Rows) != rows {
			t.Errorf("%s: %d rows, want %d", src, len(res.Rows), rows)
		}
	}
}
