// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package search

import (
	"context"
	"reflect"
	"testing"
)

func TestGeostats(t *testing.T) {
	base := `| makeresults count=4 | streamstats count as n | eval lat=case(n=1, 10, n=2, 12, n=3, -40, n=4, 95), lon=case(n=1, 20, n=2, 22, n=3, 100, n=4, 0), action=if(n=2, "deny", "allow")`
	res := runSeq(t, base+` | geostats count`)
	if want := []string{"geobin", "latitude", "longitude", "count"}; !reflect.DeepEqual(res.Columns, want) {
		t.Fatalf("columns = %v", res.Columns)
	}
	got := map[any]Row{}
	for _, r := range res.Rows {
		got[r["geobin"]] = r
	}
	// lat 10 and 12 fall in y=4 (90+10)/22.5, lon 20 and 22 in x=4; the
	// out-of-range latitude 95 is left out.
	if len(got) != 2 {
		t.Fatalf("rows = %v", res.Rows)
	}
	if r := got["bin_id_zl_0_y_4_x_4"]; r == nil || r["count"] != int64(2) || r["latitude"] != int64(11) || r["longitude"] != int64(21) {
		t.Errorf("first square = %v", r)
	}
	if r := got["bin_id_zl_0_y_2_x_6"]; r == nil || r["count"] != int64(1) {
		t.Errorf("second square = %v", r)
	}

	res = runSeq(t, base+` | rename lat AS la | geostats latfield=la binspanlat=1 binspanlong=1 count by action`)
	if want := []string{"geobin", "latitude", "longitude", "allow", "deny"}; !reflect.DeepEqual(res.Columns, want) {
		t.Errorf("split columns = %v", res.Columns)
	}
	if len(res.Rows) != 3 {
		t.Errorf("split rows = %v", res.Rows)
	}

	for _, bad := range []string{"geostats binspanlat=0", "geostats binspanlat=181", "geostats binspanlong=x", "geostats globallimit=1001", "geostats foo=1", "geostats count by a b", "geostats count, dc(x) by a", "geostats latfield="} {
		if _, err := (&Engine{Store: &fakeStore{}}).Run(context.Background(), "| makeresults | "+bad); err == nil {
			t.Errorf("%s parsed", bad)
		}
	}
}
