// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package search

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/query"
)

// @w, bin span=1w and timechart span=1w all start weeks on Sunday
// (SL-05).
func TestWeeksStartOnSunday(t *testing.T) {
	wed := time.Date(2026, 10, 14, 13, 0, 0, 0, time.UTC)
	if got, _ := relativeTime(wed, "@w"); got.Weekday() != time.Sunday {
		t.Errorf("relative_time @w = %v", got)
	}
	// bin's week buckets start weekStart seconds after Unix time 0.
	if d := time.Unix(weekStart, 0).UTC().Weekday(); d != time.Sunday {
		t.Errorf("bin weeks start on %v", d)
	}
	iv, err := spanInterval("2w")
	if err != nil || iv["fixed_interval"] != "14d" || iv["offset"] != "+3d" {
		t.Errorf("timechart span=2w = %v %v", iv, err)
	}
	// Unix time 0 plus the offset is a Sunday.
	if d := time.Unix(0, 0).UTC().AddDate(0, 0, 3).Weekday(); d != time.Sunday {
		t.Errorf("timechart weeks start on %v", d)
	}
	if iv, err := spanInterval("1q"); err != nil || iv["calendar_interval"] != "quarter" {
		t.Errorf("span=1q = %v %v", iv, err)
	}
}

// A search in a time zone rounds days there and says so (SL-11).
func TestSearchInATimeZone(t *testing.T) {
	q, err := query.Parse(`* earliest=-1d@d | timechart span=1d count`)
	if err != nil {
		t.Fatal(err)
	}
	q.TimeZone = "America/New_York"
	p, err := (&Engine{}).Compile(q)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(p.Body)
	for _, want := range []string{`"time_zone":"America/New_York"`, `"date_histogram":{"field":"@timestamp","fixed_interval":"1d","min_doc_count":0,"time_zone":"America/New_York"}`} {
		if !strings.Contains(string(body), want) {
			t.Errorf("body lacks %s: %s", want, body)
		}
	}

	// 03:00 UTC on 14 October is 23:00 on the 13th in New York.
	at := time.Date(2026, 10, 14, 3, 0, 0, 0, time.UTC).Unix()
	src := fmt.Sprintf(`| makeresults | eval t=%d, day=strftime(t, "%%Y-%%m-%%d %%Z"), back=strptime("2026-10-13 23:00", "%%Y-%%m-%%d %%H:%%M"), snap=relative_time(t, "@d") | bin span=1d t | table t, day, back, snap`, at)
	q, _ = query.Parse(src)
	q.TimeZone = "America/New_York"
	res, err := (&Engine{}).Execute(context.Background(), q)
	if err != nil {
		t.Fatal(err)
	}
	r := res.Rows[0]
	midnight := time.Date(2026, 10, 13, 0, 0, 0, 0, zoneOf("America/New_York")).Unix()
	if r["day"] != "2026-10-13 EDT" || fmt.Sprint(r["back"]) != fmt.Sprint(at) || fmt.Sprint(r["snap"]) != fmt.Sprint(midnight) || fmt.Sprint(r["t"]) != fmt.Sprint(midnight) {
		t.Errorf("row = %v, want day 2026-10-13 EDT, back %d, snap and t %d", r, at, midnight)
	}
	if res.TimeZone != "America/New_York" {
		t.Errorf("time zone = %q", res.TimeZone)
	}
	if ValidTimeZone("Mars/Olympus") == nil || ValidTimeZone("Europe/Berlin") != nil || ValidTimeZone("") != nil {
		t.Error("ValidTimeZone")
	}
}
