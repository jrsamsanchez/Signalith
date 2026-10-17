package splcheck

import (
	"fmt"
	"net/netip"
	"strings"
	"testing"
)

// splunkIPLocation is what Splunk's iplocation does to a row, as its
// documentation says: for an address the database lists, City, Country,
// Region, lat and lon, each empty when the database has no value for
// it; for one it does not list, or a value that is not an address,
// nothing. A field with several values is read by its first.
func splunkIPLocation(t *testing.T, row map[string]any, field string) {
	t.Helper()
	v := row[field]
	if mv, ok := v.([]any); ok && len(mv) > 0 {
		v = mv[0]
	}
	s, _ := v.(string)
	ip, err := netip.ParseAddr(s)
	if err != nil {
		return
	}
	loc, found, err := TestGeoIP().Lookup(ip, "en")
	if err != nil {
		t.Fatal(err)
	}
	if !found {
		return
	}
	row["City"], row["Region"], row["Country"], row["lat"], row["lon"] = loc.City, loc.Region, loc.Country, "", ""
	if loc.HasCoords {
		row["lat"], row["lon"] = loc.Lat, loc.Lon
	}
}

// TestIPLocationAsSplunk: a rule's iplocation, as converted, gives each
// row the fields Splunk's gives it, empty and missing alike, for an
// address located to a city, to its country only, to its continent only,
// a private one, text that is not an address, a list, and a row that
// already has a City.
func TestIPLocationAsSplunk(t *testing.T) {
	r := &Rule{}
	stages := []string{"iplocation sourceIPs{}", "table sourceIPs{} City Region Country lat lon"}
	if err := r.postCommands(stages, func(f string) (string, bool) { return f, true }, ""); err != nil {
		t.Fatal(err)
	}
	if !r.IPLocation() || r.iplocationField() != "sourceIPs{}" {
		t.Fatalf("Post:\n%s", r.Post)
	}
	for _, tc := range []map[string]any{
		{"sourceIPs{}": "203.0.113.9"},
		{"sourceIPs{}": "198.51.100.9"},
		{"sourceIPs{}": "192.0.2.9"},
		{"sourceIPs{}": TestPrivateIP},
		{"sourceIPs{}": "not an address"},
		{"sourceIPs{}": []any{"198.51.100.9", "203.0.113.9"}},
		{"sourceIPs{}": TestPrivateIP, "City": "Kept"},
		{"sourceIPs{}": "203.0.113.9", "City": "Replaced"},
		{"sourceIPs{}": "198.51.100.9", "City": "Emptied"},
	} {
		want := map[string]any{}
		for k, v := range tc {
			want[k] = v
		}
		splunkIPLocation(t, want, "sourceIPs{}")
		rows, err := r.runPost([]map[string]any{tc})
		if err != nil || len(rows) != 1 {
			t.Fatalf("%v: %v %v", tc, rows, err)
		}
		for _, f := range iplocationFields {
			w, wok := want[f]
			g, gok := rows[0][f]
			if wok != gok || fmt.Sprint(w) != fmt.Sprint(g) {
				t.Errorf("%v: %s is %v (%v), Splunk's %v (%v)", tc, f, g, gok, w, wok)
			}
		}
		for k := range rows[0] {
			if strings.HasPrefix(k, iplocationPrefix) {
				t.Errorf("%v: left %s", tc, k)
			}
		}
	}
}

// TestIPLocationRefused: iplocation with options, and a stage after it
// that reads every field a row has, are refused; an iplocation no later
// stage reads is dropped.
func TestIPLocationRefused(t *testing.T) {
	field := func(f string) (string, bool) { return f, true }
	for _, stages := range [][]string{
		{"iplocation prefix=src_ src", "stats count by src_City"},
		{"iplocation allfields=true src", "stats count by City"},
		{"iplocation src", "fillnull", "stats count by City"},
		{"iplocation src", "stats values(*) as * by City"},
	} {
		r := &Rule{}
		if err := r.postCommands(stages, field, ""); err == nil {
			t.Errorf("%q: converted as\n%s", stages, r.Post)
		}
	}
	r := &Rule{}
	if err := r.postCommands([]string{"stats count by src", "iplocation src"}, field, ""); err != nil || r.IPLocation() || strings.Contains(r.Post, "iplocation") {
		t.Errorf("unread iplocation: %v\n%s", err, r.Post)
	}
}
