package search

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/geoip"
	"github.com/jrsamsanchez/signalith/internal/geoip/geoiptest"
)

func geoEngine(t *testing.T) *Engine {
	t.Helper()
	dir := t.TempDir()
	b, err := geoiptest.Build("GeoLite2-City", map[string]geoiptest.City{
		"81.2.69.0/24": {City: "London", Region: "England", Country: "United Kingdom", CountryCode: "GB", Continent: "Europe",
			Timezone: "Europe/London", Lat: 51.5, Lon: -0.09, MetroCode: 0,
			Other: map[string]map[string]string{"de": {"United Kingdom": "Vereinigtes Königreich"}}},
		"2001:db8::/32": {Country: "Testland", Lat: 1.5, Lon: 2.25, MetroCode: 7, Timezone: "UTC", Continent: "Nowhere"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "city.mmdb"), b, 0o600); err != nil {
		t.Fatal(err)
	}
	return &Engine{Store: &fakeStore{}, GeoIP: geoip.Open(dir)}
}

func TestIPLocation(t *testing.T) {
	e := geoEngine(t)
	res, err := e.Run(context.Background(), `| makeresults count=4 | streamstats count as n | eval src=case(n=1, "81.2.69.160", n=2, " 2001:db8::5 ", n=3, "10.0.0.1", n=4, "not an ip") | iplocation src | table n src City Region Country lat lon`)
	if err != nil {
		t.Fatal(err)
	}
	r := res.Rows[0]
	if r["City"] != "London" || r["Region"] != "England" || r["Country"] != "United Kingdom" || r["lat"] != 51.5 || r["lon"] != -0.09 {
		t.Errorf("row 1 = %v", r)
	}
	r = res.Rows[1]
	if r["Country"] != "Testland" || r["City"] != nil || r["lat"] != 1.5 {
		t.Errorf("row 2 = %v", r)
	}
	for _, r := range res.Rows[2:] {
		if r["Country"] != nil || r["City"] != nil || r["lat"] != nil {
			t.Errorf("row = %v", r)
		}
	}
	res, err = e.Run(context.Background(), `| makeresults | eval ip=split("2001:db8::1,81.2.69.1", ",") | iplocation prefix=ip_ allfields=true lang=de ip`)
	if err != nil {
		t.Fatal(err)
	}
	r = res.Rows[0]
	if r["ip_Country"] != "Testland" || r["ip_MetroCode"] != int64(7) || r["ip_Timezone"] != "UTC" || r["ip_Continent"] != "Nowhere" || r["Country"] != nil {
		t.Errorf("prefix row = %v", r)
	}
	res, err = e.Run(context.Background(), `| makeresults | eval ip="81.2.69.1" | iplocation lang=de ip`)
	if err != nil {
		t.Fatal(err)
	}
	if r := res.Rows[0]; r["Country"] != "Vereinigtes Königreich" || r["City"] != "London" {
		t.Errorf("de row = %v", r)
	}
	for _, bad := range []string{`iplocation`, `iplocation a b`, `iplocation x=1 src`, `iplocation allfields=maybe src`, `iplocation lang=e src`, `iplocation lang="en us" src`, `iplocation prefix=` + strings.Repeat("p", 101) + ` src`} {
		if _, err := e.Run(context.Background(), "| makeresults | "+bad); err == nil {
			t.Errorf("%s parsed", bad)
		}
	}
}

func TestIPLocationWithoutDatabase(t *testing.T) {
	for name, e := range map[string]*Engine{
		"no store":    {Store: &fakeStore{}},
		"empty dir":   {Store: &fakeStore{}, GeoIP: geoip.Open(t.TempDir())},
		"broken file": {Store: &fakeStore{}, GeoIP: geoip.Open(brokenDir(t))},
	} {
		_, err := e.Run(context.Background(), `| makeresults | eval ip="81.2.69.1" | iplocation ip`)
		var qe *QueryError
		if !errors.As(err, &qe) {
			t.Errorf("%s: err = %v, want a QueryError", name, err)
			continue
		}
		if strings.Contains(qe.Msg, string(filepath.Separator)+"geoip") || strings.Contains(qe.Msg, os.TempDir()) {
			t.Errorf("%s: message shows a server path: %s", name, qe.Msg)
		}
	}
}

func brokenDir(t *testing.T) string {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "x.mmdb"), []byte("junk"), 0o600)
	return dir
}
