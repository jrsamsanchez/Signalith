// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package geoip

import (
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/geoip/geoiptest"
)

func writeDB(t *testing.T, dir, name, dbType string, nets map[string]geoiptest.City) {
	t.Helper()
	b, err := geoiptest.Build(dbType, nets)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), b, 0o600); err != nil {
		t.Fatal(err)
	}
}

var testNets = map[string]geoiptest.City{
	"81.2.69.0/24": {City: "London", Region: "England", Country: "United Kingdom", CountryCode: "GB", Continent: "Europe",
		Timezone: "Europe/London", Lat: 51.5142, Lon: -0.0931,
		Other: map[string]map[string]string{"de": {"London": "London", "United Kingdom": "Vereinigtes Königreich"}}},
	"2001:db8::/32": {Country: "Testland", CountryCode: "TL", Lat: 1.5, Lon: 2.25, MetroCode: 7},
}

func TestLookup(t *testing.T) {
	dir := t.TempDir()
	writeDB(t, dir, "city.mmdb", "GeoLite2-City", testNets)
	s := Open(dir)
	loc, found, err := s.Lookup(netip.MustParseAddr("81.2.69.160"), "en")
	if err != nil || !found {
		t.Fatalf("found=%v err=%v", found, err)
	}
	want := Location{City: "London", Region: "England", Country: "United Kingdom", Continent: "Europe",
		Timezone: "Europe/London", Lat: 51.5142, Lon: -0.0931, HasCoords: true}
	if loc != want {
		t.Errorf("got %+v, want %+v", loc, want)
	}
	loc, _, _ = s.Lookup(netip.MustParseAddr("::ffff:81.2.69.1"), "de")
	if loc.Country != "Vereinigtes Königreich" || loc.Region != "England" {
		t.Errorf("de names: %+v", loc)
	}
	loc, found, err = s.Lookup(netip.MustParseAddr("2001:db8::1"), "en")
	if err != nil || !found || loc.Country != "Testland" || loc.MetroCode != 7 || loc.City != "" {
		t.Errorf("IPv6: %+v %v %v", loc, found, err)
	}
	for _, ip := range []string{"10.0.0.1", "81.2.70.1", "2001:db9::1"} {
		if _, found, err := s.Lookup(netip.MustParseAddr(ip), "en"); found || err != nil {
			t.Errorf("%s: found=%v err=%v", ip, found, err)
		}
	}
	if f, err := s.Status(); err != nil || filepath.Base(f) != "city.mmdb" {
		t.Errorf("Status = %q, %v", f, err)
	}
}

func TestNoDatabase(t *testing.T) {
	dir := t.TempDir()
	s := Open(filepath.Join(dir, "missing"))
	if _, _, err := s.Lookup(netip.MustParseAddr("81.2.69.1"), "en"); err == nil || !strings.Contains(err.Error(), "put a GeoIP") {
		t.Fatalf("err = %v", err)
	}
}

func TestBadFiles(t *testing.T) {
	for name, content := range map[string][]byte{
		"empty":   {},
		"garbage": []byte(strings.Repeat("not a database ", 100)),
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			os.WriteFile(filepath.Join(dir, "x.mmdb"), content, 0o600)
			s := Open(dir)
			if _, _, err := s.Lookup(netip.MustParseAddr("81.2.69.1"), "en"); err == nil {
				t.Fatal("no error")
			}
		})
	}
	t.Run("asn", func(t *testing.T) {
		dir := t.TempDir()
		writeDB(t, dir, "asn.mmdb", "GeoLite2-ASN", testNets)
		if _, _, err := Open(dir).Lookup(netip.MustParseAddr("81.2.69.1"), "en"); err == nil || !strings.Contains(err.Error(), "City or Country") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("truncated", func(t *testing.T) {
		dir := t.TempDir()
		b, _ := geoiptest.Build("GeoLite2-City", testNets)
		// Drop part of the data section but keep the metadata.
		i := strings.Index(string(b), "\xAB\xCD\xEFMaxMind.com")
		os.WriteFile(filepath.Join(dir, "x.mmdb"), append(append([]byte{}, b[:i-20]...), b[i:]...), 0o600)
		if _, _, err := Open(dir).Lookup(netip.MustParseAddr("81.2.69.1"), "en"); err == nil {
			t.Fatal("no error")
		}
	})
}

func TestNewerFile(t *testing.T) {
	dir := t.TempDir()
	writeDB(t, dir, "a.mmdb", "GeoLite2-City", testNets)
	s := Open(dir)
	now := time.Now()
	s.now = func() time.Time { return now }
	if loc, _, _ := s.Lookup(netip.MustParseAddr("81.2.69.1"), "en"); loc.City != "London" {
		t.Fatalf("got %+v", loc)
	}
	writeDB(t, dir, "b.mmdb", "GeoLite2-Country", map[string]geoiptest.City{"81.2.69.0/24": {Country: "Elsewhere"}})
	os.Chtimes(filepath.Join(dir, "b.mmdb"), now.Add(time.Minute), now.Add(time.Minute))
	// Not looked at again within 30 seconds.
	if loc, _, _ := s.Lookup(netip.MustParseAddr("81.2.69.1"), "en"); loc.City != "London" {
		t.Fatalf("switched early: %+v", loc)
	}
	now = now.Add(31 * time.Second)
	if loc, _, _ := s.Lookup(netip.MustParseAddr("81.2.69.1"), "en"); loc.Country != "Elsewhere" || loc.City != "" {
		t.Fatalf("not switched: %+v", loc)
	}
	// A broken newer file keeps the one in use and reports why.
	os.WriteFile(filepath.Join(dir, "c.mmdb"), []byte("junk"), 0o600)
	os.Chtimes(filepath.Join(dir, "c.mmdb"), now.Add(2*time.Minute), now.Add(2*time.Minute))
	now = now.Add(31 * time.Second)
	if loc, _, _ := s.Lookup(netip.MustParseAddr("81.2.69.1"), "en"); loc.Country != "Elsewhere" {
		t.Fatalf("lost the working file: %+v", loc)
	}
	if f, err := s.Status(); filepath.Base(f) != "b.mmdb" || err == nil {
		t.Errorf("Status = %q, %v", f, err)
	}
}

// FuzzLoad checks that any file in the geoip folder is used or refused,
// never crashing a search.
func FuzzLoad(f *testing.F) {
	b, err := geoiptest.Build("GeoLite2-City", testNets)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(b)
	f.Add([]byte("\xAB\xCD\xEFMaxMind.com"))
	f.Fuzz(func(t *testing.T, data []byte) {
		db, err := openBytes(data)
		if err != nil {
			return
		}
		s := &Store{db: db, file: "x.mmdb", now: time.Now, checked: time.Now()}
		for _, ip := range []string{"81.2.69.1", "2001:db8::1", "10.0.0.1", "::"} {
			s.Lookup(netip.MustParseAddr(ip), "de") //nolint:errcheck
		}
	})
}

func TestLookupDoesNotWaitForALoad(t *testing.T) {
	dir := t.TempDir()
	writeDB(t, dir, "a.mmdb", "GeoLite2-City", testNets)
	s := Open(dir)
	// Another search is loading the first file.
	s.loadMu.Lock()
	if _, _, err := s.Lookup(netip.MustParseAddr("81.2.69.1"), "en"); !errors.Is(err, ErrLoading) {
		t.Fatalf("err = %v, want ErrLoading", err)
	}
	s.loadMu.Unlock()
	if loc, _, err := s.Lookup(netip.MustParseAddr("81.2.69.1"), "en"); err != nil || loc.City != "London" {
		t.Fatalf("got %+v, %v", loc, err)
	}
	// While a newer file loads, the one in use answers.
	s.loadMu.Lock()
	defer s.loadMu.Unlock()
	if loc, _, err := s.Lookup(netip.MustParseAddr("81.2.69.1"), "en"); err != nil || loc.City != "London" {
		t.Fatalf("during a load: %+v, %v", loc, err)
	}
}

// TestFromBytes: a store of a database in memory reads it and no folder,
// and refuses a file that is not a City or Country database.
func TestFromBytes(t *testing.T) {
	b, err := geoiptest.Build("GeoLite2-City", testNets)
	if err != nil {
		t.Fatal(err)
	}
	s, err := FromBytes(b)
	if err != nil {
		t.Fatal(err)
	}
	if f, err := s.Status(); f == "" || err != nil {
		t.Errorf("Status = %q, %v", f, err)
	}
	loc, found, err := s.Lookup(netip.MustParseAddr("81.2.69.160"), "en")
	if err != nil || !found || loc.City != "London" {
		t.Errorf("got %+v %v %v", loc, found, err)
	}
	if _, found, err := s.Lookup(netip.MustParseAddr("10.0.0.1"), "en"); found || err != nil {
		t.Errorf("private: found=%v err=%v", found, err)
	}
	asn, _ := geoiptest.Build("GeoLite2-ASN", testNets)
	if _, err := FromBytes(asn); err == nil {
		t.Error("an ASN database was read")
	}
}
