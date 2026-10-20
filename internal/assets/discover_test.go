// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package assets

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

const discoveryAnswer = `{"aggregations":{
 "hosts":{"doc_count":9,"ip":{"buckets":[
  {"key":"192.168.10.5","doc_count":5,"svc":{"buckets":[{"key":"ssh","doc_count":2},{"key":"smb","doc_count":2},{"key":"=cmd|' /C calc'!A0","doc_count":1},{"key":"domain-controller","doc_count":1},{"key":"Domain_Controller","doc_count":1},{"key":"my.dns","doc_count":1}]}},
  {"key":"192.168.10.21","doc_count":3,"svc":{"buckets":[{"key":"dns","doc_count":1}]}},
  {"key":"::ffff:192.168.10.30","doc_count":1,"svc":{"buckets":[{"key":"rdp","doc_count":1}]}},
  {"key":"not-an-address","doc_count":1,"svc":{"buckets":[]}}
 ]}},
 "leases":{"doc_count":3,"ip":{"buckets":[
  {"key":"192.168.10.21","doc_count":2,"name":{"buckets":[{"key":"WS-0042.corp.example.","doc_count":2,"last":{"value":1}}]}},
  {"key":"192.168.10.40","doc_count":1,"name":{"buckets":[{"key":"printer-2","doc_count":1,"last":{"value":1}}]}},
  {"key":"192.168.10.41","doc_count":1,"name":{"buckets":[{"key":"bad name; rm","doc_count":1,"last":{"value":1}}]}},
  {"key":"192.168.10.42","doc_count":1,"name":{"buckets":[]}}
 ]}}
}}`

func TestParseDiscovery(t *testing.T) {
	var resp map[string]any
	if err := json.Unmarshal([]byte(discoveryAnswer), &resp); err != nil {
		t.Fatal(err)
	}
	got := ParseDiscovery(resp)
	want := []Asset{
		{IP: []string{"192.168.10.5"}, Category: []string{"discovered", "service:smb", "service:ssh"}},
		{IP: []string{"192.168.10.21"}, Host: []string{"ws-0042.corp.example", "ws-0042"}, Category: []string{"discovered"}},
		{IP: []string{"192.168.10.30"}, Category: []string{"discovered", "service:rdp"}},
		{IP: []string{"192.168.10.40"}, Host: []string{"printer-2"}, Category: []string{"discovered"}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got  %+v\nwant %+v", got, want)
	}
	if ParseDiscovery(map[string]any{}) == nil || len(ParseDiscovery(nil)) != 0 {
		t.Error("an empty answer is no hosts")
	}
}

func TestDiscoveryQuery(t *testing.T) {
	since := time.Date(2026, 10, 8, 0, 0, 0, 0, time.UTC)
	b, err := json.Marshal(DiscoveryQuery(since))
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{`"zeek:known_hosts"`, `"zeek:dhcp"`, `"gte":"2026-10-08T00:00:00Z"`, `"field":"dest"`, `"field":"src_host"`, `"must_not"`,
		`{"term":{"signalith_intake":"agent"}}`, `{"term":{"signalith_token_purpose":"sensor"}}`} {
		if !strings.Contains(string(b), s) {
			t.Errorf("query has no %s: %s", s, b)
		}
	}
	if DiscoveryIndex("signalith") != "signalith-other-*" {
		t.Error(DiscoveryIndex("signalith"))
	}
}

// TestDiscoveredNeverOverride: the user's own rows win over hosts the
// sensor found, in lookups and in the list, matched by name or address.
func TestDiscoveredNeverOverride(t *testing.T) {
	s, err := NewStore("")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.SetAssets([]byte("host,ip,cidr,owner,priority\nfile-01,192.168.10.5,,it,critical\n,,192.168.20.0/24,lab,low\n")); err != nil {
		t.Fatal(err)
	}
	s.SetFound([]Asset{
		{IP: []string{"192.168.10.5"}, Category: []string{"discovered"}},
		{IP: []string{"192.168.10.21"}, Host: []string{"ws-0042"}, Category: []string{"discovered"}},
		{IP: []string{"192.168.20.7"}, Category: []string{"discovered"}},
	})
	if a, ok := s.Asset("192.168.10.5"); !ok || a.Owner != "it" {
		t.Errorf("192.168.10.5: %+v", a)
	}
	if a, ok := s.Asset("192.168.20.7"); !ok || a.Owner != "lab" {
		t.Errorf("192.168.20.7: %+v", a)
	}
	if a, ok := s.Asset("ws-0042"); !ok || a.Category[0] != "discovered" {
		t.Errorf("ws-0042: %+v", a)
	}
	var ips []string
	for _, a := range s.Found() {
		ips = append(ips, a.IP...)
	}
	// A host in a network row of the list is still listed: the row
	// describes the network, not the host.
	if strings.Join(ips, ",") != "192.168.10.21,192.168.20.7" {
		t.Errorf("found listed: %v", ips)
	}
}

// TestFoundNameFirstWins: a discovered host that announces the name of
// an osquery host (its DHCP client chose it) does not take that name's
// lookups over; it keeps its address.
func TestFoundNameFirstWins(t *testing.T) {
	s, err := NewStore("")
	if err != nil {
		t.Fatal(err)
	}
	s.SetFound([]Asset{
		{Host: []string{"fileserver01.corp.example", "fileserver01"}, IP: []string{"10.0.0.5"}, Category: []string{"endpoint", "linux"}},
		{Host: []string{"FileServer01"}, IP: []string{"10.0.0.66"}, Category: []string{"discovered"}},
		{Host: []string{"fileserver01.evil.example"}, IP: []string{"10.0.0.67"}, Category: []string{"discovered"}},
	})
	for _, name := range []string{"fileserver01", "fileserver01.corp.example"} {
		if a, ok := s.Asset(name); !ok || a.IP[0] != "10.0.0.5" {
			t.Errorf("%s: %+v", name, a)
		}
	}
	if a, ok := s.Asset("10.0.0.66"); !ok || len(a.Host) != 0 {
		t.Errorf("10.0.0.66: %+v", a)
	}
	if a, ok := s.Asset("fileserver01.evil.example"); !ok || a.IP[0] != "10.0.0.67" {
		t.Errorf("a new full name is the host's own: %+v", a)
	}
}
