// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package sigmacheck

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestNetworkCategories(t *testing.T) {
	for cat, want := range map[string]bool{"dns": true, "proxy": true, "firewall": true, "zeek_rdp": true, "process_creation": false} {
		if got := IsNetworkCategory(cat); got != want {
			t.Errorf("IsNetworkCategory(%s) = %v", cat, got)
		}
	}
	if got := NetworkChannel("zeek_kerberos"); got != "zeek:kerberos" {
		t.Errorf("channel = %s", got)
	}
	if b := NetworkBase("zeek_x509"); b["id.orig_h"] != "" || b["certificate.subject"] == "" {
		t.Errorf("x509 base = %v", b)
	}
	if b := NetworkBase("zeek_dns"); b["id.orig_h"] != "192.0.2.10" || b["id.resp_p"] != "53" || b["query"] == "" {
		t.Errorf("dns base = %v", b)
	}
	if b := NetworkBase("zeek_unknown"); !reflect.DeepEqual(b, zeekTupleBase) {
		t.Errorf("unknown log base = %v", b)
	}
	// The base is a copy: changing it leaves the next one as it was.
	NetworkBase("zeek_rdp")["cookie"] = "changed"
	if NetworkBase("zeek_rdp")["cookie"] != "alice" {
		t.Error("base shared")
	}
}

// A DNS rule's events name who asked and the resolver; a firewall rule's
// are connections.
func TestNetworkCasesDNSFirewall(t *testing.T) {
	now := time.Now().Add(-time.Hour)
	r := mustParse(t, "title: t\nlogsource: {category: dns}\ndetection:\n  sel:\n    query|endswith: '.evil.example'\n  condition: sel\n")
	syn := &Synthesis{Positive: []map[string]string{{"query": "a.evil.example"}, {"query": "a.evil.example"}}, Negative: []map[string]string{{"query": "ok.example"}}}
	cs := NetworkCases(r, "dns", syn)
	if len(cs) != 2 || !cs[0].Expect || cs[1].Expect {
		t.Fatalf("cases = %+v", cs)
	}
	if cs[0].Data["src_ip"] != NetworkBases["dns"]["src_ip"] || cs[0].EventID != "dns" || cs[0].Channel != "zeek:dns" {
		t.Errorf("dns case = %+v", cs[0])
	}
	ev := cs[0].Stored("nsm-1", now)
	if ev.Model != "Network_Resolution" || ev.Fields["query"] != "a.evil.example" {
		t.Errorf("dns stored = %s %v", ev.Model, ev.Fields)
	}

	fw := mustParse(t, "title: t\nlogsource: {category: firewall}\ndetection:\n  sel:\n    dst_port: 4444\n  condition: sel\n")
	cs = NetworkCases(fw, "firewall", &Synthesis{Positive: []map[string]string{merge(NetworkBases["firewall"], map[string]string{"dst_port": "4444"})}})
	if len(cs) != 1 {
		t.Fatalf("firewall = %+v", cs)
	}
	_, rec := cs[0].Record("nsm-1", now)
	var line map[string]any
	if err := json.Unmarshal([]byte(rec["log"].(string)), &line); err != nil {
		t.Fatal(err)
	}
	if line["conn_state"] != "SF" || line["id.resp_p"] != float64(4444) || line["proto"] != "tcp" || line["_path"] != "conn" {
		t.Errorf("firewall line = %v", line)
	}
	if ev := cs[0].Stored("nsm-1", now); ev.Model != "Network_Traffic" || ev.Fields["dest_port"] != int64(4444) {
		t.Errorf("firewall stored = %s %v", ev.Model, ev.Fields)
	}
	// An error from the rule leaves the event out.
	bad := mustParse(t, "title: t\ndetection:\n  sel: {query|re: '('}\n  condition: sel\n")
	if cs := NetworkCases(bad, "dns", syn); len(cs) != 0 {
		t.Errorf("cases of a broken rule: %+v", cs)
	}
}

// A proxy event's address is made whole, as a sensor logs it.
func TestFullURI(t *testing.T) {
	for _, c := range []struct {
		in, want map[string]string
	}{
		{map[string]string{"cs-host": "x"}, map[string]string{"cs-host": "x"}},
		{map[string]string{"c-uri": "/a"}, map[string]string{"c-uri": "http://downloads.example.com/a", "cs-host": "downloads.example.com"}},
		{map[string]string{"c-uri": "a", "r-dns": "r.example"}, map[string]string{"c-uri": "http://r.example/a", "r-dns": "r.example"}},
		{map[string]string{"c-uri-stem": "/p", "c-uri-query": "q=1", "cs-host": "h.example"},
			map[string]string{"c-uri": "http://h.example/p?q=1", "c-uri-stem": "/p", "c-uri-query": "q=1", "cs-host": "h.example"}},
		{map[string]string{"c-uri-stem": "", "cs-host": "h.example"}, map[string]string{"c-uri": "http://h.example/", "c-uri-stem": "/", "cs-host": "h.example"}},
		{map[string]string{"c-uri": "https://s.example", "c-uri-stem": "x"}, map[string]string{"c-uri": "https://s.example", "c-uri-stem": "/"}},
	} {
		ev := map[string]string{}
		for k, v := range c.in {
			ev[k] = v
		}
		fullURI(ev)
		if !reflect.DeepEqual(ev, c.want) {
			t.Errorf("fullURI(%v) = %v, want %v", c.in, ev, c.want)
		}
	}
	if h, ok := hostOf("https://a.example/x"); !ok || h != "a.example" {
		t.Errorf("hostOf = %s %v", h, ok)
	}
	if _, ok := hostOf("http:///x"); ok {
		t.Error("host of an address without one")
	}
	if _, ok := hostOf("/x"); ok {
		t.Error("host of a path")
	}
}

// Zeek writes numbers, booleans and lists as JSON of their own types.
func TestZeekValues(t *testing.T) {
	for _, c := range []struct {
		k, v string
		want any
	}{
		{"id.resp_p", "53", int64(53)},
		{"id.resp_p", "x", "x"},
		{"AA", "true", true},
		{"AA", "maybe", "maybe"},
		{"answers", "192.0.2.1", []any{"192.0.2.1"}},
		{"query", "q", "q"},
	} {
		if got := zeekValue(c.k, c.v); !reflect.DeepEqual(got, c.want) {
			t.Errorf("zeekValue(%s, %s) = %#v", c.k, c.v, got)
		}
	}
	// A proxy request's Host header is its address's server; the path of a
	// split address is left to the parser.
	now := time.Now().Add(-time.Hour)
	c := Case{Channel: "zeek:http", EventID: "proxy", Data: map[string]string{"c-uri": "http://h.example/a", "c-uri-stem": "/a", "X-Custom": "v"}}
	tag, rec := c.Record("nsm-1", now)
	if tag != "zeek.http" {
		t.Errorf("tag = %s", tag)
	}
	log := rec["log"].(string)
	if !strings.Contains(log, `"host":"h.example"`) || strings.Contains(log, "c-uri-stem") || !strings.Contains(log, `"X-Custom":"v"`) {
		t.Errorf("proxy line = %s", log)
	}
}
