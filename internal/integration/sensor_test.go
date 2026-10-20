// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package integration

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/ingest"
)

// TestNetworkSensorEndToEnd sends Zeek and Suricata lines the way the
// sensor's Fluent Bit does ({"log": "<line>"} under the zeek.* and
// suricata.eve tags) through the real pipeline into OpenSearch, searches
// the network data models, and sends the same batch again: nothing is
// stored twice.
func TestNetworkSensorEndToEnd(t *testing.T) {
	cl, eng, prefix := setup(t)
	ctx := context.Background()
	p := &ingest.Pipeline{Store: cl, Prefix: prefix}
	now := time.Now().Add(-10 * time.Minute).UTC()
	ts := float64(now.UnixMicro()) / 1e6
	eveTS := now.Format("2006-01-02T15:04:05.000000-0700")

	zeek := map[string][]string{
		"conn": {
			fmt.Sprintf(`{"ts":%.6f,"uid":"CHhAvVGS1DHFjwGM9","id.orig_h":"192.168.10.21","id.orig_p":51522,"id.resp_h":"198.51.100.120","id.resp_p":443,"proto":"tcp","service":"ssl","duration":0.4,"orig_bytes":1520,"resp_bytes":48210,"conn_state":"SF","local_orig":true,"local_resp":false,"orig_pkts":14,"resp_pkts":38,"community_id":"1:LQU9qZlK+B5F3KDmev6m5PMibrg="}`, ts),
			fmt.Sprintf(`{"ts":%.6f,"uid":"C4J4Th3PJpwUYZZ6gc","id.orig_h":"192.168.10.21","id.orig_p":51530,"id.resp_h":"203.0.113.80","id.resp_p":8443,"proto":"tcp","duration":0.2,"orig_bytes":0,"resp_bytes":0,"conn_state":"S0","local_orig":true,"local_resp":false}`, ts+1),
		},
		"dns": {
			fmt.Sprintf(`{"ts":%.6f,"uid":"CdJ7Sb2CbbpjM1ixyb","id.orig_h":"192.168.10.21","id.orig_p":53211,"id.resp_h":"192.168.10.1","id.resp_p":53,"proto":"udp","query":"nosuch.example","qtype_name":"A","rcode":3,"rcode_name":"NXDOMAIN"}`, ts+2),
		},
		"http": {
			fmt.Sprintf(`{"ts":%.6f,"uid":"CxQ4aX1Vd9iO0hY8ub","id.orig_h":"192.168.10.21","id.orig_p":51600,"id.resp_h":"198.51.100.130","id.resp_p":80,"method":"GET","host":"www.example.org","uri":"/missing?x=1","user_agent":"curl/8.5.0","status_code":404,"response_body_len":162}`, ts+3),
		},
	}
	eve := []string{
		fmt.Sprintf(`{"timestamp":"%s","flow_id":1805461738637437123,"event_type":"alert","src_ip":"203.0.113.80","src_port":80,"dest_ip":"192.168.10.21","dest_port":49822,"proto":"TCP","alert":{"action":"allowed","gid":1,"signature_id":2014520,"rev":7,"signature":"ET INFO EXE - Served Attached HTTP","category":"Misc activity","severity":1},"payload":"TVqQAAMAAAAEAAAA","app_proto":"http"}`, eveTS),
		fmt.Sprintf(`{"timestamp":"%s","flow_id":1805461738637437124,"event_type":"alert","src_ip":"192.168.10.21","src_port":49900,"dest_ip":"198.51.100.9","dest_port":80,"proto":"TCP","alert":{"action":"allowed","gid":1,"signature_id":2013028,"rev":3,"signature":"ET POLICY curl User-Agent Outbound","category":"Attempted Information Leak","severity":3}}`, eveTS),
	}

	send := func() (dups, indexed int) {
		t.Helper()
		for log, lines := range zeek {
			var recs []map[string]any
			for _, l := range lines {
				recs = append(recs, map[string]any{"log": l, "hostname": "nsm-01"})
			}
			res, err := p.Ingest(ctx, "zeek.opt.zeek.logs.current."+log+".log", recs)
			if err != nil || len(res.Errors) > 0 {
				t.Fatalf("zeek %s: %v %+v", log, err, res)
			}
			dups += res.Duplicates
			indexed += res.Indexed
		}
		var recs []map[string]any
		for _, l := range eve {
			recs = append(recs, map[string]any{"log": l, "hostname": "nsm-01"})
		}
		res, err := p.Ingest(ctx, "suricata.eve", recs)
		if err != nil || len(res.Errors) > 0 {
			t.Fatalf("suricata: %v %+v", err, res)
		}
		if err := cl.Do(ctx, http.MethodPost, "/"+prefix+"-*/_refresh", nil, nil); err != nil {
			t.Fatal(err)
		}
		return dups + res.Duplicates, indexed + res.Indexed
	}
	const total = 6
	if dups, n := send(); dups != 0 || n != total {
		t.Fatalf("first send: %d duplicates, %d indexed", dups, n)
	}

	count := func(q string) int64 {
		t.Helper()
		res := run(t, eng, q+" | stats count")
		if len(res.Rows) != 1 {
			t.Fatalf("%s: rows %v", q, res.Rows)
		}
		n, _ := res.Rows[0]["count"].(int64)
		return n
	}
	for q, want := range map[string]int64{
		"datamodel=Intrusion_Detection severity=high":                        1,
		"datamodel=Intrusion_Detection":                                      2,
		"datamodel=Network_Traffic duration>0.3":                             1,
		"datamodel=Network_Traffic action=failed":                            1,
		"datamodel=Network_Traffic direction=outbound bytes_out>1000":        1,
		"datamodel=Web status=404":                                           1,
		"datamodel=Network_Resolution reply_code=NXDomain src=192.168.10.21": 1,
		"vendor_product IN (Zeek, Suricata) host=nsm-01":                     total,
		`datamodel=Intrusion_Detection session_id="1805461738637437123"`:     1,
	} {
		if got := count(q); got != want {
			t.Errorf("%s: %d, want %d", q, got, want)
		}
	}
	// The payload never reaches OpenSearch, not even in _raw.
	if got := count(`datamodel=Intrusion_Detection "TVqQAAMAAAAEAAAA"`); got != 0 {
		t.Errorf("payload stored: %d", got)
	}

	// Fluent Bit sends the batch again after a 503: every line is a
	// duplicate and nothing new is stored.
	if dups, _ := send(); dups != total {
		t.Errorf("resend: %d duplicates, want %d", dups, total)
	}
	if got := count("vendor_product IN (Zeek, Suricata)"); got != total {
		t.Errorf("after the resend: %d events, want %d", got, total)
	}

	// duration is a decimal and status text in the index mapping.
	var m map[string]struct {
		Mappings struct {
			Properties map[string]struct {
				Type string `json:"type"`
			} `json:"properties"`
		} `json:"mappings"`
	}
	day := now.Format("2006.01.02")
	for _, c := range []struct{ index, field, want string }{
		{prefix + "-network_traffic-" + day, "duration", "double"},
		{prefix + "-web-" + day, "status", "keyword"},
		{prefix + "-network_traffic-" + day, "bytes_out", "long"},
	} {
		m = nil
		if err := cl.Do(ctx, http.MethodGet, "/"+c.index+"/_mapping", nil, &m); err != nil {
			t.Fatal(err)
		}
		if got := m[c.index].Mappings.Properties[c.field].Type; got != c.want {
			t.Errorf("%s %s is %q, want %q", c.index, c.field, got, c.want)
		}
	}
}
