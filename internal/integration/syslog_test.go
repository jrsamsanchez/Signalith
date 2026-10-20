// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package integration

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/ingest"
	"github.com/jrsamsanchez/signalith/internal/syslog"
)

// TestSyslogEndToEnd sends syslog over UDP and TCP to a running receiver
// and finds the events with searches against OpenSearch.
func TestSyslogEndToEnd(t *testing.T) {
	cl, eng, prefix := setup(t)
	p := &ingest.Pipeline{Store: cl, Prefix: prefix}
	r := syslog.New(syslog.Config{UDP: "127.0.0.1:0", TCP: "127.0.0.1:0", FlushInterval: 100 * time.Millisecond}, p, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := r.Start(ctx); err != nil {
		t.Fatal(err)
	}
	addrs := map[string]string{}
	for _, l := range r.Stats().Listeners {
		addrs[l.Protocol] = l.Address
	}

	stamp := time.Now().UTC().Add(-time.Minute).Format(time.RFC3339)
	udp, err := net.Dial("udp", addrs["udp"])
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		fmt.Fprintf(udp, "<38>%s web7 sshd[%d]: Failed password for invalid user oracle from 203.0.113.77 port %d ssh2",
			syslogTime(time.Now().Add(-time.Minute)), 4000+i, 50000+i)
	}
	fmt.Fprintf(udp, "<134>1 %s fw1 - - - - CEF:0|Acme|Firewall|1.0|100|Blocked connection|7|src=10.0.0.5 dst=198.51.100.9 spt=40000 dpt=4444 proto=TCP act=deny", stamp)
	// A replayed or forged old timestamp must not create an index for its day.
	fmt.Fprint(udp, "<13>1 2001-01-01T12:00:00Z oldhost app - - - replayed")
	udp.Close()
	tcp, err := net.Dial("tcp", addrs["tcp"])
	if err != nil {
		t.Fatal(err)
	}
	msg := fmt.Sprintf("<86>1 %s web7 useradd 900 - - new user: name=syslogged, UID=1003, GID=1003, home=/home/syslogged, shell=/bin/bash", stamp)
	fmt.Fprintf(tcp, "%d %s", len(msg), msg)
	tcp.Close()

	deadline := time.Now().Add(30 * time.Second)
	for p.Stats().Indexed < 6 {
		if time.Now().After(deadline) {
			t.Fatalf("indexed %+v, receiver %+v", p.Stats(), r.Stats())
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err := cl.Do(ctx, http.MethodPost, "/"+prefix+"-*/_refresh", nil, nil); err != nil {
		t.Fatal(err)
	}

	res := run(t, eng, `sourcetype=syslog datamodel=Authentication src=203.0.113.77 | stats count by user, host, dvc`)
	if len(res.Rows) != 1 || res.Rows[0]["count"] != int64(3) || res.Rows[0]["user"] != "oracle" || res.Rows[0]["host"] != "web7" || res.Rows[0]["dvc"] != "127.0.0.1" {
		t.Errorf("auth rows = %v", res.Rows)
	}
	if res := run(t, eng, `datamodel=Change object=syslogged`); res.Matched != 1 {
		t.Errorf("change matched %d", res.Matched)
	}
	res = run(t, eng, `datamodel=Network_Traffic sourcetype=cef dest_port=4444 action=blocked`)
	if res.Matched != 1 || res.Rows[0]["src"] != "10.0.0.5" || res.Rows[0]["vendor_product"] != "Acme Firewall" || res.Rows[0]["severity"] != "high" {
		t.Errorf("cef rows = %v", res.Rows)
	}
	if res := run(t, eng, `"invalid user oracle" facility=auth severity=informational`); res.Matched != 3 {
		t.Errorf("text search matched %d", res.Matched)
	}

	res = run(t, eng, `host=oldhost`)
	if res.Matched != 1 || res.Rows[0]["device_time"] != "2001-01-01T12:00:00Z" {
		t.Errorf("old message rows = %v", res.Rows)
	}
	names, err := cl.ListIndices(ctx, prefix+"-*")
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range names {
		if strings.Contains(n, "2001.") {
			t.Errorf("index %s created for the old timestamp", n)
		}
	}

	cancel()
	r.Wait()
	if s := r.Stats(); s.Received != 6 || s.Dropped != 0 || s.WriteFailed != 0 {
		t.Errorf("receiver stats = %+v", s)
	}
}
