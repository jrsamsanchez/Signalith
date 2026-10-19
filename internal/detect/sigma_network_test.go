// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package detect

import (
	"strings"
	"testing"
)

// TestSigmaNetworkScope: a Zeek rule reads its own log, a dns rule the
// lookups that name who asked, a proxy rule leaves web servers' access
// logs out, and a Zeek http rule's uri is the path.
func TestSigmaNetworkScope(t *testing.T) {
	for _, c := range []struct{ logsource, detection, want string }{
		{"product: zeek\n  service: http", "sel:\n    uri|startswith: '/admin'", `datamodel=Web sourcetype=zeek:http uri_path=/admin*`},
		{"category: dns", "sel:\n    query: 'api.telegram.org'", `datamodel=Network_Resolution src=* query=api.telegram.org`},
		{"category: proxy", "sel:\n    c-useragent: 'rclone/v*'", `datamodel=Web NOT sourcetype IN (apache:access, nginx:access) http_user_agent=rclone/v*`},
		{"category: firewall", "sel:\n    dst_port: 4444", `datamodel=Network_Traffic dest_port=4444`},
	} {
		src := "title: T\nid: 6f0e7c2a-1111-4c3e-9d6b-2a1b3c4d5e6f\nstatus: test\nlevel: high\nlogsource:\n  " + c.logsource +
			"\ndetection:\n  " + c.detection + "\n  condition: sel\n"
		res, err := ConvertSigma([]byte(src))
		if err != nil {
			t.Fatalf("%s: %v", c.logsource, err)
		}
		if got := strings.TrimSpace(res.Detection.Query); got != c.want {
			t.Errorf("%s:\n got %s\nwant %s", c.logsource, got, c.want)
		}
	}
}

// TestNetworkPackKeys: a certificate rule's risk is on the sensor that saw
// it (x509 has no client), and network DNS rules count only lookups that
// name who asked.
func TestNetworkPackKeys(t *testing.T) {
	_, ds, err := Packs()
	if err != nil {
		t.Fatal(err)
	}
	seen := 0
	for _, d := range ds {
		switch d.ID {
		case "sigma-zeek-default-cobalt-strike-certificate":
			seen++
			if len(d.Risk.Objects) != 1 || d.Risk.Objects[0].Field != "host" {
				t.Errorf("%s: risk objects %+v", d.ID, d.Risk.Objects)
			}
		case "splunk-ngrok-reverse-proxy-on-network", "sigma-net-dns-susp-telegram-api":
			seen++
			if !strings.Contains(d.Query, " src=* ") {
				t.Errorf("%s: %s", d.ID, d.Query)
			}
		}
	}
	if seen != 3 {
		t.Errorf("found %d of the 3 rules", seen)
	}
}
