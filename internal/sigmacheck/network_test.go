// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package sigmacheck

import (
	"testing"
	"time"
)

// A generic proxy rule's events are written as http.log lines, with the
// whole address the sensor logs, and a Zeek rule's by Zeek's own keys.
func TestNetworkCases(t *testing.T) {
	r, err := Parse([]byte(`title: t
id: 00000000-0000-0000-0000-000000000001
logsource: {category: proxy}
detection:
  selection:
    c-uri|contains: '/pwndrop/'
    c-useragent|startswith: 'curl/'
  condition: selection
level: high
`))
	if err != nil {
		t.Fatal(err)
	}
	syn, err := r.Synthesize(1, NetworkBase("proxy"))
	if err != nil {
		t.Fatal(err)
	}
	cases := NetworkCases(r, "proxy", syn)
	positives := 0
	for _, c := range cases {
		if c.Channel != "zeek:http" || c.EventID != "proxy" {
			t.Fatalf("case %+v", c)
		}
		ev := c.Stored("nsm-01", time.Unix(1_800_000_000, 0))
		if ev.Model != "Web" || ev.Fields["host"] != "nsm-01" {
			t.Errorf("stored %s %v", ev.Model, ev.Fields)
		}
		if c.Expect {
			positives++
			if ev.Fields["url"] != c.Data["c-uri"] {
				t.Errorf("url %v, Sigma's c-uri %q", ev.Fields["url"], c.Data["c-uri"])
			}
		}
	}
	if positives == 0 {
		t.Fatal("no positive case")
	}

	c := Case{Expect: true, Channel: NetworkChannel("zeek_smb_files"), Data: map[string]string{"name": `\PIPE\atsvc`, "id.resp_h": "192.0.2.20", "id.resp_p": "445"}}
	ev := c.Stored("nsm-01", time.Unix(1_800_000_000, 0))
	if ev.Fields["sourcetype"] != "zeek:smb_files" || ev.Fields["zeek_name"] != `\PIPE\atsvc` || ev.Fields["dest_port"] != int64(445) {
		t.Errorf("smb_files: %v", ev.Fields)
	}
}
