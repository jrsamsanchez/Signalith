// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package intel

import (
	"slices"
	"strings"
	"testing"
	"time"
)

// Samples in each catalog feed's real layout: comment styles, trailing
// comments, line endings and the mix of values each one publishes.
var catalogSamples = map[string]struct {
	body     string
	want     string // type:value list, in order
	skipped  int
	reserved int
}{
	"feodo-tracker": {
		body: "################################################################\r\n" +
			"# abuse.ch Feodo Tracker Botnet C2 IP Blocklist (IPs only)     #\r\n" +
			"# Last updated: 2026-10-12 10:05:13 UTC                        #\r\n" +
			"#                                                              #\r\n" +
			"# Terms Of Use: https://feodotracker.abuse.ch/blocklist/       #\r\n" +
			"# For questions please contact feodotracker [at] abuse.ch      #\r\n" +
			"################################################################\r\n" +
			"#\r\n# DstIP\r\n203.0.113.9\r\n198.51.100.77\r\n# END 2 entries\r\n",
		want: "ip:203.0.113.9 ip:198.51.100.77",
	},
	"urlhaus": {
		body: "################################################################\r\n" +
			"# abuse.ch URLhaus Database Dump (TXT - recent URLs only)       #\r\n" +
			"# Last updated: 2026-10-12 10:05:03 (UTC)                      #\r\n" +
			"#                                                              #\r\n" +
			"# Terms Of Use: https://urlhaus.abuse.ch/api/                  #\r\n" +
			"################################################################\r\n" +
			"#\r\n" +
			"http://203.0.113.155:51352/i\r\n" +
			"http://198.51.100.14:44551/bin.sh\r\n" +
			"https://bad.example/wp-content/a;b,c.php?id=1,2\r\n",
		want: "url:http://203.0.113.155:51352/i url:http://198.51.100.14:44551/bin.sh url:https://bad.example/wp-content/a;b,c.php?id=1,2",
	},
	"malwarebazaar": {
		body: "################################################################\n" +
			"# MalwareBazaar recent malware samples (SHA256 hashes)         #\n" +
			"# Last updated: 2026-10-12 10:00:35 UTC                        #\n" +
			"#                                                              #\n" +
			"# Terms Of Use: https://bazaar.abuse.ch/faq/#tos               #\n" +
			"################################################################\n" +
			"#\n# sha256_hash\n" +
			strings.Repeat("a", 64) + "\n" + strings.Repeat("B", 64) + "\n# Number of entries: 2\n",
		want: "sha256:" + strings.Repeat("a", 64) + " sha256:" + strings.Repeat("b", 64),
	},
	"et-compromised": {
		body: "203.0.113.20\n198.51.100.21\n\n203.0.113.22\n",
		want: "ip:203.0.113.20 ip:198.51.100.21 ip:203.0.113.22",
	},
	"spamhaus-drop": {
		body: "; Spamhaus DROP List 2026/10/12 - (c) 2026 The Spamhaus Project SLU\n" +
			"; https://www.spamhaus.org/drop/drop.txt\n" +
			"; Last-Modified: Sun, 12 Oct 2026 08:11:44 GMT\n" +
			"; Expires: Sun, 12 Oct 2026 20:20:43 GMT\n" +
			"198.51.100.0/24 ; SBL256894\n203.0.112.0/22 ; SBL434604\n",
		want: "cidr:198.51.100.0/24 cidr:203.0.112.0/22",
	},
	"openphish": {
		body: "https://login-secure.example/signin\nhttp://bad.example/office365/index.php?email=a@b.example\n",
		want: "url:https://login-secure.example/signin url:http://bad.example/office365/index.php?email=a@b.example",
	},
	"cins-army": {
		body: "203.0.113.30\n203.0.113.31\n198.51.100.32\n",
		want: "ip:203.0.113.30 ip:203.0.113.31 ip:198.51.100.32",
	},
	"blocklist-de": {
		body: "203.0.113.40\n2001:db8::40\n198.51.100.41\n",
		want: "ip:203.0.113.40 ip:2001:db8::40 ip:198.51.100.41",
	},
	"firehol-level1": {
		body: "#\n# firehol_level1\n#\n# ipv4 hash:net ipset\n#\n" +
			"# A firewall blacklist composed from IP lists, providing\n" +
			"# maximum protection with minimum false positives.\n#\n" +
			"# Maintainer      : FireHOL\n# Entries         : 4517 subnets, 610000000 unique IPs\n#\n" +
			"0.0.0.0/8\n10.0.0.0/8\n100.64.0.0/10\n127.0.0.0/8\n169.254.0.0/16\n172.16.0.0/12\n192.168.0.0/16\n224.0.0.0/3\n" +
			"192.0.2.0/24\n198.51.100.7\n203.0.112.0/21\n",
		want:     "cidr:192.0.2.0/24 ip:198.51.100.7 cidr:203.0.112.0/21",
		reserved: 8,
	},
	"tor-exits": {
		body: "203.0.113.50\n203.0.113.51\n",
		want: "ip:203.0.113.50 ip:203.0.113.51",
	},
}

func TestCatalogEntries(t *testing.T) {
	ids := map[string]bool{}
	recommended := 0
	for _, e := range Catalog {
		if ids[e.ID] {
			t.Errorf("%s: duplicate id", e.ID)
		}
		ids[e.ID] = true
		// Every entry passes the same checks as a configured feed.
		spec := e.Spec()
		spec.Defaults()
		if p := spec.Problems(false); len(p) > 0 {
			t.Errorf("%s: %v", e.ID, p)
		}
		if iv, _ := ParseDuration(e.Interval); iv < 30*time.Minute {
			t.Errorf("%s: interval %s is below 30m", e.ID, e.Interval)
		}
		if e.Title == "" || e.Provider == "" || !strings.HasPrefix(e.Homepage, "https://") {
			t.Errorf("%s: title, provider and an https homepage are required", e.ID)
		}
		if !strings.HasSuffix(e.Description, ".") || strings.Contains(strings.TrimSuffix(e.Description, "."), ". ") {
			t.Errorf("%s: description must be one sentence: %q", e.ID, e.Description)
		}
		if e.NeedsKey && (e.KeyHeader == "" || e.KeyHelp == "") {
			t.Errorf("%s: a feed that needs a key must say which header and where to get one", e.ID)
		}
		if e.Recommended {
			recommended++
		}
		if _, ok := catalogSamples[e.ID]; !ok {
			t.Errorf("%s: no parser sample", e.ID)
		}
	}
	if recommended < 3 || recommended > 6 {
		t.Errorf("%d recommended feeds; keep the one-click set small", recommended)
	}
}

func TestCatalogSamplesParse(t *testing.T) {
	for _, e := range Catalog {
		sample, ok := catalogSamples[e.ID]
		if !ok {
			continue
		}
		for _, format := range []string{e.Format, FormatAuto} {
			res, err := Parse([]byte(sample.body), ParseOptions{Format: format, Type: e.Type, Column: e.Column})
			if err != nil {
				t.Errorf("%s (%s): %v", e.ID, format, err)
				continue
			}
			if got := values(res.Indicators); got != sample.want || res.Skipped != sample.skipped || res.Reserved != sample.reserved {
				t.Errorf("%s (%s):\n got %s (skipped %d %q, reserved %d)\nwant %s (skipped %d, reserved %d)",
					e.ID, format, got, res.Skipped, res.Example, res.Reserved, sample.want, sample.skipped, sample.reserved)
			}
			if res.Format != e.Format {
				t.Errorf("%s: read as %s, want %s", e.ID, res.Format, e.Format)
			}
		}
	}
}

func TestSniff(t *testing.T) {
	urlhausCSV := "################################################################\n" +
		"# abuse.ch URLhaus Database Dump (CSV - recent URLs only)       #\n" +
		"################################################################\n#\n" +
		"# id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter\n" +
		`"3311","2026-10-11 10:00:00","http://bad.example/x.sh","online","2026-10-11 10:00:00","malware_download","elf","https://urlhaus.abuse.ch/url/3311/","r"` + "\n" +
		`"3312","2026-10-11 10:01:00","http://other.example/y","online","","malware_download","","https://urlhaus.abuse.ch/url/3312/",""` + "\n"
	feodoCSV := "first_seen_utc,dst_ip,dst_port,c2_status,last_online,malware\r\n" +
		"2026-10-01 10:00:00,203.0.113.9,443,online,2026-10-12,QakBot\r\n" +
		"2026-10-02 10:00:00,198.51.100.4,8080,offline,2026-10-10,Pikabot\r\n"
	noNames := "a,b,c\nx,203.0.113.1,y\nz,203.0.113.2,w\n"
	cases := []struct {
		name, data, typ, column, format, wantCol string
	}{
		{"stix bundle", `{"type":"bundle","id":"bundle--1","objects":[]}`, "auto", "", FormatSTIX, ""},
		{"taxii envelope", ` {"more":false,"objects":[{"type":"indicator"}]}`, "auto", "", FormatSTIX, ""},
		{"stix array", `[{"type":"indicator","pattern":"[ipv4-addr:value = '192.0.2.5']"}]`, "auto", "", FormatSTIX, ""},
		{"other json", `{"data":[1,2,3]}`, "auto", "", FormatLines, ""},
		{"urlhaus csv", urlhausCSV, "auto", "", FormatCSV, "url"},
		{"feodo csv", feodoCSV, "auto", "", FormatCSV, "dst_ip"},
		{"column kept", feodoCSV, "auto", "malware", FormatCSV, "malware"},
		{"number for unnamed duplicates", "ip,ip\n203.0.113.1,x\n203.0.113.2,y\n", "auto", "", FormatCSV, "1"},
		{"header without indicators", noNames, "auto", "", FormatCSV, "b"},
		{"value,comment list", "203.0.113.1,scanner\n203.0.113.2,botnet\n", "auto", "", FormatLines, ""},
		{"plain list", "# list\n203.0.113.1\n", "auto", "", FormatLines, ""},
		{"spamhaus", "; DROP\n198.51.100.0/24 ; SBL1\n", "auto", "", FormatLines, ""},
		{"title with a comma", "Bad IPs, updated daily\n203.0.113.1\n203.0.113.2\n", "auto", "", FormatLines, ""},
		{"web page", "<!DOCTYPE html><html><body>Not here</body></html>", "auto", "", FormatLines, ""},
		// Dotted column names (Elastic ECS, OpenCTI) read as domain names.
		{"ecs columns", "source.ip,destination.ip,url.domain\n203.0.113.1,198.51.100.2,evil.example\n203.0.113.3,198.51.100.4,bad.example\n", "auto", "", FormatCSV, "source.ip"},
		{"ecs domain columns", "url.domain,dns.question.name\nevil.example,bad.example\nx.example,y.example\n", "auto", "", FormatCSV, "url.domain"},
		{"ecs hash column", "file.name,file.hash.sha256\nx.exe," + strings.Repeat("a", 64) + "\ny.dll," + strings.Repeat("b", 64) + "\n", "auto", "", FormatCSV, "file.hash.sha256"},
		{"domains without a header", "evil.example,bad.example\nx.example,y.example\n", "auto", "", FormatLines, ""},
		{"domain and word rows", "evil.example,botnet\nbad.example,phishing\n", "auto", "", FormatLines, ""},
	}
	for _, c := range cases {
		format, col := Sniff([]byte(c.data), c.typ, c.column)
		if format != c.format || col != c.wantCol {
			t.Errorf("%s: Sniff = %s %q, want %s %q", c.name, format, col, c.format, c.wantCol)
		}
	}
	// Auto parses with what it detected and says so.
	res, err := Parse([]byte(urlhausCSV), ParseOptions{Format: FormatAuto, Type: "auto"})
	if err != nil || res.Format != FormatCSV || res.Column != "url" || values(res.Indicators) != "url:http://bad.example/x.sh url:http://other.example/y" {
		t.Errorf("auto urlhaus = %+v %v", res, err)
	}
	// The header cell of a dotted column is never an indicator.
	res, err = Parse([]byte(cases[len(cases)-5].data), ParseOptions{Format: FormatAuto, Type: "auto"})
	if err != nil || values(res.Indicators) != "ip:203.0.113.1 ip:203.0.113.3" {
		t.Errorf("auto ecs = %+v %v", res, err)
	}
}

func TestSuggestType(t *testing.T) {
	cases := []struct {
		by   map[string]int
		want string
	}{
		{map[string]int{}, "auto"},
		{map[string]int{TypeIP: 5}, TypeIP},
		{map[string]int{TypeCIDR: 5}, TypeCIDR},
		{map[string]int{TypeIP: 5, TypeCIDR: 2}, TypeIP},
		{map[string]int{TypeSHA256: 3}, TypeSHA256},
		{map[string]int{TypeSHA256: 3, TypeMD5: 1}, "hash"},
		{map[string]int{TypeURL: 3, TypeDomain: 1}, "auto"},
	}
	for _, c := range cases {
		if got := SuggestType(c.by); got != c.want {
			t.Errorf("SuggestType(%v) = %s, want %s", c.by, got, c.want)
		}
	}
}

func TestReservedNetworks(t *testing.T) {
	for _, v := range []string{"10.1.2.3", "192.168.0.0/16", "172.20.0.0/16", "127.0.0.1", "169.254.169.254", "0.0.0.0/8",
		"224.0.0.0/3", "100.64.1.1", "255.255.255.255", "::1", "fd00::/8", "fe80::1", "ff02::1", "0.0.0.0/0", "128.0.0.0/1", "2000::/3"} {
		if !reservedNet(v) {
			t.Errorf("%s should be skipped", v)
		}
	}
	for _, v := range []string{"203.0.113.9", "198.51.100.0/24", "8.0.0.0/8", "2001:db8::1", "2a00::/16"} {
		if reservedNet(v) {
			t.Errorf("%s should be kept", v)
		}
	}
	// Manual indicators are not filtered: someone may list an internal
	// host on purpose.
	if ind, err := (Input{Value: "10.1.2.3"}).Build(time.Now()); err != nil || ind.Value != "10.1.2.3" {
		t.Errorf("manual private address = %+v %v", ind, err)
	}
	// But a network so broad it would match most of the internet is
	// refused, by hand and in an upload, as feeds skip it.
	for _, v := range []string{"0.0.0.0/0", "::/0", "128.0.0.0/1", "0.0.0.0/7", "2000::/3", "::ffff:0.0.0.0/96"} {
		if ind, err := (Input{Value: v}).Build(time.Now()); err == nil || !strings.Contains(err.Error(), "too broad") {
			t.Errorf("manual %s = %+v %v, want refused as too broad", v, ind, err)
		}
	}
	for _, v := range []string{"10.0.0.0/8", "8.0.0.0/8", "2a00::/16", "fd12::/16"} {
		if _, err := (Input{Value: v, Type: TypeCIDR}).Build(time.Now()); err != nil {
			t.Errorf("manual %s refused: %v", v, err)
		}
	}
	if _, err := ParseUpload(strings.NewReader("203.0.113.9\n0.0.0.0/0\n"), time.Now()); err == nil || !strings.Contains(err.Error(), "line 2: network 0.0.0.0/0 is too broad") {
		t.Errorf("upload with 0.0.0.0/0 = %v, want refused", err)
	}
	if !slices.Contains(FeedTypes, TypeCIDR) {
		t.Error("cidr must be a feed type")
	}
}
