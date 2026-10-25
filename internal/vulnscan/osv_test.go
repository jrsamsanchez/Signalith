// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package vulnscan

import (
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/endpoint"
)

// Advisories as OSV.dev publishes them, cut down to the parts read.
const (
	// A Debian CVE record: one entry per release, by source package.
	osvDebianCVE = `{"id":"CVE-2023-38408","published":"2023-07-20T03:15:10Z",
	"details":"The PKCS#11 feature in ssh-agent in OpenSSH before 9.3p2 has an insufficiently trustworthy search path, leading to remote code execution. More text.",
	"related":["ALSA-2023:4419","USN-6242-1"],
	"severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
	"affected":[
	 {"package":{"name":"openssh","ecosystem":"Debian:11"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1:8.4p1-5+deb11u2"}]}]},
	 {"package":{"name":"openssh","ecosystem":"Debian:12"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1:9.2p1-2+deb12u1"}]}],"versions":["1:9.2p1-2"]},
	 {"package":{"name":"openssh","ecosystem":"Debian:13"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1:9.3p2-1"}]}]},
	 {"package":{"name":"openssh","ecosystem":"Alpine:v3.16"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"9.0_p1-r3"}]}]}]}`
	// The Debian advisory that fixed it, naming the same CVE.
	osvDebianDSA = `{"id":"DSA-5800-1","summary":"openssh security update","upstream":["CVE-2023-38408","CVE-2024-6387"],
	"affected":[{"package":{"name":"openssh","ecosystem":"Debian:12"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1:9.2p1-2+deb12u3"}]}]}]}`
	// Not fixed in Debian 12 yet: not reported.
	osvDebianUnfixed = `{"id":"CVE-2099-0001","details":"Unfixed.","affected":[{"package":{"name":"openssh","ecosystem":"Debian:12"},
	"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"}]}],"ecosystem_specific":{"urgency":"unimportant"}}]}`
	// Withdrawn: not reported.
	osvDebianWithdrawn = `{"id":"CVE-2099-0002","withdrawn":"2024-01-01T00:00:00Z","affected":[{"package":{"name":"openssh","ecosystem":"Debian:12"},
	"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1:99-1"}]}]}]}`
	// Only in a version range: introduced after the installed version.
	osvDebianLater = `{"id":"CVE-2099-0003","details":"A bug in 1:9.5 and later.","affected":[{"package":{"name":"openssh","ecosystem":"Debian:12"},
	"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"1:9.5p1-1"},{"fixed":"1:9.6p1-1"}]}]}]}`
	// A library from its own source package; no CVSS vector, so Debian's
	// urgency rates it.
	osvDebianOpenSSL = `{"id":"CVE-2023-5678","details":"Generating excessively long X9.42 DH keys may be slow.","affected":[{"package":{"name":"openssl","ecosystem":"Debian:12"},
	"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"3.0.13-1~deb12u1"}]}],"ecosystem_specific":{"urgency":"low*"}}]}`

	osvUbuntu = `{"id":"UBUNTU-CVE-2023-38408","details":"The PKCS#11 feature in ssh-agent in OpenSSH before 9.3p2 has an insufficiently trustworthy search path.",
	"upstream":["CVE-2023-38408"],
	"affected":[
	 {"package":{"name":"openssh","ecosystem":"Ubuntu:Pro:18.04:LTS"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1:7.6p1-4ubuntu0.7+esm1"}]}],"ecosystem_specific":{"ubuntu_priority":"medium"}},
	 {"package":{"name":"openssh","ecosystem":"Ubuntu:22.04:LTS"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1:8.9p1-3ubuntu0.3"}]}],"ecosystem_specific":{"ubuntu_priority":"medium"}},
	 {"package":{"name":"openssh","ecosystem":"Ubuntu:22.04:LTS:for:NVIDIA:BlueField"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1:99"}]}]}]}`

	osvAlma = `{"id":"ALSA-2023:4419","summary":"Important: openssh security update","related":["CVE-2023-38408"],
	"details":"OpenSSH is an SSH protocol implementation.",
	"affected":[
	 {"package":{"name":"openssh","ecosystem":"AlmaLinux:8"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"8.0p1-19.el8_8"}]}]},
	 {"package":{"name":"openssh-server","ecosystem":"AlmaLinux:8"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"8.0p1-19.el8_8"}]}]},
	 {"package":{"name":"openssh-clients","ecosystem":"AlmaLinux:8"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"8.0p1-19.el8_8"}]}]}]}`
	// A bug fix names no CVE: left out.
	osvAlmaBugfix = `{"id":"ALBA-2023:1000","summary":"openssh bug fix update","affected":[{"package":{"name":"openssh","ecosystem":"AlmaLinux:8"},
	"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"8.0p1-20.el8"}]}]}]}`

	osvRocky = `{"id":"RLSA-2023:4419","summary":"Important: openssh security update","upstream":["CVE-2023-38408"],
	"severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
	"affected":[{"package":{"name":"openssh-server","ecosystem":"Rocky Linux:9"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"0:8.7p1-30.el9_2"}]}]}]}`

	osvRedHat = `{"id":"RHSA-2023:4382","upstream":["CVE-2023-38408"],"summary":"Red Hat Security Advisory: openssh security update",
	"severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
	"affected":[
	 {"package":{"name":"openssh-server","ecosystem":"Red Hat:enterprise_linux:9::baseos"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"0:8.7p1-30.el9_2"}]}]},
	 {"package":{"name":"openssh-server","ecosystem":"Red Hat:enterprise_linux:90::baseos"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"0:99-1"}]}]},
	 {"package":{"name":"openssh-server","ecosystem":"Red Hat:rhel_eus:9.0::baseos"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"0:99-1"}]}]}]}`
)

func TestEcosystemFor(t *testing.T) {
	for _, c := range []struct {
		platform, version string
		name, feed, kind  string
		ok                bool
	}{
		{"debian", "12.0", "Debian:12", "Debian:12", "deb", true},
		{"debian", "11", "Debian:11", "Debian:11", "deb", true},
		{"ubuntu", "22.4", "Ubuntu:22.04:LTS", "Ubuntu:22.04:LTS", "deb", true},
		{"ubuntu", "24.04", "Ubuntu:24.04:LTS", "Ubuntu:24.04:LTS", "deb", true},
		{"ubuntu", "24.10", "Ubuntu:24.10", "Ubuntu:24.10", "deb", true},
		{"ubuntu", "23.4", "Ubuntu:23.04", "Ubuntu:23.04", "deb", true},
		{"almalinux", "9.4", "AlmaLinux:9", "AlmaLinux", "rpm", true},
		{"rocky", "8.10", "Rocky Linux:8", "Rocky Linux", "rpm", true},
		{"rhel", "9.4", "Red Hat:enterprise_linux:9", "Red Hat", "rpm", true},
		{"centos", "9.0", "", "", "", false},
		{"amzn", "2023.0", "", "", "", false},
		{"ubuntu", "", "", "", "", false},
		{"windows", "10.0", "", "", "", false},
	} {
		e, ok := EcosystemFor(c.platform, c.version)
		if ok != c.ok || e.Name != c.name || e.Feed != c.feed || e.Kind != c.kind {
			t.Errorf("EcosystemFor(%q, %q) = %+v %v", c.platform, c.version, e, ok)
		}
	}
	rh, _ := EcosystemFor("rhel", "10.2")
	for name, want := range map[string]bool{
		"Red Hat:enterprise_linux:10::baseos": true, "Red Hat:enterprise_linux:10.2": true, "Red Hat:enterprise_linux:10": true,
		"Red Hat:enterprise_linux:1::baseos": false, "Red Hat:enterprise_linux:100": false, "Red Hat:rhel_eus:10.0::baseos": false,
	} {
		if rh.Has(name) != want {
			t.Errorf("RHEL 10 has %q = %v", name, !want)
		}
	}
	deb, _ := EcosystemFor("debian", "12")
	if deb.Has("Debian:12.1") || deb.Has("Debian:1") || !deb.Has("Debian:12") {
		t.Error("Debian 12 matches other releases")
	}
}

func index(t *testing.T, platform, version string, records ...string) *OSVIndex {
	t.Helper()
	e, ok := EcosystemFor(platform, version)
	if !ok {
		t.Fatal(platform, version)
	}
	x := NewOSVIndex(e)
	for _, r := range records {
		if err := x.Add([]byte(r)); err != nil {
			t.Fatal(err)
		}
	}
	return x
}

func TestOSVMatchDebian(t *testing.T) {
	x := index(t, "debian", "12.5", osvDebianCVE, osvDebianDSA, osvDebianUnfixed, osvDebianWithdrawn, osvDebianLater, osvDebianOpenSSL)
	if x.Advisories != 4 {
		t.Errorf("advisories = %d, want the CVE record, the DSA, the later one and openssl's", x.Advisories)
	}
	pkgs := []endpoint.Package{
		// Binary packages of the openssh source, as dpkg lists them.
		{Name: "openssh-server", Version: "1:9.2p1-2+deb12u2", Source: "openssh", Type: "deb"},
		{Name: "openssh-client", Version: "1:9.2p1-2+deb12u2", Source: "openssh", Type: "deb"},
		// The source's version differs from the binary's.
		{Name: "libssl3", Version: "3.0.11-1~deb12u2+b1", Source: "openssl (3.0.11-1~deb12u2)", Type: "deb"},
		// Fixed already.
		{Name: "openssl", Version: "3.0.13-1~deb12u1", Type: "deb"},
		{Name: "rpm-thing", Version: "1-1", Type: "rpm"},
	}
	svcs := x.Match(pkgs)
	if len(svcs) != 2 || svcs[0].Product != "openssh" || svcs[1].Product != "openssl" {
		t.Fatalf("services = %+v", svcs)
	}
	ssh := svcs[0]
	if ssh.Name != SourcePackage || ssh.Port != 0 || ssh.Version != "1:9.2p1-2+deb12u2" || ssh.Extra != "deb package" {
		t.Errorf("openssh service = %+v", ssh.Service)
	}
	// deb12u2 is past the CVE record's fix (deb12u1), but the DSA fixed
	// CVE-2023-38408 again, with CVE-2024-6387, in deb12u3.
	if len(ssh.Vulns) != 2 {
		t.Fatalf("openssh vulns = %+v", ssh.Vulns)
	}
	byCVE := map[string]Vuln{}
	for _, v := range ssh.Vulns {
		byCVE[v.CVE] = v
	}
	a := byCVE["CVE-2023-38408"]
	if a.Fixed != "1:9.2p1-2+deb12u3" || a.CVSS != 9.8 || a.Severity != "critical" || a.Source != SourcePackage || a.Ecosystem != "Debian 12" ||
		a.Advisory != "DSA-5800-1" || a.Published != "2023-07-20" || !strings.HasPrefix(a.Description, "The PKCS#11 feature") || a.Distro != "" {
		t.Errorf("CVE-2023-38408 = %+v", a)
	}
	if b := byCVE["CVE-2024-6387"]; b.Fixed != "1:9.2p1-2+deb12u3" || b.Advisory != "DSA-5800-1" || b.Severity != "unknown" {
		t.Errorf("CVE-2024-6387 = %+v", b)
	}
	ssl := svcs[1]
	if ssl.Version != "3.0.11-1~deb12u2" || len(ssl.Vulns) != 1 || ssl.Vulns[0].CVE != "CVE-2023-5678" || ssl.Vulns[0].Severity != "low" || ssl.Vulns[0].CVSS != 0 {
		t.Errorf("openssl = %+v", ssl)
	}

	// Once every fix is installed, nothing is left.
	if got := x.Match([]endpoint.Package{{Name: "openssh-server", Version: "1:9.2p1-2+deb12u3", Source: "openssh", Type: "deb"}}); len(got) != 0 {
		t.Errorf("fixed host = %+v", got)
	}
	// Debian 11's fix is not Debian 12's.
	x11 := index(t, "debian", "11", osvDebianCVE)
	if got := x11.Match([]endpoint.Package{{Name: "openssh-server", Version: "1:8.4p1-5+deb11u1", Type: "deb", Source: "openssh"}}); len(got) != 1 || got[0].Vulns[0].Fixed != "1:8.4p1-5+deb11u2" {
		t.Errorf("Debian 11 = %+v", got)
	}
}

func TestOSVMatchUbuntu(t *testing.T) {
	x := index(t, "ubuntu", "22.4", osvUbuntu)
	got := x.Match([]endpoint.Package{
		{Name: "openssh-server", Version: "1:8.9p1-3ubuntu0.1", Source: "openssh", Type: "deb"},
	})
	if len(got) != 1 || len(got[0].Vulns) != 1 {
		t.Fatalf("match = %+v", got)
	}
	v := got[0].Vulns[0]
	// UBUNTU-CVE-... is the CVE itself: no separate advisory. Ubuntu's
	// priority rates it, as the record has no vector.
	if v.CVE != "CVE-2023-38408" || v.Fixed != "1:8.9p1-3ubuntu0.3" || v.Advisory != "" || v.Severity != "medium" || v.Ecosystem != "Ubuntu 22.04" {
		t.Errorf("vuln = %+v", v)
	}
	// 0.10 sorts after 0.3.
	if got := x.Match([]endpoint.Package{{Name: "openssh-server", Version: "1:8.9p1-3ubuntu0.10", Source: "openssh", Type: "deb"}}); len(got) != 0 {
		t.Errorf("patched = %+v", got)
	}
}

func TestOSVMatchRPM(t *testing.T) {
	alma := index(t, "almalinux", "8.8", osvAlma, osvAlmaBugfix)
	if alma.Advisories != 1 {
		t.Errorf("advisories = %d; the bug fix names no CVE", alma.Advisories)
	}
	pkgs := []endpoint.Package{
		{Name: "openssh", Version: "8.0p1-17.el8_7", Source: "openssh-8.0p1-17.el8_7.src.rpm", Type: "rpm"},
		{Name: "openssh-server", Version: "8.0p1-17.el8_7", Source: "openssh-8.0p1-17.el8_7.src.rpm", Type: "rpm"},
		{Name: "openssh-clients", Version: "8.0p1-19.el8_8", Source: "openssh-8.0p1-19.el8_8.src.rpm", Type: "rpm"},
	}
	got := alma.Match(pkgs)
	// One service for the source RPM, one CVE however many of its
	// packages are behind.
	if len(got) != 1 || got[0].Product != "openssh" || got[0].Extra != "rpm package" || len(got[0].Vulns) != 1 {
		t.Fatalf("match = %+v", got)
	}
	v := got[0].Vulns[0]
	if v.CVE != "CVE-2023-38408" || v.Fixed != "8.0p1-19.el8_8" || v.Advisory != "ALSA-2023:4419" || v.Severity != "high" || v.CVSS != 0 ||
		!strings.HasPrefix(v.Description, "Important: openssh security update. OpenSSH is") {
		t.Errorf("vuln = %+v", v)
	}

	rocky := index(t, "rocky", "9.2", osvRocky)
	got = rocky.Match([]endpoint.Package{{Name: "openssh-server", Version: "8.7p1-29.el9_2", Source: "openssh-8.7p1-29.el9_2.src.rpm", Type: "rpm"}})
	if len(got) != 1 || got[0].Vulns[0].Fixed != "0:8.7p1-30.el9_2" || got[0].Vulns[0].CVSS != 9.8 || got[0].Vulns[0].Severity != "critical" {
		t.Errorf("rocky = %+v", got)
	}
	// An epoch the fix lacks wins.
	if got := rocky.Match([]endpoint.Package{{Name: "openssh-server", Version: "1:8.7p1-29.el9_2", Type: "rpm"}}); len(got) != 0 {
		t.Errorf("epoch 1 = %+v", got)
	}

	rhel := index(t, "rhel", "9.2", osvRedHat)
	got = rhel.Match([]endpoint.Package{{Name: "openssh-server", Version: "8.7p1-29.el9", Type: "rpm"}})
	if len(got) != 1 || got[0].Product != "openssh-server" || len(got[0].Vulns) != 1 || got[0].Vulns[0].Fixed != "0:8.7p1-30.el9_2" {
		t.Errorf("rhel = %+v", got)
	}
}

func TestOSVFixedAfter(t *testing.T) {
	e, _ := EcosystemFor("debian", "12")
	evs := func(s ...string) []osvEvent {
		var out []osvEvent
		for _, x := range s {
			out = append(out, osvEvent{x[0], x[2:]})
		}
		return out
	}
	for _, c := range []struct {
		ranges  [][]osvEvent
		version string
		fixed   string
	}{
		{[][]osvEvent{evs("i:0", "f:2.0-1")}, "1.0-1", "2.0-1"},
		{[][]osvEvent{evs("i:0", "f:2.0-1")}, "2.0-1", ""},
		{[][]osvEvent{evs("i:0", "f:2.0-1")}, "3.0-1", ""},
		// Out of order events are sorted.
		{[][]osvEvent{evs("f:2.0-1", "i:0")}, "1.0-1", "2.0-1"},
		// Two stretches: introduced again after a fix.
		{[][]osvEvent{evs("i:0", "f:1.5-1", "i:2.0-1", "f:2.5-1")}, "1.7-1", ""},
		{[][]osvEvent{evs("i:0", "f:1.5-1", "i:2.0-1", "f:2.5-1")}, "2.1-1", "2.5-1"},
		{[][]osvEvent{evs("i:1.0-1", "f:2.0-1")}, "0.9-1", ""},
		// No fix: last_affected, or introduced alone.
		{[][]osvEvent{evs("i:0", "l:2.0-1")}, "1.0-1", ""},
		{[][]osvEvent{evs("i:0")}, "1.0-1", ""},
		// The newest fix of two ranges that both apply.
		{[][]osvEvent{evs("i:0", "f:2.0-1"), evs("i:0", "f:2.0-3")}, "1.0-1", "2.0-3"},
		{[][]osvEvent{evs("i:0", "f:1.0~rc1-1")}, "1.0~beta-1", "1.0~rc1-1"},
	} {
		for _, r := range c.ranges {
			sortEvents(r, e.Compare)
		}
		got, ok := osvAffected{ranges: c.ranges}.fixedAfter(c.version, e.Compare)
		if got != c.fixed || ok != (c.fixed != "") {
			t.Errorf("fixedAfter(%v, %s) = %q %v, want %q", c.ranges, c.version, got, ok, c.fixed)
		}
	}
}

func TestDebSourceAndRPMSource(t *testing.T) {
	for _, c := range []struct {
		p          endpoint.Package
		name, vers string
	}{
		{endpoint.Package{Name: "openssh-server", Version: "1:9.2p1-2", Source: "openssh"}, "openssh", "1:9.2p1-2"},
		{endpoint.Package{Name: "libssl3", Version: "3.0.11-1+b1", Source: "openssl (3.0.11-1)"}, "openssl", "3.0.11-1"},
		{endpoint.Package{Name: "bash", Version: "5.2.15-2+b2"}, "bash", "5.2.15-2+b2"},
	} {
		if n, v := debSource(c.p); n != c.name || v != c.vers {
			t.Errorf("debSource(%+v) = %q %q", c.p, n, v)
		}
	}
	for src, want := range map[string]string{
		"openssh-8.0p1-19.el8_8.src.rpm":       "openssh",
		"python3.11-3.11.5-1.el9_3.src.rpm":    "python3.11",
		"kernel-5.14.0-427.13.1.el9_4.src.rpm": "kernel",
		"":                                     "",
		"weird":                                "",
	} {
		if got := rpmSourceName(src); got != want {
			t.Errorf("rpmSourceName(%q) = %q, want %q", src, got, want)
		}
	}
}

func TestDistroSeverity(t *testing.T) {
	for _, c := range []struct{ ubuntu, urgency, summary, want string }{
		{"high", "", "", "high"},
		{"negligible", "", "", "low"},
		{"", "medium**", "", "medium"},
		{"", "not yet assigned", "Critical: kernel security update", "critical"},
		{"", "", "Important: openssh security update", "high"},
		{"", "", "Moderate: curl security update", "medium"},
		{"", "", "Red Hat Security Advisory: openssh security update", "unknown"},
	} {
		if got := distroSeverity(c.ubuntu, c.urgency, c.summary); got != c.want {
			t.Errorf("distroSeverity(%q, %q, %q) = %q, want %q", c.ubuntu, c.urgency, c.summary, got, c.want)
		}
	}
}

// osvZip makes a bulk download holding the advisories.
func osvZip(t *testing.T, records map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, body := range records {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestReadOSVZip(t *testing.T) {
	e, _ := EcosystemFor("debian", "12")
	z := osvZip(t, map[string]string{
		"CVE-2023-38408.json": osvDebianCVE, "DSA-5800-1.json": osvDebianDSA,
		"broken.json": "{not json", "README.txt": "not an advisory",
		"big.json": `{"id":"CVE-2099-9999","details":"` + strings.Repeat("x", maxOSVRecord) + `"}`,
	})
	x, err := ReadOSVZip(context.Background(), bytes.NewReader(z), int64(len(z)), e)
	if err != nil {
		t.Fatal(err)
	}
	if x.Advisories != 2 || len(x.pkgs["openssh"]) != 2 {
		t.Errorf("advisories = %d, openssh = %d", x.Advisories, len(x.pkgs["openssh"]))
	}
	if _, err := ReadOSVZip(context.Background(), bytes.NewReader([]byte("not a zip")), 9, e); err == nil {
		t.Error("read a file that is not a zip")
	}
	empty := osvZip(t, map[string]string{"README.txt": "x"})
	if _, err := ReadOSVZip(context.Background(), bytes.NewReader(empty), int64(len(empty)), e); err == nil {
		t.Error("read a zip with no advisories")
	}

	// What the files inflate to together is capped.
	old := maxOSVInflate
	maxOSVInflate = int64(len(osvDebianCVE))
	defer func() { maxOSVInflate = old }()
	if _, err := ReadOSVZip(context.Background(), bytes.NewReader(z), int64(len(z)), e); err == nil || !strings.Contains(err.Error(), "inflate") {
		t.Errorf("over the inflate cap = %v", err)
	}
	maxOSVInflate = old
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := ReadOSVZip(ctx, bytes.NewReader(z), int64(len(z)), e); err == nil {
		t.Error("read with a cancelled context")
	}
}

func TestMatchCapsVersions(t *testing.T) {
	e, _ := EcosystemFor("debian", "12")
	x := NewOSVIndex(e)
	if err := x.Add([]byte(osvDebianDSA)); err != nil {
		t.Fatal(err)
	}
	var pkgs []endpoint.Package
	for i := 0; i < 1000; i++ {
		v := fmt.Sprintf("1:9.2p1-2+deb12u2~%d", i%(maxPackageVersions+5))
		pkgs = append(pkgs, endpoint.Package{Name: "openssh-server", Version: v, Source: "openssh", Type: "deb"})
	}
	svcs := x.Match(pkgs)
	if len(svcs) != 1 || len(svcs[0].Vulns) == 0 {
		t.Fatalf("services = %+v", svcs)
	}
}
