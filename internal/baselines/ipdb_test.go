// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package baselines

import (
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/detect"
)

func TestParseIPDB(t *testing.T) {
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	zw.Write([]byte(testIPDB))
	zw.Close()
	for name, data := range map[string][]byte{"plain": []byte(testIPDB), "gzip": gz.Bytes()} {
		db, err := ParseIPDB(bytes.NewReader(data))
		if err != nil {
			t.Fatal(name, err)
		}
		// The range that is not routed is left out.
		if db.Rows() != 5 {
			t.Errorf("%s: %d rows", name, db.Rows())
		}
		for ip, want := range map[string]Network{
			"1.0.0.1":        {ASN: 13335, Country: "US", Name: "CLOUDFLARENET"},
			"1.0.0.255":      {ASN: 13335, Country: "US", Name: "CLOUDFLARENET"},
			"177.0.9.9":      {ASN: 28573, Country: "BR", Name: "CLARO"},
			"2600::1234":     {ASN: 7018, Country: "US", Name: "ATT-INTERNET4"},
			"::ffff:8.8.8.8": {ASN: 15169, Country: "US", Name: "GOOGLE"},
		} {
			got, ok := db.Lookup(netip.MustParseAddr(ip))
			if !ok || got != want {
				t.Errorf("%s: %s is %+v %v", name, ip, got, ok)
			}
		}
		for _, ip := range []string{"1.0.1.0", "2.0.0.1", "0.0.0.1", "2601::1", "255.255.255.255"} {
			if got, ok := db.Lookup(netip.MustParseAddr(ip)); ok {
				t.Errorf("%s: %s found as %+v", name, ip, got)
			}
		}
	}
	// What the store keeps reads back the same.
	db, _ := ParseIPDB(strings.NewReader(testIPDB))
	z, err := db.encode(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	back, err := ParseIPDB(bytes.NewReader(z))
	if err != nil || back.Rows() != 5 {
		t.Fatalf("read back: %v %v", back.Rows(), err)
	}
	if n, _ := back.Lookup(netip.MustParseAddr("177.0.0.1")); n.Name != "CLARO" {
		t.Errorf("read back %+v", n)
	}
}

func TestParseIPDBRefuses(t *testing.T) {
	for name, in := range map[string]string{
		"empty":     "",
		"html":      "<html><body>Not found</body></html>\n",
		"bad range": "1.0.0.9\t1.0.0.1\t5\tUS\tX\n",
		"bad asn":   "1.0.0.0\t1.0.0.1\tAS5\tUS\tX\n",
		"mixed":     "1.0.0.0\t2600::\t5\tUS\tX\n",
	} {
		if _, err := ParseIPDB(strings.NewReader(in)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// Too large is refused, not cut.
	big := &repeat{line: []byte("1.0.0.0\t1.0.0.255\t13335\tUS\tCLOUDFLARENET\n"), left: maxIPDBBytes + 100}
	if _, err := ParseIPDB(big); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Errorf("oversized: %v", err)
	}
}

type repeat struct {
	line []byte
	left int
	pos  int
}

func (r *repeat) Read(p []byte) (int, error) {
	if r.left <= 0 {
		return 0, io.EOF
	}
	n := 0
	for n < len(p) && r.left > 0 {
		p[n] = r.line[r.pos%len(r.line)]
		r.pos++
		n++
		r.left--
	}
	return n, nil
}

func TestPublic(t *testing.T) {
	for ip, want := range map[string]bool{
		"8.8.8.8": true, "2600::1": true, "10.0.0.1": false, "192.168.1.1": false, "172.16.0.1": false,
		"100.64.0.1": false, "127.0.0.1": false, "169.254.1.1": false, "fe80::1": false, "fd00::1": false,
		"192.0.2.1": false, "203.0.113.9": false, "2001:db8::1": false, "::ffff:10.0.0.1": false, "::ffff:1.1.1.1": true,
	} {
		if got := Public(netip.MustParseAddr(ip)); got != want {
			t.Errorf("Public(%s) = %v", ip, got)
		}
	}
}

func TestProfileBounds(t *testing.T) {
	p := newProfile(NewChange, "u", time.Unix(0, 0).UTC())
	at := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for i := range MaxValues + 20 {
		p.see(strings.Repeat("x", i%3)+string(rune('a'+i%26))+time.Duration(i).String(), at.Add(time.Duration(i)*time.Hour))
	}
	if len(p.Values) != MaxValues {
		t.Fatalf("%d values", len(p.Values))
	}
	// The ones seen longest ago went.
	for _, v := range p.Values {
		if v.Last.Before(at.Add(20 * time.Hour)) {
			t.Errorf("kept %+v", v)
		}
	}
	if !p.see(strings.Repeat("y", 1000), at) || len(p.Values[len(p.Values)-1].V) != maxValueLen {
		t.Error("long value not cut")
	}
	p.forget(at.Add(time.Duration(MaxValues) * time.Hour))
	if len(p.Values) > 21 {
		t.Errorf("forget kept %d", len(p.Values))
	}
	if NormEntity("  CORP\\Alice ") != "corp\\alice" || NormEntity("-") != "" {
		t.Error("NormEntity")
	}
	if got := cut("aé", 2); got != "a" {
		t.Errorf("cut on a character: %q", got)
	}
}

func TestSettingsProblems(t *testing.T) {
	ok := Settings{LearningDays: 14, ForgetDays: 60, IPDatabase: "https://mirror.example.com/ip2asn.tsv.gz",
		Checks:     map[string]CheckSettings{NewCountry: {Score: 80}},
		Exceptions: []detect.Exception{{ID: "ex-1", Match: map[string]string{"baseline": NewCountry, "src_country": "CA"}}}}
	if p := ok.Problems(); len(p) != 0 {
		t.Errorf("good settings: %v", p)
	}
	for name, s := range map[string]Settings{
		"learning":      {LearningDays: 120},
		"forget":        {ForgetDays: 3},
		"forget short":  {LearningDays: 30, ForgetDays: 20},
		"ip password":   {IPDatabase: "https://u:p@example.com/x.gz"},
		"ip scheme":     {IPDatabase: "ftp://example.com/x.gz"},
		"ip relative":   {IPDatabase: "file://data/x.gz"},
		"ip extension":  {IPDatabase: "/etc/passwd"},
		"check":         {Checks: map[string]CheckSettings{"nope": {}}},
		"score":         {Checks: map[string]CheckSettings{NewCountry: {Score: 5000}}},
		"exception":     {Exceptions: []detect.Exception{{ID: "ex-1"}}},
		"unknown check": {Exceptions: []detect.Exception{{ID: "ex-1", Match: map[string]string{"baseline": "nope"}}}},
		"rare":          {RareHosts: 50},
		"min mb":        {MinMB: -1},
	} {
		if p := s.Problems(); len(p) == 0 {
			t.Errorf("%s: no problem", name)
		}
	}
	for _, v := range []string{"", "off", "OFF", "file:ip2asn.tsv.gz", "FILE:ip.tsv", "https://mirror.example.com/ip2asn.tsv.gz"} {
		if err := IPSourceProblem(v); err != nil {
			t.Errorf("%q: %v", v, err)
		}
	}
	// Only a bare file name in the ipdb folder, and only https: no other
	// file of the server, no network share, nothing changed on the way.
	for _, v := range []string{`C:\data\ip2asn.tsv.gz`, "/srv/ip2asn.tsv", "//attacker/share/x.tsv", `\\attacker\share\x.tsv`,
		"file:///srv/ip.gz", "file:../users.json.gz", "file:..", "file:sub/ip.gz", `file:sub\ip.gz`, "file:.hidden.gz", "file:ip.json",
		"file:C:ip.gz", "http://mirror.example.com/ip.gz", "https://u:p@mirror.example.com/ip.gz", "ftp://x/ip.gz"} {
		if IPSourceProblem(v) == nil {
			t.Errorf("%q: allowed", v)
		}
	}
	if (Settings{}).IPSource() != DefaultIPDatabase || (Settings{IPDatabase: "off"}).IPSource() != "" {
		t.Error("IPSource")
	}
}

// TestChecksATTACK keeps each check's ATT&CK tags real: a technique of the
// catalog, and a tactic that technique belongs to (or any tactic of it).
func TestChecksATTACK(t *testing.T) {
	cat := detect.ATTACK()
	for _, c := range Checks {
		for _, id := range c.MITRE {
			tech, ok := cat.Technique(id)
			if !ok {
				t.Errorf("%s: %s is not an ATT&CK technique", c.ID, id)
				continue
			}
			if c.Tactic != "" && !slices.Contains(tech.Tactics, c.Tactic) {
				t.Errorf("%s: %s is not a tactic of %s (%v)", c.ID, c.Tactic, id, tech.Tactics)
			}
		}
	}
}

// TestIPDBFileStaysInFolder: a file: IP database is read only from the
// ipdb folder, not through a link out of it, and a bad line's error
// doesn't quote the file.
func TestIPDBFileStaysInFolder(t *testing.T) {
	dir, out := t.TempDir(), t.TempDir()
	secret := filepath.Join(out, "secret.tsv")
	if err := os.WriteFile(secret, []byte("top-secret-value\tsecond\t1\tUS\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	e := &Engine{FileDir: dir}
	ctx := context.Background()
	if err := os.Symlink(secret, filepath.Join(dir, "link.tsv")); err == nil {
		if _, err := e.fetchIPDB(ctx, "file:link.tsv"); err == nil {
			t.Error("read a file outside the folder through a link")
		}
	}
	if _, err := e.fetchIPDB(ctx, "file:../"+filepath.Base(out)+"/secret.tsv"); err == nil {
		t.Error("read a file outside the folder")
	}
	if err := os.WriteFile(filepath.Join(dir, "bad.tsv"), []byte("top-secret-value\tsecond\t1\tUS\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := e.fetchIPDB(ctx, "file:bad.tsv")
	if err == nil || strings.Contains(err.Error(), "secret") {
		t.Errorf("bad line: %v", err)
	}
}

// TestIPDBRedirectStaysHTTPS: an https mirror can't send the download to
// plain http.
func TestIPDBRedirectStaysHTTPS(t *testing.T) {
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, testIPDB) }))
	defer plain.Close()
	tls := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, plain.URL+"/ip.tsv", http.StatusFound)
	}))
	defer tls.Close()
	e := &Engine{HTTP: tls.Client()}
	if _, err := e.fetchIPDB(context.Background(), tls.URL+"/ip.tsv"); err == nil || !strings.Contains(err.Error(), "not https") {
		t.Errorf("followed a redirect to http: %v", err)
	}
}

// TestIPDBStopsWithContext: reading a large database ends at once when
// the server stops.
func TestIPDBStopsWithContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := ParseIPDB(&ctxReader{ctx: ctx, r: strings.NewReader(testIPDB)}); err == nil {
		t.Error("parsed after the context ended")
	}
}
