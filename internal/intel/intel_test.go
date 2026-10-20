// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package intel

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestNormalize(t *testing.T) {
	cases := []struct{ typ, in, wantType, want string }{
		{"", "203.0.113.9", TypeIP, "203.0.113.9"},
		{"auto", "::ffff:203.0.113.9", TypeIP, "203.0.113.9"},
		{"", "203.0.113.0/24", TypeCIDR, "203.0.113.0/24"},
		{"", "203.0.113.7/24", TypeCIDR, "203.0.113.0/24"},
		{"", "203.0.113.7/32", TypeIP, "203.0.113.7"},
		{"", "Evil.Example.COM.", TypeDomain, "evil.example.com"},
		{"", "evil[.]example[.]com", TypeDomain, "evil.example.com"},
		{"", "hxxp://Evil.Example.com/Payload.exe", TypeURL, "http://evil.example.com/Payload.exe"},
		{"", "https://x.example.com", TypeURL, "https://x.example.com"},
		{"", "D41D8CD98F00B204E9800998ECF8427E", TypeMD5, "d41d8cd98f00b204e9800998ecf8427e"},
		{"hash", strings.Repeat("a", 40), TypeSHA1, strings.Repeat("a", 40)},
		{"", strings.Repeat("F", 64), TypeSHA256, strings.Repeat("f", 64)},
		{"", "Phish@Bad.Example", TypeEmail, "phish@bad.example"},
		{"domain", "*.bad.example", TypeDomain, "bad.example"},
		{"ip", "10.0.0.0/8", TypeCIDR, "10.0.0.0/8"},
	}
	for _, c := range cases {
		typ, v, err := Normalize(c.typ, c.in)
		if err != nil || typ != c.wantType || v != c.want {
			t.Errorf("Normalize(%q, %q) = %q %q %v, want %q %q", c.typ, c.in, typ, v, err, c.wantType, c.want)
		}
	}
	for _, c := range [][2]string{{"", "not a thing"}, {"ip", "evil.com"}, {"md5", strings.Repeat("a", 40)}, {"", "abc"}, {"url", "evil.com/x"}, {"email", "a@b"}, {"", ""}, {"ipv4", "1.2.3.4"}} {
		if typ, v, err := Normalize(c[0], c[1]); err == nil {
			t.Errorf("Normalize(%q, %q) = %q %q, want error", c[0], c[1], typ, v)
		}
	}
}

func TestParseLines(t *testing.T) {
	feed := "# Feodo Tracker\n# last updated today\n\n203.0.113.9\n198.51.100.0/24 ; SBL123\n203.0.113.9\n0.0.0.0 evil.example.com\nnot-an-ip!\n192.0.2.3 # trailing comment\n10.1.2.3\n"
	res, err := Parse([]byte(feed), ParseOptions{Format: FormatLines, Type: "auto"})
	if err != nil {
		t.Fatal(err)
	}
	got := values(res.Indicators)
	if got != "ip:203.0.113.9 cidr:198.51.100.0/24 domain:evil.example.com ip:192.0.2.3" || res.Skipped != 1 || res.Example != "not-an-ip!" || res.Reserved != 1 {
		t.Errorf("got %s skipped %d %q reserved %d", got, res.Skipped, res.Example, res.Reserved)
	}
	// A type limits what counts as valid.
	res, _ = Parse([]byte(feed), ParseOptions{Format: FormatLines, Type: "ip"})
	if values(res.Indicators) != "ip:203.0.113.9 cidr:198.51.100.0/24 ip:192.0.2.3" || res.Skipped != 2 {
		t.Errorf("ip only: %s skipped %d", values(res.Indicators), res.Skipped)
	}
}

func values(inds []Indicator) string {
	var s []string
	for _, i := range inds {
		s = append(s, i.Type+":"+i.Value)
	}
	return strings.Join(s, " ")
}

func TestParseCSV(t *testing.T) {
	// abuse.ch style: the header is the last comment line.
	urlhaus := `################################################################
# abuse.ch URLhaus Database Dump (CSV - recent URLs only)       #
################################################################
#
# id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter
"3311","2026-10-11 10:00:00","http://bad.example/x.sh","online","2026-10-11 10:00:00","malware_download","elf","https://urlhaus.abuse.ch/url/3311/","r"
"3312","2026-10-11 10:01:00","hxxp://other.example/y","online","","malware_download","","",""
`
	res, err := Parse([]byte(urlhaus), ParseOptions{Format: FormatCSV, Type: "url", Column: "url"})
	if err != nil {
		t.Fatal(err)
	}
	if values(res.Indicators) != "url:http://bad.example/x.sh url:http://other.example/y" {
		t.Errorf("urlhaus = %s", values(res.Indicators))
	}
	// A normal header row, and a column number.
	csvFeed := "ip,first_seen,malware\n192.0.2.1,2026-10-01,Emotet\n192.0.2.2,2026-10-02,QakBot\n,,\n"
	res, err = Parse([]byte(csvFeed), ParseOptions{Format: FormatCSV, Column: "IP"})
	if err != nil || values(res.Indicators) != "ip:192.0.2.1 ip:192.0.2.2" || res.Skipped != 1 {
		t.Errorf("header = %s %d %v", values(res.Indicators), res.Skipped, err)
	}
	res, err = Parse([]byte(csvFeed), ParseOptions{Format: FormatCSV, Column: "1"})
	if err != nil || len(res.Indicators) != 2 || res.Skipped != 2 { // the header and the empty row
		t.Errorf("number = %s %d %v", values(res.Indicators), res.Skipped, err)
	}
	if _, err := Parse([]byte(csvFeed), ParseOptions{Format: FormatCSV, Column: "nope"}); err == nil || !strings.Contains(err.Error(), "no column named") {
		t.Errorf("missing column: %v", err)
	}
	if _, err := Parse([]byte(csvFeed), ParseOptions{Format: FormatCSV}); err == nil {
		t.Error("csv without a column should fail")
	}
}

func TestParseSTIX(t *testing.T) {
	now := time.Date(2026, 10, 12, 0, 0, 0, 0, time.UTC)
	bundle := `{"type":"bundle","id":"bundle--1","objects":[
	 {"type":"indicator","spec_version":"2.1","id":"indicator--1","name":"Emotet C2","pattern":"[ipv4-addr:value = '203.0.113.9']","pattern_type":"stix","valid_from":"2026-10-01T00:00:00Z","indicator_types":["malicious-activity"]},
	 {"type":"indicator","id":"indicator--2","description":"Phishing kit","pattern":"[domain-name:value = 'login-bank.example'] OR [url:value = 'http://login-bank.example/a']","pattern_type":"stix","valid_until":"2026-12-01T00:00:00Z"},
	 {"type":"indicator","id":"indicator--3","pattern":"[file:hashes.'SHA-256' = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' AND file:hashes.MD5 = 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb']","pattern_type":"stix"},
	 {"type":"indicator","id":"indicator--4","pattern":"[email-message:from_ref.value = 'ceo@spoof.example']"},
	 {"type":"indicator","id":"indicator--5","pattern":"[ipv4-addr:value = '198.51.100.1']","revoked":true},
	 {"type":"indicator","id":"indicator--6","pattern":"[ipv4-addr:value = '198.51.100.2']","valid_until":"2026-01-01T00:00:00Z"},
	 {"type":"indicator","id":"indicator--7","pattern":"rule x { condition: true }","pattern_type":"yara"},
	 {"type":"indicator","id":"indicator--8","pattern":"[ipv4-addr:value = '198.51.100.0/25']"},
	 {"type":"malware","id":"malware--1","name":"Emotet"}
	]}`
	res, err := Parse([]byte(bundle), ParseOptions{Format: FormatSTIX, Type: "auto", Now: now})
	if err != nil {
		t.Fatal(err)
	}
	want := "ip:203.0.113.9 domain:login-bank.example url:http://login-bank.example/a sha256:" + strings.Repeat("a", 64) +
		" md5:" + strings.Repeat("b", 32) + " email:ceo@spoof.example cidr:198.51.100.0/25"
	if values(res.Indicators) != want {
		t.Errorf("stix =\n %s\nwant\n %s", values(res.Indicators), want)
	}
	if res.Indicators[0].Description != "Emotet C2" || res.Indicators[0].Tags[0] != "malicious-activity" {
		t.Errorf("first = %+v", res.Indicators[0])
	}
	if res.Indicators[1].Expires.IsZero() || res.Indicators[1].Description != "Phishing kit" {
		t.Errorf("valid_until/description = %+v", res.Indicators[1])
	}
	// A feed limited to one type keeps only that type.
	res, _ = Parse([]byte(bundle), ParseOptions{Format: FormatSTIX, Type: "hash", Now: now})
	if len(res.Indicators) != 2 {
		t.Errorf("hash only = %s", values(res.Indicators))
	}
	// TAXII envelopes and bare objects work too.
	res, err = Parse([]byte(`{"more":false,"objects":[{"type":"indicator","pattern":"[ipv4-addr:value = '192.0.2.5']"}]}`), ParseOptions{Format: FormatSTIX})
	if err != nil || values(res.Indicators) != "ip:192.0.2.5" {
		t.Errorf("envelope = %s %v", values(res.Indicators), err)
	}
	if _, err := Parse([]byte(`<html>`), ParseOptions{Format: FormatSTIX}); err == nil {
		t.Error("html should not parse as STIX")
	}
}

func TestParseUpload(t *testing.T) {
	now := time.Date(2026, 10, 12, 0, 0, 0, 0, time.UTC)
	good := "value,type,description,weight,expires,tags\n203.0.113.9,,Scanner,2,30d,scanner|ssh\nevil.example,domain,,,2027-01-01,\n# a comment\n\n"
	inds, err := ParseUpload(strings.NewReader(good), now)
	if err != nil {
		t.Fatal(err)
	}
	if len(inds) != 2 || inds[0].Weight != 2 || inds[0].Source != ManualSource || len(inds[0].Tags) != 2 ||
		!inds[0].Expires.Equal(now.Add(30*24*time.Hour)) || inds[1].Type != TypeDomain || inds[1].Weight != 1 {
		t.Errorf("upload = %+v", inds)
	}
	// A plain list needs no header.
	inds, err = ParseUpload(strings.NewReader("203.0.113.9\nbad.example,phishing site\n"), now)
	if err != nil || len(inds) != 2 || inds[1].Description != "phishing site" {
		t.Errorf("plain = %+v %v", inds, err)
	}
	bad := "value,type,weight,expires\n203.0.113.9,,abc,\nnot a value,,,\n203.0.113.10,domain,,\n203.0.113.11,,,2020-01-01\n"
	_, err = ParseUpload(strings.NewReader(bad), now)
	var pe *ParseError
	if !errors.As(err, &pe) || len(pe.Lines) != 4 || pe.Lines[0].Line != 2 || pe.Lines[3].Line != 5 ||
		!strings.Contains(pe.Lines[0].Msg, "weight") || !strings.Contains(pe.Lines[3].Msg, "in the past") {
		t.Fatalf("errors = %v", err)
	}
	if _, err := ParseUpload(strings.NewReader("value,colour\n1.2.3.4,red\n"), now); err == nil || !strings.Contains(err.Error(), "unknown column") {
		t.Errorf("unknown column: %v", err)
	}
	// A byte order mark is skipped.
	if inds, err := ParseUpload(strings.NewReader("\ufeffvalue\n203.0.113.9\n"), now); err != nil || len(inds) != 1 {
		t.Errorf("bom = %+v %v", inds, err)
	}
}

// ipLines yields n distinct IPv4 addresses, one per line, without holding
// them all in memory.
type ipLines struct {
	n, i int
	buf  []byte
}

func (g *ipLines) Read(p []byte) (int, error) {
	for len(g.buf) < len(p) && g.i < g.n {
		g.buf = fmt.Appendf(g.buf, "11.%d.%d.%d\n", g.i>>16&255, g.i>>8&255, g.i&255)
		g.i++
	}
	if len(g.buf) == 0 {
		return 0, io.EOF
	}
	n := copy(p, g.buf)
	g.buf = g.buf[n:]
	return n, nil
}

func TestParseUploadCap(t *testing.T) {
	defer func(n int) { maxUploadIndicators = n }(maxUploadIndicators)
	maxUploadIndicators = 1000
	now := time.Now()
	// Exactly the cap is fine; one more refuses the whole upload as soon
	// as it is seen, without reading the rest of a 2.1 million line file.
	if inds, err := ParseUpload(&ipLines{n: 1000}, now); err != nil || len(inds) != 1000 {
		t.Fatalf("at the cap = %d %v", len(inds), err)
	}
	g := &ipLines{n: 2_100_000}
	inds, err := ParseUpload(g, now)
	if err == nil || inds != nil || !strings.Contains(err.Error(), "more than 1000 indicators") {
		t.Fatalf("over the cap = %d %v", len(inds), err)
	}
	if g.i > 100_000 {
		t.Errorf("read %d lines before refusing", g.i)
	}
	// Each line counts, so repeating one value cannot slip past the cap.
	if _, err := ParseUpload(strings.NewReader(strings.Repeat("203.0.113.9\n", 1001)), now); err == nil {
		t.Error("1001 lines accepted")
	}
}

// A read error, such as a body over its limit, is returned as it is.
func TestParseUploadReadError(t *testing.T) {
	r := http.MaxBytesReader(httptest.NewRecorder(), io.NopCloser(&ipLines{n: 100_000}), 1000)
	var tooBig *http.MaxBytesError
	if _, err := ParseUpload(r, time.Now()); !errors.As(err, &tooBig) {
		t.Errorf("err = %v", err)
	}
}

func TestStoreLookupAndExpiry(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC)
	s := NewStore(NewMemory())
	s.Now = func() time.Time { return now }
	if err := s.Load(ctx); err != nil {
		t.Fatal(err)
	}
	add := func(typ, v, src string, w float64, exp time.Time) {
		if err := s.Add(ctx, []Indicator{{Type: typ, Value: v, Source: src, Weight: w, Expires: exp}}); err != nil {
			t.Fatal(err)
		}
	}
	add(TypeIP, "203.0.113.9", "feodo", 1, time.Time{})
	add(TypeIP, "203.0.113.9", ManualSource, 3, time.Time{})
	add(TypeCIDR, "198.51.100.0/24", "drop", 1, time.Time{})
	add(TypeDomain, "evil.example", "urlhaus", 1, time.Time{})
	add(TypeSHA256, strings.Repeat("c", 64), ManualSource, 1, time.Time{})
	add(TypeEmail, "ceo@spoof.example", ManualSource, 1, time.Time{})
	add(TypeIP, "192.0.2.1", ManualSource, 1, now.Add(time.Hour))

	m := s.Lookup("203.0.113.9")
	if len(m) != 2 || m[0].Source != ManualSource {
		t.Errorf("two sources, highest weight first: %+v", m)
	}
	if m := s.Lookup("198.51.100.77"); len(m) != 1 || m[0].Value != "198.51.100.0/24" {
		t.Errorf("network = %+v", m)
	}
	if m := s.Lookup("http://Evil.Example/path"); len(m) != 1 {
		t.Errorf("url host as domain = %+v", m)
	}
	if m := s.Lookup("MD5=AA,SHA256=" + strings.Repeat("C", 64)); len(m) != 1 {
		t.Errorf("sysmon hashes = %+v", m)
	}
	if m := s.Lookup("CEO@spoof.example"); len(m) != 1 {
		t.Errorf("email = %+v", m)
	}
	if m := s.Lookup("203.0.113.9", "hash"); len(m) != 0 {
		t.Errorf("class filter = %+v", m)
	}
	if m := s.Lookup("192.0.2.1"); len(m) != 1 {
		t.Errorf("not yet expired = %+v", m)
	}
	if v := s.Values(TypeIP); strings.Join(v, ",") != "192.0.2.1,203.0.113.9" {
		t.Errorf("values = %v", v)
	}
	// Expired indicators stop matching at once and are purged later.
	now = now.Add(2 * time.Hour)
	if m := s.Lookup("192.0.2.1"); len(m) != 0 {
		t.Errorf("expired still matches: %+v", m)
	}
	if v := s.Values(TypeIP); strings.Join(v, ",") != "203.0.113.9" {
		t.Errorf("values after expiry = %v", v)
	}
	if n, err := s.Purge(ctx); err != nil || n != 1 || s.Summary().Total != 6 {
		t.Errorf("purge = %d %v total %d", n, err, s.Summary().Total)
	}
	// List and summary.
	list, total := s.List(Filter{Text: "203.0.113", Limit: 1})
	if total != 2 || len(list) != 1 {
		t.Errorf("list = %d %v", total, list)
	}
	if list, _ := s.List(Filter{Type: "hash"}); len(list) != 1 {
		t.Errorf("hash list = %v", list)
	}
	if list, _ := s.List(Filter{Text: "evil[.]example"}); len(list) != 1 {
		t.Errorf("defanged search = %v", list)
	}
	if sum := s.Summary(); sum.BySource[ManualSource] != 3 || sum.ByType[TypeIP] != 2 {
		t.Errorf("summary = %+v", sum)
	}
	// Removing a feed keeps manual indicators.
	if n, err := s.RemoveSources(ctx, []string{"urlhaus"}); err != nil || n != 2 || s.CountSource("urlhaus") != 1 {
		t.Errorf("remove = %d %v", n, err)
	}
	// Another server's change is picked up by Sync.
	other := NewStore(s.Backend)
	if reloaded, err := other.Sync(ctx); err != nil || !reloaded || other.Summary().Total != 4 {
		t.Errorf("sync = %v %v %d", reloaded, err, other.Summary().Total)
	}
	if reloaded, _ := other.Sync(ctx); reloaded {
		t.Error("second sync reloaded without a change")
	}
}

func TestReplaceSourceAgesOut(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC)
	s := NewStore(NewMemory())
	s.Now = func() time.Time { return now }
	first := []Indicator{{Type: TypeIP, Value: "192.0.2.1"}, {Type: TypeIP, Value: "192.0.2.2"}}
	if a, r, err := s.ReplaceSource(ctx, "feed", first); err != nil || a != 2 || r != 0 {
		t.Fatalf("first = %d %d %v", a, r, err)
	}
	now = now.Add(time.Hour)
	second := []Indicator{{Type: TypeIP, Value: "192.0.2.2"}, {Type: TypeIP, Value: "192.0.2.3"}}
	if a, r, err := s.ReplaceSource(ctx, "feed", second); err != nil || a != 1 || r != 1 {
		t.Fatalf("second = %d %d %v", a, r, err)
	}
	if len(s.Lookup("192.0.2.1")) != 0 {
		t.Error("an indicator dropped from the feed still matches")
	}
	m := s.Lookup("192.0.2.2")
	if len(m) != 1 || !m[0].FirstSeen.Equal(now.Add(-time.Hour)) || !m[0].LastSeen.Equal(now) {
		t.Errorf("first/last seen = %+v", m)
	}
}

func TestFeedRefresh(t *testing.T) {
	ctx := context.Background()
	var mu sync.Mutex
	body, status, gotAuth := "203.0.113.9\n198.51.100.0/24\n", 200, ""
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(status)
		w.Write([]byte(body))
	}))
	defer srv.Close()
	t.Setenv("SIGNALITH_TEST_FEED_KEY", "s3cret")
	now := time.Date(2026, 10, 12, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	s := NewStore(NewMemory())
	s.Now = clock
	statusFile := filepath.Join(t.TempDir(), "intel_feeds.json")
	f := &Feeds{Store: s, Now: clock, StatusFile: statusFile, AllowLoopback: true, List: []Feed{
		{Name: "blocklist", URL: srv.URL, Format: FormatLines, Type: "auto", Interval: time.Hour, MaxAge: 7 * 24 * time.Hour,
			Weight: 1.5, Description: "Test list", Tags: []string{"botnet"}, Headers: map[string]string{"Authorization": "Bearer ${SIGNALITH_TEST_FEED_KEY}"}, Enabled: true},
		{Name: "off", URL: srv.URL, Enabled: false, Interval: time.Hour},
	}}
	f.RunDue(ctx)
	st := f.Status()
	if st[0].Status.Count != 2 || st[0].Status.LastError != "" || st[0].Indicators != 2 || !st[0].Status.NextRun.Equal(now.Add(time.Hour)) {
		t.Fatalf("status = %+v", st[0])
	}
	if !st[1].Status.LastAttempt.IsZero() {
		t.Error("a disabled feed was downloaded")
	}
	if gotAuth != "Bearer s3cret" {
		t.Errorf("auth header = %q", gotAuth)
	}
	m := s.Lookup("203.0.113.9")
	if len(m) != 1 || m[0].Weight != 1.5 || m[0].Source != "blocklist" || m[0].Description != "Test list" ||
		m[0].Tags[0] != "botnet" || !m[0].Expires.Equal(now.Add(7*24*time.Hour)) {
		t.Errorf("indicator = %+v", m)
	}
	// Not due yet.
	now = now.Add(30 * time.Minute)
	mu.Lock()
	body = "203.0.113.10\n"
	mu.Unlock()
	f.RunDue(ctx)
	if len(s.Lookup("203.0.113.10")) != 0 {
		t.Error("feed ran before its interval")
	}
	// A failed download keeps the indicators and retries sooner.
	now = now.Add(time.Hour)
	mu.Lock()
	status = 503
	mu.Unlock()
	f.RunDue(ctx)
	st = f.Status()
	if !strings.Contains(st[0].Status.LastError, "503") || st[0].Indicators != 2 || !st[0].Status.NextRun.Equal(now.Add(15*time.Minute)) {
		t.Errorf("after failure = %+v", st[0])
	}
	// A download of junk is an error, not an empty feed.
	mu.Lock()
	status, body = 200, "<html>maintenance</html>\n"
	mu.Unlock()
	if _, err := f.Refresh(ctx, "blocklist"); err == nil || !strings.Contains(err.Error(), "web page, not a feed") || s.CountSource("blocklist") != 2 {
		t.Errorf("web page = %v, %d left", err, s.CountSource("blocklist"))
	}
	mu.Lock()
	body = "maintenance\n"
	mu.Unlock()
	// The indicators from before stay; the page says so only when there
	// were some, so the message does not.
	if _, err := f.Refresh(ctx, "blocklist"); err == nil || !strings.Contains(err.Error(), "None of the 1 values") ||
		strings.Contains(err.Error(), "previous indicators") || s.CountSource("blocklist") != 2 {
		t.Errorf("junk = %v, %d left", err, s.CountSource("blocklist"))
	}
	// Indicators that disappear from the feed are removed.
	mu.Lock()
	body = "203.0.113.10\n198.51.100.0/24\n"
	mu.Unlock()
	if st, err := f.Refresh(ctx, "blocklist"); err != nil || st.Added != 1 || st.Removed != 1 {
		t.Errorf("refresh = %+v %v", st, err)
	}
	if len(s.Lookup("203.0.113.9")) != 0 || len(s.Lookup("203.0.113.10")) != 1 {
		t.Error("feed contents not replaced")
	}
	if _, err := f.Refresh(ctx, "nope"); !errors.Is(err, ErrUnknownFeed) {
		t.Errorf("unknown feed = %v", err)
	}
	// Status survives a restart, so feeds are not downloaded again at once.
	if _, err := os.Stat(statusFile); err != nil {
		t.Fatal(err)
	}
	f2 := &Feeds{Store: s, Now: clock, StatusFile: statusFile, AllowLoopback: true, List: f.List}
	if st := f2.Status(); st[0].Status.LastSuccess.IsZero() || st[0].Status.Count != 2 {
		t.Errorf("reloaded status = %+v", st[0].Status)
	}
	// If a feed keeps failing, its indicators expire after max_age.
	now = now.Add(8 * 24 * time.Hour)
	if n, _ := s.Purge(ctx); n != 2 {
		t.Errorf("purged %d after max_age", n)
	}
}

func TestExpandEnv(t *testing.T) {
	t.Setenv("SIGNALITH_TEST_X", "abc")
	if got := ExpandEnv("Key ${SIGNALITH_TEST_X}/$1/${"); got != "Key abc/$1/${" {
		t.Errorf("got %q", got)
	}
	if refs := EnvRefs("${A} and ${B}"); len(refs) != 2 || refs[1] != "B" {
		t.Errorf("refs = %v", refs)
	}
}

// A server that no longer runs the background jobs downloads no feed on
// the schedule.
func TestFeedsAskAllowed(t *testing.T) {
	var mu sync.Mutex
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits++
		mu.Unlock()
		w.Write([]byte("203.0.113.9\n"))
	}))
	defer srv.Close()
	allowed := false
	f := &Feeds{Store: NewStore(NewMemory()), AllowLoopback: true, Allowed: func() bool { return allowed }, List: []Feed{
		{Name: "blocklist", URL: srv.URL, Format: FormatLines, Type: "auto", Interval: time.Hour, MaxAge: time.Hour, Enabled: true},
	}}
	f.RunDue(context.Background())
	mu.Lock()
	n := hits
	mu.Unlock()
	if n != 0 {
		t.Fatalf("%d downloads while not allowed", n)
	}
	allowed = true
	f.RunDue(context.Background())
	if st := f.Status(); st[0].Status.Count != 1 {
		t.Fatalf("status %+v", st[0])
	}
}
