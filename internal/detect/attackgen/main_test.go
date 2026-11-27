// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/jrsamsanchez/signalith/internal/detect"
	"github.com/jrsamsanchez/signalith/internal/sigmacheck"
	"github.com/jrsamsanchez/signalith/internal/splcheck"
)

// shipped is the Splunk pack, whose rules and recorded test events the
// tests build recordings from.
var shipped = filepath.Join("..", "packs", "splunk")

// cachePath is where the tool keeps a recording it downloaded from url.
func cachePath(url string) string {
	return filepath.Join(*cacheDir, strings.NewReplacer("https://", "", "/", "_").Replace(url))
}

// setFlags sets the tool's flags for one test, restoring them after.
func setFlags(t *testing.T, pack, cache string) {
	t.Helper()
	oldPack, oldCache, oldMax, oldOnly, oldWrite, oldList, oldSplunk, oldExtra := *packDir, *cacheDir, *maxBytes, *only, *write, *list, *splunk, *extra
	t.Cleanup(func() {
		*packDir, *cacheDir, *maxBytes, *only, *write, *list, *splunk, *extra = oldPack, oldCache, oldMax, oldOnly, oldWrite, oldList, oldSplunk, oldExtra
	})
	*packDir, *cacheDir, *maxBytes, *only, *write, *list, *splunk, *extra = pack, cache, 40<<20, "", false, "", "", ""
}

func writeFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
}

// xmlEvent writes a test event as Windows writes it to a recording.
func xmlEvent(c sigmacheck.Case) string {
	var b strings.Builder
	b.WriteString("<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>")
	fmt.Fprintf(&b, "<Provider Name='%s'/>", xmlText(c.Data["Provider_Name"]))
	fmt.Fprintf(&b, "<EventID>%s</EventID><Channel>%s</Channel><Computer>host</Computer>", xmlText(c.EventID), xmlText(c.Channel))
	b.WriteString("</System><EventData>")
	keys := make([]string, 0, len(c.Data))
	for k := range c.Data {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(&b, "<Data Name='%s'>%s</Data>", xmlText(k), xmlText(c.Data[k]))
	}
	b.WriteString("</EventData></Event>")
	return b.String()
}

func xmlText(s string) string {
	var b strings.Builder
	_ = xml.EscapeText(&b, []byte(s))
	return strings.ReplaceAll(b.String(), "'", "&apos;")
}

// line writes a test event as a line of a recording.
func line(c sigmacheck.Case) string {
	if raw, ok := c.Data["_raw"]; ok {
		return raw
	}
	return xmlEvent(c)
}

type attackRef struct{ Data, Sourcetype string }

func attackData(t *testing.T, src []byte) []attackRef {
	t.Helper()
	var rt ruleTests
	if err := yaml.Unmarshal(src, &rt); err != nil {
		t.Fatal(err)
	}
	var out []attackRef
	for _, tt := range rt.Tests {
		for _, a := range tt.AttackData {
			out = append(out, attackRef{a.Data, a.Sourcetype})
		}
	}
	return out
}

// handled reports whether the tool reads a recording of the sourcetype.
func handled(st string) bool {
	return strings.HasPrefix(st, "XmlWinEventLog") || st == "auditd" || cloudChannels[st] != ""
}

// TestMainChecksRecordings builds a pack of a few rules of each kind of
// recording, with recordings (in the download cache) made from their
// recorded test events, and runs the tool over it.
func TestMainChecksRecordings(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(shipped, "pack.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var p detect.Pack
	if err := yaml.Unmarshal(data, &p); err != nil {
		t.Fatal(err)
	}
	pack, cache := t.TempDir(), t.TempDir()
	setFlags(t, pack, cache)

	type pickedRule struct {
		r        detect.PackRule
		src      []byte
		recorded []sigmacheck.Case
		silent   []sigmacheck.Case
		refs     []attackRef
	}
	var picked []pickedRule
	usedURL := map[string]bool{}
	perKind := map[string]int{}
	for _, r := range p.Rules {
		src, err := os.ReadFile(filepath.Join(shipped, "rules", r.File))
		if err != nil {
			t.Fatal(err)
		}
		tdata, err := os.ReadFile(filepath.Join(shipped, "tests", strings.TrimSuffix(r.File, ".yml")+".json"))
		if err != nil {
			t.Fatal(err)
		}
		tf, err := sigmacheck.DecodeTestFile(tdata)
		if err != nil {
			t.Fatal(err)
		}
		refs := attackData(t, src)
		if len(refs) == 0 {
			continue
		}
		shared := false
		for _, a := range refs {
			shared = shared || usedURL[a.Data]
		}
		if shared {
			continue
		}
		kind := refs[0].Sourcetype
		if !handled(kind) {
			kind = "other"
		}
		post := strings.Contains(string(src), "| where count")
		if post {
			kind += " count"
		}
		if perKind[kind] >= 2 {
			continue
		}
		pr := pickedRule{r: r, src: src, refs: refs}
		for _, c := range tf.Cases {
			switch {
			case c.Source == splcheck.AttackDataSource:
				pr.recorded = append(pr.recorded, c)
			case !c.Expect:
				pr.silent = append(pr.silent, c)
			}
		}
		if kind != "other" && len(pr.recorded) == 0 && perKind[kind] == 0 {
			continue
		}
		perKind[kind]++
		for _, a := range refs {
			usedURL[a.Data] = true
		}
		picked = append(picked, pr)
	}
	if len(picked) < 6 {
		t.Fatalf("only %d rules picked: %v", len(picked), perKind)
	}

	// The pack: its manifest, rules, macros and test files.
	var m detect.Pack
	m.Name = "splunk"
	for _, pr := range picked {
		m.Rules = append(m.Rules, pr.r)
		writeFile(t, filepath.Join(pack, "rules", pr.r.File), pr.src)
		tdata, err := os.ReadFile(filepath.Join(shipped, "tests", strings.TrimSuffix(pr.r.File, ".yml")+".json"))
		if err != nil {
			t.Fatal(err)
		}
		writeFile(t, filepath.Join(pack, "tests", strings.TrimSuffix(pr.r.File, ".yml")+".json"), tdata)
	}
	mb, err := yaml.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(pack, "pack.yaml"), mb)
	macroFiles, _ := filepath.Glob(filepath.Join(shipped, "macros", "*.yml"))
	for _, f := range macroFiles {
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		writeFile(t, filepath.Join(pack, "macros", filepath.Base(f)), src)
	}

	// The recordings: each rule's recorded events in its first recording
	// that the tool reads, the others empty. The first rule of each kind
	// with no recorded events gets the events it must not find.
	silentRule := ""
	for i, pr := range picked {
		events := pr.recorded
		if len(events) == 0 && len(pr.silent) > 0 && silentRule == "" && strings.HasPrefix(pr.refs[0].Sourcetype, "XmlWinEventLog") {
			events = pr.silent[:1]
			silentRule = pr.r.File
		}
		written := false
		for _, a := range pr.refs {
			if !handled(a.Sourcetype) {
				continue
			}
			var lines []string
			if !written {
				for _, c := range events {
					lines = append(lines, line(c))
				}
				written = true
			}
			if i == 0 && strings.HasPrefix(a.Sourcetype, "XmlWinEventLog") {
				// An event that does not decode does not end the recording.
				lines = append([]string{"<Event><System><EventID>1</EventID></System><EventData><Data Name='a'>&bogus;</Data></EventData><Broken></Event>"}, lines...)
			}
			writeFile(t, cachePath(a.Data), []byte(strings.Join(lines, "\r\n")+"\n"))
		}
	}

	*write = true
	out := captureStdout(t, main)
	if !strings.Contains(out, "fired ") || !strings.Contains(out, "disagreements 0") {
		t.Errorf("summary missing or with disagreements:\n%s", out)
	}
	var fired, silent, noData, wrong int
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(l, "fired ") {
			if _, err := fmt.Sscanf(l, "fired %d, silent %d, no recording %d, disagreements %d", &fired, &silent, &noData, &wrong); err != nil {
				t.Fatalf("summary %q: %v", l, err)
			}
		}
	}
	if fired == 0 {
		t.Errorf("no rule fired:\n%s", out)
	}
	if perKind["other"] > 0 && noData == 0 {
		t.Errorf("rules without a recording the tool reads not counted:\n%s", out)
	}
	if silentRule != "" && !strings.Contains(out, "silent: "+silentRule) {
		t.Errorf("%s not silent:\n%s", silentRule, out)
	}
	if fired+silent+noData != len(picked) {
		t.Errorf("fired %d + silent %d + no recording %d != %d rules", fired, silent, noData, len(picked))
	}
	// -write keeps the recorded events each rule finds in its test file.
	for _, pr := range picked {
		if len(pr.recorded) == 0 {
			continue
		}
		tdata, err := os.ReadFile(filepath.Join(pack, "tests", strings.TrimSuffix(pr.r.File, ".yml")+".json"))
		if err != nil {
			t.Fatal(err)
		}
		tf, err := sigmacheck.DecodeTestFile(tdata)
		if err != nil {
			t.Fatal(err)
		}
		n := 0
		for _, c := range tf.Cases {
			if c.Source == splcheck.AttackDataSource {
				n++
			}
		}
		if n > 2 {
			t.Errorf("%s: %d recorded events kept, want at most 2", pr.r.File, n)
		}
	}

	// -only and -list narrow the rules; -extra adds rules of a
	// checkout, one of which does not convert.
	*write = false
	*only = strings.TrimSuffix(picked[0].r.File, ".yml")
	listFile := filepath.Join(t.TempDir(), "list.txt")
	writeFile(t, listFile, []byte(picked[0].r.File+"\n"))
	*list = listFile
	checkout := t.TempDir()
	for _, f := range macroFiles[:1] {
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		writeFile(t, filepath.Join(checkout, "macros", filepath.Base(f)), src)
	}
	writeFile(t, filepath.Join(checkout, "macros", "broken.yml"), []byte("definition: x\n"))
	writeFile(t, filepath.Join(checkout, "macros", "extra_macro.yml"), []byte("name: extra_macro\ndefinition: 'x=1'\n"))
	writeFile(t, filepath.Join(checkout, "detections", "endpoint", "copy.yml"), picked[0].src)
	writeFile(t, filepath.Join(checkout, "detections", "endpoint", "bad.yml"), []byte("name: bad\nsearch: '| transaction x'\n"))
	extraFile := filepath.Join(t.TempDir(), "extra.txt")
	writeFile(t, extraFile, []byte("detections/endpoint/copy.yml\ndetections/endpoint/bad.yml\n"))
	*splunk, *extra = checkout, extraFile
	out = captureStdout(t, main)
	if !strings.Contains(out, "does not convert: bad.yml") {
		t.Errorf("unconvertible extra rule not reported:\n%s", out)
	}
	var total int
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(l, "fired ") {
			_, _ = fmt.Sscanf(l, "fired %d, silent %d, no recording %d", &fired, &silent, &noData)
			total = fired + silent + noData
		}
	}
	if total != 2 {
		t.Errorf("checked %d rules, want the listed one and the extra one:\n%s", total, out)
	}
}

// captureStdout runs f with standard output sent to a file, and returns
// what it wrote.
func captureStdout(t *testing.T, f func()) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "stdout")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdout
	os.Stdout = file
	func() {
		defer func() { os.Stdout = old }()
		f()
	}()
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestRecording(t *testing.T) {
	setFlags(t, "", t.TempDir())
	url := "https://example.invalid/win/sysmon.log"
	events := []string{
		xmlEvent(sigmacheck.Case{Channel: "Microsoft-Windows-Sysmon/Operational", EventID: "1", Data: map[string]string{"Image": `C:\x.exe`, "CommandLine": " x  "}}),
		xmlEvent(sigmacheck.Case{Channel: sigmacheck.SystemChannel, EventID: "7045", Data: map[string]string{"Provider_Name": "Service Control Manager", "ServiceName": "svc"}}),
		"<Event><System><EventID>1</EventID></System><EventData><Data Name='x'>v</Data></EventData><Unclosed></Event>",
		"not an event",
	}
	writeFile(t, cachePath(url), []byte(strings.Join(events, "\n")))
	got, err := recording(url)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) < 2 {
		t.Fatalf("recording read %d events, want at least 2: %+v", len(got), got)
	}
	if got[0].EventID != "1" || got[0].Data["CommandLine"] != "x" || got[0].Data["Image"] != `C:\x.exe` || got[0].Source != "attack_data" {
		t.Errorf("first event %+v", got[0])
	}
	if got[1].Channel != sigmacheck.SystemChannel || got[1].Data["Provider_Name"] != "Service Control Manager" {
		t.Errorf("System event %+v", got[1])
	}
	// A recording larger than -max is cut.
	*maxBytes = int64(len(events[0]))
	got, err = recording(url)
	if err != nil || len(got) != 1 {
		t.Errorf("cut recording: %d events, %v", len(got), err)
	}
}

func TestAuditdRecording(t *testing.T) {
	setFlags(t, "", t.TempDir())
	url := "https://example.invalid/linux/auditd.log"
	lines := "type=PROCTITLE msg=audit(1700000000.000:1): proctitle=useradd x\r\n" +
		"garbage line\n" +
		"type=SYSCALL msg=audit(1700000000.000:2): arch=c000003e syscall=59 success=yes \n"
	writeFile(t, cachePath(url), []byte(lines))
	got, err := auditdRecording(url)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("read %d records, want 2: %+v", len(got), got)
	}
	if got[0].EventID != "PROCTITLE" || got[0].Channel != sigmacheck.AuditdChannel || got[0].Data["_raw"] != "type=PROCTITLE msg=audit(1700000000.000:1): proctitle=useradd x" {
		t.Errorf("first record %+v", got[0])
	}
	if got[1].EventID != "SYSCALL" || strings.HasSuffix(got[1].Data["_raw"], " ") {
		t.Errorf("second record %+v", got[1])
	}
	*maxBytes = 20
	got, err = auditdRecording(url)
	if err != nil || len(got) != 0 {
		t.Errorf("cut recording: %+v, %v", got, err)
	}
}

func TestCloudRecording(t *testing.T) {
	setFlags(t, "", t.TempDir())
	url := "https://example.invalid/cloud/records.json"
	writeFile(t, cachePath(url), []byte("{\"a\":1}\r\n\n  {\"b\":2}  \nnot json\n"))
	for _, tc := range []struct{ channel, id string }{
		{sigmacheck.CloudTrailChannel, "record"},
		{sigmacheck.OktaChannel, "log"},
	} {
		got, err := cloudRecording(url, tc.channel)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 2 || got[0].Data["_raw"] != `{"a":1}` || got[1].Data["_raw"] != `{"b":2}` {
			t.Fatalf("%s: records %+v", tc.channel, got)
		}
		for _, c := range got {
			if c.Channel != tc.channel || c.EventID != tc.id || c.Source != "attack_data" {
				t.Errorf("%s: record %+v", tc.channel, c)
			}
		}
	}
	*maxBytes = 3
	if got, err := cloudRecording(url, sigmacheck.CloudTrailChannel); err != nil || len(got) != 1 || got[0].Data["_raw"] != `{"a` {
		t.Errorf("cut recording: %+v, %v", got, err)
	}
}

func TestDownload(t *testing.T) {
	setFlags(t, "", t.TempDir())
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/ok" {
			http.NotFound(w, r)
			return
		}
		_, _ = io.WriteString(w, "0123456789")
	}))
	defer srv.Close()
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "ok.log")
	if err := download(srv.URL+"/ok", path); err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(path); err != nil || string(b) != "0123456789" {
		t.Errorf("downloaded %q, %v", b, err)
	}
	if _, err := os.Stat(path + ".part"); !os.IsNotExist(err) {
		t.Errorf("partial file left: %v", err)
	}
	// -max limits what is kept.
	*maxBytes = 4
	if err := download(srv.URL+"/ok", path); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(path); string(b) != "0123" {
		t.Errorf("limited download %q", b)
	}
	err := download(srv.URL+"/missing", filepath.Join(dir, "missing.log"))
	if err == nil || !strings.Contains(err.Error(), "404") {
		t.Errorf("missing recording: %v", err)
	}
	if err := download("http://127.0.0.1:0/x", filepath.Join(dir, "x.log")); err == nil {
		t.Error("unreachable server gives no error")
	}
	// A folder that cannot be made.
	blocker := filepath.Join(dir, "file")
	writeFile(t, blocker, []byte("x"))
	if err := download(srv.URL+"/ok", filepath.Join(blocker, "sub", "x.log")); err == nil {
		t.Error("download under a file gives no error")
	}
	// A recording not in the cache is downloaded; one that cannot be is
	// an error for each reader.
	for name, read := range map[string]func(string) ([]sigmacheck.Case, error){
		"recording":       recording,
		"auditdRecording": auditdRecording,
		"cloudRecording":  func(u string) ([]sigmacheck.Case, error) { return cloudRecording(u, sigmacheck.CloudTrailChannel) },
	} {
		if _, err := read(srv.URL + "/missing"); err == nil {
			t.Errorf("%s of a missing recording gives no error", name)
		}
	}
}

func TestKeep(t *testing.T) {
	pack := t.TempDir()
	setFlags(t, pack, t.TempDir())
	tf := &sigmacheck.TestFile{Rule: "r", Cases: []sigmacheck.Case{
		{Expect: true, Source: "synthesized", Channel: "c", EventID: "1", Data: map[string]string{"a": "1"}},
		{Expect: true, Source: splcheck.AttackDataSource, Channel: "c", EventID: "1", Data: map[string]string{"old": "1"}},
	}}
	data, err := sigmacheck.EncodeTestFile(tf)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(pack, "tests", "rule.json"), data)
	ev := func(k, v string) sigmacheck.Case {
		return sigmacheck.Case{Expect: true, Channel: "c", EventID: "1", Data: map[string]string{k: v}}
	}
	found := []sigmacheck.Case{
		ev("long", strings.Repeat("x", 50)),
		ev("big", strings.Repeat("y", maxEventSize+1)),
		ev("key", "AKIAABCDEFGHIJKLMNOP"),
		ev("s", "1"),
		ev("s", "1"),
		ev("m", "22"),
	}
	if err := keep("rule.yml", found); err != nil {
		t.Fatal(err)
	}
	data, err = os.ReadFile(filepath.Join(pack, "tests", "rule.json"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := sigmacheck.DecodeTestFile(data)
	if err != nil {
		t.Fatal(err)
	}
	var kept []string
	for _, c := range got.Cases {
		if c.Source == splcheck.AttackDataSource {
			kept = append(kept, sigmacheck.String(c.Data))
		}
	}
	want := []string{sigmacheck.String(map[string]string{"s": "1"}), sigmacheck.String(map[string]string{"m": "22"})}
	if strings.Join(kept, "|") != strings.Join(want, "|") {
		t.Errorf("kept %q, want the two smallest distinct events %q", kept, want)
	}
	if len(got.Cases) != 3 || got.Cases[0].Source != "synthesized" {
		t.Errorf("cases %+v", got.Cases)
	}
	if err := keep("missing.yml", nil); err == nil {
		t.Error("keep with no test file gives no error")
	}
	writeFile(t, filepath.Join(pack, "tests", "bad.json"), []byte("{not json"))
	if err := keep("bad.yml", nil); err == nil {
		t.Error("keep with a broken test file gives no error")
	}
}

func TestSecretRe(t *testing.T) {
	for _, s := range []string{
		"token ya29.abc", "AKIAABCDEFGHIJKLMNOP", "ghp_" + strings.Repeat("a", 20), "xoxb-1",
		"-----BEGIN RSA PRIVATE KEY", "eyJhbGciOiJIUzI1.eyJzdWIi", "AIza" + strings.Repeat("A", 35),
	} {
		if !secretRe.MatchString(s) {
			t.Errorf("%q not seen as a secret", s)
		}
	}
	for _, s := range []string{"plain text", "AKIA123", "ghp_short", "eyJ alone"} {
		if secretRe.MatchString(s) {
			t.Errorf("%q seen as a secret", s)
		}
	}
}
