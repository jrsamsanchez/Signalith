package sigmacheck

import (
	"math/rand"
	"net/netip"
	"regexp"
	"strings"
	"testing"
	"time"
)

// checkSynthesis requires every positive to match and every negative not to.
func checkSynthesis(t *testing.T, r *Rule, syn *Synthesis) {
	t.Helper()
	if len(syn.Positive) == 0 {
		t.Fatal("no positives")
	}
	for _, ev := range syn.Positive {
		if m, err := r.Match(ev); err != nil || !m {
			t.Errorf("positive does not match: %s (%v)", String(ev), err)
		}
	}
	for _, ev := range syn.Negative {
		if m, err := r.Match(ev); err != nil || m {
			t.Errorf("negative matches: %s (%v)", String(ev), err)
		}
	}
}

// Rules with every kind of value get events they match, and near misses
// they do not.
func TestSynthesizeShapes(t *testing.T) {
	for _, src := range []string{
		// Regular expressions, alone and with other constraints.
		"title: t\ndetection:\n  sel:\n    CommandLine|re: '^powershell(\\.exe)? -[Ee]nc [A-Za-z0-9+/=]{8,}$'\n  condition: sel\n",
		"title: t\ndetection:\n  sel:\n    CommandLine|re|i: 'invoke-(web|rest)request'\n    CommandLine|contains: 'http'\n  condition: sel\n",
		"title: t\ndetection:\n  a:\n    CommandLine|re: '\\d{3}'\n  b:\n    CommandLine|startswith: 'run '\n    CommandLine|endswith: ' now'\n  condition: a and b\n",
		"title: t\ndetection:\n  a:\n    CommandLine|re: 'x[0-9]y'\n  b:\n    CommandLine: 'ax5yb'\n  condition: a and b\n",
		// Addresses in a range, and a list of them.
		"title: t\ndetection:\n  sel:\n    DestinationIp|cidr: ['10.0.0.0/8', '2001:db8::/32']\n  filter:\n    DestinationIp|cidr: '10.1.0.0/16'\n  condition: sel and not filter\n",
		// Encoded values.
		"title: t\ndetection:\n  sel:\n    CommandLine|base64offset|contains: 'IEX'\n    Image|windash|contains: ' -enc '\n  condition: sel\n",
		// Field presence.
		"title: t\ndetection:\n  sel:\n    Image|exists: true\n    Hashes|exists: false\n  condition: sel\n",
		// All of a list, with wildcards and escapes.
		"title: t\ndetection:\n  sel:\n    CommandLine|contains|all: ['a?c', 'd\\*e', ' tail ']\n  condition: sel\n",
		// Or of nots, and not of an or: every DNF branch.
		"title: t\ndetection:\n  a: {A: '1'}\n  b: {B: '2'}\n  c: {C: '3'}\n  condition: a and not (b or c)\n",
		"title: t\ndetection:\n  a: {A: '1'}\n  b: {B: '2'}\n  c: {C: '3'}\n  condition: a and not (b and c)\n",
		"title: t\ndetection:\n  a: {A: '1'}\n  b: {B: '2'}\n  c: {C: '3'}\n  condition: (a or b) and not c\n",
		"title: t\ndetection:\n  a: {A: '1'}\n  b: {B: '2'}\n  condition: not (not a or not b)\n",
		// Several alternatives in a selection, and a null value.
		"title: t\ndetection:\n  sel:\n    - Image|endswith: '\\x.exe'\n    - OriginalFileName: 'x.exe'\n      Product: null\n  condition: sel\n",
	} {
		r := mustParse(t, src)
		syn, err := r.Synthesize(7, map[string]string{"User": "tester"}, nil)
		if err != nil {
			t.Errorf("%v: %s", err, src)
			continue
		}
		checkSynthesis(t, r, syn)
	}
}

// Rules no event can satisfy are refused.
func TestSynthesizeImpossible(t *testing.T) {
	for _, src := range []string{
		"title: t\ndetection:\n  a: {A: 'x'}\n  condition: a and not a\n",
		"title: t\ndetection:\n  a: {A: null}\n  b: {A|contains: 'y'}\n  condition: a and b\n",
		"title: t\ndetection:\n  a: {A|cidr: 'bad'}\n  condition: a\n",
		"title: t\ndetection:\n  a: {A|frob: 'x'}\n  condition: a\n",
	} {
		r := mustParse(t, src)
		if syn, err := r.Synthesize(1); err == nil {
			t.Errorf("synthesized %+v for %s", syn, src)
		}
	}
}

// The building blocks of synthesis, directly.
func TestSynthesisParts(t *testing.T) {
	if got := instantiateCase(`a*b?c\*d\?e\\f\g`); got != `abxc*d?e\f\g` {
		t.Errorf("instantiateCase = %q", got)
	}
	if got := reFlags([]string{"re", "i", "s"}); got != "(?is)" {
		t.Errorf("reFlags = %q", got)
	}
	if got := reFlags([]string{"re"}); got != "" {
		t.Errorf("reFlags without flags = %q", got)
	}
	rng := rand.New(rand.NewSource(3))
	// A constraint set that must be missing and set is refused, unless the
	// only value is empty.
	if _, ok := build(rng, constraints{"A": {{how: "null"}, {how: "exists"}}}); ok {
		t.Error("missing and present")
	}
	if v, ok := build(rng, constraints{"A": {{how: "null"}, {how: "equals", pattern: ""}}}); !ok || v["A"] != "" {
		t.Errorf("missing and empty: %v %v", v, ok)
	}
	if _, ok := build(rng, constraints{"A": {{how: "cidr", pattern: "nope"}}}); ok {
		t.Error("bad cidr built")
	}
	v, ok := build(rng, constraints{"A": {{how: "cidr", pattern: "192.0.2.0/24"}}, "B": {{how: "equals", pattern: "**"}}, "C": {{how: "exists"}}})
	if !ok || !netip.MustParsePrefix("192.0.2.0/24").Contains(netip.MustParseAddr(v["A"])) || v["B"] != "x" || v["C"] != "x" {
		t.Errorf("built %v %v", v, ok)
	}
	v, ok = build(rng, constraints{"A": {{how: "contains", pattern: " mid "}}})
	if !ok || strings.TrimSpace(v["A"]) != v["A"] || !strings.Contains(v["A"], " mid ") {
		t.Errorf("spaces at the ends: %q %v", v["A"], ok)
	}
	if _, ok := build(rng, constraints{"A": {{how: "re", pattern: "^a$"}, {how: "equals", pattern: "b"}}}); ok {
		t.Error("conflicting expression and value built")
	}
	if _, ok := build(rng, constraints{"A": {{how: "re", pattern: "^a$"}, {how: "cidr", pattern: "10.0.0.0/8"}}}); ok {
		t.Error("expression and range built")
	}
	if _, ok := withRegexes(rng, []constraint{{how: "re", pattern: "("}}, []string{"("}, nil, nil, nil, nil); ok {
		t.Error("bad expression built")
	}

	// pick refuses keywords and empty selections.
	if err := pick(rng, &selection{keywords: []string{"x"}}, constraints{}); err == nil {
		t.Error("picked a keyword")
	}
	if err := pick(rng, &selection{}, constraints{}); err == nil {
		t.Error("picked from nothing")
	}
	// A selection with exists: false needs the field missing.
	cs := constraints{}
	f := "false"
	if err := pick(rng, &selection{alts: [][]*fieldCond{{{field: "A", mods: []string{"exists"}, values: []*string{&f}}}}}, cs); err != nil || cs["A"][0].how != "null" {
		t.Errorf("exists false: %v %v", cs, err)
	}

	for _, c := range []struct {
		fc   fieldCond
		want bool
	}{
		{fieldCond{mods: []string{"exists"}, values: []*string{&f}}, true},
		{fieldCond{mods: []string{"contains"}, values: []*string{&f}}, false},
		{fieldCond{values: []*string{nil}}, true},
		{fieldCond{values: []*string{&f}}, false},
	} {
		if got := missingTest(&c.fc); got != c.want {
			t.Errorf("missingTest(%+v) = %v", c.fc, got)
		}
	}
	// A term with too many alternatives is cut to maxTerms.
	var kids []node
	for i := 0; i < maxTerms+5; i++ {
		kids = append(kids, &selNode{s: &selection{}})
	}
	if got := len(dnf(&orNode{kids}, false)); got != maxTerms {
		t.Errorf("or terms = %d", got)
	}
	if got := len(dnf(&notNode{&andNode{kids}}, false)); got != maxTerms {
		t.Errorf("not-and terms = %d", got)
	}
	pair := []node{&orNode{kids[:9]}, &orNode{kids[:9]}}
	if got := len(dnf(&andNode{pair}, false)); got > maxTerms+9 {
		t.Errorf("and terms = %d", got)
	}
	if dnf(nil, false) != nil {
		t.Error("terms of nothing")
	}
}

// A regular expression's example is used when the other constraints alone
// do not satisfy it.
func TestWithRegexes(t *testing.T) {
	rng := rand.New(rand.NewSource(5))
	re := `id=\d+`
	cs := []constraint{{how: "re", pattern: re}, {how: "startswith", pattern: "GET "}, {how: "endswith", pattern: " end"}}
	v, ok := withRegexes(rng, cs, []string{re}, nil, []string{"GET "}, []string{" end"}, nil)
	if !ok || !regexp.MustCompile(re).MatchString(v) || !strings.HasPrefix(v, "GET") || !strings.HasSuffix(v, "end") {
		t.Errorf("value %q %v", v, ok)
	}
}

// A Sysmon for Linux program start is also written as the audit records
// of it, which the real parser joins into the same program start.
func TestAuditdProcessRecords(t *testing.T) {
	now := time.Now().Add(-time.Hour)
	c := Case{Channel: LinuxSysmonChannel, EventID: "1", Data: map[string]string{
		"Image": "/usr/bin/curl", "CommandLine": "curl -s http://example.com/x", "ParentImage": "/bin/bash",
		"ParentCommandLine": "bash -i", "User": "tester", "LogonId": "1001", "CurrentDirectory": "/tmp",
		"ProcessId": "300", "ParentProcessId": "200",
	}}
	recs, ok := c.AuditdProcessRecords("lnx-1", now)
	if !ok || len(recs) != 5 {
		t.Fatalf("records = %d %v", len(recs), ok)
	}
	ev, ok := c.AuditdProcessStart("lnx-1", now)
	if !ok || ev.Model != "Endpoint" {
		t.Fatalf("start = %v %v", ev, ok)
	}
	if ev.Fields["process"] != "curl -s http://example.com/x" || ev.Fields["process_name"] != "curl" || ev.Fields["host"] != "lnx-1" {
		t.Errorf("start fields = %v", ev.Fields)
	}

	// A start without a program or parent still records one.
	bare := Case{Channel: LinuxSysmonChannel, EventID: "1", Data: map[string]string{"User": "tester"}}
	recs, ok = bare.AuditdProcessRecords("lnx-1", now)
	if !ok || len(recs) != 2 {
		t.Errorf("bare = %d %v", len(recs), ok)
	}
	if ev, ok := bare.AuditdProcessStart("lnx-1", now); !ok || ev.Fields["process_path"] != "/opt/test/program" {
		t.Errorf("bare start = %v %v", ev.Fields, ok)
	}

	for _, c := range []Case{
		{Channel: SysmonChannel, EventID: "1"},
		{Channel: LinuxSysmonChannel, EventID: "3"},
		{Channel: LinuxSysmonChannel, EventID: "1", Data: map[string]string{"Hashes": "x"}},
	} {
		if _, ok := c.AuditdProcessRecords("h", now); ok {
			t.Errorf("records of %+v", c)
		}
		if _, ok := c.AuditdProcessStart("h", now); ok {
			t.Errorf("start of %+v", c)
		}
	}
	if got := withSerial("type=X msg=audit(1.0:4242): a=b", 3); got != "type=X msg=audit(1.0:4245): a=b" {
		t.Errorf("withSerial = %q", got)
	}
	if baseNameOf("/a/b") != "b" || baseNameOf("c") != "c" {
		t.Error("baseNameOf")
	}
}
