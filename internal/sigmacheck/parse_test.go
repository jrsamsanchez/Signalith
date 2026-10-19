// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package sigmacheck

import (
	"math/rand"
	"reflect"
	"regexp"
	"strings"
	"testing"
)

func mustParse(t *testing.T, src string) *Rule {
	t.Helper()
	r, err := Parse([]byte(src))
	if err != nil {
		t.Fatalf("parse: %v\n%s", err, src)
	}
	return r
}

// Rules that cannot be read are refused, each with its reason.
func TestParseErrors(t *testing.T) {
	for _, c := range []struct{ src, want string }{
		{"title: [unclosed", ""},
		{"title: t\n", "no detection section"},
		{"title: t\ndetection:\n  sel: {a: b}\n", "no condition"},
		{"title: t\ndetection:\n  sel: {a: b}\n  condition: [sel, sel]\n", "several conditions"},
		{"title: t\ndetection:\n  sel: {a: b}\n  condition: sel | count() > 5\n", "aggregation condition"},
		{"title: t\ndetection:\n  sel: 5\n  condition: sel\n", "selection sel: unsupported shape int"},
		{"title: t\ndetection:\n  sel: [{a: b}]\n  condition: other\n", "unknown selection other"},
		{"title: t\ndetection:\n  sel: {a: b}\n  condition: (sel\n", "missing )"},
		{"title: t\ndetection:\n  sel: {a: b}\n  condition: sel and\n", "condition ended early"},
		{"title: t\ndetection:\n  sel: {a: b}\n  condition: 1 sel\n", "expected of after 1"},
		{"title: t\ndetection:\n  sel: {a: b}\n  condition: all of\n", "of needs a name"},
		{"title: t\ndetection:\n  sel: {a: b}\n  condition: 1 of filter*\n", "nothing matches filter*"},
		{"title: t\ndetection:\n  sel: {a: b}\n  condition: sel sel\n", `unexpected "sel"`},
		{"title: t\ndetection:\n  sel: {a: b}\n  condition: (sel or\n", "condition ended early"},
		{"title: t\ndetection:\n  sel: {a: b}\n  condition: not\n", "condition ended early"},
		{"title: t\ndetection:\n  sel: [{a: b}, 5]\n  other: [{a: [1, 2]}, {b: 5}]\n  condition: sel and (other\n", "missing )"},
	} {
		_, err := Parse([]byte(c.src))
		if err == nil {
			t.Errorf("%q parsed", c.src)
			continue
		}
		if c.want != "" && err.Error() != c.want {
			t.Errorf("%q: error %q, want %q", c.src, err, c.want)
		}
	}
	// A condition given as a one-item list is that condition.
	r := mustParse(t, "title: t\ndetection:\n  sel: {a: b}\n  timeframe: 5m\n  condition: [sel]\n")
	if m, err := r.Match(map[string]string{"a": "B"}); err != nil || !m {
		t.Errorf("list condition: %v %v", m, err)
	}
}

// A Security log rule's legacy event IDs are dropped when it names current
// ones too, and kept when they are all it names.
func TestEventIDsAndFields(t *testing.T) {
	r := mustParse(t, `title: t
logsource: {product: Windows, service: Security}
detection:
  sel:
    EventID: [517, 1102]
  other:
    EventID|contains: 5
    SubjectUserName: tester
  condition: sel or other
`)
	if r.Logsource["product"] != "windows" {
		t.Errorf("logsource not lower-cased: %v", r.Logsource)
	}
	if got := r.EventIDs(); !reflect.DeepEqual(got, []string{"1102"}) {
		t.Errorf("EventIDs = %v", got)
	}
	if got := r.Fields(); !reflect.DeepEqual(got, []string{"EventID", "SubjectUserName"}) {
		t.Errorf("Fields = %v", got)
	}
	if m, _ := r.Match(map[string]string{"EventID": "517"}); m {
		t.Error("the legacy ID was not dropped from the selection")
	}
	if m, _ := r.Match(map[string]string{"EventID": "1102"}); !m {
		t.Error("1102 does not match")
	}

	legacy := mustParse(t, "title: t\nlogsource: {service: security}\ndetection:\n  sel:\n    EventID: [517, null]\n  condition: sel\n")
	if got := legacy.EventIDs(); !reflect.DeepEqual(got, []string{"517"}) {
		t.Errorf("legacy EventIDs = %v", got)
	}
	if m, _ := legacy.Match(map[string]string{"EventID": "517"}); !m {
		t.Error("a rule of only legacy IDs lost them")
	}
	if legacy.HasKeywords() {
		t.Error("field rule has keywords")
	}
}

// Web server and Google Cloud keywords become searches of the fields the
// converter searches.
func TestKeywordRewrites(t *testing.T) {
	web := mustParse(t, "title: t\nlogsource: {category: webserver}\ndetection:\n  keywords: ['/etc/passwd', 'union select']\n  condition: keywords\n")
	if web.HasKeywords() {
		t.Fatal("web keywords kept as free text")
	}
	if got := web.Fields(); !reflect.DeepEqual(got, []string{"cs-referer", "cs-uri-query", "cs-user-agent"}) {
		t.Errorf("web fields = %v", got)
	}
	for _, f := range WebKeywordFields {
		if m, err := web.Match(map[string]string{f: "x UNION SELECT y"}); err != nil || !m {
			t.Errorf("%s: %v %v", f, m, err)
		}
	}
	if m, _ := web.Match(map[string]string{"cs-method": "/etc/passwd"}); m {
		t.Error("matched a field keywords are not searched in")
	}

	gcp := mustParse(t, "title: t\nlogsource: {product: gcp, service: gcp.audit}\ndetection:\n  keywords: 'setIamPolicy'\n  sel: {a: b}\n  condition: keywords or sel\n")
	if gcp.HasKeywords() {
		t.Fatal("gcp keywords kept as free text")
	}
	if m, err := gcp.Match(map[string]string{"data.protoPayload.request": `{"method":"SetIamPolicy"}`}); err != nil || !m {
		t.Errorf("gcp keyword: %v %v", m, err)
	}

	// Elsewhere a keyword is free text, which is not evaluated.
	kw := mustParse(t, "title: t\ndetection:\n  keywords: [evil]\n  condition: keywords\n")
	if !kw.HasKeywords() {
		t.Fatal("no keywords")
	}
	if _, err := kw.Match(map[string]string{"a": "evil"}); err == nil {
		t.Error("keyword evaluated")
	}
}

// Every modifier is read by the specification.
func TestModifiers(t *testing.T) {
	r := mustParse(t, `title: t
detection:
  re: {A|re: '^ab+c$'}
  rei: {B|re|i: '^HELLO'}
  rems: {C|re|m|s: '^two.three$'}
  cidr: {Ip|cidr: ['10.0.0.0/8', '192.168.0.0/16']}
  b64: {D|base64: 'hi'}
  le: {E|utf16le|base64: 'a'}
  be: {F|utf16be|base64: 'a'}
  u16: {G|utf16|base64: 'a'}
  wide: {H|wide|base64offset|contains: 'abc'}
  ex: {I|exists: true}
  nex: {J|exists: false}
  all: {K|contains|all: [x, y]}
  cased: {L|cased: 'Exact'}
  starts: {M|startswith: 'pre'}
  ends: {N|endswith: 'post'}
  quest: {O: 'a?c'}
  esc: {P: 'a\\b'}
  boolv: {R: true}
  condition: 1 of them
`)
	for _, c := range []struct {
		ev   map[string]string
		want bool
	}{
		{map[string]string{"A": "abbbc"}, true},
		{map[string]string{"A": "ac", "J": "1"}, false},
		{map[string]string{"B": "hello world"}, true},
		{map[string]string{"C": "one\ntwo\nthree"}, true},
		{map[string]string{"Ip": "10.1.2.3"}, true},
		{map[string]string{"Ip": "192.168.4.4"}, true},
		{map[string]string{"Ip": "172.16.0.1", "J": "1"}, false},
		{map[string]string{"Ip": "not-an-ip", "J": "1"}, false},
		{map[string]string{"D": "aGk="}, true},
		{map[string]string{"E": "YQA="}, true},
		{map[string]string{"F": "AGE="}, true},
		{map[string]string{"G": "//5hAA=="}, true},
		{map[string]string{"I": "anything"}, true},
		{map[string]string{"X": "1"}, true}, // J is missing
		{map[string]string{"J": "1", "K": "y and x"}, true},
		{map[string]string{"J": "1", "K": "just x"}, false},
		{map[string]string{"J": "1", "L": "exact"}, true}, // cased is read, compared as Sigma's default
		{map[string]string{"J": "1", "M": "PREFIX"}, true},
		{map[string]string{"J": "1", "N": "xpost"}, true},
		{map[string]string{"J": "1", "N": "postx"}, false},
		{map[string]string{"J": "1", "O": "abc"}, true},
		{map[string]string{"J": "1", "O": "abbc"}, false},
		{map[string]string{"J": "1", "P": `a\b`}, true},
		{map[string]string{"J": "1", "R": "TRUE"}, true},
		{map[string]string{"J": "1", "R": "yes"}, false},
	} {
		if got, err := r.Match(c.ev); err != nil || got != c.want {
			t.Errorf("%v: %v %v, want %v", c.ev, got, err, c.want)
		}
	}
	// An empty value, and an empty list, match a missing field.
	empty := mustParse(t, "title: t\ndetection:\n  a: {Q: ''}\n  b: {S: []}\n  condition: a and b\n")
	if m, err := empty.Match(map[string]string{"Q": "-"}); err != nil || !m {
		t.Errorf("empty: %v %v", m, err)
	}
	if m, _ := empty.Match(map[string]string{"S": "set"}); m {
		t.Error("an empty list matched a set field")
	}
	// With |wide|base64offset the value is found at any offset.
	_, pats, err := Patterns([]string{"wide", "base64offset", "contains"}, "abc")
	if err != nil || len(pats) != 3 {
		t.Fatalf("wide base64offset: %q %v", pats, err)
	}

	for _, src := range []string{
		"title: t\ndetection:\n  sel: {A|re: '('}\n  condition: sel\n",
		"title: t\ndetection:\n  sel: {A|cidr: 'nope'}\n  condition: sel\n",
		"title: t\ndetection:\n  sel: {A|frobnicate: 'x'}\n  condition: sel\n",
	} {
		r := mustParse(t, src)
		if _, err := r.Match(map[string]string{"A": "x"}); err == nil {
			t.Errorf("no error from %s", src)
		}
		// The error stops an or and an and alike.
		or := mustParse(t, strings.Replace(src, "condition: sel", "ok: {B: y}\n  condition: sel or ok", 1))
		if _, err := or.Match(map[string]string{"A": "x"}); err == nil {
			t.Errorf("or hid the error of %s", src)
		}
		and := mustParse(t, strings.Replace(src, "condition: sel", "ok: {B: y}\n  condition: ok and sel", 1))
		if _, err := and.Match(map[string]string{"A": "x", "B": "y"}); err == nil {
			t.Errorf("and hid the error of %s", src)
		}
		not := mustParse(t, strings.Replace(src, "condition: sel", "condition: not sel", 1))
		if _, err := not.Match(map[string]string{"A": "x"}); err == nil {
			t.Errorf("not hid the error of %s", src)
		}
	}
}

// Conditions combine selections with and, or, not, parentheses and the
// "of" forms.
func TestConditions(t *testing.T) {
	r := mustParse(t, `title: t
detection:
  sel_a: {A: '1'}
  sel_b: {B: '1'}
  filter: {C: '1'}
  condition: (all of sel_* and not filter) or (any of filter and sel_a)
`)
	for _, c := range []struct {
		ev   map[string]string
		want bool
	}{
		{map[string]string{"A": "1", "B": "1"}, true},
		{map[string]string{"A": "1", "B": "1", "C": "1"}, true},
		{map[string]string{"A": "1", "C": "1"}, true},
		{map[string]string{"B": "1", "C": "1"}, false},
		{map[string]string{"A": "1"}, false},
	} {
		if got, err := r.Match(c.ev); err != nil || got != c.want {
			t.Errorf("%v: %v %v, want %v", c.ev, got, err, c.want)
		}
	}
}

// A regular expression's example matches it.
func TestRegexExample(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	for _, p := range []string{
		`^a(b|c)+d?e*[0-9]{2,3}x{0,2}.$`,
		`(?i)hello\s+world`,
		`[^a-z]q`,
		`[ ]x`,
		`[!-#]`,
	} {
		re := regexp.MustCompile(p)
		for i := 0; i < 10; i++ {
			s, err := RegexExample(rng, p)
			if err != nil {
				t.Fatalf("%s: %v", p, err)
			}
			if !re.MatchString(s) {
				t.Errorf("%s: example %q does not match", p, s)
			}
		}
	}
	if _, err := RegexExample(rng, `(`); err == nil {
		t.Error("example of a bad expression")
	}
	if _, err := RegexExample(rng, `\bword\b`); err == nil {
		t.Error("example of a word boundary between letters")
	}
	if got := classRune([]rune{0x4e00, 0x4e01}); got != 0x4e00 {
		t.Errorf("class of only wide runes: %q", got)
	}
	if got := classRune([]rune{' ', ' '}); got != ' ' {
		t.Errorf("class of a space: %q", got)
	}
	if got := classRune([]rune{'!', '#'}); got != '!' {
		t.Errorf("class of punctuation: %q", got)
	}
	if got := classRune([]rune{'!', '#', '0', '9', 'a', 'c'}); got != 'a' {
		t.Errorf("class prefers a letter: %q", got)
	}
}
