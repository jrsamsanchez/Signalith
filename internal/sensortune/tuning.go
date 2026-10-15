// Package sensortune keeps the Suricata rule tuning admins edit on
// Settings > Network sensors: the rules to turn off (disable.conf), the
// limits and suppressions (threshold.config) and their own rules
// (local.rules). Every network sensor fetches it with its sensor token
// (GET /api/sensor/tuning) and applies it after suricata-update tested it.
//
// The sensor writes what it fetches to files and never runs it, so the
// checks here are a syntax gate, not a Suricata parser: each line must be
// one of the forms the file takes, nothing may look like the bundle's
// section markers, and rules may not use the keywords that make Suricata
// run Lua or read and write files on the sensor, not even in a rule that
// is commented out, which suricata-update can turn back on.
package sensortune

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// The three fields, as the API and the bundle name them.
const (
	FieldDisable   = "disable"
	FieldThreshold = "threshold"
	FieldLocal     = "local"
)

// Fields lists them in the bundle's order.
var Fields = []string{FieldDisable, FieldThreshold, FieldLocal}

// Labels are the fields as the page names them, for messages.
var Labels = map[string]string{
	FieldDisable:   "Rules to turn off",
	FieldThreshold: "Limits and suppressions",
	FieldLocal:     "Your own rules",
}

// Limits on what an admin may save: every sensor fetches it.
const (
	MaxFieldBytes  = 256 << 10
	MaxLineBytes   = 8 << 10
	MaxDisable     = 5000
	MaxThreshold   = 2000
	MaxLocal       = 5000
	MaxBundleBytes = 3*MaxFieldBytes + 1024
	// Local rules normally use SIDs in this range, which no published
	// rule set uses.
	LocalSIDMin = 1000000
	LocalSIDMax = 1999999
)

// BundleHeader is the bundle's first line, and BundleEnd its last: a
// sensor refuses a body without it as cut short.
const (
	BundleHeader = "# signalith-sensor-tuning 1"
	BundleEnd    = "[end]"
)

// Tuning is the rule tuning every sensor fetches.
type Tuning struct {
	Disable   string    `json:"disable"`
	Threshold string    `json:"threshold"`
	Local     string    `json:"local"`
	UpdatedBy string    `json:"updated_by,omitempty"`
	UpdatedAt time.Time `json:"updated_at,omitzero"`
}

// Field returns one of the three texts.
func (t Tuning) Field(name string) string {
	switch name {
	case FieldDisable:
		return t.Disable
	case FieldThreshold:
		return t.Threshold
	case FieldLocal:
		return t.Local
	}
	return ""
}

// LineError is a line the checks refuse: Line counts from 1, 0 for the
// whole field.
type LineError struct {
	Field string
	Line  int
	Msg   string
}

func (e *LineError) Error() string {
	label := Labels[e.Field]
	if e.Line > 0 {
		return fmt.Sprintf("%s, line %d: %s", label, e.Line, e.Msg)
	}
	return label + ": " + e.Msg
}

// Normalize tidies what a browser sent: Windows line ends, a byte order
// mark, spaces at the end of lines and blank lines at the end go. Blank
// lines at the start stay, so a line number in a *LineError is the line
// the admin sees in the box.
func (t Tuning) Normalize() Tuning {
	t.Disable = normalize(t.Disable)
	t.Threshold = normalize(t.Threshold)
	t.Local = normalize(t.Local)
	return t
}

func normalize(s string) string {
	s = strings.TrimPrefix(s, "\ufeff")
	s = strings.ReplaceAll(s, "\r\n", "\n")
	lines := strings.Split(s, "\n")
	for i, l := range lines {
		lines[i] = strings.TrimRight(l, " \t")
	}
	for len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	return strings.Join(lines, "\n")
}

// lines splits a normalized field; none for an empty one.
func lines(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}

// skip reports whether a line is blank or a comment.
func skip(l string) bool {
	l = strings.TrimSpace(l)
	return l == "" || strings.HasPrefix(l, "#")
}

// Validate checks a normalized tuning and returns the first problem, a
// *LineError.
func (t Tuning) Validate() error {
	if err := t.check(FieldDisable, MaxDisable, disableLine); err != nil {
		return err
	}
	if err := t.check(FieldThreshold, MaxThreshold, thresholdLine); err != nil {
		return err
	}
	return t.check(FieldLocal, MaxLocal, localLine(map[uint64]int{}))
}

// check runs the checks every field shares, then one per line.
func (t Tuning) check(field string, max int, line func(string, int) string) error {
	s := t.Field(field)
	if len(s) > MaxFieldBytes {
		return &LineError{Field: field, Msg: fmt.Sprintf("this box holds at most %d KB; it has %d KB", MaxFieldBytes>>10, (len(s)+1023)>>10)}
	}
	n := 0
	for i, l := range lines(s) {
		if msg := common(l); msg != "" {
			return &LineError{Field: field, Line: i + 1, Msg: msg}
		}
		if skip(l) {
			if field == FieldLocal {
				if msg := commentedRule(l); msg != "" {
					return &LineError{Field: field, Line: i + 1, Msg: msg}
				}
			}
			continue
		}
		if n++; n > max {
			return &LineError{Field: field, Line: i + 1, Msg: fmt.Sprintf("this box holds at most %d entries", max)}
		}
		if line == nil {
			continue
		}
		if msg := line(strings.TrimSpace(l), i+1); msg != "" {
			return &LineError{Field: field, Line: i + 1, Msg: msg}
		}
	}
	return nil
}

// common checks what every line must be: text, not too long, and never
// like the bundle's markers.
func common(l string) string {
	switch {
	case !utf8.ValidString(l):
		return "the line is not text (UTF-8)"
	case len(l) > MaxLineBytes:
		return fmt.Sprintf("the line is longer than %d KB", MaxLineBytes>>10)
	case strings.ContainsFunc(l, func(c rune) bool {
		return c != '\t' && (c < ' ' || c == 0x7f || c == 0x85 || c == 0x2028 || c == 0x2029)
	}):
		return "the line holds a control character; type it again by hand"
	case strings.HasPrefix(strings.TrimSpace(l), "["):
		return "a line cannot start with ["
	}
	return ""
}

var (
	reSID      = `[0-9]{1,10}`
	reIDList   = regexp.MustCompile(`^(` + reSID + `(:` + reSID + `)?)(\s*,\s*` + reSID + `(:` + reSID + `)?)*$`)
	reGroup    = regexp.MustCompile(`^group:\s*[A-Za-z0-9._/*-]{1,128}$`)
	reMetadata = regexp.MustCompile(`^metadata:\s*[A-Za-z0-9_.-]{1,64}\s+[A-Za-z0-9_.:/ -]{1,128}$`)
	// reNested finds a repeated group that holds a repeat, such as (a+)+
	// or (a|b*){2,}: suricata-update matches re: patterns with Python's
	// backtracking regular expressions against every rule, and such a
	// pattern can take exponential time. reBackref finds a back
	// reference, which no linear-time matcher supports either.
	reNested  = regexp.MustCompile(`\([^()]*(?:[+*]|\{[0-9,]+\})[^()]*\)(?:[+*]|\{[0-9,]+\})`)
	reBackref = regexp.MustCompile(`\\[1-9]|\(\?P=`)
)

// disableLine checks one line of disable.conf, the forms suricata-update
// reads: a SID, gid:sid (or a list of them), re:<pattern>, group:<file>
// or metadata:<key> <value>.
func disableLine(l string, _ int) string {
	const help = "write a rule's SID such as 2014520, gid:sid such as 1:2014520, re:<pattern>, group:<rules file> or metadata:<key> <value>"
	switch {
	case reIDList.MatchString(l):
		for _, part := range strings.Split(l, ",") {
			part = strings.TrimSpace(part)
			if i := strings.IndexByte(part, ':'); i >= 0 {
				if msg := idRange(part[:i], 0); msg != "" {
					return msg
				}
				part = part[i+1:]
			}
			if msg := idRange(part, 1); msg != "" {
				return msg
			}
		}
		return ""
	case strings.HasPrefix(l, "re:"):
		p := strings.TrimSpace(l[3:])
		if p == "" || len(p) > 512 {
			return "write the pattern after re: (at most 512 characters)"
		}
		if reNested.MatchString(p) || reBackref.MatchString(p) {
			return "this pattern repeats a group that itself repeats (such as (a+)+) or refers back to a group: suricata-update could take hours on it. Write a simpler pattern"
		}
		return ""
	case strings.HasPrefix(l, "group:"):
		if !reGroup.MatchString(l) || strings.Contains(l, "..") {
			return "write a rules file name after group:, such as group:emerging-icmp.rules"
		}
		return ""
	case strings.HasPrefix(l, "metadata:"):
		if !reMetadata.MatchString(l) {
			return "write a key and a value after metadata:, such as metadata: deployment perimeter"
		}
		return ""
	}
	return help
}

// idRange checks a SID or gid: a number from min to 2^32-1.
func idRange(s string, min uint64) string {
	n, err := strconv.ParseUint(s, 10, 32)
	if err != nil || n < min {
		return fmt.Sprintf("%s is not a rule number (%d to 4294967295)", s, min)
	}
	return ""
}

var (
	num         = `[0-9]{1,10}`
	sep         = `\s*,\s*`
	gidSid      = `gen_id\s+` + num + sep + `sig_id\s+` + num
	trackRule   = `track\s+(by_src|by_dst|by_rule|by_both)`
	reSuppress  = regexp.MustCompile(`^suppress\s+` + gidSid + `(` + sep + `track\s+(by_src|by_dst|by_either)` + sep + `ip\s+(\[[^\]]*\]|\S+)` + `)?$`)
	reThreshold = regexp.MustCompile(`^(threshold|event_filter)\s+` + gidSid + sep + `type\s+(limit|threshold|both)` + sep + trackRule +
		sep + `count\s+` + num + sep + `seconds\s+` + num + `$`)
	reRate = regexp.MustCompile(`^rate_filter\s+` + gidSid + sep + trackRule + sep + `count\s+` + num + sep + `seconds\s+` + num +
		sep + `new_action\s+(alert|drop|pass|reject)` + sep + `timeout\s+` + num + `$`)
	reVar = regexp.MustCompile(`^!?\$[A-Z][A-Z0-9_]{0,63}$`)
)

// thresholdLine checks one line of threshold.config: suppress,
// threshold, event_filter or rate_filter, as Suricata documents them.
func thresholdLine(l string, _ int) string {
	if m := reSuppress.FindStringSubmatch(l); m != nil {
		if ip := m[len(m)-1]; ip != "" && !addresses(ip) {
			return ip + " is not an address: write an IP, a network such as 10.0.0.0/8, a list in [ ], or a variable such as $HOME_NET"
		}
		return ""
	}
	if reThreshold.MatchString(l) || reRate.MatchString(l) {
		return ""
	}
	switch first, _, _ := strings.Cut(l, " "); first {
	case "suppress":
		return "write it as: suppress gen_id 1, sig_id 2014520 (and optionally , track by_src, ip 10.0.0.5)"
	case "threshold", "event_filter":
		return "write it as: " + first + " gen_id 1, sig_id 2014520, type limit, track by_src, count 1, seconds 60"
	case "rate_filter":
		return "write it as: rate_filter gen_id 1, sig_id 2014520, track by_rule, count 10, seconds 60, new_action alert, timeout 300"
	}
	return "each line starts with suppress, threshold, event_filter or rate_filter"
}

// addresses checks suppress's ip: an address, a network, a variable, or
// a list of them in [ ].
func addresses(s string) bool {
	if strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]") {
		items := strings.Split(s[1:len(s)-1], ",")
		if len(items) == 0 || len(items) > 64 {
			return false
		}
		for _, it := range items {
			if !address(strings.TrimSpace(it)) {
				return false
			}
		}
		return true
	}
	return address(s)
}

func address(s string) bool {
	if reVar.MatchString(s) {
		return true
	}
	s = strings.TrimPrefix(s, "!")
	if _, err := netip.ParseAddr(s); err == nil {
		return true
	}
	_, err := netip.ParsePrefix(s)
	return err == nil
}

var (
	reRule = regexp.MustCompile(`^(alert|drop|pass|reject|rejectsrc|rejectdst|rejectboth|config)\s+\S+\s+.*\(.*\)$`)
	reSIDs = regexp.MustCompile(`(?:^|[;(\s])sid\s*:\s*([0-9]+)\s*;`)
	// reForbidden finds the rule keywords that run Lua or read and write
	// files on the sensor (ForbiddenKeywords).
	reForbidden = regexp.MustCompile(`(?i)(?:^|[;(\s])(` + strings.Join(ForbiddenKeywords, "|") + `)\s*[:;]`)
	// reCommented finds a rule after the # of a comment, as
	// suricata-update reads a disabled rule.
	reCommented = regexp.MustCompile(`^[\s#]*(.*)$`)
)

// ForbiddenKeywords are the rule keywords that run code or read and
// write files on the sensor: Lua scripts, datasets and their JSON and
// reputation files, IP reputation files, file hash lists and stored
// files. A rule using one belongs in /etc/signalith-sensor/local.rules on
// the sensor, where only its admin puts it.
var ForbiddenKeywords = []string{
	"lua", "luajit", "luaxform",
	"dataset", "datarep", "datajson",
	"iprep",
	"filemd5", "filesha1", "filesha256",
	"filestore",
}

// commentedRule checks a comment line of the local rules: suricata-update
// reads a commented-out rule as a disabled one, which an enable.conf or
// modify.conf on the sensor can turn on, so it may not use the forbidden
// keywords either.
func commentedRule(l string) string {
	r := reCommented.FindStringSubmatch(l)[1]
	if !reRule.MatchString(strings.ToLower(r)) {
		return ""
	}
	_, opts, _ := strings.Cut(r, "(")
	if m := reForbidden.FindStringSubmatch(opts); m != nil {
		return "rules here cannot use " + strings.ToLower(m[1]) + ", even commented out (suricata-update can turn a commented rule back on): it runs code or reads and writes files on the sensor. Keep such a rule in /etc/signalith-sensor/local.rules on the sensor itself"
	}
	return ""
}

// localLine checks one local rule: one rule a line, with one SID used
// by no rule above it, and none of the forbidden keywords.
func localLine(seen map[uint64]int) func(string, int) string {
	return func(l string, n int) string {
		if !reRule.MatchString(l) {
			return "write one whole rule per line: action, protocol, addresses, then options in ( ), such as alert tcp any any -> $HOME_NET 23 (msg:\"Telnet\"; sid:1000001; rev:1;)"
		}
		_, opts, _ := strings.Cut(l, "(")
		if m := reForbidden.FindStringSubmatch(opts); m != nil {
			return "rules here cannot use " + strings.ToLower(m[1]) + ": it runs code or reads and writes files on the sensor. Keep such a rule in /etc/signalith-sensor/local.rules on the sensor itself"
		}
		sids := reSIDs.FindAllStringSubmatch(opts, -1)
		if len(sids) != 1 {
			return "a rule needs exactly one sid, such as sid:1000001;"
		}
		if msg := idRange(sids[0][1], 1); msg != "" {
			return msg
		}
		sid, _ := strconv.ParseUint(sids[0][1], 10, 32)
		if first, ok := seen[sid]; ok {
			return fmt.Sprintf("sid %d is used on line %d too; each rule needs its own", sid, first)
		}
		seen[sid] = n
		return ""
	}
}

// localSIDs returns the SIDs of the local rules, in order.
func (t Tuning) localSIDs() []uint64 {
	var out []uint64
	for _, l := range lines(t.Local) {
		if skip(l) {
			continue
		}
		_, opts, _ := strings.Cut(l, "(")
		if m := reSIDs.FindStringSubmatch(opts); m != nil {
			if n, err := strconv.ParseUint(m[1], 10, 32); err == nil {
				out = append(out, n)
			}
		}
	}
	return out
}

// Warnings are what is allowed but probably a mistake.
func (t Tuning) Warnings() []string {
	var out []string
	for _, sid := range t.localSIDs() {
		if sid < LocalSIDMin || sid > LocalSIDMax {
			out = append(out, fmt.Sprintf("Your own rules: sid %d is outside %d-%d, the range kept for local rules; it may clash with a published rule.", sid, LocalSIDMin, LocalSIDMax))
			if len(out) == 5 {
				break
			}
		}
	}
	return out
}

// Counts are how many entries each field has: blank lines and comments
// are not counted.
func (t Tuning) Counts() map[string]int {
	out := map[string]int{}
	for _, f := range Fields {
		n := 0
		for _, l := range lines(t.Field(f)) {
			if !skip(l) {
				n++
			}
		}
		out[f] = n
	}
	return out
}

// Bundle is the text a sensor fetches: a header line, then each field
// under its [name] line, then [end]. Validate makes sure no line of a
// field starts with [.
func (t Tuning) Bundle() []byte {
	var b bytes.Buffer
	b.WriteString(BundleHeader + "\n")
	for _, f := range Fields {
		b.WriteString("[" + f + "]\n")
		if s := t.Field(f); s != "" {
			b.WriteString(s)
			b.WriteByte('\n')
		}
	}
	b.WriteString(BundleEnd + "\n")
	return b.Bytes()
}

// Hash is the SHA-256 of the bundle in hex: its ETag, and what a sensor
// reports it runs.
func (t Tuning) Hash() string {
	sum := sha256.Sum256(t.Bundle())
	return hex.EncodeToString(sum[:])
}

// ShortHash is the part of Hash a sensor's status line carries.
func ShortHash(h string) string {
	if len(h) > 12 {
		return h[:12]
	}
	return h
}

// Limits on Diff, so one audit line stays readable.
const (
	maxDiffLines     = 100
	maxDiffLineBytes = 300
)

// Diff returns the lines of a field added and removed from before to
// after, blank lines aside, for the audit trail: at most maxDiffLines
// each, cut to maxDiffLineBytes, the last one saying how many more there
// are.
func Diff(before, after string) (added, removed []string) {
	count := func(s string) map[string]int {
		m := map[string]int{}
		for _, l := range lines(s) {
			if strings.TrimSpace(l) != "" {
				m[l]++
			}
		}
		return m
	}
	b, a := count(before), count(after)
	pick := func(from string, other map[string]int) []string {
		var out []string
		left := map[string]int{}
		for l, n := range other {
			left[l] = n
		}
		more := 0
		for _, l := range lines(from) {
			if strings.TrimSpace(l) == "" {
				continue
			}
			if left[l] > 0 {
				left[l]--
				continue
			}
			if len(out) == maxDiffLines {
				more++
				continue
			}
			if len(l) > maxDiffLineBytes {
				l = strings.ToValidUTF8(l[:maxDiffLineBytes], "") + "..."
			}
			out = append(out, l)
		}
		if more > 0 {
			out = append(out, fmt.Sprintf("(and %d more lines)", more))
		}
		return out
	}
	return pick(after, b), pick(before, a)
}
