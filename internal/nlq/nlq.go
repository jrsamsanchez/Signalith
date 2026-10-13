// Package nlq turns plain-English questions into Signalith queries, such
// as "failed logins from 203.0.113.9 in the last 24 hours" or "top 10 users
// with failed logins". It works offline with a vocabulary of security
// terms, CIM field names and data models, and reports which words it used
// and which it ignored, so an analyst can see why the query looks the way
// it does. Harder questions can go to an AI model (see package assistant).
package nlq

import (
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"unicode"

	"github.com/jrsamsanchez/signalith/internal/query"
)

// Step explains how one phrase of the question was understood.
type Step struct {
	Phrase  string `json:"phrase"`
	Meaning string `json:"meaning"`
}

// Result is a translated question.
type Result struct {
	Query string `json:"query"`
	Steps []Step `json:"steps"`
	// Unknown lists the words that were not understood.
	Unknown []string `json:"unknown,omitempty"`
	// Confidence is the share of meaningful words that were understood,
	// from 0 to 1.
	Confidence float64 `json:"confidence"`
}

// Hints tells the translator which bare words are known users or hosts,
// usually from the asset and identity lists. Nil is fine.
type Hints interface {
	KnownUser(v string) bool
	KnownHost(v string) bool
}

// Translate converts a question to a query. It always returns a query
// that parses; a question with nothing recognizable becomes a text search.
func Translate(question string, hints Hints) (*Result, error) {
	t := &translator{toks: tokenize(question), hints: hints}
	if len(t.toks) == 0 {
		return nil, fmt.Errorf("ask a question, for example: failed logins in the last 24 hours")
	}
	t.used = make([]bool, len(t.toks))
	t.malware = mentionsMalware(t.toks)
	for t.i < len(t.toks) {
		if n := t.step(); n > 0 {
			for k := t.i; k < t.i+n && k < len(t.toks); k++ {
				t.used[k] = true
			}
			t.i += n
		} else {
			t.i++
		}
	}
	q := t.finish()
	text := q.String()
	if _, err := query.Parse(text); err != nil {
		return nil, fmt.Errorf("could not build a valid query from that question: %v", err)
	}
	res := &Result{Query: text, Steps: t.steps}
	content, known := 0, 0
	for i, tk := range t.toks {
		if !tk.quoted && stopwords[tk.low] && !t.used[i] {
			continue
		}
		content++
		if t.used[i] {
			known++
		} else {
			res.Unknown = append(res.Unknown, tk.text)
		}
	}
	if content > 0 {
		res.Confidence = float64(known) / float64(content)
	}
	return res, nil
}

// ---------- tokens ----------

type token struct {
	text, low string
	quoted    bool
}

func tokenize(s string) []token {
	var out []token
	var b strings.Builder
	flush := func() {
		w := strings.TrimRight(b.String(), ".:")
		w = strings.TrimSuffix(strings.TrimSuffix(w, "'s"), "’s")
		if w != "" {
			out = append(out, token{text: w, low: strings.ToLower(w)})
		}
		b.Reset()
	}
	rs := []rune(s)
	for i := 0; i < len(rs); i++ {
		r := rs[i]
		if (r == '"' || r == '“' || r == '\'' || r == '‘') && b.Len() == 0 {
			closeQ := map[rune]rune{'"': '"', '“': '”', '\'': '\'', '‘': '’'}[r]
			if j := indexRune(rs[i+1:], closeQ); j > 0 {
				v := string(rs[i+1 : i+1+j])
				out = append(out, token{text: v, low: strings.ToLower(v), quoted: true})
				i += j + 1
				continue
			}
		}
		if unicode.IsSpace(r) || strings.ContainsRune(",;?!()[]", r) {
			flush()
			continue
		}
		b.WriteRune(r)
	}
	flush()
	return out
}

func indexRune(rs []rune, r rune) int {
	for i, c := range rs {
		if c == r {
			return i
		}
	}
	return -1
}

// ---------- vocabulary ----------

var stopwords = set("a", "an", "the", "of", "in", "on", "at", "for", "to", "from", "by", "and", "or", "with", "that",
	"which", "what", "who", "were", "was", "is", "are", "be", "been", "being", "have", "has", "had", "did", "do", "does",
	"show", "list", "find", "get", "give", "display", "search", "me", "all", "any", "there", "my", "our", "us", "we", "i",
	"you", "can", "could", "please", "see", "tell", "about", "events", "event", "logs", "log", "activity", "attempts",
	"attempt", "times", "time", "ones", "everything", "happened", "occurred", "seen", "made", "where", "when", "how",
	"many", "much", "it", "its", "this", "these", "those", "some", "into", "within", "during", "via", "as", "them",
	"their", "per", "each", "every", "than", "then", "so", "if", "just", "only", "also", "recent", "recently", "ever",
	"anything", "something", "like", "using", "used", "use", "against", "between", "up", "out", "over", "under",
	"while", "had", "got", "occur", "happen", "records", "record", "entries", "entry", "data", "results", "result",
	"look", "looking", "check", "lets", "let's", "want", "need", "would", "should", "i'd")

func set(words ...string) map[string]bool {
	m := make(map[string]bool, len(words))
	for _, w := range words {
		m[w] = true
	}
	return m
}

// noun maps a word for a field to the field and its plain name.
type noun struct {
	field, name string
	numeric     bool
	measure     bool   // a quantity to add up rather than group by
	model       string // data model this field implies, if any
}

// hostField is resolved at the end: dest for most data models, host when
// searching all data.
const hostField = "$host"

var nouns = map[string]noun{}

func addNoun(n noun, words ...string) {
	for _, w := range words {
		nouns[w] = n
	}
}

func init() {
	addNoun(noun{field: "user", name: "user"}, "user", "users", "account", "accounts", "username", "usernames", "identity", "identities", "people", "person")
	addNoun(noun{field: "src", name: "source"}, "source", "sources", "src", "ip", "ips", "address", "addresses", "attacker", "attackers", "client", "clients", "origin", "origins")
	addNoun(noun{field: "dest", name: "destination"}, "destination", "destinations", "dest", "target", "targets")
	addNoun(noun{field: hostField, name: "host"}, "host", "hosts", "hostname", "hostnames", "computer", "computers", "machine", "machines", "server", "servers", "system", "systems", "endpoint", "endpoints", "device", "devices", "workstation", "workstations", "box", "boxes")
	addNoun(noun{field: "dest_port", name: "port", numeric: true, model: "Network_Traffic"}, "port", "ports")
	addNoun(noun{field: "process_name", name: "process", model: "Endpoint"}, "process", "processes", "program", "programs", "executable", "executables", "binary", "binaries", "exe")
	addNoun(noun{field: "process", name: "command line", model: "Endpoint"}, "command", "commands", "commandline", "commandlines", "cmdline")
	addNoun(noun{field: "parent_process_name", name: "parent process", model: "Endpoint"}, "parent", "parents")
	addNoun(noun{field: "app", name: "app"}, "app", "apps", "application", "applications", "service", "services")
	addNoun(noun{field: "transport", name: "protocol", model: "Network_Traffic"}, "protocol", "protocols", "transport")
	addNoun(noun{field: "action", name: "outcome"}, "action", "actions", "outcome", "outcomes", "status")
	addNoun(noun{field: "reason", name: "reason", model: "Authentication"}, "reason", "reasons")
	addNoun(noun{field: "bytes", name: "bytes", numeric: true, measure: true, model: "Network_Traffic"}, "bytes", "volume", "bandwidth")
	addNoun(noun{field: "signature_id", name: "event code"}, "eventcode", "eventid", "code", "codes")
	addNoun(noun{field: "signature", name: "event name"}, "signature", "signatures")
	addNoun(noun{field: "sourcetype", name: "source type"}, "sourcetype", "sourcetypes")
	addNoun(noun{field: "logon_type", name: "logon type", numeric: true, model: "Authentication"}, "logon_type")
	addNoun(noun{field: "authentication_method", name: "method", model: "Authentication"}, "method", "methods")
	addNoun(noun{field: "user_domain", name: "domain", model: "Authentication"}, "domain", "domains")
	addNoun(noun{field: "object", name: "changed object", model: "Change"}, "object", "objects")
	addNoun(noun{field: "detection_id", name: "detection", model: "Risk"}, "detection", "detections", "rule", "rules")
	addNoun(noun{field: "mitre_tactic", name: "ATT&CK tactic", model: "Risk"}, "tactic", "tactics")
	addNoun(noun{field: "mitre", name: "ATT&CK technique", model: "Risk"}, "technique", "techniques")
	addNoun(noun{field: "risk_score", name: "risk score", numeric: true, measure: true, model: "Risk"}, "score", "scores")
	// Field names typed as-is.
	for _, f := range []string{"src_user", "src_port", "dest_host", "process_path", "process_id", "parent_process", "parent_process_path", "process_hash", "object_category", "risk_object", "risk_object_type", "risk_message", "vendor_product"} {
		addNoun(noun{field: f, name: f})
	}
}

// twoWordNouns are checked before single words.
var twoWordNouns = map[string]noun{
	"source ip":        {field: "src", name: "source"},
	"source address":   {field: "src", name: "source"},
	"source port":      {field: "src_port", name: "source port", numeric: true, model: "Network_Traffic"},
	"destination ip":   {field: "dest", name: "destination"},
	"dest port":        {field: "dest_port", name: "port", numeric: true, model: "Network_Traffic"},
	"destination port": {field: "dest_port", name: "port", numeric: true, model: "Network_Traffic"},
	"process name":     {field: "process_name", name: "process", model: "Endpoint"},
	"command line":     {field: "process", name: "command line", model: "Endpoint"},
	"parent process":   {field: "parent_process_name", name: "parent process", model: "Endpoint"},
	"logon type":       {field: "logon_type", name: "logon type", numeric: true, model: "Authentication"},
	"event id":         {field: "signature_id", name: "event code"},
	"event code":       {field: "signature_id", name: "event code"},
	"source type":      {field: "sourcetype", name: "source type"},
	"risk score":       {field: "risk_score", name: "risk score", numeric: true, measure: true, model: "Risk"},
	"risk object":      {field: "risk_object", name: "risk object", model: "Risk"},
}

var modelWords = map[string]string{
	"login": "Authentication", "logins": "Authentication", "logon": "Authentication", "logons": "Authentication",
	"signin": "Authentication", "signins": "Authentication", "sign-in": "Authentication", "sign-ins": "Authentication",
	"log-in": "Authentication", "log-ins": "Authentication", "authentication": "Authentication",
	"authentications": "Authentication", "auth": "Authentication", "password": "Authentication",
	"passwords": "Authentication", "credential": "Authentication", "credentials": "Authentication",
	"executed": "Endpoint", "execution": "Endpoint", "executions": "Endpoint", "ran": "Endpoint", "run": "Endpoint",
	"launched": "Endpoint", "launch": "Endpoint", "launches": "Endpoint", "spawned": "Endpoint", "started": "Endpoint",
	"connection": "Network_Traffic", "connections": "Network_Traffic", "connected": "Network_Traffic",
	"traffic": "Network_Traffic", "network": "Network_Traffic", "flow": "Network_Traffic", "flows": "Network_Traffic",
	"firewall": "Network_Traffic", "outbound": "Network_Traffic", "inbound": "Network_Traffic",
	"change": "Change", "changes": "Change", "risk": "Risk", "risky": "Risk",
	"malware": "Malware", "virus": "Malware", "viruses": "Malware", "infection": "Malware", "infections": "Malware",
	"infected": "Malware", "trojan": "Malware", "trojans": "Malware", "ransomware": "Malware", "quarantined": "Malware",
	"antivirus": "Malware", "anti-virus": "Malware", "av": "Malware", "defender": "Malware", "clamav": "Malware",
	"threat": "Malware", "threats": "Malware",
}

var modelNames = map[string]string{
	"Authentication": "logon data (Authentication)", "Endpoint": "process data (Endpoint)",
	"Network_Traffic": "network data (Network_Traffic)", "Change": "account and group changes (Change)",
	"Risk": "risk events (Risk)", "Malware": "antivirus data (Malware)",
}

var actionWords = map[string]string{
	"failed": "failure", "failure": "failure", "failures": "failure", "failing": "failure", "unsuccessful": "failure",
	"bad": "failure", "wrong": "failure", "invalid": "failure", "fail": "failure", "fails": "failure",
	"successful": "success", "succeeded": "success", "success": "success", "successfully": "success", "succeed": "success",
	"blocked": "blocked", "denied": "blocked", "dropped": "blocked", "rejected": "blocked", "block": "blocked",
	"allowed": "allowed", "permitted": "allowed", "accepted": "allowed",
	"created": "created", "new": "created", "added": "created", "deleted": "deleted", "removed": "deleted",
	"disabled": "modified", "modified": "modified", "changed": "modified",
}

// processNames are programs analysts often hunt for, with their file names.
var processNames = map[string]string{
	"powershell": "powershell.exe", "pwsh": "pwsh.exe", "cmd": "cmd.exe", "rundll32": "rundll32.exe",
	"regsvr32": "regsvr32.exe", "mshta": "mshta.exe", "certutil": "certutil.exe", "wmic": "wmic.exe",
	"bitsadmin": "bitsadmin.exe", "schtasks": "schtasks.exe", "psexec": "psexec.exe", "mimikatz": "mimikatz.exe",
	"whoami": "whoami.exe", "cscript": "cscript.exe", "wscript": "wscript.exe", "msbuild": "msbuild.exe",
	"procdump": "procdump.exe", "vssadmin": "vssadmin.exe", "net": "net.exe", "nltest": "nltest.exe",
	"winword": "winword.exe", "excel": "excel.exe", "outlook": "outlook.exe", "explorer": "explorer.exe",
	"bash": "bash", "curl": "curl", "wget": "wget", "nc": "nc", "ncat": "ncat", "nmap": "nmap", "python": "python",
	"python3": "python3", "perl": "perl", "useradd": "useradd", "crontab": "crontab", "chmod": "chmod",
}

var units = map[string]string{
	"second": "s", "seconds": "s", "sec": "s", "secs": "s", "minute": "m", "minutes": "m", "min": "m", "mins": "m",
	"hour": "h", "hours": "h", "hr": "h", "hrs": "h", "day": "d", "days": "d", "week": "w", "weeks": "w",
	"month": "mon", "months": "mon", "year": "y", "years": "y",
}

var unitNames = map[string]string{"s": "second", "m": "minute", "h": "hour", "d": "day", "w": "week", "mon": "month", "y": "year"}

var numberWords = map[string]int{"one": 1, "two": 2, "three": 3, "four": 4, "five": 5, "six": 6, "seven": 7,
	"eight": 8, "nine": 9, "ten": 10, "twelve": 12, "fifteen": 15, "twenty": 20, "thirty": 30, "fifty": 50, "hundred": 100}

func number(s string) (int, bool) {
	if n, ok := numberWords[s]; ok {
		return n, true
	}
	n, err := strconv.Atoi(strings.ReplaceAll(s, ",", ""))
	return n, err == nil && n >= 0
}

// ---------- translator ----------

type filter struct {
	field, op, value string
}

type translator struct {
	toks  []token
	used  []bool
	i     int
	hints Hints
	steps []Step

	model     string
	modelHint string // from a field noun, weaker than a model word
	filters   []filter
	ors       [][]filter // each is field=value OR field=value
	texts     []string
	contains  []string
	action    string
	group     bool // object_category=group for Change
	earliest  string
	latest    string

	mode      string // "", stats, timechart, top
	agg       query.Agg
	by        []string
	pending   []string // nouns that may be a group-by
	pendStep  []int    // the step that explains each pending noun
	chartStep int      // the step that chose a chart
	groupNext bool
	span      string
	topN      int
	ascending bool
	threshold *filter
	limit     int
	fields    []string
	negNext   bool
	lastNoun  *noun
	lastNounI int

	// Antivirus questions. malware is true when the question names
	// malware or antivirus anywhere, so words such as "disabled", "blocks"
	// and "rule" take their antivirus meaning.
	malware    bool
	mwType     string   // threat, rule or health
	mwStrong   bool     // mwType came from a rule or health phrase, which a threat word does not override
	mwCategory string   // category=
	mwActions  []string // action=, or action IN (...) when more than one
	mwVendor   string   // vendor_product=
}

func (t *translator) low(k int) string {
	if t.i+k < len(t.toks) && !t.toks[t.i+k].quoted {
		return t.toks[t.i+k].low
	}
	return ""
}

func (t *translator) tok(k int) (token, bool) {
	if t.i+k < len(t.toks) {
		return t.toks[t.i+k], true
	}
	return token{}, false
}

func (t *translator) phrase(n int) string {
	var parts []string
	for k := t.i; k < t.i+n && k < len(t.toks); k++ {
		parts = append(parts, t.toks[k].text)
	}
	return strings.Join(parts, " ")
}

func (t *translator) note(n int, meaning string, args ...any) int {
	t.steps = append(t.steps, Step{Phrase: t.phrase(n), Meaning: fmt.Sprintf(meaning, args...)})
	return n
}

func (t *translator) setModel(m string) {
	if t.model == "" {
		t.model = m
	}
}

// step tries every rule at the current token and returns how many tokens
// the matching rule consumed.
func (t *translator) step() int {
	for _, rule := range []func() int{
		t.ruleQuoted, t.ruleTime, t.ruleThreshold, t.ruleMalware, t.ruleNegation, t.ruleTop, t.ruleAgg, t.ruleGroup,
		t.ruleShowFields, t.ruleContains, t.rulePreposition, t.ruleNoun, t.ruleWords, t.ruleValue,
	} {
		if n := rule(); n > 0 {
			return n
		}
	}
	return 0
}

func (t *translator) ruleQuoted() int {
	tk, _ := t.tok(0)
	if !tk.quoted {
		return 0
	}
	t.texts = append(t.texts, tk.text)
	return t.note(1, "events containing the text %q", tk.text)
}

func (t *translator) ruleTime() int {
	w := t.low(0)
	switch w {
	case "today":
		t.earliest = "@d"
		return t.note(1, "time range: since midnight")
	case "yesterday":
		t.earliest, t.latest = "-1d@d", "@d"
		return t.note(1, "time range: yesterday")
	case "this":
		switch t.low(1) {
		case "week":
			t.earliest = "@w"
			return t.note(2, "time range: this week")
		case "month":
			t.earliest = "@mon"
			return t.note(2, "time range: this month")
		case "morning":
			t.earliest = "@d"
			return t.note(2, "time range: since midnight")
		}
	case "hourly", "daily":
		u := map[string]string{"hourly": "h", "daily": "d"}[w]
		t.mode, t.span, t.chartStep = "timechart", "1"+u, len(t.steps)
		return t.note(1, "a chart with one point per %s", unitNames[u])
	}
	if w != "last" && w != "past" && w != "previous" && w != "since" {
		return 0
	}
	k := 1
	if t.low(k) == "the" {
		k++
	}
	n := 1
	if v, ok := number(t.low(k)); ok {
		n = v
		k++
	} else if t.low(k) == "a" || t.low(k) == "an" {
		k++
	}
	u, ok := units[t.low(k)]
	if !ok {
		return 0
	}
	k++
	t.earliest = fmt.Sprintf("-%d%s", n, u)
	name := unitNames[u]
	if n != 1 {
		name = fmt.Sprintf("%d %ss", n, name)
	}
	return t.note(k, "time range: last %s", name)
}

func (t *translator) ruleThreshold() int {
	ops := []struct {
		words []string
		op    string
	}{
		{[]string{"more", "than"}, ">"}, {[]string{"greater", "than"}, ">"}, {[]string{"higher", "than"}, ">"},
		{[]string{"over"}, ">"}, {[]string{"above"}, ">"}, {[]string{"exceeding"}, ">"}, {[]string{"exceeds"}, ">"},
		{[]string{">"}, ">"}, {[]string{"at", "least"}, ">="}, {[]string{"minimum", "of"}, ">="}, {[]string{">="}, ">="},
		{[]string{"fewer", "than"}, "<"}, {[]string{"less", "than"}, "<"}, {[]string{"lower", "than"}, "<"},
		{[]string{"under"}, "<"}, {[]string{"below"}, "<"}, {[]string{"<"}, "<"}, {[]string{"at", "most"}, "<="},
		{[]string{"<="}, "<="}, {[]string{"equal", "to"}, "="}, {[]string{"exactly"}, "="},
	}
	for _, o := range ops {
		k := 0
		for _, w := range o.words {
			if t.low(k) != w {
				k = -1
				break
			}
			k++
		}
		if k <= 0 {
			continue
		}
		n, ok := number(t.low(k))
		if !ok {
			continue
		}
		k++
		if t.low(k) == "times" || t.low(k) == "time" {
			k++
		}
		return t.threshold0(k, o.op, n)
	}
	// "5 or more", "10+"
	if n, ok := number(t.low(0)); ok && t.low(1) == "or" && (t.low(2) == "more" || t.low(2) == "fewer" || t.low(2) == "less") {
		op := ">="
		if t.low(2) != "more" {
			op = "<="
		}
		k := 3
		if t.low(k) == "times" {
			k++
		}
		return t.threshold0(k, op, n)
	}
	if w := t.low(0); strings.HasSuffix(w, "+") {
		if n, ok := number(strings.TrimSuffix(w, "+")); ok {
			return t.threshold0(1, ">=", n)
		}
	}
	return 0
}

func (t *translator) threshold0(k int, op string, n int) int {
	// Right after a numeric field ("port over 1024", "bytes above 1000000")
	// it filters events; otherwise it filters counts.
	if t.lastNoun != nil && t.lastNoun.numeric && t.lastNounI == t.i-1 {
		f := t.lastNoun.field
		t.filters = append(t.filters, filter{f, op, strconv.Itoa(n)})
		return t.note(k, "%s %s %d", t.lastNoun.name, op, n)
	}
	t.threshold = &filter{op: op, value: strconv.Itoa(n)}
	// "logged in to more than 3 hosts" counts distinct hosts.
	if nn, nk := t.nounAt(k); nk > 0 && !nn.numeric && t.agg.Func == "" {
		t.agg = query.Agg{Func: "dc", Field: nn.field}
		t.hintModel(nn)
		return t.note(k+nk, "keep only rows with %s %d different %ss", opWords[op], n, nn.name)
	}
	return t.note(k, "keep only rows with %s %d events", opWords[op], n)
}

func (t *translator) ruleNegation() int {
	switch t.low(0) {
	case "not", "except", "excluding", "exclude", "without", "isn't", "aren't", "wasn't", "but":
		if t.low(0) == "but" && t.low(1) != "not" {
			return 0
		}
		k := 1
		if t.low(0) == "but" {
			k = 2
		}
		t.negNext = true
		// "except root": guess the field from the value.
		if nt, ok := t.tok(k); ok && t.looksLikeValue(nt) && nouns[nt.low].field == "" && t.low(k) != "from" && t.low(k) != "to" && t.low(k) != "on" && t.low(k) != "by" {
			f := t.guessField(nt.text)
			t.addFilter(f, nt.text)
			return t.note(k+1, "exclude %s %s", fieldName(f), nt.text)
		}
		return t.note(k, "exclude what follows")
	case "other":
		if t.low(1) == "than" {
			t.negNext = true
			return t.note(2, "exclude what follows")
		}
	}
	return 0
}

func (t *translator) ruleTop() int {
	w := t.low(0)
	k := 0
	n := 0
	switch {
	case w == "top" || w == "highest":
		k = 1
		if v, ok := number(t.low(1)); ok {
			n, k = v, 2
		}
	case w == "most" || w == "biggest" || w == "largest" || w == "busiest" || w == "noisiest":
		k = 1
		if t.low(1) == "common" || t.low(1) == "frequent" || t.low(1) == "active" || t.low(1) == "often" {
			k = 2
		}
	case w == "least" || w == "fewest" || w == "rarest" || w == "rare" || w == "uncommon":
		t.ascending = true
		k = 1
		if t.low(1) == "common" || t.low(1) == "frequent" {
			k = 2
		}
	default:
		if v, ok := number(w); ok && (t.low(1) == "most" || t.low(1) == "top") {
			n, k = v, 2
			if t.low(2) == "common" || t.low(2) == "frequent" || t.low(2) == "active" {
				k = 3
			}
		}
	}
	if k == 0 {
		return 0
	}
	if t.mode != "timechart" {
		t.mode = "top"
	}
	if n > 0 {
		t.topN = n
	}
	t.groupNext = true
	if t.ascending {
		return t.note(k, "the least common values first")
	}
	if n > 0 {
		return t.note(k, "the top %d", n)
	}
	return t.note(k, "the most common values first")
}

func (t *translator) ruleAgg() int {
	w := t.low(0)
	switch {
	case w == "how" && t.low(1) == "many":
		t.countMode()
		if n := t.distinctAfter(2); n > 0 {
			return n
		}
		return t.note(2, "count the events")
	case (w == "number" || w == "count" || w == "total") && t.low(1) == "of":
		t.countMode()
		if n := t.distinctAfter(2); n > 0 {
			return n
		}
		return t.note(2, "count the events")
	case w == "count" || w == "counts" || w == "tally":
		t.countMode()
		return t.note(1, "count the events")
	case w == "distinct" || w == "unique" || w == "different":
		return t.distinctAfter(0)
	}
	fn := map[string]string{"total": "sum", "sum": "sum", "average": "avg", "avg": "avg", "mean": "avg",
		"maximum": "max", "max": "max", "minimum": "min", "min": "min", "smallest": "min"}[w]
	if fn == "" {
		return 0
	}
	k := 1
	if t.low(k) == "of" {
		k++
	}
	nn, nk := t.nounAt(k)
	if nk == 0 || !nn.numeric {
		return 0
	}
	t.agg = query.Agg{Func: fn, Field: nn.field, Alias: map[string]string{"sum": "total", "avg": "avg", "max": "max", "min": "min"}[fn] + "_" + nn.field}
	if t.mode == "" {
		t.mode = "stats"
	}
	t.hintModel(nn)
	return t.note(k+nk, "%s of %s", map[string]string{"sum": "total", "avg": "average", "max": "maximum", "min": "minimum"}[fn], nn.name)
}

func (t *translator) countMode() {
	if t.mode == "" {
		t.mode = "stats"
	}
}

// distinctAfter handles "distinct users" starting at offset k.
func (t *translator) distinctAfter(k int) int {
	if w := t.low(k); w != "distinct" && w != "unique" && w != "different" {
		return 0
	}
	nn, nk := t.nounAt(k + 1)
	if nk == 0 {
		return 0
	}
	f := nn.field
	t.agg = query.Agg{Func: "dc", Field: f, Alias: "distinct_" + strings.TrimPrefix(f, "$")}
	if t.mode == "" || t.mode == "top" {
		t.mode = "stats"
	}
	t.hintModel(nn)
	return t.note(k+1+nk, "count distinct %ss", nn.name)
}

func (t *translator) ruleGroup() int {
	w := t.low(0)
	k := 0
	switch {
	case w == "by" || w == "per" || w == "across":
		k = 1
	case (w == "for" && (t.low(1) == "each" || t.low(1) == "every")) || ((w == "grouped" || w == "split" || w == "broken") && t.low(1) == "by"):
		k = 2
	case w == "broken" && t.low(1) == "down" && t.low(2) == "by":
		k = 3
	case w == "over" && t.low(1) == "time":
		t.mode, t.chartStep = "timechart", len(t.steps)
		return t.note(2, "a chart over time")
	case w == "trend" || w == "trends" || w == "timeline" || w == "chart" || w == "histogram" || w == "graph" || w == "plot":
		t.mode, t.chartStep = "timechart", len(t.steps)
		return t.note(1, "a chart over time")
	default:
		return 0
	}
	if t.low(k) == "each" || t.low(k) == "every" {
		k++
	}
	if u, ok := units[t.low(k)]; ok {
		t.mode, t.span, t.chartStep = "timechart", "1"+u, len(t.steps)
		return t.note(k+1, "a chart with one point per %s", unitNames[u])
	}
	var got []noun
	for {
		nn, nk := t.nounAt(k)
		if nk == 0 {
			break
		}
		got = append(got, nn)
		k += nk
		if t.low(k) == "and" {
			if _, nk2 := t.nounAt(k + 1); nk2 > 0 {
				k++
				continue
			}
		}
		if _, nk2 := t.nounAt(k); nk2 == 0 {
			break
		}
	}
	if len(got) == 0 {
		return 0
	}
	var names []string
	for _, nn := range got {
		t.by = append(t.by, nn.field)
		t.hintModel(nn)
		names = append(names, nn.name)
	}
	if t.mode == "" {
		t.mode = "stats"
	}
	return t.note(k, "one row per %s", strings.Join(names, " and "))
}

// ruleShowFields handles "show user, src and dest for ...": two or more
// fields after a show verb become the result columns.
func (t *translator) ruleShowFields() int {
	switch t.low(0) {
	case "show", "list", "display", "table", "columns":
	default:
		return 0
	}
	k := 1
	if t.low(k) == "me" {
		k++
	}
	if t.low(k) == "the" || t.low(k) == "only" {
		k++
	}
	var fs []noun
	for {
		nn, nk := t.nounAt(k)
		if nk == 0 {
			break
		}
		fs = append(fs, nn)
		k += nk
		if t.low(k) == "and" {
			k++
		}
	}
	if len(fs) < 2 {
		return 0
	}
	if t.low(k-1) == "and" {
		k--
	}
	var names []string
	for _, nn := range fs {
		t.fields = append(t.fields, nn.field)
		names = append(names, nn.name)
	}
	return t.note(k, "show the columns %s", strings.Join(names, ", "))
}

func (t *translator) ruleContains() int {
	switch t.low(0) {
	case "containing", "contains", "contain", "mentioning", "mentions", "matching", "includes", "including", "include", "referencing":
	default:
		return 0
	}
	nt, ok := t.tok(1)
	if !ok {
		return 0
	}
	t.contains = append(t.contains, nt.text)
	return t.note(2, "containing %q", nt.text)
}

func (t *translator) rulePreposition() int {
	w := t.low(0)
	if (w == "to" && t.low(1) == "or" && t.low(2) == "from") || (w == "from" && t.low(1) == "or" && t.low(2) == "to") {
		if nt, ok := t.tok(3); ok && t.looksLikeValue(nt) {
			t.ors = append(t.ors, []filter{{"src", t.eqOp(), nt.text}, {"dest", t.eqOp(), nt.text}})
			neg := t.consumeNeg()
			return t.note(4, "source or destination %s %s", negWord(neg), nt.text)
		}
	}
	kind := ""
	switch w {
	case "from":
		kind = "src"
	case "to", "on", "at", "into", "targeting", "toward", "towards":
		kind = "dest"
	case "by", "for", "as":
		kind = "user"
		if t.i > 0 {
			switch t.toks[t.i-1].low {
			case "spawned", "launched", "started", "opened":
				kind = "parent"
			}
		}
	default:
		return 0
	}
	k := 1
	if t.low(k) == "the" {
		k++
	}
	nt, ok := t.tok(k)
	if !ok || !t.looksLikeValue(nt) || nouns[nt.low].field != "" || modelWords[nt.low] != "" {
		return 0
	}
	v := nt.text
	f := kind
	switch {
	case kind == "src" && t.isKnownUser(v) && !isIP(v):
		f = "user"
	case kind == "user" && (t.isKnownHost(v) || isIP(v)):
		f = hostField
		if isIP(v) {
			f = "src"
		}
	case kind == "dest" && !isIP(v):
		f = hostField
	case kind == "parent":
		f = "parent_process_name"
		if p, ok := processNames[nt.low]; ok {
			v = p
		}
		t.setModel("Endpoint")
	}
	t.addFilter(f, v)
	return t.note(k+1, "%s %s %s", fieldName(f), negWord(t.lastNeg()), v)
}

func (t *translator) ruleNoun() int {
	nn, k := t.nounAt(0)
	if k == 0 {
		return 0
	}
	t.hintModel(nn)
	t.lastNoun, t.lastNounI = &nn, t.i+k-1
	// "user alice", "port 22", "process mimikatz.exe", "user is root"
	j := k
	if w := t.low(j); w == "is" || w == "=" || w == "equals" || w == "was" || w == "named" || w == "called" {
		j++
	}
	if nt, ok := t.tok(j); ok && t.looksLikeValue(nt) && nouns[nt.low].field == "" && modelWords[nt.low] == "" && actionWords[nt.low] == "" {
		if !nn.numeric || isNumber(nt.text) {
			v := nt.text
			if p, ok := processNames[nt.low]; ok && (nn.field == "process_name" || nn.field == "parent_process_name") {
				v = p
			}
			t.addFilter(nn.field, v)
			return t.note(j+1, "%s %s %s", nn.name, negWord(t.lastNeg()), v)
		}
	}
	if nn.measure && (t.mode == "top" || t.mode == "stats" || t.mode == "") && t.agg.Func == "" {
		t.agg = query.Agg{Func: "sum", Field: nn.field, Alias: "total_" + nn.field}
		if nn.field == "risk_score" {
			t.agg.Alias = "risk_score"
		}
		return t.note(k, "add up %s", nn.name)
	}
	if t.i > 0 && (t.toks[t.i-1].low == "which" || t.toks[t.i-1].low == "what") {
		t.groupNext = true
	}
	if t.groupNext {
		t.groupNext = false
		t.by = append(t.by, nn.field)
		if t.mode == "" {
			t.mode = "stats"
		}
		return t.note(k, "one row per %s", nn.name)
	}
	t.pending = append(t.pending, nn.field)
	t.pendStep = append(t.pendStep, len(t.steps))
	if nn.model != "" {
		return t.note(k, "%s", modelNames[nn.model])
	}
	return t.note(k, "about %ss", nn.name)
}

func (t *translator) ruleWords() int {
	w := t.low(0)
	two := w + " " + t.low(1)
	switch two {
	case "log in", "logged in", "logging in", "sign in", "signed in", "logged on", "log on", "logging on":
		t.setModel("Authentication")
		return t.note(2, "%s", modelNames["Authentication"])
	case "remote desktop":
		t.setModel("Authentication")
		t.filters = append(t.filters, filter{"logon_type", "=", "10"})
		return t.note(2, "remote desktop logons (logon type 10)")
	case "added to":
		t.setModel("Change")
		t.action = "modified"
		return t.note(2, "group membership changes")
	case "admin group", "admins group", "administrators group", "domain admins":
		t.setModel("Change")
		t.group = true
		return t.note(2, "group changes")
	}
	switch w {
	case "ssh", "sshd":
		t.setModel("Authentication")
		t.filters = append(t.filters, filter{"app", "=", "sshd"})
		return t.note(1, "SSH logons")
	case "sudo", "su":
		t.setModel("Authentication")
		t.filters = append(t.filters, filter{"app", "=", w})
		return t.note(1, "%s use", w)
	case "rdp":
		t.setModel("Authentication")
		t.filters = append(t.filters, filter{"logon_type", "=", "10"})
		return t.note(1, "remote desktop logons (logon type 10)")
	case "group", "groups", "membership", "memberships":
		t.group = true
		t.setModel("Change")
		return t.note(1, "group changes")
	case "tcp", "udp", "icmp":
		t.setModel("Network_Traffic")
		t.filters = append(t.filters, filter{"transport", "=", w})
		return t.note(1, "%s traffic", strings.ToUpper(w))
	case "root", "administrator", "admin", "system":
		if w == "system" || w == "admin" {
			return 0
		}
		t.addFilter("user", w)
		return t.note(1, "user %s %s", negWord(t.lastNeg()), w)
	}
	if m, ok := modelWords[w]; ok {
		t.setModel(m)
		return t.note(1, "%s", modelNames[m])
	}
	if a, ok := actionWords[w]; ok {
		if t.action == "" || t.action == "created" && a != "created" {
			t.action = a
		}
		return t.note(1, "only %s", map[string]string{"failure": "failures", "success": "successes", "blocked": "blocked traffic",
			"allowed": "allowed traffic", "created": "things created", "deleted": "things deleted", "modified": "changes"}[a])
	}
	if p, ok := processNames[w]; ok {
		t.setModel("Endpoint")
		t.addFilter("process_name", p)
		return t.note(1, "process %s %s", negWord(t.lastNeg()), p)
	}
	return 0
}

// ruleValue handles a bare IP address, file name or known user or host.
func (t *translator) ruleValue() int {
	tk, _ := t.tok(0)
	v := tk.text
	switch {
	case isIP(v) || isCIDR(v):
		t.ors = append(t.ors, []filter{{"src", t.eqOp(), v}, {"dest", t.eqOp(), v}})
		neg := t.consumeNeg()
		return t.note(1, "source or destination %s %s", negWord(neg), v)
	case hasExt(tk.low):
		t.setModel("Endpoint")
		t.addFilter("process_name", v)
		return t.note(1, "process %s %s", negWord(t.lastNeg()), v)
	case t.isKnownUser(v):
		t.addFilter("user", v)
		return t.note(1, "user %s %s", negWord(t.lastNeg()), v)
	case t.isKnownHost(v):
		t.addFilter(hostField, v)
		return t.note(1, "host %s %s", negWord(t.lastNeg()), v)
	}
	return 0
}

// ---------- helpers ----------

var opWords = map[string]string{">": "more than", ">=": "at least", "<": "fewer than", "<=": "at most", "=": "exactly"}

// nounAt returns the field noun at offset k, trying two-word nouns first.
func (t *translator) nounAt(k int) (noun, int) {
	if n, ok := twoWordNouns[t.low(k)+" "+t.low(k+1)]; ok && t.low(k+1) != "" {
		return n, 2
	}
	if t.malware {
		if n, ok := malwareNouns[t.low(k)]; ok {
			return n, 1
		}
	}
	if n, ok := nouns[t.low(k)]; ok {
		return n, 1
	}
	return noun{}, 0
}

// malwareNouns are field nouns that only apply to antivirus questions.
var malwareNouns = map[string]noun{
	"threat": {field: "signature", name: "threat", model: "Malware"}, "threats": {field: "signature", name: "threat", model: "Malware"},
	"file": {field: "file_name", name: "file", model: "Malware"}, "files": {field: "file_name", name: "file", model: "Malware"},
	"rule": {field: "rule", name: "protection rule", model: "Malware"}, "rules": {field: "rule", name: "protection rule", model: "Malware"},
	"category": {field: "category", name: "category", model: "Malware"}, "categories": {field: "category", name: "category", model: "Malware"},
}

func (t *translator) hintModel(nn noun) {
	if nn.model != "" && t.modelHint == "" {
		t.modelHint = nn.model
	}
}

func (t *translator) looksLikeValue(tk token) bool {
	if tk.quoted {
		return true
	}
	w := tk.low
	if w == "" || stopwords[w] || units[w] != "" || numberWords[w] > 0 {
		return isIP(w) || isNumber(w)
	}
	if _, ok := actionWords[w]; ok {
		return false
	}
	switch w {
	case "most", "top", "least", "over", "more", "less", "than", "last", "past", "today", "yesterday", "not",
		"logged", "signed", "logging", "signing", "sent", "received", "spawned", "launched", "opened", "highest",
		"except", "containing", "contains", "per", "distinct", "unique", "total", "average", "count", "trend":
		return false
	}
	return true
}

func (t *translator) isKnownUser(v string) bool { return t.hints != nil && t.hints.KnownUser(v) }
func (t *translator) isKnownHost(v string) bool { return t.hints != nil && t.hints.KnownHost(v) }

func (t *translator) guessField(v string) string {
	switch {
	case isIP(v):
		return "src"
	case t.isKnownHost(v):
		return hostField
	case hasExt(strings.ToLower(v)):
		return "process_name"
	}
	return "user"
}

func (t *translator) eqOp() string {
	if t.negNext {
		return "!="
	}
	return "="
}

func (t *translator) consumeNeg() bool {
	n := t.negNext
	t.negNext = false
	return n
}

// lastNeg reports whether the filter just added was negated.
func (t *translator) lastNeg() bool {
	return len(t.filters) > 0 && t.filters[len(t.filters)-1].op == "!="
}

func (t *translator) addFilter(field, value string) {
	op := t.eqOp()
	t.negNext = false
	t.filters = append(t.filters, filter{field, op, value})
}

func negWord(neg bool) string {
	if neg {
		return "is not"
	}
	return "is"
}

func fieldName(f string) string {
	switch f {
	case "src":
		return "source"
	case "dest":
		return "destination"
	case hostField:
		return "host"
	case "process_name":
		return "process"
	}
	return f
}

func isIP(s string) bool {
	_, err := netip.ParseAddr(s)
	return err == nil
}

func isCIDR(s string) bool {
	_, err := netip.ParsePrefix(s)
	return err == nil
}

func isNumber(s string) bool {
	_, err := strconv.Atoi(s)
	return err == nil
}

func hasExt(w string) bool {
	for _, e := range []string{".exe", ".dll", ".ps1", ".bat", ".cmd", ".vbs", ".js", ".hta", ".sh", ".py", ".msi", ".scr"} {
		if strings.HasSuffix(w, e) && len(w) > len(e) {
			return true
		}
	}
	return false
}

// ---------- assembly ----------

// defaultEntity is what a "top" or threshold question counts by when it
// names no field.
var defaultEntity = map[string]string{
	"Authentication": "user", "Endpoint": "process_name", "Network_Traffic": "dest",
	"Change": "object", "Risk": "risk_object", "Malware": "signature", "": "host",
}

func (t *translator) finish() *query.Query {
	model := t.model
	if model == "" {
		model = t.modelHint
	}
	if model == "" {
		switch t.action {
		case "failure", "success":
			model = "Authentication"
		case "blocked", "allowed":
			model = "Network_Traffic"
		case "created", "deleted":
			if t.group {
				model = "Change"
			}
		}
		if t.group || (t.action == "created" || t.action == "deleted") && slices.Contains(t.pending, "user") {
			model = "Change"
		}
	}
	// "risky users": rank risk objects.
	if model == "Risk" && t.mode == "" && len(t.by) == 0 && len(t.pending) > 0 {
		t.by, t.mode = t.pending[:1], "stats"
		t.steps[t.pendStep[0]].Meaning = "rank " + fieldName(t.pending[0]) + "s by total risk"
	}
	if model != t.model && model != "" {
		t.steps = append(t.steps, Step{Phrase: "", Meaning: "searching " + modelNames[model]})
	}
	q := &query.Query{Datamodel: model, Earliest: t.earliest, Latest: t.latest}
	var terms []query.Expr

	host := "dest"
	if model == "" {
		host = "host"
	}
	resolve := func(f string) string {
		if model == "Risk" && (f == "user" || f == "dest" || f == "src" || f == "host" || f == hostField) {
			return "risk_object"
		}
		if f == hostField {
			return host
		}
		return f
	}

	if model == "Malware" {
		terms = append(terms, t.malwareTerms()...)
	}
	if a := t.action; a != "" {
		switch model {
		case "Authentication":
			a = map[string]string{"failure": "failure", "success": "success", "blocked": "failure", "allowed": "success"}[a]
		case "Network_Traffic":
			a = map[string]string{"failure": "blocked", "success": "allowed", "blocked": "blocked", "allowed": "allowed"}[a]
		case "Change":
			if a == "success" || a == "failure" || a == "blocked" || a == "allowed" {
				a = ""
			}
		case "Endpoint", "Risk":
			a = ""
		case "Malware":
			a = map[string]string{"failure": "failed", "blocked": "blocked", "allowed": "allowed", "deleted": "deleted"}[a]
			if len(t.mwActions) > 0 {
				a = ""
			}
		}
		if a != "" {
			terms = append(terms, &query.Compare{Field: "action", Op: "=", Value: a})
		}
	}
	if model == "Change" {
		cat := "user"
		if t.group {
			cat = "group"
		}
		terms = append(terms, &query.Compare{Field: "object_category", Op: "=", Value: cat})
	}
	if model == "Risk" {
		for _, f := range t.by {
			switch f {
			case "user":
				terms = append(terms, &query.Compare{Field: "risk_object_type", Op: "=", Value: "user"})
			case hostField, "dest", "src", "host":
				terms = append(terms, &query.Compare{Field: "risk_object_type", Op: "=", Value: "system"})
			}
		}
	}
	for _, f := range t.filters {
		terms = append(terms, &query.Compare{Field: resolve(f.field), Op: f.op, Value: f.value})
	}
	for _, o := range t.ors {
		if model == "Risk" {
			terms = append(terms, &query.Compare{Field: "risk_object", Op: o[0].op, Value: o[0].value})
			continue
		}
		if model == "Authentication" && o[0].op == "=" {
			// Logons name the system by host name; an IP is the source.
			terms = append(terms, &query.Compare{Field: "src", Op: "=", Value: o[0].value})
			continue
		}
		if o[0].op == "!=" {
			terms = append(terms, &query.Compare{Field: "src", Op: "!=", Value: o[0].value}, &query.Compare{Field: "dest", Op: "!=", Value: o[0].value})
			continue
		}
		terms = append(terms, &query.Or{Children: []query.Expr{
			&query.Compare{Field: "src", Op: "=", Value: o[0].value}, &query.Compare{Field: "dest", Op: "=", Value: o[0].value}}})
	}
	for _, c := range t.contains {
		if model == "Endpoint" {
			terms = append(terms, &query.Compare{Field: "process", Op: "=", Value: "*" + c + "*"})
		} else {
			terms = append(terms, &query.Text{Value: c})
		}
	}
	for _, x := range t.texts {
		terms = append(terms, &query.Text{Value: x})
	}
	switch len(terms) {
	case 0:
	case 1:
		q.Search = terms[0]
	default:
		q.Search = &query.And{Children: terms}
	}

	by := dedupe(mapStrings(t.by, resolve))
	agg := t.agg
	if agg.Func == "" {
		agg = query.Agg{Func: "count"}
		if model == "Risk" {
			agg = query.Agg{Func: "sum", Field: "risk_score", Alias: "risk_score"}
		}
	} else {
		agg.Field = resolve(agg.Field)
		if agg.Func == "dc" {
			agg.Alias = "distinct_" + agg.Field
		}
	}
	col := agg.Alias
	if col == "" {
		col = "count"
	}
	mode := t.mode
	if t.threshold != nil && mode == "" {
		mode = "stats"
	}
	// "quarantined files on web1", "hosts where antivirus was turned off":
	// for antivirus data a field noun with nothing else to do lists its
	// values, most common first.
	if model == "Malware" && mode == "" && len(by) == 0 && len(t.fields) == 0 && len(t.pending) > 0 {
		mode, by = "stats", []string{resolve(t.pending[0])}
		t.steps[t.pendStep[0]].Meaning = "one row per " + fieldName(t.pending[0])
	}
	if t.threshold != nil && mode == "timechart" {
		// A chart cannot filter rows by count; count over the whole range.
		mode = "stats"
		t.steps[t.chartStep].Meaning = "not applied: counts cover the whole time range, not each interval"
	}
	needEntity := mode == "top" || t.threshold != nil
	if len(by) == 0 && needEntity {
		if len(t.pending) > 0 {
			by = []string{resolve(t.pending[0])}
			t.steps[t.pendStep[0]].Meaning = "one row per " + fieldName(t.pending[0])
		} else {
			by = []string{defaultEntity[model]}
			t.steps = append(t.steps, Step{Meaning: "one row per " + fieldName(by[0])})
		}
	}

	switch mode {
	case "timechart":
		tc := &query.Timechart{Span: t.span, Aggs: []query.Agg{agg}}
		if len(by) > 0 {
			tc.By = by[0]
		}
		q.Commands = append(q.Commands, tc)
	case "top":
		n := t.topN
		if n == 0 {
			n = 10
		}
		if agg.Func == "count" && !t.ascending && t.threshold == nil {
			q.Commands = append(q.Commands, &query.Top{Fields: by, Limit: n})
			break
		}
		q.Commands = append(q.Commands, &query.Stats{Aggs: []query.Agg{agg}, By: by})
		if t.threshold != nil {
			q.Commands = append(q.Commands, &query.Where{Expr: &query.Compare{Field: col, Op: t.threshold.op, Value: t.threshold.value}})
		}
		q.Commands = append(q.Commands, &query.Sort{Keys: []query.SortKey{{Field: col, Desc: !t.ascending}}}, &query.Head{N: n})
	case "stats":
		q.Commands = append(q.Commands, &query.Stats{Aggs: []query.Agg{agg}, By: by})
		if t.threshold != nil {
			q.Commands = append(q.Commands, &query.Where{Expr: &query.Compare{Field: col, Op: t.threshold.op, Value: t.threshold.value}})
		}
		if len(by) > 0 {
			q.Commands = append(q.Commands, &query.Sort{Keys: []query.SortKey{{Field: col, Desc: !t.ascending}}})
		}
	default:
		if len(t.fields) > 0 {
			q.Commands = append(q.Commands, &query.Table{Fields: append([]string{"_time"}, dedupe(mapStrings(t.fields, resolve))...)})
		}
	}
	return q
}

func mapStrings(in []string, f func(string) string) []string {
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = f(s)
	}
	return out
}

func dedupe(in []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// ---------- antivirus ----------

// mentionsMalware reports whether a question is about antivirus data.
func mentionsMalware(toks []token) bool {
	for i, tk := range toks {
		if tk.quoted {
			continue
		}
		switch tk.low {
		case "asr", "tamper", "tampering", "tampered", "exclusion", "exclusions":
			return true
		}
		if modelWords[tk.low] == "Malware" {
			return true
		}
		if tk.low == "attack" && i+1 < len(toks) && toks[i+1].low == "surface" {
			return true
		}
	}
	return false
}

// anyWord reports whether the question has one of words anywhere.
func (t *translator) anyWord(words ...string) bool {
	for _, tk := range t.toks {
		if !tk.quoted && slices.Contains(words, tk.low) {
			return true
		}
	}
	return false
}

func (t *translator) setMalwareType(typ string, strong bool) {
	if strong || !t.mwStrong {
		t.mwType = typ
	}
	t.mwStrong = t.mwStrong || strong
}

// ruleMalware handles the antivirus words, only in antivirus questions.
func (t *translator) ruleMalware() int {
	if !t.malware {
		return 0
	}
	w := t.low(0)
	switch w + " " + t.low(1) {
	case "not removed", "not deleted", "not cleaned", "not quarantined":
		t.setModel("Malware")
		t.setMalwareType("threat", false)
		t.mwActions = []string{"allowed", "failed", "restored"}
		return t.note(2, "malware the antivirus did not remove (allowed, failed or restored)")
	case "turned off", "switched off":
		t.setModel("Malware")
		t.setMalwareType("health", true)
		t.mwActions = []string{"disabled"}
		return t.note(2, "antivirus protection turned off")
	case "turned on", "switched on":
		t.setModel("Malware")
		t.setMalwareType("health", true)
		t.mwActions = []string{"enabled"}
		return t.note(2, "antivirus protection turned on")
	case "attack surface":
		t.setModel("Malware")
		t.setMalwareType("rule", true)
		k := 2
		if t.low(2) == "reduction" {
			k = 3
		}
		return t.note(k, "protection rule events (attack surface reduction)")
	}
	switch w {
	case "malware", "virus", "viruses", "infection", "infections", "infected", "trojan", "trojans":
		t.setModel("Malware")
		t.setMalwareType("threat", false)
		return t.note(1, "malware found (antivirus data, type threat)")
	case "threat", "threats":
		t.setModel("Malware")
		t.setMalwareType("threat", false)
		return t.ruleNoun()
	case "ransomware":
		t.setModel("Malware")
		t.setMalwareType("threat", false)
		t.mwCategory = "ransomware"
		return t.note(1, "ransomware found by antivirus")
	case "quarantined":
		t.setModel("Malware")
		t.setMalwareType("threat", false)
		t.mwActions = []string{"quarantined"}
		return t.note(1, "malware the antivirus quarantined")
	case "antivirus", "anti-virus", "av":
		t.setModel("Malware")
		return t.note(1, "%s", modelNames["Malware"])
	case "defender":
		t.setModel("Malware")
		t.mwVendor = "Microsoft Defender Antivirus"
		return t.note(1, "events from Microsoft Defender Antivirus")
	case "clamav":
		t.setModel("Malware")
		t.mwVendor = "ClamAV"
		return t.note(1, "events from ClamAV")
	case "asr":
		t.setModel("Malware")
		t.setMalwareType("rule", true)
		return t.note(1, "protection rule events (attack surface reduction)")
	case "disabled":
		t.setModel("Malware")
		t.setMalwareType("health", true)
		t.mwActions = []string{"disabled"}
		return t.note(1, "antivirus protection turned off")
	case "exclusion", "exclusions":
		t.setModel("Malware")
		t.setMalwareType("health", true)
		if t.anyWord("removed", "deleted") {
			t.mwActions = []string{"exclusion_removed"}
			return t.note(1, "antivirus exclusions removed")
		}
		t.mwActions = []string{"exclusion_added"}
		return t.note(1, "antivirus exclusions added")
	case "definition", "definitions", "update", "updates":
		if !t.anyWord("fail", "failed", "failing", "fails", "failure", "failures") {
			return 0
		}
		t.setModel("Malware")
		t.setMalwareType("health", true)
		t.mwActions = []string{"update_failed"}
		return t.note(1, "antivirus definition updates that failed")
	case "tamper", "tampering", "tampered":
		t.setModel("Malware")
		t.setMalwareType("health", true)
		t.mwActions = []string{"tamper_blocked"}
		return t.note(1, "tamper protection blocking a change")
	case "block", "blocks", "blocked":
		t.mwActions = []string{"blocked"}
		return t.note(1, "only what the antivirus blocked")
	case "detection", "detections":
		return t.note(1, "antivirus detections")
	case "protection":
		t.setModel("Malware")
		return t.note(1, "%s", modelNames["Malware"])
	}
	return 0
}

// malwareTerms returns the antivirus filters, in a fixed order: type,
// category, action, product. Several actions use IN, the same form as the
// built-in detections and the Malware dashboard.
func (t *translator) malwareTerms() []query.Expr {
	var out []query.Expr
	if t.mwType != "" {
		out = append(out, &query.Compare{Field: "type", Op: "=", Value: t.mwType})
	}
	if t.mwCategory != "" {
		out = append(out, &query.Compare{Field: "category", Op: "=", Value: t.mwCategory})
	}
	switch len(t.mwActions) {
	case 0:
	case 1:
		out = append(out, &query.Compare{Field: "action", Op: "=", Value: t.mwActions[0]})
	default:
		out = append(out, &query.In{Field: "action", Values: t.mwActions})
	}
	if t.mwVendor != "" {
		out = append(out, &query.Compare{Field: "vendor_product", Op: "=", Value: t.mwVendor})
	}
	return out
}
