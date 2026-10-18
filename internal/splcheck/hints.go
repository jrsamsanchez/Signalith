package splcheck

import (
	"cmp"
	"maps"
	"math/rand"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/jrsamsanchez/signalith/internal/query"
	"github.com/jrsamsanchez/signalith/internal/search"
	"github.com/jrsamsanchez/signalith/internal/sigmacheck"
)

// A rule's later stages may test fields its where clause leaves open: a
// where on the command line after a tstats search (where process IN
// ("*share* /delete*")), a match() or like() in an eval or where, a rex
// a later stage needs a value from, or a regex stage. Hints are those
// tests as comparisons of the fields Signalith stores, for test events
// only: each is ANDed with the where clause to make candidate events,
// and whether the rule finds one is still what the where clause and the
// later stages, run as written, say of the event as stored.

var (
	hintInRe = regexp.MustCompile(`(?i)\b(?:where|search)\s+'?([A-Za-z_][\w.{}]*)'?\s+IN\s*\(([^)]*)\)`)
	// hintTermInRe is any field IN (...) term of a search.
	hintTermInRe = regexp.MustCompile(`(?i)(?:^search|\s)\s*'?([A-Za-z_][\w.{}]*)'?\s+IN\s*\(([^)]*)\)`)
	hintEqRe     = regexp.MustCompile(`(?i)\b(?:where|search)\s+'?([A-Za-z_][\w.{}]*)'?\s*=\s*("(?:[^"\\]|\\.)*")`)
	hintLikeRe   = regexp.MustCompile(`(?i)\blike\(\s*(?:lower\(\s*)?'?([A-Za-z_][\w.{}]*)'?\s*\)?\s*,\s*("(?:[^"\\]|\\.)*")\s*\)`)
	hintMatchRe  = regexp.MustCompile(`(?i)\bmatch\(\s*'?([A-Za-z_][\w.{}]*)'?\s*,\s*("(?:[^"\\]|\\.)*")\s*\)`)
	hintRexRe    = regexp.MustCompile(`(?i)\brex\s+field=\s*"?([A-Za-z_][\w.{}]*)"?\s+("(?:[^"\\]|\\.)*")`)
	hintRegexRe  = regexp.MustCompile(`(?i)\bregex\s+'?([A-Za-z_][\w.{}]*)'?\s*=\s*("(?:[^"\\]|\\.)*")`)
	hintNotRe    = regexp.MustCompile(`(?i)\bNOT\s*\(?\s*$`)
	// replaceRe is an eval assignment of a field with some text taken
	// out (and its case changed); firstArgRe of a coalesce() whose first
	// argument is a field, or of an mvmap() or mvfilter(match()) of a
	// field's values; copyRe one that copies a field, or its lower or
	// upper case.
	replaceRe  = regexp.MustCompile(`(?i)^\s*'?([A-Za-z_][\w.{}]*)'?\s*=\s*(?:(?:lower|upper)\(\s*)?replace\(\s*'?([A-Za-z_][\w.{}]*)'?\s*,`)
	firstArgRe = regexp.MustCompile(`(?i)^\s*'?([A-Za-z_][\w.{}]*)'?\s*=\s*(?:coalesce|mvmap|mvfilter\(\s*match)\(\s*'?([A-Za-z_][\w.{}]*)'?\s*,`)
	copyRe     = regexp.MustCompile(`(?i)(?:^|,)\s*'?([A-Za-z_][\w.{}]*)'?\s*=\s*(?:(?:lower|upper)\(\s*)?'?([A-Za-z_][\w.{}]*)'?\s*\)?\s*(?:,|$)`)
)

// lenRe is an eval assignment of a field's length; maxHintLen is the
// longest text a length hint makes.
var lenRe = regexp.MustCompile(`(?i)^\s*'?([A-Za-z_]\w*)'?\s*=\s*len\(\s*'?([A-Za-z_][\w.{}]*)'?\s*\)\s*$`)

const maxHintLen = 4096

// rexGroupRe is a named group of a regular expression.
var rexGroupRe = regexp.MustCompile(`\(\?P?<([A-Za-z_]\w*)>`)

// unquote reads a double-quoted string of the search language, whose \\
// is a backslash and \" a quote (as Signalith's search reads it).
func unquote(s string) string {
	return splString(strings.TrimSuffix(strings.TrimPrefix(s, `"`), `"`))
}

// hints are a rule's later stages' tests of fields, as comparisons of
// stored fields (nil when it has none).
func (r *Rule) hints() []Expr {
	if r.Post == "" {
		return nil
	}
	stages := strings.Split(r.Post, "\n| ")
	// Splunk's name of a field, or an eval's copy of it, to the field
	// Signalith stores.
	alias := map[string]string{}
	for _, s := range stages {
		s = strings.TrimSpace(s)
		{
			// A field a later stage tests may be a rename or a rex's of
			// the field Signalith stores: a lookup's key field, a
			// channel node's rename param1 as display_name, a request
			// parameter a CloudTrail rule renames.
			if q, err := query.Parse("* | " + s); err == nil && len(q.Commands) == 1 {
				switch c := q.Commands[0].(type) {
				case *query.Rename:
					for _, p := range c.Pairs {
						if !strings.Contains(p[0], "*") && p[0] != p[1] {
							alias[p[1]] = p[0]
						}
					}
				case *query.Rex:
					for _, m := range rexGroupRe.FindAllStringSubmatch(c.Pattern, -1) {
						if c.Field != "" && m[1] != c.Field {
							alias[m[1]] = c.Field
						}
					}
				case *query.Stats:
					// A field's values, which one event gives as its own.
					for _, a := range c.Aggs {
						switch a.Func {
						case "values", "list", "first", "last", "earliest", "latest":
							if a.Field != "" && a.Column() != a.Field {
								alias[a.Column()] = a.Field
							}
						}
					}
				case *query.Eval:
					// The values joined, which is the one value of one event.
					for _, a := range c.Assigns {
						if x, ok := a.Expr.(*query.Call); ok && x.Func == "mvjoin" && len(x.Args) == 2 {
							if f, ok := x.Args[0].(*query.Field); ok && f.Name != a.Field {
								alias[a.Field] = f.Name
							}
						}
					}
				}
			}
		}
		body, ok := strings.CutPrefix(s, "eval ")
		if !ok {
			continue
		}
		for _, part := range splitTop(body) {
			if m := copyRe.FindStringSubmatch(part); m != nil && m[1] != m[2] {
				alias[m[1]] = m[2]
			} else if m := replaceRe.FindStringSubmatch(part); m != nil && m[1] != m[2] {
				// A field with some text taken out is close to it.
				alias[m[1]] = m[2]
			} else if m := firstArgRe.FindStringSubmatch(part); m != nil && m[1] != m[2] {
				// The field when it is set (coalesce), or each of its
				// values (mvmap, mvfilter).
				alias[m[1]] = m[2]
			}
		}
	}
	stored := func(f string) string {
		for range 4 {
			g, ok := alias[f]
			if !ok {
				break
			}
			f = g
		}
		return f
	}
	var out []Expr
	seen := map[string]bool{}
	add := func(e *Cmp) {
		k := key(map[string]string{"f": e.Field, "v": strings.Join(e.Values, "\x01"), "r": map[bool]string{true: "1"}[e.Regex]})
		if seen[k] || len(e.Values) == 0 {
			return
		}
		if e.Regex {
			if _, err := compiled(e.Values[0]); err != nil {
				return
			}
		}
		seen[k] = true
		out = append(out, e)
	}
	// A lookup's key field with values of its table, each a hint.
	for _, h := range r.lookupHints {
		for _, v := range h.values() {
			add(&Cmp{Field: stored(h.field), Values: []string{v}})
		}
	}
	groups := map[string][2]string{} // a rex's group: its field and pattern
	lens := map[string]string{}      // an eval's length of a field: the field
	// groupValues adds, for text a channel node's rex group is compared
	// with, the rex's pattern with that text for the group (where
	// config_name IN ("clr enabled")).
	groupValues := func(group string, vals []string) {
		g, ok := groups[group]
		if !ok || !IsChannelNode(r.Node) {
			return
		}
		start, end := groupSpan(g[1], group)
		if start < 0 {
			return
		}
		for _, v := range vals[:min(len(vals), 4)] {
			add(&Cmp{Field: stored(g[0]), Values: []string{g[1][:start] + "(?:" + regexp.QuoteMeta(v) + ")" + g[1][end:]}, Regex: true})
		}
	}
	for _, s := range stages {
		s = strings.TrimSpace(s)
		negated := func(at int) bool { return hintNotRe.MatchString(s[:at]) }
		inRe := hintInRe
		if IsChannelNode(r.Node) && strings.HasPrefix(s, "search ") {
			// Any term of a channel node's later search.
			inRe = hintTermInRe
		}
		for _, m := range inRe.FindAllStringSubmatchIndex(s, -1) {
			if negated(m[0]) {
				continue
			}
			var vals []string
			for _, q := range quotedRe.FindAllString(s[m[4]:m[5]], -1) {
				vals = append(vals, unquote(q))
			}
			add(&Cmp{Field: stored(s[m[2]:m[3]]), Values: vals})
			groupValues(s[m[2]:m[3]], vals)
		}
		for _, m := range hintEqRe.FindAllStringSubmatchIndex(s, -1) {
			if !negated(m[0]) {
				add(&Cmp{Field: stored(s[m[2]:m[3]]), Values: []string{unquote(s[m[4]:m[5]])}})
				groupValues(s[m[2]:m[3]], []string{unquote(s[m[4]:m[5]])})
			}
		}
		for _, m := range hintLikeRe.FindAllStringSubmatchIndex(s, -1) {
			if negated(m[0]) {
				continue
			}
			// like's % is any run of characters; _ any one, which the
			// character itself is.
			add(&Cmp{Field: stored(s[m[2]:m[3]]), Values: []string{strings.ReplaceAll(unquote(s[m[4]:m[5]]), "%", "*")}})
		}
		for _, re := range []*regexp.Regexp{hintMatchRe, hintRexRe, hintRegexRe} {
			for _, m := range re.FindAllStringSubmatchIndex(s, -1) {
				if negated(m[0]) || strings.Contains(s[m[0]:m[1]], "mode=sed") || strings.HasPrefix(s[m[1]:], "!") {
					continue
				}
				add(&Cmp{Field: stored(s[m[2]:m[3]]), Values: []string{unquote(s[m[4]:m[5]])}, Regex: true})
			}
		}
		// A number a rex's group is compared with (where
		// tonumber(target_rid) IN (512, 513)): the rex's pattern with
		// that number for the group.
		if m := hintRexRe.FindStringSubmatch(s); m != nil && !strings.Contains(s, "mode=sed") {
			pat := unquote(m[2])
			for _, g := range rexGroupRe.FindAllStringSubmatch(pat, -1) {
				groups[g[1]] = [2]string{m[1], pat}
			}
		}
		if body, ok := strings.CutPrefix(s, "eval "); ok {
			for _, part := range splitTop(body) {
				if m := lenRe.FindStringSubmatch(part); m != nil {
					lens[m[1]] = m[2]
				}
			}
		}
		for _, n := range hintNumbers(s, negated) {
			// A length a where needs (eval n = len(value) | where n >
			// 512): text that long.
			if f, ok := lens[n[0]]; ok {
				if l, err := strconv.Atoi(n[1]); err == nil && l > 0 && l <= maxHintLen {
					add(&Cmp{Field: stored(f), Values: []string{strings.Repeat("A", l)}})
				}
			}
			g, ok := groups[n[0]]
			if !ok {
				continue
			}
			if start, end := groupSpan(g[1], n[0]); start >= 0 {
				add(&Cmp{Field: stored(g[0]), Values: []string{g[1][:start] + "(?:" + n[1] + ")" + g[1][end:]}, Regex: true})
			}
		}
	}
	return out
}

// hintNumRe is a where's comparison of a field, or its number, with a
// number, and hintNumInRe its test against a list of numbers.
var (
	hintNumRe   = regexp.MustCompile(`(?i)\b(?:tonumber\(\s*'?([A-Za-z_]\w*)'?\s*\)|'?([A-Za-z_]\w*)'?)\s*(==?|>=|>)\s*(\d+)\b`)
	hintNumInRe = regexp.MustCompile(`(?i)\b(?:tonumber\(\s*'?([A-Za-z_]\w*)'?\s*\)|'?([A-Za-z_]\w*)'?)\s+IN\s*\(([\d\s,]+)\)`)
)

// hintNumbers are the fields a where stage compares with numbers, each
// with a number the comparison accepts.
func hintNumbers(s string, negated func(int) bool) [][2]string {
	if !strings.HasPrefix(strings.ToLower(s), "where ") {
		return nil
	}
	var out [][2]string
	for _, m := range hintNumRe.FindAllStringSubmatchIndex(s, -1) {
		if negated(m[0]) {
			continue
		}
		f := s[max(m[2], 0):max(m[3], 0)] + s[max(m[4], 0):max(m[5], 0)]
		n, err := strconv.Atoi(s[m[8]:m[9]])
		if err != nil {
			continue
		}
		if s[m[6]:m[7]] == ">" {
			n++
		}
		out = append(out, [2]string{f, strconv.Itoa(n)})
	}
	for _, m := range hintNumInRe.FindAllStringSubmatchIndex(s, -1) {
		if negated(m[0]) {
			continue
		}
		f := s[max(m[2], 0):max(m[3], 0)] + s[max(m[4], 0):max(m[5], 0)]
		for _, v := range strings.Split(s[m[6]:m[7]], ",") {
			if v = strings.TrimSpace(v); v != "" {
				out = append(out, [2]string{f, v})
			}
		}
	}
	return out
}

// splitTop splits an eval's assignments at the commas outside
// parentheses and quotes.
func splitTop(s string) []string {
	var out []string
	depth, quote, start := 0, false, 0
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == '\\' && quote:
			i++
		case c == '"':
			quote = !quote
		case quote:
		case c == '(':
			depth++
		case c == ')':
			depth--
		case c == ',' && depth == 0:
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	return append(out, s[start:])
}

// hinted are candidate field-level events from a rule's hints: the where
// clause with all of them, then with each one.
func (r *Rule) hinted() (pos, neg []map[string]string) {
	base, _ := Events(r.Where)
	if len(base) == 0 {
		return nil, nil
	}
	// Only a test of a field the node's events carry can help: those of
	// one of the first events (a registry value's data is a value's, not
	// a key's).
	var hs []Expr
	for _, h := range r.hints() {
		c := h.(*Cmp)
		v := example(lit{field: c.Field, values: c.Values, re: c.Regex}, rand.New(rand.NewSource(1)))
		if v != "" && slices.ContainsFunc(base[:min(len(base), maxHintBases)], func(b map[string]string) bool {
			ev := maps.Clone(b)
			ev[c.Field] = v
			return slices.ContainsFunc(r.records(ev), func(rc sigmacheck.Case) bool {
				doc, _ := Stored(rc)
				return View(doc)[c.Field] != ""
			})
		}) {
			hs = append(hs, h)
		}
	}
	if len(hs) == 0 {
		return nil, nil
	}
	hs = hs[:min(len(hs), maxHints)]
	all := &And{append([]Expr{r.Where}, hs...)}
	pos, neg = Events(all)
	if len(hs) > 1 {
		seen := map[string]bool{}
		for _, ev := range pos {
			seen[key(ev)] = true
		}
		for _, h := range hs {
			p, _ := Events(&And{[]Expr{r.Where, h}})
			for _, ev := range p {
				if k := key(ev); !seen[k] {
					seen[k] = true
					pos = append(pos, ev)
				}
			}
		}
	}
	return pos[:min(len(pos), maxHinted)], neg[:min(len(neg), maxHinted)]
}

// maxHints is how many of a rule's hints are tried, and maxHinted how
// many matching and near-miss events are made from them, which keeps a
// rule with many (a case() of 50 like()s) quick to test.
const (
	maxHints  = 16
	maxHinted = 48
	// maxHintBases is how many of the where clause's events a hint's
	// field is looked for in.
	maxHintBases = 4
)

// records are the events of the rule's platform that carry a field-level
// event.
func (r *Rule) records(ev map[string]string) []sigmacheck.Case {
	if r.Linux {
		return linuxRecords(r.Node, ev)
	}
	if r.MacOS {
		return macOSRecords(r.Node, ev)
	}
	return records(r.Node, ev)
}

// imageDirs are where a test event's program runs from when the rule
// names its file name alone and leaves out the system folder.
var imageDirs = []string{`C:\Users\Public\`, `C:\ProgramData\`}

// variants are other field-level events like ev, for a rule none of
// whose test events it finds: the program in a folder other than
// System32, the program's file name at the end of the folder the rule
// names, a library loaded from the program's own folder, and a write to
// a share rather than a read.
func variants(node string, ev map[string]string) []map[string]string {
	var out []map[string]string
	if node == "ImageLoad" && ev["process_path"] == "" && ev["loaded_file_path"] == "" {
		// A program and the library it loads from its own folder, as a
		// side-loaded one is.
		m := maps.Clone(ev)
		dir := `C:\Users\Public\Downloads\Updater\`
		m["process_path"] = dir + cmp.Or(ev["process_name"], "updater.exe")
		m["loaded_file_path"] = dir + "version.dll"
		out = append(out, m)
	}
	if node == "ShareAccess" && ev["access_mask"] == "" && ev["access_list"] == "" {
		// A write to a file on the share (WriteData) rather than a read.
		m := maps.Clone(ev)
		m["access_mask"], m["access_list"] = "0x2", "%%4417"
		out = append(out, m)
	}
	for _, p := range [][2]string{{"process_path", "process_name"}, {"parent_process_path", "parent_process_name"}} {
		path, name := ev[p[0]], ev[p[1]]
		switch {
		case name != "" && path == "":
			for _, d := range imageDirs {
				m := maps.Clone(ev)
				m[p[0]] = d + name
				out = append(out, m)
			}
		case name != "" && !strings.HasSuffix(strings.ToLower(path), `\`+strings.ToLower(name)):
			m := maps.Clone(ev)
			m[p[0]] = strings.TrimRight(path, `\`) + `\` + name
			out = append(out, m)
		}
	}
	return slices.DeleteFunc(out, func(m map[string]string) bool { return key(m) == key(ev) })
}

// NoEventsReason says why none of a rule's test events is one it finds:
// none matches its filter, or the later stages keep none of those that
// do, an outlier test (above the average by three standard deviations)
// among them, which needs a baseline of earlier counts.
func NoEventsReason(r *Rule, cases []sigmacheck.Case) string {
	src := "Windows"
	switch {
	case IsSensorNode(r.Node):
		src = "network sensor"
	case r.Node == AuditdNode:
		src = "Linux audit"
	case r.Node == CloudTrailNode:
		src = "CloudTrail"
	case r.Node == AzureNode:
		src = "Entra ID or Azure"
	case r.Node == O365Node:
		src = "Microsoft 365"
	case r.Node == OktaNode || r.Node == OktaAuthNode || r.Node == OktaChangeNode:
		src = "Okta"
	case r.Node == KubernetesNode:
		src = "Kubernetes audit"
	case r.Node == GitHubNode:
		src = "GitHub audit"
	case r.Node == "Web":
		src = "web access log"
	}
	if !slices.ContainsFunc(cases, func(c sigmacheck.Case) bool { return reads(r, c) }) {
		return "no test events: no " + src + " event as Signalith stores it matches the rule"
	}
	if len(r.Joins) > 0 {
		return "no test events: no " + src + " events the rule's join joins"
	}
	if strings.Contains(r.Post, "stdev(") {
		return "no test events: the rule's later stages keep only outliers above a baseline (average and standard deviation) of earlier counts"
	}
	switch stage, missing := r.dropStage(cases); {
	case len(missing) > 0:
		return "no test events: the rule's later stats groups by " + strings.Join(missing[:min(len(missing), 3)], ", ") +
			", which none of the " + src + " events that match its filter has"
	case stage != "":
		return "no test events: the rule's later " + stage + " keeps none of the " + src + " events that match its filter"
	}
	return "no test events: the rule's later stages keep none of the " + src + " events that match its filter"
}

// dropStage is the later stage that keeps none of the rows of the test
// events the rule's filter matches, of the event whose rows get furthest
// ("" when it cannot say), with the fields a stats groups by that none
// of the rows before it has.
func (r *Rule) dropStage(cases []sigmacheck.Case) (string, []string) {
	stages := strings.Split(r.Post, "\n| ")
	if len(stages) != len(r.post) {
		return "", nil
	}
	// rows are the rows of an event's docs after the first k stages.
	rows := func(docs []map[string]any, k int) ([]search.Row, error) {
		rr := *r
		rr.post = r.post[:k]
		return rr.runPost(docs)
	}
	best := -1
	var bestDocs []map[string]any
	for _, c := range cases {
		if !reads(r, c) {
			continue
		}
		docs, _ := StoredAll(c)
		for k := range r.post {
			out, err := rows(docs, k+1)
			if err != nil {
				break
			}
			if len(out) == 0 {
				if k > best {
					best, bestDocs = k, docs
				}
				break
			}
		}
	}
	if best < 0 {
		return "", nil
	}
	before, err := rows(bestDocs, best)
	if err != nil {
		return "", nil
	}
	if s, ok := r.post[best].(*query.Stats); ok {
		var missing []string
		for _, f := range s.By {
			if !slices.ContainsFunc(before, func(row search.Row) bool { return View(row)[f] != "" }) {
				missing = append(missing, f)
			}
		}
		if len(missing) > 0 {
			return "", missing
		}
	}
	stage := strings.Join(strings.Fields(stages[best]), " ")
	if len(stage) > maxStageText {
		stage = strings.ToValidUTF8(stage[:maxStageText], "") + "…"
	}
	return stage, nil
}

// maxStageText is how much of a stage a reason quotes.
const maxStageText = 60
