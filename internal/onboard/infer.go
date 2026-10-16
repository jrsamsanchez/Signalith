package onboard

import (
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// Free text is read with a regular expression Signalith writes from the
// sample: each line is cut into tokens (times, addresses, numbers, quoted
// strings, bracketed parts and words), the lines' tokens are lined up,
// and a token that is the same on every line stays literal while one
// that varies becomes a named group, named from the word before it
// (from 10.0.0.5 gives src) or else from what it holds.

// token kinds.
const (
	tkTime    = "time"
	tkIP      = "ip"
	tkIPPort  = "ipport"
	tkNum     = "num"
	tkQuoted  = "quoted"
	tkBracket = "bracket"
	tkProgPID = "progpid"
	tkKV      = "kv"
	tkWord    = "word"
)

type token struct {
	kind string
	text string
	// re is the pattern of a time token's format.
	re string
	// key is a key=value token's key.
	key string
}

// timePatterns are the times tokenize recognizes, as patterns anchored
// at the token's start.
var timePatterns = []string{
	`\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?`,
	`\[\d{2}/[A-Z][a-z]{2}/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4}\]`,
	`\d{2}/[A-Z][a-z]{2}/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4}`,
	`[A-Z][a-z]{2} [ \d]\d \d{2}:\d{2}:\d{2}`,
	`\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?`,
	`\d{1,2}/\d{1,2}/\d{4},? \d{1,2}:\d{2}:\d{2}(?: [AP]M)?`,
}

var (
	timeREs    []*regexp.Regexp
	quotedRE   = regexp.MustCompile(`^"(?:[^"\\]|\\.)*"`)
	bracketRE  = regexp.MustCompile(`^\[[^\]]{0,512}\]`)
	progPIDRE  = regexp.MustCompile(`^[A-Za-z][\w.\-/]{0,63}\[\d{1,10}\]:?$`)
	kvTokenRE  = regexp.MustCompile(`^([A-Za-z_][\w.\-]{0,63})=\S*$`)
	numRE      = regexp.MustCompile(`^-?\d+(?:\.\d+)?$`)
	requestRE  = regexp.MustCompile(`^"(?:GET|POST|PUT|DELETE|HEAD|PATCH|OPTIONS|CONNECT|TRACE) \S+ HTTP/[\d.]+"$`)
	labelClean = strings.NewReplacer(":", "", "=", "", "(", "", ")", "", ",", "", "'", "", `"`, "")
)

func init() {
	for _, p := range timePatterns {
		timeREs = append(timeREs, regexp.MustCompile(`^(?:`+p+`)`))
	}
}

// maxTokens is the most tokens of a line that are lined up.
const maxTokens = 48

// tokenize cuts a line into tokens.
func tokenize(s string) []token {
	var out []token
	i := 0
	for i < len(s) && len(out) < maxTokens {
		for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
			i++
		}
		if i >= len(s) {
			break
		}
		rest := s[i:]
		matched := false
		for j, re := range timeREs {
			if loc := re.FindStringIndex(rest); loc != nil {
				end := loc[1]
				if end < len(rest) && rest[end] != ' ' && rest[end] != '\t' {
					continue
				}
				out = append(out, token{kind: tkTime, text: rest[:end], re: timePatterns[j]})
				i += end
				matched = true
				break
			}
		}
		if matched {
			continue
		}
		if loc := quotedRE.FindStringIndex(rest); loc != nil && (loc[1] == len(rest) || rest[loc[1]] == ' ') {
			out = append(out, token{kind: tkQuoted, text: rest[:loc[1]]})
			i += loc[1]
			continue
		}
		if loc := bracketRE.FindStringIndex(rest); loc != nil && (loc[1] == len(rest) || rest[loc[1]] == ' ') {
			out = append(out, token{kind: tkBracket, text: rest[:loc[1]]})
			i += loc[1]
			continue
		}
		end := strings.IndexAny(rest, " \t")
		if end < 0 {
			end = len(rest)
		}
		w := rest[:end]
		t := token{kind: wordKind(w), text: w}
		if m := kvTokenRE.FindStringSubmatch(w); m != nil && t.kind == tkWord {
			t.kind, t.key = tkKV, m[1]
		}
		out = append(out, t)
		i += end
	}
	return out
}

func wordKind(w string) string {
	if a, err := netip.ParseAddr(w); err == nil && (a.Is4() || strings.Count(w, ":") >= 2) {
		return tkIP
	}
	if ap, err := netip.ParseAddrPort(w); err == nil && ap.Addr().Is4() {
		return tkIPPort
	}
	if numRE.MatchString(w) {
		return tkNum
	}
	if progPIDRE.MatchString(w) {
		return tkProgPID
	}
	return tkWord
}

// context words: the word before a value names it.
var contextNames = map[string]string{
	"from": "src", "src": "src", "source": "src", "client": "src", "remote": "src", "rhost": "src",
	"to": "dest", "dst": "dest", "dest": "dest", "destination": "dest", "server": "dest", "target": "dest",
	"user": "user", "for": "user", "username": "user", "account": "user", "by": "user", "uid": "user",
	"pid": "process_id", "status": "status", "code": "status", "method": "http_method", "url": "url",
	"proto": "transport", "protocol": "transport", "port": "port", "action": "action", "rule": "signature",
	"bytes": "bytes", "size": "bytes", "host": "dest_host", "hostname": "dest_host", "domain": "query",
	"query": "query", "file": "file_name", "path": "file_path", "process": "process_name", "cmd": "process",
}

// inferred is a pattern written from a sample.
type inferred struct {
	pattern   string
	timeField string
	// matched is how many of the lines the pattern reads.
	matched int
}

// inferPattern writes a regular expression for lines of free text, or
// reports false when the lines give nothing to extract. Lines are grouped
// by their shape (how many tokens, of which kinds), and the pattern is
// written for the largest group; when no group has half the lines, the
// tokens the lines start with alike are lined up and the rest of each
// line is one field.
func inferPattern(lines []string) (inferred, bool) {
	if len(lines) == 0 {
		return inferred{}, false
	}
	all := make([][]token, len(lines))
	groups := map[string][]int{}
	var order []string
	for i, l := range lines {
		all[i] = tokenize(l)
		sh := shape(all[i])
		if _, ok := groups[sh]; !ok {
			order = append(order, sh)
		}
		groups[sh] = append(groups[sh], i)
	}
	best := order[0]
	for _, sh := range order[1:] {
		if len(groups[sh]) > len(groups[best]) {
			best = sh
		}
	}
	var toks [][]token
	if len(groups[best])*2 >= len(lines) {
		for _, i := range groups[best] {
			toks = append(toks, all[i])
		}
	} else {
		toks = all
	}
	inf, ok := writePattern(toks, lines[groups[best][0]])
	if !ok {
		return inferred{}, false
	}
	re, err := compilePattern(inf.pattern)
	if err != nil {
		return inferred{}, false
	}
	for _, l := range lines {
		if re.MatchString(l) {
			inf.matched++
		}
	}
	return inf, true
}

// shape is a line's tokens' kinds, with the key of each key=value.
func shape(ts []token) string {
	var b strings.Builder
	for _, t := range ts {
		k := t.kind
		if isWordish(k) {
			k = tkWord
		}
		b.WriteString(k)
		if t.kind == tkKV {
			b.WriteString(":" + t.key)
		}
		b.WriteByte(' ')
	}
	return b.String()
}

var (
	levelWords  = []string{"trace", "debug", "info", "information", "informational", "notice", "warn", "warning", "error", "err", "crit", "critical", "alert", "emerg", "emergency", "fatal", "severe"}
	actionWords = slices.Concat(allowedWords, blockedWords, successWords, failureWords)
)

// allIn reports whether every token at p is one of words, ignoring case.
func allIn(toks [][]token, p int, words []string) bool {
	for _, t := range toks {
		if !slices.Contains(words, strings.ToLower(strings.Trim(t[p].text, ":,;"))) {
			return false
		}
	}
	return true
}

// writePattern lines up the lines' tokens and writes the pattern. first
// is a line of the group, which tells an access log's leading client
// address apart.
func writePattern(toks [][]token, first0 string) (inferred, bool) {
	minN, maxN := maxTokens+1, 0
	for _, t := range toks {
		minN = min(minN, len(t))
		maxN = max(maxN, len(t))
	}
	if minN == 0 {
		return inferred{}, false
	}
	n := minN
	for p := 0; p < minN; p++ {
		kind := toks[0][p].kind
		for _, t := range toks[1:] {
			if t[p].kind != kind && !(isWordish(t[p].kind) && isWordish(kind)) || kind == tkKV && t[p].key != toks[0][p].key {
				n = p
				break
			}
		}
		if n == p {
			break
		}
	}
	tail := n < maxN
	if tail && n == minN && n > 0 {
		// Lines of different lengths: the last lined-up token starts the
		// message, so lines with more words still match.
		n--
	}
	var b strings.Builder
	b.WriteString("^")
	used := map[string]int{}
	name := func(base string) string {
		used[base]++
		if used[base] == 1 {
			return base
		}
		return base + strconv.Itoa(used[base])
	}
	counts := map[string]int{}
	numbered := func(kind string) string {
		counts[kind]++
		return kind + strconv.Itoa(counts[kind])
	}
	inf := inferred{}
	groups := 0
	prevLabel := ""
	lastAddr := ""
	afterRequest := 0
	single := len(toks) == 1
	for p := 0; p < n; p++ {
		if p > 0 {
			b.WriteString(`\s+`)
		}
		first := toks[0][p]
		constant := true
		for _, t := range toks[1:] {
			if t[p].text != first.text {
				constant = false
				break
			}
		}
		label := contextNames[prevLabel]
		// A token alike on every line stays literal, unless the word
		// before names it (for root). A lone line has nothing to compare
		// with: words stay literal, values become fields.
		if constant && label == "" && first.kind != tkTime && first.kind != tkKV && (!single || first.kind == tkWord) {
			b.WriteString(regexp.QuoteMeta(first.text))
			prevLabel = strings.ToLower(labelClean.Replace(first.text))
			continue
		}
		prevLabel = ""
		kind := first.kind
		for _, t := range toks[1:] {
			if t[p].kind != kind {
				kind = tkWord
			}
		}
		switch kind {
		case tkTime:
			f := name("timestamp")
			if inf.timeField == "" {
				inf.timeField = f
			}
			if strings.HasPrefix(first.text, "[") {
				b.WriteString(`\[(?P<` + f + `>[^\]]+)\]`)
			} else {
				b.WriteString(`(?P<` + f + `>` + first.re + `)`)
			}
		case tkKV:
			f := MapName(first.key)
			if f == "" {
				f = SanitizeName(first.key)
			}
			if f == "" {
				f = numbered("field")
			}
			b.WriteString(regexp.QuoteMeta(first.key) + `=(?P<` + name(f) + `>\S*)`)
		case tkIP:
			f := label
			if f != "src" && f != "dest" {
				f = numbered("ip")
				if counts["ip"] == 1 && strings.HasPrefix(first0, first.text) {
					f = "src" // an access log starts with the client
				}
			}
			lastAddr = f
			b.WriteString(`(?P<` + name(f) + `>[0-9A-Fa-f:.]+)`)
		case tkIPPort:
			f := label
			if f != "src" && f != "dest" {
				f = numbered("ip")
			}
			lastAddr = f
			port := f + "_port"
			if f != "src" && f != "dest" {
				port = numbered("port")
			}
			b.WriteString(`(?P<` + name(f) + `>\d{1,3}(?:\.\d{1,3}){3}):(?P<` + name(port) + `>\d+)`)
		case tkNum:
			f := label
			switch {
			case f == "port" && (lastAddr == "src" || lastAddr == "dest"):
				f = lastAddr + "_port"
			case f == "port":
				f = "dest_port"
			case afterRequest == 1:
				f = "status"
			case afterRequest == 2:
				f = "bytes_out"
			case f == "":
				f = numbered("number")
			}
			if afterRequest > 0 {
				afterRequest++
			}
			b.WriteString(`(?P<` + name(f) + `>-?\d+(?:\.\d+)?)`)
		case tkQuoted:
			if allMatch(toks, p, requestRE) {
				b.WriteString(`"(?P<` + name("http_method") + `>[A-Z]+) (?P<` + name("uri_path") + `>[^ "?]*)(?:\?(?P<` + name("uri_query") + `>[^ "]*))? HTTP/(?P<` + name("http_version") + `>[\d.]+)"`)
				afterRequest = 1
				break
			}
			f := label
			if afterRequest > 0 {
				if used["http_referrer"] == 0 {
					f = "http_referrer"
				} else {
					f = "http_user_agent"
				}
			}
			if f == "" {
				f = numbered("text")
			}
			b.WriteString(`"(?P<` + name(f) + `>(?:[^"\\]|\\.)*)"`)
		case tkBracket:
			f := label
			if f == "" {
				f = numbered("field")
			}
			b.WriteString(`\[(?P<` + name(f) + `>[^\]]*)\]`)
		case tkProgPID:
			b.WriteString(`(?P<` + name("app") + `>[A-Za-z][\w.\-/]*)\[(?P<` + name("process_id") + `>\d+)\]:?`)
		default:
			f := label
			switch {
			case f != "" && f != "port":
			case allIn(toks, p, levelWords):
				f = "severity"
			case allIn(toks, p, actionWords):
				f = "action"
			default:
				f = numbered("field")
			}
			b.WriteString(`(?P<` + name(f) + `>\S+)`)
		}
		groups++
	}
	if tail {
		if n > 0 {
			b.WriteString(`\s+`)
		}
		b.WriteString(`(?P<` + name("detail") + `>.*)`)
		groups++
	}
	if groups == 0 {
		return inferred{}, false
	}
	inf.pattern = b.String()
	return inf, true
}

func isWordish(kind string) bool { return kind == tkWord || kind == tkProgPID || kind == tkNum }

func allMatch(toks [][]token, p int, re *regexp.Regexp) bool {
	for _, t := range toks {
		if !re.MatchString(t[p].text) {
			return false
		}
	}
	return true
}
