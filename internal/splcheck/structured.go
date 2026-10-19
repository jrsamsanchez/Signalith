// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package splcheck

import (
	"cmp"
	"encoding/json"
	"fmt"
	"maps"
	"math/rand"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/jrsamsanchez/signalith/internal/ingest"
	"github.com/jrsamsanchez/signalith/internal/query"
	"github.com/jrsamsanchez/signalith/internal/sigmacheck"
)

// A cloud rule's later stages often read a record's lists and the JSON
// in its values: an entry of Entra ID's modified properties by its place
// (mvindex('ModifiedProperties{}.NewValue', 4)) or by its name
// (mvfind('ModifiedProperties{}.Name', "AllowUserConsentForRiskyApps")),
// the last actor (mvindex('Actor{}.ID', len-1)), a policy's statements
// (spath input=requestParameters.policy path=Statement{}), a scan's
// findings, or a piece a rex takes from one of them. Structured events
// are candidate field-level events whose lists and JSON values hold what
// those stages read: each place a stage reads gets a value its tests of
// it accept (the where, search, rex, like() and mvfind() tests, as hints
// are), and every other entry of a list a placeholder, so the list keeps
// its places. As for hints, they are only candidates: whether the rule
// finds one is still what its where clause and later stages, run as
// written, say of the event as Signalith stores it.

// A step reads a piece of a value: the value at a JSON path in it, a
// piece of it split at a separator, or a rex group of it.
type step struct {
	kind  byte // 'j' JSON path, 's' split, 'r' rex group
	arg   string
	group string
}

// A place is where a later stage's field comes from: a field of the
// record (a list's entries by their place, ModifiedProperties{4}.NewValue,
// {last} for the last and {fN} for the one a find picks), and the steps
// that read a piece of its value.
type place struct {
	base  string
	steps []step
}

func (p place) key() string {
	var b strings.Builder
	b.WriteString(p.base)
	for _, s := range p.steps {
		fmt.Fprintf(&b, "\x00%c%s\x01%s", s.kind, s.arg, s.group)
	}
	return b.String()
}

func (p place) then(s step) place {
	return place{p.base, append(slices.Clone(p.steps), s)}
}

// into is the place of the value at a JSON path in p's value. An entry
// of a list of objects (spath path=findings{}, then spath input=findings)
// is the list's first entry's.
func (p place) into(path string) place {
	if strings.HasPrefix(path, "{}") {
		return p.then(step{kind: 'j', arg: path})
	}
	if len(p.steps) == 0 && strings.HasSuffix(p.base, "{}") {
		return place{base: p.base[:len(p.base)-2] + "{0}." + path}
	}
	if n := len(p.steps); n > 0 && p.steps[n-1].kind == 'j' && strings.HasSuffix(p.steps[n-1].arg, "{}") {
		q := place{p.base, slices.Clone(p.steps)}
		a := q.steps[n-1].arg
		q.steps[n-1].arg = a[:len(a)-2] + "{0}." + path
		return q
	}
	if p.base == "" && len(p.steps) == 0 {
		// The record itself.
		return place{base: path}
	}
	return p.then(step{kind: 'j', arg: path})
}

// A shape is what a rule's later stages need of an event: the tests of
// each place, and the places they need present.
type shape struct {
	tests   map[string][]lit
	present map[string]bool
	places  map[string]place
	// finds are the entries a find picks: the list's field it tests and
	// the regular expression.
	finds []find
	// ties are places a stage compares with each other (where
	// process=process_path), which need the same value.
	ties []tie
	// pieces are how many pieces a stage needs a place's value split
	// into, by the place's key.
	pieces map[string]pieceCount
}

// A tie is two places whose values a stage compares, ignoring case when
// fold.
type tie struct {
	a, b place
	fold bool
	// rest, when set, is a place whose value follows b's in a's
	// (like(process_path, process_current_directory.process_name)).
	rest *place
}

// A pieceCount is how many pieces a value split at sep must have:
// exactly n, or at least n.
type pieceCount struct {
	sep   string
	n     int
	exact bool
}

type find struct {
	field string // a list's field, with {} for the list (ModifiedProperties{}.Name)
	re    string
}

var (
	evalAssignRe  = regexp.MustCompile(`(?s)^\s*'?([A-Za-z_][\w.{}]*)'?\s*=([^=].*)$`)
	mvindexRe     = regexp.MustCompile(`(?i)^mvindex\s*\(\s*('[^']+'|[A-Za-z_][\w.{}]*)\s*,\s*([^,()]+?)\s*\)$`)
	mvcountRe     = regexp.MustCompile(`(?i)^mvcount\s*\(\s*('[^']+'|[A-Za-z_][\w.{}]*)\s*\)$`)
	mvindexFindRe = regexp.MustCompile(`(?i)^mvindex\s*\(\s*('[^']+'|[A-Za-z_][\w.{}]*)\s*,\s*mvfind\s*\(\s*('[^']+'|[A-Za-z_][\w.{}]*)\s*,\s*("(?:[^"\\]|\\.)*")\s*\)\s*\)$`)
	mvfindRe      = regexp.MustCompile(`(?i)mvfind\s*\(\s*('[^']+'|[A-Za-z_][\w.{}]*)\s*,\s*("(?:[^"\\]|\\.)*")\s*\)`)
	splitRe       = regexp.MustCompile(`(?i)^split\s*\(\s*('[^']+'|[A-Za-z_][\w.{}]*)\s*,\s*("(?:[^"\\]|\\.)*")\s*\)$`)
	copyExprRe    = regexp.MustCompile(`(?i)^(?:(?:lower|upper|trim|ltrim|rtrim|coalesce|replace|mvappend)\s*\(\s*)*('[^']+'|[A-Za-z_][\w.{}]*)\s*(?:[,)].*)?$`)
	countedRe     = regexp.MustCompile(`(?i)^(?:coalesce\s*\(\s*)?mvcount\s*\(\s*('[^']+'|[A-Za-z_][\w.{}]*)\s*\)`)
	condGtRe      = regexp.MustCompile(`(?i)'?([A-Za-z_]\w*)'?\s*>=?\s*('?[A-Za-z_]\w*'?|\d+)`)
	spathArgRe    = regexp.MustCompile(`(?i)\b(input|output|path)\s*=\s*("[^"]*"|\S+)`)
	rexStageRe    = regexp.MustCompile(`(?is)^rex\s+(?:field\s*=\s*("[^"]+"|\S+)\s+)?(?:max_match\s*=\s*\d+\s+)?("(?:[^"\\]|\\.)*")`)
	groupNameRe   = regexp.MustCompile(`\(\?P?<([A-Za-z_]\w*)>`)
	statsByRe     = regexp.MustCompile(`(?is)^stats\s.*?\bby\s+(.+)$`)
	dcArgRe       = regexp.MustCompile(`(?i)\bdc\(\s*'?([A-Za-z_][\w.{}]*)'?\s*\)`)
	condMvInRe    = regexp.MustCompile(`(?i)\bin\(\s*(?:mvmap\(\s*)?('[^']+'|[A-Za-z_][\w.{}]*)\s*(?:,\s*lower\([^()]*\)\s*\))?\s*,([^()]*)\)`)
	condInRe      = regexp.MustCompile(`(?i)('[^']+'|[A-Za-z_][\w.{}]*)\s+IN\s*\(([^)]*)\)`)
	condEqRe      = regexp.MustCompile(`(?i)('[^']+'|[A-Za-z_][\w.{}]*)\s*(=|!=|\s+like\s+)\s*("(?:[^"\\]|\\.)*"|[A-Za-z_][\w.]*)`)
	condFnRe      = regexp.MustCompile(`(?i)\b(like|match|isnotnull)\s*\(\s*('[^']+'|[A-Za-z_][\w.{}]*)\s*(?:,\s*("(?:[^"\\]|\\.)*"))?\s*\)`)
	condNotRe     = regexp.MustCompile(`(?i)\bNOT\s*\(?\s*$`)
	mvindexArgRe  = regexp.MustCompile(`^(-?\d+)$|^([A-Za-z_]\w*)\s*(?:-\s*(\d+))?$`)
)

// Ties, counts of pieces and the tests of an eval's if() or case().
var (
	// condTieRe is a comparison of two places: fields, their lower or
	// upper case, or a piece of a split field.
	condTieRe = regexp.MustCompile(`(?i)(` + tieSide + `)\s*==?\s*(` + tieSide + `)`)
	// likeTieRe is a like() of a field with another's value inside.
	likeTieRe = regexp.MustCompile(`(?i)\blike\(\s*('[^']+'|[A-Za-z_][\w.{}]*)\s*,\s*"%"\s*\.\s*('[^']+'|[A-Za-z_][\w.{}]*)\s*\.\s*"%"\s*\)`)
	// likeJoinRe is a like() of a field with two others' values joined.
	likeJoinRe = regexp.MustCompile(`(?i)\blike\(\s*('[^']+'|[A-Za-z_][\w.{}]*)\s*,\s*('[^']+'|[A-Za-z_][\w.{}]*)\s*\.\s*('[^']+'|[A-Za-z_][\w.{}]*)\s*\)`)
	// condNumRe is a comparison of a field with a number.
	condNumRe = regexp.MustCompile(`('[^']+'|[A-Za-z_][\w.{}]*)\s*(>=|>|==|=)\s*(\d+)\b`)
	// splitCountRe is a count of a field's pieces, less some.
	splitCountRe = regexp.MustCompile(`(?i)^mvcount\s*\(\s*split\s*\(\s*('[^']+'|[A-Za-z_][\w.{}]*)\s*,\s*("(?:[^"\\]|\\.)*")\s*\)\s*\)\s*(?:-\s*(\d+))?$`)
	condExprRe   = regexp.MustCompile(`(?is)^(?:if|case)\s*\(.*\)$`)
	splitPieceRe = regexp.MustCompile(`(?i)^mvindex\(\s*split\(\s*('[^']+'|[A-Za-z_][\w.{}]*)\s*,\s*("(?:[^"\\]|\\.)*")\s*\)\s*,\s*(\d+)\s*\)$`)
	foldRe       = regexp.MustCompile(`(?i)^(?:lower|upper)\(\s*(.*?)\s*\)$`)
)

const (
	tieField = `'[^']+'|[A-Za-z_][\w.{}]*`
	tiePiece = `mvindex\(\s*split\(\s*(?:` + tieField + `)\s*,\s*"(?:[^"\\]|\\.)*"\s*\)\s*,\s*\d+\s*\)`
	tieSide  = `(?:(?:lower|upper)\(\s*(?:` + tiePiece + `|` + tieField + `)\s*\)|` + tiePiece + `|` + tieField + `)`
	// maxCondDepth is how deep the tests of if()s are read, and
	// maxPieces the most pieces a split value is made of.
	maxCondDepth = 3
	maxPieces    = 16
)

// An evalCond is the test of an eval's if(), or of a case()'s first
// branch, and the value it gives when the test holds.
type evalCond struct {
	cond, then string
}

// A pieceVar is a count of the pieces of a place's value split at sep,
// less offset.
type pieceVar struct {
	src    place
	sep    string
	offset int
}

// condOf reads an eval's if(test, a, b), or case(test, a, ...).
func condOf(expr string) (evalCond, bool) {
	open := strings.IndexByte(expr, '(')
	args := splitTop(expr[open+1 : len(expr)-1])
	if len(args) < 2 || strings.HasPrefix(strings.ToLower(expr), "if") && len(args) != 3 {
		return evalCond{}, false
	}
	cond, then := strings.TrimSpace(args[0]), strings.TrimSpace(args[1])
	if strings.EqualFold(cond, "true()") || strings.EqualFold(then, "null()") || strings.EqualFold(then, "null") {
		return evalCond{}, false
	}
	return evalCond{cond, strings.Trim(then, `'"`)}, true
}

// sidePlace is the place a side of a tie reads, and whether the
// comparison ignores case; false for a word that is not a field.
func sidePlace(s string, resolve func(string) place) (place, bool, bool) {
	fold := false
	if m := foldRe.FindStringSubmatch(s); m != nil {
		s, fold = m[1], true
	}
	if m := splitPieceRe.FindStringSubmatch(s); m != nil {
		return resolve(m[1]).then(step{kind: 's', arg: unquote(m[2]), group: m[3]}), fold, true
	}
	switch strings.ToLower(strings.Trim(s, "'")) {
	case "and", "or", "not", "null", "true", "false", "like", "in":
		return place{}, false, false
	}
	return resolve(s), fold, true
}

func isWordByte(c byte) bool {
	return c == '_' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

// shapeOf reads what a rule's later stages need of an event.
func (r *Rule) shapeOf() *shape {
	sh := &shape{tests: map[string][]lit{}, present: map[string]bool{}, places: map[string]place{}, pieces: map[string]pieceCount{}}
	vars := map[string]place{}
	counts := map[string]string{} // a count of a list's entries: the list's field
	finds := map[string]int{}     // an index a find picks
	splits := map[string]place{}  // a split value, and its separator
	seps := map[string]string{}
	conds := map[string]evalCond{}     // what an eval's if() or case() tests
	pieceVars := map[string]pieceVar{} // a count of a split value's pieces
	tied := map[string]bool{}          // places a tie already gives a value
	var auto []place                   // values spath reads every field of
	props := false                     // rename properties.* as *
	unq := func(s string) string { return strings.Trim(s, `'"`) }
	resolve := func(name string) place {
		name = unq(name)
		if p, ok := vars[name]; ok {
			return p
		}
		if strings.HasPrefix(name, "{}") && len(auto) > 0 {
			return auto[len(auto)-1].into(name)
		}
		if r.postField != nil {
			if f, ok := r.postField(name); ok {
				return place{base: f}
			}
		}
		if props && r.Node == AzureNode && ingest.AzureField("properties."+name) {
			return place{base: "properties." + name}
		}
		if len(auto) > 0 && !strings.Contains(name, "{") {
			return auto[len(auto)-1].into(name)
		}
		return place{base: name}
	}
	// at is a list's field at an index: the last {} becomes it.
	at := func(p place, idx string) place {
		if len(p.steps) > 0 {
			if last := &p.steps[len(p.steps)-1]; last.kind == 'j' {
				if i := strings.LastIndex(last.arg, "{}"); i >= 0 {
					p.steps = slices.Clone(p.steps)
					p.steps[len(p.steps)-1].arg = last.arg[:i] + "{" + idx + "}" + last.arg[i+2:]
				}
			}
			return p
		}
		if i := strings.LastIndex(p.base, "{}"); i >= 0 {
			p.base = p.base[:i] + "{" + idx + "}" + p.base[i+2:]
		}
		return p
	}
	need := func(p place, l *lit) {
		k := p.key()
		sh.places[k] = p
		if l == nil {
			sh.present[k] = true
			return
		}
		sh.tests[k] = append(sh.tests[k], *l)
	}
	addFind := func(field, re string) int {
		p := resolve(field)
		if !strings.Contains(p.base, "{}") || len(p.steps) > 0 {
			// A find in a value that is not a record's list: the
			// value must match.
			need(p, &lit{field: "v", values: []string{re}, re: true})
			return -1
		}
		n := slices.Index(sh.finds, find{p.base, re})
		if n >= 0 {
			return n
		}
		sh.finds = append(sh.finds, find{p.base, re})
		n = len(sh.finds) - 1
		need(at(p, fmt.Sprintf("f%d", n)), &lit{field: "v", values: []string{re}, re: true})
		return n
	}
	// test reads what a where or search condition needs of an event. A
	// bare word is a field in a where (and an eval's test), and a value in
	// a search, which so compares no two fields.
	var test func(cond string, depth int, where bool)
	test = func(cond string, depth int, where bool) {
		if depth > maxCondDepth {
			return
		}
		negated := func(at int) bool { return condNotRe.MatchString(cond[:at]) }
		// Two places compared with each other (where process=process_path,
		// like(process, "%".parent_process."%")): of tests in an OR, the
		// first that ties a place.
		addTie := func(a, b place, fold bool) {
			if tied[a.key()] || tied[b.key()] || a.key() == b.key() {
				return
			}
			tied[a.key()], tied[b.key()] = true, true
			sh.ties = append(sh.ties, tie{a: a, b: b, fold: fold})
			need(a, nil)
			need(b, nil)
		}
		for _, m := range condTieRe.FindAllStringSubmatchIndex(cond, -1) {
			if !where || negated(m[0]) || m[0] > 0 && strings.ContainsRune("!<>=.'{}_", rune(cond[m[0]-1])) ||
				m[0] > 0 && isWordByte(cond[m[0]-1]) || m[1] < len(cond) && (cond[m[1]] == '(' || isWordByte(cond[m[1]])) {
				continue
			}
			a, foldA, okA := sidePlace(cond[m[2]:m[3]], resolve)
			b, foldB, okB := sidePlace(cond[m[4]:m[5]], resolve)
			if okA && okB {
				addTie(a, b, foldA || foldB)
			}
		}
		for _, m := range likeJoinRe.FindAllStringSubmatchIndex(cond, -1) {
			a, b, rest := resolve(cond[m[2]:m[3]]), resolve(cond[m[4]:m[5]]), resolve(cond[m[6]:m[7]])
			if !negated(m[0]) && !tied[b.key()] {
				tied[b.key()] = true
				sh.ties = append(sh.ties, tie{a: a, b: b, rest: &rest})
				need(b, nil)
			}
		}
		for _, m := range likeTieRe.FindAllStringSubmatchIndex(cond, -1) {
			if !negated(m[0]) {
				// The value contains the other's: is the same.
				addTie(resolve(cond[m[2]:m[3]]), resolve(cond[m[4]:m[5]]), false)
			}
		}
		for _, m := range condNumRe.FindAllStringSubmatchIndex(cond, -1) {
			name, op, num := unq(cond[m[2]:m[3]]), cond[m[4]:m[5]], cond[m[6]:m[7]]
			if negated(m[0]) {
				continue
			}
			if c, ok := conds[name]; ok && (op == "=" || op == "==") && c.then == num {
				// The number an if() gives when its test holds.
				test(c.cond, depth+1, true)
				continue
			}
			// A count of a split value's pieces compared with a number.
			pv, ok := pieceVars[name]
			if !ok {
				continue
			}
			n, _ := strconv.Atoi(num)
			if op == ">" {
				n++
			}
			if n += pv.offset; n < 1 || n > maxPieces {
				continue
			}
			k := pv.src.key()
			sh.places[k] = pv.src
			sh.pieces[k] = pieceCount{sep: pv.sep, n: n, exact: op == "=" || op == "=="}
		}
		for _, m := range condInRe.FindAllStringSubmatchIndex(cond, -1) {
			if negated(m[0]) {
				continue
			}
			var vals []string
			for _, q := range quotedRe.FindAllString(cond[m[4]:m[5]], -1) {
				vals = append(vals, unquote(q))
			}
			if len(vals) > 0 {
				need(resolve(cond[m[2]:m[3]]), &lit{field: "v", values: vals})
			}
		}
		for _, m := range condMvInRe.FindAllStringSubmatchIndex(cond, -1) {
			// A test of a field's values against a list (multiIn, inStarCompared).
			if negated(m[0]) {
				continue
			}
			var vals, exact []string
			for _, q := range quotedRe.FindAllString(cond[m[4]:m[5]], -1) {
				vals = append(vals, unquote(q))
				exact = append(exact, regexp.QuoteMeta(unquote(q)))
			}
			switch {
			case len(vals) == 0:
			case strings.Contains(cond[m[4]:m[5]], "*"):
				// in() compares exactly: a * is the character.
				need(resolve(cond[m[2]:m[3]]), &lit{field: "v", values: []string{"^(?:" + strings.Join(exact, "|") + ")$"}, re: true})
			default:
				need(resolve(cond[m[2]:m[3]]), &lit{field: "v", values: vals})
			}
		}
		for _, m := range condEqRe.FindAllStringSubmatchIndex(cond, -1) {
			name, op, val := cond[m[2]:m[3]], strings.TrimSpace(cond[m[4]:m[5]]), cond[m[6]:m[7]]
			if negated(m[0]) || strings.EqualFold(name, "NOT") {
				continue
			}
			if c, ok := conds[unq(name)]; ok {
				// The value an eval's if() or case() gives when its
				// test holds: the test.
				if op == "=" && unq(val) == c.then {
					test(c.cond, depth+1, true)
				}
				continue
			}
			quoted := strings.HasPrefix(val, `"`)
			if !quoted {
				if _, bound := vars[val]; bound || strings.EqualFold(val, "null") || r.postField != nil && func() bool { _, ok := r.postField(val); return ok }() {
					continue
				}
				if _, isNum := strconv.ParseFloat(val, 64); isNum == nil {
					continue
				}
			}
			v := val
			if quoted {
				v = unquote(val)
			}
			switch strings.ToLower(op) {
			case "=":
				need(resolve(name), &lit{field: "v", values: []string{v}})
			case "like":
				need(resolve(name), &lit{field: "v", values: []string{strings.ReplaceAll(v, "%", "*")}})
			case "!=":
				need(resolve(name), nil)
				need(resolve(name), &lit{field: "v", values: []string{v}, neg: true})
			}
		}
		for _, m := range condGtRe.FindAllStringSubmatch(cond, -1) {
			// A count of a rex's matches above another's, or above
			// a number: what it counts is there.
			if g, ok := counts[m[1]]; ok {
				need(resolve(g), nil)
			}
		}
		for _, m := range condFnRe.FindAllStringSubmatchIndex(cond, -1) {
			if negated(m[0]) {
				continue
			}
			fn, name := strings.ToLower(cond[m[2]:m[3]]), cond[m[4]:m[5]]
			if _, ok := finds[unq(name)]; ok {
				continue
			}
			if c, ok := conds[unq(name)]; ok {
				if fn == "isnotnull" {
					test(c.cond, depth+1, true)
				}
				continue
			}
			switch {
			case fn == "isnotnull":
				need(resolve(name), nil)
			case m[6] < 0:
			case fn == "like":
				need(resolve(name), &lit{field: "v", values: []string{strings.ReplaceAll(unquote(cond[m[6]:m[7]]), "%", "*")}})
			case fn == "match":
				need(resolve(name), &lit{field: "v", values: []string{unquote(cond[m[6]:m[7]])}, re: true})
			}
		}
	}
	stats := false
	for _, s := range strings.Split(r.Post, "\n| ") {
		s = strings.TrimSpace(s)
		word, rest, _ := strings.Cut(s, " ")
		switch strings.ToLower(word) {
		case "eval":
			for _, part := range splitTop(rest) {
				m := evalAssignRe.FindStringSubmatch(part)
				if m == nil {
					continue
				}
				name, expr := m[1], strings.TrimSpace(m[2])
				old, had := vars[name]
				delete(vars, name)
				delete(conds, name)
				delete(pieceVars, name)
				for _, f := range mvfindRe.FindAllStringSubmatch(expr, -1) {
					if n := addFind(f[1], unquote(f[2])); n >= 0 {
						finds[name] = n
					}
				}
				switch {
				case mvindexFindRe.MatchString(expr):
					// The entry a find picks, in one expression
					// (mvindex('X{}.NewValue', mvfind('X{}.Name', "re"))).
					f := mvindexFindRe.FindStringSubmatch(expr)
					if n := slices.Index(sh.finds, find{resolve(f[2]).base, unquote(f[3])}); n >= 0 {
						vars[name] = at(resolve(f[1]), fmt.Sprintf("f%d", n))
					}
				case mvfindRe.MatchString(expr):
				case mvindexRe.MatchString(expr):
					f := mvindexRe.FindStringSubmatch(expr)
					src := unq(f[1])
					if sp, ok := splits[src]; ok {
						vars[name] = sp.then(step{kind: 's', arg: seps[src], group: f[2]})
						continue
					}
					p := resolve(src)
					a := mvindexArgRe.FindStringSubmatch(f[2])
					switch {
					case a == nil:
					case a[1] == "-1":
						vars[name] = at(p, "last")
					case a[1] != "":
						if n, _ := strconv.Atoi(a[1]); n >= 0 {
							vars[name] = at(p, a[1])
						}
					case counts[a[2]] != "" && a[3] == "1":
						vars[name] = at(p, "last")
					default:
						if n, ok := finds[a[2]]; ok && a[3] == "" {
							vars[name] = at(p, fmt.Sprintf("f%d", n))
						}
					}
				case splitCountRe.MatchString(expr):
					f := splitCountRe.FindStringSubmatch(expr)
					off, _ := strconv.Atoi(f[3])
					pieceVars[name] = pieceVar{resolve(f[1]), unquote(f[2]), off}
				case mvcountRe.MatchString(expr):
					src := unq(mvcountRe.FindStringSubmatch(expr)[1])
					counts[name] = src
					if sp, ok := splits[src]; ok {
						pieceVars[name] = pieceVar{sp, seps[src], 0}
					}
				case countedRe.MatchString(expr):
					// A count of a rex's matches (coalesce(mvcount(g), 0)).
					counts[name] = unq(countedRe.FindStringSubmatch(expr)[1])
				case splitRe.MatchString(expr):
					f := splitRe.FindStringSubmatch(expr)
					splits[name], seps[name] = resolve(f[1]), unquote(f[2])
				case condExprRe.MatchString(expr):
					if c, ok := condOf(expr); ok {
						conds[name] = c
					}
				case copyExprRe.MatchString(expr):
					src := copyExprRe.FindStringSubmatch(expr)[1]
					if strings.EqualFold(src, "null") || strings.EqualFold(src, "true") || strings.EqualFold(src, "false") {
						continue
					}
					if args := coalesceArgs(expr); len(args) > 1 {
						// The first that is a list's entry or a field of
						// one, else the first.
						src = args[0]
						for _, a := range args {
							if strings.Contains(a, "{") || mvindexRe.MatchString(a) {
								src = a
								break
							}
						}
						if f := mvindexRe.FindStringSubmatch(src); f != nil {
							if a := mvindexArgRe.FindStringSubmatch(f[2]); a != nil && a[1] != "" && a[1] != "-1" {
								vars[name] = at(resolve(f[1]), a[1])
							}
							continue
						}
					}
					switch {
					case unq(src) != name:
						vars[name] = resolve(src)
					case had:
						// A field changed in place (replace(x, ...)).
						vars[name] = old
					}
				}
			}
		case "rename":
			pairs, err := parseRename(s)
			if err != nil {
				continue
			}
			for _, p := range pairs {
				switch {
				case p.from == "properties.*" && p.to == "*":
					props = true
				case !strings.Contains(p.from, "*"):
					vars[p.to] = resolve(p.from)
				}
			}
		case "spath":
			args := map[string]string{}
			for _, m := range spathArgRe.FindAllStringSubmatch(rest, -1) {
				args[strings.ToLower(m[1])] = strings.Trim(m[2], `"`)
			}
			in, path := args["input"], args["path"]
			out := cmp.Or(args["output"], path)
			switch {
			case path == "" && in != "":
				auto = append(auto, resolve(in))
			case path == "":
			case in == "" || in == "_raw":
				vars[out] = place{base: path}
			default:
				// The record itself (rex field=_raw "(?<j>{.+})"), an entry
				// of a list of objects, or JSON in a value.
				vars[out] = resolve(in).into(path)
			}
		case "regex":
			// A field's value must match (regex script_name="\.js$").
			if m := regexStageRe.FindStringSubmatch(s); m != nil {
				need(resolve(m[1]), &lit{field: "v", values: []string{splString(m[2])}, re: true})
			}
		case "rex":
			m := rexStageRe.FindStringSubmatch(s)
			if m == nil || strings.Contains(s, "mode=sed") {
				continue
			}
			field, re := unq(cmp.Or(m[1], "_raw")), unquote(m[2])
			for _, g := range groupNameRe.FindAllStringSubmatch(re, -1) {
				if field == "_raw" {
					if re == "(?<"+g[1]+">{.+})" {
						vars[g[1]] = place{}
					}
					continue
				}
				vars[g[1]] = resolve(field).then(step{kind: 'r', arg: re, group: g[1]})
			}
			if field != "_raw" && len(groupNameRe.FindAllString(re, -1)) == 0 {
				need(resolve(field), &lit{field: "v", values: []string{re}, re: true})
			}
		case "where", "search":
			test(rest, 0, strings.EqualFold(word, "where"))
		case "lookup":
			// A value of the table for the field it looks up.
			for _, h := range r.lookupHints {
				if q, err := query.Parse("* | " + s); err == nil && len(q.Commands) == 1 {
					if c, ok := q.Commands[0].(*query.Lookup); ok && c.Table == h.lookup.Table.Name && len(c.Keys) == 1 && c.Keys[0].Field() == h.field {
						need(resolve(h.field), &lit{field: "v", values: h.values()})
					}
				}
			}
		case "stats", "eventstats":
			if stats {
				continue
			}
			stats = true
			for _, m := range dcArgRe.FindAllStringSubmatch(s, -1) {
				need(resolve(m[1]), nil)
			}
			if m := statsByRe.FindStringSubmatch(s); m != nil {
				for _, f := range strings.FieldsFunc(m[1], func(c rune) bool { return c == ',' || c == ' ' || c == '\n' || c == '\t' }) {
					if f != "_time" {
						need(resolve(f), nil)
					}
				}
			}
		}
	}
	return sh
}

// A tree is the value a place's steps build: JSON with a value at each
// path, a value split around a separator, or the text rex groups are
// taken from; or a value its tests accept.
type tree struct {
	tests   []lit
	present bool
	json    map[string]*tree
	split   map[string]*tree // by separator and index
	rex     map[string]*tree // by regular expression and group
	// orig is the event's own value, kept when the tests take it, and
	// pieces how many pieces a split of it must have.
	orig   string
	pieces *pieceCount
}

func (t *tree) kid(m *map[string]*tree, k string) *tree {
	if *m == nil {
		*m = map[string]*tree{}
	}
	if (*m)[k] == nil {
		(*m)[k] = &tree{}
	}
	return (*m)[k]
}

// constrained reports whether a tree's value is tested anywhere.
func (t *tree) constrained() bool {
	if len(t.tests) > 0 {
		return true
	}
	for _, m := range []map[string]*tree{t.json, t.split, t.rex} {
		for _, k := range m {
			if k.constrained() {
				return true
			}
		}
	}
	return false
}

// render is a tree's value, with name for a placeholder; change, when
// set, is the tree whose value is changed (a near miss).
func (t *tree) render(name string, change *tree, extra ...lit) string {
	v := t.value(name, change, extra)
	if t == change {
		return mutate(v)
	}
	return v
}

func (t *tree) value(name string, change *tree, extra []lit) string {
	switch {
	case len(t.json) > 0:
		var doc any
		for _, path := range slices.Sorted(maps.Keys(t.json)) {
			doc = setJSON(doc, splitPath(path), t.json[path].render(path, change))
		}
		b, _ := json.Marshal(doc)
		return string(b)
	case len(t.split) > 0 || t.pieces != nil:
		return t.pieced(name, change)
	case len(t.rex) > 0:
		// The event's own value, when it has one, with text each group
		// needs after it (unless the value already gives the group
		// what it needs).
		var parts []string
		if t.orig != "" {
			parts = append(parts, t.orig)
		}
		for _, k := range slices.Sorted(maps.Keys(t.rex)) {
			re, group, _ := strings.Cut(k, "\x00")
			kid := t.rex[k]
			v := ""
			had, _ := placeValue(place{steps: []step{{kind: 'r', arg: re, group: group}}}, func(string) string { return t.orig })
			kid.orig = had
			if kid.constrained() || kid == change {
				// A value the group's own pattern takes too.
				var own []lit
				if start, end := groupSpan(re, group); start >= 0 {
					sub := re[start:end]
					sub = sub[strings.Index(sub, ">")+1 : len(sub)-1]
					flags := ""
					if strings.HasPrefix(re, "(?i)") {
						flags = "(?i)"
					}
					own = append(own, lit{field: "v", values: []string{flags + "^(?:" + sub + ")$"}, re: true})
				}
				v = kid.render(group, change, own...)
			}
			if had != "" && (v == had || v == "") {
				continue
			}
			if ex := rexExample(re, group, v); ex != "" {
				parts = append(parts, ex)
			}
		}
		sep := ", "
		if t.orig != "" {
			sep = " "
		}
		return strings.Join(parts, sep)
	}
	if tests := append(slices.Clone(t.tests), extra...); len(t.tests) > 0 {
		if t.orig != "" && t != change && accepts(tests, t.orig) {
			return t.orig
		}
		if v, ok := satisfy(tests); ok {
			return v
		}
	} else if t.orig != "" {
		return t.orig
	}
	return "test-" + strings.ToLower(lastName(name))
}

// pieced is the value of a tree split into pieces: the event's own
// pieces, or placeholders, as many as its count needs (placeholders
// before the last piece, which is often a file name or a program's
// argument; the last ones dropped first), with the value each index the
// stages read needs.
func (t *tree) pieced(name string, change *tree) string {
	var sep string
	if t.pieces != nil {
		sep = t.pieces.sep
	}
	at := map[int]*tree{}
	var last *tree
	for _, k := range slices.Sorted(maps.Keys(t.split)) {
		s, idx, _ := strings.Cut(k, "\x00")
		if sep == "" {
			sep = s
		}
		if s != sep {
			continue
		}
		if idx == "-1" {
			last = t.split[k]
		} else if n, err := strconv.Atoi(idx); err == nil && n >= 0 && n < maxPieces {
			at[n] = t.split[k]
		}
	}
	var pieces []string
	if t.orig != "" && sep != "" {
		pieces = strings.Split(t.orig, sep)
	}
	n := 2
	for i := range at {
		n = max(n, i+1)
	}
	if t.pieces != nil && (t.pieces.exact || t.pieces.n > n) {
		n = t.pieces.n
	}
	for len(pieces) < n {
		pieces = slices.Insert(pieces, max(len(pieces)-1, 0), "test")
	}
	if t.pieces != nil && t.pieces.exact && len(pieces) > n {
		pieces = append(pieces[:n-1], pieces[len(pieces)-1])
	}
	set := func(i int, kid *tree) {
		kid.orig = pieces[i]
		pieces[i] = kid.render(name, change)
	}
	for _, i := range slices.Sorted(maps.Keys(at)) {
		if i < len(pieces) {
			set(i, at[i])
		}
	}
	if last != nil {
		set(len(pieces)-1, last)
	}
	return strings.Join(pieces, sep)
}

// accepts reports whether every test takes a value.
func accepts(tests []lit, v string) bool {
	for _, l := range tests {
		if l.neg == slices.ContainsFunc(l.values, func(p string) bool { return l.matches(p, v) }) {
			return false
		}
	}
	return true
}

// placeValue is the value of a place in an event (own is a field's
// value): a field's, a piece of it split, or a rex group of it.
func placeValue(p place, own func(string) string) (string, bool) {
	v := own(p.base)
	for _, s := range p.steps {
		if v == "" {
			break
		}
		switch s.kind {
		case 's':
			pieces := strings.Split(v, s.arg)
			i, err := strconv.Atoi(s.group)
			if i < 0 {
				i += len(pieces)
			}
			if err != nil || i < 0 || i >= len(pieces) {
				return "", false
			}
			v = pieces[i]
		case 'r':
			re, err := compiled(s.arg)
			if err != nil {
				return "", false
			}
			m := re.FindStringSubmatch(v)
			if g := re.SubexpIndex(s.group); m == nil || g < 0 {
				return "", false
			} else {
				v = m[g]
			}
		default:
			return "", false
		}
	}
	return v, v != ""
}

// satisfy is a value every test accepts: one written as a test's pattern
// reads (a glob's text with or without what its * stand for, a regular
// expression's text), else one assign makes.
func satisfy(tests []lit) (string, bool) {
	ok := func(c string) bool { return c != "" && accepts(tests, c) }
	var cands []string
	for _, l := range tests {
		if l.neg {
			continue
		}
		p := l.values[0]
		if l.re {
			lit := strings.TrimSuffix(strings.TrimPrefix(strings.TrimPrefix(p, "(?i)"), "^"), "$")
			cands = append(cands, regexp.MustCompile(`\\(.)`).ReplaceAllString(lit, "$1"))
			continue
		}
		cands = append(cands, instantiate(p), strings.ReplaceAll(p, "*", ""), strings.ReplaceAll(p, "*", " "))
	}
	for _, c := range cands {
		if ok(c) {
			return c, true
		}
	}
	if ev, found := assign(tests); found && ok(ev["v"]) {
		return ev["v"], true
	}
	return "", false
}

// groupSpan is where a regular expression's named group is, from its
// ( to its ), or -1.
func groupSpan(pat, group string) (int, int) {
	start := strings.Index(pat, "(?<"+group+">")
	if start < 0 {
		start = strings.Index(pat, "(?P<"+group+">")
	}
	if start < 0 {
		return -1, -1
	}
	depth := 0
	for i := start; i < len(pat); i++ {
		switch pat[i] {
		case '\\':
			i++
		case '[':
			// A class, whose ( and ) are characters (a ] first in it is
			// one too).
			i++
			if i < len(pat) && pat[i] == '^' {
				i++
			}
			if i < len(pat) && pat[i] == ']' {
				i++
			}
			for ; i < len(pat) && pat[i] != ']'; i++ {
				if pat[i] == '\\' {
					i++
				}
			}
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return start, i + 1
			}
		}
	}
	return -1, -1
}

// lastName is the last part of a field's name, without its list marks.
func lastName(s string) string {
	s = regexp.MustCompile(`\{[^}]*\}`).ReplaceAllString(s, "")
	if i := strings.LastIndex(s, "."); i >= 0 {
		s = s[i+1:]
	}
	return cmp.Or(s, "value")
}

// rexExample is text a regular expression matches with the group's
// value, when set, being value.
func rexExample(re, group, value string) string {
	pat := strings.TrimPrefix(re, "(?i)")
	if value != "" {
		if start, end := groupSpan(pat, group); start >= 0 {
			pat = pat[:start] + "(?:" + regexp.QuoteMeta(value) + ")" + pat[end:]
		}
	}
	ex, err := sigmacheck.RegexExample(rand.New(rand.NewSource(1)), pat)
	if err != nil {
		return ""
	}
	return ex
}

// A path part: a name, and whether it is a list with an entry's index.
type pathPart struct {
	name string
	list bool
	idx  string
}

var pathPartRe = regexp.MustCompile(`([^.{}]*)(?:\{([^}]*)\})?`)

// splitPath reads a dotted path with list marks
// (targetResources{0}.modifiedProperties{f1}.newValue).
func splitPath(p string) []pathPart {
	var out []pathPart
	for _, seg := range strings.Split(p, ".") {
		for _, m := range pathPartRe.FindAllStringSubmatchIndex(seg, -1) {
			if m[1] == m[0] {
				continue
			}
			pp := pathPart{name: seg[m[2]:m[3]]}
			if m[4] >= 0 {
				pp.list, pp.idx = true, seg[m[4]:m[5]]
			}
			if pp.list && pp.name != "" {
				out = append(out, pathPart{name: pp.name})
				pp.name = ""
			}
			out = append(out, pp)
		}
	}
	return out
}

// setJSON puts v at a path in a JSON value; an index other than a number
// is the list's first entry.
func setJSON(doc any, path []pathPart, v string) any {
	if len(path) == 0 {
		return v
	}
	p := path[0]
	if p.list {
		l, _ := doc.([]any)
		i, err := strconv.Atoi(p.idx)
		if err != nil || i < 0 || i > 16 {
			i = 0
		}
		for len(l) <= i {
			l = append(l, nil)
		}
		l[i] = setJSON(l[i], path[1:], v)
		return l
	}
	m, _ := doc.(map[string]any)
	if m == nil {
		m = map[string]any{}
	}
	m[p.name] = setJSON(m[p.name], path[1:], v)
	return m
}

// structured are candidate field-level events from what the rule's later
// stages read of an event like ev: matching ones, and near misses with
// one tested value changed.
func (r *Rule) structured(ev map[string]string) (pos, neg []map[string]string) {
	if r.Post == "" {
		return nil, nil
	}
	sh := r.shapeOf()
	if len(sh.places) == 0 {
		return nil, nil
	}
	// What the event already has, as stored.
	stored := map[string]string{}
	for _, c := range r.records(ev) {
		doc, _ := Stored(c)
		maps.Copy(stored, View(doc))
	}
	own := func(base string) string {
		if strings.Contains(base, "{") {
			return ""
		}
		return cmp.Or(ev[base], stored[base])
	}
	// A tie's places get one value: the one a place has, given to the
	// other (to a field rather than a piece of one when both have
	// theirs), or the same placeholder for both.
	for _, t := range sh.ties {
		va, oka := placeValue(t.a, own)
		vb, okb := placeValue(t.b, own)
		var to []place
		v := vb
		if t.rest != nil {
			// b is a's value without rest's at its end.
			vr, okr := placeValue(*t.rest, own)
			if !oka || !okr || !strings.HasSuffix(va, vr) || len(va) == len(vr) {
				continue
			}
			to, v = []place{t.b}, va[:len(va)-len(vr)]
		}
		switch {
		case t.rest != nil:
		case oka && okb && (va == vb || t.fold && strings.EqualFold(va, vb)):
			continue
		case okb && (!oka || len(t.a.steps) == 0):
			to = []place{t.a}
		case oka:
			to, v = []place{t.b}, va
		default:
			to, v = []place{t.a, t.b}, "test-"+strings.ToLower(lastName(t.a.base))
		}
		pat := "^" + regexp.QuoteMeta(v) + "$"
		if t.fold {
			pat = "(?i)" + pat
		}
		for _, p := range to {
			sh.places[p.key()] = p
			sh.tests[p.key()] = append(sh.tests[p.key()], lit{field: "v", values: []string{pat}, re: true})
		}
	}
	roots := map[string]*tree{}
	for _, k := range slices.Sorted(maps.Keys(sh.places)) {
		p := sh.places[k]
		if len(p.steps) == 0 && !strings.Contains(p.base, "{") && len(sh.tests[k]) == 0 && sh.pieces[k] == (pieceCount{}) {
			if p.base == "" || stored[p.base] != "" || ev[p.base] != "" {
				continue // already there
			}
			if _, cim := o365CIM[p.base]; r.Node == O365Node && !cim && !o365Carries(stored["Workload"], p.base) {
				continue // not a field of the record's workload
			}
		}
		if p.base == "" {
			continue
		}
		if roots[p.base] == nil {
			roots[p.base] = &tree{orig: own(p.base)}
		}
		t := roots[p.base]
		for _, s := range p.steps {
			switch s.kind {
			case 'j':
				t = t.kid(&t.json, s.arg)
			case 's':
				t = t.kid(&t.split, s.arg+"\x00"+s.group)
			case 'r':
				t = t.kid(&t.rex, s.arg+"\x00"+s.group)
			}
		}
		t.tests = append(t.tests, sh.tests[k]...)
		t.present = t.present || sh.present[k]
		if pc, ok := sh.pieces[k]; ok {
			t.pieces = &pc
		}
	}
	if len(roots) == 0 {
		return nil, nil
	}
	var leaves []*tree
	var walk func(t *tree)
	walk = func(t *tree) {
		if len(t.tests) > 0 {
			leaves = append(leaves, t)
		}
		for _, m := range []map[string]*tree{t.json, t.split, t.rex} {
			for _, k := range slices.Sorted(maps.Keys(m)) {
				walk(m[k])
			}
		}
	}
	for _, k := range slices.Sorted(maps.Keys(roots)) {
		walk(roots[k])
	}
	build := func(change *tree) map[string]string {
		out := maps.Clone(ev)
		var list []string
		for _, base := range slices.Sorted(maps.Keys(roots)) {
			v := roots[base].render(base, change)
			if !strings.Contains(base, "{") {
				out[base] = v
				continue
			}
			list = append(list, base+"\x00"+v)
		}
		for k, v := range lists(list, sh.finds) {
			out[k] = v
		}
		return out
	}
	pos = append(pos, build(nil))
	for _, l := range leaves {
		neg = append(neg, build(l))
	}
	return pos, neg
}

// lists builds the record's lists from the values at places in them
// (base and value, joined by \x00), each written as JSON under the
// field the list is (ModifiedProperties, properties.targetResources).
// An entry a find picks is one of its own, after those by index; {last}
// is the list's last. The entries in between have a placeholder for each
// field the others have, so every field's values keep their places.
func lists(vals []string, finds []find) map[string]string {
	type entry struct {
		path []pathPart
		v    string
	}
	byRoot := map[string][]entry{}
	for _, s := range vals {
		base, v, _ := strings.Cut(s, "\x00")
		path := splitPath(base)
		i := slices.IndexFunc(path, func(p pathPart) bool { return p.list })
		var names []string
		for _, p := range path[:i] {
			names = append(names, p.name)
		}
		root := strings.Join(names, ".")
		byRoot[root] = append(byRoot[root], entry{path[i:], v})
	}
	out := map[string]string{}
	for root, es := range byRoot {
		var build func(es []entry) any
		build = func(es []entry) any {
			if len(es) == 0 {
				return nil
			}
			if len(es[0].path) == 0 {
				return es[0].v
			}
			if es[0].path[0].list {
				// The entries by index: numbers first, then the
				// finds' own, then the last.
				byIdx := map[string][]entry{}
				for _, e := range es {
					if len(e.path) == 0 || !e.path[0].list {
						continue
					}
					// A list's field read without an index is its first
					// entry's.
					idx := cmp.Or(e.path[0].idx, "0")
					byIdx[idx] = append(byIdx[idx], entry{e.path[1:], e.v})
				}
				n := 0
				for k := range byIdx {
					if i, err := strconv.Atoi(k); err == nil && i < 16 {
						n = max(n, i+1)
					}
				}
				place := map[string]int{}
				for _, k := range slices.Sorted(maps.Keys(byIdx)) {
					if _, err := strconv.Atoi(k); err != nil && k != "last" {
						place[k] = n
						n++
					}
				}
				if _, ok := byIdx["last"]; ok {
					if n == 0 {
						n = 1
					}
					place["last"] = n - 1
				}
				items := make([][]entry, n)
				for k, sub := range byIdx {
					i, err := strconv.Atoi(k)
					if err != nil {
						i = place[k]
					}
					if i >= 0 && i < n {
						items[i] = append(items[i], sub...)
					}
				}
				// Every entry has each field the others have.
				var fields []string
				for _, it := range items {
					for _, e := range it {
						if len(e.path) == 1 && !e.path[0].list && !slices.Contains(fields, e.path[0].name) {
							fields = append(fields, e.path[0].name)
						}
					}
				}
				l := make([]any, n)
				for i, it := range items {
					v := build(it)
					if m, ok := v.(map[string]any); ok || v == nil {
						if m == nil {
							m = map[string]any{}
						}
						for _, f := range fields {
							if _, ok := m[f]; !ok {
								m[f] = fmt.Sprintf("test-%s-%d", strings.ToLower(f), i)
							}
						}
						v = m
					}
					l[i] = v
				}
				return l
			}
			m := map[string]any{}
			byName := map[string][]entry{}
			for _, e := range es {
				if len(e.path) == 0 || e.path[0].list {
					continue
				}
				byName[e.path[0].name] = append(byName[e.path[0].name], entry{e.path[1:], e.v})
			}
			for k, sub := range byName {
				m[k] = build(sub)
			}
			return m
		}
		b, _ := json.Marshal(build(es))
		out[root] = string(b)
	}
	_ = finds
	return out
}

// coalesceArgs are the arguments of a coalesce(), or nil.
func coalesceArgs(expr string) []string {
	body, ok := strings.CutPrefix(expr, "coalesce(")
	if !ok || !strings.HasSuffix(body, ")") {
		return nil
	}
	var out []string
	for _, a := range splitTop(body[:len(body)-1]) {
		out = append(out, strings.TrimSpace(a))
	}
	return out
}

// maxStructured is how many of a rule's first events structured events
// are made from.
const maxStructured = 2
