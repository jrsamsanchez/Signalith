package search

import (
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"net/netip"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jrsamsanchez/signalith/internal/query"
)

// maxEvalValue caps one string that eval builds, so a few chained
// concatenations cannot double a value until the server runs out of memory.
const maxEvalValue = 1 << 20

// maxEvalTotal caps the bytes of values that eval and where expressions
// build in one search, across all rows and commands. Multivalue results
// count every value's bytes, even when they share memory, since writing
// the result out copies each one.
const maxEvalTotal = 256 << 20

// maxMultiValues caps the values of one multivalue field (split, mvappend,
// rex max_match=0).
const maxMultiValues = 10000

// maxCachedRegexes caps the compiled regular expressions one search keeps.
const maxCachedRegexes = 256

// evaluator computes eval expressions over rows. One search uses one
// evaluator for all its commands, so the size budget covers the whole
// search; regular expressions are compiled once and kept.
type evaluator struct {
	ctx      context.Context
	now      time.Time
	regexes  map[string]*regexp.Regexp
	produced int
	steps    int
	err      error
	// eachValues counts the values mvmap and mvfilter went through.
	eachValues int
	// The JSON text the JSON functions decoded last, and its value.
	jsonText string
	jsonDoc  any
	jsonOK   bool
}

func newEvaluator(ctx context.Context) *evaluator {
	return &evaluator{ctx: ctx, now: time.Now()}
}

type evaluatorKey struct{}

// withEvaluator gives the commands of one search a shared evaluator.
func withEvaluator(ctx context.Context) context.Context {
	return context.WithValue(ctx, evaluatorKey{}, newEvaluator(ctx))
}

// evaluatorFor returns the search's evaluator, or a new one when the
// commands run outside a search (as in tests).
func evaluatorFor(ctx context.Context) *evaluator {
	if ctx == nil {
		return newEvaluator(nil)
	}
	if ev, ok := ctx.Value(evaluatorKey{}).(*evaluator); ok {
		return ev
	}
	return newEvaluator(ctx)
}

// checkSteps is how often, in expression steps and list values, the
// evaluator checks whether the search has been cancelled or timed out.
const checkSteps = 256

// maxEvalSteps caps the expression steps of one search, so work that
// multiplies (foreach over many fields, nested mvmap) ends in seconds
// rather than at the search timeout. A search over 100,000 events with
// 20 assignments of 100 steps each takes 200 million.
var maxEvalSteps = 500_000_000 // a variable so tests can lower it

// stepN counts n steps of work at once, checking the step budget and
// the search's context as step does.
func (ev *evaluator) stepN(n int) bool {
	if ev.err != nil {
		return false
	}
	ev.steps += n
	if ev.steps > maxEvalSteps {
		ev.fail("the search evaluated more than %d million expressions; narrow the search first", maxEvalSteps/1_000_000)
		return false
	}
	if ev.ctx != nil {
		if err := ev.ctx.Err(); err != nil {
			ev.err = err
			return false
		}
	}
	return true
}

// step counts work and stops the evaluation once the search's context
// ends, so a few expensive rows cannot outlive the search timeout.
func (ev *evaluator) step() bool {
	if ev.err != nil {
		return false
	}
	if ev.steps++; ev.steps%checkSteps == 0 {
		if ev.steps > maxEvalSteps {
			ev.fail("the search evaluated more than %d million expressions; narrow the search first", maxEvalSteps/1_000_000)
			return false
		}
		if ev.ctx == nil {
			return true
		}
		if err := ev.ctx.Err(); err != nil {
			ev.err = err
			return false
		}
	}
	return true
}

// safeEval evaluates e for one row. A bug in a function fails the search
// with an error instead of crashing the server.
func (ev *evaluator) safeEval(e query.EvalExpr, r Row) (v any) {
	defer func() {
		if p := recover(); p != nil {
			v = ev.fail("an expression failed: %v", p)
		}
	}()
	return ev.eval(e, r)
}

func (ev *evaluator) fail(format string, args ...any) any {
	if ev.err == nil {
		ev.err = &QueryError{Msg: fmt.Sprintf(format, args...)}
	}
	return nil
}

// regex compiles a pattern once per search. A pattern that does not
// compile fails the search.
func (ev *evaluator) regex(pattern string) *regexp.Regexp {
	if re, ok := ev.regexes[pattern]; ok {
		return re
	}
	if len(pattern) > maxPatternLen {
		ev.fail("a regular expression is %d characters long; the limit is %d", len(pattern), maxPatternLen)
		return nil
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		ev.fail("regular expression %q: %v", pattern, err)
		return nil
	}
	// Patterns usually come from the query, but can come from event
	// values; keep only so many.
	if ev.regexes == nil || len(ev.regexes) >= maxCachedRegexes {
		ev.regexes = map[string]*regexp.Regexp{}
	}
	ev.regexes[pattern] = re
	return re
}

// str returns a new string after checking it against the size limits.
func (ev *evaluator) str(s string) any {
	if !ev.fits(len(s)) || !ev.charge(len(s)) {
		return nil
	}
	return s
}

// fits reports whether a value of n bytes is small enough to build. Check
// it before building a value whose size is known in advance.
func (ev *evaluator) fits(n int) bool {
	if n > maxEvalValue {
		ev.fail("a computed value is longer than %d MB; eval cannot build values that large", maxEvalValue>>20)
		return false
	}
	return true
}

// charge counts n bytes against the search's budget.
func (ev *evaluator) charge(n int) bool {
	if ev.produced += n; ev.produced > maxEvalTotal {
		ev.fail("eval built more than %d MB of values; narrow the search first", maxEvalTotal>>20)
		return false
	}
	return true
}

// fieldOverhead is what the budget counts for a field a command adds to
// a row, besides its name and value: the row map's entry and its growth.
const fieldOverhead = 64

// newField charges for adding name to r, when r does not have it yet.
func (ev *evaluator) newField(r Row, name string) bool {
	if _, ok := r[name]; ok {
		return true
	}
	return ev.charge(len(name) + fieldOverhead)
}

// maxEachValues caps the values mvmap and mvfilter go through in one
// search, so nesting them over different multivalue fields cannot
// multiply into work that only the deadline stops.
const maxEachValues = 10_000_000

// eachValue calls f for each value of r's field name, with the field set
// to that one value while f runs, and gives the values f keeps.
func (ev *evaluator) eachValue(r Row, name string, f func(v any) (any, bool)) any {
	orig, had := r[name]
	if orig == nil {
		return nil
	}
	defer func() {
		if had {
			r[name] = orig
		} else {
			delete(r, name)
		}
	}()
	vals := asList(orig)
	if ev.eachValues += len(vals); ev.eachValues > maxEachValues {
		return ev.fail("mvmap and mvfilter went through more than %d million values; narrow the search first", maxEachValues/1_000_000)
	}
	var out []any
	for _, v := range vals {
		if !ev.step() {
			return nil
		}
		r[name] = v
		if x, keep := f(v); keep {
			out = append(out, x)
		}
		if ev.err != nil {
			return nil
		}
	}
	return ev.list(out)
}

// evalFields adds the names of the fields e reads to names.
func evalFields(e query.EvalExpr, names map[string]bool) {
	switch e := e.(type) {
	case *query.Field:
		names[e.Name] = true
	case *query.Call:
		for _, a := range e.Args {
			evalFields(a, names)
		}
	case *query.Unary:
		evalFields(e.X, names)
	case *query.Binary:
		evalFields(e.L, names)
		evalFields(e.R, names)
	}
}

// list returns a new multivalue result after checking its count and its
// bytes against the limits.
func (ev *evaluator) list(vs []any) any {
	if len(vs) > maxMultiValues {
		return ev.fail("a multivalue field would hold %d values; the limit is %d", len(vs), maxMultiValues)
	}
	n := 0
	for _, v := range vs {
		n += valueSize(v) + 1
	}
	if !ev.fits(n) || !ev.charge(n) {
		return nil
	}
	return mvOut(vs)
}

// valueSize is about how many bytes v takes once written out as text.
func valueSize(v any) int {
	switch x := v.(type) {
	case string:
		return len(x)
	case []any:
		n := 0
		for _, e := range x {
			n += valueSize(e) + 1
		}
		return n
	case nil:
		return 0
	}
	return 8
}

func mvOut(vs []any) any {
	switch len(vs) {
	case 0:
		return nil
	case 1:
		return vs[0]
	}
	return vs
}

func asList(v any) []any {
	switch x := v.(type) {
	case nil:
		return nil
	case []any:
		return x
	}
	return []any{v}
}

// evNum reads a value as a number: numbers, and strings that hold one.
func evNum(v any) (float64, bool) {
	switch n := v.(type) {
	case []any:
		if len(n) == 1 {
			return evNum(n[0])
		}
		return 0, false
	case bool:
		return 0, false
	}
	return asFloat(v)
}

// evStr reads a value as text. A multivalue field reads as its values on
// separate lines.
func evStr(v any) (string, bool) {
	switch x := v.(type) {
	case nil:
		return "", false
	case string:
		return x, true
	case int64:
		return strconv.FormatInt(x, 10), true
	case int:
		return strconv.Itoa(x), true
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64), true
	case bool:
		return strconv.FormatBool(x), true
	case []any:
		parts := make([]string, 0, len(x))
		for _, e := range x {
			if s, ok := evStr(e); ok {
				parts = append(parts, s)
			}
		}
		return strings.Join(parts, "\n"), true
	}
	return fmt.Sprint(v), true
}

func numOut(f float64) any {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return nil
	}
	return toNumber(f)
}

// truth reads a value as a condition.
func truth(v any) bool {
	switch x := v.(type) {
	case nil:
		return false
	case bool:
		return x
	case string:
		if f, ok := asFloat(x); ok {
			return f != 0
		}
		return x != "" && !strings.EqualFold(x, "false")
	case []any:
		return len(x) > 0
	}
	if f, ok := evNum(v); ok {
		return f != 0
	}
	return true
}

// evCompare orders two values: numerically when both are numbers, else
// as case-sensitive text.
func evCompare(a, b any) int {
	if fa, ok := evNum(a); ok {
		if fb, ok := evNum(b); ok {
			switch {
			case fa < fb:
				return -1
			case fa > fb:
				return 1
			}
			return 0
		}
	}
	sa, _ := evStr(a)
	sb, _ := evStr(b)
	return strings.Compare(sa, sb)
}

func (ev *evaluator) eval(e query.EvalExpr, r Row) any {
	if !ev.step() {
		return nil
	}
	switch e := e.(type) {
	case *query.Num:
		if i, err := strconv.ParseInt(e.Text, 10, 64); err == nil {
			return i
		}
		f, err := strconv.ParseFloat(e.Text, 64)
		if err != nil {
			return nil
		}
		return numOut(f)
	case *query.Str:
		return e.Value
	case *query.Field:
		if e.Name == "_time" {
			return timeNumber(r[e.Name])
		}
		return r[e.Name]
	case *query.Unary:
		v := ev.eval(e.X, r)
		if v == nil {
			return nil
		}
		if e.Op == "NOT" {
			return !truth(v)
		}
		f, ok := evNum(v)
		if !ok {
			return nil
		}
		return numOut(-f)
	case *query.Binary:
		return ev.binary(e, r)
	case *query.Call:
		return ev.call(e, r)
	}
	return nil
}

func (ev *evaluator) binary(e *query.Binary, r Row) any {
	switch e.Op {
	case "AND":
		return truth(ev.eval(e.L, r)) && truth(ev.eval(e.R, r))
	case "OR":
		return truth(ev.eval(e.L, r)) || truth(ev.eval(e.R, r))
	case "XOR":
		return truth(ev.eval(e.L, r)) != truth(ev.eval(e.R, r))
	}
	l, rv := ev.eval(e.L, r), ev.eval(e.R, r)
	if l == nil || rv == nil {
		return nil
	}
	switch e.Op {
	case "=", "!=":
		eq := false
		for _, x := range asList(l) {
			if evCompare(x, rv) == 0 {
				eq = true
				break
			}
		}
		return eq == (e.Op == "=")
	case "<", "<=", ">", ">=":
		c := evCompare(l, rv)
		switch e.Op {
		case "<":
			return c < 0
		case "<=":
			return c <= 0
		case ">":
			return c > 0
		}
		return c >= 0
	case "LIKE":
		return ev.like(l, rv)
	case ".":
		ls, _ := evStr(l)
		rs, _ := evStr(rv)
		if !ev.fits(len(ls) + len(rs)) {
			return nil
		}
		return ev.str(ls + rs)
	}
	fl, okl := evNum(l)
	fr, okr := evNum(rv)
	if !okl || !okr {
		if e.Op == "+" {
			ls, lok := l.(string)
			rs, rok := rv.(string)
			if lok && rok && ev.fits(len(ls)+len(rs)) {
				return ev.str(ls + rs)
			}
		}
		return nil
	}
	switch e.Op {
	case "+":
		return numOut(fl + fr)
	case "-":
		return numOut(fl - fr)
	case "*":
		return numOut(fl * fr)
	case "/":
		if fr == 0 {
			return nil
		}
		return numOut(fl / fr)
	case "%":
		if fr == 0 {
			return nil
		}
		return numOut(math.Mod(fl, fr))
	}
	return nil
}

// like matches SQL LIKE patterns: % is any run of characters and _ any
// one character. It is case-sensitive.
func (ev *evaluator) like(v, pattern any) bool {
	p, ok := evStr(pattern)
	if !ok {
		return false
	}
	var b strings.Builder
	b.WriteString(`(?s)\A`)
	for _, r := range p {
		switch r {
		case '%':
			b.WriteString(".*")
		case '_':
			b.WriteString(".")
		default:
			b.WriteString(regexp.QuoteMeta(string(r)))
		}
	}
	b.WriteString(`\z`)
	re := ev.regex(b.String())
	if re == nil {
		return false
	}
	for _, x := range asList(v) {
		if !ev.step() {
			return false
		}
		if s, ok := evStr(x); ok && re.MatchString(s) {
			return true
		}
	}
	return false
}

func (ev *evaluator) call(c *query.Call, r Row) any {
	// The conditional functions evaluate only the arguments they need.
	switch c.Func {
	case "if":
		if truth(ev.eval(c.Args[0], r)) {
			return ev.eval(c.Args[1], r)
		}
		return ev.eval(c.Args[2], r)
	case "case":
		for i := 0; i+1 < len(c.Args); i += 2 {
			if truth(ev.eval(c.Args[i], r)) {
				return ev.eval(c.Args[i+1], r)
			}
		}
		return nil
	case "coalesce":
		for _, a := range c.Args {
			if v := ev.eval(a, r); v != nil {
				return v
			}
		}
		return nil
	case "mvfilter":
		names := map[string]bool{}
		evalFields(c.Args[0], names)
		if len(names) != 1 {
			return ev.fail("mvfilter's expression must use exactly one field, like mvfilter(match(email, \"@corp$\"))")
		}
		var name string
		for n := range names {
			name = n
		}
		return ev.eachValue(r, name, func(v any) (any, bool) {
			keep := truth(ev.eval(c.Args[0], r))
			return v, keep
		})
	case "mvmap":
		f, ok := c.Args[0].(*query.Field)
		if !ok {
			return ev.fail("mvmap's first argument must be a field, like mvmap(sizes, sizes*2)")
		}
		return ev.eachValue(r, f.Name, func(any) (any, bool) {
			out := ev.eval(c.Args[1], r)
			return out, out != nil
		})
	}
	args := make([]any, len(c.Args))
	for i, a := range c.Args {
		args[i] = ev.eval(a, r)
	}
	if ev.err != nil {
		return nil
	}
	arg := func(i int) any {
		if i < len(args) {
			return args[i]
		}
		return nil
	}
	num := func(i int) (float64, bool) { return evNum(arg(i)) }
	math1 := func(f func(float64) float64) any {
		x, ok := num(0)
		if !ok {
			return nil
		}
		return numOut(f(x))
	}
	text := func(i int) (string, bool) { return evStr(arg(i)) }

	switch c.Func {
	case "abs":
		return math1(math.Abs)
	case "ceil", "ceiling":
		return math1(math.Ceil)
	case "floor":
		return math1(math.Floor)
	case "sqrt":
		return math1(math.Sqrt)
	case "exp":
		return math1(math.Exp)
	case "ln":
		return math1(math.Log)
	case "log":
		x, ok := num(0)
		if !ok {
			return nil
		}
		base := 10.0
		if len(args) > 1 {
			if base, ok = num(1); !ok {
				return nil
			}
		}
		switch base {
		case 10:
			return numOut(math.Log10(x))
		case 2:
			return numOut(math.Log2(x))
		}
		return numOut(math.Log(x) / math.Log(base))
	case "pow":
		x, ok1 := num(0)
		y, ok2 := num(1)
		if !ok1 || !ok2 {
			return nil
		}
		return numOut(math.Pow(x, y))
	case "round":
		x, ok := num(0)
		if !ok {
			return nil
		}
		digits := 0.0
		if len(args) > 1 {
			if digits, ok = num(1); !ok {
				return nil
			}
		}
		p := math.Pow(10, math.Trunc(digits))
		return numOut(math.Round(x*p) / p)
	case "min", "max":
		var vals []any
		for _, a := range args {
			for _, v := range asList(a) {
				if v != nil {
					vals = append(vals, v)
				}
			}
		}
		if len(vals) == 0 {
			return nil
		}
		best := vals[0]
		for _, v := range vals[1:] {
			cmp := evCompare(v, best)
			if cmp < 0 && c.Func == "min" || cmp > 0 && c.Func == "max" {
				best = v
			}
		}
		return best
	case "len":
		s, ok := text(0)
		if !ok {
			return nil
		}
		return int64(utf8.RuneCountInString(s))
	case "lower", "upper":
		s, ok := text(0)
		if !ok {
			return nil
		}
		if c.Func == "lower" {
			return ev.str(strings.ToLower(s))
		}
		return ev.str(strings.ToUpper(s))
	case "trim", "ltrim", "rtrim":
		s, ok := text(0)
		if !ok {
			return nil
		}
		cut := " \t"
		if len(args) > 1 {
			if cut, ok = text(1); !ok {
				return nil
			}
		}
		switch c.Func {
		case "ltrim":
			return strings.TrimLeft(s, cut)
		case "rtrim":
			return strings.TrimRight(s, cut)
		}
		return strings.Trim(s, cut)
	case "substr":
		s, ok := text(0)
		start, ok2 := num(1)
		if !ok || !ok2 || !finite(start) {
			return nil
		}
		rs := []rune(s)
		n := len(rs)
		// Clamp before converting, so a huge start cannot overflow.
		start = math.Max(-float64(n)-1, math.Min(start, float64(n)+1))
		i := int(start) - 1
		if start < 0 {
			i = n + int(start)
		} else if start == 0 {
			i = 0
		}
		i = max(0, min(i, n))
		j := n
		if len(args) > 2 {
			l, ok := num(2)
			if !ok || !finite(l) {
				return nil
			}
			if l < 0 {
				return ""
			}
			j = min(n, i+int(min(l, float64(n))))
		}
		return string(rs[i:j])
	case "replace":
		s, ok := text(0)
		pat, ok2 := text(1)
		repl, ok3 := text(2)
		if !ok || !ok2 || !ok3 {
			return nil
		}
		re := ev.regex(pat)
		if re == nil {
			return nil
		}
		return ev.replace(re, s, goReplacement(repl))
	case "split":
		s, ok := text(0)
		sep, ok2 := text(1)
		if !ok || !ok2 {
			return nil
		}
		if strings.Count(s, sep) >= maxMultiValues || sep == "" && utf8.RuneCountInString(s) > maxMultiValues {
			return ev.fail("split would make more than %d values", maxMultiValues)
		}
		parts := strings.Split(s, sep)
		out := make([]any, len(parts))
		for i, p := range parts {
			out[i] = p
		}
		return ev.list(out)
	case "mvcount":
		if args[0] == nil {
			return nil
		}
		return int64(len(asList(args[0])))
	case "mvindex":
		l := asList(args[0])
		n := len(l)
		at := func(i int) (int, bool) {
			f, ok := num(i)
			if !ok || !finite(f) || math.Abs(f) > float64(n)+1 {
				return 0, false
			}
			k := int(f)
			if k < 0 {
				k += n
			}
			return k, k >= 0 && k < n
		}
		s, ok := at(1)
		if !ok {
			return nil
		}
		e := s
		if len(args) > 2 {
			if e, ok = at(2); !ok || e < s {
				return nil
			}
		}
		return mvOut(append([]any(nil), l[s:e+1]...))
	case "mvjoin":
		sep, ok := text(1)
		if !ok || args[0] == nil {
			return nil
		}
		parts := make([]string, 0)
		size := 0
		for _, v := range asList(args[0]) {
			if s, ok := evStr(v); ok {
				parts = append(parts, s)
				size += len(s) + len(sep)
			}
			if !ev.fits(size) {
				return nil
			}
		}
		return ev.str(strings.Join(parts, sep))
	case "mvappend":
		var out []any
		for _, a := range args {
			out = append(out, asList(a)...)
			if len(out) > maxMultiValues {
				break
			}
		}
		return ev.list(out)
	case "mvfind":
		pat, ok := text(1)
		if !ok || args[0] == nil {
			return nil
		}
		re := ev.regex(pat)
		if re == nil {
			return nil
		}
		for i, v := range asList(args[0]) {
			if !ev.step() {
				return nil
			}
			if s, ok := evStr(v); ok && re.MatchString(s) {
				return int64(i)
			}
		}
		return nil
	case "mvzip":
		if args[0] == nil || args[1] == nil {
			return nil
		}
		sep := ","
		if len(args) > 2 {
			s, ok := text(2)
			if !ok {
				return nil
			}
			sep = s
		}
		a, b := asList(args[0]), asList(args[1])
		n := min(len(a), len(b))
		out := make([]any, 0, n)
		size := 0
		for i := 0; i < n; i++ {
			x, _ := evStr(a[i])
			y, _ := evStr(b[i])
			if size += len(x) + len(sep) + len(y); !ev.fits(size) {
				return nil
			}
			out = append(out, x+sep+y)
		}
		return ev.list(out)
	case "mvdedup":
		seen := map[string]bool{}
		var out []any
		for _, v := range asList(args[0]) {
			if !ev.step() {
				return nil
			}
			k, _ := evStr(v)
			if !seen[k] {
				seen[k] = true
				out = append(out, v)
			}
		}
		return mvOut(out)
	case "mvsort":
		out := append([]any(nil), asList(args[0])...)
		sort.SliceStable(out, func(i, j int) bool {
			a, _ := evStr(out[i])
			b, _ := evStr(out[j])
			return a < b
		})
		return mvOut(out)
	case "match":
		pat, ok := text(1)
		if !ok || args[0] == nil {
			return false
		}
		re := ev.regex(pat)
		if re == nil {
			return false
		}
		for _, v := range asList(args[0]) {
			if !ev.step() {
				return false
			}
			if s, ok := evStr(v); ok && re.MatchString(s) {
				return true
			}
		}
		return false
	case "like":
		if args[0] == nil {
			return false
		}
		return ev.like(args[0], args[1])
	case "cidrmatch":
		cidr, ok := text(0)
		if !ok {
			return false
		}
		p, err := netip.ParsePrefix(strings.TrimSpace(cidr))
		if err != nil {
			return false
		}
		p = p.Masked()
		for _, v := range asList(args[1]) {
			if !ev.step() {
				return false
			}
			s, _ := evStr(v)
			if a, err := netip.ParseAddr(strings.TrimSpace(s)); err == nil && p.Contains(a.Unmap()) {
				return true
			}
		}
		return false
	case "in":
		if args[0] == nil {
			return false
		}
		for _, x := range asList(args[0]) {
			if !ev.step() {
				return false
			}
			for _, v := range args[1:] {
				if v != nil && evCompare(x, v) == 0 {
					return true
				}
			}
		}
		return false
	case "isnull":
		return args[0] == nil
	case "isnotnull":
		return args[0] != nil
	case "isnum":
		switch args[0].(type) {
		case int64, int, float64:
			return true
		}
		return false
	case "isstr":
		_, ok := args[0].(string)
		return ok
	case "typeof":
		switch args[0].(type) {
		case nil:
			return "Invalid"
		case int64, int, float64:
			return "Number"
		case string:
			return "String"
		case bool:
			return "Boolean"
		case []any:
			return "Multivalue"
		}
		return "Invalid"
	case "null":
		return nil
	case "nullif":
		if args[0] != nil && args[1] != nil && evCompare(args[0], args[1]) == 0 {
			return nil
		}
		return args[0]
	case "true":
		return true
	case "false":
		return false
	case "tonumber":
		s, ok := text(0)
		if !ok {
			return nil
		}
		s = strings.TrimSpace(s)
		if len(args) > 1 {
			base, ok := num(1)
			if !ok || base < 2 || base > 36 || base != math.Trunc(base) {
				return nil
			}
			if base == 16 {
				s = strings.TrimPrefix(strings.TrimPrefix(s, "0x"), "0X")
			}
			n, err := strconv.ParseInt(s, int(base), 64)
			if err != nil {
				return nil
			}
			return n
		}
		f, ok := asFloat(s)
		if !ok {
			return nil
		}
		return numOut(f)
	case "tostring":
		if args[0] == nil {
			return nil
		}
		if len(args) < 2 {
			s, _ := evStr(args[0])
			return s
		}
		format, _ := text(1)
		f, ok := num(0)
		if !ok {
			s, _ := evStr(args[0])
			return s
		}
		switch strings.ToLower(format) {
		case "hex":
			return fmt.Sprintf("0x%X", int64(f))
		case "commas":
			return withCommas(f)
		case "duration":
			return duration(f)
		}
		s, _ := evStr(args[0])
		return s
	case "urldecode":
		s, ok := text(0)
		if !ok {
			return nil
		}
		if d, err := url.QueryUnescape(s); err == nil {
			return d
		}
		return s
	case "md5", "sha1", "sha256":
		s, ok := text(0)
		if !ok {
			return nil
		}
		switch c.Func {
		case "md5":
			h := md5.Sum([]byte(s))
			return hex.EncodeToString(h[:])
		case "sha1":
			h := sha1.Sum([]byte(s))
			return hex.EncodeToString(h[:])
		}
		h := sha256.Sum256([]byte(s))
		return hex.EncodeToString(h[:])
	case "now":
		return ev.now.Unix()
	case "time":
		return numOut(float64(ev.now.UnixMicro()) / 1e6)
	case "strftime":
		t, ok := toTime(arg(0))
		format, ok2 := text(1)
		if !ok || !ok2 {
			return nil
		}
		return ev.str(strftime(t, format))
	case "strptime":
		s, ok := text(0)
		format, ok2 := text(1)
		if !ok || !ok2 {
			return nil
		}
		t, ok := strptime(s, format)
		if !ok {
			return nil
		}
		return numOut(float64(t.UnixNano()) / 1e9)
	}
	if v, ok := ev.callMore(c.Func, args); ok {
		return v
	}
	return ev.fail("function %s() is not supported here", c.Func)
}

// goReplacement turns replace()'s \1 back-references into Go's ${1}, and
// keeps every other character as typed.
func goReplacement(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		switch {
		case s[i] == '\\' && i+1 < len(s) && s[i+1] >= '0' && s[i+1] <= '9':
			b.WriteString("${" + string(s[i+1]) + "}")
			i++
		case s[i] == '$':
			b.WriteString("$$")
		default:
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

// replace is regexp's ReplaceAllString with the size limit checked as
// the result grows, so a pattern that matches everywhere (such as "")
// cannot build a huge string before the check.
func (ev *evaluator) replace(re *regexp.Regexp, s, template string) any {
	return ev.replaceNth(re, s, template, 0)
}

// replaceNth is replace for only the nth match when nth > 0.
func (ev *evaluator) replaceNth(re *regexp.Regexp, s, template string, nth int) any {
	refs := strings.Count(template, "${")
	var out []byte
	last := 0
	limit := -1
	if nth > 0 {
		limit = nth
	}
	for i, m := range re.FindAllStringSubmatchIndex(s, limit) {
		if !ev.step() {
			return nil
		}
		if nth > 0 && i != nth-1 {
			continue
		}
		// A group's text lies within its match.
		if !ev.fits(len(out) + m[0] - last + len(template) + refs*(m[1]-m[0])) {
			return nil
		}
		out = append(out, s[last:m[0]]...)
		out = re.ExpandString(out, template, s, m)
		last = m[1]
	}
	if !ev.fits(len(out) + len(s) - last) {
		return nil
	}
	out = append(out, s[last:]...)
	return ev.str(string(out))
}

func finite(f float64) bool { return !math.IsNaN(f) && !math.IsInf(f, 0) }

func withCommas(f float64) string {
	s := strconv.FormatFloat(math.Abs(f), 'f', -1, 64)
	if f != math.Trunc(f) {
		s = strconv.FormatFloat(math.Abs(f), 'f', 2, 64)
	}
	whole, frac, _ := strings.Cut(s, ".")
	var b strings.Builder
	if f < 0 {
		b.WriteByte('-')
	}
	for i, c := range whole {
		if i > 0 && (len(whole)-i)%3 == 0 {
			b.WriteByte(',')
		}
		b.WriteRune(c)
	}
	if frac != "" {
		b.WriteString("." + frac)
	}
	return b.String()
}

func duration(f float64) string {
	sec := int64(f)
	neg := sec < 0
	if neg {
		sec = -sec
	}
	d, h, m, s := sec/86400, sec%86400/3600, sec%3600/60, sec%60
	out := fmt.Sprintf("%02d:%02d:%02d", h, m, s)
	if d > 0 {
		out = fmt.Sprintf("%d+%s", d, out)
	}
	if neg {
		out = "-" + out
	}
	return out
}

// toTime reads a time: epoch seconds, or text as stored in events
// (RFC 3339).
func toTime(v any) (time.Time, bool) {
	if f, ok := evNum(v); ok {
		if math.IsNaN(f) || math.Abs(f) > 1e12 {
			return time.Time{}, false
		}
		// To the microsecond: a float64 of epoch seconds holds no finer
		// time, and 0.123 must not read back as 0.122999.
		sec, frac := math.Modf(f)
		return time.Unix(int64(sec), int64(math.Round(frac*1e6))*1e3).UTC(), true
	}
	s, ok := evStr(v)
	if !ok {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(s))
	if err != nil {
		return time.Time{}, false
	}
	return t.UTC(), true
}

// timeNumber is _time as expressions see it: epoch seconds, as in Splunk,
// though rows carry it as RFC 3339 text. Other values pass through.
func timeNumber(v any) any {
	s, ok := v.(string)
	if !ok {
		return v
	}
	t, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(s))
	if err != nil {
		return v
	}
	return numOut(float64(t.Unix()) + float64(t.Nanosecond())/1e9)
}

// strftime formats t (in UTC) with the usual % conversions.
func strftime(t time.Time, format string) string {
	var b strings.Builder
	for i := 0; i < len(format); i++ {
		if format[i] != '%' || i+1 >= len(format) {
			b.WriteByte(format[i])
			continue
		}
		i++
		c := format[i]
		if c >= '1' && c <= '9' && i+1 < len(format) && format[i+1] == 'N' {
			ns := fmt.Sprintf("%09d", t.Nanosecond())
			b.WriteString(ns[:c-'0'])
			i++
			continue
		}
		switch c {
		case 'Y':
			b.WriteString(fmt.Sprintf("%04d", t.Year()))
		case 'y':
			b.WriteString(fmt.Sprintf("%02d", t.Year()%100))
		case 'm':
			b.WriteString(fmt.Sprintf("%02d", int(t.Month())))
		case 'd':
			b.WriteString(fmt.Sprintf("%02d", t.Day()))
		case 'e':
			b.WriteString(fmt.Sprintf("%2d", t.Day()))
		case 'H':
			b.WriteString(fmt.Sprintf("%02d", t.Hour()))
		case 'I':
			h := t.Hour() % 12
			if h == 0 {
				h = 12
			}
			b.WriteString(fmt.Sprintf("%02d", h))
		case 'M':
			b.WriteString(fmt.Sprintf("%02d", t.Minute()))
		case 'S':
			b.WriteString(fmt.Sprintf("%02d", t.Second()))
		case 'N':
			b.WriteString(fmt.Sprintf("%09d", t.Nanosecond()))
		case 'p':
			b.WriteString(t.Format("PM"))
		case 'b', 'h':
			b.WriteString(t.Format("Jan"))
		case 'B':
			b.WriteString(t.Format("January"))
		case 'a':
			b.WriteString(t.Format("Mon"))
		case 'A':
			b.WriteString(t.Format("Monday"))
		case 'j':
			b.WriteString(fmt.Sprintf("%03d", t.YearDay()))
		case 'Z':
			b.WriteString("UTC")
		case 'z':
			b.WriteString("+0000")
		case 's':
			b.WriteString(strconv.FormatInt(t.Unix(), 10))
		case 'T':
			b.WriteString(t.Format("15:04:05"))
		case 'F':
			b.WriteString(t.Format("2006-01-02"))
		case 'D':
			b.WriteString(t.Format("01/02/06"))
		case 'u':
			wd := int(t.Weekday())
			if wd == 0 {
				wd = 7
			}
			b.WriteString(strconv.Itoa(wd))
		case 'w':
			b.WriteString(strconv.Itoa(int(t.Weekday())))
		case '%':
			b.WriteByte('%')
		default:
			b.WriteByte('%')
			b.WriteByte(c)
		}
	}
	return b.String()
}

// strptime parses s with a % format, in UTC unless the format reads a zone.
func strptime(s, format string) (time.Time, bool) {
	if strings.TrimSpace(format) == "%s" {
		f, ok := asFloat(s)
		if !ok {
			return time.Time{}, false
		}
		return toTime(f)
	}
	var layout strings.Builder
	for i := 0; i < len(format); i++ {
		if format[i] != '%' || i+1 >= len(format) {
			layout.WriteByte(format[i])
			continue
		}
		i++
		c := format[i]
		if c >= '1' && c <= '9' && i+1 < len(format) && format[i+1] == 'N' {
			layout.WriteString(strings.Repeat("0", int(c-'0')))
			i++
			continue
		}
		parts := map[byte]string{
			'Y': "2006", 'y': "06", 'm': "01", 'd': "02", 'e': "_2", 'H': "15", 'I': "03", 'M': "04",
			'S': "05", 'p': "PM", 'b': "Jan", 'h': "Jan", 'B': "January", 'a': "Mon", 'A': "Monday",
			'j': "002", 'z': "-0700", 'Z': "MST", 'T': "15:04:05", 'F': "2006-01-02", 'D': "01/02/06",
			'N': "000000000", '%': "%",
		}
		p, ok := parts[c]
		if !ok {
			return time.Time{}, false
		}
		layout.WriteString(p)
	}
	t, err := time.Parse(layout.String(), strings.TrimSpace(s))
	if err != nil {
		return time.Time{}, false
	}
	return t.UTC(), true
}

// ---- commands ----

func addColumn(res *Result, name string) {
	for _, c := range res.Columns {
		if c == name {
			return
		}
	}
	if n := len(res.Columns); res.Kind == "events" && n > 0 && res.Columns[n-1] == RawField {
		res.Columns = append(res.Columns[:n-1], name, RawField)
		return
	}
	res.Columns = append(res.Columns, name)
}

func applyEval(ctx context.Context, res *Result, c *query.Eval) error {
	ev := evaluatorFor(ctx)
	for i, r := range res.Rows {
		if i%checkEvery == 0 && ctx.Err() != nil {
			return ctx.Err()
		}
		// Each assignment sees the ones before it, as in SPL.
		for _, a := range c.Assigns {
			before := ev.produced
			v := ev.safeEval(a.Expr, r)
			// A value the expression passed on rather than built (c=b,
			// if(x, b, b)) is charged too: each copy is written out in
			// full with the result.
			if extra := valueSize(v) - (ev.produced - before); extra > 0 && ev.err == nil {
				ev.charge(extra)
			}
			if ev.err != nil {
				return ev.err
			}
			if v == nil {
				delete(r, a.Field)
			} else {
				if !ev.newField(r, a.Field) {
					return ev.err
				}
				r[a.Field] = v
			}
		}
	}
	for _, a := range c.Assigns {
		addColumn(res, a.Field)
	}
	return nil
}

func applyRex(ctx context.Context, res *Result, c *query.Rex) error {
	if c.Sed != "" {
		return applySed(ctx, res, c)
	}
	ev := evaluatorFor(ctx)
	re, err := regexp.Compile(c.Pattern)
	if err != nil {
		return &QueryError{Msg: fmt.Sprintf("rex pattern: %v", err)}
	}
	names := re.SubexpNames()
	limit := c.MaxMatch
	if limit <= 0 || limit > maxMultiValues {
		limit = maxMultiValues
	}
	for i, r := range res.Rows {
		if i%checkEvery == 0 && ctx.Err() != nil {
			return ctx.Err()
		}
		s, ok := evStr(r[c.Field])
		if !ok {
			continue
		}
		matches := re.FindAllStringSubmatchIndex(s, limit)
		if len(matches) == 0 {
			continue
		}
		for g, name := range names {
			if name == "" {
				continue
			}
			var vals []any
			for _, m := range matches {
				if m[2*g] >= 0 {
					vals = append(vals, s[m[2*g]:m[2*g+1]])
				}
			}
			if len(vals) == 0 {
				continue
			}
			if !ev.newField(r, name) {
				return ev.err
			}
			if c.MaxMatch == 1 {
				r[name] = vals[0]
			} else {
				r[name] = mvOut(vals)
			}
		}
	}
	for _, name := range names {
		if name != "" {
			addColumn(res, name)
		}
	}
	return nil
}

func applyDedup(ctx context.Context, res *Result, c *query.Dedup) error {
	seen := map[string]int{}
	prev, run := "", 0
	out := res.Rows[:0:0]
	for i, r := range res.Rows {
		if i%checkEvery == 0 && ctx.Err() != nil {
			return ctx.Err()
		}
		k, ok := groupKey(r, c.Fields)
		if !ok {
			if c.KeepEmpty {
				out = append(out, r)
			}
			continue
		}
		if c.Consecutive {
			if run > 0 && k == prev {
				run++
			} else {
				prev, run = k, 1
			}
			if run <= c.N {
				out = append(out, r)
			}
			continue
		}
		if seen[k]++; seen[k] <= c.N {
			out = append(out, r)
		}
	}
	res.Rows = out
	return nil
}

func applyFillnull(res *Result, c *query.Fillnull) {
	var fill any = c.Value
	if n, ok := parseNumber(c.Value); ok {
		fill = toNumber(n)
	}
	fields := c.Fields
	if len(fields) == 0 {
		fields = res.Columns
	}
	for _, r := range res.Rows {
		for _, f := range fields {
			if v, ok := r[f]; !ok || v == nil {
				r[f] = fill
			}
		}
	}
	for _, f := range c.Fields {
		addColumn(res, f)
	}
}

func applyEventStats(ctx context.Context, res *Result, c *query.EventStats) error {
	groups, cols, err := goStats(ctx, res.Rows, &query.Stats{Aggs: c.Aggs, By: c.By})
	if err != nil {
		return err
	}
	byKey := make(map[string]Row, len(groups))
	for _, g := range groups {
		if k, ok := groupKey(g, c.By); ok {
			byKey[k] = g
		}
	}
	aggCols := cols[len(c.By):]
	// Each row gets its group's results, written out in full with every
	// row: a values() or list() of large fields counts against the
	// search's budget once per row.
	ev := evaluatorFor(ctx)
	for i, r := range res.Rows {
		if i%checkEvery == 0 && ctx.Err() != nil {
			return ctx.Err()
		}
		k, ok := groupKey(r, c.By)
		if !ok {
			continue
		}
		g := byKey[k]
		for _, col := range aggCols {
			if v := g[col]; v != nil {
				if !ev.charge(valueSize(v)) {
					return ev.err
				}
				r[col] = v
			}
		}
	}
	for _, col := range aggCols {
		addColumn(res, col)
	}
	return nil
}

// fieldMatcher returns match with each field name's answer remembered, so
// a command tries its n field patterns once per name instead of once per
// row, charging a step for each pattern tried. ok is false once the
// search's budget or deadline is spent (ev.err says which).
func fieldMatcher(ev *evaluator, n int, match func(name string) bool) func(name string) (matched, ok bool) {
	seen := map[string]bool{}
	return func(name string) (bool, bool) {
		if m, ok := seen[name]; ok {
			return m, true
		}
		if !ev.stepN(n + 1) {
			return false, false
		}
		m := match(name)
		seen[name] = m
		return m, true
	}
}
