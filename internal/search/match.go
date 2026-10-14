package search

import (
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/jrsamsanchez/signalith/internal/query"
)

// keywordIgnoreAbove is the index template's ignore_above for keyword
// fields: longer values are stored but not indexed, so no filter matches
// them (ingest.IndexTemplate).
const keywordIgnoreAbove = 8191

// MatchDoc reports whether one stored event document (ingest's
// Event.Document) matches a filter expression. It evaluates the same
// OpenSearch query compileExpr builds, clause by clause, so it agrees with
// a real search for keyword and numeric fields: case-insensitive terms and
// wildcards, exists, IPv4 ranges, and number terms. Free text against the
// raw message is approximated as a case-insensitive substring match,
// since OpenSearch analyzes that field. The detection content checks use
// it to prove each shipped rule fires on its test events without a
// running OpenSearch; the integration test checks the same events against
// a real one.
func MatchDoc(e query.Expr, doc map[string]any) (bool, error) {
	q, err := compileExpr(e)
	if err != nil {
		return false, err
	}
	return evalDSL(q, doc)
}

func evalDSL(q map[string]any, doc map[string]any) (bool, error) {
	if len(q) != 1 {
		return false, fmt.Errorf("query clause with %d keys", len(q))
	}
	for kind, body := range q {
		b, _ := body.(map[string]any)
		switch kind {
		case "match_all":
			return true, nil
		case "bool":
			return evalBool(b, doc)
		case "exists":
			field, _ := b["field"].(string)
			_, ok := indexedValue(doc, field)
			return ok, nil
		case "term", "wildcard", "prefix":
			for field, spec := range b {
				s, _ := spec.(map[string]any)
				return evalLeaf(kind, field, s, doc)
			}
			return false, nil
		case "match_phrase":
			for field, v := range b {
				text, _ := doc[field].(string)
				return strings.Contains(strings.ToLower(text), strings.ToLower(fmt.Sprint(v))), nil
			}
			return false, nil
		case "query_string":
			field, _ := b["default_field"].(string)
			text, _ := doc[field].(string)
			pat := unescapeQueryString(fmt.Sprint(b["query"]))
			return globMatch("*"+strings.Trim(pat, "*")+"*", text), nil
		case "range":
			for field, spec := range b {
				s, _ := spec.(map[string]any)
				return evalRange(field, s, doc), nil
			}
			return false, nil
		default:
			return false, fmt.Errorf("query clause %q is not supported in memory", kind)
		}
	}
	return false, nil
}

func evalBool(b map[string]any, doc map[string]any) (bool, error) {
	list := func(k string) []any { l, _ := b[k].([]any); return l }
	for _, c := range append(list("filter"), list("must")...) {
		m, _ := c.(map[string]any)
		ok, err := evalDSL(m, doc)
		if err != nil || !ok {
			return false, err
		}
	}
	for _, c := range list("must_not") {
		m, _ := c.(map[string]any)
		ok, err := evalDSL(m, doc)
		if err != nil {
			return false, err
		}
		if ok {
			return false, nil
		}
	}
	if should := list("should"); len(should) > 0 {
		for _, c := range should {
			m, _ := c.(map[string]any)
			ok, err := evalDSL(m, doc)
			if err != nil {
				return false, err
			}
			if ok {
				return true, nil
			}
		}
		return false, nil
	}
	return true, nil
}

// indexedValue returns a field's value as OpenSearch indexed it: absent
// when missing, and absent for a keyword longer than ignore_above (a
// wildcard field indexes any length).
func indexedValue(doc map[string]any, field string) (any, bool) {
	v, ok := doc[field]
	if !ok || v == nil {
		return nil, false
	}
	if s, isStr := v.(string); isStr && field != StoredRawField && !WildcardFields[field] && utf8.RuneCountInString(s) > keywordIgnoreAbove {
		return nil, false
	}
	return v, true
}

func evalLeaf(kind, field string, spec map[string]any, doc map[string]any) (bool, error) {
	v, ok := indexedValue(doc, field)
	if !ok {
		return false, nil
	}
	want := fmt.Sprint(spec["value"])
	fold := spec["case_insensitive"] == true
	switch x := v.(type) {
	case string:
		switch kind {
		case "term":
			if fold {
				return strings.EqualFold(x, want), nil
			}
			return x == want, nil
		case "prefix":
			return strings.HasPrefix(x, want), nil
		default:
			// The compiler doubled each backslash for the wildcard escape.
			return globMatch(strings.ReplaceAll(want, `\\`, `\`), x), nil
		}
	case int64, int, float64:
		// A numeric field: OpenSearch rejects wildcard and prefix queries on
		// it, and a term must be a number.
		if kind != "term" {
			return false, fmt.Errorf("%s query on numeric field %s", kind, field)
		}
		n, err := strconv.ParseFloat(want, 64)
		if err != nil {
			return false, fmt.Errorf("field %s is numeric but the value %q is not a number", field, want)
		}
		f, _ := strconv.ParseFloat(fmt.Sprint(x), 64)
		return f == n, nil
	case bool:
		return strings.EqualFold(strconv.FormatBool(x), want), nil
	}
	return false, nil
}

func evalRange(field string, spec map[string]any, doc map[string]any) bool {
	v, ok := indexedValue(doc, field)
	if !ok {
		return false
	}
	have, err := strconv.ParseFloat(fmt.Sprint(v), 64)
	if err != nil {
		return false
	}
	for op, raw := range spec {
		want, err := strconv.ParseFloat(fmt.Sprint(raw), 64)
		if err != nil {
			return false
		}
		switch op {
		case "lt":
			ok = have < want
		case "lte":
			ok = have <= want
		case "gt":
			ok = have > want
		case "gte":
			ok = have >= want
		}
		if !ok {
			return false
		}
	}
	return true
}

// globMatch matches an OpenSearch wildcard pattern (* any run, ? any one
// character, everything else literal) case-insensitively.
func globMatch(pattern, s string) bool {
	p := []rune(strings.ToLower(pattern))
	t := []rune(strings.ToLower(s))
	// Iterative matching with backtracking to the last star.
	pi, ti, star, mark := 0, 0, -1, 0
	for ti < len(t) {
		switch {
		case pi < len(p) && p[pi] != '*' && (p[pi] == '?' || p[pi] == t[ti]):
			pi++
			ti++
		case pi < len(p) && p[pi] == '*':
			star, mark = pi, ti
			pi++
		case star >= 0:
			pi = star + 1
			mark++
			ti = mark
		default:
			return false
		}
	}
	for pi < len(p) && p[pi] == '*' {
		pi++
	}
	return pi == len(p)
}

func unescapeQueryString(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			i++
		}
		b.WriteByte(s[i])
	}
	return b.String()
}
