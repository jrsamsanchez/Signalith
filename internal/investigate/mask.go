package investigate

import (
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/jrsamsanchez/signalith/internal/query"
)

// AlwaysMasked are field name patterns whose values are never sent,
// whatever the settings say: credentials and session material.
var AlwaysMasked = []string{"*password*", "*passwd*", "*secret*", "*token*", "*api_key*", "*apikey*", "*cookie*", "*authorization*", "*session_id*", "*private_key*"}

// minTextMask is the shortest value replaced in free text such as _raw.
// Shorter ones ("1", "ok") would mangle the text without hiding anything.
const minTextMask = 3

// Masker replaces the values of masked fields with stand-ins such as
// masked-user-1 before anything is sent, and keeps the mapping, so the
// model can still tell two values apart and search for them: its
// queries are translated back before they run. The real values never
// leave the server.
type Masker struct {
	patterns []string
	dropRaw  bool
	byValue  map[string]string // lower-case real value -> stand-in
	byToken  map[string]string // stand-in -> real value
	counts   map[string]int    // stand-ins made per field
	re       *regexp.Regexp    // every real value, for free text; nil when stale
}

// NewMasker masks the fields in AlwaysMasked and in fields. A field of
// "_raw" leaves out the original event text instead.
func NewMasker(fields []string) *Masker {
	m := &Masker{byValue: map[string]string{}, byToken: map[string]string{}, counts: map[string]int{}}
	m.patterns = append(m.patterns, AlwaysMasked...)
	for _, f := range fields {
		f = strings.ToLower(strings.TrimSpace(f))
		switch f {
		case "":
		case "_raw":
			m.dropRaw = true
		default:
			m.patterns = append(m.patterns, f)
		}
	}
	return m
}

// Fields lists what is masked, for the page.
func (m *Masker) Fields() []string {
	out := append([]string{}, m.patterns...)
	if m.dropRaw {
		out = append(out, "_raw")
	}
	return out
}

// DropsRaw reports whether the original event text is left out.
func (m *Masker) DropsRaw() bool { return m.dropRaw }

// Masks reports whether a field's values are masked.
func (m *Masker) Masks(field string) bool {
	f := strings.ToLower(field)
	if f == "_raw" {
		return m.dropRaw
	}
	for _, p := range m.patterns {
		if ok, _ := path.Match(p, f); ok {
			return true
		}
	}
	return false
}

// token returns the stand-in for a value of a masked field.
func (m *Masker) token(field, value string) string {
	key := strings.ToLower(value)
	if t, ok := m.byValue[key]; ok {
		return t
	}
	kind := strings.Trim(nonWord.ReplaceAllString(strings.ToLower(field), "-"), "-")
	if kind == "" {
		kind = "value"
	}
	m.counts[kind]++
	t := fmt.Sprintf("masked-%s-%d", kind, m.counts[kind])
	m.byValue[key] = t
	m.byToken[t] = value
	m.re = nil
	return t
}

// Value returns what is sent for one field's value: the value, or its
// stand-in when the field is masked.
func (m *Masker) Value(field string, v any) any {
	if v == nil || !m.Masks(field) {
		return v
	}
	switch x := v.(type) {
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = m.Value(field, e)
		}
		return out
	case []string:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = m.Value(field, e)
		}
		return out
	}
	s := fmt.Sprint(v)
	if s == "" {
		return v
	}
	return m.token(field, s)
}

// Row returns a copy of a row with masked fields replaced and, when
// _raw is masked, the event text left out. Free text in other fields is
// masked later, by Text, once every masked value is known.
func (m *Masker) Row(row map[string]any) map[string]any {
	out := make(map[string]any, len(row))
	for k, v := range row {
		if k == "_raw" && m.dropRaw {
			continue
		}
		out[k] = m.Value(k, v)
	}
	return out
}

// Text replaces every masked value seen so far wherever it appears in s,
// such as inside _raw or a command line.
func (m *Masker) Text(s string) string {
	if len(m.byValue) == 0 {
		return s
	}
	if m.re == nil {
		var vals []string
		for v := range m.byValue {
			if len(v) >= minTextMask {
				vals = append(vals, v)
			}
		}
		if len(vals) == 0 {
			return s
		}
		// Longest first, so a value inside a longer one does not split it.
		sort.Slice(vals, func(i, j int) bool { return len(vals[i]) > len(vals[j]) })
		parts := make([]string, len(vals))
		for i, v := range vals {
			parts[i] = regexp.QuoteMeta(v)
		}
		m.re = regexp.MustCompile(`(?i)` + strings.Join(parts, "|"))
	}
	// Stand-ins already in s are kept whole: a short value such as "user"
	// must not be replaced inside masked-user-1.
	var b strings.Builder
	last := 0
	swap := func(part string) string {
		return m.re.ReplaceAllStringFunc(part, func(v string) string { return m.byValue[strings.ToLower(v)] })
	}
	for _, loc := range tokenRE.FindAllStringIndex(s, -1) {
		b.WriteString(swap(s[last:loc[0]]))
		b.WriteString(s[loc[0]:loc[1]])
		last = loc[1]
	}
	b.WriteString(swap(s[last:]))
	return b.String()
}

var (
	tokenRE = regexp.MustCompile(`"?\bmasked-[a-z0-9-]+-\d+\b"?`)
	nonWord = regexp.MustCompile(`[^a-z0-9]+`)
)

// Query puts the real values back into a query the model wrote, quoted
// as the query language needs.
func (m *Masker) Query(q string) string {
	return tokenRE.ReplaceAllStringFunc(q, func(t string) string {
		real, ok := m.byToken[strings.Trim(t, `"`)]
		if !ok {
			return t
		}
		return quote(real)
	})
}

// Reveal puts the real values back into text the model wrote, for the
// analyst to read.
func (m *Masker) Reveal(s string) string {
	return tokenRE.ReplaceAllStringFunc(s, func(t string) string {
		bare := strings.Trim(t, `"`)
		real, ok := m.byToken[bare]
		if !ok {
			return t
		}
		return strings.Replace(t, bare, real, 1)
	})
}

// quote renders a value as one query term.
func quote(v string) string {
	f := query.FormatValue(v)
	if strings.HasPrefix(f, `"`) {
		return f
	}
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(v) + `"`
}
