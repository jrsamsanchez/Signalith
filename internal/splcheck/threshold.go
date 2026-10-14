package splcheck

import (
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jrsamsanchez/signalith/internal/sigmacheck"
)

// Threshold rules count the events their where clause selects: grouped
// by some fields, within a span of time (tstats ... by _time span=1m, or
// bucket span=5m _time before stats), and kept when a count passes a
// limit (where count >= 10, where unique_accounts > 30).
type Threshold struct {
	// Span is the time the events are counted over; 0 is the rule's whole
	// scheduled search, an hour in Splunk's default deployment.
	Span time.Duration
	// By are the Signalith fields the events are grouped by.
	By []string
	// Aggs are the counts the limits read, by the name the search gives
	// each.
	Aggs []Agg
	// Limits must all hold for a group to be found.
	Limits []Limit
}

// Agg is one count: of events (Func count) or of a field's distinct
// values (Func dc).
type Agg struct {
	Name, Func, Field string
}

// Limit is one test of a count: Name >= Value or Name > Value.
type Limit struct {
	Name  string
	Op    string
	Value int
}

// DefaultSpan is the time a threshold without a span counts over:
// Splunk's default deployment runs each rule hourly over the hour before.
const DefaultSpan = time.Hour

var (
	spanRe       = regexp.MustCompile(`(?i)\bspan\s*=\s*(\d+)([smh])\b`)
	bucketRe     = regexp.MustCompile(`(?i)^(?:bucket|bin)\s+(?:_time\s+span\s*=\s*(\d+)([smh])|span\s*=\s*(\d+)([smh])\s+_time)$`)
	limitRe      = regexp.MustCompile(`^(\w+)\s*(>=|>)\s*(\d+)$`)
	statsSplitRe = regexp.MustCompile(`(?is)^(?:\|\s*)?(?:stats|tstats)\s+(.*?)\s+(?:by|BY)\s+(.*)$`)
	// The aggregations a threshold search reads: count, and distinct
	// counts with a name. values(), min(_time) and max(_time) only add
	// columns.
	aggRe      = regexp.MustCompile(`(?i)^(count|(?:dc|distinct_count)\(\s*([\w.]+)\s*\)\s+as\s+(\w+))\s*,?\s*`)
	columnsRe  = regexp.MustCompile(`(?i)^(?:values|min|max|latest|earliest)\(\s*[\w.]+\s*\)\s+as\s+\w+\s*,?\s*`)
	summaryRe  = regexp.MustCompile("^`security_content_summariesonly`\\s*")
	byFieldsRe = regexp.MustCompile(`[\s,]+`)
)

// parseSpan reads a span such as 5m or 30s.
func parseSpan(n, unit string) time.Duration {
	v, _ := strconv.Atoi(n)
	switch strings.ToLower(unit) {
	case "s":
		return time.Duration(v) * time.Second
	case "m":
		return time.Duration(v) * time.Minute
	}
	return time.Duration(v) * time.Hour
}

// parseAggs reads a stats or tstats command's aggregations.
func parseAggs(s string, field func(string) (string, error)) ([]Agg, error) {
	var aggs []Agg
	s = strings.TrimSpace(summaryRe.ReplaceAllString(strings.TrimSpace(s), ""))
	for s != "" {
		if m := columnsRe.FindString(s); m != "" {
			s = s[len(m):]
			continue
		}
		m := aggRe.FindStringSubmatch(s)
		if m == nil {
			return nil, fmt.Errorf("stats aggregation %s is not supported", firstWords(s))
		}
		s = s[len(m[0]):]
		if strings.EqualFold(m[1], "count") {
			aggs = append(aggs, Agg{Name: "count", Func: "count"})
			continue
		}
		f, err := field(m[2])
		if err != nil {
			return nil, err
		}
		aggs = append(aggs, Agg{Name: m[3], Func: "dc", Field: f})
	}
	return aggs, nil
}

// parseBy reads a by clause: the fields, and the span when it groups by
// _time. bucketed says an earlier bucket stage set the span, so _time
// alone is allowed.
func parseBy(s string, bucketed bool, field func(string) (string, bool, error)) ([]string, time.Duration, error) {
	var span time.Duration
	if m := spanRe.FindStringSubmatch(s); m != nil {
		span = parseSpan(m[1], m[2])
		s = spanRe.ReplaceAllString(s, " ")
	}
	var by []string
	timed := false
	for _, f := range byFieldsRe.Split(strings.TrimSpace(s), -1) {
		switch {
		case f == "":
		case f == "_time":
			timed = true
		default:
			name, keep, err := field(f)
			if err != nil {
				return nil, 0, err
			}
			if keep && !slices.Contains(by, name) {
				by = append(by, name)
			}
		}
	}
	if timed != (span > 0 || bucketed) {
		return nil, 0, fmt.Errorf("a count by _time needs a span")
	}
	if len(by) == 0 {
		return nil, 0, fmt.Errorf("a count must be by at least one field")
	}
	return by, span, nil
}

// parseLimits reads a where of limits joined by AND (count >= 10).
func parseLimits(s string) ([]Limit, bool) {
	w := whereRe.FindStringSubmatch(s)
	if w == nil {
		return nil, false
	}
	var out []Limit
	for _, part := range andRe.Split(strings.TrimSpace(w[1]), -1) {
		m := limitRe.FindStringSubmatch(strings.TrimSpace(part))
		if m == nil {
			return nil, false
		}
		v, _ := strconv.Atoi(m[3])
		out = append(out, Limit{Name: m[1], Op: m[2], Value: v})
	}
	return out, true
}

var andRe = regexp.MustCompile(`(?i)\s+AND\s+`)

// threshold puts a count's parts together: each limit must read one of
// its counts.
func threshold(aggs []Agg, by []string, span time.Duration, limits []Limit) (*Threshold, error) {
	for _, l := range limits {
		if !slices.ContainsFunc(aggs, func(a Agg) bool { return a.Name == l.Name }) {
			return nil, fmt.Errorf("where %s reads no count of the search", l.Name)
		}
	}
	return &Threshold{Span: span, By: by, Aggs: aggs, Limits: limits}, nil
}

// The CIM fields Splunk's Windows add-ons give raw events that a raw
// count may group by, with the Signalith field each is stored as. The
// event's Computer is the host that logged it.
var rawGroupFields = map[string]string{
	"dest": "dest", "user": "user", "src": "src", "src_ip": "src", "process_path": "process_path",
	"process_id": "process_id", "action": "action", "signature_id": "signature_id", "EventCode": "signature_id",
	"Computer": "host", "src_user": "user",
}

// sameAsEvent are add-on fields that only restate which event it is (its
// event code, product or device), so grouping by them splits nothing once
// the event code is grouped by or fixed.
var sameAsEvent = map[string]bool{
	"signature": true, "vendor_product": true, "dvc": true, "app": true, "user_id": true,
	"authentication_method": true,
}

// rawGroupField is the Signalith field a raw count groups by.
func rawGroupField(node, f string) (string, bool, error) {
	if sameAsEvent[f] {
		return "", false, nil
	}
	// An event's IpAddress is stored as src without its ::ffff: prefix,
	// which groups the same events.
	if f == "IpAddress" {
		return "src", true, nil
	}
	if name, ok := RawFields[node][f]; ok && name != RawUser {
		return name, true, nil
	}
	if name, ok := rawGroupFields[f]; ok {
		return name, true, nil
	}
	return "", false, fmt.Errorf("field %s has no Signalith mapping", f)
}

// Fields are the stored fields a threshold reads: what it groups by and
// what it counts.
func (t *Threshold) Fields() []string {
	out := slices.Clone(t.By)
	for _, a := range t.Aggs {
		if a.Field != "" && !slices.Contains(out, a.Field) {
			out = append(out, a.Field)
		}
	}
	return out
}

// tstatsThreshold reads a tstats count: its aggregations (head) and by
// clause, over node's fields.
func tstatsThreshold(node, head, by string, limits []Limit) (*Threshold, error) {
	field := func(f string) (string, error) {
		name, ok := strings.CutPrefix(f, node+".")
		if !ok || !slices.Contains(Nodes[node], name) && name != "dest" {
			return "", fmt.Errorf("field %s has no Signalith mapping", f)
		}
		return nodeField(node, name), nil
	}
	aggs, err := parseAggs(head, field)
	if err != nil {
		return nil, err
	}
	fields, span, err := parseBy(by, false, func(f string) (string, bool, error) {
		name, err := field(f)
		return name, err == nil, err
	})
	if err != nil {
		return nil, err
	}
	return threshold(aggs, fields, span, limits)
}

// isLimits reports whether a stage is a where of limits.
func isLimits(s string) bool {
	_, ok := parseLimits(s)
	return ok
}

// rawThreshold reads a raw search's count: its stats stage, after a
// bucket of span when span is set.
func rawThreshold(node, stats string, span time.Duration, limits []Limit) (*Threshold, error) {
	m := statsSplitRe.FindStringSubmatch(stats)
	if m == nil {
		return nil, fmt.Errorf("a count must be by at least one field")
	}
	aggs, err := parseAggs(m[1], func(f string) (string, error) {
		name, keep, err := rawGroupField(node, f)
		if err == nil && !keep {
			err = fmt.Errorf("field %s has no Signalith mapping", f)
		}
		return name, err
	})
	if err != nil {
		return nil, err
	}
	if spanRe.MatchString(m[2]) {
		return nil, fmt.Errorf("a raw count's span must come from bucket")
	}
	by, _, err := parseBy(m[2], span > 0, func(f string) (string, bool, error) { return rawGroupField(node, f) })
	if err != nil {
		return nil, err
	}
	return threshold(aggs, by, span, limits)
}

// reaches reports whether some group of the events, all counted
// together whatever their time, passes every limit.
func (t *Threshold) reaches(views []map[string]string) bool {
	type group struct {
		count    int
		distinct map[string]map[string]bool
	}
	groups := map[string]*group{}
	for _, v := range views {
		var key []string
		missing := false
		for _, f := range t.By {
			missing = missing || v[f] == ""
			key = append(key, v[f])
		}
		if missing {
			continue
		}
		k := strings.Join(key, "\x00")
		g := groups[k]
		if g == nil {
			g = &group{distinct: map[string]map[string]bool{}}
			groups[k] = g
		}
		g.count++
		for _, a := range t.Aggs {
			if a.Func == "dc" && v[a.Field] != "" {
				if g.distinct[a.Name] == nil {
					g.distinct[a.Name] = map[string]bool{}
				}
				g.distinct[a.Name][v[a.Field]] = true
			}
		}
	}
	for _, g := range groups {
		ok := true
		for _, l := range t.Limits {
			n := g.count
			for _, a := range t.Aggs {
				if a.Name == l.Name && a.Func == "dc" {
					n = len(g.distinct[a.Name])
				}
			}
			ok = ok && (n > l.Value || l.Op == ">=" && n == l.Value)
		}
		if ok {
			return true
		}
	}
	return false
}

// Reaches reports whether the cases' events, as stored and all counted
// together whatever their time, make a group that passes every limit.
func Reaches(t *Threshold, cases []sigmacheck.Case) bool {
	var views []map[string]string
	for _, c := range cases {
		doc, _ := Stored(c)
		views = append(views, View(doc))
	}
	return t.reaches(views)
}
