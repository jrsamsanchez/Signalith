package onboard

import (
	"sort"
	"strings"
	"sync"

	"github.com/jrsamsanchez/signalith/internal/detect"
	"github.com/jrsamsanchez/signalith/internal/query"
	"github.com/jrsamsanchez/signalith/internal/search"
)

// DetectionRef is a detection a parser's events could feed.
type DetectionRef struct {
	ID       string `json:"id"`
	Title    string `json:"title"`
	Severity string `json:"severity"`
	Enabled  bool   `json:"enabled"`
	// Fires counts the sample's events the detection's filter matches.
	Fires int `json:"fires,omitempty"`
	// Missing lists the fields it reads that the events lack.
	Missing []string `json:"missing,omitempty"`
}

// Unlock is a field that, once mapped, would let more detections run.
type Unlock struct {
	Field string `json:"field"`
	Count int    `json:"count"`
}

// Coverage is what detections can do with a parser's events.
type Coverage struct {
	Model string `json:"model"`
	// InModel counts the detections that read the parser's data model.
	InModel int `json:"in_model"`
	// Ready counts those whose every field the events have.
	Ready int `json:"ready"`
	// List shows some of the ready ones, those the sample fires first,
	// then enabled ones; Partial shows some that miss a field or two.
	List    []DetectionRef `json:"list"`
	Partial []DetectionRef `json:"partial,omitempty"`
	// Unlock lists the fields worth mapping, by how many more
	// detections each would let run.
	Unlock []Unlock `json:"unlock,omitempty"`
}

// fieldsAlways are fields a detection may filter on that say nothing
// about whether the events can feed it.
var fieldsAlways = map[string]bool{"datamodel": true, "index": true, "_raw": true, "message": true, "_time": true}

// parsed caches the detections' parsed filters, by query text.
var parsed = struct {
	sync.Mutex
	m map[string]*query.Query
}{m: map[string]*query.Query{}}

func parseCached(q string) *query.Query {
	parsed.Lock()
	defer parsed.Unlock()
	if v, ok := parsed.m[q]; ok {
		return v
	}
	v, err := query.Parse(q)
	if err != nil {
		v = nil
	}
	if len(parsed.m) > 20000 {
		clear(parsed.m)
	}
	parsed.m[q] = v
	return v
}

// MatchDetections says which detections could use events of a model with
// the fields of docs (the preview's events, as stored).
func MatchDetections(ds []*detect.Detection, model, sourcetype string, docs []map[string]any) *Coverage {
	cov := &Coverage{Model: model}
	have := map[string]bool{}
	for _, d := range docs {
		for k := range d {
			have[k] = true
		}
	}
	unlock := map[string]int{}
	var ready, partial []DetectionRef
	for _, d := range ds {
		q := parseCached(d.Query)
		if q == nil || !strings.EqualFold(q.Datamodel, model) {
			continue
		}
		fields, other := filterFields(q.Search, sourcetype)
		if other {
			continue // made for another product's sourcetype
		}
		cov.InModel++
		ref := DetectionRef{ID: d.ID, Title: d.BaseTitle(), Severity: d.Severity, Enabled: d.Enabled}
		for _, f := range fields {
			if !have[f] {
				ref.Missing = append(ref.Missing, f)
			}
		}
		switch {
		case len(ref.Missing) == 0:
			if q.Search != nil {
				for _, doc := range docs {
					if ok, err := search.MatchDoc(q.Search, doc); err == nil && ok {
						ref.Fires++
					}
				}
			}
			ready = append(ready, ref)
		case len(ref.Missing) <= 2 && len(ref.Missing) < len(fields):
			partial = append(partial, ref)
			if len(ref.Missing) == 1 {
				unlock[ref.Missing[0]]++
			}
		}
	}
	cov.Ready = len(ready)
	sort.SliceStable(ready, func(i, j int) bool {
		a, b := ready[i], ready[j]
		if (a.Fires > 0) != (b.Fires > 0) {
			return a.Fires > 0
		}
		if a.Enabled != b.Enabled {
			return a.Enabled
		}
		return a.Title < b.Title
	})
	cov.List = ready[:min(len(ready), 25)]
	sort.SliceStable(partial, func(i, j int) bool { return len(partial[i].Missing) < len(partial[j].Missing) })
	cov.Partial = partial[:min(len(partial), 10)]
	for f, n := range unlock {
		cov.Unlock = append(cov.Unlock, Unlock{Field: f, Count: n})
	}
	sort.Slice(cov.Unlock, func(i, j int) bool {
		if cov.Unlock[i].Count != cov.Unlock[j].Count {
			return cov.Unlock[i].Count > cov.Unlock[j].Count
		}
		return cov.Unlock[i].Field < cov.Unlock[j].Field
	})
	cov.Unlock = cov.Unlock[:min(len(cov.Unlock), 8)]
	return cov
}

// filterFields lists the fields a filter reads. other reports a filter
// that only takes another sourcetype (or vendor product) than ours.
func filterFields(e query.Expr, sourcetype string) (fields []string, other bool) {
	seen := map[string]bool{}
	var walk func(e query.Expr, negated bool)
	walk = func(e query.Expr, negated bool) {
		switch x := e.(type) {
		case *query.And:
			for _, c := range x.Children {
				walk(c, negated)
			}
		case *query.Or:
			for _, c := range x.Children {
				walk(c, negated)
			}
		case *query.Not:
			walk(x.Child, !negated)
		case *query.Compare:
			if x.Field == "sourcetype" && x.Op == "=" && !negated {
				if !globMatch(strings.ToLower(x.Value), strings.ToLower(sourcetype)) {
					other = true
				}
				return
			}
			add(seen, &fields, x.Field, negated)
		case *query.In:
			if x.Field == "sourcetype" && !negated {
				any := false
				for _, v := range x.Values {
					if globMatch(strings.ToLower(v), strings.ToLower(sourcetype)) {
						any = true
					}
				}
				other = other || !any
				return
			}
			add(seen, &fields, x.Field, negated)
		}
	}
	if e != nil {
		walk(e, false)
	}
	return fields, other
}

func add(seen map[string]bool, fields *[]string, f string, negated bool) {
	// A field only ever negated (NOT x=y) does not need to be there.
	if negated || fieldsAlways[f] || f == "sourcetype" || f == "host" || seen[f] {
		return
	}
	seen[f] = true
	*fields = append(*fields, f)
}

// globMatch matches a value with * wildcards, as a filter does.
func globMatch(pattern, s string) bool {
	if !strings.Contains(pattern, "*") {
		return pattern == s
	}
	parts := strings.Split(pattern, "*")
	if !strings.HasPrefix(s, parts[0]) {
		return false
	}
	s = s[len(parts[0]):]
	for i, p := range parts[1:] {
		if i == len(parts)-2 {
			return strings.HasSuffix(s, p)
		}
		j := strings.Index(s, p)
		if j < 0 {
			return false
		}
		s = s[j+len(p):]
	}
	return true
}
