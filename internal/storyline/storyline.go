// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

// Package storyline gathers what Signalith knows about one intrusion into
// a single story: the findings and risk events about a host or a user, the
// users, systems, addresses and processes they share, and the sign-ins,
// process starts and connections that link them, ordered by ATT&CK tactic.
// An analyst sees one attack instead of twenty separate alerts.
//
// Everything it reads is bounded: a capped number of seeds, findings, risk
// events and activity rows, inside a time window of at most MaxWindow.
package storyline

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/jrsamsanchez/signalith/internal/assets"
	"github.com/jrsamsanchez/signalith/internal/cases"
	"github.com/jrsamsanchez/signalith/internal/datamodel"
	"github.com/jrsamsanchez/signalith/internal/detect"
	"github.com/jrsamsanchez/signalith/internal/findings"
	"github.com/jrsamsanchez/signalith/internal/query"
)

// Limits on what one storyline reads and returns.
const (
	MaxSeeds    = 8
	MaxFindings = 200
	MaxRisk     = 300
	// MaxActivity is the most rows of each kind of activity (sign-ins,
	// processes, connections).
	MaxActivity = 40
	MaxNodes    = 60
	MaxEdges    = 120
	// MaxWindow is the longest time a storyline covers.
	MaxWindow = 31 * 24 * time.Hour
	// maxPerItem is how many of an item's entities are linked to each
	// other in the graph, seeds first.
	maxPerItem = 6
	// maxLinked is the most entities of each type the activity searches
	// look for, beyond the seeds.
	maxLinked = 10
	maxValue  = 256
)

// Entity types.
const (
	User    = "user"
	System  = "system"
	IP      = "ip"
	Process = "process"
	Other   = "other"
)

// SeedTypes are the entity types a storyline can start from.
var SeedTypes = []string{User, System, IP}

// Entity is one user, system, address or process.
type Entity struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// Key is the entity's node ID.
func (e Entity) Key() string { return e.Type + ":" + e.Value }

// Item is one finding or risk event on the timeline.
type Item struct {
	ID          string    `json:"id"`
	Kind        string    `json:"kind"` // finding or risk
	Time        time.Time `json:"time"`
	Title       string    `json:"title"`
	Severity    string    `json:"severity,omitempty"` // a finding's urgency
	Status      string    `json:"status,omitempty"`
	CaseID      string    `json:"case_id,omitempty"`
	DetectionID string    `json:"detection_id,omitempty"`
	// Risk is the risk the item added; a finding's includes the risk
	// events its detection wrote alongside it.
	Risk float64 `json:"risk,omitempty"`
	// Tactics are ATT&CK tactic short names, in the order of the matrix.
	Tactics    []string `json:"tactics,omitempty"`
	Techniques []string `json:"techniques,omitempty"`
	// Entities are the node IDs the item is about.
	Entities []string `json:"entities,omitempty"`
	Sample   bool     `json:"sample,omitempty"`

	groupKey string
}

// Node is one entity in the graph.
type Node struct {
	ID       string          `json:"id"`
	Type     string          `json:"type"`
	Value    string          `json:"value"`
	Seed     bool            `json:"seed,omitempty"`
	Findings int             `json:"findings,omitempty"`
	Risk     float64         `json:"risk,omitempty"`
	Severity string          `json:"severity,omitempty"` // highest urgency of its findings
	First    time.Time       `json:"first,omitzero"`
	Last     time.Time       `json:"last,omitzero"`
	Context  *assets.Context `json:"context,omitempty"`

	weight int
}

// Edge links two entities.
type Edge struct {
	From string `json:"from"`
	To   string `json:"to"`
	// Kind is together (in the same finding or risk event), login,
	// started (a parent process started a child) or connected.
	Kind  string `json:"kind"`
	Label string `json:"label,omitempty"`
	Count int    `json:"count"`
}

// Phase is one ATT&CK tactic the story reached.
type Phase struct {
	Tactic   string    `json:"tactic"` // short name; empty for items with no tactic
	ID       string    `json:"id,omitempty"`
	Name     string    `json:"name"`
	Items    int       `json:"items"`
	First    time.Time `json:"first"`
	Last     time.Time `json:"last"`
	Severity string    `json:"severity,omitempty"`
}

// Activity is one summarized row of sign-ins, process starts or
// connections between the story's entities.
type Activity struct {
	Kind   string            `json:"kind"` // login, process or connection
	Fields map[string]string `json:"fields"`
	Count  int               `json:"count"`
	First  time.Time         `json:"first,omitzero"`
	Last   time.Time         `json:"last,omitzero"`
}

// Storyline is the whole story.
type Storyline struct {
	Seeds    []Entity   `json:"seeds"`
	Earliest time.Time  `json:"earliest"`
	Latest   time.Time  `json:"latest"`
	Phases   []Phase    `json:"phases"`
	Items    []Item     `json:"items"`
	Nodes    []Node     `json:"nodes"`
	Edges    []Edge     `json:"edges"`
	Activity []Activity `json:"activity"`
	Risk     float64    `json:"risk"`
	// Searches open each part of the story in Search.
	Searches map[string]string `json:"searches"`
	// Truncated names what reached its limit: findings, risk, login,
	// process, connection, nodes or edges.
	Truncated []string `json:"truncated,omitempty"`
	// Warnings say which activity could not be read; the rest of the
	// story is still shown.
	Warnings []string `json:"warnings,omitempty"`
}

// Builder reads the story's parts.
type Builder struct {
	Findings findings.Store
	// Run runs a search and returns its rows; nil leaves out risk events
	// and activity.
	Run    func(ctx context.Context, q *query.Query) ([]map[string]any, error)
	Assets *assets.Store
}

// Request says what to build a story about.
type Request struct {
	Seeds    []Entity
	Earliest time.Time
	Latest   time.Time
}

// ErrNoSeeds is a request with nothing to build a story about.
var ErrNoSeeds = errors.New("nothing to build a storyline about: give a user, system or address")

// ParseSeed checks one entity a person asked for.
func ParseSeed(typ, value string) (Entity, error) {
	value = strings.TrimSpace(value)
	if !slices.Contains(SeedTypes, typ) {
		return Entity{}, fmt.Errorf("type must be one of %s", strings.Join(SeedTypes, ", "))
	}
	if !usable(value) {
		return Entity{}, errors.New("the value must be 1 to 256 characters with no wildcards or control characters")
	}
	if typ == System && net.ParseIP(value) != nil {
		typ = IP
	}
	return Entity{Type: typ, Value: value}, nil
}

// usable reports whether a value can be looked up exactly: wildcards
// would widen a search, and control characters are never real names.
func usable(v string) bool {
	if v == "" || len(v) > maxValue || v == "-" || strings.ContainsAny(v, "*?") {
		return false
	}
	return !strings.ContainsFunc(v, unicode.IsControl)
}

// entityOf types one entity value of a finding or risk event by the field
// it was found in.
func entityOf(field string, v any, row map[string]any) (Entity, bool) {
	s := strings.TrimSpace(str(v))
	if !usable(s) {
		return Entity{}, false
	}
	switch field {
	case "user", "src_user", "member", "parent_user":
		return Entity{User, s}, true
	case "host", "dest_host", "src_host":
		return Entity{System, s}, true
	case "src", "dest":
		if net.ParseIP(s) != nil {
			return Entity{IP, s}, true
		}
		return Entity{System, s}, true
	case "process_name", "parent_process_name":
		return Entity{Process, s}, true
	case "risk_object":
		switch str(row["risk_object_type"]) {
		case "user":
			return Entity{User, s}, true
		case "system":
			if net.ParseIP(s) != nil {
				return Entity{IP, s}, true
			}
			return Entity{System, s}, true
		}
		return Entity{Other, s}, true
	}
	return Entity{}, false
}

// entityFields are the fields entities are read from, most telling first.
var entityFields = []string{"risk_object", "user", "dest", "host", "dest_host", "src", "src_host", "src_user", "member", "process_name"}

// entitiesOf lists the entities of a finding's or risk event's fields.
func entitiesOf(row map[string]any) []Entity {
	var out []Entity
	for _, f := range entityFields {
		v, ok := row[f]
		if !ok {
			continue
		}
		for _, one := range strs(v) {
			if e, ok := entityOf(f, one, row); ok && !slices.Contains(out, e) {
				out = append(out, e)
			}
		}
	}
	return out
}

// SeedsFromFinding starts a story from a finding's users, systems and
// addresses.
func SeedsFromFinding(f *findings.Finding) []Entity {
	return seedsOf(entitiesOf(f.Entities))
}

// SeedsFromCase starts a story from a case's entities and its findings',
// the most frequent first.
func SeedsFromCase(c *cases.Case, fs []*findings.Finding) []Entity {
	count := map[Entity]int{}
	var order []Entity
	add := func(e Entity, n int) {
		if _, ok := count[e]; !ok {
			order = append(order, e)
		}
		count[e] += n
	}
	for _, ce := range c.Entities {
		if e, ok := entityOf(ce.Field, ce.Value, nil); ok {
			add(e, 100) // an analyst picked these
		} else if e, err := ParseSeed(System, ce.Value); err == nil && ce.Field == "ip" {
			add(e, 100)
		}
	}
	for _, f := range fs {
		for _, e := range entitiesOf(f.Entities) {
			add(e, 1)
		}
	}
	sort.SliceStable(order, func(i, j int) bool { return count[order[i]] > count[order[j]] })
	return seedsOf(order)
}

// seedsOf keeps the entities a story can start from, up to MaxSeeds.
func seedsOf(es []Entity) []Entity {
	var out []Entity
	for _, e := range es {
		if slices.Contains(SeedTypes, e.Type) && !slices.Contains(out, e) {
			out = append(out, e)
		}
		if len(out) == MaxSeeds {
			break
		}
	}
	return out
}

// WindowAround is the time a story about things that happened at these
// times covers: three days before the first, to a day after the last, but
// never past now nor longer than MaxWindow.
func WindowAround(times []time.Time, now time.Time) (time.Time, time.Time) {
	if len(times) == 0 {
		return now.Add(-7 * 24 * time.Hour), now
	}
	first, last := slices.MinFunc(times, time.Time.Compare), slices.MaxFunc(times, time.Time.Compare)
	earliest, latest := first.Add(-72*time.Hour), last.Add(24*time.Hour)
	if latest.After(now) {
		latest = now
	}
	if latest.Sub(earliest) > MaxWindow {
		earliest = latest.Add(-MaxWindow)
	}
	return earliest, latest
}

// story is a storyline being built.
type story struct {
	*Storyline
	nodes map[string]*Node
	edges map[[3]string]*Edge
	seeds map[string]bool
}

// Build reads and assembles the story.
func (b *Builder) Build(ctx context.Context, req Request) (*Storyline, error) {
	if len(req.Seeds) == 0 {
		return nil, ErrNoSeeds
	}
	if len(req.Seeds) > MaxSeeds {
		req.Seeds = req.Seeds[:MaxSeeds]
	}
	if !req.Latest.After(req.Earliest) {
		return nil, errors.New("the time range is empty")
	}
	if req.Latest.Sub(req.Earliest) > MaxWindow {
		req.Earliest = req.Latest.Add(-MaxWindow)
	}
	st := &story{
		Storyline: &Storyline{Seeds: req.Seeds, Earliest: req.Earliest.UTC(), Latest: req.Latest.UTC(),
			Phases: []Phase{}, Items: []Item{}, Nodes: []Node{}, Edges: []Edge{}, Activity: []Activity{}, Searches: map[string]string{}},
		nodes: map[string]*Node{}, edges: map[[3]string]*Edge{}, seeds: map[string]bool{},
	}
	var values []string
	for _, e := range req.Seeds {
		st.seeds[e.Key()] = true
		st.node(e)
		if !slices.Contains(values, e.Value) {
			values = append(values, e.Value)
		}
	}
	if err := st.addFindings(ctx, b.Findings, values); err != nil {
		return nil, err
	}
	if b.Run != nil {
		if err := st.addRisk(ctx, b.Run, values); err != nil {
			return nil, err
		}
		st.addActivity(ctx, b.Run)
	}
	st.finish(b.Assets)
	return st.Storyline, nil
}

func (st *story) node(e Entity) *Node {
	n := st.nodes[e.Key()]
	if n == nil {
		n = &Node{ID: e.Key(), Type: e.Type, Value: e.Value, Seed: st.seeds[e.Key()]}
		st.nodes[n.ID] = n
	}
	return n
}

func (st *story) seen(n *Node, t time.Time) {
	if t.IsZero() {
		return
	}
	if n.First.IsZero() || t.Before(n.First) {
		n.First = t
	}
	if t.After(n.Last) {
		n.Last = t
	}
}

func (st *story) edge(from, to, kind, label string, count int) {
	if from == to {
		return
	}
	if kind == "together" && from > to {
		from, to = to, from // undirected
	}
	k := [3]string{from, to, kind + "\x00" + label}
	e := st.edges[k]
	if e == nil {
		e = &Edge{From: from, To: to, Kind: kind, Label: label}
		st.edges[k] = e
	}
	e.Count += count
}

// link adds an item's entities to the graph and links them to each
// other, seeds first.
func (st *story) link(it *Item, es []Entity) {
	sort.SliceStable(es, func(i, j int) bool { return st.seeds[es[i].Key()] && !st.seeds[es[j].Key()] })
	if len(es) > maxPerItem {
		es = es[:maxPerItem]
	}
	for i, e := range es {
		n := st.node(e)
		st.seen(n, it.Time)
		n.weight++
		it.Entities = append(it.Entities, n.ID)
		for _, o := range es[:i] {
			st.edge(o.Key(), n.ID, "together", "", 1)
		}
	}
}

func (st *story) addFindings(ctx context.Context, store findings.Store, values []string) error {
	if store == nil {
		return nil
	}
	fs, total, err := store.Search(ctx, findings.Filter{EntityValues: values, Since: st.Earliest, Limit: MaxFindings})
	if err != nil {
		return fmt.Errorf("reading findings: %w", err)
	}
	if total > len(fs) {
		st.Truncated = append(st.Truncated, "findings")
	}
	for _, f := range fs {
		if f.Created.After(st.Latest) {
			continue
		}
		it := Item{
			ID: f.ID, Kind: "finding", Time: f.Created.UTC(), Title: detect.ShowHidden(f.Title), Severity: f.EffectiveUrgency(),
			Status: f.Status, CaseID: f.CaseID, DetectionID: f.DetectionID,
			Techniques: f.MITRE, Tactics: ordered(detect.Tactics(f.MITRE)), Sample: f.Sample != "", groupKey: f.GroupKey,
		}
		es := entitiesOf(f.Entities)
		st.link(&it, es)
		for _, id := range it.Entities {
			n := st.nodes[id]
			n.Findings++
			if rank(it.Severity) > rank(n.Severity) {
				n.Severity = it.Severity
			}
		}
		st.Items = append(st.Items, it)
	}
	return nil
}

// riskFields are where a seed may appear in a risk event.
var riskFields = []string{"risk_object", "user", "src_user", "dest", "host", "src", "src_host", "dest_host"}

func (st *story) addRisk(ctx context.Context, run func(context.Context, *query.Query) ([]map[string]any, error), values []string) error {
	var ors []query.Expr
	for _, f := range riskFields {
		ors = append(ors, in(f, values))
	}
	q := &query.Query{Datamodel: datamodel.RiskModel, Earliest: st.Earliest.Format(time.RFC3339), Latest: st.Latest.Format(time.RFC3339),
		Search: &query.Or{Children: ors}, Commands: []query.Command{&query.Head{N: MaxRisk + 1}}}
	st.Searches["risk"] = q.String()
	rows, err := run(ctx, q)
	if err != nil {
		return fmt.Errorf("reading risk events: %w", err)
	}
	if len(rows) > MaxRisk {
		rows = rows[:MaxRisk]
		st.Truncated = append(st.Truncated, "risk")
	}
	// A detection that raises a finding writes its risk events with the
	// same group key at the same moment: those add to the finding.
	byKey := map[string][]int{}
	for i, it := range st.Items {
		if f := it.DetectionID; f != "" {
			byKey[f] = append(byKey[f], i)
		}
	}
	riskItems := map[string]int{}
	for _, row := range rows {
		t := timeOf(row["_time"])
		if t.IsZero() {
			t = timeOf(row["@timestamp"])
		}
		score, _ := num(row["risk_score"])
		st.Risk += score
		obj, ok := entityOf("risk_object", row["risk_object"], row)
		if ok {
			n := st.node(obj)
			n.Risk += score
			st.seen(n, t)
		}
		det, key := str(row["detection_id"]), str(row["group_key"])
		merged := false
		for _, i := range byKey[det] {
			it := &st.Items[i]
			if d := it.Time.Sub(t); it.groupKey == key && d < 10*time.Minute && d > -10*time.Minute {
				it.Risk += score
				merged = true
				break
			}
		}
		if merged {
			continue
		}
		// A detection writes one risk event per object it names: the
		// same moment for a user and a system is one item.
		same := det + "\x00" + key + "\x00" + t.Format(time.RFC3339Nano)
		if i, ok := riskItems[same]; ok {
			st.Items[i].Risk += score
			continue
		}
		riskItems[same] = len(st.Items)
		it := Item{
			ID: riskID(row, t), Kind: "risk", Time: t, Title: str(row["risk_message"]), DetectionID: det, Risk: score,
			Techniques: strs(row["mitre"]), Tactics: ordered(strs(row["mitre_tactic"])), Sample: str(row[datamodel.SampleField]) != "",
		}
		if it.Title == "" {
			it.Title = str(row["message"])
		}
		st.link(&it, entitiesOf(row))
		st.Items = append(st.Items, it)
	}
	return nil
}

func riskID(row map[string]any, t time.Time) string {
	if id := str(row["_id"]); id != "" {
		return id
	}
	return "risk:" + str(row["detection_id"]) + ":" + str(row["risk_object"]) + ":" + t.Format(time.RFC3339Nano)
}

// linked lists the values of one type the activity searches look for:
// the seeds, then the entities with the most findings.
func (st *story) linked(types ...string) []string {
	var ns []*Node
	for _, n := range st.nodes {
		if slices.Contains(types, n.Type) {
			ns = append(ns, n)
		}
	}
	sort.Slice(ns, func(i, j int) bool {
		if ns[i].Seed != ns[j].Seed {
			return ns[i].Seed
		}
		if ns[i].weight != ns[j].weight {
			return ns[i].weight > ns[j].weight
		}
		return ns[i].ID < ns[j].ID
	})
	var out []string
	for _, n := range ns {
		if len(out) == maxLinked+MaxSeeds {
			break
		}
		if !slices.Contains(out, n.Value) {
			out = append(out, n.Value)
		}
	}
	return out
}

func in(field string, values []string) query.Expr { return &query.In{Field: field, Values: values} }

func anyOf(es ...query.Expr) query.Expr {
	var kept []query.Expr
	for _, e := range es {
		if e != nil {
			kept = append(kept, e)
		}
	}
	if len(kept) == 1 {
		return kept[0]
	}
	return &query.Or{Children: kept}
}

func (st *story) activityQuery(model string, search query.Expr, by []string) *query.Query {
	return &query.Query{Datamodel: model, Earliest: st.Earliest.Format(time.RFC3339), Latest: st.Latest.Format(time.RFC3339),
		Search: search, Commands: []query.Command{
			&query.Stats{Aggs: []query.Agg{{Func: "count", Alias: "count"}, {Func: "min", Field: "_time", Alias: "first"}, {Func: "max", Field: "_time", Alias: "last"}}, By: by},
			&query.Sort{Keys: []query.SortKey{{Field: "count", Desc: true}}},
			&query.Head{N: MaxActivity + 1},
		}}
}

// addActivity reads the sign-ins, process starts and connections between
// the story's entities. A search that fails leaves its part out with a
// warning; the findings and risk are still worth showing.
func (st *story) addActivity(ctx context.Context, run func(context.Context, *query.Query) ([]map[string]any, error)) {
	users, systems, ips := st.linked(User), st.linked(System), st.linked(IP)
	procs := st.linked(Process)
	var seedIPs []string
	for _, e := range st.Seeds {
		if e.Type == IP {
			seedIPs = append(seedIPs, e.Value)
		}
	}

	type part struct {
		kind, what string
		q          *query.Query
		fields     []string
		add        func(f map[string]string, count int) bool
	}
	var parts []part
	if len(users)+len(systems)+len(ips) > 0 {
		var es []query.Expr
		if len(users) > 0 {
			es = append(es, in("user", users))
		}
		if len(systems) > 0 {
			es = append(es, in("dest", systems))
		}
		if hosts := append(slices.Clone(ips), systems...); len(hosts) > 0 {
			es = append(es, in("src", hosts))
		}
		parts = append(parts, part{kind: "login", what: "sign-ins", fields: []string{"user", "src", "dest", "action"},
			q: st.activityQuery("Authentication", anyOf(es...), []string{"user", "src", "dest", "action"}),
			add: func(f map[string]string, count int) bool {
				dest, ok := entityOf("dest", f["dest"], nil)
				if !ok {
					return false
				}
				linked := false
				if u, ok := entityOf("user", f["user"], nil); ok {
					linked = st.activityEdge(u, dest, "login", f["action"], count)
				}
				if s, ok := entityOf("src", f["src"], nil); ok {
					linked = st.activityEdge(s, dest, "login", f["action"], count) || linked
				}
				return linked
			}})
	}
	if len(procs) > 0 && len(systems) > 0 {
		q := st.activityQuery("Endpoint", &query.And{Children: []query.Expr{
			anyOf(in("dest", systems), in("host", systems)),
			anyOf(in("process_name", procs), in("parent_process_name", procs)),
		}}, []string{"dest", "parent_process_name", "process_name"})
		parts = append(parts, part{kind: "process", what: "process starts", fields: []string{"dest", "parent_process_name", "process_name"}, q: q,
			add: func(f map[string]string, count int) bool {
				child, ok := entityOf("process_name", f["process_name"], nil)
				if !ok {
					return false
				}
				// The parent draws the tree; the system only when there
				// is no parent.
				if p, ok := entityOf("parent_process_name", f["parent_process_name"], nil); ok {
					return st.activityEdge(p, child, "started", "", count)
				}
				h, ok := entityOf("dest", f["dest"], nil)
				return ok && st.activityEdge(h, child, "ran", "", count)
			}})
	}
	if len(ips) > 1 || len(seedIPs) > 0 {
		// Connections between the story's addresses; for an address the
		// analyst follows, every connection to or from it.
		var es []query.Expr
		if len(ips) > 1 {
			es = append(es, &query.And{Children: []query.Expr{in("src", ips), in("dest", ips)}})
		}
		if len(seedIPs) > 0 {
			es = append(es, in("src", seedIPs), in("dest", seedIPs))
		}
		parts = append(parts, part{kind: "connection", what: "connections", fields: []string{"src", "dest", "dest_port", "action"},
			q: st.activityQuery("Network_Traffic", anyOf(es...), []string{"src", "dest", "dest_port", "action"}),
			add: func(f map[string]string, count int) bool {
				s, ok1 := entityOf("src", f["src"], nil)
				d, ok2 := entityOf("dest", f["dest"], nil)
				return ok1 && ok2 && st.activityEdge(s, d, "connected", f["dest_port"], count)
			}})
	}
	for _, p := range parts {
		st.Searches[p.kind] = p.q.String()
		rows, err := run(ctx, p.q)
		if err != nil {
			if ctx.Err() != nil {
				st.Warnings = append(st.Warnings, "Stopped before reading "+p.what+": the storyline took too long.")
				return
			}
			st.Warnings = append(st.Warnings, "Couldn’t read "+p.what+": "+err.Error())
			continue
		}
		if len(rows) > MaxActivity {
			rows = rows[:MaxActivity]
			st.Truncated = append(st.Truncated, p.kind)
		}
		for _, row := range rows {
			a := Activity{Kind: p.kind, Fields: map[string]string{}, First: timeOf(row["first"]), Last: timeOf(row["last"])}
			c, _ := num(row["count"])
			a.Count = int(c)
			for _, f := range p.fields {
				if v := str(row[f]); v != "" {
					a.Fields[f] = v
				}
			}
			// Rows that touch nothing in the story are left out.
			if p.add(a.Fields, a.Count) {
				st.Activity = append(st.Activity, a)
			}
		}
	}
}

// activityEdge links two entities through activity. Activity only links
// entities: a new one joins the graph when it touches one already there,
// so a busy server does not bring every account that signed in to it.
func (st *story) activityEdge(from, to Entity, kind, label string, count int) bool {
	_, a := st.nodes[from.Key()]
	_, b := st.nodes[to.Key()]
	if !a && !b {
		return false
	}
	st.node(from)
	st.node(to)
	st.edge(from.Key(), to.Key(), kind, label, count)
	return true
}

// finish orders and caps everything, adds context and builds the phases.
func (st *story) finish(lists *assets.Store) {
	sort.SliceStable(st.Items, func(i, j int) bool { return st.Items[i].Time.Before(st.Items[j].Time) })

	// Nodes: seeds first, then by how much of the story they are in.
	degree := map[string]int{}
	for _, e := range st.edges {
		degree[e.From] += e.Count
		degree[e.To] += e.Count
	}
	ns := make([]*Node, 0, len(st.nodes))
	for _, n := range st.nodes {
		ns = append(ns, n)
	}
	score := func(n *Node) float64 { return float64(n.Findings*10+n.weight*3+degree[n.ID]) + n.Risk }
	sort.Slice(ns, func(i, j int) bool {
		if ns[i].Seed != ns[j].Seed {
			return ns[i].Seed
		}
		if si, sj := score(ns[i]), score(ns[j]); si != sj {
			return si > sj
		}
		return ns[i].ID < ns[j].ID
	})
	if len(ns) > MaxNodes {
		ns = ns[:MaxNodes]
		st.Truncated = append(st.Truncated, "nodes")
	}
	kept := map[string]bool{}
	for _, n := range ns {
		kept[n.ID] = true
		if lists != nil && n.Type != Process && n.Type != Other {
			field := "dest"
			if n.Type == User {
				field = "user"
			}
			if c, ok := lists.Lookup(field, n.Value); ok {
				n.Context = c
			}
		}
		st.Nodes = append(st.Nodes, *n)
	}
	var es []*Edge
	for _, e := range st.edges {
		if kept[e.From] && kept[e.To] {
			es = append(es, e)
		}
	}
	sort.Slice(es, func(i, j int) bool {
		if es[i].Count != es[j].Count {
			return es[i].Count > es[j].Count
		}
		return es[i].From+es[i].To+es[i].Kind+es[i].Label < es[j].From+es[j].To+es[j].Kind+es[j].Label
	})
	if len(es) > MaxEdges {
		es = es[:MaxEdges]
		st.Truncated = append(st.Truncated, "edges")
	}
	for _, e := range es {
		st.Edges = append(st.Edges, *e)
	}
	for i := range st.Items {
		st.Items[i].Entities = slices.DeleteFunc(st.Items[i].Entities, func(id string) bool { return !kept[id] })
	}

	// Phases, in the order of the ATT&CK matrix; items with no tactic last.
	phase := map[string]*Phase{}
	add := func(tac string, it Item) {
		p := phase[tac]
		if p == nil {
			p = &Phase{Tactic: tac, First: it.Time, Name: "No ATT&CK tactic"}
			phase[tac] = p
		}
		p.Items++
		if it.Time.Before(p.First) {
			p.First = it.Time
		}
		if it.Time.After(p.Last) {
			p.Last = it.Time
		}
		if rank(it.Severity) > rank(p.Severity) {
			p.Severity = it.Severity
		}
	}
	for _, it := range st.Items {
		if len(it.Tactics) == 0 {
			add("", it)
		}
		for _, t := range it.Tactics {
			add(t, it)
		}
	}
	for _, t := range detect.ATTACK().Tactics {
		if p := phase[t.Short]; p != nil {
			p.ID, p.Name = t.ID, t.Name
			st.Phases = append(st.Phases, *p)
			delete(phase, t.Short)
		}
	}
	// Tactic names the matrix does not know, then the items with none.
	var rest []string
	for t := range phase {
		if t != "" {
			rest = append(rest, t)
		}
	}
	sort.Strings(rest)
	for _, t := range rest {
		p := phase[t]
		p.Name = t
		st.Phases = append(st.Phases, *p)
	}
	if p := phase[""]; p != nil {
		st.Phases = append(st.Phases, *p)
	}
}

// ordered puts tactic short names in the order of the ATT&CK matrix,
// unknown ones last.
func ordered(tactics []string) []string {
	if len(tactics) == 0 {
		return nil
	}
	pos := map[string]int{}
	for i, t := range detect.ATTACK().Tactics {
		pos[t.Short] = i
	}
	out := slices.Clone(tactics)
	slices.SortStableFunc(out, func(a, b string) int {
		pa, oka := pos[a]
		pb, okb := pos[b]
		switch {
		case oka && okb:
			return pa - pb
		case oka:
			return -1
		case okb:
			return 1
		}
		return strings.Compare(a, b)
	})
	return slices.Compact(out)
}

func rank(sev string) int { return slices.Index(findings.Severities, sev) }

// str reads a single value from a row cell.
func str(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return x
	case []any:
		if len(x) > 0 {
			return str(x[0])
		}
		return ""
	case []string:
		if len(x) > 0 {
			return x[0]
		}
		return ""
	case json.Number:
		return x.String()
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	}
	return fmt.Sprint(v)
}

// strs reads a multivalue cell.
func strs(v any) []string {
	switch x := v.(type) {
	case nil:
		return nil
	case []string:
		return x
	case []any:
		var out []string
		for _, e := range x {
			if s := str(e); s != "" {
				out = append(out, s)
			}
		}
		return out
	}
	if s := str(v); s != "" {
		return []string{s}
	}
	return nil
}

func num(v any) (float64, bool) {
	switch x := v.(type) {
	case float64:
		return x, true
	case int:
		return float64(x), true
	case int64:
		return float64(x), true
	case json.Number:
		f, err := x.Float64()
		return f, err == nil
	case string:
		f, err := strconv.ParseFloat(x, 64)
		return f, err == nil
	}
	return 0, false
}

// timeOf reads a time from a cell: text, or epoch seconds as min and
// max of _time return them.
func timeOf(v any) time.Time {
	if s, ok := v.(string); ok {
		for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04:05.000Z0700", "2006-01-02 15:04:05"} {
			if t, err := time.Parse(layout, s); err == nil {
				return t.UTC()
			}
		}
	}
	if f, ok := num(v); ok && f > 0 {
		return time.Unix(0, int64(f*1e9)).UTC()
	}
	return time.Time{}
}
