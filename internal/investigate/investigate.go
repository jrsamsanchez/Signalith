// Package investigate runs Investigate with AI on a finding. It gathers
// the finding's events, where its users, hosts and addresses show up,
// threat intel matches and related findings; lets an AI model run a few
// more read-only searches; and returns the model's verdict with a
// timeline and the evidence behind it.
//
// It changes nothing. The query language has no command that writes, and
// response actions the model suggests are only suggestions: a person
// reviews and runs them on the Respond dialog. Values of masked fields
// are replaced before anything is sent (see Masker).
package investigate

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/jrsamsanchez/signalith/internal/assistant"
	"github.com/jrsamsanchez/signalith/internal/findings"
	"github.com/jrsamsanchez/signalith/internal/intel"
	"github.com/jrsamsanchez/signalith/internal/query"
	"github.com/jrsamsanchez/signalith/internal/respond"
	"github.com/jrsamsanchez/signalith/internal/search"
)

// Limits keep what is sent, and what the model can ask for, small.
const (
	MaxRounds       = 3  // turns in which the model may ask for searches
	MaxPerRound     = 3  // searches per turn
	MaxSearches     = 8  // searches the model may ask for in all
	MaxEntities     = 5  // entities whose history is gathered
	RowsSent        = 10 // rows of each search sent to the model
	MaxValueLen     = 300
	MaxRawLen       = 800
	MaxSpan         = 31 * 24 * time.Hour // the widest time range a search may cover
	searchTimeout   = 30 * time.Second
	historyBefore   = 7 * 24 * time.Hour
	historyAfter    = 24 * time.Hour
	maxReplyTokens  = 4000
	maxRelated      = 10
	maxSuggestions  = 5
	maxTimelineRows = 20
)

// Verdicts the model may give.
const (
	VerdictReal   = "real"
	VerdictBenign = "benign"
	VerdictUnsure = "unsure"
)

// Model is the AI model; *assistant.Client is one.
type Model interface {
	Chat(ctx context.Context, system string, msgs []assistant.Message, maxTokens int) (string, error)
	Name() string
}

// Searcher runs a query; *search.Engine is one.
type Searcher interface {
	Execute(ctx context.Context, q *query.Query) (*search.Result, error)
}

// Investigator investigates findings.
type Investigator struct {
	Model    Model
	Search   Searcher
	Findings findings.Store // for related findings; may be nil
	Intel    *intel.Store   // may be nil
	// Actions are the response actions the model may suggest.
	Actions []respond.Info
	// Mask lists the fields whose values are never sent (assistant.mask_fields).
	Mask []string
	Now  func() time.Time
}

// Step is one piece of evidence: a search, threat intel matches or
// related findings. Rows are what the model was sent, with masked
// values as their stand-ins.
type Step struct {
	N     int    `json:"n"`
	Kind  string `json:"kind"` // search, intel, findings
	Title string `json:"title"`
	// By is "signalith" for what is always gathered, "ai" for a search
	// the model asked for.
	By       string           `json:"by"`
	Why      string           `json:"why,omitempty"`
	Query    string           `json:"query,omitempty"`
	Earliest string           `json:"earliest,omitempty"`
	Latest   string           `json:"latest,omitempty"`
	Matched  int64            `json:"matched"`
	Columns  []string         `json:"columns,omitempty"`
	Rows     []map[string]any `json:"rows,omitempty"`
	More     bool             `json:"more,omitempty"` // more rows than were sent
	Error    string           `json:"error,omitempty"`
}

// TimelineItem is one moment in the model's account of what happened.
type TimelineItem struct {
	Time string `json:"time"`
	Text string `json:"text"`
}

// Evidence is one point the verdict rests on, with the steps behind it.
type Evidence struct {
	Text  string `json:"text"`
	Steps []int  `json:"steps,omitempty"`
}

// Suggestion is a response action the model suggests. It is never run
// by Signalith; an analyst reviews it on the Respond dialog.
type Suggestion struct {
	Action string `json:"action"`
	Label  string `json:"label"`
	Target string `json:"target"`
	Reason string `json:"reason"`
}

// Result is a finished investigation.
type Result struct {
	FindingID  string         `json:"finding_id"`
	Verdict    string         `json:"verdict"`
	Confidence string         `json:"confidence"`
	Summary    string         `json:"summary"`
	Timeline   []TimelineItem `json:"timeline"`
	Evidence   []Evidence     `json:"evidence"`
	Actions    []Suggestion   `json:"actions"`
	NextSteps  []string       `json:"next_steps"`
	Steps      []Step         `json:"steps"`
	Model      string         `json:"model"`
	Masked     []string       `json:"masked"`
	// Sent is how many characters went to the model in all.
	Sent     int       `json:"sent"`
	Started  time.Time `json:"started"`
	Finished time.Time `json:"finished"`
}

// Preview is what the first message to the model would hold, for the
// analyst to read before anything is sent.
type Preview struct {
	Model   string   `json:"model"`
	System  string   `json:"system"`
	Message string   `json:"message"`
	Masked  []string `json:"masked"`
	Steps   []Step   `json:"steps"`
}

// Event reports progress while an investigation runs.
type Event struct {
	Type   string  `json:"type"` // step, status, result, error
	Text   string  `json:"text,omitempty"`
	Step   *Step   `json:"step,omitempty"`
	Result *Result `json:"result,omitempty"`
}

// run is one investigation's state.
type run struct {
	inv   *Investigator
	f     *findings.Finding
	mask  *Masker
	steps []Step
	emit  func(Event)
	// from and to bound the searches gathered by default.
	from, to time.Time
}

func (inv *Investigator) now() time.Time {
	if inv.Now != nil {
		return inv.Now()
	}
	return time.Now()
}

func (inv *Investigator) start(f *findings.Finding, emit func(Event)) *run {
	if emit == nil {
		emit = func(Event) {}
	}
	at := f.Created
	if at.IsZero() {
		at = inv.now()
	}
	r := &run{inv: inv, f: f, mask: NewMasker(inv.Mask), emit: emit, from: at.Add(-historyBefore), to: at.Add(historyAfter)}
	if now := inv.now(); r.to.After(now) {
		r.to = now
	}
	return r
}

// Preview gathers the evidence and returns the first message exactly as
// Run would send it.
func (inv *Investigator) Preview(ctx context.Context, f *findings.Finding) (*Preview, error) {
	r := inv.start(f, nil)
	r.gather(ctx)
	msg := r.firstMessage()
	return &Preview{Model: inv.Model.Name(), System: inv.systemPrompt(), Message: msg, Masked: r.mask.Fields(), Steps: r.steps}, nil
}

// Run investigates a finding, reporting each step through emit.
func (inv *Investigator) Run(ctx context.Context, f *findings.Finding, emit func(Event)) (*Result, error) {
	r := inv.start(f, emit)
	res := &Result{FindingID: f.ID, Model: inv.Model.Name(), Masked: r.mask.Fields(), Started: inv.now().UTC()}
	r.emit(Event{Type: "status", Text: "Gathering the finding's events and history"})
	r.gather(ctx)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	system := inv.systemPrompt()
	msgs := []assistant.Message{{Role: "user", Content: r.firstMessage()}}
	res.Sent = len(system) + len(msgs[0].Content)
	asked := 0
	for turn := 0; ; turn++ {
		r.emit(Event{Type: "status", Text: "Asking " + inv.Model.Name()})
		text, err := inv.Model.Chat(ctx, system, msgs, maxReplyTokens)
		if err != nil {
			return nil, err
		}
		msgs = append(msgs, assistant.Message{Role: "assistant", Content: text})
		var rep reply
		if err := decode(text, &rep); err != nil {
			if turn > MaxRounds {
				return nil, fmt.Errorf("the AI model did not reply in the expected form: %v", err)
			}
			next := fmt.Sprintf("That was not one JSON object as asked (%v). Reply again with the JSON object only.", err)
			msgs = append(msgs, assistant.Message{Role: "user", Content: next})
			res.Sent += len(next)
			continue
		}
		if rep.Verdict == "" && len(rep.Searches) > 0 && turn < MaxRounds && asked < MaxSearches {
			var b strings.Builder
			for i, s := range rep.Searches {
				if asked >= MaxSearches || i >= MaxPerRound {
					break
				}
				asked++
				st := r.followUp(ctx, s)
				b.WriteString(r.describe(st))
			}
			left := MaxRounds - turn - 1
			if asked >= MaxSearches {
				left = 0
			}
			if left > 0 {
				fmt.Fprintf(&b, "\nYou may ask for more searches in %d more turn(s), or give your verdict.", left)
			} else {
				b.WriteString("\nNo more searches are possible: give your verdict now.")
			}
			next := r.mask.Text(b.String())
			msgs = append(msgs, assistant.Message{Role: "user", Content: next})
			res.Sent += len(next)
			continue
		}
		if rep.Verdict == "" {
			if turn > MaxRounds {
				return nil, errors.New("the AI model gave no verdict")
			}
			next := "No more searches are possible: give your verdict now, as the JSON object described."
			msgs = append(msgs, assistant.Message{Role: "user", Content: next})
			res.Sent += len(next)
			continue
		}
		r.finish(res, rep)
		break
	}
	res.Steps = r.steps
	res.Finished = inv.now().UTC()
	return res, nil
}

// ---- gathering ----

// gather runs what every investigation starts with.
func (r *run) gather(ctx context.Context) {
	f := r.f
	// Masked entity values get their stand-ins first, so they are hidden
	// everywhere they appear from the first message on.
	for k, v := range f.Entities {
		r.mask.Value(k, v)
	}
	for k, v := range f.Result {
		r.mask.Value(k, v)
	}
	if strings.TrimSpace(f.Query) != "" {
		earliest, latest := f.Earliest, f.Latest
		if earliest == "" && latest == "" {
			earliest, latest = stamp(r.from), stamp(r.to)
		}
		r.search(ctx, Step{Title: "Events behind the finding", By: "signalith", Query: f.Query, Earliest: earliest, Latest: latest})
	}
	for _, e := range r.entities() {
		r.search(ctx, Step{Title: "Where " + e.label + " shows up, 7 days before to 1 day after", By: "signalith",
			Query: e.filter + "\n| stats count by datamodel, sourcetype\n| sort -count", Earliest: stamp(r.from), Latest: stamp(r.to)})
	}
	r.intelMatches()
	r.related(ctx)
}

type entity struct{ label, filter string }

// entities are the finding's users, hosts and addresses, with a search
// filter for each that also finds them in other roles (an IP as src or
// dest).
func (r *run) entities() []entity {
	keys := make([]string, 0, len(r.f.Entities))
	for k := range r.f.Entities {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var out []entity
	seen := map[string]bool{}
	for _, k := range keys {
		if k == "risk_object_type" {
			continue
		}
		for _, v := range values(r.f.Entities[k]) {
			if v == "" || seen[strings.ToLower(v)] || len(out) >= MaxEntities {
				continue
			}
			seen[strings.ToLower(v)] = true
			kind := k
			if k == "risk_object" {
				kind = "dest"
				if t, _ := r.f.Entities["risk_object_type"].(string); t == "user" {
					kind = "user"
				}
			}
			q := quote(v)
			var filter string
			switch {
			case isAddr(v):
				filter = fmt.Sprintf("src=%s OR dest=%s OR host=%s", q, q, q)
			case kind == "user" || kind == "src_user":
				filter = fmt.Sprintf("user=%s OR src_user=%s", q, q)
			case kind == "dest" || kind == "host" || kind == "src" || kind == "dvc":
				filter = fmt.Sprintf("dest=%s OR host=%s OR src=%s", q, q, q)
			default:
				filter = fmt.Sprintf("%s=%s", k, q)
			}
			out = append(out, entity{label: k + " " + v, filter: filter})
		}
	}
	return out
}

func values(v any) []string {
	switch x := v.(type) {
	case nil:
		return nil
	case []any:
		var out []string
		for _, e := range x {
			out = append(out, values(e)...)
		}
		return out
	case []string:
		return x
	}
	return []string{strings.TrimSpace(fmt.Sprint(v))}
}

func isAddr(v string) bool {
	_, err := netip.ParseAddr(v)
	return err == nil
}

// search runs one search step and records it.
func (r *run) search(ctx context.Context, st Step) Step {
	st.Kind = "search"
	q, err := query.Parse(st.Query)
	if err == nil {
		if q.Earliest == "" {
			q.Earliest = st.Earliest
		}
		if q.Latest == "" {
			q.Latest = st.Latest
		}
		st.Earliest, st.Latest = q.Earliest, q.Latest
		shown := *q
		shown.Earliest, shown.Latest = "", ""
		st.Query = shown.String()
		sctx, cancel := context.WithTimeout(ctx, searchTimeout)
		var res *search.Result
		res, err = r.inv.Search.Execute(sctx, q)
		cancel()
		if err == nil {
			st.Matched = res.Matched
			if st.Matched == 0 {
				st.Matched = int64(len(res.Rows))
			}
			st.Columns = res.Columns
			for i, row := range res.Rows {
				if i >= RowsSent {
					st.More = true
					break
				}
				st.Rows = append(st.Rows, r.trim(r.mask.Row(row)))
			}
		}
	}
	if err != nil {
		st.Error = err.Error()
	}
	return r.add(st)
}

// trim shortens long values.
func (r *run) trim(row map[string]any) map[string]any {
	for k, v := range row {
		s, ok := v.(string)
		if !ok {
			continue
		}
		limit := MaxValueLen
		if k == "_raw" {
			limit = MaxRawLen
		}
		if len(s) > limit {
			row[k] = cut(s, limit) + "…"
		}
	}
	return row
}

func cut(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8Start(s[n]) {
		n--
	}
	return s[:n]
}

func utf8Start(b byte) bool { return b&0xC0 != 0x80 }

func (r *run) add(st Step) Step {
	st.N = len(r.steps) + 1
	r.steps = append(r.steps, st)
	r.emit(Event{Type: "step", Step: &st})
	return st
}

// intelMatches looks up the finding's values in threat intel.
func (r *run) intelMatches() {
	if r.inv.Intel == nil {
		return
	}
	st := Step{Kind: "intel", Title: "Threat intel matches", By: "signalith", Columns: []string{"field", "value", "type", "source", "description", "weight"}}
	seen := map[string]bool{}
	look := func(field string, v any) {
		for _, s := range values(v) {
			if s == "" || len(s) > 2048 || seen[s] {
				continue
			}
			seen[s] = true
			for _, ind := range r.inv.Intel.Lookup(s) {
				st.Matched++
				if len(st.Rows) < RowsSent {
					st.Rows = append(st.Rows, r.mask.Row(map[string]any{"field": field, "value": s, "type": ind.Type, "source": ind.Source,
						"description": cut(ind.Description, MaxValueLen), "weight": ind.Weight}))
				} else {
					st.More = true
				}
			}
		}
	}
	for _, k := range sortedKeys(r.f.Entities) {
		look(k, r.f.Entities[k])
	}
	for _, k := range sortedKeys(r.f.Result) {
		if k != "_raw" && k != "_time" {
			look(k, r.f.Result[k])
		}
	}
	// The value column holds the real value for intel; mask it like the
	// field it came from.
	for _, row := range st.Rows {
		if f, _ := row["field"].(string); f != "" {
			row["value"] = r.mask.Value(f, row["value"])
		}
	}
	r.add(st)
}

func sortedKeys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// related lists other findings about the same entities.
func (r *run) related(ctx context.Context) {
	if r.inv.Findings == nil {
		return
	}
	var vals []string
	for k, v := range r.f.Entities {
		if k != "risk_object_type" {
			vals = append(vals, values(v)...)
		}
	}
	st := Step{Kind: "findings", Title: "Other findings about the same users, hosts and addresses, 7 days before to 1 day after", By: "signalith",
		Columns: []string{"id", "title", "severity", "status", "disposition", "created", "entities"}}
	if len(vals) == 0 {
		return
	}
	list, _, err := r.inv.Findings.Search(ctx, findings.Filter{EntityValues: vals, Since: r.from, Limit: maxRelated + 1})
	if err != nil {
		st.Error = err.Error()
	}
	for _, x := range list {
		if x.ID == r.f.ID || x.Created.After(r.to) {
			continue
		}
		st.Matched++
		if len(st.Rows) >= maxRelated {
			st.More = true
			continue
		}
		ents := map[string]any{}
		for k, v := range x.Entities {
			if k != "risk_object_type" {
				ents[k] = r.mask.Value(k, v)
			}
		}
		st.Rows = append(st.Rows, map[string]any{"id": x.ID, "title": x.Title, "severity": x.Severity, "status": x.Status,
			"disposition": x.Disposition, "created": stamp(x.Created), "entities": ents})
	}
	r.add(st)
}

// followUp runs a search the model asked for.
func (r *run) followUp(ctx context.Context, s askedSearch) Step {
	st := Step{Title: strings.TrimSpace(s.Why), By: "ai", Why: strings.TrimSpace(s.Why), Query: r.mask.Query(strings.TrimSpace(s.Query))}
	if st.Title == "" {
		st.Title = "A search the AI model asked for"
	}
	st.Title = cut(st.Title, 200)
	from, to := r.from, r.to
	if t, err := time.Parse(time.RFC3339, strings.TrimSpace(s.Earliest)); err == nil {
		from = t
	}
	if t, err := time.Parse(time.RFC3339, strings.TrimSpace(s.Latest)); err == nil {
		to = t
	}
	if !to.After(from) {
		from, to = r.from, r.to
	}
	if to.Sub(from) > MaxSpan {
		from = to.Add(-MaxSpan)
	}
	st.Earliest, st.Latest = stamp(from), stamp(to)
	if q, err := query.Parse(st.Query); err == nil && (q.Earliest != "" || q.Latest != "") {
		// Times in the query itself are relative to now; the ones given
		// alongside are kept to so a search cannot cover more than MaxSpan.
		q.Earliest, q.Latest = "", ""
		st.Query = q.String()
	}
	if strings.TrimSpace(st.Query) == "" {
		st.Kind = "search"
		st.Error = "no query was given"
		return r.add(st)
	}
	return r.search(ctx, st)
}

func stamp(t time.Time) string { return t.UTC().Format(time.RFC3339) }

// ---- talking to the model ----

type askedSearch struct {
	Why      string `json:"why"`
	Query    string `json:"query"`
	Earliest string `json:"earliest"`
	Latest   string `json:"latest"`
}

type reply struct {
	Searches   []askedSearch  `json:"searches"`
	Verdict    string         `json:"verdict"`
	Confidence string         `json:"confidence"`
	Summary    string         `json:"summary"`
	Timeline   []TimelineItem `json:"timeline"`
	Evidence   []Evidence     `json:"evidence"`
	Actions    []Suggestion   `json:"actions"`
	NextSteps  []string       `json:"next_steps"`
}

// decode reads the JSON object in a reply, ignoring code fences and any
// words around it.
func decode(s string, v any) error {
	i, j := strings.Index(s, "{"), strings.LastIndex(s, "}")
	if i < 0 || j < i {
		return errors.New("no JSON object found")
	}
	return json.Unmarshal([]byte(s[i:j+1]), v)
}

func (inv *Investigator) systemPrompt() string {
	var b strings.Builder
	fmt.Fprintf(&b, `You help a security analyst investigate one finding (an alert) in Signalith, a SIEM. Decide whether it is likely a real threat, likely benign, or unclear, and show the evidence. You cannot change anything: you can only ask for read-only searches.

Reply every time with one JSON object and nothing else.

To run more searches (at most %d per turn, %d in all, in up to %d turns):
{"searches": [{"why": "what this checks, in a few words", "query": "<Signalith query>", "earliest": "<RFC 3339 time, optional>", "latest": "<RFC 3339 time, optional>"}]}
Without earliest and latest a search covers 7 days before the finding to 1 day after it. A search covers at most 31 days. Write times with earliest and latest in the JSON, not in the query.

When you have enough evidence, reply with your verdict:
{"verdict": "real" | "benign" | "unsure",
 "confidence": "low" | "medium" | "high",
 "summary": "two to four plain sentences: what happened and why you think so",
 "timeline": [{"time": "<RFC 3339>", "text": "what happened"}],
 "evidence": [{"text": "one fact the verdict rests on", "steps": [<step numbers>]}],
 "actions": [{"action": "<name from the list of response actions>", "target": "<value to act on>", "reason": "why"}],
 "next_steps": ["what a person should check next"]}

Rules:
- Base every claim on the data shown, and cite the step numbers it came from. Say "unsure" when the data is thin or points both ways.
- Values like masked-user-1 stand in for values that are hidden from you. Use them as they are in queries; never guess the real value.
- Suggest response actions only when the verdict is real, and only from the list given; leave "actions" empty otherwise. A person reviews and runs them.
- Keep the timeline to the events that matter, in time order, at most %d entries.
- Plain language for a busy analyst. No markdown.

`, MaxPerRound, MaxSearches, MaxRounds, maxTimelineRows)
	b.WriteString(assistant.QueryReference())
	return b.String()
}

// firstMessage describes the finding and the evidence gathered.
func (r *run) firstMessage() string {
	f := r.f
	var b strings.Builder
	b.WriteString("## The finding\n")
	fmt.Fprintf(&b, "Title: %s\n", f.Title)
	if f.Description != "" {
		fmt.Fprintf(&b, "Description: %s\n", cut(f.Description, 2000))
	}
	fmt.Fprintf(&b, "Detection: %s\nSeverity: %s\n", f.DetectionID, f.Severity)
	if f.Urgency != "" && f.Urgency != f.Severity {
		fmt.Fprintf(&b, "Urgency (severity adjusted for asset and user priority): %s\n", f.Urgency)
	}
	fmt.Fprintf(&b, "Raised: %s\n", stamp(f.Created))
	if f.Earliest != "" || f.Latest != "" {
		fmt.Fprintf(&b, "Window the detection searched: %s to %s\n", f.Earliest, f.Latest)
	}
	if len(f.MITRE) > 0 {
		fmt.Fprintf(&b, "MITRE ATT&CK: %s\n", strings.Join(f.MITRE, ", "))
	}
	if len(f.Entities) > 0 {
		ents := map[string]any{}
		for k, v := range f.Entities {
			ents[k] = r.mask.Value(k, v)
		}
		fmt.Fprintf(&b, "Entities: %s\n", compact(ents))
	}
	for _, k := range sortedKeys(contextMap(f)) {
		c := f.Context[k]
		var bits []string
		if c.Priority != "" {
			bits = append(bits, "priority "+c.Priority)
		}
		if c.BUnit != "" {
			bits = append(bits, "business unit "+c.BUnit)
		}
		if len(c.Category) > 0 {
			bits = append(bits, "category "+strings.Join(c.Category, ", "))
		}
		if c.Watchlist {
			bits = append(bits, "on the watchlist")
		}
		if len(bits) > 0 {
			fmt.Fprintf(&b, "Context for %s: %s\n", k, strings.Join(bits, "; "))
		}
	}
	if len(f.Result) > 0 {
		fmt.Fprintf(&b, "The result row that fired: %s\n", compact(r.trim(r.mask.Row(f.Result))))
	}
	if len(r.f.Comments) > 0 {
		b.WriteString("Analyst notes so far:\n")
		for _, c := range r.f.Comments {
			fmt.Fprintf(&b, "- %s\n", cut(c.Text, 500))
		}
	}
	b.WriteString("\n## Response actions that can be suggested\n")
	n := 0
	for _, a := range r.inv.Actions {
		if a.Problem != "" {
			continue
		}
		n++
		fmt.Fprintf(&b, "- %s: %s (acts on: %s)\n", a.Name, strings.ReplaceAll(a.What, "{target}", "the target"), a.Target)
	}
	if n == 0 {
		b.WriteString("None are set up; leave \"actions\" empty.\n")
	}
	b.WriteString("\n## Evidence gathered\n")
	for _, st := range r.steps {
		b.WriteString(r.describe(st))
	}
	fmt.Fprintf(&b, "\nNow ask for up to %d searches, or give your verdict.", MaxPerRound)
	return r.mask.Text(b.String())
}

func contextMap(f *findings.Finding) map[string]any {
	m := map[string]any{}
	for k, c := range f.Context {
		if c != nil {
			m[k] = c
		}
	}
	return m
}

// describe writes one step for the model.
func (r *run) describe(st Step) string {
	var b strings.Builder
	fmt.Fprintf(&b, "\n### Step %d: %s\n", st.N, st.Title)
	if st.Query != "" {
		fmt.Fprintf(&b, "Query: %s\n", strings.ReplaceAll(st.Query, "\n", " "))
		fmt.Fprintf(&b, "Time: %s to %s\n", st.Earliest, st.Latest)
	}
	if st.Error != "" {
		fmt.Fprintf(&b, "Failed: %s\n", st.Error)
		return b.String()
	}
	if len(st.Rows) == 0 {
		b.WriteString("Nothing found.\n")
		return b.String()
	}
	if st.More {
		fmt.Fprintf(&b, "%d matched; the first %d rows:\n", st.Matched, len(st.Rows))
	} else if st.Kind == "search" && st.Matched > int64(len(st.Rows)) {
		fmt.Fprintf(&b, "%d events matched:\n", st.Matched)
	}
	for _, row := range st.Rows {
		b.WriteString(compact(row) + "\n")
	}
	return b.String()
}

// compact renders a value as one line of JSON.
func compact(v any) string {
	data, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprint(v)
	}
	return string(data)
}

// finish checks the model's verdict and turns stand-ins back into real
// values for the analyst.
func (r *run) finish(res *Result, rep reply) {
	reveal := r.mask.Reveal
	res.Verdict = strings.ToLower(strings.TrimSpace(rep.Verdict))
	switch res.Verdict {
	case VerdictReal, VerdictBenign, VerdictUnsure:
	case "malicious", "true_positive", "likely_real":
		res.Verdict = VerdictReal
	case "false_positive", "likely_benign":
		res.Verdict = VerdictBenign
	default:
		res.Verdict = VerdictUnsure
	}
	res.Confidence = strings.ToLower(strings.TrimSpace(rep.Confidence))
	if !slices.Contains([]string{"low", "medium", "high"}, res.Confidence) {
		res.Confidence = "low"
	}
	res.Summary = reveal(cut(strings.TrimSpace(rep.Summary), 3000))
	res.Timeline = []TimelineItem{}
	for _, t := range rep.Timeline {
		if strings.TrimSpace(t.Text) == "" || len(res.Timeline) >= maxTimelineRows {
			continue
		}
		res.Timeline = append(res.Timeline, TimelineItem{Time: cut(strings.TrimSpace(t.Time), 40), Text: reveal(cut(strings.TrimSpace(t.Text), 500))})
	}
	sort.SliceStable(res.Timeline, func(i, j int) bool { return res.Timeline[i].Time < res.Timeline[j].Time })
	res.Evidence = []Evidence{}
	for _, e := range rep.Evidence {
		if strings.TrimSpace(e.Text) == "" || len(res.Evidence) >= 12 {
			continue
		}
		var steps []int
		for _, n := range e.Steps {
			if n >= 1 && n <= len(r.steps) && !slices.Contains(steps, n) {
				steps = append(steps, n)
			}
		}
		res.Evidence = append(res.Evidence, Evidence{Text: reveal(cut(strings.TrimSpace(e.Text), 600)), Steps: steps})
	}
	res.Actions = []Suggestion{}
	for _, a := range rep.Actions {
		if len(res.Actions) >= maxSuggestions {
			break
		}
		i := slices.IndexFunc(r.inv.Actions, func(x respond.Info) bool { return x.Name == strings.TrimSpace(a.Action) && x.Problem == "" })
		target := strings.Trim(reveal(strings.TrimSpace(a.Target)), `"`)
		if i < 0 || target == "" {
			continue // only actions that exist and can run
		}
		if r.inv.Actions[i].Target == "ip" && !isAddr(target) {
			continue // not an address: the model mixed up its values
		}
		res.Actions = append(res.Actions, Suggestion{Action: r.inv.Actions[i].Name, Label: r.inv.Actions[i].Label, Target: cut(target, 500),
			Reason: reveal(cut(strings.TrimSpace(a.Reason), 1000))})
	}
	res.NextSteps = []string{}
	for _, s := range rep.NextSteps {
		if s = strings.TrimSpace(s); s != "" && len(res.NextSteps) < 8 {
			res.NextSteps = append(res.NextSteps, reveal(cut(s, 500)))
		}
	}
}
