package search

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"runtime/debug"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jrsamsanchez/signalith/internal/assets"
	"github.com/jrsamsanchez/signalith/internal/intel"
	"github.com/jrsamsanchez/signalith/internal/lookuptables"
	"github.com/jrsamsanchez/signalith/internal/query"
	"github.com/jrsamsanchez/signalith/internal/store"
)

// Options tune query execution.
type Options struct {
	IndexPrefix     string // default "signalith"
	DefaultEarliest string // used when a query has no earliest=; "" means all time
	DefaultEvents   int    // events returned when no head is given (default 100)
	MaxEvents       int    // events fetched for in-memory post-processing (default 10000, at most 100000)
	MaxBuckets      int    // stats rows fetched before truncating (default 50000)
	// MaxSearches caps the searches running at once (default 8), apart
	// from the detection scheduler's (see Background). Each can hold up to
	// MaxEvents rows in memory and keep a CPU busy.
	MaxSearches int
	// QueueWait is how long a search waits for its turn before failing
	// with ErrBusy (default 15s).
	QueueWait time.Duration
}

// maxEventsLimit bounds MaxEvents however it is set.
const maxEventsLimit = 100000

// Engine runs queries.
type Engine struct {
	Store store.Searcher
	// Opt is set before use; SetDefaults changes it afterwards.
	Opt Options
	// Assets backs the enrich command; nil makes enrich an error.
	Assets *assets.Store
	// Intel backs the intel and threatmatch commands; nil makes them errors.
	Intel *intel.Store
	// Lookups backs the lookup command; nil makes it an error.
	Lookups *lookuptables.Store

	optMu   sync.RWMutex
	slotsMu sync.Mutex
	slots   chan struct{}
	perUser map[string]chan struct{}
}

// SetDefaults changes the default time range and the most events a
// search fetches, for searches that start after it returns.
func (e *Engine) SetDefaults(earliest string, maxEvents int) {
	e.optMu.Lock()
	defer e.optMu.Unlock()
	e.Opt.DefaultEarliest, e.Opt.MaxEvents = earliest, maxEvents
}

// ErrBusy is returned when MaxSearches searches are already running and
// none finished within QueueWait.
var ErrBusy = errors.New("Signalith is busy running other searches; try again in a few seconds")

// QueryError is a query that cannot run as written, such as one naming an
// index outside Signalith's events, as opposed to OpenSearch failing; the
// API answers it with 400.
type QueryError struct{ Msg string }

func (e *QueryError) Error() string { return e.Msg }

type backgroundKey struct{}

// Background marks ctx as the detection scheduler's own work. Those
// searches do not count against MaxSearches: the scheduler runs a bounded
// number of them itself, and busy analysts must not hold up detections.
func Background(ctx context.Context) context.Context {
	return context.WithValue(ctx, backgroundKey{}, true)
}

type userKey struct{}

// ForUser marks ctx as a signed-in user's work. One user's searches hold
// at most half of the MaxSearches slots at once, so one user (or one
// stolen sign-in) cannot keep everyone else waiting.
func ForUser(ctx context.Context, user string) context.Context {
	return context.WithValue(ctx, userKey{}, user)
}

// ErrUserBusy is returned when a user's own searches already hold their
// share of the slots and none finished within QueueWait.
var ErrUserBusy = errors.New("You already have several searches running; wait for one to finish, then try again")

// perUserSearches is how many of MaxSearches slots one user's searches
// may hold at once.
func perUserSearches(total int) int {
	return max(1, total/2)
}

// acquire waits for one of MaxSearches slots, and for one of the user's
// own share of them when ctx names a user (see ForUser), and returns the
// function that frees them.
func (e *Engine) acquire(ctx context.Context) (func(), error) {
	if bg, _ := ctx.Value(backgroundKey{}).(bool); bg {
		return func() {}, nil
	}
	o := e.opts()
	user, _ := ctx.Value(userKey{}).(string)
	e.slotsMu.Lock()
	if e.slots == nil {
		e.slots = make(chan struct{}, o.MaxSearches)
	}
	slots := e.slots
	var mine chan struct{}
	if user != "" {
		if e.perUser == nil {
			e.perUser = map[string]chan struct{}{}
		}
		if mine = e.perUser[user]; mine == nil {
			mine = make(chan struct{}, perUserSearches(cap(slots)))
			e.perUser[user] = mine
		}
	}
	e.slotsMu.Unlock()

	t := time.NewTimer(o.QueueWait)
	defer t.Stop()
	take := func(c chan struct{}, busy error) error {
		select {
		case c <- struct{}{}:
			return nil
		default:
		}
		select {
		case c <- struct{}{}:
			return nil
		case <-t.C:
			return busy
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if mine != nil {
		if err := take(mine, ErrUserBusy); err != nil {
			return nil, err
		}
	}
	if err := take(slots, ErrBusy); err != nil {
		if mine != nil {
			<-mine
		}
		return nil, err
	}
	return func() {
		<-slots
		if mine != nil {
			<-mine
		}
	}, nil
}

// Row is one result row.
type Row map[string]any

// Result is a query result.
type Result struct {
	Kind      string   `json:"kind"` // events, table, timechart
	Columns   []string `json:"columns"`
	Rows      []Row    `json:"rows"`
	Matched   int64    `json:"matched"` // events matching the search
	Truncated bool     `json:"truncated,omitempty"`
	TookMS    int64    `json:"took_ms"`
	// Drill finds the events behind the numbers in a summary; the search
	// API sets it.
	Drill *query.Drill `json:"drill,omitempty"`
}

// Plan is the OpenSearch request a query compiles to, for "show the
// OpenSearch query" in the UI and for tests.
type Plan struct {
	Index string         `json:"index"`
	Body  map[string]any `json:"body"`
	Mode  string         `json:"mode"` // events, stats, timechart, top, inputlookup, makeresults

	transform query.Command
	post      []query.Command
	threat    *query.ThreatMatch
}

func (e *Engine) opts() Options {
	e.optMu.RLock()
	o := e.Opt
	e.optMu.RUnlock()
	if o.IndexPrefix == "" {
		o.IndexPrefix = "signalith"
	}
	if o.DefaultEvents <= 0 {
		o.DefaultEvents = 100
	}
	if o.MaxEvents <= 0 {
		o.MaxEvents = 10000
	}
	if o.MaxBuckets <= 0 {
		o.MaxBuckets = 50000
	}
	o.MaxEvents = min(o.MaxEvents, maxEventsLimit)
	if o.MaxSearches <= 0 {
		o.MaxSearches = 8
	}
	if o.QueueWait <= 0 {
		o.QueueWait = 15 * time.Second
	}
	return o
}

// IndexPattern returns the index pattern for a query. Searches only reach
// Signalith's daily event and risk indices, "<prefix>-<model>-<day>":
// datamodel= must be a built-in data model, and index= one pattern under
// "<prefix>-". Everything else OpenSearch holds (Signalith's own findings,
// cases and intel in "<prefix>_*", other applications' indices, system
// indices, other clusters) is refused with a *QueryError, whoever asks and
// however the query arrived (search, dashboards, detections, the API).
func (e *Engine) IndexPattern(q *query.Query) (string, error) {
	o := e.opts()
	if q.Index != "" && q.Index != "*" {
		v := strings.ToLower(q.Index)
		if err := query.CheckIndex(v); err != nil {
			return "", &QueryError{Msg: err.Error()}
		}
		if !strings.HasPrefix(v, o.IndexPrefix+"-") {
			return "", &QueryError{Msg: fmt.Sprintf("index=%q is outside Signalith's events: index patterns must start with %q, for example %s-* or %s-authentication-*", q.Index, o.IndexPrefix+"-", o.IndexPrefix, o.IndexPrefix)}
		}
		return v, nil
	}
	if q.Datamodel != "" {
		if err := query.CheckDatamodel(q.Datamodel); err != nil {
			return "", &QueryError{Msg: err.Error()}
		}
		return o.IndexPrefix + "-" + strings.ToLower(q.Datamodel) + "-*", nil
	}
	// All data except risk events, which are derived from other events;
	// index=* means the same.
	return o.IndexPrefix + "-*,-" + o.IndexPrefix + "-risk-*", nil
}

// Compile builds the OpenSearch request for a query without running it.
func (e *Engine) Compile(q *query.Query) (*Plan, error) {
	p, err := e.compile(q)
	if err != nil {
		return nil, err
	}
	// A subsearch that does not compile fails the search before it runs.
	if err := e.compileSubsearches(p.post, q); err != nil {
		return nil, err
	}
	return p, nil
}

func (e *Engine) compileSubsearches(cmds []query.Command, q *query.Query) error {
	for _, c := range cmds {
		var sub *query.Query
		switch c := c.(type) {
		case *query.Join:
			sub = c.Sub
		case *query.Append:
			sub = c.Sub
		case *query.AppendPipe:
			if err := e.compileSubsearches(c.Commands, q); err != nil {
				return err
			}
		}
		if sub != nil {
			if _, err := e.Compile(subsearch(sub, q)); err != nil {
				return err
			}
		}
	}
	return nil
}

func (e *Engine) compile(q *query.Query) (*Plan, error) {
	o := e.opts()
	cmds := q.Commands
	if len(cmds) > 0 {
		if c, ok := cmds[0].(*query.InputLookup); ok {
			// The rows come from a lookup table, not from OpenSearch.
			return &Plan{Mode: "inputlookup", transform: c, post: cmds[1:]}, nil
		}
		if c, ok := cmds[0].(*query.MakeResults); ok {
			return &Plan{Mode: "makeresults", transform: c, post: cmds[1:]}, nil
		}
	}

	// where commands before any transforming command filter raw events, so
	// they run inside OpenSearch.
	filters := []query.Expr{}
	if q.Search != nil {
		filters = append(filters, q.Search)
	}
	for len(cmds) > 0 {
		w, ok := cmds[0].(*query.Where)
		if !ok {
			break
		}
		if _, expr := w.Expr.(*query.Cond); expr {
			break // runs in the server, over the events OpenSearch returns
		}
		filters = append(filters, w.Expr)
		cmds = cmds[1:]
	}
	// threatmatch right after the search becomes a filter too.
	var threat *query.ThreatMatch
	var threatDSL map[string]any
	if len(cmds) > 0 {
		if tm, ok := cmds[0].(*query.ThreatMatch); ok {
			var err error
			if threatDSL, err = e.threatFilter(tm); err != nil {
				return nil, err
			}
			threat = tm
			cmds = cmds[1:]
		}
	}
	if err := checkThreatMatch(cmds); err != nil {
		return nil, err
	}
	earliest := q.Earliest
	if earliest == "" {
		earliest = o.DefaultEarliest
	}
	var fs []any
	for _, f := range filters {
		c, err := compileExpr(f)
		if err != nil {
			return nil, err
		}
		fs = append(fs, c)
	}
	if threatDSL != nil {
		fs = append(fs, threatDSL)
	}
	timeRange := map[string]any{}
	if earliest != "" && earliest != "0" {
		timeRange["gte"] = toDateMath(earliest)
	}
	if q.Latest != "" {
		timeRange["lte"] = toDateMath(q.Latest)
	}
	if len(timeRange) > 0 {
		fs = append(fs, map[string]any{"range": map[string]any{TimeField: timeRange}})
	}
	var dsl map[string]any
	if len(fs) == 0 {
		dsl = map[string]any{"match_all": map[string]any{}}
	} else {
		dsl = boolQuery("filter", fs)
	}

	index, err := e.IndexPattern(q)
	if err != nil {
		return nil, err
	}
	if err := checkPatterns(q); err != nil {
		return nil, err
	}
	p := &Plan{Index: index, threat: threat}
	body := map[string]any{"query": dsl, "track_total_hits": true}
	p.Body = body

	if len(cmds) > 0 {
		switch c := cmds[0].(type) {
		case *query.Stats:
			p.Mode, p.transform, p.post = "stats", c, cmds[1:]
			body["size"] = 0
			if len(c.By) == 0 {
				aggs, err := metricAggs(c.Aggs)
				if err != nil {
					return nil, err
				}
				if len(aggs) > 0 {
					body["aggs"] = aggs
				}
			} else {
				comp, err := compositeAgg(c.By, c.Aggs, o.MaxBuckets)
				if err != nil {
					return nil, err
				}
				body["aggs"] = map[string]any{"groups": comp}
			}
			return p, nil
		case *query.Top:
			p.Mode, p.transform, p.post = "top", c, cmds[1:]
			body["size"] = 0
			comp, err := compositeAgg(append(append([]string{}, c.By...), c.Fields...), []query.Agg{{Func: "count"}}, o.MaxBuckets)
			if err != nil {
				return nil, err
			}
			body["aggs"] = map[string]any{"groups": comp}
			return p, nil
		case *query.Timechart:
			p.Mode, p.transform, p.post = "timechart", c, cmds[1:]
			body["size"] = 0
			span := c.Span
			if span == "" {
				span = autoSpan(earliest)
			}
			interval, err := spanInterval(span)
			if err != nil {
				return nil, err
			}
			hist := map[string]any{"field": TimeField, "min_doc_count": 0}
			for k, v := range interval {
				hist[k] = v
			}
			sub, err := metricAggs(c.Aggs)
			if err != nil {
				return nil, err
			}
			ts := map[string]any{"date_histogram": hist}
			if c.By != "" {
				by := map[string]any{"terms": map[string]any{"field": storedField(c.By), "size": 10}}
				if len(sub) > 0 {
					by["aggs"] = sub
				}
				ts["aggs"] = map[string]any{"by": by}
			} else if len(sub) > 0 {
				ts["aggs"] = sub
			}
			body["aggs"] = map[string]any{"time": ts}
			return p, nil
		}
	}

	p.Mode, p.post = "events", cmds
	size := o.DefaultEvents
	if needsAllEvents(cmds) {
		size = o.MaxEvents
	} else if n, ok := leadingHead(cmds); ok {
		size = min(n, o.MaxEvents)
	}
	body["size"] = size
	body["sort"] = []any{map[string]any{TimeField: map[string]any{"order": "desc", "unmapped_type": "date"}}}
	return p, nil
}

// needsAllEvents reports whether later commands look at the whole event set
// (sorting, filtering or aggregating), not just the newest few.
func needsAllEvents(cmds []query.Command) bool {
	for _, c := range cmds {
		switch c.(type) {
		case *query.Head:
			return false
		case *query.Sort, *query.Where, *query.Stats, *query.Top, *query.Dedup, *query.EventStats, *query.Transaction,
			*query.StreamStats, *query.Regex, *query.AppendPipe:
			return true
		}
	}
	return false
}

func leadingHead(cmds []query.Command) (int, bool) {
	for _, c := range cmds {
		switch c := c.(type) {
		case *query.Head:
			return c.N, true
		case *query.Table, *query.Rename, *query.Enrich, *query.Intel, *query.Eval, *query.Rex, *query.Fillnull, *query.Lookup,
			*query.Bin, *query.FieldsRemove:
			continue
		}
		return 0, false
	}
	return 0, false
}

func metricAggs(aggs []query.Agg) (map[string]any, error) {
	out := map[string]any{}
	for i, a := range aggs {
		m, err := metricAgg(a)
		if err != nil {
			return nil, err
		}
		if m != nil {
			out[fmt.Sprintf("m%d", i)] = m
		}
	}
	return out, nil
}

func compositeAgg(by []string, aggs []query.Agg, maxBuckets int) (map[string]any, error) {
	var sources []any
	for i, f := range by {
		sources = append(sources, map[string]any{fmt.Sprintf("k%d", i): map[string]any{"terms": map[string]any{"field": storedField(f)}}})
	}
	size := min(maxBuckets, 10000)
	comp := map[string]any{"composite": map[string]any{"size": size, "sources": sources}}
	sub, err := metricAggs(aggs)
	if err != nil {
		return nil, err
	}
	if len(sub) > 0 {
		comp["aggs"] = sub
	}
	return comp, nil
}

// Run parses and executes a query.
func (e *Engine) Run(ctx context.Context, src string) (*Result, error) {
	q, err := query.Parse(src)
	if err != nil {
		return nil, err
	}
	return e.Execute(ctx, q)
}

// Execute runs a parsed query. It waits for a turn when MaxSearches are
// running (ErrBusy after QueueWait), and stops when ctx ends, including
// during the commands that run over results in memory.
func (e *Engine) Execute(ctx context.Context, q *query.Query) (res *Result, err error) {
	// A bug in a command must fail this search, not the process: the
	// detection scheduler runs searches outside any HTTP handler, so a
	// panic there would stop the server, and again at every run.
	defer func() {
		if r := recover(); r != nil {
			slog.Error("a search stopped on an internal error", "panic", fmt.Sprint(r), "stack", string(debug.Stack()))
			res, err = nil, ErrInternal
		}
	}()
	return e.execute(ctx, q)
}

// ErrInternal is a search that stopped on a bug in Signalith rather than
// in the query; the details are in the server log.
var ErrInternal = errors.New("the search stopped on an internal error; the details are in the server log")

func (e *Engine) execute(ctx context.Context, q *query.Query) (*Result, error) {
	start := time.Now()
	p, err := e.Compile(q)
	if err != nil {
		return nil, err
	}
	release, err := e.acquire(ctx)
	if err != nil {
		return nil, err
	}
	defer release()
	res, err := e.run(withEvaluator(ctx), q, p)
	if err != nil {
		return nil, err
	}
	res.TookMS = time.Since(start).Milliseconds()
	return res, nil
}

// run gets a compiled query's rows and runs its commands over them. A
// join's subsearch runs here too, within the search's slot and limits.
func (e *Engine) run(ctx context.Context, q *query.Query, p *Plan) (*Result, error) {
	var res *Result
	var err error
	switch c := p.transform.(type) {
	case *query.InputLookup:
		res, err = e.inputLookup(c)
	case *query.MakeResults:
		res = makeResults(c)
	default:
		res, err = e.fetch(ctx, p)
	}
	if err != nil {
		return nil, err
	}
	if p.threat != nil {
		e.threatAnnotate(res, p.threat, p.Mode == "events")
	}
	if len(p.post) == 0 {
		return res, nil
	}
	before := resultBytes(res)
	if err := e.post(ctx, res, p.post, q); err != nil {
		return nil, err
	}
	// Commands such as rex and fillnull can put one value in many fields
	// without building anything, but each copy is written out with the
	// result.
	if grown := resultBytes(res) - before; grown > maxResultGrowth {
		return nil, &QueryError{Msg: fmt.Sprintf("the search's commands add more than %d MB to its results; narrow the search first", maxResultGrowth>>20)}
	}
	return res, nil
}

// maxResultGrowth caps how much a search's commands may add to the rows
// they were given, measured as written out.
const maxResultGrowth = maxEvalTotal

// resultBytes is about how many bytes res's rows take once written out.
func resultBytes(res *Result) int {
	n := 0
	for _, r := range res.Rows {
		for f, v := range r {
			n += len(f) + valueSize(v)
		}
	}
	return n
}

// post runs commands over rows held in memory; q is the query they belong
// to, whose time range subsearches inherit.
func (e *Engine) post(ctx context.Context, res *Result, cmds []query.Command, q *query.Query) error {
	for _, c := range cmds {
		if err := ctx.Err(); err != nil {
			return err
		}
		var err error
		switch c := c.(type) {
		case *query.Enrich:
			err = e.enrich(res, c)
		case *query.Lookup:
			err = e.lookup(ctx, res, c)
		case *query.Join:
			err = e.join(ctx, res, c, q)
		case *query.Append:
			err = e.appendSearch(ctx, res, c, q)
		case *query.AppendPipe:
			err = e.appendPipe(ctx, res, c, q)
		case *query.Intel:
			err = e.intelEnrich(res, c)
		default:
			err = applyCommand(ctx, res, c)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func (e *Engine) fetch(ctx context.Context, p *Plan) (*Result, error) {
	o := e.opts()
	resp, err := e.Store.Search(ctx, p.Index, p.Body)
	if err != nil {
		return nil, err
	}
	res := &Result{Matched: totalHits(resp)}
	switch p.Mode {
	case "events":
		res.Kind = "events"
		res.Rows, res.Columns = eventRows(resp)
		return res, nil
	case "stats":
		st := p.transform.(*query.Stats)
		res.Kind = "table"
		res.Columns = append(append([]string{}, st.By...), aggColumns(st.Aggs)...)
		if len(st.By) == 0 {
			aggs, _ := resp["aggregations"].(map[string]any)
			row := Row{}
			for i, a := range st.Aggs {
				if a.Func == "count" && a.Field == "" {
					row[a.Column()] = res.Matched
				} else {
					row[a.Column()] = aggValue(a, aggs, fmt.Sprintf("m%d", i))
				}
			}
			res.Rows = []Row{row}
			return res, nil
		}
		buckets, truncated, err := e.allBuckets(ctx, p, resp, o.MaxBuckets)
		if err != nil {
			return nil, err
		}
		res.Truncated = truncated
		for _, b := range buckets {
			row := bucketKeys(b, st.By)
			for i, a := range st.Aggs {
				if a.Func == "count" && a.Field == "" {
					row[a.Column()] = toNumber(b["doc_count"])
				} else {
					row[a.Column()] = aggValue(a, b, fmt.Sprintf("m%d", i))
				}
			}
			res.Rows = append(res.Rows, row)
		}
		return res, nil
	case "top":
		top := p.transform.(*query.Top)
		buckets, truncated, err := e.allBuckets(ctx, p, resp, o.MaxBuckets)
		if err != nil {
			return nil, err
		}
		res.Truncated = truncated
		keys := append(append([]string{}, top.By...), top.Fields...)
		var rows []Row
		for _, b := range buckets {
			row := bucketKeys(b, keys)
			row["count"] = toNumber(b["doc_count"])
			rows = append(rows, row)
		}
		res.Kind = "table"
		res.Rows, res.Columns = topRows(rows, top)
		return res, nil
	case "timechart":
		res.Kind = "timechart"
		tc := p.transform.(*query.Timechart)
		res.Rows, res.Columns = timechartRows(resp, tc)
		return res, nil
	}
	return nil, fmt.Errorf("unknown plan mode %q", p.Mode)
}

// allBuckets pages through a composite aggregation.
func (e *Engine) allBuckets(ctx context.Context, p *Plan, resp map[string]any, max int) ([]map[string]any, bool, error) {
	var out []map[string]any
	for {
		aggs, _ := resp["aggregations"].(map[string]any)
		groups, _ := aggs["groups"].(map[string]any)
		bs, _ := groups["buckets"].([]any)
		for _, b := range bs {
			if m, ok := b.(map[string]any); ok {
				out = append(out, m)
			}
		}
		if len(out) >= max {
			return out[:max], true, nil
		}
		after, ok := groups["after_key"]
		if !ok || len(bs) == 0 {
			return out, false, nil
		}
		// Ask for the next page.
		next := cloneMap(p.Body)
		nextAggs := cloneMap(next["aggs"].(map[string]any))
		g := cloneMap(nextAggs["groups"].(map[string]any))
		comp := cloneMap(g["composite"].(map[string]any))
		comp["after"] = after
		g["composite"] = comp
		nextAggs["groups"] = g
		next["aggs"] = nextAggs
		next["track_total_hits"] = false
		var err error
		resp, err = e.Store.Search(ctx, p.Index, next)
		if err != nil {
			return nil, false, err
		}
	}
}

func cloneMap(m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func aggColumns(aggs []query.Agg) []string {
	cols := make([]string, len(aggs))
	for i, a := range aggs {
		cols[i] = a.Column()
	}
	return cols
}

func bucketKeys(b map[string]any, fields []string) Row {
	row := Row{}
	key, _ := b["key"].(map[string]any)
	for i, f := range fields {
		row[f] = normalize(key[fmt.Sprintf("k%d", i)])
	}
	return row
}

func totalHits(resp map[string]any) int64 {
	hits, _ := resp["hits"].(map[string]any)
	switch t := hits["total"].(type) {
	case map[string]any:
		n, _ := toNumber(t["value"]).(int64)
		return n
	default:
		n, _ := toNumber(t).(int64)
		return n
	}
}

func metricValue(aggs map[string]any, name string) any {
	m, _ := aggs[name].(map[string]any)
	if m == nil {
		return nil
	}
	return toNumber(m["value"])
}

// toNumber converts decoded JSON numbers to int64 when whole, else float64.
func toNumber(v any) any {
	switch n := v.(type) {
	case json.Number:
		if i, err := n.Int64(); err == nil {
			return i
		}
		if f, err := n.Float64(); err == nil {
			if f == float64(int64(f)) && f < 1e15 && f > -1e15 {
				return int64(f)
			}
			return f
		}
		return n.String()
	case float64:
		if n == float64(int64(n)) && n < 1e15 && n > -1e15 {
			return int64(n)
		}
		return n
	}
	return v
}

func normalize(v any) any {
	switch x := v.(type) {
	case json.Number, float64:
		return toNumber(x)
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = normalize(e)
		}
		return out
	}
	return v
}

func eventRows(resp map[string]any) ([]Row, []string) {
	hits, _ := resp["hits"].(map[string]any)
	hs, _ := hits["hits"].([]any)
	seen := map[string]bool{}
	var rows []Row
	for _, h := range hs {
		hm, _ := h.(map[string]any)
		src, _ := hm["_source"].(map[string]any)
		row := Row{}
		flatten("", src, row)
		if t, ok := row[TimeField]; ok {
			row["_time"] = t
			delete(row, TimeField)
		}
		if m, ok := row[StoredRawField]; ok {
			row[RawField] = m
			delete(row, StoredRawField)
		}
		if ix, ok := hm[indexMeta].(string); ok && ix != "" {
			row[IndexField] = ix
		}
		for k := range row {
			seen[k] = true
		}
		rows = append(rows, row)
	}
	var cols []string
	for k := range seen {
		if k != "_time" && k != RawField {
			cols = append(cols, k)
		}
	}
	sort.Strings(cols)
	if seen["_time"] {
		cols = append([]string{"_time"}, cols...)
	}
	if seen[RawField] {
		cols = append(cols, RawField)
	}
	return rows, cols
}

func flatten(prefix string, m map[string]any, out Row) {
	for k, v := range m {
		key := k
		if prefix != "" {
			key = prefix + "." + k
		}
		if sub, ok := v.(map[string]any); ok {
			flatten(key, sub, out)
			continue
		}
		out[key] = normalize(v)
	}
}

func timechartRows(resp map[string]any, tc *query.Timechart) ([]Row, []string) {
	aggs, _ := resp["aggregations"].(map[string]any)
	ts, _ := aggs["time"].(map[string]any)
	bs, _ := ts["buckets"].([]any)
	var rows []Row
	cols := []string{"_time"}
	if tc.By == "" {
		cols = append(cols, aggColumns(tc.Aggs)...)
		for _, b := range bs {
			bm, _ := b.(map[string]any)
			row := Row{"_time": bm["key_as_string"]}
			for i, a := range tc.Aggs {
				if a.Func == "count" && a.Field == "" {
					row[a.Column()] = toNumber(bm["doc_count"])
				} else {
					row[a.Column()] = aggValue(a, bm, fmt.Sprintf("m%d", i))
				}
			}
			rows = append(rows, row)
		}
		return rows, cols
	}
	// One column per value of the by field, ordered by overall total.
	totals := map[string]float64{}
	a := tc.Aggs[0]
	for _, b := range bs {
		bm, _ := b.(map[string]any)
		row := Row{"_time": bm["key_as_string"]}
		by, _ := bm["by"].(map[string]any)
		vbs, _ := by["buckets"].([]any)
		for _, vb := range vbs {
			vm, _ := vb.(map[string]any)
			name := fmt.Sprint(normalize(vm["key"]))
			var val any
			if a.Func == "count" && a.Field == "" {
				val = toNumber(vm["doc_count"])
			} else {
				val = aggValue(a, vm, "m0")
			}
			row[name] = val
			if f, ok := asFloat(val); ok {
				totals[name] += f
			} else if _, ok := totals[name]; !ok {
				totals[name] = 0
			}
		}
		rows = append(rows, row)
	}
	names := make([]string, 0, len(totals))
	for n := range totals {
		names = append(names, n)
	}
	sort.Slice(names, func(i, j int) bool {
		if totals[names[i]] != totals[names[j]] {
			return totals[names[i]] > totals[names[j]]
		}
		return names[i] < names[j]
	})
	for _, r := range rows {
		for _, n := range names {
			if _, ok := r[n]; !ok && (a.Func == "count" || a.Func == "dc") {
				r[n] = int64(0)
			}
		}
	}
	return rows, append(cols, names...)
}
