package dashboards

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jrsamsanchez/signalith/internal/datamodel"
	"github.com/jrsamsanchez/signalith/internal/detect"
	"github.com/jrsamsanchez/signalith/internal/findings"
	"github.com/jrsamsanchez/signalith/internal/query"
	"github.com/jrsamsanchez/signalith/internal/search"
)

// Posture computes the built-in security posture dashboard: key
// indicators compared with the previous period, findings over time, what
// is firing, risk, ATT&CK tactics, data volume and detection health.
type Posture struct {
	Engine Executor
	// Findings backs the findings indicators; nil reports them as errors.
	Findings findings.Store
	// Detections and Status back detection health; nil reports an error.
	Detections  *detect.Library
	Status      func() map[string]detect.RunState
	SchedulerOn bool
	// Elsewhere is true when another server runs the detections (RunsOn
	// names it) or none does: this server's run times and errors are not
	// theirs, so they are left out.
	Elsewhere bool
	RunsOn    string
	// StaleAfter is how long a host and source type can be quiet before it
	// counts as stopped (default 2h).
	StaleAfter  time.Duration
	Now         func() time.Time
	Concurrency int
}

// Report is the posture dashboard. Each section fails on its own: a
// section that could not be computed is listed in Errors and the rest
// still show.
type Report struct {
	Range              string            `json:"range"`
	Start              time.Time         `json:"start"`
	End                time.Time         `json:"end"`
	PrevStart          time.Time         `json:"prev_start"`
	Indicators         []Indicator       `json:"indicators"`
	OpenByUrgency      map[string]int    `json:"open_by_urgency"`
	FindingsOverTime   *search.Result    `json:"findings_over_time,omitempty"`
	TopDetections      []DetectionCount  `json:"top_detections"`
	TopRiskObjects     []search.Row      `json:"top_risk_objects"`
	Tactics            []TacticCount     `json:"tactics"`
	EventsByDatamodel  *search.Result    `json:"events_by_datamodel,omitempty"`
	EventsBySourcetype *search.Result    `json:"events_by_sourcetype,omitempty"`
	Health             *Health           `json:"health,omitempty"`
	Queries            map[string]string `json:"queries"`
	Errors             map[string]string `json:"errors,omitempty"`
	// FindingsTruncated is set when there were more findings in the period
	// than one request returns; finding metrics then undercount.
	FindingsTruncated bool `json:"findings_truncated,omitempty"`
}

// Indicator is one key number. Value and Previous are nil when there is
// nothing to measure (for example no finding was triaged).
type Indicator struct {
	ID       string   `json:"id"`
	Label    string   `json:"label"`
	Value    *float64 `json:"value"`
	Previous *float64 `json:"previous"`
	// Unit is "count" or "seconds".
	Unit string `json:"unit"`
	// Better is "up", "down" or "" (neutral), for coloring the change.
	Better string `json:"better,omitempty"`
	Help   string `json:"help,omitempty"`
	Error  string `json:"error,omitempty"`
}

// DetectionCount is how much one detection fired in the period.
type DetectionCount struct {
	ID         string `json:"id"`
	Title      string `json:"title"`
	Findings   int64  `json:"findings"`
	RiskEvents int64  `json:"risk_events"`
}

// TacticCount is activity for one ATT&CK tactic.
type TacticCount struct {
	Tactic     string `json:"tactic"`
	Name       string `json:"name"`
	Findings   int64  `json:"findings"`
	RiskEvents int64  `json:"risk_events"`
}

// Health is detection and data source health.
type Health struct {
	Total       int  `json:"total"`
	Enabled     int  `json:"enabled"`
	SchedulerOn bool `json:"scheduler_on"`
	// RunsElsewhere is true when this server does not run the detections:
	// RunsOn names the one that does, if any. NotRun and Erroring are then
	// not known here.
	RunsElsewhere bool   `json:"runs_elsewhere,omitempty"`
	RunsOn        string `json:"runs_on,omitempty"`
	// NotRun counts enabled detections that have not run since the server
	// started.
	NotRun   int              `json:"not_run"`
	Erroring []DetectionIssue `json:"erroring"`
	// Silent lists enabled detections with no findings and no risk events
	// in SilentWindow.
	Silent       []DetectionIssue `json:"silent"`
	SilentWindow string           `json:"silent_window"`
	// Sources counts host and source type pairs seen in SourceLookback.
	Sources        int      `json:"sources"`
	StaleSources   []Source `json:"stale_sources"`
	StaleAfter     string   `json:"stale_after"`
	SourceLookback string   `json:"source_lookback"`
}

// DetectionIssue names a detection that needs a look.
type DetectionIssue struct {
	ID      string    `json:"id"`
	Title   string    `json:"title"`
	Error   string    `json:"error,omitempty"`
	LastRun time.Time `json:"last_run,omitzero"`
}

// Source is a host and source type that sent events.
type Source struct {
	Host       string    `json:"host"`
	Sourcetype string    `json:"sourcetype"`
	LastSeen   time.Time `json:"last_seen"`
	Events     int64     `json:"events"`
}

// silentWindow is how long an enabled detection can go without matching
// before posture lists it as silent.
const silentWindow = 30 * 24 * time.Hour

// Posture queries, without a time range; the range is added when run.
const (
	qEvents          = `* | stats count`
	qByDatamodel     = `* | timechart count by datamodel`
	qBySourcetype    = `* | timechart count by sourcetype`
	qRiskObjects     = "datamodel=Risk\n| stats sum(risk_score) as risk_score, count as events, dc(detection_id) as detections by risk_object, risk_object_type\n| sort -risk_score\n| head 10"
	qRiskByDetection = "datamodel=Risk\n| stats count by detection_id"
	qRiskByTactic    = "datamodel=Risk\n| stats count by mitre_tactic"
	// Sample data is left out of source health: it is loaded all at once and
	// removed all at once, so it would otherwise show as a source that goes
	// stale the moment it is removed. Its marker field is one no sender
	// uses, so no real source is ever left out.
	qSources = "NOT " + datamodel.SampleField + "=*\n| stats max(_time) as last_seen, count by host, sourcetype"
)

func (p *Posture) now() time.Time {
	if p.Now != nil {
		return p.Now()
	}
	return time.Now()
}

// Report computes the dashboard for the last rng (for example 24h).
func (p *Posture) Report(ctx context.Context, rng time.Duration, rangeLabel string) *Report {
	now := p.now().UTC()
	start, prevStart := now.Add(-rng), now.Add(-2*rng)
	earliest, prevEarliest := "-"+rangeLabel, ""
	if pe, _, ok := PreviousPeriod(earliest); ok {
		prevEarliest = pe
	}
	stale := p.StaleAfter
	if stale <= 0 {
		stale = 2 * time.Hour
	}
	lookback := max(7*24*time.Hour, 4*stale)
	rep := &Report{
		Range: rangeLabel, Start: start, End: now, PrevStart: prevStart,
		OpenByUrgency: map[string]int{}, TopDetections: []DetectionCount{}, TopRiskObjects: []search.Row{}, Tactics: []TacticCount{},
		Queries: map[string]string{
			"events": qEvents, "events_by_datamodel": qByDatamodel, "events_by_sourcetype": qBySourcetype,
			"risk_objects": qRiskObjects, "risk_by_detection": qRiskByDetection, "risk_by_tactic": qRiskByTactic,
			"sources": qSources + " earliest=" + durLabel(lookback),
		},
		Errors: map[string]string{},
	}

	var (
		mu                                     sync.Mutex
		sum                                    *findings.Summary
		list                                   []*findings.Finding
		events, prevEvents                     *search.Result
		riskObjects, riskByDet, riskByTac, r30 *search.Result
		sources                                *search.Result
	)
	fail := func(section string, err error) {
		mu.Lock()
		defer mu.Unlock()
		rep.Errors[section] = err.Error()
	}
	run := func(ctx context.Context, src, earliest, latest string) (*search.Result, error) {
		q, err := query.Parse(src)
		if err != nil {
			return nil, err
		}
		if q.Earliest == "" {
			q.Earliest = earliest
		}
		q.Latest = latest
		return p.Engine.Execute(ctx, q)
	}
	fetchStart := prevStart
	if s := now.Add(-silentWindow); s.Before(fetchStart) {
		fetchStart = s
	}
	tasks := []func(context.Context){
		func(ctx context.Context) {
			if p.Findings == nil {
				fail("findings", fmt.Errorf("findings are not configured on this server"))
				return
			}
			s, err := p.Findings.Summary(ctx)
			if err != nil {
				fail("findings", err)
				return
			}
			l, total, err := p.Findings.Search(ctx, findings.Filter{UpdatedSince: fetchStart, Limit: 10000})
			if err != nil {
				fail("findings", err)
				return
			}
			sum, list, rep.FindingsTruncated = s, l, total > len(l)
		},
		func(ctx context.Context) {
			var err error
			if events, err = run(ctx, qEvents, earliest, ""); err != nil {
				fail("events", err)
			}
		},
		func(ctx context.Context) {
			if prevEarliest == "" {
				return
			}
			var err error
			if prevEvents, err = run(ctx, qEvents, prevEarliest, earliest); err != nil {
				fail("events", err)
			}
		},
		func(ctx context.Context) {
			res, err := run(ctx, qByDatamodel, earliest, "")
			if err != nil {
				fail("events_by_datamodel", err)
				return
			}
			rep.EventsByDatamodel = res
		},
		func(ctx context.Context) {
			res, err := run(ctx, qBySourcetype, earliest, "")
			if err != nil {
				fail("events_by_sourcetype", err)
				return
			}
			rep.EventsBySourcetype = res
		},
		func(ctx context.Context) {
			var err error
			if riskObjects, err = run(ctx, qRiskObjects, earliest, ""); err != nil {
				fail("risk_objects", err)
			}
		},
		func(ctx context.Context) {
			var err error
			if riskByDet, err = run(ctx, qRiskByDetection, earliest, ""); err != nil {
				fail("top_detections", err)
			}
		},
		func(ctx context.Context) {
			var err error
			if riskByTac, err = run(ctx, qRiskByTactic, earliest, ""); err != nil {
				fail("tactics", err)
			}
		},
		func(ctx context.Context) {
			var err error
			if r30, err = run(ctx, qRiskByDetection, durLabel(silentWindow), ""); err != nil {
				fail("health", fmt.Errorf("risk events for silent detections: %w", err))
			}
		},
		func(ctx context.Context) {
			var err error
			if sources, err = run(ctx, qSources, durLabel(lookback), ""); err != nil {
				fail("sources", err)
			}
		},
	}
	n := p.Concurrency
	if n <= 0 {
		n = DefaultConcurrency
	}
	sem := make(chan struct{}, n)
	var wg sync.WaitGroup
	for _, t := range tasks {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			defer func() {
				if v := recover(); v != nil {
					fail("internal", fmt.Errorf("%v", v))
				}
			}()
			cctx, cancel := context.WithTimeout(ctx, time.Minute)
			defer cancel()
			t(cctx)
		}()
	}
	wg.Wait()

	// Findings indicators and charts.
	fs := computeFindingStats(list, start, now, prevStart, rng)
	findingsErr := rep.Errors["findings"]
	ind := func(id, label, unit, better, help string, cur, prev *float64, errMsg string) {
		rep.Indicators = append(rep.Indicators, Indicator{ID: id, Label: label, Value: cur, Previous: prev, Unit: unit, Better: better, Help: help, Error: errMsg})
	}
	if findingsErr == "" {
		for u, c := range sum.ByUrgency {
			rep.OpenByUrgency[u] = c
		}
		ind("open_findings", "Open findings", "count", "down", "Findings not yet resolved or closed, by urgency", num(float64(sum.Open)), nil, "")
		ind("new_findings", "New findings", "count", "down", "Findings raised in the period", num(float64(fs.newCur)), num(float64(fs.newPrev)), "")
		ind("closed_findings", "Findings closed", "count", "up", "Findings resolved or closed in the period", num(float64(fs.closedCur)), num(float64(fs.closedPrev)), "")
		ind("mean_time_to_triage", "Mean time to triage", "seconds", "down", "From raised to first status change or owner assignment, for findings triaged in the period", mean(fs.triageCur), mean(fs.triagePrev), "")
		ind("mean_time_to_resolve", "Mean time to resolve", "seconds", "down", "From raised to resolved or closed, for findings closed in the period", mean(fs.resolveCur), mean(fs.resolvePrev), "")
		rep.FindingsOverTime = fs.overTime
	} else {
		for _, x := range [][2]string{{"open_findings", "Open findings"}, {"new_findings", "New findings"}, {"closed_findings", "Findings closed"}, {"mean_time_to_triage", "Mean time to triage"}, {"mean_time_to_resolve", "Mean time to resolve"}} {
			ind(x[0], x[1], "count", "", "", nil, nil, findingsErr)
		}
	}
	if e := rep.Errors["events"]; e != "" {
		ind("events_ingested", "Events ingested", "count", "", "", nil, nil, e)
	} else {
		var prev *float64
		if prevEvents != nil {
			prev = num(firstNumber(prevEvents, "count"))
		}
		ind("events_ingested", "Events ingested", "count", "", "Events stored in the period, all data models except Risk", num(firstNumber(events, "count")), prev, "")
	}

	// What fired: findings plus risk events by detection.
	titles := map[string]string{}
	if p.Detections != nil {
		for _, d := range p.Detections.List() {
			titles[d.ID] = d.BaseTitle()
		}
	}
	byDet := map[string]*DetectionCount{}
	get := func(id string) *DetectionCount {
		if byDet[id] == nil {
			t := titles[id]
			if t == "" {
				t = fs.titles[id]
			}
			if t == "" {
				t = id
			}
			byDet[id] = &DetectionCount{ID: id, Title: t}
		}
		return byDet[id]
	}
	for id, n := range fs.byDetection {
		get(id).Findings += n
	}
	if riskByDet != nil {
		for _, r := range riskByDet.Rows {
			if id, ok := r["detection_id"].(string); ok && id != "" {
				get(id).RiskEvents += int64(toNum(r["count"]))
			}
		}
	}
	for _, d := range byDet {
		rep.TopDetections = append(rep.TopDetections, *d)
	}
	sort.Slice(rep.TopDetections, func(i, j int) bool {
		a, b := rep.TopDetections[i], rep.TopDetections[j]
		if a.Findings+a.RiskEvents != b.Findings+b.RiskEvents {
			return a.Findings+a.RiskEvents > b.Findings+b.RiskEvents
		}
		return a.ID < b.ID
	})
	rep.TopDetections = rep.TopDetections[:min(10, len(rep.TopDetections))]

	if riskObjects != nil {
		rep.TopRiskObjects = riskObjects.Rows
	}

	// ATT&CK tactics, in matrix order.
	tac := map[string]*TacticCount{}
	tget := func(short string) *TacticCount {
		if tac[short] == nil {
			tac[short] = &TacticCount{Tactic: short, Name: short}
		}
		return tac[short]
	}
	for t, n := range fs.tactics {
		tget(t).Findings += n
	}
	if riskByTac != nil {
		for _, r := range riskByTac.Rows {
			if t, ok := r["mitre_tactic"].(string); ok && t != "" {
				tget(t).RiskEvents += int64(toNum(r["count"]))
			}
		}
	}
	for _, t := range detect.ATTACK().Tactics {
		if c := tac[t.Short]; c != nil {
			c.Name = t.Name
			rep.Tactics = append(rep.Tactics, *c)
			delete(tac, t.Short)
		}
	}
	for _, c := range tac {
		rep.Tactics = append(rep.Tactics, *c)
	}

	rep.Health = p.health(fs, r30, sources, rep.Errors, now, stale, lookback)
	if len(rep.Errors) == 0 {
		rep.Errors = nil
	}
	return rep
}

func (p *Posture) health(fs *findingStats, r30, sources *search.Result, errs map[string]string, now time.Time, stale, lookback time.Duration) *Health {
	h := &Health{SchedulerOn: p.SchedulerOn && !p.Elsewhere, RunsElsewhere: p.Elsewhere, RunsOn: p.RunsOn,
		Erroring: []DetectionIssue{}, Silent: []DetectionIssue{}, StaleSources: []Source{},
		StaleAfter: durLabel(stale)[1:], SourceLookback: durLabel(lookback)[1:], SilentWindow: durLabel(silentWindow)[1:]}
	if p.Detections == nil {
		errs["health"] = "detections are not configured on this server"
	} else {
		var states map[string]detect.RunState
		if p.Status != nil {
			states = p.Status()
		}
		matched := map[string]bool{}
		for id := range fs.seen30 {
			matched[id] = true
		}
		if r30 != nil {
			for _, r := range r30.Rows {
				if id, ok := r["detection_id"].(string); ok && toNum(r["count"]) > 0 {
					matched[id] = true
				}
			}
		}
		canJudgeSilence := errs["findings"] == "" && r30 != nil
		for _, d := range p.Detections.List() {
			h.Total++
			if !d.Enabled {
				continue
			}
			h.Enabled++
			st, ran := states[d.ID]
			if !ran || st.LastRun.IsZero() {
				if !p.Elsewhere {
					h.NotRun++
				}
			}
			if st.LastError != "" && !p.Elsewhere {
				h.Erroring = append(h.Erroring, DetectionIssue{ID: d.ID, Title: d.BaseTitle(), Error: st.LastError, LastRun: st.LastRun})
			}
			if canJudgeSilence && !matched[d.ID] && st.LastResults == 0 {
				h.Silent = append(h.Silent, DetectionIssue{ID: d.ID, Title: d.BaseTitle(), LastRun: st.LastRun})
			}
		}
	}
	if sources != nil {
		for _, r := range sources.Rows {
			h.Sources++
			ms, ok := toFloatAny(r["last_seen"])
			if !ok {
				continue
			}
			last := time.UnixMilli(int64(ms)).UTC()
			if now.Sub(last) > stale {
				h.StaleSources = append(h.StaleSources, Source{Host: fmt.Sprint(r["host"]), Sourcetype: fmt.Sprint(r["sourcetype"]), LastSeen: last, Events: int64(toNum(r["count"]))})
			}
		}
		sort.Slice(h.StaleSources, func(i, j int) bool { return h.StaleSources[i].LastSeen.After(h.StaleSources[j].LastSeen) })
		h.StaleSources = h.StaleSources[:min(50, len(h.StaleSources))]
	}
	return h
}

// findingStats is what posture derives from the findings list.
type findingStats struct {
	newCur, newPrev         int
	closedCur, closedPrev   int
	triageCur, triagePrev   []time.Duration
	resolveCur, resolvePrev []time.Duration
	byDetection             map[string]int64
	titles                  map[string]string
	tactics                 map[string]int64
	seen30                  map[string]bool
	overTime                *search.Result
}

// TriagedAt is when an analyst first acted on a finding: the first status
// change or owner assignment.
func TriagedAt(f *findings.Finding) (time.Time, bool) {
	for _, c := range f.History {
		if c.Field == "status" || (c.Field == "owner" && c.To != "") {
			return c.Time, true
		}
	}
	return time.Time{}, false
}

// ResolvedAt is when a resolved or closed finding was last moved to
// resolved or closed.
func ResolvedAt(f *findings.Finding) (time.Time, bool) {
	if findings.IsOpen(f.Status) {
		return time.Time{}, false
	}
	for i := len(f.History) - 1; i >= 0; i-- {
		c := f.History[i]
		if c.Field == "status" && !findings.IsOpen(c.To) {
			return c.Time, true
		}
	}
	return f.Updated, !f.Updated.IsZero()
}

func computeFindingStats(list []*findings.Finding, start, end, prevStart time.Time, rng time.Duration) *findingStats {
	fs := &findingStats{byDetection: map[string]int64{}, titles: map[string]string{}, tactics: map[string]int64{}, seen30: map[string]bool{}}
	in := func(t time.Time) int { // 1 current, -1 previous, 0 neither
		switch {
		case !t.Before(start) && !t.After(end):
			return 1
		case !t.Before(prevStart) && t.Before(start):
			return -1
		}
		return 0
	}
	bucket := bucketFor(rng)
	first := start.Truncate(bucket)
	nb := int(end.Sub(first)/bucket) + 1
	counts := make([]map[string]int64, nb)
	used := map[string]bool{}
	for _, f := range list {
		if !f.Created.Before(end.Add(-silentWindow)) {
			fs.seen30[f.DetectionID] = true
		}
		switch in(f.Created) {
		case 1:
			fs.newCur++
			fs.byDetection[f.DetectionID]++
			// A detection no longer in the library is named by its
			// findings' title, but only when they all agree: a title
			// filled in for one host must not name a count across hosts.
			if t, ok := fs.titles[f.DetectionID]; !ok {
				fs.titles[f.DetectionID] = f.Title
			} else if t != f.Title {
				fs.titles[f.DetectionID] = ""
			}
			for _, t := range detect.Tactics(f.MITRE) {
				fs.tactics[t]++
			}
			i := int(f.Created.Sub(first) / bucket)
			if i >= 0 && i < nb {
				if counts[i] == nil {
					counts[i] = map[string]int64{}
				}
				u := f.EffectiveUrgency()
				counts[i][u]++
				used[u] = true
			}
		case -1:
			fs.newPrev++
		}
		if t, ok := TriagedAt(f); ok {
			switch in(t) {
			case 1:
				fs.triageCur = append(fs.triageCur, t.Sub(f.Created))
			case -1:
				fs.triagePrev = append(fs.triagePrev, t.Sub(f.Created))
			}
		}
		if t, ok := ResolvedAt(f); ok {
			switch in(t) {
			case 1:
				fs.closedCur++
				fs.resolveCur = append(fs.resolveCur, t.Sub(f.Created))
			case -1:
				fs.closedPrev++
				fs.resolvePrev = append(fs.resolvePrev, t.Sub(f.Created))
			}
		}
	}
	res := &search.Result{Kind: "timechart", Columns: []string{"_time"}, Rows: []search.Row{}}
	for _, u := range slices.Backward(findings.Severities) {
		if used[u] {
			res.Columns = append(res.Columns, u)
		}
	}
	for i := range nb {
		row := search.Row{"_time": first.Add(time.Duration(i) * bucket).Format(time.RFC3339)}
		for _, u := range res.Columns[1:] {
			row[u] = counts[i][u]
		}
		res.Rows = append(res.Rows, row)
	}
	fs.overTime = res
	return fs
}

// bucketFor picks the findings-over-time bucket for a range.
func bucketFor(rng time.Duration) time.Duration {
	switch {
	case rng <= 4*time.Hour:
		return 15 * time.Minute
	case rng <= 24*time.Hour:
		return time.Hour
	case rng <= 3*24*time.Hour:
		return 3 * time.Hour
	case rng <= 7*24*time.Hour:
		return 6 * time.Hour
	case rng <= 31*24*time.Hour:
		return 24 * time.Hour
	}
	return 7 * 24 * time.Hour
}

// durLabel renders a duration as a relative search time such as -7d.
func durLabel(d time.Duration) string {
	switch {
	case d%(24*time.Hour) == 0:
		return fmt.Sprintf("-%dd", d/(24*time.Hour))
	case d%time.Hour == 0:
		return fmt.Sprintf("-%dh", d/time.Hour)
	}
	return fmt.Sprintf("-%dm", d/time.Minute)
}

func num(v float64) *float64 { return &v }

func mean(ds []time.Duration) *float64 {
	if len(ds) == 0 {
		return nil
	}
	var total time.Duration
	for _, d := range ds {
		total += d
	}
	return num((total / time.Duration(len(ds))).Seconds())
}

func firstNumber(res *search.Result, col string) float64 {
	if res == nil || len(res.Rows) == 0 {
		return 0
	}
	return toNum(res.Rows[0][col])
}

func toNum(v any) float64 {
	f, _ := toFloatAny(v)
	return f
}

func toFloatAny(v any) (float64, bool) {
	if f, ok := toFloat(v); ok {
		return f, true
	}
	if s, ok := v.(string); ok && strings.TrimSpace(s) != "" {
		var f float64
		if _, err := fmt.Sscan(s, &f); err == nil {
			return f, true
		}
	}
	return 0, false
}
