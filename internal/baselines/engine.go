// Package baselines learns how each user and host usually behaves, and
// adds risk to them when they do something new or rare: a sign-in from a
// new country or network, or at an unusual hour; a rare program on a host;
// a new kind of change by a user; an unusual amount of data sent. This is
// user and entity behavior analytics (UEBA). The risk goes to the Risk
// data model like a detection's, so it adds up with the detections' own
// risk and raises a finding through the risk incident detections rather
// than a stream of alerts of its own.
//
// The server that runs the background jobs learns one clock hour of
// events at a time, a few minutes after it ends, with a search per check
// (stats by user or host, so only one row per entity and value leaves
// OpenSearch). What it learned is kept in the baselines index, one profile
// per check and entity, so a server that takes the jobs over carries on
// where the last one stopped. Everything is bounded: the values one
// profile keeps (MaxValues), the profiles one check keeps (MaxProfiles),
// the rows one hour's search reads, and the risk one hour can raise.
package baselines

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net/http"
	"net/netip"
	"os"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jrsamsanchez/signalith/internal/assets"
	"github.com/jrsamsanchez/signalith/internal/detect"
	"github.com/jrsamsanchez/signalith/internal/query"
	"github.com/jrsamsanchez/signalith/internal/search"
)

// Runner runs searches: *search.Engine.
type Runner interface {
	Execute(ctx context.Context, q *query.Query) (*search.Result, error)
}

// Timings.
const (
	// settle is how long after an hour ends it is learned from, so the
	// events that arrive a little late are in it.
	settle = 5 * time.Minute
	// maxHoursPerRound is how many hours one round learns from, so a
	// server catching up does a day at a time and checks in between
	// whether it still runs the jobs.
	maxHoursPerRound = 24
	// backfill is how much history is learned from when the baselines
	// first run, or the learning period when that is longer, so users
	// and hosts with a history in the stored events are judged at once.
	// maxCatchUp is how far back hours missed while no server ran them
	// are made up; older ones are skipped.
	backfill   = 30 * 24 * time.Hour
	maxCatchUp = 7 * 24 * time.Hour
	// searchTimeout bounds one search.
	searchTimeout = 2 * time.Minute
	// ipdbFresh is how often the IP database is downloaded again, and
	// ipdbRetry how soon after a failed download it is tried again.
	ipdbFresh = 7 * 24 * time.Hour
	ipdbRetry = time.Hour
	// housekeepEvery is how often forgotten profiles are removed and the
	// profiles counted again.
	housekeepEvery = time.Hour
	// chunk is how many profiles are read and written at once.
	chunk = 500
	// minHourHistory is how many active hours a user needs before an
	// hour of the day can be unusual for them, and rareHourShare the
	// share of them an unusual hour (with the hours either side) has.
	minHourHistory = 40
	rareHourShare  = 0.02
	// Data volume: an unusual hour sends at least volumeFactor times the
	// usual hour, and volumeSigmas standard deviations over it, after at
	// least minVolumeHours hours of history.
	volumeFactor   = 5
	volumeSigmas   = 4
	minVolumeHours = 72
)

// Engine learns the baselines and raises their risk.
type Engine struct {
	Store  *Store
	Search Runner
	// Risk stores the risk events.
	Risk detect.RiskStore
	// Assets scales risk by the priority of the user or host; nil means
	// none.
	Assets *assets.Store
	// HTTP downloads the IP database. It must refuse addresses on this
	// machine and cloud metadata services (intel.NewDownloadClient).
	HTTP *http.Client
	// FileDir is the ipdb folder, the only place a file: IP database is
	// read from.
	FileDir string
	// Allowed reports whether this server still runs the background
	// jobs. It is asked before every write. Epoch is the job lease's
	// epoch, NodeID this server's name.
	Allowed func() bool
	Epoch   func() int64
	NodeID  string
	// Now is the time hours are worked out with: OpenSearch's clock as
	// this server measures it, so every server agrees. Nil is time.Now.
	Now func() time.Time
	Log *slog.Logger
	// Every is the time between rounds (one minute).
	Every time.Duration

	// history, when set, is how much history the first run learns from
	// in place of backfill (tests).
	history time.Duration

	mu        sync.Mutex
	ipdb      *IPDB
	ipdbAt    time.Time
	counts    map[string]int64
	houseAt   time.Time
	lastReset map[string]time.Time
}

func (e *Engine) now() time.Time {
	if e.Now != nil {
		return e.Now().UTC()
	}
	return time.Now().UTC()
}

func (e *Engine) log() *slog.Logger {
	if e.Log != nil {
		return e.Log
	}
	return slog.Default()
}

func (e *Engine) allowed() bool { return e.Allowed == nil || e.Allowed() }

func (e *Engine) epoch() int64 {
	if e.Epoch != nil {
		return e.Epoch()
	}
	return 0
}

// Run learns until ctx ends.
func (e *Engine) Run(ctx context.Context) {
	every := e.Every
	if every <= 0 {
		every = time.Minute
	}
	defer func() {
		// What a server keeps only while it runs the jobs.
		e.mu.Lock()
		e.ipdb, e.ipdbAt, e.counts, e.houseAt = nil, time.Time{}, nil, time.Time{}
		e.mu.Unlock()
	}()
	t := time.NewTimer(5 * time.Second)
	defer t.Stop()
	lastErr := ""
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		more, err := e.Round(ctx)
		// A failure that goes on is logged once, not every minute.
		if err != nil && ctx.Err() == nil && !errors.Is(err, ErrStale) && err.Error() != lastErr {
			e.log().Warn("behavior baselines: could not learn from the last hour; it is tried again every minute", "err", err)
		}
		lastErr = ""
		if err != nil {
			lastErr = err.Error()
		}
		if more && err == nil {
			t.Reset(time.Second)
		} else {
			t.Reset(every)
		}
	}
}

// Round learns from the hours that ended since the last round, up to
// maxHoursPerRound of them. It reports whether more are waiting.
func (e *Engine) Round(ctx context.Context) (more bool, err error) {
	if !e.allowed() {
		return false, nil
	}
	set, _, err := e.Store.Settings(ctx)
	if err != nil {
		return false, err
	}
	if set.Off {
		return false, nil
	}
	now := e.now()
	st, ver, found, err := e.Store.State(ctx)
	if err != nil {
		return false, err
	}
	if !found {
		back := max(set.Learning(), backfill)
		if e.history > 0 {
			back = e.history
		}
		st = State{Through: now.Add(-back).Truncate(time.Hour), LiveFrom: now}
		e.log().Info("behavior baselines start learning", "from", st.Through, "learning_days", int(set.Learning().Hours()/24))
	}
	dirty := !found
	if st.Checks == nil {
		st.Checks = map[string]*CheckState{}
	}
	for _, c := range Checks {
		cs := st.Checks[c.ID]
		if cs == nil {
			cs = &CheckState{}
			st.Checks[c.ID] = cs
		}
		if cs.Started.IsZero() && set.On(c.ID) {
			cs.Started, dirty = now, true
		}
	}
	reset, err := e.resets(ctx, set, &st)
	if err != nil {
		return false, err
	}
	dirty = dirty || reset
	if err := e.housekeep(ctx, set, now); err != nil {
		e.log().Warn("behavior baselines: could not remove forgotten profiles", "err", err)
	}
	if set.On(NewCountry) || set.On(NewNetwork) {
		// Kept up to date once in use; first downloaded when a sign-in
		// from the internet needs it (signins).
		e.maintainIPDB(ctx, set, now, false)
	}
	// Hours missed while no server ran the jobs are made up for a week;
	// the history of the first run is learned however old.
	if oldest := now.Add(-maxCatchUp).Truncate(time.Hour); found && st.Through.Before(oldest) && !st.Through.Before(st.LiveFrom.Truncate(time.Hour)) {
		e.log().Warn("behavior baselines skip hours no server learned from", "from", st.Through, "to", oldest)
		st.Through = oldest
	}
	st.Epoch, st.Node = e.epoch(), e.NodeID
	done := 0
	for h := st.Through; !h.Add(time.Hour + settle).After(now); h = h.Add(time.Hour) {
		if done == maxHoursPerRound {
			more = true
			break
		}
		if ctx.Err() != nil || !e.allowed() {
			return false, ctx.Err()
		}
		if err := e.hour(ctx, set, &st, h); err != nil {
			st.LastError = err.Error()
			if _, serr := e.Store.SaveState(ctx, st, ver); serr != nil && !errors.Is(serr, ErrStale) {
				e.log().Debug("behavior baselines: could not save the state", "err", serr)
			}
			return false, err
		}
		st.Through, st.LastRun, st.LastError = h.Add(time.Hour), now, ""
		if !e.allowed() {
			return false, nil
		}
		nv, err := e.Store.SaveState(ctx, st, ver)
		if err != nil {
			return false, err
		}
		ver = nv
		done++
	}
	if dirty && done == 0 {
		if !e.allowed() {
			return false, nil
		}
		if _, err := e.Store.SaveState(ctx, st, ver); err != nil {
			return false, err
		}
	}
	return more, nil
}

// resets forgets the profiles of the checks reset since the last round.
func (e *Engine) resets(ctx context.Context, set Settings, st *State) (bool, error) {
	any := false
	for id, cs := range set.Checks {
		at := cs.ResetAt
		state := st.Checks[id]
		if at.IsZero() || state == nil || !at.After(state.Started) {
			continue
		}
		if !e.allowed() {
			return any, nil
		}
		if err := e.Store.Reset(ctx, id); err != nil {
			return any, err
		}
		any = true
		e.log().Info("behavior baselines: a check was reset and learns again", "check", id)
		*state = CheckState{Started: at}
		e.mu.Lock()
		delete(e.counts, id)
		if id == RareProcess {
			delete(e.counts, prevalenceCheck)
		}
		e.mu.Unlock()
	}
	return any, nil
}

func (e *Engine) housekeep(ctx context.Context, set Settings, now time.Time) error {
	e.mu.Lock()
	due := e.houseAt.IsZero() || now.Sub(e.houseAt) >= housekeepEvery
	if due {
		e.houseAt = now
	}
	e.mu.Unlock()
	if !due || !e.allowed() {
		return nil
	}
	if err := e.Store.Forget(ctx, now.Add(-set.Forget())); err != nil {
		return err
	}
	counts := map[string]int64{}
	for _, id := range append(checkIDs(), prevalenceCheck) {
		n, err := e.Store.Count(ctx, id)
		if err != nil {
			return err
		}
		counts[id] = n
	}
	e.mu.Lock()
	e.counts = counts
	e.mu.Unlock()
	return nil
}

func checkIDs() []string {
	out := make([]string, len(Checks))
	for i, c := range Checks {
		out[i] = c.ID
	}
	return out
}

// room reports whether a check may learn one more entity, and counts it.
func (e *Engine) room(check string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.counts == nil {
		e.counts = map[string]int64{}
	}
	if e.counts[check] >= MaxProfiles {
		return false
	}
	e.counts[check]++
	return true
}

// hourRun is one hour being learned from.
type hourRun struct {
	e     *Engine
	set   Settings
	st    *State
	start time.Time
	// live is false for hours that ended before the baselines first ran:
	// they are only learned from.
	live  bool
	lists *assets.Store
	// raised counts the risk events of each check this hour.
	raised map[string]int
	// countryNew holds the users with a new country this hour, whose
	// new network is not raised again.
	countryNew map[string]bool
}

func (e *Engine) hour(ctx context.Context, set Settings, st *State, h time.Time) error {
	r := &hourRun{e: e, set: set, st: st, start: h, live: h.Add(time.Hour).After(st.LiveFrom),
		raised: map[string]int{}, countryNew: map[string]bool{}}
	if e.Assets != nil {
		r.lists = e.Assets.Own()
	}
	if set.On(NewCountry) || set.On(NewNetwork) || set.On(UnusualHour) {
		if err := r.signins(ctx); err != nil {
			return err
		}
	}
	if set.On(RareProcess) {
		if err := r.processes(ctx); err != nil {
			return err
		}
	}
	if set.On(NewChange) {
		if err := r.changes(ctx); err != nil {
			return err
		}
	}
	if set.On(DataVolume) {
		if err := r.volume(ctx); err != nil {
			return err
		}
	}
	return nil
}

// search runs one search over the hour, with sample data left out.
func (r *hourRun) search(ctx context.Context, check, src string) ([]search.Row, error) {
	q, err := query.Parse(src)
	if err != nil {
		return nil, err
	}
	q.Earliest = r.start.Format(time.RFC3339)
	q.Latest = r.start.Add(time.Hour).Format(time.RFC3339)
	detect.ScopeSample(q, "")
	q.EventsOnly = true // it raises risk, as detections do
	ctx, cancel := context.WithTimeout(ctx, searchTimeout)
	defer cancel()
	res, err := r.e.Search.Execute(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", check, err)
	}
	if res.Truncated {
		r.state(check).Truncated = r.start
	}
	return res.Rows, nil
}

func (r *hourRun) state(check string) *CheckState {
	cs := r.st.Checks[check]
	if cs == nil {
		cs = &CheckState{}
		r.st.Checks[check] = cs
	}
	return cs
}

// The searches. Each groups the hour's events by user or host, so one row
// per entity and value is read. Computer accounts (names ending in $)
// sign in by themselves all day, so they are left out.
const (
	signinSearch  = `datamodel=Authentication action=success user=* src=* NOT user="*$" | stats count, min(_time) as first by user, src`
	activeSearch  = `datamodel=Authentication action=success user=* NOT user="*$" | stats count, min(_time) as first by user`
	processSearch = `datamodel=Endpoint process_name=* dest=* | stats count, min(_time) as first by dest, process_name`
	commandSearch = `datamodel=Change user=* command=* NOT status=failure NOT user="*$" | stats count, min(_time) as first by user, command`
	changeSearch  = `datamodel=Change user=* action=* object_category=* NOT command=* NOT status=failure NOT user="*$" | stats count, min(_time) as first by user, action, object_category`
	volumeSearch  = `datamodel=Network_Traffic src=* bytes_out>0 NOT direction=inbound | stats sum(bytes_out) as bytes, min(_time) as first by src`
)

// seen is what an hour's rows say of one entity: its name as the events
// spell it, and each value with the first time and an example row.
type seen struct {
	name   string
	values map[string]*seenValue
	bytes  float64
	first  time.Time
}

type seenValue struct {
	first time.Time
	row   search.Row
	extra map[string]any
}

// group collects rows by the normalized entity in field ent, with the
// value valueOf returns ("" skips the row).
func (r *hourRun) group(rows []search.Row, ent string, valueOf func(search.Row) (string, map[string]any)) map[string]*seen {
	out := map[string]*seen{}
	for _, row := range rows {
		name := strings.TrimSpace(str(row[ent]))
		key := NormEntity(name)
		if key == "" {
			continue
		}
		s := out[key]
		if s == nil {
			s = &seen{name: name, values: map[string]*seenValue{}}
			out[key] = s
		}
		t := r.timeOf(row)
		if s.first.IsZero() || t.Before(s.first) {
			s.first = t
		}
		if valueOf == nil {
			continue
		}
		v, extra := valueOf(row)
		if v == "" {
			continue
		}
		if sv := s.values[v]; sv == nil || t.Before(sv.first) {
			s.values[v] = &seenValue{first: t, row: row, extra: extra}
		}
	}
	return out
}

// timeOf reads a row's first time, within the hour.
func (r *hourRun) timeOf(row search.Row) time.Time {
	end := r.start.Add(time.Hour - time.Second)
	var t time.Time
	switch v := row["first"].(type) {
	case nil:
	case string:
		if parsed, err := time.Parse(time.RFC3339Nano, v); err == nil {
			t = parsed.UTC()
		} else if ms := num(v); ms > 0 {
			t = time.UnixMilli(int64(ms)).UTC()
		}
	default:
		// min(_time) is in milliseconds since 1970.
		if ms := num(v); ms > 0 {
			t = time.UnixMilli(int64(ms)).UTC()
		}
	}
	if t.Before(r.start) || t.After(end) {
		return end
	}
	return t
}

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
	}
	return fmt.Sprint(v)
}

func num(v any) float64 {
	switch x := v.(type) {
	case float64:
		return x
	case int64:
		return float64(x)
	case int:
		return float64(x)
	case string:
		f, _ := strconv.ParseFloat(strings.TrimSpace(x), 64)
		return f
	}
	return 0
}

// learn reads the profiles of the entities in chunks, lets fn update each
// one (nil when the check has none yet) and return its risk events, then
// writes the risk and the profiles. fn returns a nil profile to leave it
// as it is. An entity whose profile already has this hour is skipped, so
// an hour learned twice counts once.
func (r *hourRun) learn(ctx context.Context, check string, all map[string]*seen, fn func(p *Profile, key string, s *seen) []detect.RiskEvent) error {
	keys := make([]string, 0, len(all))
	for k := range all {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for len(keys) > 0 {
		part := keys[:min(chunk, len(keys))]
		keys = keys[len(part):]
		ps, err := r.e.Store.Profiles(ctx, check, part)
		if err != nil {
			return err
		}
		var write []*Profile
		var events []detect.RiskEvent
		for i, key := range part {
			p := ps[i]
			if p != nil && p.applied(r.start) {
				continue
			}
			if p == nil {
				if !r.e.room(check) {
					r.state(check).Full = r.start
					continue
				}
				p = newProfile(check, key, r.start)
			}
			p.forget(r.start.Add(-r.set.Forget()))
			events = append(events, fn(p, key, all[key])...)
			p.touch(r.start)
			write = append(write, p)
		}
		events = r.admit(check, events)
		if !r.e.allowed() {
			return ErrStale
		}
		if len(events) > 0 && r.e.Risk != nil {
			if err := r.e.Risk.Write(ctx, events); err != nil {
				return fmt.Errorf("%s: %w", check, err)
			}
		}
		if err := r.e.Store.WriteProfiles(ctx, write); err != nil {
			return err
		}
	}
	return nil
}

// canRaise reports whether a profile has learned long enough for its
// unusual behavior in this hour to add risk.
func (r *hourRun) canRaise(p *Profile) bool {
	return r.live && p.learned(r.start, r.set.Learning())
}

// admit drops the events an exception holds back and those over the most
// one hour may raise, and counts what is left.
func (r *hourRun) admit(check string, events []detect.RiskEvent) []detect.RiskEvent {
	cs := r.state(check)
	out := events[:0]
	for _, ev := range events {
		if r.excepted(ev) {
			cs.Excepted++
			continue
		}
		if r.raised[check] >= MaxRaisedPerHour {
			cs.Capped++
			continue
		}
		r.raised[check]++
		cs.Raised++
		if ev.Time.After(cs.LastRaised) {
			cs.LastRaised = ev.Time
		}
		out = append(out, ev)
	}
	return out
}

func (r *hourRun) excepted(ev detect.RiskEvent) bool {
	if len(r.set.Exceptions) == 0 {
		return false
	}
	row := make(map[string]any, len(ev.Fields)+2)
	for k, v := range ev.Fields {
		row[k] = v
	}
	row["risk_object"], row["risk_object_type"] = ev.Object, ev.ObjectType
	for i := range r.set.Exceptions {
		if x := &r.set.Exceptions[i]; x.Active(ev.Time) && x.Matches(row) {
			return true
		}
	}
	return false
}

// event makes a check's risk event for an entity and value.
func (r *hourRun) event(check, objType, object, value, message string, at time.Time, fields map[string]any) detect.RiskEvent {
	base := r.set.Score(check)
	score := float64(base)
	ev := detect.RiskEvent{
		ID:   eventID(check, NormEntity(object), value, r.start),
		Time: at, Object: object, ObjectType: objType, BaseScore: base, Score: score,
		Message: message, DetectionID: DetectionID(check), GroupKey: check + "\x00" + NormEntity(object),
		Fields: fields,
	}
	if c, ok := CheckByID(check); ok {
		ev.MITRE = c.MITRE
		if c.Tactic != "" {
			ev.Tactics = []string{c.Tactic}
		}
	}
	if r.lists != nil {
		field := "dest"
		if objType == "user" {
			field = "user"
		}
		if c, ok := r.lists.Lookup(field, object); ok {
			ev.Priority = c.Priority
			mult := assets.Multiplier(c.Priority)
			if c.Watchlist && mult < 1.5 {
				mult = 1.5
			}
			ev.Score = math.Round(score*mult*10) / 10
		}
	}
	fields["baseline"], fields["baseline_value"] = check, value
	return ev
}

func eventID(parts ...any) string {
	h := sha256.New()
	for _, p := range parts {
		switch v := p.(type) {
		case time.Time:
			fmt.Fprint(h, v.UTC().Format(time.RFC3339), "\x00")
		default:
			fmt.Fprint(h, v, "\x00")
		}
	}
	return "bl_" + hex.EncodeToString(h.Sum(nil)[:16])
}

// sortedValues returns a seen entity's values in order.
func sortedValues(s *seen) []string {
	out := make([]string, 0, len(s.values))
	for v := range s.values {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

// ---------- sign-ins ----------

// publicSource reports whether any row's src is an internet address.
func publicSource(rows []search.Row) bool {
	for _, row := range rows {
		if a, err := netip.ParseAddr(str(row["src"])); err == nil && Public(a) {
			return true
		}
	}
	return false
}

func (r *hourRun) signins(ctx context.Context) error {
	if (r.set.On(NewCountry) || r.set.On(NewNetwork)) && r.set.IPSource() != "" {
		rows, err := r.search(ctx, NewCountry, signinSearch)
		if err != nil {
			return err
		}
		db := r.e.currentIPDB()
		if db == nil && publicSource(rows) {
			// The first sign-in from the internet: only now is the IP
			// database downloaded, so a server whose users sign in only
			// from inside never fetches it.
			r.e.maintainIPDB(ctx, r.set, r.e.now(), true)
			db = r.e.currentIPDB()
		}
		if db != nil {
			if err := r.networks(ctx, db, rows); err != nil {
				return err
			}
		}
	}
	if r.set.On(UnusualHour) {
		rows, err := r.search(ctx, UnusualHour, activeSearch)
		if err != nil {
			return err
		}
		if err := r.hours(ctx, rows); err != nil {
			return err
		}
	}
	return nil
}

func (r *hourRun) networks(ctx context.Context, db *IPDB, rows []search.Row) error {
	netOf := func(row search.Row) (Network, string, bool) {
		src := strings.TrimSpace(str(row["src"]))
		a, err := netip.ParseAddr(src)
		if err != nil || !Public(a) {
			return Network{}, "", false
		}
		n, ok := db.Lookup(a)
		return n, src, ok
	}
	if r.set.On(NewCountry) {
		users := r.group(rows, "user", func(row search.Row) (string, map[string]any) {
			n, src, ok := netOf(row)
			if !ok || n.Country == "" {
				return "", nil
			}
			return n.Country, map[string]any{"src": src, "src_country": n.Country, "src_asn": n.AS(), "src_asn_name": n.Name}
		})
		err := r.learn(ctx, NewCountry, users, func(p *Profile, key string, s *seen) []detect.RiskEvent {
			var out []detect.RiskEvent
			can := r.canRaise(p)
			for _, c := range sortedValues(s) {
				if p.see(c, r.start) && can {
					sv := s.values[c]
					f := map[string]any{"user": s.name}
					for k, v := range sv.extra {
						f[k] = v
					}
					msg := fmt.Sprintf("First sign-in from %s for %s, from %s", CountryName(c), s.name, sv.extra["src"])
					out = append(out, r.event(NewCountry, "user", s.name, c, msg, sv.first, f))
					r.countryNew[key] = true
				}
			}
			return out
		})
		if err != nil {
			return err
		}
	}
	if r.set.On(NewNetwork) {
		users := r.group(rows, "user", func(row search.Row) (string, map[string]any) {
			n, src, ok := netOf(row)
			if !ok {
				return "", nil
			}
			return n.AS(), map[string]any{"src": src, "src_country": n.Country, "src_asn": n.AS(), "src_asn_name": n.Name}
		})
		err := r.learn(ctx, NewNetwork, users, func(p *Profile, key string, s *seen) []detect.RiskEvent {
			var out []detect.RiskEvent
			can := r.canRaise(p) && !r.countryNew[key]
			for _, as := range sortedValues(s) {
				if p.see(as, r.start) && can {
					sv := s.values[as]
					f := map[string]any{"user": s.name}
					for k, v := range sv.extra {
						if v != "" {
							f[k] = v
						}
					}
					name := as
					if n, _ := sv.extra["src_asn_name"].(string); n != "" {
						name += " (" + n + ")"
					}
					msg := fmt.Sprintf("First sign-in from network %s for %s, from %s", name, s.name, sv.extra["src"])
					out = append(out, r.event(NewNetwork, "user", s.name, as, msg, sv.first, f))
				}
			}
			return out
		})
		if err != nil {
			return err
		}
	}
	return nil
}

func (r *hourRun) hours(ctx context.Context, rows []search.Row) error {
	users := r.group(rows, "user", nil)
	hr := r.start.Hour()
	return r.learn(ctx, UnusualHour, users, func(p *Profile, key string, s *seen) []detect.RiskEvent {
		share := p.hourShare(hr)
		rare := r.canRaise(p) && p.Hours >= minHourHistory && share < rareHourShare
		p.countHour(hr)
		if !rare {
			return nil
		}
		value := fmt.Sprintf("%02d:00 UTC", hr)
		msg := fmt.Sprintf("Sign-in by %s between %02d:00 and %02d:00 UTC, when they are rarely active (%.1f%% of their active hours)",
			s.name, hr, (hr+1)%24, share*100)
		return []detect.RiskEvent{r.event(UnusualHour, "user", s.name, value, msg, s.first, map[string]any{"user": s.name})}
	})
}

// ---------- processes ----------

func (r *hourRun) processes(ctx context.Context) error {
	rows, err := r.search(ctx, RareProcess, processSearch)
	if err != nil {
		return err
	}
	procName := func(row search.Row) (string, map[string]any) {
		return NormEntity(str(row["process_name"])), nil
	}
	hosts := r.group(rows, "dest", procName)
	// How many hosts ran each program: first the fleet profiles learn
	// this hour's hosts.
	procs := map[string]*seen{}
	for hk, h := range hosts {
		for p, sv := range h.values {
			s := procs[p]
			if s == nil {
				s = &seen{name: p, values: map[string]*seenValue{}}
				procs[p] = s
			}
			s.values[hk] = sv
		}
	}
	prevalence := map[string]int{}
	err = r.learn(ctx, prevalenceCheck, procs, func(p *Profile, key string, s *seen) []detect.RiskEvent {
		for _, h := range sortedValues(s) {
			if p.has(h) {
				p.see(h, r.start)
				continue
			}
			if len(p.Values) >= prevalenceCap {
				p.Many = true
				continue
			}
			p.see(h, r.start)
		}
		prevalence[key] = len(p.Values)
		if p.Many {
			prevalence[key] = prevalenceCap + 1
		}
		return nil
	})
	if err != nil {
		return err
	}
	rare := r.set.rareHosts()
	return r.learn(ctx, RareProcess, hosts, func(p *Profile, key string, s *seen) []detect.RiskEvent {
		var out []detect.RiskEvent
		can := r.canRaise(p)
		for _, proc := range sortedValues(s) {
			if !p.see(proc, r.start) || !can {
				continue
			}
			n, known := prevalence[proc]
			if !known || n > rare {
				continue
			}
			sv := s.values[proc]
			name := strings.TrimSpace(str(sv.row["process_name"]))
			hostsWord := "host"
			if n != 1 {
				hostsWord = "hosts"
			}
			msg := fmt.Sprintf("First run of %s on %s, a program %d %s ever ran", name, s.name, n, hostsWord)
			out = append(out, r.event(RareProcess, "system", s.name, proc, msg, sv.first,
				map[string]any{"dest": s.name, "process_name": name, "baseline_hosts": n}))
		}
		return out
	})
}

// ---------- changes ----------

func (r *hourRun) changes(ctx context.Context) error {
	cmds, err := r.search(ctx, NewChange, commandSearch)
	if err != nil {
		return err
	}
	others, err := r.search(ctx, NewChange, changeSearch)
	if err != nil {
		return err
	}
	rows := append(slices.Clip(cmds), others...)
	users := r.group(rows, "user", func(row search.Row) (string, map[string]any) {
		if c := strings.TrimSpace(str(row["command"])); c != "" {
			return cut(c, maxValueLen), map[string]any{"command": c}
		}
		a, o := strings.TrimSpace(str(row["action"])), strings.TrimSpace(str(row["object_category"]))
		if a == "" || o == "" {
			return "", nil
		}
		return cut(strings.ToLower(a+" "+o), maxValueLen), map[string]any{"action": a, "object_category": o}
	})
	return r.learn(ctx, NewChange, users, func(p *Profile, key string, s *seen) []detect.RiskEvent {
		var out []detect.RiskEvent
		can := r.canRaise(p)
		for _, v := range sortedValues(s) {
			if p.see(v, r.start) && can {
				sv := s.values[v]
				f := map[string]any{"user": s.name}
				for k, x := range sv.extra {
					f[k] = x
				}
				msg := fmt.Sprintf("First time %s made this kind of change: %s", s.name, v)
				out = append(out, r.event(NewChange, "user", s.name, v, msg, sv.first, f))
			}
		}
		return out
	})
}

// ---------- data volume ----------

func (r *hourRun) volume(ctx context.Context) error {
	rows, err := r.search(ctx, DataVolume, volumeSearch)
	if err != nil {
		return err
	}
	srcs := map[string]*seen{}
	for _, row := range rows {
		name := strings.TrimSpace(str(row["src"]))
		a, err := netip.ParseAddr(name)
		// Only hosts on your own network: an outside address sending to
		// it is not data leaving.
		if err != nil || Public(a) {
			continue
		}
		key := a.Unmap().String()
		s := srcs[key]
		if s == nil {
			s = &seen{name: key, first: r.timeOf(row)}
			srcs[key] = s
		}
		s.bytes += num(row["bytes"])
	}
	minBytes := r.set.minBytes()
	return r.learn(ctx, DataVolume, srcs, func(p *Profile, key string, s *seen) []detect.RiskEvent {
		mean, sd := p.usual(r.start)
		spike := r.canRaise(p) && p.Span >= minVolumeHours && s.bytes >= minBytes &&
			s.bytes >= volumeFactor*mean && s.bytes >= mean+volumeSigmas*sd
		p.addVolume(s.bytes, r.start)
		if !spike {
			return nil
		}
		times := "far more than"
		if mean > 0 {
			times = fmt.Sprintf("about %s times", strconv.FormatFloat(math.Round(s.bytes/mean), 'f', -1, 64))
		}
		msg := fmt.Sprintf("%s sent %s in an hour, %s its usual %s", s.name, size(s.bytes), times, size(mean))
		return []detect.RiskEvent{r.event(DataVolume, "system", s.name, size(s.bytes), msg, s.first,
			map[string]any{"src": s.name, "bytes_out": int64(s.bytes), "baseline_usual_bytes": int64(mean)})}
	})
}

// size words a number of bytes.
func size(b float64) string {
	switch {
	case b >= 1e12:
		return fmt.Sprintf("%.1f TB", b/1e12)
	case b >= 1e9:
		return fmt.Sprintf("%.1f GB", b/1e9)
	case b >= 1e6:
		return fmt.Sprintf("%.0f MB", b/1e6)
	case b >= 1e3:
		return fmt.Sprintf("%.0f KB", b/1e3)
	}
	return fmt.Sprintf("%.0f bytes", b)
}

// ---------- the IP database ----------

func (e *Engine) currentIPDB() *IPDB {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.ipdb
}

// maintainIPDB downloads the IP database when it is a week old or its
// source changed, and loads the stored copy when it is newer than the one
// in memory. A failed download keeps the last copy. Until it was first
// downloaded, it is downloaded only when need is true.
func (e *Engine) maintainIPDB(ctx context.Context, set Settings, now time.Time, need bool) {
	src := set.IPSource()
	if src == "" {
		e.mu.Lock()
		e.ipdb, e.ipdbAt = nil, time.Time{}
		e.mu.Unlock()
		return
	}
	meta, _, err := e.Store.IPDBStatus(ctx)
	if err != nil {
		e.log().Warn("behavior baselines: could not read the IP database's status", "err", err)
		return
	}
	if !need && meta.FetchedAt.IsZero() {
		return // not needed yet
	}
	stale := meta.Source != src || meta.FetchedAt.IsZero() || now.Sub(meta.FetchedAt) >= ipdbFresh
	retry := meta.Source != src || meta.TriedAt.IsZero() || now.Sub(meta.TriedAt) >= ipdbRetry
	if stale && retry && e.allowed() {
		meta.TriedAt = now
		db, err := e.fetchIPDB(ctx, src)
		if err == nil {
			err = e.Store.saveIPDB(ctx, db, now)
		}
		if ctx.Err() != nil {
			return // stopping: tried again by the next round
		}
		if err != nil {
			meta.Error = sentence(err)
			e.log().Warn("behavior baselines: could not download the IP database; the last copy is used", "source", redactSource(src), "err", err)
		} else {
			meta.Source, meta.FetchedAt, meta.Rows, meta.Error = src, now, db.Rows(), ""
			e.mu.Lock()
			e.ipdb, e.ipdbAt = db, now
			e.mu.Unlock()
			e.log().Info("behavior baselines: IP database updated", "ranges", db.Rows())
		}
		if err := e.Store.saveIPDBStatus(ctx, meta); err != nil {
			e.log().Warn("behavior baselines: could not save the IP database's status", "err", err)
		}
	}
	e.mu.Lock()
	loaded := e.ipdbAt
	e.mu.Unlock()
	if meta.FetchedAt.IsZero() || meta.FetchedAt.Equal(loaded) {
		return
	}
	db, at, err := e.Store.loadIPDB(ctx)
	if err != nil || db == nil {
		if err != nil {
			e.log().Warn("behavior baselines: could not read the stored IP database", "err", err)
		}
		return
	}
	e.mu.Lock()
	e.ipdb, e.ipdbAt = db, at
	e.mu.Unlock()
}

func (e *Engine) fetchIPDB(ctx context.Context, src string) (*IPDB, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	if name, ok := ipFile(src); ok {
		if err := fileNameProblem(name); err != nil {
			return nil, err
		}
		if e.FileDir == "" {
			return nil, errors.New("this server has no ipdb folder for IP database files")
		}
		// The root keeps the open inside the folder, through symbolic
		// links too.
		root, err := os.OpenRoot(e.FileDir)
		if err != nil {
			return nil, fmt.Errorf("the ipdb folder can't be opened: %w", err)
		}
		defer root.Close()
		f, err := root.Open(name)
		if err != nil {
			return nil, fmt.Errorf("%s is not in the ipdb folder (%s)", name, e.FileDir)
		}
		defer f.Close()
		return ParseIPDB(&ctxReader{ctx: ctx, r: f})
	}
	if e.HTTP == nil {
		return nil, errors.New("downloads are not set up on this server")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, src, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Signalith")
	// A redirect stays on https, as the address itself must.
	client := *e.HTTP
	client.CheckRedirect = func(r *http.Request, via []*http.Request) error {
		if r.URL.Scheme != "https" {
			return errors.New("the IP database address redirected to an address that is not https")
		}
		if len(via) >= 5 {
			return errors.New("the IP database address redirected too many times")
		}
		return nil
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s answered %s", redactSource(src), resp.Status)
	}
	return ParseIPDB(&ctxReader{ctx: ctx, r: resp.Body})
}

// redactSource leaves only the host of an address, for logs.
func redactSource(src string) string {
	if name, ok := ipFile(src); ok {
		return "file:" + name
	}
	rest := strings.TrimPrefix(strings.TrimPrefix(src, "https://"), "http://")
	host, _, _ := strings.Cut(rest, "/")
	return host
}

func sentence(err error) string {
	s := err.Error()
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}
