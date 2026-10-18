package dashboards

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jrsamsanchez/signalith/internal/datamodel"
	"github.com/jrsamsanchez/signalith/internal/ingest"
	"github.com/jrsamsanchez/signalith/internal/query"
	"github.com/jrsamsanchez/signalith/internal/search"
)

// SourceWatch writes a "Data source stopped sending" event (sourcetype
// source:health) when a host and source type that sent steadily goes
// quiet: a search cannot find what did not arrive, so the built-in
// detection data-source-stopped reads these. A logging pipeline that
// breaks, or an attacker who turns logging off, looks the same from here.
//
// Steady means the source sent something in each of the four six-hour
// blocks of the day before it went quiet, so a workstation that is off at
// night or a weekly scan never counts. Quiet means nothing for StaleAfter
// (dashboards.stale_after, the same setting the Posture dashboard uses).
// One event is written per silence. It runs on the server that runs the
// background jobs; the event IDs come from the source and when it was last
// heard, so a second server taking over writes the same ones again.
type SourceWatch struct {
	Engine Executor
	Events interface {
		IngestEvents(ctx context.Context, events []ingest.Event) (*ingest.Result, error)
	}
	// StaleAfter returns how long a source can be quiet (2h when nil or
	// not positive). It is read on each check, so a change on the
	// Settings page applies at once.
	StaleAfter func() time.Duration
	// Leader reports whether this server runs the background jobs; nil
	// for a single server, which always does.
	Leader func() bool
	Log    *slog.Logger
	Now    func() time.Time
	// Every is how often sources are checked (15 minutes when zero).
	Every time.Duration

	mu sync.Mutex
	// written is, by source, when the source was last heard for the event
	// already written.
	written map[sourceKey]time.Time
}

type sourceKey struct{ host, sourcetype string }

// SourceHealthSourcetype is the sourcetype of the events SourceWatch
// writes.
const SourceHealthSourcetype = "source:health"

const (
	// steadyBlocks blocks of steadyBlock each make up the day a source must
	// have sent in throughout to count as steady.
	steadyBlocks = 4
	steadyBlock  = 6 * time.Hour
	// maxSourceEvents caps the events one check writes, so a whole site
	// going dark is a handful of findings, not thousands.
	maxSourceEvents = 50
)

// qWatched leaves out sample data, what Signalith writes about itself and
// its own scans, which come and go by design.
var qWatched = "NOT " + datamodel.SampleField + "=* NOT " + ingest.IntakeField + " IN (" +
	ingest.IntakeSignalith + ", " + ingest.IntakeScanner + ")\n"

func (w *SourceWatch) now() time.Time {
	if w.Now != nil {
		return w.Now()
	}
	return time.Now()
}

func (w *SourceWatch) stale() time.Duration {
	if w.StaleAfter != nil {
		if d := w.StaleAfter(); d > 0 {
			return d
		}
	}
	return 2 * time.Hour
}

// Run checks the sources every Every until ctx ends.
func (w *SourceWatch) Run(ctx context.Context) {
	every := w.Every
	if every <= 0 {
		every = 15 * time.Minute
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := w.Check(ctx); err != nil && ctx.Err() == nil && w.Log != nil {
				w.Log.Warn("data sources that stopped sending could not be checked; Signalith tries again later", "err", err)
			}
		}
	}
}

// Check writes an event for each steady source that went quiet since the
// last check.
func (w *SourceWatch) Check(ctx context.Context) error {
	if w.Leader != nil && !w.Leader() {
		return nil
	}
	now := w.now().UTC()
	stale := w.stale()
	cutoff := now.Add(-stale)
	run := func(src string, from, to time.Time) (*search.Result, error) {
		q, err := query.Parse(qWatched + src)
		if err != nil {
			return nil, err
		}
		q.Earliest = from.Format(time.RFC3339Nano)
		if !to.IsZero() {
			q.Latest = to.Format(time.RFC3339Nano)
		}
		q.EventsOnly = true // it raises findings, as detections do
		return w.Engine.Execute(ctx, q)
	}
	// The last block runs to now: a source heard in it before the cutoff
	// and not since went quiet. One heard only before it went quiet
	// earlier, and had its event then.
	recent, err := run("| stats max(_time) as last_seen by host, sourcetype", cutoff.Add(-steadyBlock), time.Time{})
	if err != nil {
		return err
	}
	quiet := map[sourceKey]time.Time{}
	for _, r := range recent.Rows {
		k, ok := rowSource(r)
		if !ok {
			continue
		}
		ms, ok := toFloatAny(r["last_seen"])
		if !ok {
			continue
		}
		if last := time.UnixMilli(int64(ms)).UTC(); last.Before(cutoff) {
			quiet[k] = last
		}
	}
	// Each earlier block must have the source too.
	for i := 1; i < steadyBlocks && len(quiet) > 0; i++ {
		to := cutoff.Add(-time.Duration(i) * steadyBlock)
		res, err := run("| stats count by host, sourcetype", to.Add(-steadyBlock), to)
		if err != nil {
			return err
		}
		in := map[sourceKey]bool{}
		for _, r := range res.Rows {
			if k, ok := rowSource(r); ok && toNum(r["count"]) > 0 {
				in[k] = true
			}
		}
		for k := range quiet {
			if !in[k] {
				delete(quiet, k)
			}
		}
	}

	w.mu.Lock()
	defer w.mu.Unlock()
	if w.written == nil {
		w.written = map[sourceKey]time.Time{}
	}
	for k, last := range w.written {
		// Keep a silence while it can still be found again; a source that
		// sent and went quiet again has a new last event and a new event.
		q, ok := quiet[k]
		if (ok && !q.Equal(last)) || (!ok && now.Sub(last) > stale+steadyBlock) {
			delete(w.written, k)
		}
	}
	keys := make([]sourceKey, 0, len(quiet))
	for k, last := range quiet {
		if prev, ok := w.written[k]; ok && prev.Equal(last) {
			continue
		}
		keys = append(keys, k)
	}
	if len(keys) == 0 {
		return nil
	}
	// The most recently quiet first: those are the ones still news.
	sort.Slice(keys, func(i, j int) bool {
		if a, b := quiet[keys[i]], quiet[keys[j]]; !a.Equal(b) {
			return a.After(b)
		}
		if keys[i].host != keys[j].host {
			return keys[i].host < keys[j].host
		}
		return keys[i].sourcetype < keys[j].sourcetype
	})
	keys = keys[:min(len(keys), maxSourceEvents)]
	evs := make([]ingest.Event, 0, len(keys))
	for _, k := range keys {
		evs = append(evs, stoppedEvent(k, quiet[k], now))
	}
	ctx = ingest.WithOrigin(ctx, ingest.Origin{Intake: ingest.IntakeSignalith})
	if _, err := w.Events.IngestEvents(ctx, evs); err != nil {
		return err
	}
	for _, k := range keys {
		w.written[k] = quiet[k]
	}
	return nil
}

// rowSource reads the host and source type of a stats row.
func rowSource(r search.Row) (sourceKey, bool) {
	h, _ := r["host"].(string)
	st, _ := r["sourcetype"].(string)
	if h == "" || st == "" || st == SourceHealthSourcetype {
		return sourceKey{}, false
	}
	return sourceKey{host: h, sourcetype: st}, true
}

// stoppedEvent is the event for source k, quiet since last.
func stoppedEvent(k sourceKey, last, now time.Time) ingest.Event {
	quiet := now.Sub(last).Truncate(time.Minute)
	h := sha256.Sum256([]byte(strings.Join([]string{"stopped", k.host, k.sourcetype, last.UTC().Format(time.RFC3339Nano)}, "\x00")))
	return ingest.Event{Time: now, Model: "Other", ID: "source-health-" + hex.EncodeToString(h[:8]), Fields: map[string]any{
		"sourcetype":         SourceHealthSourcetype,
		"vendor_product":     "Signalith",
		"signature":          "Data source stopped sending",
		"host":               k.host,
		"dvc":                k.host,
		"stopped_sourcetype": k.sourcetype,
		"last_seen":          last.UTC().Format(time.RFC3339),
		"quiet_minutes":      int64(quiet / time.Minute),
		"message": fmt.Sprintf("%s stopped sending %s: nothing for %s (last event %s UTC), after sending all day before",
			k.host, k.sourcetype, quietLabel(quiet), last.UTC().Format("2006-01-02 15:04")),
	}}
}

// quietLabel writes a silence in minutes or hours.
func quietLabel(d time.Duration) string {
	if d < 2*time.Hour {
		return fmt.Sprintf("%d minutes", int(d.Minutes()))
	}
	return fmt.Sprintf("%d hours", int(d.Hours()))
}
