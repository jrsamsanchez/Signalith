// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

// Package sample generates a realistic week of security activity for a
// fictional company, with attacks hidden in it, so an evaluator can try
// Signalith on data that makes detections fire, fills the findings queue,
// builds risk on users and hosts, matches threat intel and lights up the
// dashboards — all loaded and removed in one click.
//
// Everything is made up and safe to load on any network: the company is
// fictional, its domain is corp.example (RFC 6761), and every address,
// internal and external, is from the documentation ranges in RFC 5737
// (192.0.2.0/24 for the company, 198.51.100.0/24 and 203.0.113.0/24 for the
// internet), so no sample host can be mistaken for a real one. The
// generator is deterministic (seeded) and offline, and every document it
// makes carries a marker (datamodel.SampleField) holding the load's ID:
// the live detection scheduler leaves marked documents out, and Remove
// deletes exactly them and nothing else.
package sample

import (
	"net/netip"
	"sort"
	"time"

	"github.com/jrsamsanchez/signalith/internal/assets"
	"github.com/jrsamsanchez/signalith/internal/ingest"
	"github.com/jrsamsanchez/signalith/internal/intel"
)

// Size is how much background activity the sample holds. The attack
// stories are the same in both sizes.
type Size string

const (
	// SizeStandard is a realistic week in the tens of thousands of events.
	SizeStandard Size = "standard"
	// SizeSmall is a smaller set for tests and quick trials.
	SizeSmall Size = "small"
)

// Sizes lists the valid sizes.
var Sizes = []Size{SizeStandard, SizeSmall}

// Valid reports whether s is a known size.
func (s Size) Valid() bool {
	return s == SizeStandard || s == SizeSmall
}

// Options control a generation.
type Options struct {
	// Now is the end of the sample's time range; the last events sit a few
	// minutes before it. Zero means time.Now().
	Now time.Time
	// Size is "standard" (default) or "small".
	Size Size
	// Seed makes the generation reproducible; zero uses a fixed seed, so
	// two loads with the same options produce identical data.
	Seed int64
}

// Story is one attack narrative in the sample, for the status reply and
// the docs: what it is and which detections it makes fire.
type Story struct {
	ID         string   `json:"id"`
	Title      string   `json:"title"`
	Summary    string   `json:"summary"`
	Detections []string `json:"detections"` // built-in detection IDs it fires
	Entities   []string `json:"entities"`   // the users, hosts and IPs it involves
}

// Data is a generated sample: the events, the extra context lists and
// threat intel, the backfill run times, and the stories (for the UI and
// docs). Nothing here has been written anywhere yet.
type Data struct {
	ID         string            // the load ID, also the marker value
	Size       Size              // the size this was generated at
	Start      time.Time         // first event time
	End        time.Time         // last event time
	Events     []ingest.Event    // every event, marker already set
	Indicators []intel.Indicator // sample threat-intel indicators (source SampleIntelSource)
	Assets     []assets.Asset    // sample assets to overlay on the user's list
	Identities []assets.Identity // sample identities to overlay
	Stories    []Story           // the attack narratives
	RunTimes   []time.Time       // times to run the detections at (scenario ends)
	// CaseFocus are the entity values (host, address, user) of the story
	// the sample investigation follows, to pick its findings.
	CaseFocus []string
}

// SampleIntelSource is the threat-intel source name sample indicators use,
// so they can be removed with intel.Store.DeleteSource without touching a
// user's own indicators. No feed can have it (feed names are lowercase,
// without spaces).
const SampleIntelSource = intel.SampleSource

// SampleBUnit tags the sample's asset and identity rows so they are
// recognisable where they show (they live in the asset store's overlay,
// never in the user's own lists).
const SampleBUnit = "Sample data"

// MaxEventAge is the event age the loader writes with, whatever the
// server's own limit: the sample reaches back six days, and a shorter
// limit (a short retention period, or ingest.max_event_age) would refile
// its older events at the load time, where they would tell a false story.
// Retention later deletes the older sample days like any others.
const MaxEventAge = 8 * 24 * time.Hour

// Generate builds the sample. It is deterministic: the same options give
// the same data every time, and it reads nothing from the network or disk.
func Generate(opt Options) *Data {
	now := opt.Now
	if now.IsZero() {
		now = time.Now()
	}
	now = now.UTC().Truncate(time.Minute)
	size := opt.Size
	if size == "" {
		size = SizeStandard
	}
	seed := opt.Seed
	if seed == 0 {
		seed = 0x51A3_17E5 // fixed, so loads are reproducible
	}

	id := "sample-" + now.Format("20060102-150405")
	g := &gen{
		b:    &builder{id: id, now: now},
		rng:  newRNG(uint64(seed)),
		org:  buildOrg(),
		now:  now,
		size: size,
	}

	// The last events end a few minutes before now; history reaches back
	// six days, inside MaxEventAge, which the loader writes with.
	g.end = now.Add(-5 * time.Minute)
	g.start = now.AddDate(0, 0, -6)

	g.background()
	attackStart := len(g.b.events)
	g.attacks()
	// Back the detections over every attack event, not just the story
	// ends: a story can run longer than a detection's lookback, so an
	// early event (an Office macro, a credential dump) would fall outside
	// the window of a run anchored at the story's end. Registering a run
	// time one minute after each attack event guarantees every event sits
	// inside at least one run's lookback window, so every detection that
	// can fire does. Background noise is left out, so the run-time set
	// stays small. runTimes() truncates and de-duplicates these.
	for _, ev := range g.b.events[attackStart:] {
		g.addRunTime(ev.Time.Add(time.Minute))
	}

	d := &Data{
		ID:         id,
		Size:       size,
		Start:      g.start,
		End:        g.end,
		Events:     g.b.events,
		Indicators: sampleIndicators(now),
		Stories:    g.stories,
		RunTimes:   g.runTimes(),
		CaseFocus:  g.caseFocus,
	}
	d.Assets, d.Identities = sampleLists(g.org)
	return d
}

// gen is the working state of one generation.
type gen struct {
	b          *builder
	rng        *rng
	org        *org
	now        time.Time
	start, end time.Time
	size       Size
	stories    []Story
	runTimeSet []time.Time
	caseFocus  []string
}

func (g *gen) addRunTime(t time.Time) {
	g.runTimeSet = append(g.runTimeSet, t.UTC().Truncate(time.Minute))
}

// runTimes returns the distinct scenario run times, oldest first, plus the
// end of the range, so the backfill fires each detection where its window
// holds a burst and the risk detections see everything up to the end.
func (g *gen) runTimes() []time.Time {
	seen := map[int64]bool{}
	var out []time.Time
	add := func(t time.Time) {
		t = t.UTC().Truncate(time.Minute)
		if !seen[t.Unix()] {
			seen[t.Unix()] = true
			out = append(out, t)
		}
	}
	for _, t := range g.runTimeSet {
		add(t)
	}
	add(g.end)
	sort.Slice(out, func(i, j int) bool { return out[i].Before(out[j]) })
	return out
}

// mustAddr parses an IP for the syslog sender; sample IPs are all valid.
func mustAddr(s string) netip.Addr {
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}
	}
	return a
}

// ReservedExternal reports whether an address is in one of the
// documentation ranges (RFC 5737) the sample uses for every address. The
// test uses it to prove no real address leaks in.
func ReservedExternal(ip string) bool {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	for _, c := range []string{"192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"} {
		if netip.MustParsePrefix(c).Contains(a) {
			return true
		}
	}
	return false
}

// Internal reports whether an address is in the range the sample uses for
// the company's own hosts (InternalNet).
func Internal(ip string) bool {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	return netip.MustParsePrefix(InternalNet).Contains(a)
}

func (s Size) String() string { return string(s) }
