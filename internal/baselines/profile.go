// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package baselines

import (
	"crypto/sha256"
	"encoding/hex"
	"math"
	"slices"
	"strings"
	"time"
)

// A profile is what one check has learned of one user or host: the
// values it has seen (countries, networks, processes, kinds of change),
// the hours of the day it is active, or how much it sends in an hour.
// Each is one document in the baselines index, and each is bounded.

// Bounds of a profile.
const (
	// MaxValues is the most values one profile keeps, unless its check
	// keeps more (valueLimits). When a new one would go over, the one
	// seen longest ago is forgotten, and is new again when it comes back.
	MaxValues = 200
	// maxValueLen is the longest value kept; longer ones are cut.
	maxValueLen = 256
	// maxEntityLen is the longest user or host name kept.
	maxEntityLen = 512
	// prevalenceCap is how many hosts a process's fleet profile names:
	// once that many ran it, it is common, and which ones no longer
	// matters.
	prevalenceCap = 16
)

// valueLimits are the checks whose users or hosts often have more
// values than MaxValues: a busy admin makes hundreds of kinds of change,
// and a developer's computer runs hundreds of programs. Forgetting one
// of those would make it "new" the next time. About 120 bytes a value.
var valueLimits = map[string]int{
	NewChange:   2000,
	RareProcess: 2000,
	NewNetwork:  500,
	NewCountry:  250, // every country
}

// ValueLimit is the most values a profile of a check keeps.
func ValueLimit(check string) int {
	if n, ok := valueLimits[check]; ok {
		return n
	}
	return MaxValues
}

// Value is one value a profile has seen.
type Value struct {
	V     string    `json:"v"`
	First time.Time `json:"first"`
	Last  time.Time `json:"last"`
	// N counts the hours it was seen in.
	N int64 `json:"n"`
}

// Profile is one check's baseline of one user or host.
type Profile struct {
	Kind   string `json:"kind"`
	Check  string `json:"check"`
	Entity string `json:"entity"`
	// First is the start of the first hour the entity was seen in, Last
	// that of the most recent, and Through the end of the last hour
	// applied, so an hour applied twice (after a takeover) counts once.
	First   time.Time `json:"first_seen"`
	Last    time.Time `json:"last_seen"`
	Through time.Time `json:"through"`
	// Hours counts the hours the entity was active in.
	Hours int64 `json:"hours"`

	Values []Value `json:"values,omitempty"`
	// ByHour counts the active hours by hour of the day, in UTC, for the
	// sign-in hour check.
	ByHour []int64 `json:"by_hour,omitempty"`
	// Mean and Var are an exponentially weighted mean and variance of
	// the bytes sent per hour, zero hours included, for the data volume
	// check; Span counts the hours they cover.
	Mean float64 `json:"mean,omitempty"`
	Var  float64 `json:"var,omitempty"`
	Span int64   `json:"span,omitempty"`
	// HourMean and HourVar are the same for each hour of the day (UTC),
	// with one sample a day, and HourN counts the samples: a host that
	// sends a backup every night is judged against its other nights,
	// not against its quiet afternoons.
	HourMean []float64 `json:"hour_mean,omitempty"`
	HourVar  []float64 `json:"hour_var,omitempty"`
	HourN    []int64   `json:"hour_n,omitempty"`
	// Many marks a fleet profile with more hosts than it names.
	Many bool `json:"many,omitempty"`
}

// profileKind is the kind of the profile documents.
const profileKind = "profile"

// prevalenceCheck is the check name of the fleet profiles that count the
// hosts each process ran on, for the rare process check.
const prevalenceCheck = "process_hosts"

// ProfileID is the document ID of a check's profile of an entity: the
// entity is hashed, as names can be long or hold any character.
func ProfileID(check, entity string) string {
	sum := sha256.Sum256([]byte(check + "\x00" + entity))
	return check + ":" + hex.EncodeToString(sum[:12])
}

// NormEntity is how a user or host name is compared: trimmed and lower
// case, and cut at maxEntityLen. "" and "-" are no one.
func NormEntity(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "-" || s == "unknown" || s == "n/a" {
		return ""
	}
	return cut(s, maxEntityLen)
}

func cut(s string, n int) string {
	if len(s) <= n {
		return s
	}
	// Cut on a character boundary.
	for n > 0 && n < len(s) && s[n]&0xC0 == 0x80 {
		n--
	}
	return s[:n]
}

func newProfile(check, entity string, hour time.Time) *Profile {
	return &Profile{Kind: profileKind, Check: check, Entity: entity, First: hour, Last: hour}
}

// applied reports whether the hour starting at h was already applied.
func (p *Profile) applied(h time.Time) bool { return !p.Through.IsZero() && h.Before(p.Through) }

// learned reports whether the profile has learned for long enough by the
// hour starting at h to judge it.
func (p *Profile) learned(h time.Time, learning time.Duration) bool {
	return !p.First.IsZero() && !p.First.After(h.Add(-learning))
}

// has reports whether the profile has seen a value.
func (p *Profile) has(v string) bool {
	return slices.IndexFunc(p.Values, func(x Value) bool { return x.V == v }) >= 0
}

// see records a value seen in the hour starting at h. It reports whether
// the value was new.
func (p *Profile) see(v string, h time.Time) bool {
	v = cut(v, maxValueLen)
	if i := slices.IndexFunc(p.Values, func(x Value) bool { return x.V == v }); i >= 0 {
		if h.After(p.Values[i].Last) {
			p.Values[i].Last = h
		}
		p.Values[i].N++
		return false
	}
	if len(p.Values) >= ValueLimit(p.Check) {
		oldest := 0
		for i, x := range p.Values {
			if x.Last.Before(p.Values[oldest].Last) {
				oldest = i
			}
		}
		p.Values = slices.Delete(p.Values, oldest, oldest+1)
	}
	p.Values = append(p.Values, Value{V: v, First: h, Last: h, N: 1})
	return true
}

// forget drops the values not seen since before.
func (p *Profile) forget(before time.Time) {
	p.Values = slices.DeleteFunc(p.Values, func(x Value) bool { return x.Last.Before(before) })
}

// touch marks the hour starting at h as applied.
func (p *Profile) touch(h time.Time) {
	if h.After(p.Last) {
		p.Last = h
	}
	if end := h.Add(time.Hour); end.After(p.Through) {
		p.Through = end
	}
	p.Hours++
}

// hourShare is the share of the active hours that fell within an hour of
// hour h of the day (h-1, h and h+1), so a change of daylight saving
// time does not make a usual hour look rare.
func (p *Profile) hourShare(h int) float64 {
	if len(p.ByHour) != 24 || p.Hours == 0 {
		return 1
	}
	var n int64
	for d := -1; d <= 1; d++ {
		n += p.ByHour[(h+d+24)%24]
	}
	return float64(n) / float64(p.Hours)
}

func (p *Profile) countHour(h int) {
	if len(p.ByHour) != 24 {
		p.ByHour = make([]int64, 24)
	}
	p.ByHour[h]++
}

// volumeAlpha is the weight of each new hour in the data volume mean:
// an hour counts half as much a week later. hourAlpha is the weight of
// each new day in the mean of one hour of the day: a day counts half as
// much two weeks later.
var (
	volumeAlpha = 1 - math.Pow(0.5, 1.0/(7*24))
	hourAlpha   = 1 - math.Pow(0.5, 1.0/14)
)

// maxGapHours is the most empty hours applied to a volume profile at
// once: after a month without traffic, the mean is near zero anyway.
const maxGapHours = 30 * 24

// addVolume adds the bytes of the hour starting at h, after the hours
// with nothing since the last one applied.
func (p *Profile) addVolume(bytes float64, h time.Time) {
	if p.Span == 0 {
		p.Mean, p.Var, p.Span = bytes, 0, 1
		p.hourSample(h.Hour(), bytes)
		return
	}
	p.Span += p.fillGap(h)
	p.ewma(bytes)
	p.hourSample(h.Hour(), bytes)
	p.Span++
}

// fillGap applies the empty hours since the last one applied, up to
// maxGapHours of them, and returns how many hours had passed.
func (p *Profile) fillGap(h time.Time) int64 {
	if p.Through.IsZero() {
		return 0
	}
	gap := max(int64(h.Sub(p.Through)/time.Hour), 0)
	from := h.Add(-time.Duration(min(gap, maxGapHours)) * time.Hour)
	for t := from; t.Before(h); t = t.Add(time.Hour) {
		p.ewma(0)
		p.hourSample(t.Hour(), 0)
	}
	return gap
}

func (p *Profile) ewma(x float64) {
	d := x - p.Mean
	p.Mean += volumeAlpha * d
	p.Var = (1 - volumeAlpha) * (p.Var + volumeAlpha*d*d)
}

// hourSample adds one day's bytes for hour k of the day. The first
// sample is the mean, so a host is not judged against zero.
func (p *Profile) hourSample(k int, x float64) {
	if len(p.HourMean) != 24 || len(p.HourVar) != 24 || len(p.HourN) != 24 {
		p.HourMean, p.HourVar, p.HourN = make([]float64, 24), make([]float64, 24), make([]int64, 24)
	}
	if p.HourN[k] == 0 {
		p.HourMean[k], p.HourVar[k], p.HourN[k] = x, 0, 1
		return
	}
	d := x - p.HourMean[k]
	p.HourMean[k] += hourAlpha * d
	p.HourVar[k] = (1 - hourAlpha) * (p.HourVar[k] + hourAlpha*d*d)
	p.HourN[k]++
}

// usualVolume is what the profile would expect of the hour starting at
// h, counting the empty hours since the last.
type usualVolume struct {
	// Mean and SD are of every hour.
	Mean, SD float64
	// HourMean is the mean of this hour of the day, and HourN the days
	// it has seen. HourLimit is the least that is unusual for this hour
	// of the day and the hours either side, so a nightly job that runs
	// a little early or late, or a change of daylight saving time, does
	// not count.
	HourMean  float64
	HourN     int64
	HourLimit float64
}

func (p *Profile) usual(h time.Time) usualVolume {
	q := *p
	q.HourMean, q.HourVar, q.HourN = slices.Clone(p.HourMean), slices.Clone(p.HourVar), slices.Clone(p.HourN)
	q.fillGap(h)
	u := usualVolume{Mean: q.Mean, SD: math.Sqrt(q.Var)}
	if len(q.HourN) != 24 {
		return u
	}
	k := h.Hour()
	u.HourMean, u.HourN = q.HourMean[k], q.HourN[k]
	for d := -1; d <= 1; d++ {
		j := (k + d + 24) % 24
		if q.HourN[j] == 0 {
			continue
		}
		m, sd := q.HourMean[j], math.Sqrt(q.HourVar[j])
		u.HourLimit = max(u.HourLimit, volumeFactor*m, m+volumeSigmas*sd)
	}
	return u
}
