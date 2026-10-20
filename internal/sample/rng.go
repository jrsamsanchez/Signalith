// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package sample

import "time"

// rng is a tiny deterministic generator (splitmix64), so the sample is
// reproducible without depending on the standard library's RNG internals.
type rng struct{ state uint64 }

func newRNG(seed uint64) *rng { return &rng{state: seed + 0x9E3779B97F4A7C15} }

func (r *rng) next() uint64 {
	r.state += 0x9E3779B97F4A7C15
	z := r.state
	z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9
	z = (z ^ (z >> 27)) * 0x94D049BB133111EB
	return z ^ (z >> 31)
}

// intn returns a value in [0, n).
func (r *rng) intn(n int) int {
	if n <= 0 {
		return 0
	}
	return int(r.next() % uint64(n))
}

// chance reports true with probability num/den.
func (r *rng) chance(num, den int) bool { return r.intn(den) < num }

// pick returns a random element of xs.
func (r *rng) pick(xs []string) string {
	if len(xs) == 0 {
		return ""
	}
	return xs[r.intn(len(xs))]
}

// timeIn returns a time at a random minute within [start, end], weighted to
// working hours: 08:00-18:00 on weekdays are far more likely than nights
// and weekends, so the data has a daily and weekly rhythm.
func (r *rng) timeIn(start, end time.Time) time.Time {
	span := end.Sub(start)
	if span <= 0 {
		return start
	}
	for try := 0; try < 6; try++ {
		t := start.Add(time.Duration(r.intn(int(span.Minutes()))) * time.Minute)
		if r.likely(t) {
			return t
		}
	}
	return start.Add(time.Duration(r.intn(int(span.Minutes()))) * time.Minute)
}

// likely accepts a time with a probability that reflects working hours, so
// timeIn's rejection sampling thins out nights and weekends.
func (r *rng) likely(t time.Time) bool {
	wd := t.Weekday()
	weekend := wd == time.Saturday || wd == time.Sunday
	h := t.Hour()
	switch {
	case !weekend && h >= 8 && h < 18:
		return true // working hours: always keep
	case !weekend && (h >= 6 && h < 22):
		return r.chance(1, 3) // shoulders of the day
	case weekend && h >= 9 && h < 17:
		return r.chance(1, 4) // some weekend work
	default:
		return r.chance(1, 12) // quiet nights
	}
}
