package detect

import (
	"hash/fnv"
	"time"
)

// The slot grid. A detection with schedule S runs once per slot: slots
// end at k·S + o seconds after the Unix epoch, where the offset o comes
// from the rule's ID, so rules with the same schedule are spread over
// the period instead of all running at once. Every server works out the
// same grid, so whichever server runs the detections, a slot is the same
// slot, and it is searched once.

// slotSeconds is S in whole seconds, at least 1.
func slotSeconds(s time.Duration) int64 {
	return max(int64(s/time.Second), 1)
}

// SlotOffset is FNV-64a of the rule ID modulo S, in whole seconds.
func SlotOffset(id string, s time.Duration) time.Duration {
	h := fnv.New64a()
	h.Write([]byte(id))
	return time.Duration(h.Sum64()%uint64(slotSeconds(s))) * time.Second
}

// floorDiv is a / b rounded down, also for negative a.
func floorDiv(a, b int64) int64 {
	q := a / b
	if a%b != 0 && (a < 0) != (b < 0) {
		q--
	}
	return q
}

// SlotAt returns the latest slot end at or before now, in UTC.
func SlotAt(id string, s time.Duration, now time.Time) time.Time {
	sec := slotSeconds(s)
	o := int64(SlotOffset(id, s) / time.Second)
	k := floorDiv(now.Unix()-o, sec)
	return time.Unix(k*sec+o, 0).UTC()
}

// NextSlot returns the slot end after end, which must be on the grid.
func NextSlot(id string, s time.Duration, end time.Time) time.Time {
	return end.Add(time.Duration(slotSeconds(s)) * time.Second).UTC()
}

// Slots returns the slot ends after `after` up to and including `upto`,
// oldest first, at most n of them.
func Slots(id string, s time.Duration, after, upto time.Time, n int) []time.Time {
	var out []time.Time
	if n <= 0 {
		return out
	}
	next := NextSlot(id, s, SlotAt(id, s, after))
	for !next.After(upto) && len(out) < n {
		out = append(out, next)
		next = NextSlot(id, s, next)
	}
	return out
}

// slotsBetween counts the slot ends after `after` up to and including
// `upto`.
func slotsBetween(id string, s time.Duration, after, upto time.Time) int {
	if !upto.After(after) {
		return 0
	}
	a, b := SlotAt(id, s, after), SlotAt(id, s, upto)
	return int(b.Sub(a) / (time.Duration(slotSeconds(s)) * time.Second))
}

// slotLength is S truncated to whole seconds.
func slotLength(s time.Duration) time.Duration {
	return time.Duration(slotSeconds(s)) * time.Second
}
