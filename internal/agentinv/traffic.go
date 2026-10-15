package agentinv

import (
	"sync/atomic"
	"time"
)

// traffic counts the batches this server heard of, for its heartbeat
// (see cluster.Traffic).
type traffic struct {
	batches, events, last atomic.Int64 // last in unix nanoseconds
}

func (t *traffic) note(now time.Time, events int) {
	t.batches.Add(1)
	t.events.Add(int64(max(events, 0)))
	t.last.Store(now.UnixNano())
}

// Traffic returns how many batches agents sent this server since the
// inventory was made, the events in them, and when the latest came (zero
// before one).
func (v *Inventory) Traffic() (batches, events int64, last time.Time) {
	if v == nil {
		return 0, 0, time.Time{}
	}
	if ns := v.traffic.last.Load(); ns != 0 {
		last = time.Unix(0, ns).UTC()
	}
	return v.traffic.batches.Load(), v.traffic.events.Load(), last
}
