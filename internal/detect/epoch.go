package detect

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jrsamsanchez/signalith/internal/store"
)

// The detection epoch is the number the scheduler writes into the run
// state and throttle documents, so a server that stopped running the
// schedule cannot write over the state of the one that runs it now.
//
// Up to cluster level 11 it is the job lease's epoch. From then on
// (Scheduler.Counter) it comes from one detepoch document in the runtime
// index, which only ever grows: each time a server starts running the
// schedule under a lease epoch L, it takes the next number, at least
// L<<epochShift. So the numbers keep the lease epochs' order (a newer
// lease always gets bigger ones, and every number is bigger than the
// plain lease epochs written before the counter), while one lease epoch
// can take many of them. Running detections on several servers hands
// each part of the schedule a number of its own the same way.
const (
	kindDetEpoch = "detepoch"
	detEpochID   = kindDetEpoch
	// epochShift leaves room for 2^20 numbers per lease epoch.
	epochShift = 20
)

// epochDoc is the detepoch document: the last number taken, the lease
// epoch it was taken under, and by which server. The number is not in an
// "epoch" field: the lease takes the highest of those for its own epoch
// when it is made again (cluster.maxEpoch).
type epochDoc struct {
	Kind  string    `json:"kind"`
	Epoch int64     `json:"det_epoch"`
	Lease int64     `json:"lease_epoch"`
	Node  string    `json:"node,omitempty"`
	At    time.Time `json:"at,omitzero"`
}

// FirstEpoch is the smallest detection epoch taken under lease epoch
// lease.
func FirstEpoch(lease int64) int64 { return lease << epochShift }

// counter reports whether detection epochs come from the detepoch
// document.
func (s *Scheduler) counter() bool { return s.Counter != nil && s.Counter() }

// claimEpoch takes the next detection epoch under lease epoch lease. It
// is refused when a server holding a newer lease took one: that server
// runs the schedule now, so this one must not get a bigger number than
// it.
func (s *Scheduler) claimEpoch(ctx context.Context, lease int64) (int64, error) {
	rs, idx := s.runStore()
	return claimEpochs(ctx, rs, idx, lease, s.NodeID, s.now(), 1)
}

// claimEpochs takes the next n detection epochs under lease epoch lease
// from the detepoch document in idx, and returns the first: they are
// first, first+1, ... first+n-1. It is refused as claimEpoch is.
func claimEpochs(ctx context.Context, rs RunStore, idx string, lease int64, node string, now time.Time, n int) (int64, error) {
	if lease <= 0 || lease >= 1<<(62-epochShift) {
		return 0, fmt.Errorf("the job lease epoch %d cannot give a detection epoch", lease)
	}
	if n < 1 || n > Buckets {
		return 0, fmt.Errorf("cannot take %d detection epochs at once", n)
	}
	for range 3 {
		raw, ver, found, err := rs.Get(ctx, idx, detEpochID)
		if err != nil {
			return 0, fmt.Errorf("could not read the detection epoch: %w", err)
		}
		var cur epochDoc
		if found {
			if err := json.Unmarshal(raw, &cur); err != nil || cur.Kind != kindDetEpoch {
				return 0, fmt.Errorf("the detection epoch document cannot be read")
			}
		}
		if cur.Lease > lease {
			return 0, errStaleEpoch
		}
		first := max(cur.Epoch+1, FirstEpoch(lease))
		doc := epochDoc{Kind: kindDetEpoch, Epoch: first + int64(n) - 1, Lease: lease, Node: node, At: now.UTC()}
		if found {
			_, err = rs.PutIf(ctx, idx, detEpochID, doc, ver, true)
		} else {
			_, err = rs.Create(ctx, idx, detEpochID, doc, true)
		}
		if store.IsConflict(err) || errors.Is(err, store.ErrExists) || errors.Is(err, store.ErrNotFound) {
			continue
		}
		if err != nil {
			return 0, fmt.Errorf("could not write the detection epoch: %w", err)
		}
		return first, nil
	}
	return 0, fmt.Errorf("the detection epoch kept changing while it was taken; trying again")
}

// fenceEpoch is the detection epoch writes made now carry: the one taken
// for the leader's copy, while it was read under the current lease epoch.
// Without such a copy it is the lease epoch, and ok is false when the
// counter is on: the lease epoch is then not a detection epoch, and a
// scheduled run must not write with it.
//
// In spread mode it is the epoch of the rule's bucket, and ok is false
// when this server does not run the bucket or its copy is not current.
func (s *Scheduler) fenceEpoch(id string) (ep int64, ok bool) {
	g, counter := s.gen(), s.counter()
	if s.Owned != nil {
		s.mu.Lock()
		loaded := s.det != nil && s.loadedEpoch == g
		s.mu.Unlock()
		de, mine := s.ownsRule(id)
		return de, mine && loaded
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.det != nil && s.loadedEpoch == g {
		return s.detEpoch, true
	}
	return g, !counter
}
