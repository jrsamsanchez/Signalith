package detect

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"maps"
	"strings"
)

// Spreading the schedule over several servers.
//
// Each tenant's rules hash into Buckets buckets (BucketOf). The server
// running the background jobs writes, per tenant, an assignment document
// (detassign:<tenant> in that tenant's runtime index) naming each bucket's
// owner and the detection epoch it runs the bucket under; it takes a
// fresh number from the detepoch counter whenever a bucket moves, so a
// new owner's epoch is always bigger than the old one's. Owners are
// picked by rendezvous hashing over the servers that may run the
// tenant's detections (Rendezvous), so a server joining or leaving moves
// only its own share.
//
// A server runs the rules of the buckets it owns (Scheduler.Owned), and
// fences each rule's run state and throttles with its bucket's epoch:
// once a bucket has moved on, the old owner's writes are refused, exactly
// as a server that lost the job lease is refused today. See
// /mnt/project-files/multi-server/detection-spread.md for the design.

// Buckets is how many buckets each tenant's rules hash into. Changing it
// moves every rule, so it is a constant.
const Buckets = 64

const (
	kindDetAssign = "detassign"
	// Bucket states: the owner runs it, or is handing it over to To and
	// starts no new slots of it.
	BucketRun    = "run"
	BucketMoving = "moving"
)

// AssignmentID is the ID of a tenant's assignment document.
func AssignmentID(tenant string) string { return kindDetAssign + ":" + tenant }

// BucketOf is the bucket of a tenant's rule.
func BucketOf(tenant, rule string) int {
	h := fnv.New32a()
	h.Write([]byte(tenant))
	h.Write([]byte{0})
	h.Write([]byte(rule))
	return int(h.Sum32() % Buckets)
}

// Rendezvous is the owner of a tenant's bucket among nodes: the node with
// the highest hash of (node, tenant, bucket). "" when nodes is empty.
func Rendezvous(nodes []string, tenant string, bucket int) string {
	best, top := "", uint64(0)
	for _, n := range nodes {
		h := fnv.New64a()
		h.Write([]byte(n))
		h.Write([]byte{0})
		h.Write([]byte(tenant))
		h.Write([]byte{0})
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], uint32(bucket))
		h.Write(b[:])
		// Mix the bits, since FNV's high bits change little with the last
		// bytes written.
		v := mix64(h.Sum64())
		if best == "" || v > top || v == top && n < best {
			best, top = n, v
		}
	}
	return best
}

// mix64 is the splitmix64 finalizer.
func mix64(x uint64) uint64 {
	x ^= x >> 30
	x *= 0xbf58476d1ce4e5b9
	x ^= x >> 27
	x *= 0x94d049bb133111eb
	x ^= x >> 31
	return x
}

// Assignment is a tenant's assignment document.
type Assignment struct {
	Kind   string `json:"kind"`
	Tenant string `json:"tenant"`
	// LeaseEpoch is the job lease epoch of the server that wrote it.
	LeaseEpoch int64         `json:"lease_epoch"`
	Owners     []BucketOwner `json:"owners"`
}

// BucketOwner is one bucket's entry: its owner, the detection epoch the
// owner runs it under, and its state. Detection epochs are not kept in an
// "epoch" field (see DetState).
type BucketOwner struct {
	Node     string `json:"node,omitempty"`
	DetEpoch int64  `json:"det_epoch,omitempty"`
	State    string `json:"state,omitempty"`
	To       string `json:"to,omitempty"`
}

// maxNodeID bounds a node ID in an assignment.
const maxNodeID = 128

// DecodeAssignment reads an assignment document and checks it: it is for
// tenant, has one entry per bucket, and each owned bucket has an owner, a
// detection epoch and a known state. A document that fails runs nothing.
func DecodeAssignment(raw []byte, tenant string) (*Assignment, error) {
	var a Assignment
	if err := json.Unmarshal(raw, &a); err != nil {
		return nil, fmt.Errorf("the detection assignment cannot be read: %w", err)
	}
	if err := a.Check(tenant); err != nil {
		return nil, err
	}
	return &a, nil
}

// Check reports what is wrong with an assignment for tenant.
func (a *Assignment) Check(tenant string) error {
	switch {
	case a.Kind != kindDetAssign:
		return fmt.Errorf("the detection assignment is not one")
	case a.Tenant != tenant:
		return fmt.Errorf("the detection assignment is for another tenant")
	case len(a.Owners) != Buckets:
		return fmt.Errorf("the detection assignment has %d buckets, not %d", len(a.Owners), Buckets)
	}
	for i, o := range a.Owners {
		if o.Node == "" {
			if o.DetEpoch != 0 || o.State != "" || o.To != "" {
				return fmt.Errorf("bucket %d of the detection assignment has no owner but other fields", i)
			}
			continue
		}
		if len(o.Node) > maxNodeID || len(o.To) > maxNodeID || strings.ContainsAny(o.Node+o.To, "\x00\n") {
			return fmt.Errorf("bucket %d of the detection assignment names a node that cannot be one", i)
		}
		if o.DetEpoch <= 0 {
			return fmt.Errorf("bucket %d of the detection assignment has no detection epoch", i)
		}
		switch o.State {
		case BucketRun:
			if o.To != "" {
				return fmt.Errorf("bucket %d of the detection assignment runs but names a server to move to", i)
			}
		case BucketMoving:
			if o.To == "" || o.To == o.Node {
				return fmt.Errorf("bucket %d of the detection assignment moves to no other server", i)
			}
		default:
			return fmt.Errorf("bucket %d of the detection assignment has an unknown state", i)
		}
	}
	return nil
}

// RunsOn returns the buckets node runs under a, with their detection
// epochs: those it owns in state run. A bucket being moved away starts
// no new slots.
func (a *Assignment) RunsOn(node string) map[int]int64 {
	out := map[int]int64{}
	if a == nil || node == "" {
		return out
	}
	for i, o := range a.Owners {
		if o.Node == node && o.State == BucketRun {
			out[i] = o.DetEpoch
		}
	}
	return out
}

// Holds returns the buckets node holds under a, with their detection
// epochs: those it runs and those it is handing over, whose runs in
// flight may still write their run state.
func (a *Assignment) Holds(node string) map[int]int64 {
	out := map[int]int64{}
	if a == nil || node == "" {
		return out
	}
	for i, o := range a.Owners {
		if o.Node == node {
			out[i] = o.DetEpoch
		}
	}
	return out
}

// owned is the spread mode's view: the buckets this server runs, as
// Owned last returned them, and how many times that changed.
type owned struct {
	buckets map[int]int64
	gen     int64
	// lost holds the buckets a refused write showed another server runs
	// under a newer epoch, with the epoch this server had for them: none
	// of their rules runs here again until the assignment gives the
	// bucket a different epoch.
	lost map[int]int64
}

// gen is the generation the scheduler's copy of the run state is read
// and written under: the lease epoch, or in spread mode a count of the
// changes of the buckets this server runs (each change reads the copy
// again).
func (s *Scheduler) gen() int64 {
	if s.Owned == nil {
		return s.epoch()
	}
	m, ok := s.Owned()
	if !ok {
		m = nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !maps.Equal(m, s.own.buckets) {
		s.own.buckets, s.own.gen = maps.Clone(m), s.own.gen+1
		maps.DeleteFunc(s.own.lost, func(b int, ep int64) bool { return m[b] != ep })
	}
	return s.own.gen
}

// loseBucket marks the bucket of rule id lost after a write of it was
// refused (spread mode): a newer epoch than this server's is in use for
// it, so it has moved on, and its other rules stop now rather than each
// when its own write fails.
func (s *Scheduler) loseBucket(id string) {
	b := BucketOf(s.Tenant, id)
	s.mu.Lock()
	defer s.mu.Unlock()
	if ep, ok := s.own.buckets[b]; ok {
		if s.own.lost == nil {
			s.own.lost = map[int]int64{}
		}
		s.own.lost[b] = ep
	}
}

// startsRule reports whether this server starts new slots of rule id:
// it holds its bucket, and is not handing it over.
func (s *Scheduler) startsRule(id string) bool {
	if _, mine := s.ownsRule(id); !mine {
		return false
	}
	return s.Moving == nil || !s.Moving(BucketOf(s.Tenant, id))
}

// BucketBusy reports whether a run of a rule of bucket b is running or
// waiting for a worker here.
func (s *Scheduler) BucketBusy(b int) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id := range s.flags {
		if BucketOf(s.Tenant, id) == b {
			return true
		}
	}
	return false
}

// ownsRule reports whether this server runs rule d now, in spread mode,
// and the detection epoch of its bucket; outside spread mode it is
// always true.
func (s *Scheduler) ownsRule(id string) (int64, bool) {
	if s.Owned == nil {
		return 0, true
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	b := BucketOf(s.Tenant, id)
	ep, ok := s.own.buckets[b]
	if lost, gone := s.own.lost[b]; ok && gone && lost == ep {
		return ep, false
	}
	return ep, ok
}
