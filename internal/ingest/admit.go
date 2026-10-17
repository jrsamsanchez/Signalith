package ingest

import (
	"context"
	"time"
)

// slots hands out the pipeline's MaxConcurrent ingest slots. While
// requests wait, a slot freed goes to the longest-waiting request whose
// token holds less than its share (a quarter of the slots), and only
// when there is none to a token already over it. So one token that sends
// many small batches cannot keep the others waiting, but a token sending
// alone still gets every slot.
type slots struct {
	n, share int
	held     int
	per      map[string]int
	waiting  []*slotWaiter
}

type slotWaiter struct {
	sender  string
	granted chan struct{}
	done    bool // granted, or given up
}

func newSlots(n int) *slots {
	share := n / 4
	if share < 1 {
		share = 1
	}
	return &slots{n: n, share: share, per: map[string]int{}}
}

// Admit waits up to wait for one of MaxConcurrent ingest slots and returns
// the function that frees it, or ErrBusy. sender is what the request is
// counted under for its share, such as its agent token's ID. Take a slot
// once the request body has arrived (see ReadBody) and hold it while the
// body is decoded and written: that bounds the OpenSearch writes ingest
// runs however many agents send at once, and a slow sender cannot hold a
// slot.
func (p *Pipeline) Admit(ctx context.Context, wait time.Duration, sender string) (func(), error) {
	p.slotsMu.Lock()
	if p.slots == nil {
		n := p.MaxConcurrent
		if n <= 0 {
			n = DefaultMaxConcurrent
		}
		p.slots = newSlots(n)
	}
	s := p.slots
	release := func() {
		p.slotsMu.Lock()
		s.free(sender)
		p.slotsMu.Unlock()
	}
	// free hands slots to waiting requests first, so a free slot means
	// nobody is waiting.
	if s.held < s.n {
		s.take(sender)
		p.slotsMu.Unlock()
		return release, nil
	}
	w := &slotWaiter{sender: sender, granted: make(chan struct{})}
	s.waiting = append(s.waiting, w)
	p.slotsMu.Unlock()

	t := time.NewTimer(wait)
	defer t.Stop()
	var err error
	select {
	case <-w.granted:
		return release, nil
	case <-t.C:
		err = ErrBusy
	case <-ctx.Done():
		err = ctx.Err()
	}
	p.slotsMu.Lock()
	defer p.slotsMu.Unlock()
	if w.done {
		// Granted as the wait ended: hand it on.
		s.free(sender)
		return nil, err
	}
	w.done = true
	s.drop(w)
	return nil, err
}

func (s *slots) take(sender string) {
	s.held++
	s.per[sender]++
}

func (s *slots) free(sender string) {
	s.held--
	if s.per[sender]--; s.per[sender] <= 0 {
		delete(s.per, sender)
	}
	for s.held < s.n && len(s.waiting) > 0 {
		i := 0
		for j, w := range s.waiting {
			if s.per[w.sender] < s.share {
				i = j
				break
			}
		}
		w := s.waiting[i]
		s.waiting = append(s.waiting[:i], s.waiting[i+1:]...)
		w.done = true
		s.take(w.sender)
		close(w.granted)
	}
}

func (s *slots) drop(w *slotWaiter) {
	for i, x := range s.waiting {
		if x == w {
			s.waiting = append(s.waiting[:i], s.waiting[i+1:]...)
			return
		}
	}
}
