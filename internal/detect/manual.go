package detect

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jrsamsanchez/signalith/internal/store"
)

// RunManual runs d now on this server, whichever server runs the
// schedule ("Run now"): it searches the lookback up to now (the cluster's
// time), gives its findings random IDs, and respects and writes
// throttles, which then hold from now. It leaves the schedule's watermark
// and run state alone, and records the run in detmanual:<rule id>, with
// by (who asked) and this server, for every server's Detections page. A
// run that takes longer than RunTimeout is stopped.
func (s *Scheduler) RunManual(ctx context.Context, d *Detection, by string) (*RunResult, error) {
	timeout := s.RunTimeout(d)
	rctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	at := s.now()
	res, err := s.run(rctx, d, runSpec{at: s.clusterNow(), raised: at, manual: true, fallback: true})
	if err != nil && errors.Is(rctx.Err(), context.DeadlineExceeded) && ctx.Err() == nil {
		err = fmt.Errorf("timed out after %s, so this run was stopped; narrow the query or shorten its lookback so it finishes in time", timeout)
	}
	if ctx.Err() != nil {
		// The person went away or the server is stopping: nothing ran
		// to record.
		return res, err
	}
	m := ManualRun{At: at.UTC(), By: by, Node: s.NodeID}
	if err != nil {
		m.Error = err.Error()
	} else {
		m.Results, m.Findings, m.Risk, m.Throttled = res.Results, len(res.Findings), res.Risk, res.Throttled
	}
	// The record is written even if the run's own time ran out.
	wctx, wcancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer wcancel()
	if werr := s.writeManual(wctx, d.ID, m); werr != nil {
		s.log().Warn("could not record the Run now of a detection", "detection", d.ID, "err", werr)
	}
	return res, err
}

// writeManual stores the last "Run now" of a rule. The newest run wins:
// there is no epoch, since any server may run one.
func (s *Scheduler) writeManual(ctx context.Context, rule string, m ManualRun) error {
	rs, idx := s.runStore()
	id := detManualID(rule)
	doc := manualDoc{Kind: kindDetManual, DetectionID: rule, ManualRun: m}
	var err error
	for range 3 {
		var v store.Version
		var found bool
		if _, v, found, err = rs.Get(ctx, idx, id); err != nil {
			return err
		}
		if found {
			_, err = rs.PutIf(ctx, idx, id, doc, v, false)
		} else {
			_, err = rs.Create(ctx, idx, id, doc, false)
		}
		if err == nil {
			s.mu.Lock()
			if s.cache != nil {
				s.cache.manual[rule] = m
			}
			s.mu.Unlock()
			return nil
		}
		if !store.IsConflict(err) && !errors.Is(err, store.ErrExists) && !errors.Is(err, store.ErrNotFound) {
			return err
		}
	}
	return err
}
