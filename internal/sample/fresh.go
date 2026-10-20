// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package sample

import (
	"cmp"
	"context"
	"errors"
	"log/slog"
	"time"
)

// FreshEvery is how often a public demo loads the sample data again (see
// KeepFresh). The sample is a week that ends when it is loaded, and the
// time ranges people pick end now, so a day later the latest day is
// already thinner; loading it again daily keeps it looking current.
const FreshEvery = 24 * time.Hour

// How long KeepFresh waits after a round that could not finish: briefly
// while another load or removal runs, longer after an error.
var (
	freshBusyWait  = time.Minute
	freshErrorWait = 10 * time.Minute
)

// freshLoader is what KeepFresh needs of a Loader.
type freshLoader interface {
	Status(ctx context.Context) (*State, error)
	Load(ctx context.Context, size Size, prog ProgressFn) (*State, error)
	Remove(ctx context.Context, prog ProgressFn) (*State, error)
}

// KeepFresh keeps a standard sample set loaded and no older than every,
// until ctx ends: it loads one when none is, and removes and loads it
// again once it is older, or when a load or removal did not finish. It
// uses Load and Remove, so one job runs at a time across every server and
// the signalith sample-data command. A public demo runs it as a background
// job, on the server that runs the jobs.
func KeepFresh(ctx context.Context, l *Loader, every time.Duration, log *slog.Logger) {
	keepFresh(ctx, l, every, time.Now, log)
}

func keepFresh(ctx context.Context, l freshLoader, every time.Duration, now func() time.Time, log *slog.Logger) {
	for {
		wait, err := freshRound(ctx, l, every, now)
		if err != nil && ctx.Err() == nil {
			log.Warn("the demo's sample data could not be loaded again; trying again later", "err", err, "retry_in", wait.String())
		}
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return
		case <-t.C:
		}
	}
}

// freshRound does one round of KeepFresh and says how long to wait before
// the next.
func freshRound(ctx context.Context, l freshLoader, every time.Duration, now func() time.Time) (time.Duration, error) {
	st, err := l.Status(ctx)
	if err != nil {
		return freshErrorWait, err
	}
	if st != nil && !st.Partial {
		age := now().Sub(cmp.Or(st.LoadedAt, st.Started))
		if age < every {
			return every - age, nil
		}
	}
	if st != nil {
		if _, err := l.Remove(ctx, nil); err != nil {
			return freshWait(err), err
		}
	}
	if _, err := l.Load(ctx, SizeStandard, nil); err != nil {
		return freshWait(err), err
	}
	return every, nil
}

// freshWait is how long to wait after a round failed with err.
func freshWait(err error) time.Duration {
	if errors.Is(err, ErrBusy) || errors.Is(err, ErrAlreadyLoaded) {
		return freshBusyWait
	}
	return freshErrorWait
}
