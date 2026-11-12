// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package notify

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/findings"
	"github.com/jrsamsanchez/signalith/internal/store"
)

// flakyDeliveries is a Memory whose calls fail while their error is set.
type flakyDeliveries struct {
	*Memory
	due, purge, update, claim error
}

func (f *flakyDeliveries) Due(ctx context.Context, now, stale time.Time) ([]Stored, []Stored, error) {
	if f.due != nil {
		return nil, nil, f.due
	}
	return f.Memory.Due(ctx, now, stale)
}

func (f *flakyDeliveries) Purge(ctx context.Context, before time.Time) error {
	if f.purge != nil {
		return f.purge
	}
	return f.Memory.Purge(ctx, before)
}

func (f *flakyDeliveries) Update(ctx context.Context, d *Delivery, v store.Version) (store.Version, error) {
	if f.update != nil {
		return store.Version{}, f.update
	}
	return f.Memory.Update(ctx, d, v)
}

func (f *flakyDeliveries) Claim(ctx context.Context, d *Delivery) (store.Version, error) {
	if f.claim != nil {
		return store.Version{}, f.claim
	}
	return f.Memory.Claim(ctx, d)
}

// failSearch is a findings store whose searches fail.
type failSearch struct{ *findings.Memory }

func (failSearch) Search(context.Context, findings.Filter) ([]*findings.Finding, int, error) {
	return nil, 0, errors.New("findings index unavailable")
}

type logBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *logBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *logBuf) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

func (r *rig) captureLog() *logBuf {
	b := &logBuf{}
	r.d.Log = slog.New(slog.NewTextHandler(b, nil))
	return b
}

func TestDispatcherLogsEachProblemOnce(t *testing.T) {
	r := newRig(t, RuleInput{ID: "r1", Name: "urgent", Enabled: on(), Channels: []string{"aaa"}})
	logs := r.captureLog()
	fl := &flakyDeliveries{Memory: r.store, due: errors.New("deliveries index unavailable"), purge: errors.New("purge refused")}
	r.d.Deliveries = fl
	r.pass()
	r.pass()
	out := logs.String()
	if strings.Count(out, "could not read the notifications to send again") != 1 {
		t.Errorf("due problem logged %d times: %s", strings.Count(out, "could not read the notifications to send again"), out)
	}
	if !strings.Contains(out, "could not delete old notification deliveries") {
		t.Errorf("purge problem not logged: %s", out)
	}

	// New findings that cannot be read.
	fl.due, fl.purge = nil, nil
	r.d.Findings = failSearch{r.fs}
	r.clock.add(time.Second)
	r.pass()
	if !strings.Contains(logs.String(), "could not read new findings to send") {
		t.Errorf("search problem not logged: %s", logs.String())
	}
	// Once it works again, nothing more is logged and the finding goes.
	r.d.Findings = r.fs
	r.raise("f1", "high", "d")
	before := logs.String()
	r.pass()
	if strings.Contains(strings.TrimPrefix(logs.String(), before), "could not") || r.sender.count("aaa") != 1 {
		t.Errorf("after recovery: sent %d, logs %s", r.sender.count("aaa"), strings.TrimPrefix(logs.String(), before))
	}
}

func TestDispatcherUnreadableSettingsSendNothing(t *testing.T) {
	r := newRig(t, RuleInput{ID: "r1", Name: "urgent", Enabled: on(), Channels: []string{"aaa"}})
	logs := r.captureLog()
	r.clock.add(time.Second)
	r.raise("f1", "high", "d")
	bad := filepath.Join(t.TempDir(), "bad.yaml")
	if err := os.WriteFile(bad, []byte("channels: [::"), 0o600); err != nil {
		t.Fatal(err)
	}
	r.d.Settings = &Manager{File: bad}
	r.pass()
	if r.sender.count("") != 0 || !strings.Contains(logs.String(), "notifications are not sent until the notifications file is fixed") {
		t.Errorf("sent %d, logs %s", r.sender.count(""), logs.String())
	}
}

func TestDispatcherClaimAndUpdateFailures(t *testing.T) {
	r := newRig(t, RuleInput{ID: "r1", Name: "urgent", Enabled: on(), Channels: []string{"aaa"}})
	logs := r.captureLog()
	r.clock.add(time.Second)
	f := r.raise("f1", "high", "d")
	// A stuck delivery that cannot be marked failed is logged and left.
	id := DeliveryID(f.ID, "aaa")
	now := r.clock.Now()
	if _, err := r.store.Claim(context.Background(), &Delivery{ID: id, Kind: KindFinding, FindingID: f.ID, Channel: "aaa", ChannelName: "SOC Slack",
		Status: StatusSending, Attempts: 1, Created: now, Updated: now, Claimed: now, Server: "s0"}); err != nil {
		t.Fatal(err)
	}
	fl := &flakyDeliveries{Memory: r.store, update: errors.New("write refused")}
	r.d.Deliveries = fl
	r.clock.add(StuckAfter + time.Second)
	r.pass()
	if d, _ := r.store.Get(id); d.Status != StatusSending {
		t.Errorf("updated anyway: %+v", d)
	}
	if !strings.Contains(logs.String(), "could not mark a notification left sending as failed") {
		t.Errorf("logs %s", logs.String())
	}
	// A conflict is someone else's change, and is not logged.
	fl.update = store.ErrConflict
	before := logs.String()
	r.pass()
	if strings.Contains(strings.TrimPrefix(logs.String(), before), "could not mark") {
		t.Error("a conflict was logged")
	}

	// A new finding whose claim fails is not sent.
	fl.update, fl.claim = nil, errors.New("claim refused")
	r.raise("f2", "critical", "d")
	r.pass()
	if r.sender.count("") != 0 {
		t.Errorf("sent %d without a claim", r.sender.count(""))
	}
}

func TestDispatcherRetryClaimFailure(t *testing.T) {
	r := newRig(t, RuleInput{ID: "r1", Name: "urgent", Enabled: on(), Channels: []string{"aaa"}})
	logs := r.captureLog()
	r.clock.add(time.Second)
	r.raise("f1", "high", "d")
	r.sender.fail = errors.New("down")
	r.pass()
	r.sender.fail = nil
	r.d.Deliveries = &flakyDeliveries{Memory: r.store, update: errors.New("write refused")}
	r.clock.add(2 * time.Minute)
	r.pass()
	if r.sender.count("") != 1 || !strings.Contains(logs.String(), "could not claim a notification to send again") {
		t.Errorf("sent %d, logs %s", r.sender.count(""), logs.String())
	}
}

func TestDispatcherRun(t *testing.T) {
	r := newRig(t, RuleInput{ID: "r1", Name: "urgent", Enabled: on(), Channels: []string{"aaa"}})
	r.clock.add(time.Second)
	r.raise("f1", "high", "d")
	ctx, cancel := context.WithCancel(context.Background())
	r.sender.during = cancel
	done := make(chan struct{})
	go func() { r.d.Run(ctx); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not stop with its context")
	}
	if r.sender.count("aaa") != 1 {
		t.Errorf("sent %d", r.sender.count("aaa"))
	}
	// A pass with an ended context does nothing.
	r.raise("f2", "high", "d")
	r.d.Pass(ctx)
	if r.sender.count("") != 1 {
		t.Error("a pass ran after its context ended")
	}
}
