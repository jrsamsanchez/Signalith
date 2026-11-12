// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/sample"
	"github.com/jrsamsanchez/signalith/internal/store"
)

// sampleDocs is the sample-data record in OpenSearch: each Get returns the
// next of docs (the last one again once they run out), with a new version
// when bump is set.
type sampleDocs struct {
	mu      sync.Mutex
	docs    []string // "" is no document
	n       int
	bump    bool
	getErr  error
	putErr  error
	deleted bool
}

func (f *sampleDocs) Get(context.Context, string, string) (json.RawMessage, store.Version, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.getErr != nil {
		return nil, store.Version{}, false, f.getErr
	}
	i := f.n
	if i >= len(f.docs) {
		i = len(f.docs) - 1
	}
	f.n++
	seq := int64(1)
	if f.bump {
		seq = int64(f.n)
	}
	if i < 0 || f.docs[i] == "" || f.deleted {
		return nil, store.Version{}, false, nil
	}
	return json.RawMessage(f.docs[i]), store.Version{SeqNo: seq, PrimaryTerm: 1, Version: seq}, true, nil
}

func (f *sampleDocs) Create(context.Context, string, string, any, bool) (store.Version, error) {
	return store.Version{}, errors.New("not here")
}

func (f *sampleDocs) PutIf(_ context.Context, _, _ string, _ any, v store.Version, _ bool) (store.Version, error) {
	if f.putErr != nil {
		return store.Version{}, f.putErr
	}
	return store.Version{SeqNo: v.SeqNo + 100, PrimaryTerm: 1, Version: v.Version + 1}, nil
}

func (f *sampleDocs) DeleteIf(context.Context, string, string, store.Version, bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.deleted = true
	return nil
}

func sampleDoc(t *testing.T, st *sample.State, job *sample.Activity) string {
	t.Helper()
	b, err := json.Marshal(map[string]any{"kind": "sample_data", "body": map[string]any{"state": st, "job": job}})
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestSampleStatusCmdStates(t *testing.T) {
	now := time.Now()
	loaded := &sample.State{ID: "s1", Size: "small", Started: now.Add(-time.Hour), LoadedAt: now, Events: 10, Findings: 2, RiskEvents: 3, Indicators: 4, Assets: 5, Identities: 6}
	job := &sample.Activity{Op: "remove", Phase: "Deleting events", Percent: 40, Server: "siem-a"}
	for _, c := range []struct {
		name string
		docs []string
		bump bool
		node string
		err  error
		want string
	}{
		{"none", []string{""}, false, "", nil, "No sample data is loaded."},
		{"removal left", []string{sampleDoc(t, &sample.State{ID: "s1", Partial: true, Removing: true}, nil)}, false, "", nil, "A removal of the sample data did not finish"},
		{"load left", []string{sampleDoc(t, &sample.State{ID: "s1", Partial: true, Started: now}, nil)}, false, "", nil, "did not finish."},
		{"loaded", []string{sampleDoc(t, loaded, nil)}, false, "", nil, "Sample data is loaded"},
		{"running", []string{sampleDoc(t, loaded, job)}, true, "", nil, "Sample data is being removed on the server siem-a: Deleting events (40%)"},
		{"ended", []string{sampleDoc(t, loaded, job), "", ""}, false, "", nil, "No sample data is loaded."},
		{"stopped", []string{sampleDoc(t, loaded, job), sampleDoc(t, loaded, &sample.Activity{Op: "load", Node: "n1", Process: "gone", Phase: "Writing", Percent: 5})}, false, "n1", nil, "but that has not moved on for a while"},
	} {
		t.Run(c.name, func(t *testing.T) {
			l := &sample.Loader{Prefix: "signalith", Docs: &sampleDocs{docs: c.docs, bump: c.bump}, NodeID: c.node}
			var err error
			out := captureStdout(t, func() { err = sampleStatusCmd(context.Background(), l) })
			if err != nil || !strings.Contains(out, c.want) {
				t.Errorf("%v\n%s", err, out)
			}
			if c.name == "loaded" && !strings.Contains(out, "events:                   10") {
				t.Errorf("counts missing:\n%s", out)
			}
		})
	}
	l := &sample.Loader{Prefix: "signalith", Docs: &sampleDocs{getErr: errors.New("down")}}
	if err := sampleStatusCmd(context.Background(), l); err == nil || !strings.Contains(err.Error(), "down") {
		t.Errorf("read error: %v", err)
	}
}

func TestSampleRemoveCmdStates(t *testing.T) {
	ctx := context.Background()
	loaded := &sample.State{ID: "s1", Size: "small"}
	job := &sample.Activity{Op: "load", Phase: "Writing", Percent: 5, Server: "lap", Command: true}
	run := func(l *sample.Loader) (string, error) {
		var err error
		out := captureStdout(t, func() { err = sampleRemoveCmd(ctx, l) })
		return out, err
	}

	// Nothing recorded.
	if out, err := run(&sample.Loader{Docs: &sampleDocs{docs: []string{""}}}); err != nil || !strings.Contains(out, "There is no sample data to remove.") {
		t.Errorf("none: %v %s", err, out)
	}
	// A read that fails.
	if _, err := run(&sample.Loader{Docs: &sampleDocs{getErr: errors.New("down")}}); err == nil {
		t.Error("a failed read removed")
	}
	// A job that is still running.
	out, err := run(&sample.Loader{Docs: &sampleDocs{docs: []string{sampleDoc(t, loaded, job)}, bump: true}})
	if !errors.Is(err, errSampleBusy) || !strings.Contains(out, "with the signalith sample-data command on lap") {
		t.Errorf("running: %v %s", err, out)
	}
	// A job that ended while this looked, and took the sample data with it.
	out, err = run(&sample.Loader{Docs: &sampleDocs{docs: []string{sampleDoc(t, loaded, job), ""}}})
	if err != nil || !strings.Contains(out, "There is no sample data to remove.") {
		t.Errorf("ended: %v %s", err, out)
	}
	// A job that stopped: the removal goes on, and is refused when another
	// one takes the record first.
	stopped := sampleDoc(t, loaded, &sample.Activity{Op: "load", Node: "n1", Process: "gone"})
	out, err = run(&sample.Loader{NodeID: "n1", Docs: &sampleDocs{docs: []string{sampleDoc(t, loaded, job), stopped}, putErr: store.ErrConflict}})
	if !errors.Is(err, errSampleBusy) || !strings.Contains(out, "It is not running any more.") || !strings.Contains(out, "Removing the sample data.") {
		t.Errorf("stopped: %v %s", err, out)
	}
	// The record went away just before the removal took it.
	out, err = run(&sample.Loader{Docs: &sampleDocs{docs: []string{sampleDoc(t, &sample.State{ID: "s1", Partial: true}, nil)}, putErr: store.ErrNotFound}})
	if err != nil || !strings.Contains(out, "Removing what the unfinished load wrote.") || !strings.Contains(out, "There is no sample data to remove.") {
		t.Errorf("gone: %v %s", err, out)
	}
	out, err = run(&sample.Loader{Docs: &sampleDocs{docs: []string{sampleDoc(t, &sample.State{ID: "s1", Partial: true, Removing: true}, nil)}, putErr: errors.New("disk full")}})
	if err == nil || !strings.Contains(err.Error(), "disk full") || !strings.Contains(out, "Finishing the removal") {
		t.Errorf("write error: %v %s", err, out)
	}
	// A record that names no load: only the sample's own entries go.
	out, err = run(&sample.Loader{Docs: &sampleDocs{docs: []string{`{"kind":"sample_data","body":{}}`}}})
	if err != nil || !strings.Contains(out, "did not say which load it was") {
		t.Errorf("unnamed: %v %s", err, out)
	}
}

func TestSampleLoadCmdRefusals(t *testing.T) {
	ctx := context.Background()
	for _, c := range []struct {
		name string
		docs *sampleDocs
		want string
	}{
		{"loaded", &sampleDocs{docs: []string{sampleDoc(t, &sample.State{ID: "s1"}, nil)}}, "already loaded"},
		{"partial", &sampleDocs{docs: []string{sampleDoc(t, &sample.State{ID: "s1", Partial: true}, nil)}}, "did not finish"},
		{"busy", &sampleDocs{docs: []string{sampleDoc(t, &sample.State{ID: "s1", Partial: true}, &sample.Activity{Op: "load"})}}, "already running"},
		{"read error", &sampleDocs{getErr: errors.New("no route")}, "no route"},
	} {
		t.Run(c.name, func(t *testing.T) {
			var err error
			out := captureStdout(t, func() { err = sampleLoadCmd(ctx, &sample.Loader{Docs: c.docs}, "small") })
			if err == nil || !strings.Contains(err.Error(), c.want) || !strings.Contains(out, "Loading the small sample data") {
				t.Errorf("%v\n%s", err, out)
			}
		})
	}
}
