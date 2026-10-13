package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cluster"
	"github.com/jrsamsanchez/signalith/internal/cluster/ostest"
	"github.com/jrsamsanchez/signalith/internal/sample"
	"github.com/jrsamsanchez/signalith/internal/store"
)

// A failed sample-data job is reported in plain English with what to do,
// and the technical text only as the detail.
func TestSampleErrorText(t *testing.T) {
	refused := &url.Error{Op: "Post", URL: "http://127.0.0.1:18944/signalith-risk-%2A/_refresh", Err: errors.New("dial tcp: connection refused")}
	partial := &sample.State{ID: "sample-a", Partial: true}
	removing := &sample.State{ID: "sample-a", Partial: true, Removing: true}
	for _, tc := range []struct {
		op   string
		err  error
		st   *sample.State
		want string
	}{
		{"load", fmt.Errorf("writing sample events: %w", refused), partial, "Signalith lost its connection to OpenSearch and could not load the sample data. Check the Health page. Remove what was loaded, then load it again."},
		{"remove", &store.Error{Status: 403, Body: `{"error":{"type":"cluster_block_exception"}}`}, removing, "OpenSearch is refusing changes"},
		{"remove", &store.Error{Status: 503, Body: "busy"}, removing, "OpenSearch was too busy to remove the sample data. Check the Health page. Use Finish removing to take out the rest."},
		{"load", &store.Error{Status: 429, Body: "busy"}, nil, "OpenSearch was too busy to load the sample data. Check the Health page. Try again."},
		// A full disk in OpenSearch 2 is a 429 too, but not a busy one.
		{"load", &store.Error{Status: 429, Body: `{"error":{"type":"cluster_block_exception"}}`}, nil, "OpenSearch is refusing changes"},
		{"load", &store.Error{Status: 503, Body: "OpenSearch Security not initialized."}, nil,
			"OpenSearch's security settings aren't loaded, so it refuses every request and Signalith could not load the sample data. The Health page says what to do. Try again."},
		{"load", context.Canceled, partial, "Signalith stopped before it could load the sample data."},
		{"load", noAnswerErr(t), nil, "OpenSearch didn't answer in time, so Signalith could not load the sample data. Check the Health page. Try again."},
		{"load", sample.ErrBusy, nil, "Another sample-data load or removal is running."},
		{"load", sample.ErrTakenOver, partial, "another server took the job over. Remove what was loaded, then load it again."},
		{"load", fmt.Errorf("%w: rejected", sample.ErrNothingWritten), nil, "OpenSearch did not accept any of the sample events, so nothing was loaded. Check the Health page. Try again."},
		{"load", &sample.OldJobsServerError{Name: "siem-b", Version: "1.4.0"}, nil, "The server that runs the background jobs, siem-b, runs an older version of Signalith"},
		{"load", errors.New("boom"), nil, "Something went wrong and Signalith could not load the sample data. Try again."},
	} {
		msg, detail := sampleErrorText(tc.op, tc.err, tc.st)
		if !strings.Contains(msg, tc.want) {
			t.Errorf("%v: message %q, want %q", tc.err, msg, tc.want)
		}
		if strings.Contains(msg, "127.0.0.1") || strings.Contains(msg, "%2A") || strings.Contains(msg, "dial tcp") {
			t.Errorf("%v: message has technical text: %q", tc.err, msg)
		}
		if !errors.Is(tc.err, sample.ErrBusy) && detail != tc.err.Error() {
			t.Errorf("%v: detail %q", tc.err, detail)
		}
	}
}

// A load that stopped part way shows as partial, and a new load is refused
// until it is removed; a job in another process, such as another server
// that shares the OpenSearch, shows as running, with where it runs. The
// record is in OpenSearch's runtime index, so every server sees it.
func TestSampleStatusPartialAndElsewhere(t *testing.T) {
	fake := ostest.New(t)
	cl := store.New(store.Config{URL: fake.URL})
	loader := &sample.Loader{Prefix: "signalith", OS: cl, Docs: cl, Server: "siem-a"}
	ts, _ := newTestServerWith(t, func(s *Server) { s.Sample = loader })

	code, out := do(t, ts, "GET", "/api/sample", "", true)
	if code != 200 || out["loaded"] != false || out["partial"] == true || out["running"] != false {
		t.Fatalf("status with nothing loaded: %d %v", code, out)
	}
	code, out = do(t, ts, "POST", "/api/sample/remove", "", true)
	if code != http.StatusConflict || out["code"] != "not_loaded" {
		t.Errorf("remove with nothing loaded: %d %v", code, out)
	}

	record := func(job *sample.Activity) {
		t.Helper()
		body := map[string]any{"state": sample.State{ID: "sample-20261013-120000", Partial: true, Started: time.Now()}}
		if job != nil {
			body["job"] = job
		}
		doc := map[string]any{"kind": "sample_data", "body": body}
		b, _ := json.Marshal(doc)
		var src map[string]any
		_ = json.Unmarshal(b, &src)
		fake.Put("signalith_runtime", "sample:data", src)
	}
	record(nil)
	code, out = do(t, ts, "GET", "/api/sample", "", true)
	if code != 200 || out["partial"] != true || out["loaded"] != false || out["running"] != false {
		t.Fatalf("status %d %v", code, out)
	}
	code, out = do(t, ts, "POST", "/api/sample/load", `{"size":"small"}`, true)
	if code != http.StatusConflict || out["code"] != "partial" {
		t.Errorf("load over a partial set: %d %v", code, out)
	}

	record(&sample.Activity{Op: "remove", Phase: "Deleting events and risk", Percent: 40, Server: "siem-b", PID: 1, Started: time.Now(), Beat: time.Now()})
	code, out = do(t, ts, "GET", "/api/sample", "", true)
	if code != 200 || out["running"] != true || out["op"] != "remove" || out["percent"] != float64(40) || out["partial"] == true ||
		out["where"] != "Started on the server siem-b." {
		t.Errorf("status with a job elsewhere: %d %v", code, out)
	}
	code, out = do(t, ts, "POST", "/api/sample/remove", "", true)
	if code != http.StatusConflict || out["code"] != "busy" {
		t.Errorf("remove while a job runs elsewhere: %d %v", code, out)
	}

	record(&sample.Activity{Op: "load", Phase: "Writing events", Percent: 9, Server: "build-host", Command: true, Beat: time.Now()})
	if _, out = do(t, ts, "GET", "/api/sample", "", true); out["where"] != "Started with the signalith sample-data command on build-host." {
		t.Errorf("status with the command line loading: %v", out)
	}
}

// A failed job's error shows on the server that ran it only until another
// server loads or removes: then the shared record has moved on and the old
// error no longer applies.
func TestSampleErrorFadesWhenAnotherServerActs(t *testing.T) {
	fake := ostest.New(t)
	cl := store.New(store.Config{URL: fake.URL})
	loader := &sample.Loader{Prefix: "signalith", OS: cl, Docs: cl, Server: "siem-a"}
	var srv *Server
	ts, _ := newTestServerWith(t, func(s *Server) { s.Sample = loader; srv = s })

	put := func(id string, partial bool) {
		t.Helper()
		b, _ := json.Marshal(map[string]any{"kind": "sample_data", "body": map[string]any{
			"state": sample.State{ID: id, Partial: partial, Started: time.Now()}}})
		var src map[string]any
		_ = json.Unmarshal(b, &src)
		fake.Put("signalith_runtime", "sample:data", src)
	}
	failed := func(left string, known bool) {
		srv.sampleJob.mu.Lock()
		srv.sampleJob.op, srv.sampleJob.err = "load", errors.New("boom")
		srv.sampleJob.after = sampleAfter{left: left, known: known, seen: loader.Changes()}
		srv.sampleJob.mu.Unlock()
	}
	errorShown := func() bool {
		t.Helper()
		code, out := do(t, ts, "GET", "/api/sample", "", true)
		if code != 200 {
			t.Fatalf("status %d %v", code, out)
		}
		return out["error"] != nil
	}

	// This server's load stopped part way and left its record.
	put("sample-a", true)
	errorShown()
	failed("sample-a", true)
	if !errorShown() {
		t.Error("error missing while the record is the one the failed load left")
	}
	// Another server removed it and loaded a set of its own.
	put("sample-b", false)
	if errorShown() {
		t.Error("old error shown after another server loaded")
	}
	// Another server removed what this server's failed load left.
	fake.Delete("signalith_runtime", "sample:data")
	if errorShown() {
		t.Error("old error shown after another server removed the record")
	}
	// A failed load that wrote nothing: the error stays while nothing is loaded.
	failed("", true)
	if !errorShown() {
		t.Error("error missing for a load that wrote nothing")
	}
	// ... but not once another server has loaded and removed meanwhile,
	// though nothing is loaded again.
	put("sample-b", false)
	errorShown()
	fake.Delete("signalith_runtime", "sample:data")
	if errorShown() {
		t.Error("old error shown again after another server loaded and removed")
	}
	// When the record could not be read after the failure, the error stays.
	put("sample-b", false)
	errorShown()
	failed("", false)
	if !errorShown() {
		t.Error("error missing when the record could not be read after the failure")
	}
}

// A load refused because another server's job got there first keeps no
// error: the status shows that job, and then what it left, from the record.
func TestSampleRefusalIsNotAnError(t *testing.T) {
	fake := ostest.New(t)
	cl := store.New(store.Config{URL: fake.URL})
	loader := &sample.Loader{Prefix: "signalith", OS: cl, Docs: cl, Server: "siem-b"}
	var srv *Server
	ts, _ := newTestServerWith(t, func(s *Server) { s.Sample = loader; srv = s })
	for _, err := range []error{sample.ErrBusy, sample.ErrPartial, sample.ErrAlreadyLoaded} {
		if !srv.sampleJob.start(context.Background(), "load", func(context.Context, sample.ProgressFn) error { return err }, srv.sampleLeft) {
			t.Fatal("job did not start")
		}
		for deadline := time.Now().Add(5 * time.Second); srv.sampleJob.snapshot().running; {
			if time.Now().After(deadline) {
				t.Fatal("job did not end")
			}
			time.Sleep(5 * time.Millisecond)
		}
		b, _ := json.Marshal(map[string]any{"kind": "sample_data", "body": map[string]any{
			"state": sample.State{ID: "sample-a", Partial: true, Started: time.Now()}}})
		var src map[string]any
		_ = json.Unmarshal(b, &src)
		fake.Put("signalith_runtime", "sample:data", src)
		_, out := do(t, ts, "GET", "/api/sample", "", true)
		if out["error"] != nil || out["partial"] != true {
			t.Errorf("%v: status %v; want the unfinished load, and no error", err, out)
		}
	}
}

// A load is refused at once, with a plain reason, while the server that
// runs the background jobs runs an older version.
func TestSampleLoadRefusedWithOldJobsServer(t *testing.T) {
	fake := ostest.New(t)
	cl := store.New(store.Config{URL: fake.URL})
	loader := &sample.Loader{Prefix: "signalith", OS: cl, Docs: cl, Server: "siem-a"}
	ts, _ := newTestServerWith(t, func(s *Server) { s.Sample = loader })
	put := func(id string, v any) {
		b, _ := json.Marshal(v)
		var src map[string]any
		_ = json.Unmarshal(b, &src)
		fake.Put("signalith_runtime", id, src)
	}
	put(cluster.LeaseDocID, cluster.LeaseDoc{Kind: "lease", Holder: "n_b", HolderName: "siem-b"})
	put(cluster.NodeDocID("n_b"), cluster.Heartbeat{Kind: "node", NodeID: "n_b", Name: "siem-b", Version: "1.4.0", State: cluster.StateReady})
	code, out := do(t, ts, "POST", "/api/sample/load", `{"size":"small"}`, true)
	if code != http.StatusConflict || out["code"] != "old_jobs_server" ||
		!strings.Contains(fmt.Sprint(out["error"]), "siem-b, runs an older version") {
		t.Errorf("load with an old jobs server: %d %v", code, out)
	}
}

// A removal that stopped part way says so, and how to finish it.
func TestSampleStoppedRemovalStatus(t *testing.T) {
	fake := ostest.New(t)
	cl := store.New(store.Config{URL: fake.URL})
	loader := &sample.Loader{Prefix: "signalith", OS: cl, Docs: cl, Server: "siem-a"}
	ts, _ := newTestServerWith(t, func(s *Server) { s.Sample = loader })
	b, _ := json.Marshal(map[string]any{"kind": "sample_data", "body": map[string]any{
		"state": sample.State{ID: "sample-a", Partial: true, Removing: true, Events: 27000}}})
	var src map[string]any
	_ = json.Unmarshal(b, &src)
	fake.Put("signalith_runtime", "sample:data", src)
	code, out := do(t, ts, "GET", "/api/sample", "", true)
	st, _ := out["state"].(map[string]any)
	if code != 200 || out["loaded"] != false || out["partial"] != true || st["removing"] != true {
		t.Errorf("status after a stopped removal: %d %v", code, out)
	}
	code, out = do(t, ts, "POST", "/api/sample/load", `{"size":"small"}`, true)
	if code != http.StatusConflict || out["code"] != "partial" || !strings.Contains(fmt.Sprint(out["error"]), "removal did not finish") {
		t.Errorf("load after a stopped removal: %d %v", code, out)
	}
}
