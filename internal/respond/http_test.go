package respond

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// hook is a fake firewall API that records what it was sent.
type hook struct {
	srv  *httptest.Server
	hits atomic.Int32
	last atomic.Value // *http.Request with body read into lastBody
	body atomic.Value // string
}

func newHook(t *testing.T, h http.HandlerFunc) *hook {
	k := &hook{}
	k.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		k.hits.Add(1)
		b, _ := io.ReadAll(r.Body)
		k.last.Store(r)
		k.body.Store(string(b))
		h(w, r)
	}))
	t.Cleanup(k.srv.Close)
	return k
}

func runnerWith(t *testing.T, list ...Connector) (*Runner, *Memory) {
	t.Helper()
	a := &Actions{}
	if err := a.Save(list); err != nil {
		t.Fatal(err)
	}
	mem := &Memory{}
	return &Runner{Actions: a, Store: mem}, mem
}

func hookAction(url string) Connector {
	return Connector{Name: "block", Label: "Block IP", Kind: KindHTTP, Target: TargetIP, Method: "POST", AllowLoopback: true,
		URL: url + "/api/alias/add/{{.ip}}?case={{.case_id}}", Body: `{"address": "{{.ip}}", "why": "{{.reason}}"}`,
		Headers: map[string]string{"X-Api-Key": "sekrit-key-123"}, Username: "apiuser", Password: "sekrit-pass-456"}
}

func TestHTTPActionSendsAndHidesSecrets(t *testing.T) {
	k := newHook(t, func(w http.ResponseWriter, r *http.Request) {
		// A server that echoes the request, keys included.
		w.Header().Set("Content-Type", "text/plain")
		io.WriteString(w, "ok, got key "+r.Header.Get("X-Api-Key")+" auth "+r.Header.Get("Authorization"))
	})
	r, mem := runnerWith(t, hookAction(k.srv.URL))
	run, err := r.Run(t.Context(), Request{Action: "block", Target: "203.0.113.7", Reason: `brute "force"`, Actor: Actor{Name: "ann"}})
	if err != nil {
		t.Fatal(err)
	}
	req := k.last.Load().(*http.Request)
	if run.Status != StatusSucceeded || req.URL.Path != "/api/alias/add/203.0.113.7" || req.Header.Get("X-Api-Key") != "sekrit-key-123" ||
		req.Header.Get("Content-Type") != "application/json" {
		t.Fatalf("run %+v request %s %v", run, req.URL, req.Header)
	}
	if u, p, _ := req.BasicAuth(); u != "apiuser" || p != "sekrit-pass-456" {
		t.Errorf("basic auth %s %s", u, p)
	}
	var body map[string]string
	if err := json.Unmarshal([]byte(k.body.Load().(string)), &body); err != nil || body["why"] != `brute "force"` {
		t.Errorf("body %v %v", body, err)
	}
	for _, s := range []string{"sekrit-key-123", "sekrit-pass-456"} {
		if strings.Contains(run.Output, s) || strings.Contains(run.Summary, s) {
			t.Errorf("the run shows %q: %+v", s, run)
		}
	}
	if !strings.Contains(run.Output, "200 OK") || !strings.Contains(run.Output, "got key [hidden]") {
		t.Errorf("output %q", run.Output)
	}
	runs, _ := mem.List(t.Context(), Filter{})
	if len(runs) != 1 || runs[0].Status != StatusSucceeded || runs[0].Actor != "ann" || runs[0].Reason != `brute "force"` || runs[0].Finished.IsZero() {
		t.Errorf("audit %+v", runs)
	}
}

func TestHTTPActionFailures(t *testing.T) {
	k := newHook(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/alias/add/10.0.0.1":
			http.Error(w, "no rights", http.StatusForbidden)
		case "/api/alias/add/10.0.0.2":
			http.Redirect(w, r, "http://other.example.com/x", http.StatusFound)
		case "/api/alias/add/10.0.0.3":
			io.WriteString(w, strings.Repeat("x", 200<<10))
		}
	})
	r, _ := runnerWith(t, hookAction(k.srv.URL))
	run := func(ip string) *Run {
		t.Helper()
		run, err := r.Run(t.Context(), Request{Action: "block", Target: ip, Reason: "x", Actor: Actor{Name: "ann"}})
		if err != nil {
			t.Fatal(err)
		}
		return run
	}
	if got := run("10.0.0.1"); got.Status != StatusFailed || !strings.Contains(got.Error, "403") || !strings.Contains(got.Output, "no rights") {
		t.Errorf("403: %+v", got)
	}
	if got := run("10.0.0.2"); got.Status != StatusFailed || !strings.Contains(got.Error, "redirected to http://other.example.com") {
		t.Errorf("redirect: %+v", got)
	}
	if got := run("10.0.0.3"); got.Status != StatusSucceeded || len(got.Output) > MaxOutput+100 {
		t.Errorf("big answer: %s, %d bytes", got.Status, len(got.Output))
	}
}

func TestHTTPActionAddressChecks(t *testing.T) {
	k := newHook(t, func(w http.ResponseWriter, r *http.Request) {})
	c := hookAction(k.srv.URL)
	c.AllowLoopback = false
	r, _ := runnerWith(t, c)
	got, err := r.Run(t.Context(), Request{Action: "block", Target: "10.9.9.9", Reason: "x", Actor: Actor{Name: "ann"}})
	if err != nil || got.Status != StatusFailed || !strings.Contains(got.Error, "loopback") || !strings.Contains(got.Error, "Allow this server") {
		t.Errorf("loopback: %+v %v", got, err)
	}
	// Signalith's own OpenSearch is refused even when loopback is allowed.
	c.AllowLoopback = true
	r, _ = runnerWith(t, c)
	r.Protected = []string{strings.TrimPrefix(k.srv.URL, "http://")}
	got, _ = r.Run(t.Context(), Request{Action: "block", Target: "10.9.9.9", Reason: "x", Actor: Actor{Name: "ann"}})
	if got.Status != StatusFailed || !strings.Contains(got.Error, "OpenSearch") {
		t.Errorf("protected: %+v", got)
	}
	if k.hits.Load() != 0 {
		t.Errorf("the server was reached %d times", k.hits.Load())
	}
	// Link-local (cloud metadata) is refused whatever the action allows.
	c.URL = "http://169.254.169.254/latest/{{.ip}}"
	r, _ = runnerWith(t, c)
	got, _ = r.Run(t.Context(), Request{Action: "block", Target: "10.9.9.9", Reason: "x", Actor: Actor{Name: "ann"}})
	if got.Status != StatusFailed || !strings.Contains(got.Error, "link-local") {
		t.Errorf("metadata: %+v", got)
	}
}

func TestHTTPActionTLS(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") }))
	defer srv.Close()
	c := hookAction(srv.URL)
	r, _ := runnerWith(t, c)
	got, _ := r.Run(t.Context(), Request{Action: "block", Target: "10.9.9.9", Reason: "x", Actor: Actor{Name: "ann"}})
	if got.Status != StatusFailed || !strings.Contains(got.Error, "trusted authority") {
		t.Errorf("untrusted: %+v", got)
	}
	c.CACert = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}))
	r, _ = runnerWith(t, c)
	got, _ = r.Run(t.Context(), Request{Action: "block", Target: "10.9.9.9", Reason: "x", Actor: Actor{Name: "ann"}})
	if got.Status != StatusSucceeded {
		t.Errorf("with the CA: %+v", got)
	}
}

// recorder is a fake Recorder.
type recorder struct {
	cases, findings []string
	missing         bool
}

func (f *recorder) Check(_ context.Context, findingID, caseID string) error {
	if f.missing {
		return &RequestError{Field: "case_id", Msg: "there is no case " + caseID}
	}
	return nil
}
func (f *recorder) OnCase(_ context.Context, id string, run *Run) error {
	f.cases = append(f.cases, id+": "+run.Text())
	return nil
}
func (f *recorder) OnFinding(_ context.Context, id string, run *Run) error {
	f.findings = append(f.findings, id+": "+run.Text())
	return errors.New("finding store is down")
}

func TestRunChecksAndRecords(t *testing.T) {
	k := newHook(t, func(w http.ResponseWriter, r *http.Request) {})
	off := hookAction(k.srv.URL)
	off.Name, off.Enabled = "off", boolp(false)
	gentle := hookAction(k.srv.URL)
	gentle.Name, gentle.Disruptive = "gentle", boolp(false)
	r, mem := runnerWith(t, hookAction(k.srv.URL), off, gentle)
	rec := &recorder{}
	r.Record = rec
	ctx := t.Context()
	ann := Actor{Name: "ann"}
	var re *RequestError
	if _, err := r.Run(ctx, Request{Action: "block", Target: "203.0.113.7", Actor: ann}); !errors.As(err, &re) || re.Field != "reason" {
		t.Errorf("no reason: %v", err)
	}
	if _, err := r.Run(ctx, Request{Action: "block", Target: "bad.example.com", Reason: "x", Actor: ann}); !errors.As(err, &re) || re.Field != "target" {
		t.Errorf("a domain for an IP action: %v", err)
	}
	if _, err := r.Run(ctx, Request{Action: "block", Target: "203.0.113.7", TargetKind: "user", Reason: "x", Actor: ann}); !errors.As(err, &re) {
		t.Errorf("wrong kind: %v", err)
	}
	if _, err := r.Run(ctx, Request{Action: "off", Target: "203.0.113.7", Reason: "x", Actor: ann}); !errors.As(err, &re) {
		t.Errorf("turned off: %v", err)
	}
	if _, err := r.Run(ctx, Request{Action: "nope", Target: "203.0.113.7", Reason: "x", Actor: ann}); !errors.Is(err, ErrNotFound) {
		t.Errorf("missing: %v", err)
	}
	rec.missing = true
	if _, err := r.Run(ctx, Request{Action: "gentle", Target: "203.0.113.7", CaseID: "CASE-X", Actor: ann}); !errors.As(err, &re) {
		t.Errorf("missing case: %v", err)
	}
	rec.missing = false
	if k.hits.Load() != 0 {
		t.Fatalf("refused runs reached the server %d times", k.hits.Load())
	}
	run, err := r.Run(ctx, Request{Action: "gentle", Target: "203.0.113.7", CaseID: "CASE-1", FindingID: "F-1", Actor: ann})
	if err != nil || run.Status != StatusSucceeded {
		t.Fatalf("gentle: %+v %v", run, err)
	}
	if len(rec.cases) != 1 || !strings.HasPrefix(rec.cases[0], "CASE-1: Ran Block IP on IP address 203.0.113.7: succeeded.") {
		t.Errorf("case notes %v", rec.cases)
	}
	if len(rec.findings) != 1 || len(run.RecordErrors) != 1 || !strings.Contains(run.RecordErrors[0], "finding store is down") {
		t.Errorf("finding notes %v, record errors %v", rec.findings, run.RecordErrors)
	}
	if runs, _ := mem.List(ctx, Filter{CaseID: "CASE-1"}); len(runs) != 1 || runs[0].ID != run.ID || runs[0].Status != StatusSucceeded {
		t.Errorf("audit %+v", runs)
	}
	// An audit log that cannot be written stops the run.
	mem.Fail = errors.New("disk full")
	var ae *AuditError
	if _, err := r.Run(ctx, Request{Action: "gentle", Target: "203.0.113.8", Actor: ann}); !errors.As(err, &ae) {
		t.Errorf("broken audit log: %v", err)
	}
	if k.hits.Load() != 1 {
		t.Errorf("a run without an audit record reached the server")
	}
}

func TestRunRateLimit(t *testing.T) {
	k := newHook(t, func(w http.ResponseWriter, r *http.Request) {})
	c := hookAction(k.srv.URL)
	c.Disruptive = boolp(false)
	r, _ := runnerWith(t, c)
	for i := range RunsPerMinute {
		if _, err := r.Run(t.Context(), Request{Action: "block", Target: "203.0.113.7", Actor: Actor{Name: "Ann"}}); err != nil {
			t.Fatalf("run %d: %v", i, err)
		}
	}
	if _, err := r.Run(t.Context(), Request{Action: "block", Target: "203.0.113.7", Actor: Actor{Name: "ann"}}); !errors.Is(err, ErrRateLimited) {
		t.Errorf("run %d: %v", RunsPerMinute+1, err)
	}
	if _, err := r.Run(t.Context(), Request{Action: "block", Target: "203.0.113.7", Actor: Actor{Name: "bob"}}); err != nil {
		t.Errorf("another user is limited too: %v", err)
	}
}
