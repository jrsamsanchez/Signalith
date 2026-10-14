package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cases"
	"github.com/jrsamsanchez/signalith/internal/cluster/ostest"
	"github.com/jrsamsanchez/signalith/internal/findings"
	"github.com/jrsamsanchez/signalith/internal/store"
)

// twoServers starts two API servers, each with its own case lock, whose
// findings and cases live in one (fake) OpenSearch, as two Signalith
// servers of one cluster do.
func twoServers(t *testing.T) ([2]*httptest.Server, *findings.OpenSearch, *cases.OpenSearch) {
	t.Helper()
	fake := ostest.New(t)
	var out [2]*httptest.Server
	var fs *findings.OpenSearch
	var cs *cases.OpenSearch
	for i := range out {
		cl := store.New(store.Config{URL: fake.URL})
		fs, cs = findings.NewOpenSearch(cl, "sig"), cases.NewOpenSearch(cl, "sig")
		out[i], _ = newTestServerWith(t, func(s *Server) {
			s.Findings, s.Cases, s.Scheduler.Findings = fs, cs, fs
		})
	}
	return out, fs, cs
}

// signedIn returns a client signed in to ts with a session cookie, so
// many requests at once do not each count as a sign-in attempt.
func signedIn(t *testing.T, ts *httptest.Server) *http.Client {
	t.Helper()
	jar, _ := cookiejar.New(nil)
	cl := &http.Client{Jar: jar}
	resp, err := cl.Post(ts.URL+"/api/login", "application/json", strings.NewReader(`{"username":"admin","password":"s3cret-pass"}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("sign-in = %d", resp.StatusCode)
	}
	return cl
}

// callAsync is do for use from several goroutines, with a signed-in
// client: it reports failures with t.Error instead of stopping the test.
func callAsync(t *testing.T, cl *http.Client, ts *httptest.Server, method, path, body string) (int, map[string]any) {
	req, _ := http.NewRequest(method, ts.URL+path, strings.NewReader(body))
	resp, err := cl.Do(req)
	if err != nil {
		t.Error(err)
		return 0, nil
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	return resp.StatusCode, out
}

// TestTwoServersEditTheSameCaseAndFinding: analysts on two servers comment
// on the same case and triage the same finding at the same moment, with a
// bulk update in between; every entry and comment is kept, and the
// finding's history is complete.
func TestTwoServersEditTheSameCaseAndFinding(t *testing.T) {
	ctx := context.Background()
	srv, fs, cs := twoServers(t)
	cl := [2]*http.Client{signedIn(t, srv[0]), signedIn(t, srv[1])}
	now := time.Now().UTC()
	for _, id := range []string{"f1", "f2"} {
		if err := fs.Create(ctx, &findings.Finding{ID: id, Title: "Brute force", Severity: "high", Status: findings.StatusNew, Created: now, Updated: now}); err != nil {
			t.Fatal(err)
		}
	}
	code, out := do(t, srv[0], "POST", "/api/cases", `{"title":"Brute force on the VPN"}`, true)
	if code != 201 {
		t.Fatalf("create case = %d %v", code, out)
	}
	caseID := out["case"].(map[string]any)["id"].(string)

	const n = 20
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ts := srv[i%2]
			if code, out := callAsync(t, cl[i%2], ts, "POST", "/api/cases/"+caseID+"/entries", fmt.Sprintf(`{"kind":"note","text":"note %d"}`, i)); code != 201 {
				t.Errorf("note %d = %d %v", i, code, out)
			}
			if code, out := callAsync(t, cl[i%2], ts, "PATCH", "/api/findings/f1", fmt.Sprintf(`{"comment":"comment %d"}`, i)); code != 200 {
				t.Errorf("comment %d = %d %v", i, code, out)
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		code, out := callAsync(t, cl[1], srv[1], "POST", "/api/findings/bulk", `{"ids":["f1","f2"],"update":{"status":"in_progress","owner":"ana","comment":"taking these"}}`)
		if code != 200 || out["updated"] != float64(2) {
			t.Errorf("bulk = %d %v", code, out)
		}
	}()
	wg.Wait()

	c, err := cs.Get(ctx, caseID)
	if err != nil {
		t.Fatal(err)
	}
	notes := map[string]bool{}
	for _, e := range c.Entries {
		notes[e.Text] = true
	}
	if len(c.Entries) != n || len(notes) != n {
		t.Errorf("the case kept %d entries (%d different), want %d", len(c.Entries), len(notes), n)
	}
	f, err := fs.Get(ctx, "f1")
	if err != nil {
		t.Fatal(err)
	}
	comments := map[string]bool{}
	for _, cm := range f.Comments {
		comments[cm.Text] = true
	}
	if len(f.Comments) != n+1 || len(comments) != n+1 || !comments["taking these"] {
		t.Errorf("the finding kept %d comments (%d different), want %d", len(f.Comments), len(comments), n+1)
	}
	if f.Status != findings.StatusInProgress || f.Owner != "ana" || len(f.History) != 2 {
		t.Errorf("finding = %s %s, history %+v", f.Status, f.Owner, f.History)
	}
	if f2, _ := fs.Get(ctx, "f2"); f2.Status != findings.StatusInProgress || len(f2.Comments) != 1 {
		t.Errorf("f2 = %+v", f2)
	}
}

// TestTwoServersLinkOneFindingToTwoCases: analysts on two servers add the
// same finding to two different cases at the same moment. Whichever wins,
// the finding ends up in exactly the case its case_id names.
func TestTwoServersLinkOneFindingToTwoCases(t *testing.T) {
	ctx := context.Background()
	srv, fs, cs := twoServers(t)
	cl := [2]*http.Client{signedIn(t, srv[0]), signedIn(t, srv[1])}
	for round := 0; round < 5; round++ {
		fid := fmt.Sprintf("f%d", round)
		if err := fs.Create(ctx, &findings.Finding{ID: fid, Title: "Odd logon", Severity: "medium", Status: findings.StatusNew}); err != nil {
			t.Fatal(err)
		}
		var ids [2]string
		for i := range ids {
			code, out := do(t, srv[i], "POST", "/api/cases", fmt.Sprintf(`{"title":"Case %d.%d"}`, round, i), true)
			if code != 201 {
				t.Fatalf("create case = %d %v", code, out)
			}
			ids[i] = out["case"].(map[string]any)["id"].(string)
		}
		var wg sync.WaitGroup
		for i := range ids {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if code, out := callAsync(t, cl[i], srv[i], "POST", "/api/cases/"+ids[i]+"/findings", `{"ids":["`+fid+`"]}`); code != 200 || len(out["failed"].(map[string]any)) > 0 {
					t.Errorf("link = %d %v", code, out)
				}
			}()
		}
		wg.Wait()
		f, err := fs.Get(ctx, fid)
		if err != nil {
			t.Fatal(err)
		}
		holding := 0
		for _, id := range ids {
			c, err := cs.Get(ctx, id)
			if err != nil {
				t.Fatal(err)
			}
			has := slices.Contains(c.Findings, fid)
			if has {
				holding++
			}
			if has != (f.CaseID == id) {
				t.Errorf("round %d: case %s holds the finding: %v, but the finding names %q", round, id, has, f.CaseID)
			}
		}
		if holding != 1 || f.Status != findings.StatusInProgress {
			t.Errorf("round %d: %d cases hold the finding; status %s", round, holding, f.Status)
		}
	}
}

// busyFindings and busyCases lose every write to someone else.
type busyFindings struct{ *findings.Memory }

func (busyFindings) Modify(context.Context, string, func(*findings.Finding) (bool, error)) (*findings.Finding, error) {
	return nil, findings.ErrBusy
}

type busyCases struct{ *cases.Memory }

func (busyCases) Modify(context.Context, string, func(*cases.Case) (bool, error)) (*cases.Case, error) {
	return nil, cases.ErrBusy
}

// TestBusyEditsSayTryAgain: an edit that kept losing to other changes is
// answered 409 with a plain message, not as an OpenSearch failure.
func TestBusyEditsSayTryAgain(t *testing.T) {
	ts, _ := newTestServerWith(t, func(s *Server) {
		s.Findings, s.Cases = busyFindings{findings.NewMemory()}, busyCases{cases.NewMemory()}
	})
	code, out := do(t, ts, "PATCH", "/api/findings/f1", `{"comment":"x"}`, true)
	if code != 409 || !strings.Contains(fmt.Sprint(out["error"]), "Try again") {
		t.Errorf("busy finding = %d %v", code, out)
	}
	code, out = do(t, ts, "POST", "/api/cases/CASE-1/entries", `{"kind":"note","text":"x"}`, true)
	if code != 409 || !strings.Contains(fmt.Sprint(out["error"]), "Someone else changed this investigation") {
		t.Errorf("busy case = %d %v", code, out)
	}
}

// takenFindingID answers the first create as if its ID were taken.
type takenFindingID struct {
	*findings.Memory
	tried []string
}

func (s *takenFindingID) Create(ctx context.Context, f *findings.Finding) error {
	s.tried = append(s.tried, f.ID)
	if len(s.tried) == 1 {
		return findings.ErrExists
	}
	return s.Memory.Create(ctx, f)
}

func TestFindingIDCollisionGetsANewID(t *testing.T) {
	st := &takenFindingID{Memory: findings.NewMemory()}
	ts, _ := newTestServerWith(t, func(s *Server) { s.Findings = st })
	code, out := do(t, ts, "POST", "/api/findings", `{"title":"Odd logon"}`, true)
	if code != 201 || len(st.tried) != 2 || st.tried[0] == st.tried[1] || out["id"] != st.tried[1] {
		t.Fatalf("create = %d %v, tried %v", code, out, st.tried)
	}
}
