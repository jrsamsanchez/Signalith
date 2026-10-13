package respond

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestHTTPTestPreviewsAndSendsOnlyWhenAsked(t *testing.T) {
	k := newHook(t, func(w http.ResponseWriter, r *http.Request) {})
	c := hookAction(k.srv.URL)
	r, mem := runnerWith(t, c)
	c.Normalize()
	rep := r.Test(t.Context(), c, "203.0.113.9", false, "admin")
	if !rep.OK || rep.Request == nil || rep.Request.URL != k.srv.URL+"/api/alias/add/203.0.113.9?case=" || k.hits.Load() != 0 {
		t.Fatalf("preview: %+v %+v", rep, rep.Request)
	}
	for _, h := range rep.Request.Headers {
		if strings.Contains(h, "sekrit") {
			t.Errorf("preview shows a secret: %s", h)
		}
	}
	rep = r.Test(t.Context(), c, "203.0.113.9", true, "admin")
	if !rep.OK || rep.Run == nil || k.hits.Load() != 1 {
		t.Fatalf("send: %+v", rep)
	}
	if runs, _ := mem.List(t.Context(), Filter{}); len(runs) != 1 || runs[0].Actor != "admin" || !strings.Contains(runs[0].Reason, "Test") {
		t.Errorf("a sent test is not in the audit log: %+v", runs)
	}
	if rep := r.Test(t.Context(), c, "not an ip", false, "admin"); rep.OK {
		t.Error("a bad target passes the test")
	}
	s := Connector{Name: "s", Kind: KindScript, Target: TargetHost, Program: "missing.sh"}
	r.ScriptsDir = t.TempDir()
	if rep := r.Test(t.Context(), s, "", false, "admin"); rep.OK || !strings.Contains(rep.Message, "not in the scripts folder") {
		t.Errorf("script test: %+v", rep)
	}
}

// fakeDoer records OpenSearch requests.
type fakeDoer struct {
	paths []string
	reply string
}

func (f *fakeDoer) Do(_ context.Context, method, path string, body any, out any) error {
	f.paths = append(f.paths, method+" "+path)
	if out != nil {
		return json.Unmarshal([]byte(f.reply), out)
	}
	return nil
}

func TestOpenSearchStore(t *testing.T) {
	old := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	d := &fakeDoer{reply: `{"hits":{"hits":[{"_source":{"id":"RUN-1","status":"running","started":"` + old + `"}}]}}`}
	s := NewOpenSearch(d, "signalith")
	_ = s.Put(t.Context(), &Run{ID: "RUN-1"}, false)
	_ = s.Put(t.Context(), &Run{ID: "RUN-1"}, true)
	runs, err := s.List(t.Context(), Filter{CaseID: "CASE-1"})
	if err != nil || len(runs) != 1 || runs[0].Status != StatusInterrupted {
		t.Errorf("list %+v %v", runs, err)
	}
	want := []string{"PUT /signalith_actions/_doc/RUN-1", "PUT /signalith_actions/_doc/RUN-1?refresh=wait_for", "POST /signalith_actions/_search"}
	if strings.Join(d.paths, "|") != strings.Join(want, "|") {
		t.Errorf("paths %v", d.paths)
	}
}
