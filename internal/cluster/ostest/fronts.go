package ostest

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
)

// Front is another address of a fake, as one node of a cluster of several
// is: what is written through one front is read through every other.
// Unlike a Plug, a front can be taken down and brought back, and have
// faults of its own.
type Front struct {
	*httptest.Server
	s        *Server
	mu       sync.Mutex
	down     bool
	fault    func(method, path string) *Fault
	requests []string
}

// Front returns a new address of s. It stops when the test ends.
func (s *Server) Front(t interface{ Cleanup(func()) }) *Front {
	f := &Front{s: s}
	f.Server = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.Close)
	return f
}

// Down makes the front drop every request without an answer, as a node
// that crashed (its address still takes connections; see Close for one
// that takes none). Up undoes that.
func (f *Front) Down() { f.set(true) }

// Up answers requests again after Down.
func (f *Front) Up() { f.set(false) }

func (f *Front) set(down bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.down = down
}

// SetFault sets a function that may answer a request through this front
// with a Fault; nil clears it. The fake's own fault (Server.SetFault)
// still applies after it.
func (f *Front) SetFault(fn func(method, path string) *Fault) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.fault = fn
}

// Requests returns the requests made through this front, as
// "METHOD /path?query", and forgets them.
func (f *Front) Requests() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := f.requests
	f.requests = nil
	return out
}

func (f *Front) serve(w http.ResponseWriter, r *http.Request) {
	// Read the body first, as OpenSearch does: only then does the request
	// end when the client gives up.
	body, _ := io.ReadAll(r.Body)
	r.Body = io.NopCloser(bytes.NewReader(body))
	f.mu.Lock()
	f.requests = append(f.requests, r.Method+" "+r.URL.RequestURI())
	down, fault := f.down, f.fault
	f.mu.Unlock()
	if down {
		drop(w)
		return
	}
	if fault != nil {
		if ft := fault(r.Method, r.URL.RequestURI()); ft != nil {
			switch {
			case ft.Stall:
				<-r.Context().Done()
				return
			case ft.Drop:
				f.s.serve(httptest.NewRecorder(), r)
				drop(w)
				return
			case ft.Text != "":
				w.Header().Set("Content-Type", "text/plain; charset=UTF-8")
				w.WriteHeader(ft.Status)
				_, _ = io.WriteString(w, ft.Text)
				return
			}
			writeError(w, ft.Status, ft.Type, "injected by the test")
			return
		}
	}
	f.s.serve(w, r)
}
