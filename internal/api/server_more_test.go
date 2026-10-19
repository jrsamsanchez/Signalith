package api

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/search"
)

// A failed search is answered by what failed: the query, the slots
// everyone shares, the user's own share, or OpenSearch.
func TestWriteSearchError(t *testing.T) {
	for _, c := range []struct {
		err   error
		code  int
		retry bool
	}{
		{&search.QueryError{Msg: "unknown field"}, http.StatusBadRequest, false},
		{search.ErrBusy, http.StatusServiceUnavailable, true},
		{search.ErrUserBusy, http.StatusTooManyRequests, true},
		{errors.New("connection refused"), http.StatusBadGateway, false},
	} {
		w := httptest.NewRecorder()
		writeSearchError(w, c.err)
		if w.Code != c.code || (w.Header().Get("Retry-After") != "") != c.retry {
			t.Errorf("%v: %d %v", c.err, w.Code, w.Header())
		}
	}
	be := &batchError{err: errDown}
	if be.Error() != errDown.Error() || !errors.Is(be, errDown) {
		t.Errorf("batchError %v", be)
	}
}

// The query builder and the certificate's names answer bad bodies 400;
// without a certificate of its own there is no name to add.
func TestBuildAndTLSNames(t *testing.T) {
	ts, _ := newTestServer(t)
	if code, _ := do(t, ts, "POST", "/api/build", `{`, true); code != http.StatusBadRequest {
		t.Errorf("build bad JSON: %d", code)
	}
	if code, _ := do(t, ts, "POST", "/api/tls/names", `{`, true); code != http.StatusBadRequest {
		t.Errorf("names bad JSON: %d", code)
	}
	if code, _ := do(t, ts, "POST", "/api/tls/names", `{"name":"siem.example.com"}`, true); code != http.StatusConflict {
		t.Errorf("names without a certificate: %d", code)
	}

	ts, _ = newTestServerWith(t, func(s *Server) { s.TLS = newCertManager(t) })
	if code, out := do(t, ts, "POST", "/api/tls/names", `{"name":"10.20.30.40"}`, true); code != http.StatusOK || out["names"] == nil {
		t.Errorf("add a name: %d %v", code, out)
	}
	if code, out := do(t, ts, "POST", "/api/tls/names", `{"name":"www.example.org"}`, true); code != http.StatusBadRequest || out["field"] != "name" {
		t.Errorf("a name the CA may not sign: %d %v", code, out)
	}
}

// A decision about the example token made after the server started is
// put into use at once.
func TestUseDockerUpgrade(t *testing.T) {
	t.Setenv("SIGNALITH_STATE_DIR", t.TempDir())
	var srv *Server
	newTestServerWith(t, func(s *Server) { srv = s })
	before := srv.conf()
	srv.UseDockerUpgrade(&config.DockerUpgrade{Upgraded: true, Setup: time.Now().Add(-time.Hour)})
	if srv.conf() == before || srv.conf().DockerUpgrade() == nil || !srv.conf().DockerUpgrade().Upgraded {
		t.Errorf("not in use: %+v", srv.conf().DockerUpgrade())
	}
}
