package api

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/shared"
)

// A change of this server's own files refused while they move into the
// shared settings is a 503 the pages show, asked again shortly.
func TestMovingIsRetryable(t *testing.T) {
	w := httptest.NewRecorder()
	if !sharedError(w, fmt.Errorf("save: %w", &shared.MovingError{What: "users"})) {
		t.Fatal("not answered")
	}
	if w.Code != http.StatusServiceUnavailable || w.Header().Get("Retry-After") == "" ||
		!strings.Contains(w.Body.String(), "moving its users into the cluster; try again in a moment") {
		t.Errorf("%d %v %s", w.Code, w.Header(), w.Body)
	}
}
