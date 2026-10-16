package risk

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cluster/ostest"
	"github.com/jrsamsanchez/signalith/internal/datamodel"
	"github.com/jrsamsanchez/signalith/internal/detect"
	"github.com/jrsamsanchez/signalith/internal/store"
)

// A risk event written again with the ID it was stored under counts as
// written, and is stored once, in the daily index of its own time.
func TestWriteWithIDIsOnce(t *testing.T) {
	srv := ostest.New(t)
	s := &Store{Client: store.New(store.Config{URL: srv.URL}), Prefix: "t"}
	at := time.Date(2026, 10, 13, 23, 59, 30, 0, time.UTC)
	ev := detect.RiskEvent{ID: "abc123", Time: at, Object: "bob", ObjectType: "user", Score: 10, BaseScore: 10, DetectionID: "r1", GroupKey: "k"}
	ctx := context.Background()
	if err := s.Write(ctx, []detect.RiskEvent{ev}); err != nil {
		t.Fatal(err)
	}
	if err := s.Write(ctx, []detect.RiskEvent{ev}); err != nil {
		t.Fatalf("written again: %v", err)
	}
	index := datamodel.IndexName("t", datamodel.RiskModel, "2026.10.13")
	if src := srv.Source(index, "abc123"); src == nil || src["risk_object"] != "bob" {
		t.Errorf("stored %v", src)
	}
	var n int
	for _, ix := range srv.Indices() {
		if strings.HasPrefix(ix, "t-risk-") {
			n++
		}
	}
	if n != 1 {
		t.Errorf("%d risk indices", n)
	}
	// Without an ID, a write is never taken for one already stored.
	ev.ID = ""
	if err := s.Write(ctx, []detect.RiskEvent{ev, ev}); err != nil {
		t.Fatal(err)
	}
}
