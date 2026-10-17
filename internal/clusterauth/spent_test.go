package clusterauth

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

// A proof spent on one server is refused on every other, even when both
// are given it at the same moment, and the record names neither the
// proof nor its kind.
func TestSpentShared(t *testing.T) {
	o, a, b, clk := pair(t)
	ctx := context.Background()
	sa := &Spent{Docs: a.docs, Client: o.client, Node: "n_siem-a", Now: clk.Now}
	sb := &Spent{Docs: b.docs, Client: o.client, Node: "n_siem-b", Now: clk.Now}
	until := clk.Now().Add(5 * time.Minute)
	if err := sa.Use(ctx, "saml", "https://idp.example.com _abc123", until); err != nil {
		t.Fatal(err)
	}
	if err := sb.Use(ctx, "saml", "https://idp.example.com _abc123", until); !errors.Is(err, ErrSpent) {
		t.Fatalf("B took a proof A spent: %v", err)
	}
	if err := sa.Use(ctx, "saml", "https://idp.example.com _abc123", until); !errors.Is(err, ErrSpent) {
		t.Fatalf("A took its own proof twice: %v", err)
	}
	// Another kind, or another proof, is its own.
	if err := sb.Use(ctx, "other", "https://idp.example.com _abc123", until); err != nil {
		t.Fatal(err)
	}
	id := SpentID(a.docs.ClusterID(), "saml", "https://idp.example.com _abc123")
	src := o.fake.Source(runtimeIndex(testPrefix), id)
	if src == nil {
		t.Fatal("no spent document")
	}
	for _, v := range src {
		if s, ok := v.(string); ok && strings.Contains(s, "abc123") {
			t.Errorf("the record names the proof: %v", src)
		}
	}

	// At the same moment, exactly one server takes a proof.
	var wg sync.WaitGroup
	results := make([]error, 8)
	for i := range results {
		s := sa
		if i%2 == 1 {
			s = sb
		}
		wg.Go(func() { results[i] = s.Use(ctx, "saml", "race", until) })
	}
	wg.Wait()
	took := 0
	for _, err := range results {
		switch {
		case err == nil:
			took++
		case !errors.Is(err, ErrSpent):
			t.Errorf("unexpected error: %v", err)
		}
	}
	if took != 1 {
		t.Errorf("%d servers took the same proof", took)
	}

	// Ended records are deleted, but only an hour past their end.
	clk.Advance(30 * time.Minute)
	if n, err := sa.Housekeep(ctx); err != nil || n != 0 {
		t.Errorf("housekeeping deleted %d records still kept: %v", n, err)
	}
	clk.Advance(time.Hour)
	if n, err := sa.Housekeep(ctx); err != nil || n != 3 {
		t.Errorf("housekeeping deleted %d: %v", n, err)
	}
}

// When the record cannot be written, the proof is refused: Use returns
// an error that is not ErrSpent, and a later Use can still take it.
func TestSpentFailsClosed(t *testing.T) {
	o, a, _, clk := pair(t)
	ctx := context.Background()
	s := &Spent{Docs: a.docs, Client: o.client, Node: "n_siem-a", Now: clk.Now}
	until := clk.Now().Add(5 * time.Minute)
	o.fake.Block(true)
	err := s.Use(ctx, "saml", "p1", until)
	if err == nil || errors.Is(err, ErrSpent) {
		t.Fatalf("with writes refused: %v", err)
	}
	o.fake.Block(false)
	o.fake.FailN(1, "PUT", "_create", 503, "unavailable_shards_exception")
	if err := s.Use(ctx, "saml", "p1", until); err == nil || errors.Is(err, ErrSpent) {
		t.Fatalf("with the write failing: %v", err)
	}
	if err := s.Use(ctx, "saml", "p1", until); err != nil {
		t.Fatalf("after OpenSearch came back: %v", err)
	}
	// Not a member: refused.
	off := &Spent{Docs: NewDocs(), Client: o.client, Node: "n_x", Now: clk.Now}
	if err := off.Use(ctx, "saml", "p2", until); err == nil {
		t.Error("a server outside the cluster took a proof")
	}
}
