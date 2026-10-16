package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/cluster/ostest"
	"github.com/jrsamsanchez/signalith/internal/store"
)

var (
	testKey  = []byte("0123456789abcdef0123456789abcdef")
	otherKey = []byte("fedcba9876543210fedcba9876543210")
)

func testKeys(kid string) []byte {
	switch kid {
	case "k1":
		return testKey
	case "k2":
		return otherKey
	}
	return nil
}

func keySource(kid string) func() (string, []byte) {
	return func() (string, []byte) { return kid, testKeys(kid) }
}

// asStored returns the events as Verify reads them back from OpenSearch:
// the documents the sink writes, decoded.
func asStored(t *testing.T, evs []Event) []Hit {
	t.Helper()
	var out []Hit
	for _, ev := range evs {
		b, err := json.Marshal(ev.doc())
		if err != nil {
			t.Fatal(err)
		}
		var back Event
		if err := json.Unmarshal(b, &back); err != nil {
			t.Fatal(err)
		}
		out = append(out, Hit{Event: back, ID: ev.ID(), Index: IndexName("p", ev.Time)})
	}
	return out
}

func addN(s *Sink, n int, from int) {
	for i := range n {
		s.Add(Event{Time: time.Now(), Action: "x.y", Message: fmt.Sprint("event ", from+i), Fields: map[string]string{"i": fmt.Sprint(from + i)}})
	}
}

func wantReport(t *testing.T, r *Report, ok, problems int64) {
	t.Helper()
	if r.OK != ok || int64(len(r.Problems)) != problems {
		b, _ := json.MarshalIndent(r, "", "  ")
		t.Fatalf("report: want %d OK and %d problems:\n%s", ok, problems, b)
	}
}

func TestChainLinksAndSignsEachRecord(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "spool")
	s := newTestSink(t, SinkOptions{Dir: dir, Server: "a", NodeID: "n1"})
	s.SetKeySource(keySource("k1"))
	// A message that is not valid UTF-8 is signed as it is stored.
	s.Add(Event{Time: time.Now(), Action: "x.y", Message: "bad \xff utf-8 <&>"})
	addN(s, 4, 1)
	s.Close()
	evs := spooled(t, dir)
	if len(evs) != 5 {
		t.Fatalf("spooled %d", len(evs))
	}
	for i, ev := range evs {
		if ev.Seq != int64(i+1) || ev.Chain != evs[0].Chain || ev.KID != "k1" || len(ev.MAC) != 64 {
			t.Errorf("event %d: %+v", i, ev)
		}
		if i == 0 && (!ev.ChainStart || ev.Prev != "") || i > 0 && (ev.ChainStart || ev.Prev != evs[i-1].Hash()) {
			t.Errorf("event %d does not link: %+v", i, ev)
		}
		if !ev.checkMAC(testKey) || ev.checkMAC(otherKey) {
			t.Errorf("event %d: MAC does not check out", i)
		}
	}
	r := Check(asStored(t, evs), VerifyQuery{}, testKeys)
	wantReport(t, r, 5, 0)
	if r.Restarts != 1 || r.Records != 5 || len(r.Servers) != 1 || r.Servers[0].Server != "a" || r.Servers[0].Chains != 1 || r.Tampered() {
		t.Errorf("report %+v", r)
	}
	// Without the key, the records still link, and nothing is wrong.
	r = Check(asStored(t, evs), VerifyQuery{}, nil)
	if r.UnknownKey != 5 || r.OK != 0 || r.Tampered() {
		t.Errorf("without the key: %+v", r)
	}
}

func TestChainContinuesAfterARestart(t *testing.T) {
	fake := ostest.New(t)
	c := store.New(store.Config{URL: fake.URL})
	dir := filepath.Join(t.TempDir(), "spool")

	// Spooled, not yet written: the head comes from the spool.
	first := NewSink(SinkOptions{Dir: dir, NodeID: "n1"})
	addN(first, 3, 0)
	first.Close()
	if err := os.Remove(filepath.Join(dir, headFile)); err != nil {
		t.Fatal(err)
	}
	second := newTestSink(t, SinkOptions{Dir: dir, NodeID: "n1", Client: c, Prefix: testPrefix})
	addN(second, 2, 3)
	if err := second.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	second.Close()
	if segs := segments(t, dir); len(segs) != 0 {
		t.Fatalf("segments left %v", segs)
	}

	// All written and the spool empty: the head comes from its file.
	third := newTestSink(t, SinkOptions{Dir: dir, NodeID: "n1", Client: c, Prefix: testPrefix})
	addN(third, 2, 5)
	if err := third.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	r, err := Verify(context.Background(), c, testPrefix, VerifyQuery{}, testKeys)
	if err != nil {
		t.Fatal(err)
	}
	if r.Records != 7 || r.Restarts != 1 || r.Unsigned != 7 || r.Tampered() || len(r.Problems) != 0 {
		t.Fatalf("report %+v", r)
	}

	// A server that lost its spool folder starts a new chain, which is a
	// restart, not a removal.
	third.Close()
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	fourth := newTestSink(t, SinkOptions{Dir: dir, NodeID: "n1", Client: c, Prefix: testPrefix})
	addN(fourth, 2, 7)
	if err := fourth.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	r, err = Verify(context.Background(), c, testPrefix, VerifyQuery{}, testKeys)
	if err != nil {
		t.Fatal(err)
	}
	if r.Records != 9 || r.Restarts != 2 || r.Tampered() || r.Servers[0].Chains != 2 {
		t.Fatalf("report after the spool was lost %+v", r)
	}
}

func TestSpoolDropsAreToldFromRemovals(t *testing.T) {
	fake := ostest.New(t)
	c := store.New(store.Config{URL: fake.URL})
	dir := filepath.Join(t.TempDir(), "spool")
	s := newTestSink(t, SinkOptions{Dir: dir, MaxBytes: 4000, NodeID: "n1", Prefix: testPrefix})
	s.SetKeySource(keySource("k1"))
	s.segMax = 600
	addN(s, 30, 0)
	if s.Stats().Lost == 0 {
		t.Fatal("nothing was dropped")
	}
	s.SetTarget(c, testPrefix)
	if err := s.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	r, err := Verify(context.Background(), c, testPrefix, VerifyQuery{}, testKeys)
	if err != nil {
		t.Fatal(err)
	}
	if r.Dropped != s.Stats().Lost || r.Missing != 0 || r.Tampered() || r.Continued != 0 || r.Restarts != 1 {
		t.Fatalf("report %+v, lost %d", r, s.Stats().Lost)
	}
}

func TestRefusedRecordsAreNamed(t *testing.T) {
	fake := ostest.New(t)
	c := store.New(store.Config{URL: fake.URL})
	s := newTestSink(t, SinkOptions{NodeID: "n1", Client: c, Prefix: testPrefix})
	s.SetKeySource(keySource("k1"))
	addN(s, 2, 0)
	// One OpenSearch cannot take, then more.
	s.Add(Event{Time: time.Now(), Message: "refused"})
	addN(s, 2, 3)
	refuse := true
	bulker := bulkFunc(func(ctx context.Context, docs []store.IndexedDoc) ([]store.BulkItemError, error) {
		errs, err := c.Bulk(ctx, docs)
		if refuse {
			for i, d := range docs {
				if d.Doc["message"] == "refused" {
					refuse = false
					_ = c.Do(ctx, "DELETE", "/"+d.Index+"/_doc/"+d.ID, nil, nil)
					errs = append(errs, store.BulkItemError{Index: d.Index, Reason: "mapper_parsing_exception", Pos: i, Type: "mapper_parsing_exception", Status: 400})
				}
			}
		}
		return errs, err
	})
	s.SetTarget(bulker, testPrefix)
	for range 2 {
		if err := s.Flush(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	r, err := Verify(context.Background(), c, testPrefix, VerifyQuery{}, testKeys)
	if err != nil {
		t.Fatal(err)
	}
	if r.Dropped != 1 || r.Records != 5 || r.Tampered() {
		t.Fatalf("report %+v", r)
	}
}

type bulkFunc func(ctx context.Context, docs []store.IndexedDoc) ([]store.BulkItemError, error)

func (f bulkFunc) Bulk(ctx context.Context, docs []store.IndexedDoc) ([]store.BulkItemError, error) {
	return f(ctx, docs)
}

// chain returns n records of one server, signed with k1 unless unsigned.
func chain(t *testing.T, n int, unsigned bool) []Event {
	t.Helper()
	s := newTestSink(t, SinkOptions{Server: "a", NodeID: "n1"})
	if !unsigned {
		s.SetKeySource(keySource("k1"))
	}
	addN(s, n, 0)
	s.Close()
	return spooled(t, s.dir)
}

func TestEditsAndRemovalsShow(t *testing.T) {
	t.Run("edited", func(t *testing.T) {
		hits := asStored(t, chain(t, 5, false))
		hits[2].Message = "nothing happened"
		r := Check(hits, VerifyQuery{}, testKeys)
		wantReport(t, r, 4, 1)
		if r.Edited != 1 || r.Broken != 0 || r.Problems[0].Kind != ProblemEdited || r.Problems[0].Seq != 3 || r.Problems[0].ID == "" {
			t.Errorf("report %+v", r)
		}
	})
	t.Run("edited field", func(t *testing.T) {
		hits := asStored(t, chain(t, 3, false))
		hits[1].Fields["i"] = "9"
		if r := Check(hits, VerifyQuery{}, testKeys); r.Edited != 1 {
			t.Errorf("report %+v", r)
		}
	})
	t.Run("edited unsigned", func(t *testing.T) {
		hits := asStored(t, chain(t, 5, true))
		hits[2].User = "mallory"
		r := Check(hits, VerifyQuery{}, testKeys)
		if r.Unsigned != 5 || r.Broken != 1 || r.Problems[0].Seq != 4 || !r.Tampered() {
			t.Errorf("report %+v", r)
		}
	})
	t.Run("signed with another key", func(t *testing.T) {
		hits := asStored(t, chain(t, 3, false))
		hits[1].KID = "k2"
		if r := Check(hits, VerifyQuery{}, testKeys); r.Edited != 1 {
			t.Errorf("report %+v", r)
		}
	})
	t.Run("removed", func(t *testing.T) {
		hits := asStored(t, chain(t, 6, false))
		hits = append(hits[:2], hits[4:]...)
		r := Check(hits, VerifyQuery{}, testKeys)
		wantReport(t, r, 3, 1)
		if r.Missing != 2 || r.Problems[0].Kind != ProblemMissing || r.Problems[0].Seq != 5 {
			t.Errorf("report %+v", r)
		}
	})
	t.Run("put in", func(t *testing.T) {
		evs := chain(t, 4, false)
		fake := evs[2]
		fake.Message = "made up"
		fake.Time = fake.Time.Add(time.Millisecond)
		hits := asStored(t, append(evs, fake))
		r := Check(hits, VerifyQuery{}, testKeys)
		if r.Edited != 1 || !r.Tampered() {
			t.Errorf("report %+v", r)
		}
	})
	t.Run("restart in the middle", func(t *testing.T) {
		hits := asStored(t, chain(t, 4, true))
		hits[2].ChainStart, hits[2].Prev = true, ""
		if r := Check(hits, VerifyQuery{}, testKeys); r.Broken != 1 {
			t.Errorf("report %+v", r)
		}
	})
}

func TestCheckpointShowsTheEndRemoved(t *testing.T) {
	evs := chain(t, 5, false)
	cp := CheckpointEvent([]Event{evs[4]})
	cp.Server, cp.NodeID, cp.Time, cp.Chain, cp.Seq = "b", "n2", evs[4].Time.Add(time.Second), "c2", 1
	cp.ChainStart, cp.KID = true, "k1"
	cp.MAC = cp.sign(testKey)
	all := append(append([]Event{}, evs...), cp)

	r := Check(asStored(t, all), VerifyQuery{}, testKeys)
	if r.Checkpoints != 1 || r.Tampered() {
		t.Fatalf("intact: %+v", r)
	}
	// The last two records of n1 removed: nothing after them misses them,
	// but the checkpoint saw the last one.
	cut := append(append([]Event{}, evs[:3]...), cp)
	r = Check(asStored(t, cut), VerifyQuery{}, testKeys)
	if r.Truncated != 1 || !r.Tampered() || r.Problems[0].Kind != ProblemTruncated || r.Problems[0].NodeID != "n1" {
		t.Fatalf("cut: %+v", r)
	}
	// Checking server a alone still uses b's checkpoint.
	r = Check(asStored(t, cut), VerifyQuery{Server: "a"}, testKeys)
	if r.Truncated != 1 || r.Records != 3 || len(r.Servers) != 1 {
		t.Fatalf("server a: %+v", r)
	}
	// And server b alone does not judge a's records.
	if r = Check(asStored(t, cut), VerifyQuery{Server: "b"}, testKeys); r.Tampered() || r.Records != 1 {
		t.Fatalf("server b: %+v", r)
	}
	// The record the checkpoint saw, changed and its MAC removed, shows.
	hits := asStored(t, all)
	hits[4].MAC, hits[4].Message = "", "changed"
	if r = Check(hits, VerifyQuery{}, testKeys); r.Stripped != 1 || !r.Tampered() {
		t.Fatalf("changed: %+v", r)
	}
	// An unsigned checkpoint, which anyone could write, is not believed:
	// it neither hides the end removed nor makes up one.
	forged := cp
	forged.KID, forged.MAC = "", ""
	forged.Fields = map[string]string{"servers": "1", headPrefix + "n1": headValue(evs[2])}
	if r = Check(asStored(t, append(append([]Event{}, evs[:3]...), forged)), VerifyQuery{}, testKeys); r.Truncated != 0 || r.Tampered() {
		t.Fatalf("unsigned checkpoint: %+v", r)
	}
	ahead := evs[4]
	ahead.Seq = 9
	forged.Fields = map[string]string{"servers": "1", headPrefix + "n1": headValue(ahead)}
	if r = Check(asStored(t, append(append([]Event{}, evs...), forged)), VerifyQuery{}, testKeys); r.Truncated != 0 {
		t.Fatalf("made-up end: %+v", r)
	}
}

func TestKeyRotationKeepsRecordsVerifying(t *testing.T) {
	s := newTestSink(t, SinkOptions{NodeID: "n1"})
	s.SetKeySource(keySource("k1"))
	addN(s, 2, 0)
	s.SetKeySource(keySource("k2"))
	addN(s, 2, 2)
	s.SetKeySource(nil)
	addN(s, 1, 4)
	s.Close()
	evs := spooled(t, s.dir)
	if evs[0].KID != "k1" || evs[3].KID != "k2" || evs[4].KID != "" {
		t.Fatalf("kids %q %q %q", evs[0].KID, evs[3].KID, evs[4].KID)
	}
	// A server that signed keeps signing: an unsigned record after its
	// signed ones had its MAC removed, or was put in.
	r := Check(asStored(t, evs), VerifyQuery{}, testKeys)
	if r.OK != 4 || r.Unsigned != 0 || r.Stripped != 1 || !r.Tampered() {
		t.Errorf("report %+v", r)
	}
	evs = evs[:4]
	// A server that never held k1 cannot check those, and says so.
	r = Check(asStored(t, evs), VerifyQuery{}, func(kid string) []byte {
		if kid == "k2" {
			return otherKey
		}
		return nil
	})
	if r.OK != 2 || r.UnknownKey != 2 || r.Tampered() {
		t.Errorf("without k1: %+v", r)
	}
	// Records signed with a key this server does not hold after ones it
	// can check were signed again by someone else.
	r = Check(asStored(t, evs), VerifyQuery{}, func(kid string) []byte {
		if kid == "k1" {
			return testKey
		}
		return nil
	})
	if r.OK != 2 || r.Stripped != 2 || !r.Tampered() {
		t.Errorf("without k2: %+v", r)
	}
}

func TestVerifyRangeAndLimit(t *testing.T) {
	fake := ostest.New(t)
	c := store.New(store.Config{URL: fake.URL})
	base := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	s := newTestSink(t, SinkOptions{NodeID: "n1", Server: "a", Client: c, Prefix: testPrefix,
		Now: func() time.Time { return base }})
	s.SetKeySource(keySource("k1"))
	for i := range 10 {
		s.Add(Event{Time: base.Add(time.Duration(i) * time.Hour), Message: fmt.Sprint(i)})
	}
	if err := s.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	r, err := Verify(context.Background(), c, testPrefix, VerifyQuery{From: base.Add(3 * time.Hour), To: base.Add(6 * time.Hour)}, testKeys)
	if err != nil {
		t.Fatal(err)
	}
	if r.Records != 3 || r.OK != 3 || r.Continued != 1 || r.Tampered() {
		t.Fatalf("range: %+v", r)
	}
	r, err = Verify(context.Background(), c, testPrefix, VerifyQuery{Limit: 4}, testKeys)
	if err != nil {
		t.Fatal(err)
	}
	// The range read ends a margin before the last record read.
	if !r.Limited || r.Records != 3 || r.Tampered() {
		t.Fatalf("limit: %+v", r)
	}
	if r, err = Verify(context.Background(), c, "nothing", VerifyQuery{}, testKeys); err != nil || r.Records != 0 {
		t.Fatalf("no index: %+v, %v", r, err)
	}
	if !strings.HasPrefix(CheckpointEvent(nil).Message, "audit.checkpoint:") {
		t.Error("checkpoint message")
	}
}

func TestHeadsNameEachServersLatestRecord(t *testing.T) {
	evs := chain(t, 3, false)
	src := func(ev Event) map[string]any {
		var m map[string]any
		b, _ := json.Marshal(ev.doc())
		_ = json.Unmarshal(b, &m)
		return m
	}
	bucket := func(evs ...Event) any {
		var hits []any
		for _, ev := range evs {
			hits = append(hits, map[string]any{"_source": src(ev)})
		}
		return map[string]any{"key": evs[0].NodeID, "latest": map[string]any{"hits": map[string]any{"hits": hits}}}
	}
	legacy := Event{Time: time.Now(), NodeID: "old", Message: "before chains", Seq: 4}
	// A record put in after the latest, unsigned, is passed over.
	planted := evs[2]
	planted.Seq, planted.MAC, planted.Message = 4, "", "planted"
	var body map[string]any
	st := stubSearcher{body: &body, res: map[string]any{"aggregations": map[string]any{"nodes": map[string]any{
		"buckets": []any{bucket(planted, evs[2]), bucket(legacy)}}}}}
	heads, err := Heads(context.Background(), st, testPrefix, testKeys)
	if err != nil || len(heads) != 1 || heads[0].Seq != 3 {
		t.Fatalf("heads %+v, err %v", heads, err)
	}
	if !strings.Contains(fmt.Sprint(body), "top_hits") {
		t.Errorf("query %v", body)
	}
	cp := CheckpointEvent(heads)
	if cp.Action != ActionCheckpoint || cp.Fields["head.n1"] != headValue(evs[2]) || cp.Fields["servers"] != "1" {
		t.Errorf("checkpoint %+v", cp)
	}
	refs := parseHeads(&Hit{Event: cp})
	if len(refs) != 1 || refs[0].seq != 3 || refs[0].hash != evs[2].Hash() || refs[0].server != "a" || !refs[0].at.Equal(evs[2].Time.Truncate(time.Millisecond)) {
		t.Errorf("refs %+v", refs)
	}
}

func TestRecordsTheSpoolCouldNotTakeAreNamed(t *testing.T) {
	fake := ostest.New(t)
	c := store.New(store.Config{URL: fake.URL})
	dir := filepath.Join(t.TempDir(), "spool")
	s := newTestSink(t, SinkOptions{Dir: dir, NodeID: "n1", Client: c, Prefix: testPrefix})
	s.SetKeySource(keySource("k1"))
	addN(s, 2, 0)
	if err := s.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	// A file where the spool folder was: nothing can be spooled.
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dir, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	addN(s, 2, 2)
	if err := os.Remove(dir); err != nil {
		t.Fatal(err)
	}
	addN(s, 1, 4)
	if err := s.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	r, err := Verify(context.Background(), c, testPrefix, VerifyQuery{}, testKeys)
	if err != nil {
		t.Fatal(err)
	}
	if r.Missing != 0 || r.Dropped != s.Stats().Lost || r.Dropped < 2 || r.Tampered() {
		t.Fatalf("report %+v, lost %d", r, s.Stats().Lost)
	}
}

func TestCoversCountsEachNumberOnce(t *testing.T) {
	runs := []lostRange{{from: 3, to: 6}, {from: 5, to: 9, hash: "h"}, {from: 20, to: 30}}
	if n, last := covers(runs, 4, 9); n != 6 || last == nil || last.hash != "h" {
		t.Errorf("covers = %d, %v", n, last)
	}
	if n, last := covers(runs, 10, 19); n != 0 || last != nil {
		t.Errorf("covers = %d, %v", n, last)
	}
}

// relink makes each record of evs from i on follow the one before it
// again, as anyone can: the chain's hash takes no key.
func relink(evs []Event, i int) {
	for ; i < len(evs); i++ {
		evs[i].Prev = evs[i-1].Hash()
	}
}

// Someone who can write to OpenSearch but holds no cluster key cannot
// hide a change by removing MACs, signing with a key of their own,
// naming removed records in an audit.lost record of their own, or
// putting in records.
func TestForgeriesWithoutTheKeyShow(t *testing.T) {
	t.Run("MACs removed and relinked", func(t *testing.T) {
		evs := chain(t, 6, false)
		evs[2].User = "mallory"
		for i := 2; i < 6; i++ {
			evs[i].KID, evs[i].MAC = "", ""
		}
		relink(evs, 3)
		r := Check(asStored(t, evs), VerifyQuery{}, testKeys)
		if !r.Tampered() || r.Stripped != 4 || r.Unsigned != 0 {
			t.Fatalf("report %+v", r)
		}
	})
	t.Run("signed with an unknown key", func(t *testing.T) {
		evs := chain(t, 6, false)
		evs[2].User = "mallory"
		for i := 2; i < 6; i++ {
			evs[i].KID = "k9"
			evs[i].MAC = evs[i].sign([]byte("mallory's own key, 32 bytes long"))
		}
		relink(evs, 3)
		for i := 2; i < 6; i++ {
			evs[i].MAC = evs[i].sign([]byte("mallory's own key, 32 bytes long"))
		}
		r := Check(asStored(t, evs), VerifyQuery{}, testKeys)
		if !r.Tampered() || r.Stripped != 4 || r.UnknownKey != 0 {
			t.Fatalf("report %+v", r)
		}
	})
	t.Run("removal named in a forged audit.lost record", func(t *testing.T) {
		evs := chain(t, 6, false)
		f := lostEvent(lostRange{chain: evs[0].Chain, from: 3, to: 4, hash: evs[3].Hash(), n: 2, reason: "the spool was full"})
		f.Time, f.Server, f.NodeID, f.Chain, f.Seq, f.ChainStart = evs[5].Time, "a", "n1", "forged", 1, true
		kept := append(append(append([]Event{}, evs[:2]...), evs[4:]...), f)
		r := Check(asStored(t, kept), VerifyQuery{}, testKeys)
		if !r.Tampered() || r.Missing != 2 || r.Dropped != 0 {
			t.Fatalf("report %+v", r)
		}
		// Backdated before the server signed anything, it is still not
		// believed between signed records.
		kept[len(kept)-1].Time = evs[0].Time.Add(-time.Hour)
		if r = Check(asStored(t, kept), VerifyQuery{}, testKeys); r.Missing != 2 || r.Dropped != 0 || r.Unverifiable != 0 {
			t.Fatalf("backdated: %+v", r)
		}
	})
	t.Run("record put in", func(t *testing.T) {
		evs := chain(t, 3, false)
		fake := Event{Time: evs[2].Time.Add(2 * time.Minute), Server: "a", NodeID: "n1", User: "bob", Action: "users.delete", Message: "deleted alice"}
		r := Check(asStored(t, append(evs, fake)), VerifyQuery{}, testKeys)
		if !r.Tampered() || r.Stripped != 1 || r.Problems[0].Kind != ProblemStripped {
			t.Fatalf("report %+v", r)
		}
	})
	t.Run("unsigned before signing is not tampering", func(t *testing.T) {
		s := newTestSink(t, SinkOptions{Server: "a", NodeID: "n1"})
		addN(s, 2, 0)
		s.SetKeySource(keySource("k1"))
		addN(s, 2, 2)
		s.Close()
		r := Check(asStored(t, spooled(t, s.dir)), VerifyQuery{}, testKeys)
		if r.Tampered() || r.Unsigned != 2 || r.OK != 2 {
			t.Fatalf("report %+v", r)
		}
	})
	// When the check reads no signed record of a server at all, the time
	// the cluster document says it started signing still holds.
	since := func(evs []Event) VerifyQuery {
		return VerifyQuery{SignedSince: map[string]time.Time{"n1": evs[0].Time.Add(-2 * time.Minute)}}
	}
	t.Run("every MAC of a server removed", func(t *testing.T) {
		evs := chain(t, 6, false)
		evs[2].User = "mallory"
		for i := range evs {
			evs[i].KID, evs[i].MAC = "", ""
		}
		relink(evs, 1)
		if r := Check(asStored(t, evs), VerifyQuery{}, testKeys); r.Tampered() {
			t.Fatalf("without the cluster document's word it cannot tell: %+v", r)
		}
		r := Check(asStored(t, evs), since(evs), testKeys)
		if !r.Tampered() || r.Stripped != 6 || r.Unsigned != 0 {
			t.Fatalf("report %+v", r)
		}
		// A server holding no key checks no MAC, and says nothing of them.
		if r := Check(asStored(t, evs), since(evs), nil); r.Tampered() || r.Unsigned != 6 {
			t.Fatalf("no key: %+v", r)
		}
	})
	t.Run("every record signed again with another key", func(t *testing.T) {
		evs := chain(t, 6, false)
		evs[2].User = "mallory"
		for i := range evs {
			evs[i].KID = "k9"
		}
		relink(evs, 1)
		for i := range evs {
			evs[i].KID = "k9"
			evs[i].MAC = evs[i].sign([]byte("mallory's own key, 32 bytes long"))
		}
		r := Check(asStored(t, evs), since(evs), testKeys)
		if !r.Tampered() || r.Stripped != 6 || r.UnknownKey != 0 {
			t.Fatalf("report %+v", r)
		}
	})
	t.Run("MACs removed in the range checked", func(t *testing.T) {
		base := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
		s := newTestSink(t, SinkOptions{Server: "a", NodeID: "n1", Now: func() time.Time { return base }})
		s.SetKeySource(keySource("k1"))
		for i := range 6 {
			s.Add(Event{Time: base.Add(time.Duration(i) * time.Hour), Action: "x.y", Message: fmt.Sprint(i)})
		}
		s.Close()
		evs := spooled(t, s.dir)
		evs[2].User = "mallory"
		for i := 2; i < 4; i++ {
			evs[i].KID, evs[i].MAC = "", ""
		}
		relink(evs, 3)
		var in []Hit
		for _, h := range asStored(t, evs) {
			// What Verify reads of the range: the records next to it the
			// attacker left signed are an hour away.
			if !h.Time.Before(base.Add(2*time.Hour)) && h.Time.Before(base.Add(4*time.Hour)) {
				in = append(in, h)
			}
		}
		q := VerifyQuery{From: base.Add(2 * time.Hour), To: base.Add(4 * time.Hour), SignedSince: map[string]time.Time{"n1": base}}
		r := Check(in, q, testKeys)
		if !r.Tampered() || r.Stripped != 2 {
			t.Fatalf("report %+v", r)
		}
	})
	t.Run("unsigned drops where nothing is signed", func(t *testing.T) {
		evs := chain(t, 5, true)
		f := lostEvent(lostRange{chain: evs[0].Chain, from: 3, to: 3, hash: evs[2].Hash(), n: 1, reason: "the spool was full"})
		f.Time, f.Server, f.NodeID, f.Chain, f.Seq, f.ChainStart = evs[4].Time, "a", "n1", "other", 1, true
		kept := append(append(append([]Event{}, evs[:2]...), evs[3:]...), f)
		r := Check(asStored(t, kept), VerifyQuery{}, testKeys)
		if r.Tampered() || r.Unverifiable != 1 || r.Dropped != 0 {
			t.Fatalf("report %+v", r)
		}
	})
}
