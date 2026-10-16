package shared

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/cluster/ostest"
	"github.com/jrsamsanchez/signalith/internal/store"
)

func TestDocMutateIsSeenByAnotherServer(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	a, _ := e.hub("siem-a")
	b, _ := e.hub("siem-b")
	da := NewDoc[testBody](a, "feeds", "feeds", 1)
	db := NewDoc[testBody](b, "feeds", "feeds", 1)
	changes := 0
	db.OnChange(func(old, new *testBody) {
		changes++
		if changes == 1 && (old != nil || new.Name != "one") {
			t.Errorf("old %+v new %+v", old, new)
		}
	})
	seq, err := da.Mutate(ctx, "sam", func(v *testBody) error { v.Name = "one"; return nil })
	if err != nil || seq < 0 {
		t.Fatalf("mutate: %d %v", seq, err)
	}
	if v, ok := da.Get(); !ok || v.Name != "one" {
		t.Errorf("the writer applies its own write at once: %+v %v", v, ok)
	}
	if _, ok := db.Get(); ok {
		t.Error("b has it before reading")
	}
	cycle(t, b)
	if v, ok := db.Get(); !ok || v.Name != "one" || changes != 1 {
		t.Errorf("b after a cycle: %+v %v, %d changes", v, ok, changes)
	}
	by, at, rev := db.Updated()
	if by != (By{User: "sam", Node: "siem-a"}) || at == "" || rev != 1 || db.ETag() != da.ETag() {
		t.Errorf("updated %+v %q %d, etags %s %s", by, at, rev, db.ETag(), da.ETag())
	}
	// Nothing changed: no reload.
	cycle(t, b)
	if changes != 1 {
		t.Errorf("%d changes", changes)
	}
	src := e.os.Source(testIndex, "feeds")
	if src["mac"] == nil || src["write_id"] == nil || src["body"] != `{"name":"one"}` {
		t.Errorf("stored %v", src)
	}

	// A page edit with a stale ETag names who changed it since.
	etag := db.ETag()
	if _, err := da.Mutate(ctx, "bob", func(v *testBody) error { v.Name = "two"; return nil }); err != nil {
		t.Fatal(err)
	}
	_, err = db.SaveIf(ctx, "sam", &testBody{Name: "three"}, etag)
	var se *StaleError
	if !errors.As(err, &se) || se.By != "bob" || se.Node != "siem-a" {
		t.Fatalf("stale save: %v", err)
	}
	if _, err := db.SaveIf(ctx, "sam", &testBody{Name: "three"}, db.ETag()); err != nil {
		t.Fatalf("save: %v", err)
	}
	cycle(t, a)
	if v, _ := da.Get(); v.Name != "three" {
		t.Errorf("a: %+v", v)
	}
}

// MutateIf changes the revision the page read, even when this server's
// own copy is older: a change made elsewhere in between is kept.
func TestDocMutateIfOnANewerRevision(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	a, _ := e.hub("siem-a")
	b, _ := e.hub("siem-b")
	da := NewDoc[testBody](a, "feeds", "feeds", 1)
	db := NewDoc[testBody](b, "feeds", "feeds", 1)
	if _, err := da.Mutate(ctx, "sam", func(v *testBody) error { v.Items = []string{"one"}; return nil }); err != nil {
		t.Fatal(err)
	}
	cycle(t, b)
	// A changes it again; B has not read that yet, but the page read it
	// from A.
	if _, err := da.Mutate(ctx, "bob", func(v *testBody) error { v.Items = append(v.Items, "two"); return nil }); err != nil {
		t.Fatal(err)
	}
	etag := da.ETag()
	if db.ETag() == etag {
		t.Fatal("b already has the newer revision")
	}
	if _, err := db.MutateIf(ctx, "sam", etag, func(v *testBody) error { v.Name = "edited"; return nil }); err != nil {
		t.Fatal(err)
	}
	cycle(t, a)
	if v, _ := da.Get(); v.Name != "edited" || !slices.Equal(v.Items, []string{"one", "two"}) {
		t.Errorf("a change was lost: %+v", v)
	}
	// An etag older than the stored revision is still refused.
	if _, err := db.MutateIf(ctx, "sam", etag, func(v *testBody) error { return nil }); !errors.As(err, new(*StaleError)) {
		t.Errorf("stale: %v", err)
	}
}

// U1: a forged document and a changed one are refused; the last good copy
// stays, Tamper names it, and an audit event is logged.
func TestDocRefusesForgedAndChanged(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	a, _ := e.hub("siem-a")
	b, logs := e.hub("siem-b")
	da := NewDoc[testBody](a, "retention", "retention", 1)
	db := NewDoc[testBody](b, "retention", "retention", 1)
	if _, err := da.Mutate(ctx, "sam", func(v *testBody) error { v.Name = "keep 90 days"; return nil }); err != nil {
		t.Fatal(err)
	}
	cycle(t, b)
	good := e.os.Source(testIndex, "retention")

	// Body changed, MAC kept.
	changed := e.os.Source(testIndex, "retention")
	changed["body"] = `{"name":"keep 1 day"}`
	e.os.Put(testIndex, "retention", changed)
	cycle(t, b)
	if v, _ := db.Get(); v.Name != "keep 90 days" {
		t.Errorf("changed copy used: %+v", v)
	}
	if !slices.Equal(b.Tamper(), []string{"retention"}) {
		t.Errorf("tamper %v", b.Tamper())
	}
	l := logs.String()
	mustContain(t, "log", l, "config.tamper")
	mustContain(t, "log", l, `"audit":true`)
	mustContain(t, "log", l, `"doc":"retention"`)
	// Logged once, not at every cycle.
	cycle(t, b)
	if n := strings.Count(logs.String(), "config.tamper"); n != 1 {
		t.Errorf("logged %d times", n)
	}
	// A write refuses to build on it.
	if _, err := db.Mutate(ctx, "sam", func(v *testBody) error { return nil }); !errors.As(err, new(*ProblemError)) {
		t.Errorf("mutate over a tampered document: %v", err)
	}

	// Forged: signed with another key.
	other, _ := NewClusterKey()
	e.putSigned(other, "retention", "retention", 1, 9, `{"name":"keep 0 days"}`, nil)
	cycle(t, b)
	if v, _ := db.Get(); v.Name != "keep 90 days" || !slices.Equal(b.Tamper(), []string{"retention"}) {
		t.Errorf("forged copy: %+v, tamper %v", v, b.Tamper())
	}
	mustContain(t, "log", logs.String(), "cluster key "+other.ID())

	// No MAC at all.
	nomac := e.os.Source(testIndex, "retention")
	delete(nomac, "mac")
	e.os.Put(testIndex, "retention", nomac)
	cycle(t, b)
	if v, _ := db.Get(); v.Name != "keep 90 days" {
		t.Errorf("unsigned copy used: %+v", v)
	}

	// The good copy back clears it.
	e.os.Put(testIndex, "retention", good)
	cycle(t, b)
	if len(b.Tamper()) != 0 {
		t.Errorf("tamper after the good copy came back: %v", b.Tamper())
	}

	// Deleted outside Signalith: kept from memory.
	e.os.Delete(testIndex, "retention")
	cycle(t, b)
	if v, ok := db.Get(); !ok || v.Name != "keep 90 days" || !slices.Equal(b.Tamper(), []string{"retention"}) {
		t.Errorf("after a delete: %+v %v, tamper %v", v, ok, b.Tamper())
	}
}

// U2: an older signed revision written back is refused as a rollback,
// until accept-restore.
func TestDocRollbackAndAcceptRestore(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	a, _ := e.hub("siem-a")
	b, _ := e.hub("siem-b")
	da := NewDoc[testBody](a, "users", "users", 1)
	db := NewDoc[testBody](b, "users", "users", 1)
	if _, err := da.Mutate(ctx, "sam", func(v *testBody) error { v.Name = "jlee enabled"; return nil }); err != nil {
		t.Fatal(err)
	}
	old := e.os.Source(testIndex, "users")
	if _, err := da.Mutate(ctx, "sam", func(v *testBody) error { v.Name = "jlee disabled"; return nil }); err != nil {
		t.Fatal(err)
	}
	cycle(t, b)
	e.os.Put(testIndex, "users", old)
	cycle(t, a)
	cycle(t, b)
	for name, d := range map[string]*Doc[testBody]{"a": da, "b": db} {
		if v, _ := d.Get(); v.Name != "jlee disabled" {
			t.Errorf("%s uses the replayed copy: %+v", name, v)
		}
	}
	if !slices.Equal(b.Tamper(), []string{"users"}) || !strings.Contains(b.Problems()[0].Reason, "rolled back to revision 1") {
		t.Errorf("problems %+v", b.Problems())
	}
	if b.MaxRev() != 2 {
		t.Errorf("max rev %d", b.MaxRev())
	}

	// An admin accepts the restored revisions.
	if err := b.AcceptRestore(ctx, "sam", a.MaxRev()); err != nil {
		t.Fatal(err)
	}
	cycle(t, a)
	for name, h := range map[string]*Hub{"a": a, "b": b} {
		if len(h.Tamper()) != 0 {
			t.Errorf("%s tamper %v", name, h.Tamper())
		}
	}
	for name, d := range map[string]*Doc[testBody]{"a": da, "b": db} {
		if v, _ := d.Get(); v.Name != "jlee enabled" {
			t.Errorf("%s after accept-restore: %+v", name, v)
		}
		if _, _, rev := d.Updated(); rev != 3 {
			t.Errorf("%s rev %d", name, rev)
		}
	}
}

// U4: two servers, 50 concurrent changes each, all kept, revisions
// without gaps.
func TestDocMutateUnderContention(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	a, _ := e.hub("siem-a")
	b, _ := e.hub("siem-b")
	docs := []*Doc[testBody]{NewDoc[testBody](a, "feeds", "feeds", 1), NewDoc[testBody](b, "feeds", "feeds", 1)}
	const each = 50
	var wg sync.WaitGroup
	errs := make(chan error, 2*each)
	for i, d := range docs {
		for n := range each {
			wg.Go(func() {
				_, err := d.Mutate(ctx, "sam", func(v *testBody) error {
					v.Items = append(v.Items, fmt.Sprintf("%d-%d", i, n))
					return nil
				})
				if err != nil {
					errs <- err
				}
			})
		}
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	cycle(t, a)
	cycle(t, b)
	for _, d := range docs {
		v, _ := d.Get()
		if len(v.Items) != 2*each {
			t.Errorf("%d items", len(v.Items))
		}
		if _, _, rev := d.Updated(); rev != 2*each {
			t.Errorf("rev %d", rev)
		}
	}
	src := e.os.Source(testIndex, "feeds")
	if rev, _ := src["rev"].(json.Number).Int64(); rev != 2*each {
		t.Errorf("stored rev %v", src["rev"])
	}
}

// U5: fields this version does not know survive a round trip: in the
// envelope, at the top of the body and in each item of a list.
func TestUnknownFieldsSurvive(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	a, _ := e.hub("siem-a")
	e.putSigned(e.key, "feeds", "feeds", 1, 4,
		`{"name":"x","schedule":{"every":"1h"},"feeds":[{"name":"otx","url":"https://otx.example.com","color":"red"}]}`,
		map[string]any{"origin": "newer"})
	d := NewDoc[testBody](a, "feeds", "feeds", 1)
	cycle(t, a)
	if _, err := d.Mutate(ctx, "sam", func(v *testBody) error {
		v.Name = "y"
		v.Feeds[0].URL = "https://otx2.example.com"
		v.Feeds = append(v.Feeds, testFeed{Name: "abuse", URL: "https://abuse.example.com"})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	src := e.os.Source(testIndex, "feeds")
	if src["origin"] != "newer" || src["rev"].(json.Number).String() != "5" {
		t.Errorf("envelope %v", src)
	}
	var body map[string]any
	if err := json.Unmarshal([]byte(src["body"].(string)), &body); err != nil {
		t.Fatal(err)
	}
	if body["name"] != "y" || body["schedule"].(map[string]any)["every"] != "1h" {
		t.Errorf("body %v", body)
	}
	feeds := body["feeds"].([]any)
	f0, f1 := feeds[0].(map[string]any), feeds[1].(map[string]any)
	if f0["color"] != "red" || f0["url"] != "https://otx2.example.com" || f1["color"] != nil || len(feeds) != 2 {
		t.Errorf("feeds %v", feeds)
	}
	// And the copy verifies on another server.
	b, _ := e.hub("siem-b")
	db := NewDoc[testBody](b, "feeds", "feeds", 1)
	cycle(t, b)
	if v, ok := db.Get(); !ok || v.Name != "y" || len(b.Problems()) != 0 {
		t.Errorf("b: %+v %v %v", v, ok, b.Problems())
	}
}

// U6: an unknown kind or a newer format stops that document, which keeps
// its last good copy and is listed in NeedsUpgrade.
func TestNewerDocumentsNeedAnUpgrade(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	a, _ := e.hub("siem-a")
	d := NewDoc[testBody](a, "settings", "settings", 1)
	other := NewDoc[testBody](a, "tls", "tls", 1)
	if _, err := d.Mutate(ctx, "sam", func(v *testBody) error { v.Name = "v1"; return nil }); err != nil {
		t.Fatal(err)
	}
	if _, err := other.Mutate(ctx, "sam", func(v *testBody) error { v.Name = "fine"; return nil }); err != nil {
		t.Fatal(err)
	}
	e.putSigned(e.key, "settings", "settings", 2, 2, `{"name":"v2","layout":"new"}`, nil)
	cycle(t, a)
	if v, _ := d.Get(); v.Name != "v1" {
		t.Errorf("format 2 used: %+v", v)
	}
	if !slices.Equal(a.NeedsUpgrade(), []string{"settings"}) || len(a.Tamper()) != 0 {
		t.Errorf("needs upgrade %v, tamper %v", a.NeedsUpgrade(), a.Tamper())
	}
	if _, err := d.Mutate(ctx, "sam", func(v *testBody) error { return nil }); !errors.As(err, new(*ProblemError)) {
		t.Errorf("a write over a newer format: %v", err)
	}
	// The other document is not affected.
	if _, err := other.Mutate(ctx, "sam", func(v *testBody) error { v.Name = "still fine"; return nil }); err != nil {
		t.Error(err)
	}

	e.putSigned(e.key, "settings", "settings-v9", 1, 3, `{"name":"v9"}`, nil)
	cycle(t, a)
	if v, _ := d.Get(); v.Name != "v1" || !strings.Contains(a.Problems()[0].Reason, `"settings-v9"`) {
		t.Errorf("unknown kind: %+v %+v", v, a.Problems())
	}
	// A MAC of a newer form is not signed itself, so anyone could write
	// one with any body: it is tamper, an audit event, not "upgrade".
	src := e.os.Source(testIndex, "settings")
	src["mac"], src["body"] = "m2:abcdef01:xyz", `{"name":"evil"}`
	e.os.Put(testIndex, "settings", src)
	cycle(t, a)
	if !slices.Equal(a.Tamper(), []string{"settings"}) || len(a.NeedsUpgrade()) != 0 {
		t.Errorf("m2: needs upgrade %v, tamper %v", a.NeedsUpgrade(), a.Tamper())
	}
	if v, _ := d.Get(); v.Name != "v1" {
		t.Errorf("m2 copy used: %+v", v)
	}
}

// U8: the MAC covers values, so OpenSearch writing a source out again
// (with an unsigned field added) does not break it, whatever the body
// holds.
func TestMACSurvivesReserialization(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	a, _ := e.hub("siem-a")
	b, _ := e.hub("siem-b")
	type odd struct {
		Text   string    `json:"text"`
		Floats []float64 `json:"floats"`
		Extra  `json:"-"`
	}
	da := NewDoc[odd](a, "dashboard", "dashboard", 1)
	db := NewDoc[odd](b, "dashboard", "dashboard", 1)
	want := odd{Text: `<script>&"Grüße" ✓ 日本`, Floats: []float64{0.1, 1e21, 3.141592653589793, -0.0000012}}
	if _, err := da.Mutate(ctx, "sam", func(v *odd) error { *v = want; return nil }); err != nil {
		t.Fatal(err)
	}
	e.os.Reserialize(testIndex, "dashboard", "touched_by_update", 1.5)
	for name, h := range map[string]*Hub{"a": a, "b": b} {
		cycle(t, h)
		if len(h.Problems()) != 0 {
			t.Errorf("%s: %+v", name, h.Problems())
		}
	}
	for name, d := range map[string]*Doc[odd]{"a": da, "b": db} {
		v, ok := d.Get()
		if !ok || v.Text != want.Text || !slices.Equal(v.Floats, want.Floats) {
			t.Errorf("%s: %+v", name, v)
		}
	}
	// The unsigned field is kept in the envelope when written again.
	if _, err := db.Mutate(ctx, "sam", func(v *odd) error { v.Text = "x"; return nil }); err != nil {
		t.Fatal(err)
	}
	if src := e.os.Source(testIndex, "dashboard"); src["touched_by_update"] == nil {
		t.Errorf("unsigned field dropped: %v", src)
	}
}

func TestDocCreateOnlyOnce(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	a, _ := e.hub("siem-a")
	b, _ := e.hub("siem-b")
	da := NewDoc[testBody](a, "cluster", "cluster", 1)
	db := NewDoc[testBody](b, "cluster", "cluster", 1)
	if _, err := da.Create(ctx, "signalith", &testBody{Name: "a founds"}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Create(ctx, "signalith", &testBody{Name: "b founds"}); !errors.Is(err, store.ErrExists) {
		t.Fatalf("second create: %v", err)
	}
	cycle(t, b)
	if v, _ := db.Get(); v.Name != "a founds" {
		t.Errorf("b: %+v", v)
	}
}

func TestDocValidate(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	a, _ := e.hub("siem-a")
	d := NewDoc[testBody](a, "retention", "retention", 1)
	d.Validate = func(v *testBody) error {
		if v.Name == "" {
			return errors.New("a name is needed")
		}
		return nil
	}
	if _, err := d.Mutate(ctx, "sam", func(v *testBody) error { return nil }); err == nil || err.Error() != "a name is needed" {
		t.Errorf("mutate: %v", err)
	}
	if _, err := d.Mutate(ctx, "sam", func(v *testBody) error { v.Name = "ok"; return nil }); err != nil {
		t.Fatal(err)
	}
	e.putSigned(e.key, "retention", "retention", 1, 5, `{"name":""}`, nil)
	cycle(t, a)
	if v, _ := d.Get(); v.Name != "ok" || len(a.Problems()) != 1 || a.Problems()[0].Kind != ProblemInvalid {
		t.Errorf("%+v %+v", v, a.Problems())
	}
}

// A copy read while this server wrote the document is left alone, and
// read again at the next cycle rather than taken as seen.
func TestDocCopyLeftDuringOwnWriteIsReadAgain(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	a, _ := e.hub("siem-a")
	b, _ := e.hub("siem-b")
	da := NewDoc[testBody](a, "feeds", "feeds", 1)
	db := NewDoc[testBody](b, "feeds", "feeds", 1)
	if _, err := da.Mutate(ctx, "sam", func(v *testBody) error { v.Name = "v1"; return nil }); err != nil {
		t.Fatal(err)
	}
	cycle(t, a)
	cycle(t, b)
	// Once a's cycle has taken the document's generation: a writes v2,
	// then b writes v3 on top of it, which a's cycle reads.
	var armed atomic.Bool
	armed.Store(true)
	e.os.SetFault(func(method, path string) *ostest.Fault {
		if method != http.MethodGet || !strings.HasSuffix(path, "/_settings") || !armed.Swap(false) {
			return nil
		}
		if _, err := da.Mutate(ctx, "sam", func(v *testBody) error { v.Name = "v2-a"; return nil }); err != nil {
			t.Error(err)
		}
		if _, err := db.Mutate(ctx, "bob", func(v *testBody) error { v.Name = "v3-b"; return nil }); err != nil {
			t.Error(err)
		}
		return nil
	})
	cycle(t, a)
	e.os.SetFault(nil)
	cycle(t, a)
	if v, _ := da.Get(); v.Name != "v3-b" {
		t.Errorf("a keeps %+v", v)
	}
	if _, err := db.Mutate(ctx, "bob", func(v *testBody) error { return nil }); err != nil {
		t.Fatal(err)
	}
}

// After the config index is made again, a copy at the same version as
// the old index's is still read, and an ETag of the old index never
// matches.
func TestDocInAnIndexMadeAgain(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	a, _ := e.hub("siem-a")
	da := NewDoc[testBody](a, "settings", "settings", 1)
	if _, err := da.Mutate(ctx, "sam", func(v *testBody) error { v.Name = "old"; return nil }); err != nil {
		t.Fatal(err)
	}
	cycle(t, a)
	oldTag := da.ETag()
	if err := e.c.Do(ctx, http.MethodDelete, "/"+testIndex, nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := EnsureConfig(ctx, e.c, testPrefix); err != nil {
		t.Fatal(err)
	}
	e.putSigned(e.key, "settings", "settings", 1, 5, `{"name":"new"}`, nil)
	if ver := e.os.Source(testIndex, "settings"); ver == nil {
		t.Fatal("not put")
	}
	cycle(t, a)
	if v, _ := da.Get(); v.Name != "new" {
		t.Errorf("a keeps %+v", v)
	}
	if da.ETag() == oldTag {
		t.Errorf("same ETag %q in both indices", oldTag)
	}
	if _, err := da.SaveIf(ctx, "sam", &testBody{Name: "lost"}, oldTag); !errors.As(err, new(*StaleError)) {
		t.Errorf("save with the old index's ETag: %v", err)
	}
}

// A document refused because this server lacked its key is used once
// the key arrives.
func TestDocUsedOnceItsKeyArrives(t *testing.T) {
	e := newEnv(t)
	a, _ := e.hub("siem-a")
	d := NewDoc[testBody](a, "settings", "settings", 1)
	k2, _ := NewClusterKey()
	e.putSigned(k2, "settings", "settings", 1, 1, `{"name":"rotated"}`, nil)
	a.SetListed([]string{e.key.ID(), k2.ID()})
	cycle(t, a)
	if !slices.Equal(a.KeyMissing(), []string{"settings"}) || len(a.Tamper()) != 0 {
		t.Fatalf("key missing %v, tamper %v", a.KeyMissing(), a.Tamper())
	}
	a.SetKeys(NewKeySet(k2, e.key))
	cycle(t, a)
	if v, ok := d.Get(); !ok || v.Name != "rotated" || len(a.Problems()) != 0 {
		t.Errorf("%+v %v, problems %+v", v, ok, a.Problems())
	}
}

// accept-restore signs again documents only another server follows.
func TestAcceptRestoreOfAnotherServersDocument(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	a, _ := e.hub("siem-a")
	b, _ := e.hub("siem-b")
	da := NewDoc[testBody](a, "nodecfg:n_a", "nodecfg", 1)
	if _, err := da.Mutate(ctx, "sam", func(v *testBody) error { v.Name = "one"; return nil }); err != nil {
		t.Fatal(err)
	}
	old := e.os.Source(testIndex, "nodecfg:n_a")
	if _, err := da.Mutate(ctx, "sam", func(v *testBody) error { v.Name = "two"; return nil }); err != nil {
		t.Fatal(err)
	}
	e.os.Put(testIndex, "nodecfg:n_a", old)
	cycle(t, a)
	if !slices.Equal(a.Tamper(), []string{"nodecfg:n_a"}) {
		t.Fatalf("tamper %v", a.Tamper())
	}
	if err := b.AcceptRestore(ctx, "sam", a.MaxRev()); err != nil {
		t.Fatal(err)
	}
	cycle(t, a)
	if v, _ := da.Get(); len(a.Tamper()) != 0 || v.Name != "one" {
		t.Errorf("a: %+v, tamper %v", v, a.Tamper())
	}
	if _, _, rev := da.Updated(); rev != 3 {
		t.Errorf("rev %d", rev)
	}
}
