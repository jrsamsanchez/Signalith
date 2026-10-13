package cases

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/findings"
	"github.com/jrsamsanchez/signalith/internal/store"
)

func TestCaseFindingsAndEntities(t *testing.T) {
	now := time.Date(2026, 10, 12, 9, 0, 0, 0, time.UTC)
	c := &Case{ID: NewID(now), Title: "Suspicious logons", Severity: "low", Status: findings.StatusNew, Created: now, Updated: now}
	if !strings.HasPrefix(c.ID, "CASE-20261012-") {
		t.Errorf("id = %s", c.ID)
	}
	f := &findings.Finding{ID: "f1", Title: "Brute force from 10.0.0.9", Severity: "medium", Urgency: "high",
		Entities: map[string]any{"src": "10.0.0.9", "user": "bob", "risk_object_type": "system"}}
	added, err := c.AddFinding(f, "ana", now)
	if err != nil || !added {
		t.Fatalf("add = %v %v", added, err)
	}
	if again, _ := c.AddFinding(f, "ana", now); again {
		t.Error("finding added twice")
	}
	if c.Severity != "high" {
		t.Errorf("severity = %s, want the finding's urgency", c.Severity)
	}
	if got := c.EntityValues(); strings.Join(got, ",") != "10.0.0.9,bob" {
		t.Errorf("entities = %v", got)
	}
	if len(c.Entries) != 1 || c.Entries[0].Kind != KindFinding || c.Entries[0].FindingID != "f1" {
		t.Errorf("entries = %+v", c.Entries)
	}
	c.AddEntities(map[string]any{"dest": []any{"web1", "web2"}, "user": "bob", "_raw": "x"})
	if got := c.EntityValues(); strings.Join(got, ",") != "10.0.0.9,bob,web1,web2" {
		t.Errorf("entities after event = %v", got)
	}
	if !c.RemoveFinding("f1", "ana", now) || len(c.Findings) != 0 || len(c.Entries) != 0 {
		t.Errorf("remove left %v %v", c.Findings, c.Entries)
	}
}

func TestApplyAndNotes(t *testing.T) {
	now := time.Now().UTC()
	c := &Case{Title: "x", Severity: "medium", Status: findings.StatusNew}
	st, owner, res := findings.StatusResolved, "ana", "Password spray, blocked at the firewall"
	u := Update{Status: &st, Owner: &owner, Resolution: &res, Comment: "  checked VPN logs  "}
	if err := u.Validate(); err != nil {
		t.Fatal(err)
	}
	if !c.Apply(u, "ana", now) {
		t.Fatal("no change")
	}
	if c.Status != st || c.Owner != "ana" || c.Resolution != res {
		t.Errorf("case = %+v", c)
	}
	if len(c.Entries) != 1 || c.Entries[0].Text != "checked VPN logs" || c.Entries[0].ID == "" {
		t.Errorf("note = %+v", c.Entries)
	}
	if c.Apply(Update{Status: &st}, "ana", now) {
		t.Error("same status counted as a change")
	}
	if err := c.RemoveEntry(c.Entries[0].ID, "ana", now); err != nil || len(c.Entries) != 0 {
		t.Errorf("remove entry = %v", err)
	}
	if err := c.RemoveEntry("nope", "ana", now); err != ErrEntryNotFound {
		t.Errorf("remove unknown = %v", err)
	}
	bad := "urgent"
	if (Update{Severity: &bad}).Validate() == nil {
		t.Error("bad severity accepted")
	}
	empty := " "
	if (Update{Title: &empty}).Validate() == nil {
		t.Error("empty title accepted")
	}
}

func TestTrimEvent(t *testing.T) {
	ev := map[string]any{"user": "bob", "_raw": strings.Repeat("x", MaxEventBytes)}
	out, err := TrimEvent(ev)
	if err != nil || out["_raw"] != nil || out["user"] != "bob" {
		t.Errorf("trim = %v %v", out, err)
	}
	if _, err := TrimEvent(map[string]any{"a": strings.Repeat("x", MaxEventBytes)}); err == nil {
		t.Error("huge event accepted")
	}
}

func TestMemorySearch(t *testing.T) {
	ctx := context.Background()
	m := NewMemory()
	t0 := time.Now().UTC()
	a := &Case{ID: "A", Title: "Phishing wave", Status: findings.StatusNew, Updated: t0, Findings: []string{"f1"},
		Entities: []Entity{{"user", "bob"}}, Entries: []Entry{{ID: "e", Kind: KindNote}}}
	b := &Case{ID: "B", Title: "Malware on web1", Status: findings.StatusClosed, Owner: "ana", Updated: t0.Add(time.Minute)}
	_ = m.Create(ctx, a)
	_ = m.Create(ctx, b)
	list, total, _ := m.Search(ctx, Filter{})
	if total != 2 || list[0].ID != "B" || list[1].Entries != nil {
		t.Errorf("all = %d %v", total, list)
	}
	for _, tc := range []struct {
		f    Filter
		want string
	}{
		{Filter{Status: OpenStatuses}, "A"},
		{Filter{Owner: "ana"}, "B"},
		{Filter{Text: "BOB"}, "A"},
		{Filter{Text: "web1"}, "B"},
		{Filter{FindingID: "f1"}, "A"},
	} {
		list, _, _ := m.Search(ctx, tc.f)
		if len(list) != 1 || list[0].ID != tc.want {
			t.Errorf("%+v = %v", tc.f, list)
		}
	}
	if _, err := m.Get(ctx, "nope"); err != ErrNotFound {
		t.Errorf("get unknown = %v", err)
	}
}

func TestNewIDsAreLongAndRandom(t *testing.T) {
	now := time.Now()
	seen := map[string]bool{}
	for i := 0; i < 1000; i++ {
		id := NewID(now)
		if len(id) != len("CASE-20261012-")+16 || seen[id] {
			t.Fatalf("id %q (seen before: %v)", id, seen[id])
		}
		seen[id] = true
	}
}

// fakeDoer records requests and answers like OpenSearch.
type fakeDoer struct {
	paths []string
	err   error
}

func (f *fakeDoer) Do(_ context.Context, method, path string, _ any, _ any) error {
	f.paths = append(f.paths, method+" "+path)
	return f.err
}

func TestCreateNeverReplacesACase(t *testing.T) {
	ctx := context.Background()
	m := NewMemory()
	a := &Case{ID: "CASE-1", Title: "first"}
	if err := m.Create(ctx, a); err != nil {
		t.Fatal(err)
	}
	if err := m.Create(ctx, &Case{ID: "CASE-1", Title: "second"}); !errors.Is(err, ErrExists) {
		t.Fatalf("second create: %v", err)
	}
	if got, _ := m.Get(ctx, "CASE-1"); got.Title != "first" {
		t.Errorf("case replaced: %q", got.Title)
	}

	// OpenSearch: create only if new, and a 409 means the ID is taken.
	d := &fakeDoer{}
	os := NewOpenSearch(d, "signalith")
	if err := os.Create(ctx, a); err != nil {
		t.Fatal(err)
	}
	if err := os.Save(ctx, a); err != nil {
		t.Fatal(err)
	}
	if strings.Join(d.paths, "; ") != "PUT /signalith_cases/_create/CASE-1?refresh=wait_for; PUT /signalith_cases/_doc/CASE-1?refresh=wait_for" {
		t.Errorf("requests %v", d.paths)
	}
	d.err = &store.Error{Status: 409, Body: `{"error":{"type":"version_conflict_engine_exception"}}`}
	if err := os.Create(ctx, a); !errors.Is(err, ErrExists) {
		t.Errorf("conflict: %v", err)
	}
}

func TestFileHashIsAnEntity(t *testing.T) {
	c := &Case{}
	h := strings.Repeat("ab", 32)
	c.AddEntities(map[string]any{"file_sha256": h, "file_path": `C:\x.exe`, "dest": "ws-fin-07"})
	if got := c.EntityValues(); strings.Join(got, ",") != h+",ws-fin-07" {
		t.Errorf("entities = %v", got)
	}
}

// TestSampleFilterNeverMeansAll: a search for sample cases with an empty
// load ID finds none, in memory and in OpenSearch, so a caller that lost
// the ID cannot reach (and delete) every case by mistake.
func TestSampleFilterNeverMeansAll(t *testing.T) {
	ctx := context.Background()
	m := NewMemory()
	t0 := time.Now().UTC()
	for _, c := range []*Case{
		{ID: "real", Title: "Real investigation", Status: findings.StatusNew, Updated: t0},
		{ID: "sample", Title: "Sample case", Status: findings.StatusNew, Updated: t0, Sample: "sample-20261013-120000"},
	} {
		if err := m.Create(ctx, c); err != nil {
			t.Fatal(err)
		}
	}
	empty, id := "", "sample-20261013-120000"
	for _, tc := range []struct {
		flt  Filter
		want int
	}{
		{Filter{}, 2},
		{Filter{Sample: &empty}, 0},
		{Filter{Sample: &id}, 1},
	} {
		got, total, err := m.Search(ctx, tc.flt)
		if err != nil || len(got) != tc.want || total != tc.want {
			t.Errorf("memory search %+v = %d (%d), %v; want %d", tc.flt, len(got), total, err, tc.want)
		}
	}
	if q := filterQuery(Filter{Sample: &empty, Owner: "ana"}); q["match_none"] == nil {
		t.Errorf("an empty sample ID searches with %v, want match_none", q)
	}
	if q := filterQuery(Filter{Sample: &id}); !strings.Contains(fmt.Sprint(q), "sample:"+id) {
		t.Errorf("a sample ID searches with %v", q)
	}
}
