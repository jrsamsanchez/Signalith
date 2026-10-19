// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package notebooks

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/datamodel"
	"github.com/jrsamsanchez/signalith/internal/intel"
	"github.com/jrsamsanchez/signalith/internal/query"
	"github.com/jrsamsanchez/signalith/internal/search"
)

// Every starter hunt is valid, names real ATT&CK techniques, mixes notes
// with searches, and each search compiles against a known data model.
func TestStarters(t *testing.T) {
	list := Starters()
	if len(list) != 7 {
		t.Fatalf("%d starters", len(list))
	}
	eng := &search.Engine{Intel: intel.NewStore(intel.NewMemory())}
	models := map[string]bool{}
	for _, m := range datamodel.Models {
		models[m.Name] = true
	}
	titles := map[string]bool{}
	for _, n := range list {
		if !strings.HasPrefix(n.ID, StarterPrefix) || !n.Starter || n.Sharing != Read || titles[n.Title] {
			t.Errorf("%s: %+v", n.ID, n)
		}
		titles[n.Title] = true
		if n.Description == "" || len(n.Techniques) == 0 {
			t.Errorf("%s: needs a description and techniques", n.ID)
		}
		if err := n.Validate(); err != nil {
			t.Errorf("%s: %v", n.ID, err)
		}
		notes, searches := 0, 0
		for _, c := range n.Cells {
			if c.Kind == KindMarkdown {
				notes++
				continue
			}
			searches++
			if c.Title == "" {
				t.Errorf("%s: search %s has no title", n.ID, c.ID)
			}
			q, err := query.Parse(c.Query)
			if err != nil {
				t.Errorf("%s / %s: %v", n.ID, c.Title, err)
				continue
			}
			if !models[q.Datamodel] {
				t.Errorf("%s / %s: data model %q", n.ID, c.Title, q.Datamodel)
			}
			if _, err := eng.Compile(q); err != nil {
				t.Errorf("%s / %s: compile: %v", n.ID, c.Title, err)
			}
		}
		if notes == 0 || searches < 2 {
			t.Errorf("%s: %d notes, %d searches", n.ID, notes, searches)
		}
	}
	// Copies are independent of the embedded hunts.
	a, _ := Starter(list[0].ID)
	a.Cells[0].Text = "changed"
	if b, _ := Starter(list[0].ID); b.Cells[0].Text == "changed" {
		t.Error("Starter returned shared cells")
	}
	if _, ok := Starter("starter-nope"); ok {
		t.Error("unknown starter found")
	}
}

func valid() *Notebook {
	n := &Notebook{Title: "Hunt", Owner: "andy", Techniques: []string{"t1059.001", "T1059.001"}, Cells: []Cell{
		{Kind: "markdown", Text: "# Hi\r\nthere", Query: "dropped"},
		{Kind: "search", Title: "Encoded", Query: "datamodel=Endpoint process_name=powershell.exe"},
	}}
	n.Normalize()
	return n
}

func TestNormalizeAndValidate(t *testing.T) {
	n := valid()
	if err := n.Validate(); err != nil {
		t.Fatal(err)
	}
	if n.Sharing != Private || n.TimeRange != "7d" || len(n.Techniques) != 1 || n.Techniques[0] != "T1059.001" {
		t.Errorf("defaults: %+v", n)
	}
	if n.Cells[0].Text != "# Hi\nthere" || n.Cells[0].Query != "" || n.Cells[0].ID == "" || n.Cells[0].ID == n.Cells[1].ID {
		t.Errorf("cells: %+v", n.Cells)
	}

	bad := valid()
	bad.Title = ""
	bad.Sharing = "public"
	bad.TimeRange = "forever"
	bad.Techniques = []string{"T9999", "<script>"}
	bad.Cells = append(bad.Cells, Cell{ID: "x", Kind: "html", Text: "<b>"}, Cell{ID: "y", Kind: "search", Query: "a=1 |"})
	err := bad.Validate()
	ve, ok := err.(*ValidationError)
	if !ok {
		t.Fatalf("err = %v", err)
	}
	for _, want := range []string{"title is required", "sharing must be", "time range", "T9999 is not in the ATT&CK matrix", `"<script>" is not an ATT&CK technique`, "kind must be markdown or search", "cell 4: query:"} {
		if !strings.Contains(strings.Join(ve.Problems, "\n"), want) {
			t.Errorf("no %q in %v", want, ve.Problems)
		}
	}

	big := valid()
	for range MaxSearchCells {
		big.Cells = append(big.Cells, Cell{Kind: KindSearch, Query: "a=1"})
	}
	big.Normalize()
	if err := big.Validate(); err == nil || !strings.Contains(err.Error(), "at most 25 searches") {
		t.Errorf("too many searches: %v", err)
	}
	long := valid()
	long.Cells[0].Text = strings.Repeat("a", MaxTextLen+1)
	if err := long.Validate(); err == nil {
		t.Error("long note accepted")
	}
}

func TestRights(t *testing.T) {
	n := &Notebook{Owner: "Andy", Sharing: Private}
	for _, tc := range []struct {
		sharing                 string
		user                    string
		analyst, admin          bool
		see, edit, manage, want bool
	}{
		{Private, "andy", true, false, true, true, true, true},
		{Private, "bob", true, false, false, false, false, true},
		{Private, "root", true, true, true, true, true, true},
		{Read, "bob", true, false, true, false, false, true},
		{Read, "vera", false, false, true, false, false, true},
		{Edit, "bob", true, false, true, true, false, true},
		{Edit, "vera", false, false, true, false, false, true},
	} {
		n.Sharing = tc.sharing
		if got := n.CanSee(tc.user, tc.admin); got != tc.see {
			t.Errorf("%s %s see = %v", tc.sharing, tc.user, got)
		}
		if got := n.CanEdit(tc.user, tc.analyst, tc.admin); got != tc.edit {
			t.Errorf("%s %s edit = %v", tc.sharing, tc.user, got)
		}
		if got := n.CanManage(tc.user, tc.admin); got != tc.manage {
			t.Errorf("%s %s manage = %v", tc.sharing, tc.user, got)
		}
	}
	s, _ := Starter("starter-powershell")
	if !s.CanSee("vera", false) || s.CanEdit("root", true, true) || s.CanManage("root", true) {
		t.Error("starter hunts are read-only for everyone")
	}
}

func TestKeepResults(t *testing.T) {
	old := valid()
	old.Cells[1].Result = &Result{Matched: 3}
	n := valid()
	n.Cells = []Cell{old.Cells[1], {ID: "new", Kind: KindSearch, Query: "a=1", Result: &Result{Matched: 99}}}
	n.Cells[0].Result = nil
	n.KeepResults(old)
	if n.Cells[0].Result == nil || n.Cells[0].Result.Matched != 3 || n.Cells[1].Result != nil {
		t.Errorf("kept %+v", n.Cells)
	}
	n.Cells[0].Query = "a=2"
	n.KeepResults(old)
	if n.Cells[0].Result != nil {
		t.Error("a changed query kept its old result")
	}
}

func TestSnapshotIsBounded(t *testing.T) {
	var rows []map[string]any
	for i := range 150 {
		rows = append(rows, map[string]any{"n": float64(i), "s": strings.Repeat("é", MaxValueLen), "l": []any{"a", "b"}})
	}
	r := Snapshot("table", []string{"n", "s"}, rows, 150, false)
	if !r.Truncated || len(r.Rows) == 0 || len(r.Rows) > MaxRows {
		t.Fatalf("rows %d truncated %v", len(r.Rows), r.Truncated)
	}
	b, _ := json.Marshal(r)
	if len(b) > MaxResultBytes+64<<10 {
		t.Errorf("snapshot is %d bytes", len(b))
	}
	s := r.Rows[0]["s"].(string)
	if len(s) > MaxValueLen+len("…") || !strings.HasSuffix(s, "…") || strings.ContainsRune(s, '�') {
		t.Errorf("value not cut cleanly: %d bytes", len(s))
	}
	if small := Snapshot("events", nil, rows[:2], 2, false); small.Truncated || len(small.Rows) != 2 {
		t.Errorf("small = %+v", small)
	}
}

// Event data cannot inject Markdown structure or HTML into an export.
func TestMarkdownExport(t *testing.T) {
	n := valid()
	n.Description = "Why"
	n.Cases = []string{"CASE-1"}
	n.Cells[1].Query = "datamodel=Endpoint ```x```"
	n.Cells[1].Result = &Result{RanAt: time.Date(2026, 10, 16, 0, 0, 0, 0, time.UTC), Kind: "table", Columns: []string{"user", "cmd"},
		Rows: []map[string]any{{"user": "a|b", "cmd": "<script>alert(1)</script>\n| x |"},
			{"user": "[Reset your password](https://evil.example/login)", "cmd": "![](https://evil.example/p.png) **x** www.evil.example"}}}
	md := string(Markdown(n, 10))
	for _, want := range []string{"# Hunt\n", "**ATT&CK:** T1059.001", "**Investigations:** CASE-1", "````spl\ndatamodel=Endpoint ```x```\n````",
		"| user | cmd |", `| a\|b | &lt;script&gt;alert\(1\)&lt;/script&gt; \| x \| |`,
		`| \[Reset your password\]\(https\://evil\.example/login\) | \!\[\]\(https\://evil\.example/p\.png\) \*\*x\*\* www\.evil\.example |`} {
		if !strings.Contains(md, want) {
			t.Errorf("no %q in\n%s", want, md)
		}
	}
	if strings.Contains(md, "<script>") {
		t.Error("raw HTML in export")
	}
}

func TestMemoryStore(t *testing.T) {
	ctx := context.Background()
	m := NewMemory()
	mk := func(id, owner, sharing string, techs ...string) {
		n := &Notebook{ID: id, Title: "T " + id, Owner: owner, Sharing: sharing, Techniques: techs, Updated: time.Now()}
		if err := m.Create(ctx, n); err != nil {
			t.Fatal(err)
		}
	}
	mk("a", "andy", Private, "T1059.001")
	mk("b", "bob", Private)
	mk("c", "bob", Read, "T1059")
	if err := m.Create(ctx, &Notebook{ID: "a"}); err != ErrExists {
		t.Errorf("duplicate = %v", err)
	}
	ids := func(f Filter) string {
		list, _, err := m.Search(ctx, f)
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, s := range list {
			out = append(out, s.ID)
		}
		slices.Sort(out)
		return strings.Join(out, ",")
	}
	if got := ids(Filter{User: "ANDY"}); got != "a,c" {
		t.Errorf("andy sees %s", got)
	}
	if got := ids(Filter{User: "x", Admin: true}); got != "a,b,c" {
		t.Errorf("admin sees %s", got)
	}
	if got := ids(Filter{User: "andy", Technique: "t1059"}); got != "a,c" {
		t.Errorf("technique T1059 = %s", got)
	}
	if got := ids(Filter{User: "andy", Technique: "T1059.001"}); got != "a" {
		t.Errorf("technique T1059.001 = %s", got)
	}
	n, err := m.Modify(ctx, "a", func(n *Notebook) (bool, error) { n.Title = "New"; return true, nil })
	if err != nil || n.Title != "New" {
		t.Fatal(n, err)
	}
	if _, err := m.Modify(ctx, "zz", func(*Notebook) (bool, error) { return true, nil }); err != ErrNotFound {
		t.Errorf("missing = %v", err)
	}
}

// Two changes at the same clock reading still get different versions.
func TestTouchMovesForward(t *testing.T) {
	now := time.Date(2026, 10, 16, 0, 0, 0, 0, time.UTC)
	n := &Notebook{}
	n.Touch("a", now)
	first := n.Updated
	n.Touch("b", now)
	if !n.Updated.After(first) || n.UpdatedBy != "b" {
		t.Errorf("updated %v after %v", n.Updated, first)
	}
}
