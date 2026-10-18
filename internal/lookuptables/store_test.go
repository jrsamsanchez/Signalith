package lookuptables

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestParse(t *testing.T) {
	tb, err := Parse("owners", []byte("\ufeffhost , Owner,team\nweb-01, Ana ,Web\n\ndb-01,Sam\n"))
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"host", "Owner", "team"}; !reflect.DeepEqual(tb.Columns, want) {
		t.Errorf("columns = %q, want %q", tb.Columns, want)
	}
	if want := [][]string{{"web-01", "Ana", "Web"}, {"db-01", "Sam", ""}}; !reflect.DeepEqual(tb.Rows, want) {
		t.Errorf("rows = %q, want %q", tb.Rows, want)
	}
	for src, want := range map[string]string{
		"":                                       "empty",
		"a,a\n1,2\n":                             "twice",
		"a,,b\n":                                 "no name",
		"a,b\n1,2,3\n":                           "line 2 has 3 values",
		"a,\"b\n":                                "quote",
		strings.Repeat("c,", MaxColumns) + "c\n": "columns",
	} {
		_, err := Parse("t", []byte(src))
		var pe *ParseError
		if !errors.As(err, &pe) || !strings.Contains(err.Error(), want) {
			t.Errorf("Parse(%.40q) err = %v, want one mentioning %q", src, err, want)
		}
	}
}

func TestStoreKeepsTablesInFiles(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Put("owners", []byte("host,owner\nweb-01,ana\n")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Put("Bad Name", []byte("a\n1\n")); err == nil {
		t.Error("a bad name should be refused")
	}
	// A damaged file is reported and left out; the rest load.
	if err := os.WriteFile(filepath.Join(dir, "broken.csv"), []byte("a,a\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s2, err := Open(dir)
	if err == nil || !strings.Contains(err.Error(), "broken.csv") {
		t.Errorf("Open err = %v, want one naming broken.csv", err)
	}
	if got := s2.List(); len(got) != 1 || got[0].Name != "owners" || got[0].Rows != 1 {
		t.Errorf("List() = %+v", got)
	}
	if err := s2.Delete("owners"); err != nil {
		t.Fatal(err)
	}
	if err := s2.Delete("owners"); !errors.Is(err, ErrNotFound) {
		t.Errorf("second Delete err = %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "owners.csv")); !os.IsNotExist(err) {
		t.Errorf("owners.csv still there: %v", err)
	}
}

func TestStoreLimits(t *testing.T) {
	s, _ := Open("")
	for i := 0; i < MaxTables; i++ {
		if _, err := s.Put("t"+strings.Repeat("x", i%10)+string(rune('a'+i%26))+string(rune('a'+i/26)), []byte("a\n1\n")); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.Put("one-more", []byte("a\n1\n")); err == nil || !strings.Contains(err.Error(), "already") {
		t.Errorf("table %d err = %v", MaxTables+1, err)
	}
	if _, err := Parse("big", make([]byte, MaxTableBytes+1)); err == nil {
		t.Error("a file over the size limit should be refused")
	}
}

func TestLookupIndex(t *testing.T) {
	s, _ := Open("")
	if _, err := s.Put("ports", []byte("port,proto,name\n443,tcp,https\n53,udp,dns\n53,tcp,dns-tcp\n,tcp,blank\n")); err != nil {
		t.Fatal(err)
	}
	tb, idx, err := s.Lookup("ports", []string{"port"})
	if err != nil {
		t.Fatal(err)
	}
	if got := idx.Exact["53"]; !reflect.DeepEqual(got, []int{1, 2}) {
		t.Errorf(`idx["53"] = %v`, got)
	}
	if _, ok := idx.Exact[""]; ok {
		t.Error("an empty key should not be indexed")
	}
	_, idx2, _ := s.Lookup("ports", []string{"port", "proto"})
	if got := idx2.Exact[Key([]string{"53", "udp"})]; len(got) != 1 || tb.Rows[got[0]][2] != "dns" {
		t.Errorf("two-column key = %v", got)
	}
	if _, _, err := s.Lookup("ports", []string{"nope"}); err == nil || !strings.Contains(err.Error(), "no column") {
		t.Errorf("missing column err = %v", err)
	}
	if _, _, err := s.Lookup("nope", []string{"port"}); !errors.Is(err, ErrNotFound) {
		t.Errorf("missing table err = %v", err)
	}
	// A new upload drops the old index.
	if _, err := s.Put("ports", []byte("port,name\n22,ssh\n")); err != nil {
		t.Fatal(err)
	}
	if _, idx, _ := s.Lookup("ports", []string{"port"}); len(idx.Exact["53"]) != 0 || len(idx.Exact["22"]) != 1 {
		t.Errorf("index after replace = %v", idx)
	}
}

func TestGlob(t *testing.T) {
	for _, c := range []struct {
		p, s string
		want bool
	}{
		{"*", "", true}, {"a*", "abc", true}, {"*c", "abc", true}, {"a*c", "ac", true}, {"a*c", "a", false},
		{`*\psexec*.exe`, `c:\tools\psexec64.exe`, true}, {"*a*b*a*", "xaybza", true}, {"*a*b*a*", "xaybz", false},
		{"ab*ba", "aba", false}, {"a?c", "abc", false}, {"a?c", "a?c", true}, {"abc", "abc", true}, {"**", "x", true},
	} {
		if got := Glob(c.p, c.s); got != c.want {
			t.Errorf("Glob(%q, %q) = %v", c.p, c.s, got)
		}
	}
}

func TestWildcardsAndCase(t *testing.T) {
	dir := t.TempDir()
	s, _ := Open(dir)
	csv := []byte("path,name,note\nC:\\Windows\\*.exe,*,system\nC:\\Tools\\psexec.exe,psexec,exact\n*\\psexec*.exe,psexec,pattern\n")
	if _, err := s.PutWithOptions("tools", csv, Options{Wildcard: []string{"nope"}}); err == nil || !strings.Contains(err.Error(), "no column") {
		t.Errorf("unknown wildcard column err = %v", err)
	}
	if _, err := s.PutWithOptions("tools", csv, Options{Wildcard: []string{"path"}, IgnoreCase: true}); err != nil {
		t.Fatal(err)
	}
	tb, idx, err := s.Lookup("tools", []string{"path"})
	if err != nil {
		t.Fatal(err)
	}
	match := func(vals ...string) []int {
		steps := 0
		m, ok := idx.Match(tb, vals, 100, func(n int) bool { steps += n; return true })
		if !ok || steps == 0 && len(idx.Patterns) > 0 {
			t.Errorf("Match(%q) ok=%v steps=%d", vals, ok, steps)
		}
		return m
	}
	// Exact rows come before patterns, and case does not matter.
	if got := match(`c:\tools\PsExec.exe`); !reflect.DeepEqual(got, []int{1, 2}) {
		t.Errorf("psexec = %v", got)
	}
	if got := match(`C:\Windows\notepad.EXE`); !reflect.DeepEqual(got, []int{0}) {
		t.Errorf("notepad = %v", got)
	}
	if got := match(`D:\other.dll`); len(got) != 0 {
		t.Errorf("other = %v", got)
	}
	// name is not a wildcard column, so its * is only a *.
	_, idx2, _ := s.Lookup("tools", []string{"name"})
	if got, _ := idx2.Match(tb, []string{"cmd"}, 100, func(int) bool { return true }); len(got) != 0 {
		t.Errorf("* outside a wildcard column matched: %v", got)
	}
	if got, _ := idx2.Match(tb, []string{"*"}, 100, func(int) bool { return true }); !reflect.DeepEqual(got, []int{0}) {
		t.Errorf("literal * = %v", got)
	}
	// A step budget that runs out stops the match.
	if _, ok := idx.Match(tb, []string{"x"}, 100, func(int) bool { return false }); ok {
		t.Error("Match went on with no budget")
	}
	// The options are kept with the table, and dropped with a plain upload.
	again, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if tb, _ := again.Get("tools"); !reflect.DeepEqual(tb.Options, Options{Wildcard: []string{"path"}, IgnoreCase: true}) || tb.Info().IgnoreCase != true {
		t.Errorf("reopened options = %+v", tb.Options)
	}
	if _, err := again.Put("tools", csv); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "tools.options.json")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("options file after a plain upload: %v", err)
	}
	if _, err := again.PutWithOptions("tools", csv, Options{IgnoreCase: true}); err != nil {
		t.Fatal(err)
	}
	if err := again.Delete("tools"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "tools.options.json")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("options file after delete: %v", err)
	}
}

func TestCSVIsSafeToOpen(t *testing.T) {
	tb, _ := Parse("t", []byte("a,b\n=1+1,ok\n"))
	if got := string(tb.CSV()); got != "a,b\n'=1+1,ok\n" {
		t.Errorf("CSV() = %q", got)
	}
}

func FuzzParse(f *testing.F) {
	for _, s := range []string{"host,owner\nweb,ana\n", "\ufeffa,b\n1\n\n2,3\n", "a,\"b\nc\",d\n", "a,a\n"} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		tb, err := Parse("t", data)
		if err != nil {
			return
		}
		for _, r := range tb.Rows {
			if len(r) != len(tb.Columns) {
				t.Fatalf("row %q has %d cells for %d columns", r, len(r), len(tb.Columns))
			}
		}
		// What a table writes out reads back with the same shape.
		back, err := Parse("t", tb.CSV())
		if err != nil {
			t.Fatalf("CSV() does not read back: %v", err)
		}
		if len(back.Rows) > len(tb.Rows) || len(back.Columns) != len(tb.Columns) {
			t.Fatalf("CSV() read back as %d rows, %d columns; was %d, %d", len(back.Rows), len(back.Columns), len(tb.Rows), len(tb.Columns))
		}
	})
}

// Empty cells cost little on disk but a string header each in memory, so
// a table is measured by what it takes once parsed.
func TestParseCountsMemory(t *testing.T) {
	cols := make([]string, MaxColumns)
	for i := range cols {
		cols[i] = "c" + strings.Repeat("x", i)
	}
	data := []byte(strings.Join(cols, ",") + "\n" + strings.Repeat("x"+strings.Repeat(",", MaxColumns-1)+"\n", 50_000))
	if len(data) > MaxTableBytes {
		t.Fatalf("test file is %d bytes", len(data))
	}
	_, err := Parse("wide", data)
	if err == nil || !strings.Contains(err.Error(), "in memory") {
		t.Fatalf("err = %v", err)
	}
	tb, err := Parse("small", []byte("a,b\n1,2\n"))
	if err != nil || tb.Memory != rowOverhead+2*cellOverhead+2 {
		t.Fatalf("memory = %d, %v", tb.Memory, err)
	}
}

// A content pack's tables are read by every store, before an admin's of
// the same name, and an admin cannot add, replace or delete one, or take
// a name with the pack's prefix.
func TestPackTables(t *testing.T) {
	pt, err := NewPackTable("splunk", "splunk-pipes", []byte("pipe,tool\n*\\psexec*,PsExec\n"), Options{Wildcard: []string{"pipe"}, IgnoreCase: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewPackTable("splunk", "pipes", []byte("a\n1\n"), Options{}); err == nil {
		t.Error("a pack table must be named with the pack's prefix")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "splunk-pipes.csv"), []byte("pipe,tool\nx,mine\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	SetPackTables([]*Table{pt})
	t.Cleanup(func() { SetPackTables(nil) })
	if got, ok := s.Get("splunk-pipes"); !ok || got != pt {
		t.Errorf("Get = %v, %v; want the pack's table", got, ok)
	}
	tb, idx, err := s.Lookup("splunk-pipes", []string{"pipe"})
	if err != nil {
		t.Fatal(err)
	}
	if m, _ := idx.Match(tb, []string{`\\.\pipe\PSEXECSVC`}, 100, func(int) bool { return true }); len(m) != 1 {
		t.Errorf("Match = %v, want the pattern row", m)
	}
	// The admin's table the pack's hides is listed by neither.
	if l := s.List(); len(l) != 0 {
		t.Errorf("List() = %+v, want none", l)
	}
	if l := s.PackList(); len(l) != 1 || l[0].Pack != "splunk" {
		t.Errorf("PackList() = %+v, want the pack's table alone", l)
	}
	for _, name := range []string{"splunk-pipes", "splunk-other"} {
		if _, err := s.Put(name, []byte("a\n1\n")); err == nil || !strings.Contains(err.Error(), "content pack") {
			t.Errorf("Put(%s) err = %v, want a refusal", name, err)
		}
	}
	if err := s.Delete("splunk-pipes"); !errors.Is(err, ErrNotFound) || !strings.Contains(err.Error(), "content pack") {
		t.Errorf("Delete err = %v", err)
	}
	if _, err := s.Put("pipes", []byte("a\n1\n")); err != nil {
		t.Errorf("an admin's own name: %v", err)
	}
	// A store for checking rules reads only the tables it is given.
	if _, ok := NewPackStore(nil).Get("splunk-pipes"); ok {
		t.Error("NewPackStore(nil) has the pack's table")
	}
	// Another content version's tables replace the index built before.
	pt2, _ := NewPackTable("splunk", "splunk-pipes", []byte("pipe,tool\nother,x\n"), Options{})
	SetPackTables([]*Table{pt2})
	if tb, _, err := s.Lookup("splunk-pipes", []string{"pipe"}); err != nil || tb != pt2 {
		t.Errorf("Lookup after SetPackTables = %v, %v", tb, err)
	}
}
