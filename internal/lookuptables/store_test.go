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
	if got := idx["53"]; !reflect.DeepEqual(got, []int{1, 2}) {
		t.Errorf(`idx["53"] = %v`, got)
	}
	if _, ok := idx[""]; ok {
		t.Error("an empty key should not be indexed")
	}
	_, idx2, _ := s.Lookup("ports", []string{"port", "proto"})
	if got := idx2[Key([]string{"53", "udp"})]; len(got) != 1 || tb.Rows[got[0]][2] != "dns" {
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
	if _, idx, _ := s.Lookup("ports", []string{"port"}); len(idx["53"]) != 0 || len(idx["22"]) != 1 {
		t.Errorf("index after replace = %v", idx)
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
