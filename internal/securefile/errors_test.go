package securefile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// tempFiles lists the temporary files Prepare left in dir.
func tempFiles(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".tmp") {
			out = append(out, e.Name())
		}
	}
	return out
}

func TestWriteProblems(t *testing.T) {
	dir := t.TempDir()
	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	// The folder to write in is a file.
	if err := WriteFile(filepath.Join(blocker, "a.yaml"), []byte("a")); err == nil {
		t.Error("wrote under a file")
	}
	if err := MkdirPrivate(filepath.Join(blocker, "sub", "dir")); err == nil {
		t.Error("made a folder under a file")
	}
	if err := MkdirPrivate(filepath.Join(blocker, "dir")); err == nil {
		t.Error("made a folder in a file")
	}

	if err := Replace(filepath.Join(blocker, "a.yaml"), []byte("a")); err == nil {
		t.Error("replaced under a file")
	}
	// Names longer than a file system allows.
	long := filepath.Join(dir, strings.Repeat("n", 300))
	if err := WriteFile(long, []byte("a")); err == nil {
		t.Error("wrote a file with a 300-character name")
	}
	if err := MkdirPrivate(long); err == nil {
		t.Error("made a folder with a 300-character name")
	}
	// Nothing to put in place.
	gone := &Pending{path: filepath.Join(dir, "new.yaml"), tmp: filepath.Join(dir, ".gone.tmp")}
	if err := gone.CommitNew(); err == nil {
		t.Error("committed a temporary file that is gone")
	}
	if _, err := os.Stat(gone.path); !os.IsNotExist(err) {
		t.Errorf("the file was made: %v", err)
	}

	// A folder where the file goes cannot be replaced; the temporary file
	// is removed.
	target := filepath.Join(dir, "taken")
	if err := os.MkdirAll(filepath.Join(target, "inside"), 0o755); err != nil {
		t.Fatal(err)
	}
	p, err := Prepare(target, []byte("data"))
	if err == nil {
		if p.Path() != target {
			t.Errorf("Path = %s", p.Path())
		}
		if err := p.Commit(); err == nil {
			t.Error("replaced a folder")
		}
	}
	if left := tempFiles(t, dir); len(left) != 0 {
		t.Errorf("temporary files left: %v", left)
	}

	// Written in place: only to a file that exists.
	if err := writeInPlace(filepath.Join(dir, "missing"), []byte("x")); err == nil {
		t.Error("wrote in place to a missing file")
	}
	inPlace := filepath.Join(dir, "in-place")
	os.WriteFile(inPlace, []byte("longer old content"), 0o600)
	if err := writeInPlace(inPlace, []byte("new")); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(inPlace); string(b) != "new" {
		t.Errorf("in place = %q", b)
	}
}
