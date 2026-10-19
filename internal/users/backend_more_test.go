package users

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestReadAndWriteUsersFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "users.json")
	// A file that is not there holds no users.
	recs, last, err := ReadFile(path)
	if err != nil || len(recs) != 0 || last != nil {
		t.Fatalf("missing file = %v %v %v", recs, last, err)
	}
	if m, err := ReadFileBuiltinMFA(path); err != nil || m != nil {
		t.Fatalf("missing file MFA = %v %v", m, err)
	}

	when := time.Now().Add(-time.Hour).UTC().Truncate(time.Second)
	in := map[string]Record{
		"ann": {User: User{Username: "ann", Role: Analyst, Source: SourceLocal}, Hash: "$2a$10$notarealhash", Epoch: 3},
		"dir": {User: User{Username: "dir", Role: Viewer, Source: SourceDirectory}, Hash: "ignored"},
	}
	if err := WriteFile(path, in, &when); err != nil {
		t.Fatal(err)
	}
	recs, last, err = ReadFile(path)
	if err != nil || last == nil || !last.Equal(when) || len(recs) != 2 {
		t.Fatalf("read back = %v %v %v", recs, last, err)
	}
	if r := recs["ann"]; r.Hash != "$2a$10$notarealhash" || r.Epoch != 3 || r.Role != Analyst {
		t.Errorf("ann = %+v", r)
	}
	if r := recs["dir"]; r.Hash != "" || r.Source != SourceDirectory {
		t.Errorf("a directory user keeps no password: %+v", r)
	}
	if m, err := ReadFileBuiltinMFA(path); err != nil || m != nil {
		t.Errorf("no MFA = %v %v", m, err)
	}

	// Damaged files are errors; unknown roles and sources grant nothing.
	for name, body := range map[string]string{
		"damaged":  "{",
		"repeated": `{"version":1,"users":[{"username":"a","role":"admin"},{"username":"A","role":"admin"}]}`,
		"empty":    `{"version":1,"users":[{"username":" ","role":"admin"}]}`,
	} {
		p := filepath.Join(dir, name+".json")
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := ReadFile(p); err == nil {
			t.Errorf("%s file read", name)
		}
		if _, err := ReadFileBuiltinMFA(p); err == nil {
			t.Errorf("%s file MFA read", name)
		}
	}
	p := filepath.Join(dir, "odd.json")
	if err := os.WriteFile(p, []byte(`{"version":1,"users":[{"username":"Odd","role":"overlord","source":"magic"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	recs, _, err = ReadFile(p)
	if r := recs["odd"]; err != nil || r.Role != Viewer || r.Source != SourceLocal {
		t.Errorf("odd = %+v %v", r, err)
	}
	if !strings.HasSuffix(p, "odd.json") {
		t.Fatal(p)
	}
}
