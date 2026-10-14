package users

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
)

// The memory and file backends behave alike; every test here runs over
// both.
func eachBackend(t *testing.T, fn func(t *testing.T, s *Store)) {
	t.Run("memory", func(t *testing.T) { fn(t, NewMemory()) })
	t.Run("file", func(t *testing.T) {
		s, err := Open(filepath.Join(t.TempDir(), "users.json"))
		if err != nil {
			t.Fatal(err)
		}
		fn(t, s)
	})
}

// A new password, a disable and a directory refusal move the session
// epoch on in the same change; a rename, a re-enable or a sign-in do not.
func TestSessionEpochs(t *testing.T) {
	eachBackend(t, func(t *testing.T, s *Store) {
		ctx := context.Background()
		u, err := s.Create(ctx, newUser("jlee", Analyst))
		if err != nil || u.SessionEpoch != 1 {
			t.Fatalf("created %+v %v", u, err)
		}
		epoch := func(want int64) {
			t.Helper()
			if got, _ := s.Get("jlee"); got.SessionEpoch != want {
				t.Errorf("epoch %d, want %d", got.SessionEpoch, want)
			}
		}
		if u, _ := s.SetPassword(ctx, "jlee", "another-password", false); u.SessionEpoch != 2 {
			t.Errorf("after a new password: %d", u.SessionEpoch)
		}
		name, off, on := "J. Lee", true, false
		s.Update(ctx, "jlee", Change{Name: &name})
		s.RecordSignIn(ctx, "jlee")
		epoch(2)
		s.Update(ctx, "jlee", Change{Disabled: &off})
		epoch(3)
		s.Update(ctx, "jlee", Change{Disabled: &off})
		s.Update(ctx, "jlee", Change{Disabled: &on})
		epoch(3)

		if _, err := s.SeeDirectoryUser(ctx, DirectoryUser{Username: "bob", Role: Viewer}); err != nil {
			t.Fatal(err)
		}
		before, _ := s.Get("bob")
		s.RefreshDirectoryUser(ctx, "bob", DirectoryUser{Username: "bob", Role: Analyst})
		s.RefuseDirectoryUser(ctx, "bob", "gone")
		s.RefuseDirectoryUser(ctx, "bob", "gone")
		if after, _ := s.Get("bob"); after.SessionEpoch != before.SessionEpoch+1 {
			t.Errorf("directory user's epoch %d, then %d", before.SessionEpoch, after.SessionEpoch)
		}
	})
}

// UpdateIf, SetPasswordIf and DeleteIf refuse a user changed since it was
// read; a recorded sign-in is not such a change, and an empty etag works
// on the user as it is.
func TestChangesIfUnchanged(t *testing.T) {
	eachBackend(t, func(t *testing.T, s *Store) {
		ctx := context.Background()
		s.Create(ctx, newUser("boss", Admin))
		s.Create(ctx, newUser("jlee", Analyst))
		old := s.ETag("jlee")
		if old == "" || s.ETag("nobody") != "" {
			t.Fatalf("etags %q %q", old, s.ETag("nobody"))
		}
		s.RecordSignIn(ctx, "jlee")
		if s.ETag("jlee") != old {
			t.Error("a sign-in changed the etag")
		}
		name := "J. Lee"
		u, err := s.UpdateIf(ctx, "jlee", old, Change{Name: &name})
		if err != nil || u.Name != name {
			t.Fatalf("update %+v %v", u, err)
		}
		if s.ETag("jlee") == old {
			t.Error("the etag stayed the same after a change")
		}
		other := "Someone"
		if _, err := s.UpdateIf(ctx, "jlee", old, Change{Name: &other}); !errors.Is(err, ErrStale) {
			t.Errorf("stale update: %v", err)
		}
		if _, err := s.SetPasswordIf(ctx, "jlee", old, "another-password", true); !errors.Is(err, ErrStale) {
			t.Errorf("stale password: %v", err)
		}
		if _, err := s.DeleteIf(ctx, "jlee", old); !errors.Is(err, ErrStale) {
			t.Errorf("stale delete: %v", err)
		}
		if u, _ := s.Get("jlee"); u.Name != name || !s.CheckPassword("jlee", "temporary-pass") {
			t.Errorf("a stale change was written: %+v", u)
		}
		if _, err := s.SetPasswordIf(ctx, "jlee", s.ETag("jlee"), "another-password", false); err != nil || !s.CheckPassword("jlee", "another-password") {
			t.Errorf("password: %v", err)
		}
		if _, err := s.Update(ctx, "jlee", Change{Name: &other}); err != nil {
			t.Errorf("update without an etag: %v", err)
		}
		if _, err := s.DeleteIf(ctx, "jlee", s.ETag("jlee")); err != nil {
			t.Errorf("delete: %v", err)
		}
		if _, ok := s.Get("jlee"); ok {
			t.Error("still there")
		}
		// The rules hold with an etag too.
		if _, err := s.DeleteIf(ctx, "boss", s.ETag("boss")); !errors.Is(err, ErrLastAdmin) {
			t.Errorf("delete of the last admin: %v", err)
		}
	})
}

// countingBackend is a backend of another kind (as the shared one is),
// over the memory backend, that records who made each change.
type countingBackend struct {
	*fileBackend
	mu  sync.Mutex
	bys []string
}

func (c *countingBackend) note(by string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.bys = append(c.bys, by)
}

func (c *countingBackend) Create(ctx context.Context, by string, r Record) (Record, error) {
	c.note(by)
	return c.fileBackend.Create(ctx, by, r)
}

func (c *countingBackend) Change(ctx context.Context, by, name, etag string, fn func(*Record) error) (Record, error) {
	c.note(by)
	return c.fileBackend.Change(ctx, by, name, etag, fn)
}

// A store over any backend: who changes is passed on, the copy for reads
// follows the backend's changes, and the built-in admin's sign-ins, which
// only the file and memory backends keep, are skipped.
func TestStoreOverAnotherBackend(t *testing.T) {
	b := &countingBackend{fileBackend: newFileBackend("")}
	s, err := New(b)
	if err != nil {
		t.Fatal(err)
	}
	ctx := WithActor(context.Background(), "sam")
	if Actor(ctx) != "sam" || Actor(context.Background()) != "" {
		t.Fatal("actor")
	}
	if _, err := s.Create(ctx, newUser("jlee", Analyst)); err != nil {
		t.Fatal(err)
	}
	s.RecordSignIn(ctx, "jlee")
	if len(b.bys) != 2 || b.bys[0] != "sam" || b.bys[1] != "sam" {
		t.Errorf("by %v", b.bys)
	}
	// Changed in the backend behind the store's back, as another server
	// would: the store follows once told.
	if _, err := b.fileBackend.Change(ctx, "bob", "jlee", "", func(r *Record) error {
		r.Disabled = true
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if u, _ := s.Get("jlee"); !u.Disabled {
		t.Error("the store did not follow the backend")
	}
	s.RecordBuiltinSignIn(ctx)
	if s.BuiltinLastSignIn() != nil {
		t.Error("a backend that keeps no built-in sign-ins had one recorded")
	}
}

// The first directory sign-in of one person on two servers at once makes
// one user, and both sign in.
func TestFirstDirectorySignInRace(t *testing.T) {
	path := filepath.Join(t.TempDir(), "users.json")
	a, _ := Open(path)
	b, _ := Open(path)
	ctx := context.Background()
	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i, s := range []*Store{a, b} {
		wg.Go(func() {
			_, errs[i] = s.SeeDirectoryUser(ctx, DirectoryUser{Username: "bob", DN: "CN=Bob", Role: Viewer})
		})
	}
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			t.Error(err)
		}
	}
	if n := reopen(t, path).Count()[SourceDirectory]; n != 1 {
		t.Errorf("%d directory users", n)
	}
}

// The file backend of the directory settings: its version moves on every
// save, a save from an older version is refused, and it says where the
// settings come from.
func TestDirectoryFileBackend(t *testing.T) {
	ctx := context.Background()
	d, err := OpenDirectory(filepath.Join(t.TempDir(), "directory.json"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if d.From().Source != "" || d.Path() == "" {
		t.Errorf("defaults from %+v, path %q", d.From(), d.Path())
	}
	s := Preset(TypeOpenLDAP)
	s.URL = "ldap://ldap.example.org"
	old := d.ETag()
	if err := d.SaveIf(ctx, old, s); err != nil {
		t.Fatal(err)
	}
	if d.ETag() == old || d.From().Source != "page" || d.Revision() != 1 {
		t.Errorf("after a save: etag %q (was %q), from %+v", d.ETag(), old, d.From())
	}
	if err := d.SaveIf(ctx, old, s); !errors.Is(err, ErrStale) {
		t.Errorf("stale save: %v", err)
	}
	if err := d.Save(ctx, s); err != nil {
		t.Errorf("save without an etag: %v", err)
	}
	yaml, _ := OpenDirectory("", &s)
	if !yaml.FromConfig() || yaml.From().Source != "yaml" || yaml.Path() != "" || !yaml.Saved() {
		t.Errorf("from signalith.yaml: %+v", yaml.From())
	}
	if err := yaml.SaveIf(ctx, yaml.ETag(), s); !errors.Is(err, ErrReadOnly) {
		t.Errorf("save over signalith.yaml: %v", err)
	}
}
