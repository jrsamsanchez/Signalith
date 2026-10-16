package users

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// sharedStores opens two stores over one users file, as two servers that
// share a lookups folder do, after the first has added users. Reads by
// the second look for changes every time.
func sharedStores(t *testing.T, names ...string) (a, b *Store, path string) {
	t.Helper()
	path = filepath.Join(t.TempDir(), "lookups", "users.json")
	a, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range names {
		role := Viewer
		if n == "boss" || n == "boss2" {
			role = Admin
		}
		if _, err := a.Create(context.Background(), newUser(n, role)); err != nil {
			t.Fatal(err)
		}
	}
	b, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	b.recheck = 0
	return a, b, path
}

func reopen(t *testing.T, path string) *Store {
	t.Helper()
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// TestDisableSticksAcrossSharedFile: a user disabled on one server stays
// disabled when another server, which read the file before, records a
// sign-in for them or changes someone else, and that server refuses them
// too.
func TestDisableSticksAcrossSharedFile(t *testing.T) {
	a, b, path := sharedStores(t, "boss", "mallory", "carol")
	if u, _ := b.Get("mallory"); u.Disabled {
		t.Fatal("mallory starts enabled")
	}
	off := true
	if _, err := a.Update(context.Background(), "mallory", Change{Disabled: &off}); err != nil {
		t.Fatal(err)
	}
	b.RecordSignIn(context.Background(), "mallory")
	name := "Carol C"
	if _, err := b.Update(context.Background(), "carol", Change{Name: &name}); err != nil {
		t.Fatal(err)
	}
	if u, _ := b.Get("mallory"); !u.Disabled {
		t.Error("the other server still lets mallory in")
	}
	after := reopen(t, path)
	if u, _ := after.Get("mallory"); !u.Disabled {
		t.Error("mallory was enabled again by the other server's write")
	}
	if u, _ := after.Get("carol"); u.Name != "Carol C" {
		t.Errorf("carol = %+v, want the other server's change kept", u)
	}
}

// TestDeleteSticksAcrossSharedFile: a user deleted on one server is not
// brought back by another server's later writes, and their password stops
// working there.
func TestDeleteSticksAcrossSharedFile(t *testing.T) {
	a, b, path := sharedStores(t, "boss", "mallory", "carol")
	if !b.CheckPassword("mallory", "temporary-pass") {
		t.Fatal("mallory's password should work at first")
	}
	if _, err := a.Delete(context.Background(), "mallory"); err != nil {
		t.Fatal(err)
	}
	b.RecordSignIn(context.Background(), "mallory")
	b.RecordSignIn(context.Background(), "carol")
	b.RecordBuiltinSignIn(context.Background())
	if _, err := b.SetPassword(context.Background(), "carol", "another-password", false); err != nil {
		t.Fatal(err)
	}
	if b.CheckPassword("mallory", "temporary-pass") {
		t.Error("the other server still accepts the deleted user's password")
	}
	if _, err := b.Update(context.Background(), "mallory", Change{}); !errors.Is(err, ErrNotFound) {
		t.Errorf("updating the deleted user on the other server = %v, want ErrNotFound", err)
	}
	after := reopen(t, path)
	if _, ok := after.Get("mallory"); ok {
		t.Error("the deleted user is back")
	}
	if u, _ := after.Get("carol"); u.LastSignIn == nil || !after.CheckPassword("carol", "another-password") {
		t.Errorf("carol = %+v; want the other server's sign-in and password kept", u)
	}
	if after.BuiltinLastSignIn() == nil {
		t.Error("the built-in admin's sign-in was lost")
	}
}

// TestChangesFromBothServersAreKept: changes made on two servers one after
// the other all end up in the file, and rules that look at every user
// (at least one enabled admin, unique names) see the other server's.
func TestChangesFromBothServersAreKept(t *testing.T) {
	a, b, path := sharedStores(t, "boss", "boss2")
	if _, err := a.Create(context.Background(), newUser("dave", Viewer)); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Create(context.Background(), newUser("erin", Analyst)); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Create(context.Background(), newUser("dave", Viewer)); !errors.Is(err, ErrExists) {
		t.Errorf("the name the other server just took = %v, want ErrExists", err)
	}
	// With no built-in admin, one of the two admins must stay enabled:
	// the second server sees the first one's disable.
	off := true
	if _, err := a.Update(context.Background(), "boss", Change{Disabled: &off}); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Update(context.Background(), "boss2", Change{Disabled: &off}); !errors.Is(err, ErrLastAdmin) {
		t.Errorf("disabling the last enabled admin on the other server = %v, want ErrLastAdmin", err)
	}
	after := reopen(t, path)
	for _, n := range []string{"boss", "boss2", "dave", "erin"} {
		if _, ok := after.Get(n); !ok {
			t.Errorf("%s is missing", n)
		}
	}
	if u, _ := after.Get("boss"); !u.Disabled {
		t.Error("boss should be disabled")
	}
	if u, _ := after.Get("boss2"); u.Disabled {
		t.Error("boss2 should still be enabled")
	}
}

// TestDamagedSharedFileIsNotOverwritten: when the shared file cannot be
// understood, writes are refused rather than replace it, and reads go on
// with the users as they were.
func TestDamagedSharedFileIsNotOverwritten(t *testing.T) {
	_, b, path := sharedStores(t, "boss", "carol")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Create(context.Background(), newUser("dave", Viewer)); err == nil {
		t.Error("a write over a damaged file was allowed")
	}
	b.RecordSignIn(context.Background(), "carol")
	if got, _ := os.ReadFile(path); string(got) != "{not json" {
		t.Errorf("the damaged file was replaced: %s", got)
	}
	if _, ok := b.Get("carol"); !ok {
		t.Error("reads lost the users they had")
	}
}

// TestReadsLookForChangesAtMostOncePerInterval: reads do not read the file
// every time; within the interval they go on with what they have.
func TestReadsLookForChangesAtMostOncePerInterval(t *testing.T) {
	a, b, _ := sharedStores(t, "boss", "carol")
	b.recheck = time.Hour
	b.checked, b.checkedOK = time.Now(), true
	if _, err := a.Delete(context.Background(), "carol"); err != nil {
		t.Fatal(err)
	}
	if _, ok := b.Get("carol"); !ok {
		t.Error("a read within the interval read the file again")
	}
	// A write always works on the file as it is now.
	if _, err := b.Update(context.Background(), "carol", Change{}); !errors.Is(err, ErrNotFound) {
		t.Errorf("update = %v, want ErrNotFound", err)
	}
	if _, ok := b.Get("carol"); ok {
		t.Error("after a write, the store should hold the file's users")
	}
}

// TestConcurrentWritesOnOneServer: many sign-ins and edits at once on one
// server, as busy request handlers make them, all land, and the file stays
// whole.
func TestConcurrentWritesOnOneServer(t *testing.T) {
	a, b, path := sharedStores(t, "boss")
	var names []string
	for i := range 8 {
		n := fmt.Sprintf("user%d", i)
		if _, err := a.Create(context.Background(), newUser(n, Viewer)); err != nil {
			t.Fatal(err)
		}
		names = append(names, n)
	}
	var wg sync.WaitGroup
	for i, n := range names {
		wg.Add(2)
		go func() {
			defer wg.Done()
			b.RecordSignIn(context.Background(), n)
			_, _ = b.Get(n)
		}()
		go func() {
			defer wg.Done()
			name := fmt.Sprintf("Person %d", i)
			if _, err := b.Update(context.Background(), n, Change{Name: &name}); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	after := reopen(t, path)
	for i, n := range names {
		u, ok := after.Get(n)
		if !ok || u.LastSignIn == nil || u.Name != fmt.Sprintf("Person %d", i) {
			t.Errorf("%s = %+v, want both its sign-in and its new name", n, u)
		}
	}
}

// TestMissingSharedFileKeepsUsers: a users file that disappears (moved
// away by hand while the server runs) leaves the users the server has; the
// next change writes the file again.
func TestMissingSharedFileKeepsUsers(t *testing.T) {
	_, b, path := sharedStores(t, "boss", "carol")
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if _, ok := b.Get("carol"); !ok {
		t.Fatal("carol vanished with the file")
	}
	if _, err := b.Create(context.Background(), newUser("dave", Viewer)); err != nil {
		t.Fatal(err)
	}
	after := reopen(t, path)
	for _, n := range []string{"boss", "carol", "dave"} {
		if _, ok := after.Get(n); !ok {
			t.Errorf("%s is missing from the file written again", n)
		}
	}
}

// TestTwoServersWritingAtOnceLoseNothing: two servers changing the same
// users at the same moment both keep their changes, because each change
// is made under the lock file to the file as it is then.
func TestTwoServersWritingAtOnceLoseNothing(t *testing.T) {
	a, b, path := sharedStores(t, "boss")
	var names []string
	for i := range 6 {
		n := fmt.Sprintf("user%d", i)
		if _, err := a.Create(context.Background(), newUser(n, Viewer)); err != nil {
			t.Fatal(err)
		}
		names = append(names, n)
	}
	var wg sync.WaitGroup
	for i, n := range names {
		wg.Add(3)
		go func() {
			defer wg.Done()
			name := fmt.Sprintf("Person %d", i)
			if _, err := a.Update(context.Background(), n, Change{Name: &name}); err != nil {
				t.Error(err)
			}
		}()
		go func() {
			defer wg.Done()
			email := fmt.Sprintf("p%d@example.com", i)
			if _, err := b.Update(context.Background(), n, Change{Email: &email}); err != nil {
				t.Error(err)
			}
		}()
		go func() {
			defer wg.Done()
			b.RecordSignIn(context.Background(), n)
		}()
	}
	wg.Wait()
	after := reopen(t, path)
	for i, n := range names {
		u, ok := after.Get(n)
		if !ok || u.Name != fmt.Sprintf("Person %d", i) || u.Email != fmt.Sprintf("p%d@example.com", i) || u.LastSignIn == nil {
			t.Errorf("%s = %+v, want the name from one server and the email and sign-in from the other", n, u)
		}
	}
	if _, err := os.Stat(path + ".lock"); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("lock file left behind: %v", err)
	}
}

// TestLockFileLeftBehindIsTakenOver: a lock file from a server that
// stopped mid-change holds up changes only until it has stayed the same
// for lockStale.
func TestLockFileLeftBehindIsTakenOver(t *testing.T) {
	defer func(s, w time.Duration) { lockStale, lockWait = s, w }(lockStale, lockWait)
	lockStale, lockWait = 100*time.Millisecond, 10*time.Second
	a, _, path := sharedStores(t, "boss", "carol")
	if err := os.WriteFile(path+".lock", []byte("crashed"), 0o600); err != nil {
		t.Fatal(err)
	}
	off := true
	if _, err := a.Update(context.Background(), "carol", Change{Disabled: &off}); err != nil {
		t.Fatal(err)
	}
	if u, _ := reopen(t, path).Get("carol"); !u.Disabled {
		t.Error("the change was not written")
	}
	if _, err := os.Stat(path + ".lock"); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("lock file left behind: %v", err)
	}
}

// TestBusyLockRefusesTheChange: a lock another server keeps changing (it
// is busy, not gone) makes a change give up after lockWait with ErrBusy,
// writing nothing and leaving that server's lock alone.
func TestBusyLockRefusesTheChange(t *testing.T) {
	defer func(s, w time.Duration) { lockStale, lockWait = s, w }(lockStale, lockWait)
	lockStale, lockWait = time.Hour, 150*time.Millisecond
	a, _, path := sharedStores(t, "boss", "carol")
	if err := os.WriteFile(path+".lock", []byte("other server"), 0o600); err != nil {
		t.Fatal(err)
	}
	off := true
	if _, err := a.Update(context.Background(), "carol", Change{Disabled: &off}); !errors.Is(err, ErrBusy) {
		t.Fatalf("update = %v, want ErrBusy", err)
	}
	if u, _ := reopen(t, path).Get("carol"); u.Disabled {
		t.Error("a change was written without the lock")
	}
	if held, _ := os.ReadFile(path + ".lock"); string(held) != "other server" {
		t.Errorf("the other server's lock was touched: %q", held)
	}
}

// TestSlowShareHoldsUpOneReadOnly: while one read of the users file hangs
// (a network share that stopped answering), other reads go on with the
// users as last read instead of waiting for it.
func TestSlowShareHoldsUpOneReadOnly(t *testing.T) {
	_, b, _ := sharedStores(t, "boss", "carol")
	stuck, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	defer func(f func(string) ([]byte, error)) { readUsersFile = f }(readUsersFile)
	real := readUsersFile
	readUsersFile = func(name string) ([]byte, error) {
		block := false
		once.Do(func() { block = true })
		if block {
			close(stuck)
			<-release
		}
		return real(name)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		b.Get("carol")
	}()
	<-stuck
	got := make(chan bool)
	go func() {
		_, ok := b.Get("carol")
		_, okList := b.CheckPassword("carol", "wrong password"), len(b.List()) == 2
		got <- ok && okList
	}()
	select {
	case ok := <-got:
		if !ok {
			t.Error("reads during the slow read lost users")
		}
	case <-time.After(5 * time.Second):
		t.Error("reads waited for the slow read of the users file")
	}
	close(release)
	<-done
}

// TestSlowReadIsNotAppliedOverANewerChange: a read that started before a
// change on this server and ends after it does not bring back what the
// file held before the change.
func TestSlowReadIsNotAppliedOverANewerChange(t *testing.T) {
	_, b, _ := sharedStores(t, "boss", "carol")
	stuck, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	defer func(f func(string) ([]byte, error)) { readUsersFile = f }(readUsersFile)
	real := readUsersFile
	readUsersFile = func(name string) ([]byte, error) {
		data, err := real(name)
		block := false
		once.Do(func() { block = true })
		if block {
			close(stuck)
			<-release
		}
		return data, err // as the file was when the read began
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		b.Get("carol")
	}()
	<-stuck
	off := true
	if _, err := b.Update(context.Background(), "carol", Change{Disabled: &off}); err != nil {
		t.Fatal(err)
	}
	close(release)
	<-done
	b.recheck = time.Hour // keep the next read from reading the file again
	if u, _ := b.Get("carol"); !u.Disabled {
		t.Error("an older read undid the change")
	}
}
