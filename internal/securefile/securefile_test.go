package securefile

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
	"time"
)

func TestServiceSID(t *testing.T) {
	// Windows' own TrustedInstaller service has this well-known SID.
	if got := ServiceSID("TrustedInstaller"); got != "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464" {
		t.Errorf("ServiceSID(TrustedInstaller) = %s", got)
	}
	if ServiceSID("signalith") != ServiceSID("Signalith") {
		t.Error("service names ignore case")
	}
}

func TestWriteFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "sub", "store.json")
	if err := WriteFile(p, []byte("one")); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(p); string(b) != "one" {
		t.Fatalf("content %q", b)
	}
	if runtime.GOOS != "windows" {
		if st, _ := os.Stat(p); st.Mode().Perm() != 0o600 {
			t.Errorf("new file mode %v", st.Mode().Perm())
		}
		// A replaced file keeps its mode.
		os.Chmod(p, 0o640)
		if err := WriteFile(p, []byte("two")); err != nil {
			t.Fatal(err)
		}
		if st, _ := os.Stat(p); st.Mode().Perm() != 0o640 {
			t.Errorf("replaced file mode %v, want 0640", st.Mode().Perm())
		}
	}
	// Prepare writes nothing in place until Commit; Discard leaves nothing.
	pend, err := Prepare(p, []byte("three"))
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(p); string(b) == "three" {
		t.Error("Prepare replaced the file")
	}
	pend.Discard()
	if left, _ := filepath.Glob(filepath.Join(dir, "sub", ".*")); len(left) != 0 {
		t.Errorf("left behind: %v", left)
	}
	// CommitNew refuses to replace a file.
	pend, err = Prepare(p, []byte("four"))
	if err != nil {
		t.Fatal(err)
	}
	if err := pend.CommitNew(); !errors.Is(err, fs.ErrExist) {
		t.Errorf("CommitNew over a file: %v", err)
	}
	if b, _ := os.ReadFile(p); string(b) == "four" {
		t.Error("CommitNew replaced the file")
	}
	n := filepath.Join(dir, "sub", "new")
	pend, _ = Prepare(n, []byte("five"))
	if err := pend.CommitNew(); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(n); string(b) != "five" {
		t.Errorf("CommitNew wrote %q", b)
	}
	if left, _ := filepath.Glob(filepath.Join(dir, "sub", ".*")); len(left) != 0 {
		t.Errorf("left behind: %v", left)
	}
}

func TestMkdirPrivate(t *testing.T) {
	d := filepath.Join(t.TempDir(), "a", "keys")
	if err := MkdirPrivate(d); err != nil {
		t.Fatal(err)
	}
	if err := MkdirPrivate(d); err != nil {
		t.Fatalf("an existing folder: %v", err)
	}
	if runtime.GOOS != "windows" {
		if st, _ := os.Stat(d); st.Mode().Perm() != 0o700 {
			t.Errorf("mode %v, want 0700", st.Mode().Perm())
		}
	}
}

// A file that can only be written in place (a Docker bind mount of one
// file) gets the content given to Prepare, even when the caller cleared
// its own copy right after, as a key's bytes are.
func TestCommitInPlaceUsesItsOwnCopy(t *testing.T) {
	if !isBusy(&os.LinkError{Op: "rename", Err: syscall.EBUSY}) {
		t.Skip("no in-place writes on this system")
	}
	p := filepath.Join(t.TempDir(), "master.key")
	os.WriteFile(p, []byte("old key"), 0o600)
	defer func() { rename = os.Rename }()
	rename = func(oldpath, newpath string) error {
		return &os.LinkError{Op: "rename", Old: oldpath, New: newpath, Err: syscall.EBUSY}
	}
	data := []byte("the new key")
	pend, err := Prepare(p, data)
	if err != nil {
		t.Fatal(err)
	}
	clear(data)
	if err := pend.Commit(); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(p); string(b) != "the new key" {
		t.Errorf("written in place: %q", b)
	}
	if left, _ := filepath.Glob(filepath.Join(filepath.Dir(p), ".*")); len(left) != 0 {
		t.Errorf("left behind: %v", left)
	}
}

// Writing through a link replaces the file it points to and keeps the
// link, so no copy with the old content is left behind.
func TestWriteFileFollowsLinks(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real", "signalith.yaml")
	os.MkdirAll(filepath.Dir(real), 0o750)
	os.WriteFile(real, []byte("password: plain"), 0o640)
	link := filepath.Join(dir, "signalith.yaml")
	if err := os.Symlink(filepath.Join("real", "signalith.yaml"), link); err != nil {
		t.Skip("cannot make links here:", err)
	}
	if err := WriteFile(link, []byte("password: enc:v1:...")); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Lstat(link); err != nil || fi.Mode()&fs.ModeSymlink == 0 {
		t.Errorf("the link was replaced: %v %v", fi.Mode(), err)
	}
	if b, _ := os.ReadFile(real); string(b) != "password: enc:v1:..." {
		t.Errorf("the file the link points to holds %q", b)
	}
	if runtime.GOOS != "windows" {
		if st, _ := os.Stat(real); st.Mode().Perm() != 0o640 {
			t.Errorf("mode %v, want the old file's 0640", st.Mode().Perm())
		}
	}
	// A link to nothing is an error, not a new file in place of the link.
	dangling := filepath.Join(dir, "gone.yaml")
	os.Symlink(filepath.Join(dir, "missing", "x.yaml"), dangling)
	if err := WriteFile(dangling, []byte("x")); err == nil {
		t.Error("writing through a link to nothing worked")
	}
}

// Replace puts a new file in place of a link and leaves the file the link
// points to alone; a file it replaces is made private, whatever it allowed.
func TestReplaceReplacesLinks(t *testing.T) {
	dir := t.TempDir()
	other := filepath.Join(dir, "other.yaml")
	os.WriteFile(other, []byte("not ours"), 0o644)
	p := filepath.Join(dir, "lookups", "settings.yaml")
	os.MkdirAll(filepath.Dir(p), 0o750)
	if err := os.Symlink(other, p); err != nil {
		t.Skip("cannot make links here:", err)
	}
	if err := Replace(p, []byte("secret: enc:v1:...")); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Lstat(p); err != nil || fi.Mode()&fs.ModeSymlink != 0 {
		t.Fatalf("the link is still there: %v %v", fi.Mode(), err)
	}
	if b, _ := os.ReadFile(other); string(b) != "not ours" {
		t.Errorf("the file the link pointed to holds %q", b)
	}
	if b, _ := os.ReadFile(p); string(b) != "secret: enc:v1:..." {
		t.Errorf("content %q", b)
	}
	if runtime.GOOS != "windows" {
		if st, _ := os.Stat(p); st.Mode().Perm() != 0o600 {
			t.Errorf("new file mode %v, want 0600", st.Mode().Perm())
		}
		os.Chmod(p, 0o644)
		if err := Replace(p, []byte("two")); err != nil {
			t.Fatal(err)
		}
		if st, _ := os.Stat(p); st.Mode().Perm() != 0o600 {
			t.Errorf("replaced file mode %v, want 0600", st.Mode().Perm())
		}
	}
	// Nothing is written until Commit.
	pend, err := PrepareReplace(p, []byte("three"))
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(p); string(b) == "three" {
		t.Error("PrepareReplace replaced the file")
	}
	if err := pend.Commit(); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(p); string(b) != "three" {
		t.Errorf("content after Commit %q", b)
	}
}

func TestPreparePrivate(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file modes do not apply on Windows; see access_windows_test.go")
	}
	p := filepath.Join(t.TempDir(), "master.key")
	os.WriteFile(p, []byte("old"), 0o644)
	pend, err := PreparePrivate(p, []byte("new"))
	if err != nil {
		t.Fatal(err)
	}
	if err := pend.Commit(); err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(p); st.Mode().Perm() != 0o600 {
		t.Errorf("mode %v, want 0600 whatever the old file had", st.Mode().Perm())
	}
}

func TestOtherLinks(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "signalith.yaml")
	os.WriteFile(p, []byte("x"), 0o600)
	if n := OtherLinks(p); n != 0 {
		t.Errorf("OtherLinks = %d for a file with one name", n)
	}
	if err := os.Link(p, filepath.Join(dir, "backup.yaml")); err != nil {
		t.Skip("no hard links here:", err)
	}
	want := 1
	if runtime.GOOS == "windows" {
		want = 0
	}
	if n := OtherLinks(p); n != want {
		t.Errorf("OtherLinks = %d, want %d", n, want)
	}
}

// A folder that is a link is not followed: a link someone else planted
// could otherwise have another folder's permissions changed.
func TestMkdirPrivateRefusesLinks(t *testing.T) {
	dir := t.TempDir()
	victim := filepath.Join(dir, "victim")
	os.Mkdir(victim, 0o755)
	keys := filepath.Join(dir, "state", "keys")
	os.MkdirAll(filepath.Dir(keys), 0o750)
	if err := os.Symlink(victim, keys); err != nil {
		t.Skip("cannot make links here:", err)
	}
	if err := MkdirPrivate(keys); err == nil {
		t.Fatal("MkdirPrivate followed a link")
	}
	if runtime.GOOS != "windows" {
		if st, _ := os.Stat(victim); st.Mode().Perm() != 0o755 {
			t.Errorf("the folder the link points to became %v", st.Mode().Perm())
		}
	}
}

// A rename that meets the file open elsewhere for a moment (Windows) is
// tried again rather than failing the write.
func TestCommitWaitsWhileTheFileIsInUse(t *testing.T) {
	p := filepath.Join(t.TempDir(), "cache.enc")
	os.WriteFile(p, []byte("old"), 0o600)
	inUseErr := errors.New("in use")
	tries := 0
	defer func() { rename, fileInUse = os.Rename, inUse }()
	fileInUse = func(err error) bool { return errors.Is(err, inUseErr) }
	rename = func(oldpath, newpath string) error {
		if tries++; tries < 3 {
			return &os.LinkError{Op: "rename", Old: oldpath, New: newpath, Err: inUseErr}
		}
		return os.Rename(oldpath, newpath)
	}
	if err := WriteFile(p, []byte("new")); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(p); string(b) != "new" || tries != 3 {
		t.Errorf("content %q after %d tries", b, tries)
	}
}

// On Windows a reader that has the file open keeps it from being
// replaced until it closes it; the write waits for that.
func TestReplaceWhileAReaderHasItOpen(t *testing.T) {
	p := filepath.Join(t.TempDir(), "cache.enc")
	if err := WriteFile(p, []byte("old")); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	closed := make(chan struct{})
	go func() {
		time.Sleep(100 * time.Millisecond)
		f.Close()
		close(closed)
	}()
	err = WriteFile(p, []byte("new"))
	<-closed
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(p); string(b) != "new" {
		t.Errorf("content %q", b)
	}
}
