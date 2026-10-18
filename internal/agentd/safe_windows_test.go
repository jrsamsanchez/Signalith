//go:build windows

package agentd

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func setOwner(t *testing.T, path string, sid *windows.SID) {
	t.Helper()
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION, sid, nil, nil, nil); err != nil {
		t.Skipf("cannot set the owner of %s: %v", path, err)
	}
}

func TestCheckFolders(t *testing.T) {
	root := t.TempDir()
	conf := filepath.Join(root, "Signalith Agent")
	if err := os.Mkdir(conf, 0o700); err != nil {
		t.Fatal(err)
	}
	admins, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		t.Fatal(err)
	}
	tok := windows.GetCurrentProcessToken()
	u, err := tok.GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	p := Paths{Conf: conf, State: conf}

	// Owned by Administrators, above and below: used.
	setOwner(t, root, admins)
	setOwner(t, conf, admins)
	if err := CheckFolders(p); err != nil {
		t.Fatalf("folders owned by Administrators: %v", err)
	}
	// The folder above owned by a user: refused, as that user could swap
	// the agent's folder.
	setOwner(t, root, u.User.Sid)
	if err := CheckFolders(p); err == nil || !strings.Contains(err.Error(), "belongs to") {
		t.Errorf("parent owned by a user: %v", err)
	}
	setOwner(t, root, admins)
	// A junction in place of the agent's folder: refused.
	other := filepath.Join(root, "other")
	if err := os.Mkdir(other, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", link, other).CombinedOutput(); err != nil {
		t.Skipf("mklink /J: %v %s", err, out)
	}
	if err := CheckFolders(Paths{Conf: link, State: link}); err == nil || !strings.Contains(err.Error(), "link or junction") {
		t.Errorf("junction: %v", err)
	}
}
