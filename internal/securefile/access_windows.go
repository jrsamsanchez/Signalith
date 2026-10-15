//go:build windows

package securefile

import (
	"errors"
	"os"
	"strings"

	"golang.org/x/sys/windows"
)

// Well-known security identifiers.
const (
	sidSystem = "S-1-5-18"     // NT AUTHORITY\SYSTEM
	sidAdmins = "S-1-5-32-544" // BUILTIN\Administrators
)

// trustees returns who may use Signalith's private files: SYSTEM,
// Administrators, the service account and the account running now (the
// service itself, or whoever runs the CLI or a test). An administrator
// running as Administrator is left out: the Administrators entry already
// covers them, and an entry of their own would show on the Security page
// as another account that can read the file.
func trustees() []string {
	out := []string{sidSystem, sidAdmins, ServiceSID(ServiceName)}
	tok := windows.GetCurrentProcessToken()
	if u, err := tok.GetTokenUser(); err == nil {
		self := u.User.Sid.String()
		if self != "" && !contains(out, self) && !elevatedAdmin(tok) {
			out = append(out, self)
		}
	}
	return out
}

// elevatedAdmin reports whether tok runs as Administrator: elevated, with
// the Administrators group enabled in it.
func elevatedAdmin(tok windows.Token) bool {
	if !tok.IsElevated() {
		return false
	}
	groups, err := tok.GetTokenGroups()
	if err != nil {
		return false
	}
	for _, g := range groups.AllGroups() {
		if g.Attributes&windows.SE_GROUP_ENABLED != 0 && g.Sid.String() == sidAdmins {
			return true
		}
	}
	return false
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if strings.EqualFold(v, s) {
			return true
		}
	}
	return false
}

// privateACL returns the protected access list: full control for the
// trustees and nobody else. inherit makes the entries apply to the files
// and folders inside a folder.
func privateACL(inherit bool) (*windows.ACL, error) {
	flags := ""
	if inherit {
		flags = "OICI"
	}
	var b strings.Builder
	b.WriteString("D:P")
	for _, sid := range trustees() {
		b.WriteString("(A;" + flags + ";FA;;;" + sid + ")")
	}
	sd, err := windows.SecurityDescriptorFromString(b.String())
	if err != nil {
		return nil, err
	}
	dacl, _, err := sd.DACL()
	return dacl, err
}

// protect gives path the protected access list.
func protect(path string, folder bool) error {
	dacl, err := privateACL(folder)
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
}

// keepAccess gives tmp the access list of the file it replaces: the same
// entries, protected or inherited from the folder as that one's are.
func keepAccess(old string, _ os.FileInfo, tmp *os.File) error {
	sd, err := windows.GetNamedSecurityInfo(old, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	ctrl, _, err := sd.Control()
	if err != nil {
		return err
	}
	info := windows.SECURITY_INFORMATION(windows.DACL_SECURITY_INFORMATION | windows.UNPROTECTED_DACL_SECURITY_INFORMATION)
	if ctrl&windows.SE_DACL_PROTECTED != 0 {
		info = windows.DACL_SECURITY_INFORMATION | windows.PROTECTED_DACL_SECURITY_INFORMATION
	}
	return windows.SetNamedSecurityInfo(tmp.Name(), windows.SE_FILE_OBJECT, info, nil, nil, dacl, nil)
}

// makePrivate gives tmp the protected access list of a new file.
func makePrivate(tmp *os.File) error { return protect(tmp.Name(), false) }

// newFileAccess gives a new file the protected access list.
func newFileAccess(tmp *os.File, _ string) error { return protect(tmp.Name(), false) }

// privateDir gives a folder the protected access list, inherited by the
// files and folders inside it.
func privateDir(dir, _ string, _ bool) error { return protect(dir, true) }

// linkAllowed follows links: on Windows only administrators may make them
// (folder junctions, which any account may make, are refused by
// MkdirPrivate).
func linkAllowed(string, os.FileInfo) error { return nil }

func otherLinks(string) int { return 0 }

func isBusy(error) bool { return false }

// inUse reports whether a rename failed because another program, or this
// one, has the file open for a moment: Windows does not replace a file
// that is open without delete sharing, as Go opens files to read.
func inUse(err error) bool {
	return errors.Is(err, windows.ERROR_ACCESS_DENIED) || errors.Is(err, windows.ERROR_SHARING_VIOLATION) ||
		errors.Is(err, windows.ERROR_LOCK_VIOLATION)
}
