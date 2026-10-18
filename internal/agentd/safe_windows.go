//go:build windows

package agentd

import (
	"path/filepath"

	"golang.org/x/sys/windows"
)

// CheckFolders refuses the agent's folders unless they, and the folder
// they are in, are plain folders owned by SYSTEM, Administrators or
// TrustedInstaller (see safeOwners). The install script checks the same;
// this also catches a folder swapped after the install.
func CheckFolders(p Paths) error {
	dirs := []string{filepath.Dir(p.Conf), p.Conf}
	if p.State != p.Conf {
		dirs = append(dirs, filepath.Dir(p.State), p.State)
	}
	for _, d := range dirs {
		if err := checkFolder(d); err != nil {
			return err
		}
	}
	return nil
}

func checkFolder(path string) error {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	attrs, err := windows.GetFileAttributes(name)
	if err != nil {
		return err
	}
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return err
	}
	return folderProblem(path, owner.String(), attrs&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0)
}
