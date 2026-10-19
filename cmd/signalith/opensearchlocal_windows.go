//go:build windows

package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"time"
	"unsafe"

	"github.com/jrsamsanchez/signalith/internal/oslocal"
	"github.com/jrsamsanchez/signalith/internal/ospki"
	"github.com/jrsamsanchez/signalith/internal/securefile"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// windowsOpenSearch runs OpenSearch as a Windows service with the
// release's own service wrapper (bin\opensearch-service.bat, Apache
// Commons Daemon), as its own virtual account.
type windowsOpenSearch struct{}

func newLocalOpenSearch() (localOpenSearch, error) { return windowsOpenSearch{}, nil }

const openSearchAccount = `NT SERVICE\` + oslocal.ServiceName

func (windowsOpenSearch) prepare(l oslocal.Layout, home string) error {
	if err := securefile.MkdirPrivate(l.Data); err != nil {
		return err
	}
	// Any user may make folders in ProgramData: one made before Signalith
	// is given to Administrators, so its maker cannot change its access
	// list back.
	admins, err := windows.StringToSid("S-1-5-32-544")
	if err != nil {
		return err
	}
	if err := windows.SetNamedSecurityInfo(l.Data, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION, admins, nil, nil, nil); err != nil {
		return fmt.Errorf("could not make Administrators the owner of %s: %w", l.Data, err)
	}
	if home == "" {
		return nil
	}
	// The service runs these, so only administrators may change them.
	for _, exe := range []string{filepath.Join(home, "bin", "opensearch-service-x64.exe"), filepath.Join(home, "jdk", "bin", "java.exe")} {
		if err := checkProgramFolder(exe); err != nil {
			return err
		}
	}
	return nil
}

func (windowsOpenSearch) exists() bool {
	m, err := mgr.Connect()
	if err != nil {
		return false
	}
	defer m.Disconnect()
	s, err := m.OpenService(oslocal.ServiceName)
	if err != nil {
		return false
	}
	s.Close()
	return true
}

func (windowsOpenSearch) stop() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(oslocal.ServiceName)
	if err != nil {
		return err
	}
	defer s.Close()
	st, err := s.Query()
	if err != nil {
		return err
	}
	if st.State == svc.Stopped {
		return nil
	}
	if _, err := s.Control(svc.Stop); err != nil && !errors.Is(err, windows.ERROR_SERVICE_NOT_ACTIVE) {
		return fmt.Errorf("could not stop the %s service: %w", oslocal.ServiceName, err)
	}
	for deadline := time.Now().Add(3 * time.Minute); time.Now().Before(deadline); time.Sleep(time.Second) {
		if st, err := s.Query(); err == nil && st.State == svc.Stopped {
			return nil
		}
	}
	return fmt.Errorf("the %s service did not stop within 3 minutes", oslocal.ServiceName)
}

func (windowsOpenSearch) remove() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(oslocal.ServiceName)
	if err != nil {
		return err
	}
	err = s.Delete()
	s.Close()
	if err != nil {
		return fmt.Errorf("could not remove the %s service: %w", oslocal.ServiceName, err)
	}
	// Gone once nothing has it open any more.
	for deadline := time.Now().Add(time.Minute); time.Now().Before(deadline); time.Sleep(time.Second) {
		s, err := m.OpenService(oslocal.ServiceName)
		if err != nil {
			break
		}
		s.Close()
	}
	// The service wrapper's settings.
	for _, k := range []string{`SOFTWARE\Apache Software Foundation\Procrun 2.0\` + oslocal.ServiceName,
		`SOFTWARE\WOW6432Node\Apache Software Foundation\Procrun 2.0\` + oslocal.ServiceName} {
		deleteKeyTree(registry.LOCAL_MACHINE, k)
	}
	return nil
}

// deleteKeyTree deletes a registry key and the keys in it.
func deleteKeyTree(root registry.Key, path string) {
	k, err := registry.OpenKey(root, path, registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return
	}
	names, _ := k.ReadSubKeyNames(-1)
	k.Close()
	for _, n := range names {
		deleteKeyTree(root, path+`\`+n)
	}
	registry.DeleteKey(root, path)
}

// env is the environment OpenSearch's own scripts run with: its bundled
// Java (never one JAVA_HOME names, which may be too old), its config
// folder, and folders the service account may write to.
func openSearchEnv(l oslocal.Layout, home string) []string {
	jdk := filepath.Join(home, "jdk")
	return append(os.Environ(),
		"OPENSEARCH_JAVA_HOME="+jdk,
		"JAVA_HOME="+jdk,
		"OPENSEARCH_PATH_CONF="+l.Config(),
		"OPENSEARCH_TMPDIR="+l.Tmp(),
		"OPENSEARCH_JAVA_OPTS=",
		"SERVICE_ID="+oslocal.ServiceName,
		"SERVICE_DISPLAY_NAME=Signalith OpenSearch",
		"SERVICE_DESCRIPTION=OpenSearch, where Signalith keeps its events (installed by Signalith)",
		"SERVICE_LOG_DIR="+l.Logs(),
		"OPENSEARCH_START_TYPE=auto",
	)
}

func (windowsOpenSearch) install(l oslocal.Layout, home string) error {
	for _, d := range l.ServiceFolders() {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return err
		}
	}
	cmd := exec.Command(filepath.Join(home, "bin", "opensearch-service.bat"), "install", oslocal.ServiceName)
	cmd.Env = openSearchEnv(l, home)
	cmd.Dir = home
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("opensearch-service.bat install failed (%w):\n%s", err, out)
	}
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(oslocal.ServiceName)
	if err != nil {
		return fmt.Errorf("opensearch-service.bat did not install the %s service: %w", oslocal.ServiceName, err)
	}
	defer s.Close()
	cfg, err := s.Config()
	if err != nil {
		return err
	}
	// Its own account, with access to its own folders only, not
	// LocalSystem, which may read everything.
	cfg.ServiceStartName = openSearchAccount
	cfg.Password = ""
	cfg.SidType = windows.SERVICE_SID_TYPE_UNRESTRICTED
	cfg.StartType = mgr.StartAutomatic
	cfg.DisplayName = "Signalith OpenSearch"
	if err := s.UpdateConfig(cfg); err != nil {
		return fmt.Errorf("could not set the %s service to run as %s: %w", oslocal.ServiceName, openSearchAccount, err)
	}
	actions := []mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 10 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 30 * time.Second},
		{Type: mgr.ServiceRestart, Delay: time.Minute},
	}
	if err := s.SetRecoveryActions(actions, 24*60*60); err != nil {
		fmt.Printf("Warning: could not set the %s service to restart after a failure: %v\n", oslocal.ServiceName, err)
	}
	sid := securefile.ServiceSID(oslocal.ServiceName)
	// It may change its config (its keystore), data, logs and temporary
	// files, and look into the folder that holds them; not the CA.
	for _, d := range l.ServiceFolders() {
		if err := grantAccess(d, sid, modifyAccess, true); err != nil {
			return fmt.Errorf("could not give %s access to %s: %w", openSearchAccount, d, err)
		}
	}
	if err := grantAccess(l.Data, sid, readAccess, false); err != nil {
		return fmt.Errorf("could not give %s access to %s: %w", openSearchAccount, l.Data, err)
	}
	fmt.Printf("Installed the %s service; it runs as %s.\n", oslocal.ServiceName, openSearchAccount)
	return nil
}

func (windowsOpenSearch) start() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(oslocal.ServiceName)
	if err != nil {
		return err
	}
	defer s.Close()
	if err := s.Start(); err != nil && !errors.Is(err, windows.ERROR_SERVICE_ALREADY_RUNNING) {
		return fmt.Errorf("could not start the %s service: %w", oslocal.ServiceName, err)
	}
	return nil
}

func (windowsOpenSearch) securityAdmin(l oslocal.Layout, home string, port int) error {
	cmd := exec.Command(filepath.Join(home, "plugins", "opensearch-security", "tools", "securityadmin.bat"),
		"-cd", l.Security(), "-icl", "-h", "127.0.0.1", "-p", strconv.Itoa(port),
		"-cacert", filepath.Join(l.CA(), ospki.RootCAFile),
		"-cert", filepath.Join(l.CA(), ospki.AdminCertFile),
		"-key", filepath.Join(l.CA(), ospki.AdminKeyFile))
	cmd.Env = openSearchEnv(l, home)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("securityadmin.bat failed (%w):\n%s", err, out)
	}
	return nil
}

// memoryStatus is MEMORYSTATUSEX.
type memoryStatus struct {
	Length, MemoryLoad                        uint32
	TotalPhys, AvailPhys                      uint64
	TotalPageFile, AvailPageFile              uint64
	TotalVirtual, AvailVirtual, AvailExtended uint64
}

func (windowsOpenSearch) memoryMB() uint64 {
	var m memoryStatus
	m.Length = uint32(unsafe.Sizeof(m))
	proc := windows.NewLazySystemDLL("kernel32.dll").NewProc("GlobalMemoryStatusEx")
	if r, _, _ := proc.Call(uintptr(unsafe.Pointer(&m))); r == 0 {
		return 4096
	}
	return m.TotalPhys / (1024 * 1024)
}
