//go:build windows

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/safelog"
	"github.com/jrsamsanchez/signalith/internal/securefile"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"
)

const serviceName = "Signalith"

// runService runs the service handler instead of the CLI when Windows
// starts us as a service, and exits when the service stops. It must be
// called from main, not init: Windows calls the service handler on a
// thread of its own, and Go holds such calls until package init is done.
func runService() {
	if isSvc, err := svc.IsWindowsService(); err == nil && isSvc {
		asService = true
		path := defaultConfigPath()
		if len(os.Args) > 2 && os.Args[1] == "-c" {
			path = os.Args[2]
		}
		if err := svc.Run(serviceName, &service{configPath: path}); err != nil {
			os.Exit(1)
		}
		os.Exit(0)
	}
}

type service struct{ configPath string }

func (s *service) Execute(args []string, req <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}
	elog, _ := eventlog.Open(serviceName)
	log := newLogger(os.Stderr)
	// The log file rotates by size (signalith.log.1 and so on), so it
	// cannot fill the disk.
	if f, err := safelog.OpenRotating(filepath.Join(filepath.Dir(s.configPath), "signalith.log"), safelog.DefaultMaxSize, safelog.DefaultBackups); err == nil {
		defer f.Close()
		log = newLogger(f)
	}
	// A config that does not load stops the service before it reports
	// running, so "signalith service start" and the Services console show
	// that it failed.
	if _, err := config.Load(s.configPath); err != nil {
		log.Error("cannot start", "err", err)
		if elog != nil {
			elog.Error(1, "Signalith cannot start: "+err.Error())
		}
		return false, 1
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- serve(ctx, s.configPath, log) }()
	// PreShutdown gives a stop at reboot the same time as any other stop.
	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown | svc.AcceptPreShutdown}
	for {
		select {
		case err := <-done:
			cancel()
			if err != nil && elog != nil {
				elog.Error(1, "Signalith stopped: "+err.Error())
			}
			return false, 1
		case c := <-req:
			switch c.Cmd {
			case svc.Interrogate:
				status <- c.CurrentStatus
			case svc.Stop, svc.Shutdown, svc.PreShutdown:
				cancel()
				stopping(status, done)
				return false, 0
			}
		}
	}
}

// stopWait is how long a stop may take: the background jobs get up to a
// minute to finish before this server hands them to another one, then the
// last requests to OpenSearch and the web server's own wait.
const stopWait = 90 * time.Second

// stopping waits for serve to return, at most stopWait, telling Windows
// every few seconds that the stop is still going, so it does not give up
// on the service.
func stopping(status chan<- svc.Status, done <-chan error) {
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()
	limit := time.After(stopWait)
	for cp := uint32(1); ; cp++ {
		status <- svc.Status{State: svc.StopPending, CheckPoint: cp, WaitHint: 10000}
		select {
		case <-done:
			return
		case <-limit:
			return
		case <-tick.C:
		}
	}
}

// setPreshutdownTimeout asks Windows to wait up to stopWait for this
// service at reboot (SERVICE_PRESHUTDOWN_INFO).
func setPreshutdownTimeout(s *mgr.Service) error {
	info := struct{ timeout uint32 }{uint32((stopWait + 10*time.Second) / time.Millisecond)}
	return windows.ChangeServiceConfig2(s.Handle, windows.SERVICE_CONFIG_PRESHUTDOWN_INFO, (*byte)(unsafe.Pointer(&info)))
}

func cmdService(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: signalith service install|uninstall|start|stop [-c file]")
	}
	path := defaultConfigPath()
	if len(args) > 2 && args[1] == "-c" {
		path = args[2]
	}
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connecting to the service manager (run as Administrator): %w", err)
	}
	defer m.Disconnect()
	switch args[0] {
	case "install":
		return installService(m, path)
	case "uninstall":
		s, err := m.OpenService(serviceName)
		if err != nil {
			return err
		}
		defer s.Close()
		_ = eventlog.Remove(serviceName)
		return s.Delete()
	case "start":
		s, err := m.OpenService(serviceName)
		if err != nil {
			return err
		}
		defer s.Close()
		if err := s.Start(); err != nil {
			return err
		}
		return waitRunning(s, filepath.Join(filepath.Dir(path), "signalith.log"))
	case "stop":
		s, err := m.OpenService(serviceName)
		if err != nil {
			return err
		}
		defer s.Close()
		_, err = s.Control(svc.Stop)
		return err
	default:
		return fmt.Errorf("unknown service action %q", args[0])
	}
}

// waitRunning waits until the service reports running and is still
// running a few seconds later, so a service that stops right away (a
// config it cannot load, a file it may not read) is reported here rather
// than looking started.
func waitRunning(s *mgr.Service, logFile string) error {
	failed := func(st svc.Status) error {
		return fmt.Errorf("the %s service stopped (exit code %d). See %s and the Windows event log (Application, source %s)",
			serviceName, st.Win32ExitCode, logFile, serviceName)
	}
	deadline := time.Now().Add(60 * time.Second)
	for {
		st, err := s.Query()
		if err != nil {
			return err
		}
		switch st.State {
		case svc.Running:
			// Still running after a few seconds: it got past loading its
			// settings and opening its ports.
			time.Sleep(5 * time.Second)
			if st, err = s.Query(); err != nil {
				return err
			}
			if st.State != svc.Running {
				return failed(st)
			}
			fmt.Printf("The %s service is running.\n", serviceName)
			return nil
		case svc.Stopped:
			return failed(st)
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("the %s service did not start within a minute. See %s", serviceName, logFile)
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// serviceAccount is the virtual account the service runs as: an account
// of its own that Windows manages, with no password, that can be given
// access to exactly the files it needs (unlike LocalSystem, which can
// read everything).
const serviceAccount = `NT SERVICE\` + serviceName

// modifyAccess is the "Modify" right on files and folders: read, write,
// run and delete, but not change permissions or take ownership.
const modifyAccess windows.ACCESS_MASK = 0x1301BF

// installService installs the service, or updates an existing one (an
// upgrade, or one installed by an older version as LocalSystem), so that
// it runs this program with the config file at path, as its own virtual
// account, and restarts after a failure.
func installService(m *mgr.Mgr, path string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if err := checkProgramFolder(exe); err != nil {
		return err
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	cfg := mgr.Config{
		DisplayName:      "Signalith SIEM",
		Description:      "Signalith security event search and detection server",
		StartType:        mgr.StartAutomatic,
		ServiceStartName: serviceAccount,
		// The service's own SID (NT SERVICE\Signalith) is in its token,
		// so access lists naming it apply.
		SidType: windows.SERVICE_SID_TYPE_UNRESTRICTED,
	}
	verb := "Installed"
	s, err := m.OpenService(serviceName)
	if err == nil {
		verb = "Updated"
		cur, err := s.Config()
		if err != nil {
			s.Close()
			return err
		}
		cur.BinaryPathName = syscall.EscapeArg(exe) + " -c " + syscall.EscapeArg(abs)
		cur.DisplayName, cur.Description, cur.StartType = cfg.DisplayName, cfg.Description, cfg.StartType
		cur.ServiceStartName, cur.SidType = cfg.ServiceStartName, cfg.SidType
		// A virtual account has no password; an empty one leaves it unset.
		cur.Password = ""
		if err := s.UpdateConfig(cur); err != nil {
			s.Close()
			return fmt.Errorf("could not update the %s service: %w", serviceName, err)
		}
	} else {
		if s, err = m.CreateService(serviceName, exe, cfg, "-c", abs); err != nil {
			return err
		}
	}
	defer s.Close()
	// At a reboot Windows waits for the service as long as for any other
	// stop (stopWait), so the background jobs are handed over first.
	if err := setPreshutdownTimeout(s); err != nil {
		fmt.Printf("Warning: could not give the service time to stop when Windows shuts down: %v\n", err)
	}
	// Restart after 5 seconds, then 30, then every minute; count failures
	// from zero again after a day without one.
	actions := []mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 5 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 30 * time.Second},
		{Type: mgr.ServiceRestart, Delay: time.Minute},
	}
	if err := s.SetRecoveryActions(actions, 24*60*60); err != nil {
		fmt.Printf("Warning: could not set the service to restart after a failure: %v\n", err)
	} else if err := s.SetRecoveryActionsOnNonCrashFailures(true); err != nil {
		fmt.Printf("Warning: could not set the service to restart after it stops with an error: %v\n", err)
	}
	_ = eventlog.InstallAsEventCreate(serviceName, eventlog.Error|eventlog.Warning|eventlog.Info)
	sid := securefile.ServiceSID(serviceName)
	// The folders and files signalith.yaml and the Settings page name, as
	// the service sees them (with the environment it is given).
	applyServiceEnv(abs)
	// The state folder must exist to be given to the service: it keeps its
	// identity (node.id) and lock there, next to its master key and HTTPS
	// certificate.
	if c, err := config.LoadUnchecked(abs); err == nil {
		if err := prepareStateDir(c.StateDir(), filepath.Dir(abs)); err != nil {
			fmt.Printf("Warning: could not prepare the state folder %s: %v\n", c.StateDir(), err)
		}
	}
	access := serviceAccess(abs)
	for _, dir := range access.write {
		if err := grantAccess(dir, sid, modifyAccess, true); err != nil {
			fmt.Printf("Warning: could not give %s access to %s (%v). Run: icacls \"%s\" /grant \"*%s:(OI)(CI)M\"\n", serviceAccount, dir, err, dir, sid)
		}
	}
	for _, f := range access.read {
		if err := grantAccess(f, sid, readAccess, false); err != nil {
			fmt.Printf("Warning: %s may not be able to read %s, which signalith.yaml or the Settings page names (%v). Run: icacls \"%s\" /grant \"*%s:RX\"\n", serviceAccount, f, err, f, sid)
		}
	}
	fmt.Printf("%s the %s service using %s.\n", verb, serviceName, abs)
	fmt.Printf("It runs as %s, which may change files in: %s\n", serviceAccount, strings.Join(access.shown, ", "))
	if len(access.read) > 0 {
		fmt.Printf("It may also read: %s\n", strings.Join(access.read, ", "))
	}
	fmt.Println("Start it with: signalith service start")
	return nil
}

// readAccess is the "Read & execute" right on a file.
const readAccess windows.ACCESS_MASK = 0x1200A9

// grantAccess adds rights for sid to a file's or folder's access list
// (inherited by what is in a folder when inherit is set), keeping the
// entries already there and whether the list is its own or inherited from
// the folder above.
func grantAccess(path, sid string, rights windows.ACCESS_MASK, inherit bool) error {
	s, err := windows.StringToSid(sid)
	if err != nil {
		return err
	}
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
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
	inheritance := uint32(windows.NO_INHERITANCE)
	if inherit {
		inheritance = windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT
	}
	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{{
		AccessPermissions: rights,
		AccessMode:        windows.GRANT_ACCESS,
		Inheritance:       inheritance,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_WELL_KNOWN_GROUP,
			TrusteeValue: windows.TrusteeValueFromSID(s),
		},
	}}, dacl)
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, info, nil, nil, acl, nil)
}

// prepareStateDir makes the state folder, or the fallback folder in
// ProgramData that Signalith uses as one, private: only SYSTEM,
// Administrators, the service and this account may use it, as
// install.ps1 does for the config folder, and nothing is passed down
// from ProgramData, where every user may read. The config folder, which
// install.ps1 protects, and any other folder that already exists (one
// chosen with SIGNALITH_STATE_DIR) are left as they are.
func prepareStateDir(dir, configDir string) error {
	if strings.EqualFold(filepath.Clean(dir), filepath.Clean(configDir)) {
		return nil
	}
	_, err := os.Stat(dir)
	own := errors.Is(err, os.ErrNotExist)
	for _, f := range config.StateDirFallbacks() {
		if strings.EqualFold(filepath.Clean(f), filepath.Clean(dir)) {
			own = true
		}
	}
	if !own {
		return nil
	}
	return securefile.MkdirPrivate(dir)
}
