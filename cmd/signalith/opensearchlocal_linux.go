// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/jrsamsanchez/signalith/internal/config"
	"github.com/jrsamsanchez/signalith/internal/oslocal"
	"github.com/jrsamsanchez/signalith/internal/ospki"
	"golang.org/x/sys/unix"
)

// linuxOpenSearch runs OpenSearch from the official release for Linux as
// the systemd unit signalith-opensearch, as its own system account,
// signalith-opensearch, sandboxed the way Signalith's own unit is.
type linuxOpenSearch struct{}

// openSearchUser is the account OpenSearch runs as.
const openSearchUser = "signalith-opensearch"

// Where the unit and the kernel setting OpenSearch needs are written.
var (
	systemdUnitDir = "/etc/systemd/system"
	sysctlFile     = "/etc/sysctl.d/90-signalith-opensearch.conf"
)

func unitFile() string { return filepath.Join(systemdUnitDir, oslocal.ServiceName+".service") }

func newLocalOpenSearch() (localOpenSearch, error) {
	if os.Geteuid() != 0 {
		return nil, errors.New("run it as root: sudo signalith opensearch ...")
	}
	if _, err := os.Stat("/run/systemd/system"); err != nil {
		return nil, errors.New("signalith opensearch runs OpenSearch as a systemd service, and this system does not run systemd; " +
			"use the Docker quick start, or install OpenSearch from its own packages (docs/install-packages.md)")
	}
	return linuxOpenSearch{}, nil
}

// plainPath is what the unit file may hold without quoting: no spaces,
// quotes or systemd's % specifiers.
var plainPath = regexp.MustCompile(`^/[A-Za-z0-9._/-]+$`)

func (linuxOpenSearch) prepare(l oslocal.Layout, home string) error {
	for _, p := range []string{l.Home, l.Data, l.Client} {
		if !plainPath.MatchString(p) || strings.Contains(p, "/../") || strings.HasSuffix(p, "/..") {
			return fmt.Errorf("%q: give a full path of letters, digits and . _ - / only", p)
		}
	}
	// Data: root's, which the service may look into but not change; Home:
	// root's, which anyone may read.
	if err := rootFolder(l.Data, 0o711); err != nil {
		return err
	}
	if err := rootFolder(l.Home, 0o755); err != nil {
		return err
	}
	if home == "" {
		return nil
	}
	// The service runs these, so only root may change them.
	for _, exe := range []string{filepath.Join(home, "bin", "opensearch"), filepath.Join(home, "jdk", "bin", "java")} {
		if err := onlyRootChanges(exe); err != nil {
			return err
		}
	}
	return nil
}

// rootFolder makes dir (and the folders above it) if it is missing, and
// gives it to root with mode, after checking only root can change the
// folders above it.
func rootFolder(dir string, mode os.FileMode) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	fi, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return fmt.Errorf("%s is not a folder", dir)
	}
	if err := onlyRootChanges(filepath.Dir(dir)); err != nil {
		return err
	}
	if err := os.Lchown(dir, 0, 0); err != nil {
		return err
	}
	return os.Chmod(dir, mode)
}

// onlyRootChanges checks that p, and every folder above it, belongs to
// root and that no group or other user may change it.
func onlyRootChanges(p string) error {
	real, err := filepath.EvalSymlinks(p)
	if err != nil {
		return err
	}
	for at := real; ; at = filepath.Dir(at) {
		fi, err := os.Lstat(at)
		if err != nil {
			return err
		}
		uid, _, ok := ownerOf(fi)
		if !ok || uid != 0 || fi.Mode().Perm()&0o022 != 0 {
			return fmt.Errorf("%s may be changed by someone other than root (%s, owner %d), so OpenSearch is not run from it", at, fi.Mode(), uid)
		}
		if at == "/" {
			return nil
		}
	}
}

func (linuxOpenSearch) exists() bool {
	_, err := os.Stat(unitFile())
	return err == nil
}

func systemctl(args ...string) error {
	out, err := exec.Command("systemctl", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemctl %s failed (%w): %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (linuxOpenSearch) stop() error { return systemctl("stop", oslocal.ServiceName) }

func (linuxOpenSearch) remove() error {
	systemctl("disable", oslocal.ServiceName)
	if err := os.Remove(unitFile()); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return systemctl("daemon-reload")
}

func (linuxOpenSearch) install(l oslocal.Layout, home string) error {
	uid, gid, err := openSearchAccount(l)
	if err != nil {
		return err
	}
	// It may change its config (its keystore), data, logs and temporary
	// files; the CA and the download stay root's.
	for _, d := range l.ServiceFolders() {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return err
		}
		if err := giveTree(d, uid, gid, chownFD); err != nil {
			return fmt.Errorf("could not give %s to %s: %w", d, openSearchUser, err)
		}
	}
	if err := giveClientFiles(l); err != nil {
		return err
	}
	maxMapCount()
	if err := os.WriteFile(unitFile(), []byte(openSearchUnit(l, home)), 0o644); err != nil {
		return err
	}
	if err := systemctl("daemon-reload"); err != nil {
		return err
	}
	if err := systemctl("enable", oslocal.ServiceName); err != nil {
		return err
	}
	fmt.Printf("Installed the %s service; it runs as %s.\n", oslocal.ServiceName, openSearchUser)
	return nil
}

// openSearchAccount returns the account OpenSearch runs as, making it the
// first time.
func openSearchAccount(l oslocal.Layout) (uid, gid int, err error) {
	u, err := user.Lookup(openSearchUser)
	if err != nil {
		shell := "/bin/false"
		for _, s := range []string{"/usr/sbin/nologin", "/sbin/nologin"} {
			if _, err := os.Stat(s); err == nil {
				shell = s
				break
			}
		}
		out, err := exec.Command("useradd", "--system", "--user-group", "--no-create-home", "--home-dir", l.Data,
			"--shell", shell, "--comment", "OpenSearch for Signalith", openSearchUser).CombinedOutput()
		if err != nil {
			return 0, 0, fmt.Errorf("could not make the %s account (%w): %s", openSearchUser, err, strings.TrimSpace(string(out)))
		}
		if u, err = user.Lookup(openSearchUser); err != nil {
			return 0, 0, err
		}
	}
	uid, err1 := strconv.Atoi(u.Uid)
	gid, err2 := strconv.Atoi(u.Gid)
	if err1 != nil || err2 != nil || uid == 0 {
		return 0, 0, fmt.Errorf("the %s account is %s:%s, which OpenSearch does not run as", openSearchUser, u.Uid, u.Gid)
	}
	return uid, gid, nil
}

// giveClientFiles lets Signalith's account read its certificate for
// OpenSearch: the folder and its files go to root, group signalith, which
// may read them. Without that account (Signalith is not installed from its
// packages) they stay root's.
func giveClientFiles(l oslocal.Layout) error {
	_, gid, ok := serviceOwner()
	if !ok {
		return nil
	}
	ca, cert, key := l.ClientFiles()
	for _, f := range []struct {
		path string
		mode os.FileMode
	}{{l.Client, 0o750}, {ca, 0o640}, {cert, 0o640}, {key, 0o640}} {
		fi, err := os.Lstat(f.path)
		if err != nil {
			return err
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%s is a link", f.path)
		}
		if err := os.Lchown(f.path, 0, gid); err != nil {
			return err
		}
		if err := os.Chmod(f.path, f.mode); err != nil {
			return err
		}
	}
	return nil
}

// maxMapCount raises vm.max_map_count to what OpenSearch asks for, now
// and at every boot. OpenSearch on this computer only starts without it,
// but may fail as its indices grow.
func maxMapCount() {
	const want = 262144
	if b, err := os.ReadFile("/proc/sys/vm/max_map_count"); err == nil {
		if n, err := strconv.Atoi(strings.TrimSpace(string(b))); err == nil && n >= want {
			return
		}
	}
	line := fmt.Sprintf("# Written by signalith opensearch install: OpenSearch maps many files.\nvm.max_map_count = %d\n", want)
	if err := os.WriteFile(sysctlFile, []byte(line), 0o644); err != nil {
		fmt.Printf("Warning: could not write %s: %v\n", sysctlFile, err)
	}
	if out, err := exec.Command("sysctl", "-q", "-w", fmt.Sprintf("vm.max_map_count=%d", want)).CombinedOutput(); err != nil {
		fmt.Printf("Warning: could not set vm.max_map_count to %d (%v): %s\n", want, err, strings.TrimSpace(string(out)))
	}
}

// openSearchUnit is the systemd unit for the program in home: OpenSearch's
// own start script with its bundled Java, as its own account, which may
// write only to its config, data, logs and temporary folders.
func openSearchUnit(l oslocal.Layout, home string) string {
	jdk := filepath.Join(home, "jdk")
	return `# Written by signalith opensearch install, which writes it again on
# every install and upgrade; changes here are lost.
[Unit]
Description=OpenSearch for Signalith
Documentation=https://signalith.io/docs/install-packages/
After=network.target
Before=signalith.service

[Service]
Type=simple
User=` + openSearchUser + `
Group=` + openSearchUser + `
WorkingDirectory=` + home + `
Environment=OPENSEARCH_HOME=` + home + `
Environment=OPENSEARCH_PATH_CONF=` + l.Config() + `
Environment=OPENSEARCH_JAVA_HOME=` + jdk + `
Environment=JAVA_HOME=` + jdk + `
Environment=OPENSEARCH_TMPDIR=` + l.Tmp() + `
Environment=OPENSEARCH_JAVA_OPTS=
ExecStart=` + filepath.Join(home, "bin", "opensearch") + ` -q
StandardOutput=journal
StandardError=inherit
# OpenSearch's own limits (as in its packages).
LimitNOFILE=65535
LimitNPROC=4096
LimitAS=infinity
LimitFSIZE=infinity
LimitCORE=0
# It stops by itself on SIGTERM; Java exits 143 then.
KillSignal=SIGTERM
KillMode=process
SendSIGKILL=no
SuccessExitStatus=143
TimeoutStartSec=180
TimeoutStopSec=120
Restart=on-failure
RestartSec=10
UMask=0027

NoNewPrivileges=true
CapabilityBoundingSet=
ProtectSystem=strict
ReadWritePaths=` + strings.Join(l.ServiceFolders(), " ") + `
InaccessiblePaths=-` + l.CA() + ` -` + l.Download() + `
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
ProtectClock=true
ProtectHostname=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK
RestrictNamespaces=true
RestrictRealtime=true
RestrictSUIDSGID=true
LockPersonality=true
SystemCallArchitectures=native

[Install]
WantedBy=multi-user.target
`
}

func (linuxOpenSearch) start() error {
	if err := systemctl("start", oslocal.ServiceName); err != nil {
		return fmt.Errorf("%w. See: journalctl -u %s", err, oslocal.ServiceName)
	}
	return nil
}

func (linuxOpenSearch) securityAdmin(l oslocal.Layout, home string, port int) error {
	cmd := exec.Command(filepath.Join(home, "plugins", "opensearch-security", "tools", "securityadmin.sh"),
		"-cd", l.Security(), "-icl", "-h", "127.0.0.1", "-p", strconv.Itoa(port),
		"-cacert", filepath.Join(l.CA(), ospki.RootCAFile),
		"-cert", filepath.Join(l.CA(), ospki.AdminCertFile),
		"-key", filepath.Join(l.CA(), ospki.AdminKeyFile))
	jdk := filepath.Join(home, "jdk")
	cmd.Env = append(os.Environ(), "OPENSEARCH_JAVA_HOME="+jdk, "JAVA_HOME="+jdk, "OPENSEARCH_PATH_CONF="+l.Config())
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("securityadmin.sh failed (%w):\n%s", err, out)
	}
	return nil
}

func (linuxOpenSearch) memoryMB() uint64 {
	var si unix.Sysinfo_t
	if err := unix.Sysinfo(&si); err != nil {
		return 4096
	}
	return uint64(si.Totalram) * uint64(si.Unit) / (1024 * 1024)
}

// afterOpenSearchInstall sets Signalith to use the OpenSearch installed.
func afterOpenSearchInstall(out io.Writer, l oslocal.Layout) error { return connectSignalith(out, l) }

// signalithConfigFile is Signalith's config as its packages install it.
var signalithConfigFile = "/etc/signalith/signalith.yaml"

// restartSignalith restarts Signalith's service if it runs.
var restartSignalith = func() error { return exec.Command("systemctl", "try-restart", "signalith").Run() }

// connectSignalith sets Signalith on this computer to keep its events in
// the OpenSearch just installed, signing in with its certificate, and
// restarts it if it runs. The settings go to the Settings page's file, so
// the page shows them.
func connectSignalith(out io.Writer, l oslocal.Layout) error {
	if _, err := os.Stat(signalithConfigFile); err != nil {
		fmt.Fprintf(out, "Signalith is not installed from its packages here (no %s). Give it the address and certificate above "+
			"on the Settings page (OpenSearch).\n", signalithConfigFile)
		return nil
	}
	st, err := oslocal.LoadState(l)
	if err != nil || st == nil {
		return err
	}
	pf := config.PageFile{Config: signalithConfigFile}
	p, err := pf.Read()
	if err != nil {
		return err
	}
	const by = "signalith opensearch install"
	now := time.Now()
	ca, cert, key := l.ClientFiles()
	for k, v := range map[string]any{
		"opensearch.url":             st.URL(),
		"opensearch.ca_file":         ca,
		"opensearch.cert_file":       cert,
		"opensearch.key_file":        key,
		"opensearch.tls_skip_verify": false,
		// It signs in with its certificate only.
		"opensearch.username": "",
	} {
		if err := p.Set(k, v, by, now); err != nil {
			return err
		}
	}
	p.Remove("opensearch.password")
	if err := pf.Write(p); err != nil {
		return err
	}
	fmt.Fprintf(out, "Signalith now keeps its events in this OpenSearch (%s), signing in with its certificate in %s.\n", st.URL(), l.Client)
	if err := restartSignalith(); err != nil {
		fmt.Fprintf(out, "Restart Signalith to use it: sudo systemctl restart signalith (%v)\n", err)
	}
	return nil
}
