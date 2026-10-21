// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package main

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
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
	// Signalith's certificate goes in a folder only root may change.
	if parent := filepath.Dir(l.Client); parent != "" {
		if _, err := os.Stat(parent); err == nil {
			if err := onlyRootChanges(parent); err != nil {
				return err
			}
		}
	}
	if home == "" {
		return nil
	}
	// The service runs it, and root runs its tools, so only root may
	// change any of it.
	return rootTree(home)
}

// rootTree checks that only root can change dir, the folders above it
// and everything in it.
func rootTree(dir string) error {
	if err := onlyRootChanges(dir); err != nil {
		return err
	}
	return filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		fi, err := d.Info()
		if err != nil {
			return err
		}
		uid, _, ok := ownerOf(fi)
		// A link's own mode means nothing; where it points is checked
		// as its own entry, since it stays in the tree.
		if !ok || uid != 0 || fi.Mode()&os.ModeSymlink == 0 && fi.Mode().Perm()&0o022 != 0 {
			return fmt.Errorf("%s may be changed by someone other than root (%s, owner %d), so OpenSearch is not run from it", p, fi.Mode(), uid)
		}
		return nil
	})
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
	// It may change its data, logs and temporary files only. Its config
	// stays root's, which it may read; the CA and the download stay root's
	// alone.
	for _, d := range serviceFolders(l) {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return err
		}
		if err := giveTree(d, uid, gid, chownFD); err != nil {
			return fmt.Errorf("could not give %s to %s: %w", d, openSearchUser, err)
		}
	}
	if err := makeKeystore(l, home); err != nil {
		return err
	}
	if err := shareConfig(l.Config(), gid); err != nil {
		return err
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

// serviceFolders are the folders the service may change on Linux.
func serviceFolders(l oslocal.Layout) []string { return []string{l.DataDir(), l.Logs(), l.Tmp()} }

// toolEnv is the environment root runs OpenSearch's tools in: only
// what they need, none of root's own Java options.
func toolEnv(l oslocal.Layout, home string) []string {
	jdk := filepath.Join(home, "jdk")
	return []string{
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"OPENSEARCH_HOME=" + home,
		"OPENSEARCH_PATH_CONF=" + l.Config(),
		"OPENSEARCH_JAVA_HOME=" + jdk,
		"JAVA_HOME=" + jdk,
		"JAVA_OPTS=",
		"OPENSEARCH_JAVA_OPTS=",
	}
}

// makeKeystore makes OpenSearch's keystore anew, empty, as root:
// OpenSearch makes one when there is none, and cannot in its config
// folder, which it may not change.
func makeKeystore(l oslocal.Layout, home string) error {
	root, err := os.OpenRoot(l.Config())
	if err != nil {
		return err
	}
	err = root.Remove("opensearch.keystore")
	root.Close()
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	cmd := exec.Command(filepath.Join(home, "bin", "opensearch-keystore"), "create")
	cmd.Env = toolEnv(l, home)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("opensearch-keystore create failed (%w): %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// shareConfig gives the config folder and everything in it to root,
// group gid, which may read it but not change it. It holds only folders
// and plain files: anything else is refused, never followed.
func shareConfig(dir string, gid int) error {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer root.Close()
	return fs.WalkDir(root.FS(), ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		mode := os.FileMode(0o640)
		switch {
		case d.IsDir():
			mode = 0o750
		case !d.Type().IsRegular():
			return fmt.Errorf("%s is not a file or a folder, so OpenSearch's settings are not given to it", filepath.Join(dir, p))
		}
		if err := root.Lchown(p, 0, gid); err != nil {
			return err
		}
		return root.Chmod(p, mode)
	})
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
	if err := checkAccount(uid, gid); err != nil {
		return 0, 0, err
	}
	return uid, gid, nil
}

// Where accounts are listed; the tests change them.
var (
	passwdFile = "/etc/passwd"
	groupFile  = "/etc/group"
)

// checkAccount checks the account OpenSearch runs as, uid:gid, is one
// made for it: a system account that cannot sign in, alone in a group of
// its own name, which may read its certificates and keystore.
func checkAccount(uid, gid int) error {
	bad := func(why string) error {
		return fmt.Errorf("the %s account is not one made for OpenSearch alone (%s), so OpenSearch is not set up to run as it; "+
			"remove it (sudo userdel %s) and run the install again", openSearchUser, why, openSearchUser)
	}
	if uid >= 1000 || gid >= 1000 {
		return bad(fmt.Sprintf("%d:%d is not a system account's", uid, gid))
	}
	passwd, err := os.ReadFile(passwdFile)
	if err != nil {
		return err
	}
	found := false
	for _, line := range strings.Split(string(passwd), "\n") {
		f := strings.Split(line, ":")
		if len(f) < 7 {
			continue
		}
		if f[0] == openSearchUser {
			found = true
			if shell := filepath.Base(f[6]); shell != "nologin" && shell != "false" {
				return bad("it may sign in, with " + f[6])
			}
		} else if f[3] == strconv.Itoa(gid) {
			return bad(f[0] + " is in its group too")
		}
	}
	if !found {
		return bad("it is not in " + passwdFile)
	}
	group, err := os.ReadFile(groupFile)
	if err != nil {
		return err
	}
	for _, line := range strings.Split(string(group), "\n") {
		f := strings.Split(line, ":")
		if len(f) < 4 || f[2] != strconv.Itoa(gid) {
			continue
		}
		if f[0] != openSearchUser {
			return bad("its group is " + f[0])
		}
		for _, m := range strings.Split(f[3], ",") {
			if m != "" && m != openSearchUser {
				return bad(m + " is in its group too")
			}
		}
		return nil
	}
	return bad(fmt.Sprintf("its group %d is not in %s", gid, groupFile))
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
// write only to its data, logs and temporary folders, and reach only this
// computer.
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
# It stops by itself on SIGTERM (Java exits 143 then); what is left
# after TimeoutStopSec is killed.
KillSignal=SIGTERM
KillMode=mixed
SuccessExitStatus=143
TimeoutStartSec=180
TimeoutStopSec=120
Restart=on-failure
RestartSec=10
UMask=0027

NoNewPrivileges=true
CapabilityBoundingSet=
ProtectSystem=strict
ReadWritePaths=` + strings.Join(serviceFolders(l), " ") + `
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
ProtectProc=invisible
PrivateIPC=true
RemoveIPC=true
# It listens on 127.0.0.1 and talks to nothing else.
IPAddressDeny=any
IPAddressAllow=localhost

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
	cmd.Env = toolEnv(l, home)
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
