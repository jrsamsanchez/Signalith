// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package security

import (
	"errors"
	"net/netip"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

// sysFS reads Linux's /proc and /sys. The probes go through it so tests
// can give them a fake tree on any system, links and all.
type sysFS interface {
	ReadFile(name string) ([]byte, error)
	// ReadDir lists the names in a folder.
	ReadDir(name string) ([]string, error)
	// Resolve follows the links in name and returns the real path.
	Resolve(name string) (string, error)
}

// osFS is the real /proc and /sys, under root ("/" normally).
type osFS struct{ root string }

func (o osFS) at(name string) string { return filepath.Join(o.root, filepath.FromSlash(name)) }

func (o osFS) ReadFile(name string) ([]byte, error) { return os.ReadFile(o.at(name)) }

func (o osFS) ReadDir(name string) ([]string, error) {
	list, err := os.ReadDir(o.at(name))
	var out []string
	for _, e := range list {
		out = append(out, e.Name())
	}
	return out, err
}

func (o osFS) Resolve(name string) (string, error) {
	real, err := filepath.EvalSymlinks(o.at(name))
	if err != nil {
		return "", err
	}
	rel, err := filepath.Rel(o.root, real)
	if err != nil {
		return "", err
	}
	return "/" + filepath.ToSlash(rel), nil
}

// mapFS is a fake tree for tests: files by path, and links from a path
// to a target relative to the link's folder (or absolute).
type mapFS struct {
	files map[string]string
	links map[string]string
}

func (m mapFS) resolve(name string) string {
	parts := strings.Split(strings.Trim(path.Clean(name), "/"), "/")
	cur := "/"
	for hops := 0; len(parts) > 0 && hops < 64; {
		next := path.Join(cur, parts[0])
		parts = parts[1:]
		if t, ok := m.links[next]; ok {
			hops++
			if !path.IsAbs(t) {
				t = path.Join(cur, t)
			}
			rest := strings.Split(strings.Trim(path.Clean(t), "/"), "/")
			parts = append(rest, parts...)
			cur = "/"
			continue
		}
		cur = next
	}
	return cur
}

func (m mapFS) ReadFile(name string) ([]byte, error) {
	if s, ok := m.files[m.resolve(name)]; ok {
		return []byte(s), nil
	}
	return nil, os.ErrNotExist
}

func (m mapFS) ReadDir(name string) ([]string, error) {
	dir := m.resolve(name) + "/"
	seen := map[string]bool{}
	var out []string
	add := func(p string) {
		if rest, ok := strings.CutPrefix(p, dir); ok && rest != "" {
			n, _, _ := strings.Cut(rest, "/")
			if !seen[n] {
				seen[n] = true
				out = append(out, n)
			}
		}
	}
	for p := range m.files {
		add(p)
	}
	for p := range m.links {
		add(p)
	}
	if len(out) == 0 {
		return nil, os.ErrNotExist
	}
	slices.Sort(out)
	return out, nil
}

func (m mapFS) Resolve(name string) (string, error) {
	r := m.resolve(name)
	if _, ok := m.files[r]; ok {
		return r, nil
	}
	if _, err := m.ReadDir(r); err == nil {
		return r, nil
	}
	return "", os.ErrNotExist
}

func readText(fs sysFS, name string) string {
	b, err := fs.ReadFile(name)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func exists(fs sysFS, name string) bool {
	_, err := fs.Resolve(name)
	return err == nil
}

// mount is a line of /proc/<pid>/mountinfo.
type mount struct {
	Major, Minor int
	Point        string
	Options      []string
	FSType       string
	Source       string
	SuperOptions []string
}

// unescapeMount undoes mountinfo's octal escapes (\040 for a space).
func unescapeMount(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			if n, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(n))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// parseMountinfo reads mountinfo lines.
func parseMountinfo(data string) []mount {
	var out []mount
	for _, line := range strings.Split(data, "\n") {
		f := strings.Fields(line)
		sep := slices.Index(f, "-")
		if len(f) < 7 || sep < 6 || sep+2 >= len(f) {
			continue
		}
		var m mount
		maj, min, _ := strings.Cut(f[2], ":")
		m.Major, _ = strconv.Atoi(maj)
		m.Minor, _ = strconv.Atoi(min)
		m.Point = unescapeMount(f[4])
		m.Options = strings.Split(f[5], ",")
		m.FSType = f[sep+1]
		m.Source = unescapeMount(f[sep+2])
		if sep+3 < len(f) {
			m.SuperOptions = strings.Split(f[sep+3], ",")
		}
		out = append(out, m)
	}
	return out
}

// mountOf returns the mount that holds p: the longest mount point that
// is p or a folder above it, the last one mounted when several are.
func mountOf(mounts []mount, p string) (mount, bool) {
	best, found := mount{}, false
	for _, m := range mounts {
		under := m.Point == "/" || p == m.Point || strings.HasPrefix(p, strings.TrimSuffix(m.Point, "/")+"/")
		if under && (!found || len(m.Point) >= len(best.Point)) {
			best, found = m, true
		}
	}
	return best, found
}

// Filesystem types that are network or host shares, memory, or
// encrypted by themselves.
var (
	networkFS   = []string{"nfs", "nfs4", "cifs", "smb3", "smbfs", "fuse.sshfs", "9p", "virtiofs", "ceph", "glusterfs", "fuse.glusterfs", "lustre"}
	memoryFS    = []string{"tmpfs", "ramfs"}
	encryptedFS = map[string]string{"ecryptfs": "eCryptfs", "fuse.gocryptfs": "gocryptfs"}
)

// detectDisk finds out whether the filesystem that holds p (a path with
// no links left in it) is encrypted, from mountinfo and /sys. It needs
// no /dev, so it works under PrivateDevices=yes. vm names the virtual
// machine's host when this is one.
func detectDisk(fs sysFS, mountinfo, p string, vm vmInfo) Disk {
	return detectDiskDepth(fs, mountinfo, p, vm, 0)
}

func detectDiskDepth(fs sysFS, mountinfo, p string, vm vmInfo, depth int) Disk {
	d := Disk{Path: p, Kind: DiskUnknown}
	m, ok := mountOf(parseMountinfo(mountinfo), p)
	if !ok {
		return d
	}
	d.MountPoint, d.FSType, d.Source = m.Point, m.FSType, m.Source
	switch {
	case slices.Contains(networkFS, m.FSType):
		d.Kind = DiskNetwork
		return d
	case slices.Contains(memoryFS, m.FSType):
		d.Kind = DiskMemory
		return d
	case encryptedFS[m.FSType] != "":
		d.Kind, d.Method = DiskEncrypted, encryptedFS[m.FSType]
		return d
	case m.FSType == "zfs":
		d.Kind, d.FSType = DiskUnreadable, "ZFS"
		return d
	}
	dev := blockDevice(fs, m)
	if dev == "" {
		return d
	}
	d.Device = deviceName(fs, dev)
	// A loop device: look at the filesystem of the file behind it, once.
	if strings.HasPrefix(path.Base(dev), "loop") && depth == 0 {
		if back := readText(fs, dev+"/loop/backing_file"); back != "" {
			inner := detectDiskDepth(fs, mountinfo, strings.TrimSuffix(back, " (deleted)"), vm, depth+1)
			inner.Path, inner.Device = p, d.Device
			return inner
		}
	}
	if method, ok := cryptLayer(fs, dev, 0); ok {
		d.Kind, d.Method = DiskEncrypted, method
		return d
	}
	if vm.Virtual {
		d.Kind, d.Provider = DiskVirtual, vm.Provider
		return d
	}
	d.Kind = DiskPlain
	return d
}

// blockDevice finds the /sys folder of the block device a mount is on.
func blockDevice(fs sysFS, m mount) string {
	if m.Major != 0 {
		if dev, err := fs.Resolve("/sys/dev/block/" + strconv.Itoa(m.Major) + ":" + strconv.Itoa(m.Minor)); err == nil {
			return dev
		}
	}
	// btrfs and others report major 0: go by the mount's source.
	src := m.Source
	if !strings.HasPrefix(src, "/dev/") {
		return ""
	}
	if name, ok := strings.CutPrefix(src, "/dev/mapper/"); ok {
		list, _ := fs.ReadDir("/sys/class/block")
		for _, b := range list {
			if strings.HasPrefix(b, "dm-") && readText(fs, "/sys/class/block/"+b+"/dm/name") == name {
				if dev, err := fs.Resolve("/sys/class/block/" + b); err == nil {
					return dev
				}
			}
		}
		return ""
	}
	if dev, err := fs.Resolve("/sys/class/block/" + path.Base(src)); err == nil {
		return dev
	}
	return ""
}

// deviceName names a block device as people know it: /dev/mapper/name
// for device-mapper ones, else /dev/name.
func deviceName(fs sysFS, dev string) string {
	if name := readText(fs, dev+"/dm/name"); name != "" {
		return "/dev/mapper/" + name
	}
	return "/dev/" + path.Base(dev)
}

// cryptLayer reports whether dev, or every device under it, is a
// dm-crypt device, and which kind (LUKS2, BitLocker...).
func cryptLayer(fs sysFS, dev string, depth int) (string, bool) {
	if depth > 16 {
		return "", false
	}
	if uuid := readText(fs, dev+"/dm/uuid"); strings.HasPrefix(uuid, "CRYPT-") {
		kind, _, _ := strings.Cut(strings.TrimPrefix(uuid, "CRYPT-"), "-")
		switch kind {
		case "PLAIN":
			return "dm-crypt", true
		case "BITLK":
			return "BitLocker", true
		case "TCRYPT":
			return "VeraCrypt", true
		case "":
			return "dm-crypt", true
		}
		return kind, true
	}
	slaves, _ := fs.ReadDir(dev + "/slaves")
	if len(slaves) > 0 {
		method := ""
		for _, s := range slaves {
			under, err := fs.Resolve(dev + "/slaves/" + s)
			if err != nil {
				return "", false
			}
			m, ok := cryptLayer(fs, under, depth+1)
			if !ok {
				return "", false
			}
			method = m
		}
		return method, true
	}
	// A partition: look at the disk it is part of.
	if exists(fs, dev+"/partition") {
		return cryptLayer(fs, path.Dir(dev), depth+1)
	}
	return "", false
}

// vmInfo says whether this is a virtual machine, and whose.
type vmInfo struct {
	Virtual  bool
	Provider string
}

// hypervisors maps words in the DMI vendor or product to the host's
// name as people know it.
var hypervisors = []struct{ word, name string }{
	{"amazon ec2", "Amazon EC2"},
	{"google", "Google Cloud"},
	{"digitalocean", "DigitalOcean"},
	{"hetzner", "Hetzner"},
	{"openstack", "OpenStack"},
	{"vmware", "VMware"},
	{"virtualbox", "VirtualBox"},
	{"innotek", "VirtualBox"},
	{"parallels", "Parallels"},
	{"xen", "Xen"},
	{"qemu", "QEMU"},
	{"kvm", "KVM"},
	{"bochs", "QEMU"},
}

// providerOf names a hypervisor or cloud from a vendor and product, or
// "" when neither names one.
func providerOf(vendor, product string) string {
	v, p := strings.ToLower(vendor), strings.ToLower(product)
	if strings.Contains(v, "microsoft") && strings.Contains(p, "virtual machine") {
		return "Hyper-V"
	}
	for _, h := range hypervisors {
		if strings.Contains(v, h.word) || strings.Contains(p, h.word) {
			return h.name
		}
	}
	return ""
}

// detectVM reads the CPU flags and the DMI vendor.
func detectVM(fs sysFS) vmInfo {
	provider := providerOf(readText(fs, "/sys/class/dmi/id/sys_vendor"), readText(fs, "/sys/class/dmi/id/product_name"))
	if provider != "" {
		return vmInfo{Virtual: true, Provider: provider}
	}
	return vmInfo{Virtual: hasCPUFlag(fs, "hypervisor")}
}

func hasCPUFlag(fs sysFS, flag string) bool {
	for _, line := range strings.Split(readText(fs, "/proc/cpuinfo"), "\n") {
		k, v, ok := strings.Cut(line, ":")
		if ok && strings.TrimSpace(k) == "flags" {
			return slices.Contains(strings.Fields(v), flag)
		}
	}
	return false
}

// confidentialVM names the confidential VM technology this runs in, or
// "".
func confidentialVM(fs sysFS) string {
	switch {
	case exists(fs, "/sys/class/misc/sev-guest"):
		return "AMD SEV-SNP"
	case exists(fs, "/sys/class/misc/tdx_guest") || hasCPUFlag(fs, "tdx_guest"):
		return "Intel TDX"
	}
	return ""
}

// procStatus reads the fields of /proc/<pid>/status.
func procStatus(fs sysFS, pid string) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(readText(fs, "/proc/"+pid+"/status"), "\n") {
		if k, v, ok := strings.Cut(line, ":"); ok {
			out[k] = strings.TrimSpace(v)
		}
	}
	return out
}

// capNetBindService is the one capability the systemd unit keeps.
const capNetBindService = 1 << 10

// readProcess fills in the protections of process pid from its status
// and mount table, and whether it runs under systemd or in a container.
func readProcess(fs sysFS, pid string, p *ProcessFacts) error {
	if _, err := fs.ReadFile("/proc/" + pid + "/status"); err != nil {
		return err
	}
	st := procStatus(fs, pid)
	if len(st) == 0 {
		return errors.New("no status")
	}
	p.Known = true
	if uid := strings.Fields(st["Uid"]); len(uid) > 1 {
		p.UID, _ = strconv.Atoi(uid[1])
		p.Root = p.UID == 0
	}
	p.NoNewPrivs = st["NoNewPrivs"] == "1"
	p.Seccomp = st["Seccomp"] == "2"
	if eff, err := strconv.ParseUint(st["CapEff"], 16, 64); err == nil {
		p.NoCaps = eff&^capNetBindService == 0
		p.NoCapsAtAll = eff == 0
	}
	p.Umask077 = st["Umask"] == "0077"
	mounts := parseMountinfo(readText(fs, "/proc/"+pid+"/mountinfo"))
	for _, m := range mounts {
		switch m.Point {
		case "/":
			p.ReadOnlyRoot = slices.Contains(m.Options, "ro")
		case "/proc":
			p.HiddenProc = slices.ContainsFunc(m.SuperOptions, func(o string) bool {
				return o == "hidepid=invisible" || o == "hidepid=2" || o == "hidepid=ptraceable" || o == "hidepid=4"
			})
		case "/dev":
			p.PrivateDev = m.FSType == "tmpfs"
		}
	}
	return nil
}

// dumpValues are the values of a LocalDumps registry key, and which of
// them are set.
type dumpValues struct {
	Type, Flags                  uint64
	Folder                       string
	HasType, HasFlags, HasFolder bool
}

// miniDumpWithFullMemory is the CustomDumpFlags bit for all of memory.
const miniDumpWithFullMemory = 0x2

// mergeDumps works out what Windows Error Reporting does for
// signalith.exe from the global LocalDumps key at base and its own key
// under it (when appOK). The program's key sets only the values it has;
// the others come from the global key, or default to a mini dump.
func mergeDumps(global, app dumpValues, appOK bool, base string) MemoryFacts {
	m := MemoryFacts{Known: true}
	t, flags, folder := uint64(1), uint64(0), ""
	typeAt, flagsAt := base, base
	if global.HasType {
		t = global.Type
	}
	if global.HasFlags {
		flags = global.Flags
	}
	if global.HasFolder {
		folder = global.Folder
	}
	if appOK {
		at := base + `\signalith.exe`
		if app.HasType {
			t, typeAt = app.Type, at
		}
		if app.HasFlags {
			flags, flagsAt = app.Flags, at
		}
		if app.HasFolder {
			folder = app.Folder
		}
	}
	switch {
	case t == 2:
		m.FullDumps, m.DumpsRegistry = true, typeAt
	case t == 0 && flags&miniDumpWithFullMemory != 0:
		// A custom dump that holds all of memory.
		m.FullDumps, m.DumpsRegistry = true, flagsAt
	}
	if m.FullDumps {
		m.DumpFolder = folder
	}
	return m
}

// releaseAtLeast reports whether a Linux release, such as
// "4.18.0-553.el8.x86_64", is major.minor or newer; true when it can't be
// read.
func releaseAtLeast(release string, major, minor int) bool {
	parts := strings.SplitN(release, ".", 3)
	if len(parts) < 2 {
		return true
	}
	// The minor number may run into what follows, as in 5.8-rc1.
	digits := func(s string) string {
		if i := strings.IndexFunc(s, func(r rune) bool { return r < '0' || r > '9' }); i >= 0 {
			return s[:i]
		}
		return s
	}
	ma, err1 := strconv.Atoi(parts[0])
	mi, err2 := strconv.Atoi(digits(parts[1]))
	if err1 != nil || err2 != nil {
		return true
	}
	return ma > major || ma == major && mi >= minor
}

// coreLimit reads "Max core file size" from /proc/<pid>/limits: whether
// its soft limit is 0.
func coreLimitOff(fs sysFS, pid string) (off, known bool) {
	for _, line := range strings.Split(readText(fs, "/proc/"+pid+"/limits"), "\n") {
		if rest, ok := strings.CutPrefix(line, "Max core file size"); ok {
			f := strings.Fields(rest)
			if len(f) > 0 {
				return f[0] == "0", true
			}
		}
	}
	return false, false
}

// notDumpable tells from outside whether a process is dumpable: Linux
// gives the files in a process's /proc/<pid> to root when it is not
// dumpable, and to its effective user when it is. owner is the owner of
// /proc/<pid>/status (-1 when unread) and euid the process's effective
// user. A process running as
// root can't be told either way.
func notDumpable(owner, euid int) (not, unknown bool) {
	switch {
	case owner < 0 || euid == 0:
		return false, true
	case owner == euid:
		return false, false
	case owner == 0:
		return true, false
	}
	return false, true
}

// swapFacts reads whether swap is on, whether every swap device is
// encrypted, and whether the cgroup of pid turns swap off.
func swapFacts(fs sysFS, mountinfo, pid string, m *MemoryFacts) {
	lines := strings.Split(readText(fs, "/proc/swaps"), "\n")
	var devs []string
	for _, l := range lines[min(1, len(lines)):] {
		if f := strings.Fields(l); len(f) > 0 {
			devs = append(devs, f[0])
		}
	}
	m.SwapOn = len(devs) > 0
	m.SwapEncrypted = m.SwapOn
	for _, d := range devs {
		ok := false
		if strings.HasPrefix(d, "/dev/") {
			if dev := blockDevice(fs, mount{Source: d}); dev != "" {
				_, ok = cryptLayer(fs, dev, 0)
			}
		} else if strings.HasPrefix(d, "/") {
			// A swap file: encrypted when its filesystem is.
			ok = detectDisk(fs, mountinfo, d, vmInfo{}).Kind == DiskEncrypted
		}
		if !ok {
			m.SwapEncrypted = false
		}
	}
	// cgroup v2: 0::/system.slice/signalith.service
	for _, line := range strings.Split(readText(fs, "/proc/"+pid+"/cgroup"), "\n") {
		if rest, ok := strings.CutPrefix(line, "0::"); ok {
			if readText(fs, path.Join("/sys/fs/cgroup", rest, "memory.swap.max")) == "0" {
				m.SwapOffForUs = true
			}
		}
	}
}

// defaultGateway reads the IPv4 default route's gateway from
// /proc/net/route, where addresses are hex in the machine's (little
// endian) byte order.
func defaultGateway(fs sysFS) (netip.Addr, bool) {
	data, err := fs.ReadFile("/proc/net/route")
	if err != nil {
		return netip.Addr{}, false
	}
	for _, line := range strings.Split(string(data), "\n")[1:] {
		f := strings.Fields(line)
		if len(f) < 3 || f[1] != "00000000" || len(f[2]) != 8 {
			continue
		}
		var b [4]byte
		ok := true
		for i := range 4 {
			v, err := strconv.ParseUint(f[2][2*i:2*i+2], 16, 8)
			if err != nil {
				ok = false
				break
			}
			b[3-i] = byte(v)
		}
		if a := netip.AddrFrom4(b); ok && !a.IsUnspecified() {
			return a, true
		}
	}
	return netip.Addr{}, false
}

// procAccount reads the effective user and group of process pid from
// its status file.
func procAccount(fs sysFS, pid string) (Account, bool) {
	data, err := fs.ReadFile("/proc/" + pid + "/status")
	if err != nil {
		return Account{}, false
	}
	a, found := Account{UID: -1, GID: -1}, 0
	for _, line := range strings.Split(string(data), "\n") {
		k, v, ok := strings.Cut(line, ":")
		f := strings.Fields(v)
		if !ok || len(f) < 2 {
			continue
		}
		n, err := strconv.Atoi(f[1]) // real, effective, saved, filesystem
		if err != nil {
			continue
		}
		switch k {
		case "Uid":
			a.UID = n
			found++
		case "Gid":
			a.GID = n
			found++
		}
	}
	return a, found == 2
}
