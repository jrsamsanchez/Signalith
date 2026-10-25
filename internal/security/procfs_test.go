// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package security

import (
	"testing"
)

// mi builds a mountinfo line.
func mi(id int, majmin, point, opts, fstype, source, super string) string {
	return itoa(id) + " 1 " + majmin + " / " + point + " " + opts + " shared:1 - " + fstype + " " + source + " " + super + "\n"
}

const pci = "/sys/devices/pci0000:00/0000:00:1f.2/ata1/host0/target0:0:0/0:0:0:0/block/sda"

// tree is a fake /sys with sda (partitions sda1-sda3), and device-mapper
// devices as given: name, uuid and the devices under each.
func tree(dms ...[3]string) mapFS {
	m := mapFS{files: map[string]string{
		pci + "/size":                  "1000",
		pci + "/sda1/partition":        "1",
		pci + "/sda2/partition":        "2",
		pci + "/sda3/partition":        "3",
		"/sys/class/dmi/id/sys_vendor": "Dell Inc.",
		"/proc/cpuinfo":                "processor\t: 0\nflags\t\t: fpu vme sse2\n",
	}, links: map[string]string{
		"/sys/dev/block/8:0":    pci,
		"/sys/dev/block/8:1":    pci + "/sda1",
		"/sys/dev/block/8:2":    pci + "/sda2",
		"/sys/dev/block/8:3":    pci + "/sda3",
		"/sys/class/block/sda":  pci,
		"/sys/class/block/sda2": pci + "/sda2",
		"/sys/class/block/sda3": pci + "/sda3",
	}}
	for i, d := range dms {
		dev := "/sys/devices/virtual/block/dm-" + itoa(i)
		m.files[dev+"/dm/name"] = d[0]
		m.files[dev+"/dm/uuid"] = d[1]
		m.links["/sys/dev/block/253:"+itoa(i)] = dev
		m.links["/sys/class/block/dm-"+itoa(i)] = dev
		if d[2] != "" {
			target := pci + "/" + d[2]
			if len(d[2]) > 3 && d[2][:3] == "dm-" {
				target = "/sys/devices/virtual/block/" + d[2]
			}
			m.links[dev+"/slaves/"+d[2]] = target
		}
	}
	return m
}

func TestDetectDisk(t *testing.T) {
	luks := [3]string{"luks-abc", "CRYPT-LUKS2-abc-luks-abc", "sda3"}
	lvm := [3]string{"vg-root", "LVM-xyz", "dm-0"}
	cases := []struct {
		name      string
		fs        mapFS
		mountinfo string
		path      string
		vm        vmInfo
		kind      string
		method    string
		device    string
	}{
		{"LUKS2 on a partition", tree(luks), mi(1, "253:0", "/", "rw", "ext4", "/dev/mapper/luks-abc", "rw"), "/var/lib/signalith",
			vmInfo{}, DiskEncrypted, "LUKS2", "/dev/mapper/luks-abc"},
		{"LVM on LUKS", tree(luks, lvm), mi(1, "253:1", "/", "rw", "ext4", "/dev/mapper/vg-root", "rw"), "/etc/signalith",
			vmInfo{}, DiskEncrypted, "LUKS2", "/dev/mapper/vg-root"},
		{"LUKS on LVM", tree([3]string{"vg-data", "LVM-xyz", "sda3"}, [3]string{"luks-data", "CRYPT-LUKS1-def-luks-data", "dm-0"}),
			mi(1, "253:1", "/var", "rw", "xfs", "/dev/mapper/luks-data", "rw") + mi(2, "8:2", "/", "rw", "ext4", "/dev/sda2", "rw"),
			"/var/lib/signalith", vmInfo{}, DiskEncrypted, "LUKS1", "/dev/mapper/luks-data"},
		{"btrfs on LUKS", tree(luks), mi(1, "0:35", "/", "rw", "btrfs", "/dev/mapper/luks-abc", "rw,subvol=/@"), "/var/lib/signalith",
			vmInfo{}, DiskEncrypted, "LUKS2", "/dev/mapper/luks-abc"},
		{"btrfs plain", tree(), mi(1, "0:35", "/", "rw", "btrfs", "/dev/sda2", "rw"), "/var/lib/signalith",
			vmInfo{}, DiskPlain, "", "/dev/sda2"},
		{"plain partition", tree(), mi(1, "8:2", "/", "rw", "ext4", "/dev/sda2", "rw"), "/var/lib/signalith",
			vmInfo{}, DiskPlain, "", "/dev/sda2"},
		{"plain in a VM", tree(), mi(1, "8:2", "/", "rw", "ext4", "/dev/sda2", "rw"), "/var/lib/signalith",
			vmInfo{Virtual: true, Provider: "Amazon EC2"}, DiskVirtual, "", "/dev/sda2"},
		{"LUKS in a VM", tree(luks), mi(1, "253:0", "/", "rw", "ext4", "/dev/mapper/luks-abc", "rw"), "/srv",
			vmInfo{Virtual: true}, DiskEncrypted, "LUKS2", "/dev/mapper/luks-abc"},
		{"NFS", tree(), mi(1, "8:2", "/", "rw", "ext4", "/dev/sda2", "rw") + mi(2, "0:50", "/var/lib/signalith", "rw", "nfs4", "nas:/export", "rw"),
			"/var/lib/signalith/keys", vmInfo{}, DiskNetwork, "", ""},
		{"tmpfs", tree(), mi(1, "0:22", "/run", "rw", "tmpfs", "tmpfs", "rw"), "/run/signalith", vmInfo{}, DiskMemory, "", ""},
		{"ZFS", tree(), mi(1, "0:40", "/", "rw", "zfs", "rpool/ROOT", "rw"), "/var/lib/signalith", vmInfo{}, DiskUnreadable, "", ""},
		{"BitLocker under Linux", tree([3]string{"bitlk", "CRYPT-BITLK-x-bitlk", "sda3"}), mi(1, "253:0", "/", "rw", "ntfs3", "/dev/mapper/bitlk", "rw"),
			"/mnt", vmInfo{}, DiskEncrypted, "BitLocker", "/dev/mapper/bitlk"},
		{"no mount", tree(), "", "/x", vmInfo{}, DiskUnknown, "", ""},
		{"mount point with a space", tree(luks), mi(1, "8:2", "/", "rw", "ext4", "/dev/sda2", "rw") + mi(2, "253:0", `/srv/my\040data`, "rw", "ext4", "/dev/mapper/luks-abc", "rw"),
			"/srv/my data/state", vmInfo{}, DiskEncrypted, "LUKS2", "/dev/mapper/luks-abc"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := detectDisk(tc.fs, tc.mountinfo, tc.path, tc.vm)
			if d.Kind != tc.kind || d.Method != tc.method || d.Device != tc.device {
				t.Errorf("got %+v", d)
			}
			if tc.kind == DiskVirtual && d.Provider != tc.vm.Provider {
				t.Errorf("provider %q", d.Provider)
			}
		})
	}
}

func TestDetectDiskLoop(t *testing.T) {
	fs := tree([3]string{"luks-abc", "CRYPT-LUKS2-abc-luks-abc", "sda3"})
	fs.links["/sys/dev/block/7:0"] = "/sys/devices/virtual/block/loop0"
	fs.files["/sys/devices/virtual/block/loop0/loop/backing_file"] = "/srv/images/disk.img"
	mounts := mi(1, "8:2", "/", "rw", "ext4", "/dev/sda2", "rw") +
		mi(2, "253:0", "/srv", "rw", "ext4", "/dev/mapper/luks-abc", "rw") +
		mi(3, "7:0", "/mnt/img", "rw", "ext4", "/dev/loop0", "rw")
	d := detectDisk(fs, mounts, "/mnt/img/signalith", vmInfo{})
	if d.Kind != DiskEncrypted || d.Method != "LUKS2" || d.Device != "/dev/loop0" || d.Path != "/mnt/img/signalith" {
		t.Errorf("%+v", d)
	}
	// A loop over a file on a plain disk is plain.
	fs.files["/sys/devices/virtual/block/loop0/loop/backing_file"] = "/home/disk.img"
	if d := detectDisk(fs, mounts, "/mnt/img/x", vmInfo{}); d.Kind != DiskPlain {
		t.Errorf("%+v", d)
	}
}

func TestDetectVM(t *testing.T) {
	for _, tc := range []struct {
		vendor, product, flags string
		virtual                bool
		provider               string
	}{
		{"Amazon EC2", "t3.medium", "", true, "Amazon EC2"},
		{"QEMU", "Standard PC (Q35 + ICH9, 2009)", "hypervisor", true, "QEMU"},
		{"Microsoft Corporation", "Virtual Machine", "", true, "Hyper-V"},
		{"Microsoft Corporation", "Surface Laptop", "", false, ""},
		{"VMware, Inc.", "VMware Virtual Platform", "", true, "VMware"},
		{"Hetzner", "vServer", "", true, "Hetzner"},
		{"Dell Inc.", "PowerEdge R640", "", false, ""},
		{"Unknown", "Unknown", "fpu hypervisor", true, ""},
	} {
		fs := mapFS{files: map[string]string{"/sys/class/dmi/id/sys_vendor": tc.vendor, "/sys/class/dmi/id/product_name": tc.product,
			"/proc/cpuinfo": "flags\t: " + tc.flags + "\n"}}
		if got := detectVM(fs); got.Virtual != tc.virtual || got.Provider != tc.provider {
			t.Errorf("%s %s: %+v", tc.vendor, tc.product, got)
		}
	}
}

func TestConfidentialVMProbe(t *testing.T) {
	if got := confidentialVM(mapFS{files: map[string]string{"/sys/class/misc/sev-guest/dev": "10:1"}}); got != "AMD SEV-SNP" {
		t.Error(got)
	}
	if got := confidentialVM(mapFS{files: map[string]string{"/proc/cpuinfo": "flags : fpu tdx_guest\n"}}); got != "Intel TDX" {
		t.Error(got)
	}
	if got := confidentialVM(mapFS{files: map[string]string{"/proc/cpuinfo": "flags : fpu\n"}}); got != "" {
		t.Error(got)
	}
}

const statusSystemd = `Name:	signalith
Umask:	0077
State:	S (sleeping)
Uid:	998	998	998	998
Gid:	998	998	998	998
CapEff:	0000000000000400
NoNewPrivs:	1
Seccomp:	2
`

func TestReadProcess(t *testing.T) {
	systemdMounts := mi(1, "8:2", "/", "ro,relatime", "ext4", "/dev/sda2", "rw") +
		mi(2, "0:5", "/proc", "rw,nosuid", "proc", "proc", "rw,hidepid=invisible") +
		mi(3, "0:6", "/dev", "ro,nosuid", "tmpfs", "tmpfs", "rw,mode=755") +
		mi(4, "8:2", "/var/lib/signalith", "rw", "ext4", "/dev/sda2", "rw")
	containerStatus := "Umask:\t0022\nUid:\t65532\t65532\t65532\t65532\nCapEff:\t0000000000000000\nNoNewPrivs:\t1\nSeccomp:\t2\n"
	containerMounts := mi(1, "0:40", "/", "ro,relatime", "overlay", "overlay", "rw,lowerdir=x") +
		mi(2, "0:41", "/proc", "rw", "proc", "proc", "rw") + mi(3, "0:42", "/dev", "rw", "tmpfs", "tmpfs", "rw")
	byHand := "Umask:\t0002\nUid:\t1000\t1000\t1000\t1000\nCapEff:\t0000000000000000\nNoNewPrivs:\t0\nSeccomp:\t0\n"
	handMounts := mi(1, "8:2", "/", "rw", "ext4", "/dev/sda2", "rw") + mi(2, "0:5", "/proc", "rw", "proc", "proc", "rw") +
		mi(3, "0:6", "/dev", "rw", "devtmpfs", "udev", "rw")
	rootStatus := "Uid:\t0\t0\t0\t0\nCapEff:\t000001ffffffffff\n"

	for _, tc := range []struct {
		name, status, mounts string
		want                 ProcessFacts
	}{
		{"systemd", statusSystemd, systemdMounts, ProcessFacts{Known: true, UID: 998, NoNewPrivs: true, Seccomp: true, NoCaps: true,
			ReadOnlyRoot: true, HiddenProc: true, PrivateDev: true, Umask077: true}},
		{"container", containerStatus, containerMounts, ProcessFacts{Known: true, UID: 65532, NoNewPrivs: true, Seccomp: true, NoCaps: true,
			NoCapsAtAll: true, ReadOnlyRoot: true, PrivateDev: true}},
		{"by hand", byHand, handMounts, ProcessFacts{Known: true, UID: 1000, NoCaps: true, NoCapsAtAll: true}},
		{"root", rootStatus, handMounts, ProcessFacts{Known: true, Root: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fs := mapFS{files: map[string]string{"/proc/42/status": tc.status, "/proc/42/mountinfo": tc.mounts}}
			var p ProcessFacts
			if err := readProcess(fs, "42", &p); err != nil {
				t.Fatal(err)
			}
			if p != tc.want {
				t.Errorf("got  %+v\nwant %+v", p, tc.want)
			}
		})
	}
	var p ProcessFacts
	if err := readProcess(mapFS{files: map[string]string{}}, "42", &p); err == nil || p.Known {
		t.Error("a missing process was read")
	}
}

func TestMemoryFacts(t *testing.T) {
	fs := tree([3]string{"cryptswap", "CRYPT-PLAIN-cryptswap", "sda1"})
	fs.files["/proc/42/limits"] = "Limit                     Soft Limit           Hard Limit           Units\nMax core file size        0                    unlimited            bytes\n"
	fs.files["/proc/swaps"] = "Filename\tType\tSize\tUsed\tPriority\n/dev/dm-0\tpartition\t1000\t0\t-2\n"
	fs.files["/proc/42/cgroup"] = "0::/system.slice/signalith.service\n"
	fs.files["/sys/fs/cgroup/system.slice/signalith.service/memory.swap.max"] = "0\n"
	if off, known := coreLimitOff(fs, "42"); !off || !known {
		t.Errorf("core %v %v", off, known)
	}
	var m MemoryFacts
	swapFacts(fs, "", "42", &m)
	if !m.SwapOn || !m.SwapEncrypted || !m.SwapOffForUs {
		t.Errorf("%+v", m)
	}
	// A plain swap partition, swap allowed.
	fs.files["/proc/swaps"] = "Filename\tType\tSize\tUsed\tPriority\n/dev/sda2\tpartition\t1000\t0\t-2\n"
	fs.files["/sys/fs/cgroup/system.slice/signalith.service/memory.swap.max"] = "max\n"
	m = MemoryFacts{}
	swapFacts(fs, "", "42", &m)
	if !m.SwapOn || m.SwapEncrypted || m.SwapOffForUs {
		t.Errorf("%+v", m)
	}
	// No swap.
	fs.files["/proc/swaps"] = "Filename\tType\tSize\tUsed\tPriority\n"
	m = MemoryFacts{}
	swapFacts(fs, "", "42", &m)
	if m.SwapOn {
		t.Errorf("%+v", m)
	}
}

func TestParseMountinfo(t *testing.T) {
	ms := parseMountinfo("36 35 98:0 /mnt1 /mnt\\0402 rw,noatime master:1 - ext3 /dev/root rw,errors=continue\nbad line\n")
	if len(ms) != 1 || ms[0].Point != "/mnt 2" || ms[0].Major != 98 || ms[0].FSType != "ext3" || ms[0].Source != "/dev/root" {
		t.Errorf("%+v", ms)
	}
	m, ok := mountOf(parseMountinfo(mi(1, "8:1", "/", "rw", "ext4", "/dev/sda1", "rw")+mi(2, "8:2", "/var", "rw", "ext4", "/dev/sda2", "rw")), "/var/lib")
	if !ok || m.Point != "/var" {
		t.Errorf("%+v", m)
	}
	if m, _ := mountOf(parseMountinfo(mi(1, "8:1", "/", "rw", "ext4", "/dev/sda1", "rw")+mi(2, "8:2", "/var", "rw", "ext4", "/dev/sda2", "rw")), "/variable"); m.Point != "/" {
		t.Errorf("%+v", m)
	}
}

func TestDefaultGateway(t *testing.T) {
	route := "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n" +
		"eth0\t000011AC\t00000000\t0001\t0\t0\t0\t0000FFFF\t0\t0\t0\n" +
		"eth0\t00000000\t010011AC\t0003\t0\t0\t0\t00000000\t0\t0\t0\n"
	a, ok := defaultGateway(mapFS{files: map[string]string{"/proc/net/route": route}})
	if !ok || a.String() != "172.17.0.1" {
		t.Errorf("%v %v", a, ok)
	}
	if _, ok := defaultGateway(mapFS{files: map[string]string{"/proc/net/route": "Iface\tDestination\n"}}); ok {
		t.Error("a gateway without a default route")
	}
	if _, ok := defaultGateway(mapFS{}); ok {
		t.Error("a gateway without the file")
	}
}

// Windows Error Reporting: signalith.exe's own key sets only the values it
// has; the others come from the global key.
func TestMergeDumps(t *testing.T) {
	base := `HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps`
	app := base + `\signalith.exe`
	for _, tc := range []struct {
		name        string
		global, own dumpValues
		ownOK       bool
		full        bool
		folder, key string
	}{
		{name: "nothing set"},
		{name: "global mini", global: dumpValues{Type: 1, HasType: true}},
		{name: "global full", global: dumpValues{Type: 2, HasType: true, Folder: `C:\Dumps`, HasFolder: true}, full: true, folder: `C:\Dumps`, key: base},
		{name: "own mini over global full", global: dumpValues{Type: 2, HasType: true}, own: dumpValues{Type: 1, HasType: true}, ownOK: true},
		{name: "own full", own: dumpValues{Type: 2, HasType: true}, ownOK: true, full: true, key: app},
		// The program's key has only a folder: the global type holds.
		{name: "own folder, global full", global: dumpValues{Type: 2, HasType: true}, own: dumpValues{Folder: `D:\x`, HasFolder: true}, ownOK: true,
			full: true, folder: `D:\x`, key: base},
		{name: "custom with full memory", global: dumpValues{Type: 0, HasType: true}, own: dumpValues{Flags: 0x2 | 0x4, HasFlags: true}, ownOK: true,
			full: true, key: app},
		{name: "custom without full memory", global: dumpValues{Type: 0, HasType: true, Flags: 0x4, HasFlags: true}},
		{name: "own key unreadable", own: dumpValues{Type: 2, HasType: true}},
	} {
		m := mergeDumps(tc.global, tc.own, tc.ownOK, base)
		if !m.Known || m.FullDumps != tc.full || m.DumpFolder != tc.folder || m.DumpsRegistry != tc.key {
			t.Errorf("%s: %+v", tc.name, m)
		}
	}
}

func TestReleaseAtLeast(t *testing.T) {
	for _, tc := range []struct {
		release string
		want    bool
	}{
		{"5.8.0", true},
		{"5.10.0-28-amd64", true},
		{"6.1.0", true},
		{"5.4.0-150-generic", false},
		{"4.18.0-553.el8.x86_64", false},
		{"5.8-rc1", true},
		{"5.7-rc1", false},
		{"", true},
		{"odd", true},
	} {
		if got := releaseAtLeast(tc.release, 5, 8); got != tc.want {
			t.Errorf("%q: %v", tc.release, got)
		}
	}
}

func TestNotDumpable(t *testing.T) {
	for _, c := range []struct {
		owner, euid  int
		not, unknown bool
	}{
		{0, 999, true, false},    // folder given to root: not dumpable
		{999, 999, false, false}, // its own user's: dumpable
		{0, 0, false, true},      // runs as root: can't tell
		{-1, 999, false, true},   // folder unread
		{1000, 999, false, true}, // someone else's: can't tell
	} {
		not, unknown := notDumpable(c.owner, c.euid)
		if not != c.not || unknown != c.unknown {
			t.Errorf("notDumpable(%d, %d) = %v, %v", c.owner, c.euid, not, unknown)
		}
	}
}
