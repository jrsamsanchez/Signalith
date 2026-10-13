package sample

import (
	"fmt"
	"strconv"
	"time"
)

// intensity scales the background volume by size.
type intensity struct {
	procPerHostDay int
	authPerUserDay int
	netPerHostDay  int
	fwPerDay       int
	dnsPerDay      int
	days           int // how many of the trailing days carry background
}

func (g *gen) intensity() intensity {
	if g.size == SizeSmall {
		return intensity{procPerHostDay: 4, authPerUserDay: 1, netPerHostDay: 2, fwPerDay: 8, dnsPerDay: 6, days: 2}
	}
	return intensity{procPerHostDay: 150, authPerUserDay: 4, netPerHostDay: 22, fwPerDay: 150, dnsPerDay: 90, days: 6}
}

// benign process images seen on Windows workstations and servers. None of
// these trip a detection on their own.
var benignWinProcs = [][2]string{
	{`C:\Windows\explorer.exe`, `explorer.exe`},
	{`C:\Program Files\Google\Chrome\Application\chrome.exe`, `chrome.exe --type=renderer`},
	{`C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE`, `outlook.exe`},
	{`C:\Program Files\Microsoft Office\root\Office16\EXCEL.EXE`, `excel.exe`},
	{`C:\Windows\System32\svchost.exe`, `svchost.exe -k netsvcs`},
	{`C:\Windows\System32\taskhostw.exe`, `taskhostw.exe`},
	{`C:\Program Files\Microsoft\Teams\current\Teams.exe`, `teams.exe`},
	{`C:\Windows\System32\cmd.exe`, `cmd.exe /c dir`},
	{`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, `powershell.exe -command Get-Date`},
	{`C:\Program Files\Git\bin\git.exe`, `git.exe status`},
	{`C:\Windows\System32\notepad.exe`, `notepad.exe`},
	{`C:\Program Files\Microsoft OneDrive\OneDrive.exe`, `OneDrive.exe /background`},
}

var benignParent = `C:\Windows\explorer.exe`

// benign internal/external destinations for background network connections.
var benignNet = []struct {
	host string
	ip   string
	port int
}{
	{"proxy.corp.example", ipProxy, 3128},
	{"file-01.corp.example", netCompany + "120", 445},
	{"dc-01.corp.example", netCompany + "110", 389},
	{"update.windows.example", ipUpdates, 443},
	{"intranet.corp.example", netCompany + "131", 443},
}

var benignDomains = []string{
	"intranet.corp.example", "mail.corp.example", "update.windows.example",
	"portal.corp.example", "time.corp.example", "repo.corp.example",
}

// background fills the six-day window with normal sign-ins, process starts,
// network connections, firewall traffic, DNS, antivirus definition updates
// and a little OT traffic, with
// a working-hours and weekday rhythm. Nothing here fires a detection.
func (g *gen) background() {
	it := g.intensity()
	days := g.dayWindows(it.days)

	winHosts := g.org.windowsHosts()
	allHosts := append(append([]Host{}, g.org.Hosts...), g.org.OT...)

	for _, day := range days {
		// Sign-ins.
		for i := range g.org.Users {
			u := g.org.Users[i]
			n := it.authPerUserDay
			if g.rng.chance(1, 3) {
				n++
			}
			for k := 0; k < n; k++ {
				t := g.rng.timeIn(day.start, day.end)
				host := g.userHost(u)
				if host.OS == "linux" || u.LinuxUser && g.rng.chance(1, 3) {
					lh := g.pickLinuxHost(u)
					g.sshLogin(lh, u.Login, g.deskIP(u), 40000+g.rng.intn(20000), t, true, false)
					// the odd mistyped password
					if g.rng.chance(1, 6) {
						g.sshLogin(lh, u.Login, g.deskIP(u), 40000+g.rng.intn(20000), t.Add(-time.Minute), false, false)
					}
				} else {
					g.logonWin(host, u, t, "-", host.Name, 2)
					if g.rng.chance(1, 7) {
						g.logonFailWin(host, u.Login, t.Add(-time.Minute), "-", host.Name, "0xc000006a", 2)
					}
				}
			}
		}

		// Process starts on Windows hosts.
		for _, h := range winHosts {
			for k := 0; k < it.procPerHostDay; k++ {
				t := g.rng.timeIn(day.start, day.end)
				p := benignWinProcs[g.rng.intn(len(benignWinProcs))]
				g.procWin(h, g.hostUser(h), p[0], p[1], benignParent, t)
			}
		}

		// Network connections on all hosts (Sysmon 3), plus OT traffic.
		for _, h := range allHosts {
			for k := 0; k < it.netPerHostDay; k++ {
				t := g.rng.timeIn(day.start, day.end)
				d := benignNet[g.rng.intn(len(benignNet))]
				// The process matches the destination so ordinary file-share
				// and directory traffic is not flagged as remote-admin-port
				// use (explorer and svchost are the usual clients there).
				img := `C:\Program Files\Google\Chrome\Application\chrome.exe`
				switch d.port {
				case 445:
					img = `C:\Windows\explorer.exe`
				case 389:
					img = `C:\Windows\System32\svchost.exe`
				}
				g.sysmonNet(h, NetBIOS+`\`+g.hostUser(h), h.IP, 49000+g.rng.intn(15000), d.ip, d.host, d.port, "tcp", img, t)
			}
		}
		g.otTraffic(day)

		// Firewall allowed and blocked traffic (CEF) and DNS lookups.
		for k := 0; k < it.fwPerDay; k++ {
			t := g.rng.timeIn(day.start, day.end)
			g.firewall(t, false)
		}
		for k := 0; k < it.dnsPerDay; k++ {
			t := g.rng.timeIn(day.start, day.end)
			h := winHosts[g.rng.intn(len(winHosts))]
			g.dnsLookup(h, g.rng.pick(benignDomains), t)
		}

		// A benign account change now and then (new hire, group membership).
		if g.rng.chance(1, 2) {
			dc := g.org.host("dc-01")
			who := g.org.Users[g.rng.intn(len(g.org.Users))]
			g.accountCreatedWin(dc, "new.hire"+strconv.Itoa(g.rng.intn(999)), "dan.sato", g.rng.timeIn(day.start, day.end))
			_ = who
		}
	}
	g.antivirusBackground(days)
}

// otTraffic adds a little industrial-protocol flavour: the HMIs poll the
// PLCs over Modbus (TCP 502) and write to the historian. It is all normal;
// no detection targets OT, it just shows the plant floor in the data.
func (g *gen) otTraffic(day window) {
	hmis := []string{"hmi-01", "hmi-02"}
	plcs := []string{"plc-01", "plc-02", "plc-03"}
	hist := g.org.host("hist-01")
	n := 20
	if g.size == SizeSmall {
		n = 3
	}
	for k := 0; k < n; k++ {
		t := g.rng.timeIn(day.start, day.end)
		hmi := g.org.host(hmis[g.rng.intn(len(hmis))])
		plc := g.org.host(plcs[g.rng.intn(len(plcs))])
		g.sysmonNet(hmi, NetBIOS+`\operator`, hmi.IP, 50000+g.rng.intn(10000), plc.IP, plc.FQDN(), 502, "tcp",
			`C:\Program Files\HMI\runtime.exe`, t)
		if g.rng.chance(1, 3) {
			g.sysmonNet(hmi, NetBIOS+`\operator`, hmi.IP, 50000+g.rng.intn(10000), hist.IP, hist.FQDN(), 1433, "tcp",
				`C:\Program Files\HMI\runtime.exe`, t.Add(time.Second*5))
		}
	}
}

// firewall writes one allowed or blocked outbound connection as CEF.
func (g *gen) firewall(t time.Time, blocked bool) {
	srcs := g.org.Hosts
	h := srcs[g.rng.intn(len(srcs))]
	// Ordinary internet traffic goes to the upper half of TEST-NET-2,
	// clear of the sample's malicious addresses.
	dstIP := fmt.Sprintf("198.51.100.%d", 100+g.rng.intn(100))
	act := "allow"
	sev := "3"
	if blocked {
		act = "deny"
		sev = "6"
	}
	g.b.cef(ipFirewall, t, "Traffic", "100", sev, map[string]string{
		"act": act, "src": h.IP, "dst": dstIP, "spt": strconv.Itoa(40000 + g.rng.intn(20000)),
		"dpt": strconv.Itoa([]int{443, 80, 53, 8080}[g.rng.intn(4)]), "proto": "6",
		"in": strconv.Itoa(400 + g.rng.intn(4000)), "out": strconv.Itoa(400 + g.rng.intn(40000)),
	})
}

// dnsLookup writes a DNS query as a generic (Other) event, searchable by
// its query and answer fields.
func (g *gen) dnsLookup(h Host, query string, t time.Time) {
	g.b.generic(t, "dns", map[string]any{
		"host": h.Name, "dest": h.Name, "query": query,
		"answer":  fmt.Sprintf("%s%d", netCompany, 100+g.rng.intn(100)),
		"message": h.Name + " resolved " + query,
	})
}

// --- helpers ---

type window struct{ start, end time.Time }

// dayWindows returns the last n calendar days inside [start, end], oldest
// first, each clipped to the sample's range.
func (g *gen) dayWindows(n int) []window {
	var out []window
	end := g.end
	for i := 0; i < n; i++ {
		dayEnd := end
		dayStart := time.Date(end.Year(), end.Month(), end.Day(), 0, 0, 0, 0, time.UTC)
		if dayStart.Before(g.start) {
			dayStart = g.start
		}
		if dayStart.Before(dayEnd) {
			out = append(out, window{dayStart, dayEnd})
		}
		end = dayStart.Add(-time.Nanosecond)
		if end.Before(g.start) {
			break
		}
	}
	// oldest first
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out
}

func (g *gen) userHost(u User) Host {
	if len(u.Hosts) > 0 {
		return g.org.host(u.Hosts[0])
	}
	return g.org.windowsHosts()[g.rng.intn(len(g.org.windowsHosts()))]
}

func (g *gen) pickLinuxHost(u User) Host {
	lh := g.org.linuxHosts()
	return lh[g.rng.intn(len(lh))]
}

// hostUser returns a plausible login for a host (its usual user, else any).
func (g *gen) hostUser(h Host) string {
	for _, u := range g.org.Users {
		for _, hn := range u.Hosts {
			if hn == h.Name {
				return u.Login
			}
		}
	}
	return g.org.Users[g.rng.intn(len(g.org.Users))].Login
}

// deskIP returns the IP of a user's usual host, for SSH source addresses.
func (g *gen) deskIP(u User) string {
	h := g.userHost(u)
	if h.IP != "" {
		return h.IP
	}
	return netCompany + "50"
}
