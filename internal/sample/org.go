// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package sample

import "fmt"

// Everything here is a made-up organisation. Names are obviously fictional,
// the domain is corp.example (RFC 6761 reserves example), and every address,
// inside the company and out, is from the documentation ranges TEST-NET-1/2/3
// (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, RFC 5737), which no real
// network uses. No real company, product or person is named, and no sample
// address can belong to a real machine, so the data is safe to load on any
// network and never mixes with the user's own hosts.

// Domain is the fictional company's Windows and DNS domain.
const (
	Domain    = "corp.example"       // DNS and e-mail domain
	NetBIOS   = "CORP"               // Windows / NetBIOS domain
	CompanyID = "Northwind Turbines" // a made-up company, shown only in docs
)

// InternalNet is the documentation range the fictional company uses for
// its own hosts (TEST-NET-1). Its blocks stand in for subnets.
const InternalNet = "192.0.2.0/24"

// Address blocks inside InternalNet.
const (
	netCompany = "192.0.2." // every internal host
	ipFirewall = "192.0.2.1"
	ipProxy    = "192.0.2.160"
)

// External documentation addresses (RFC 5737). Used for the internet-facing
// C2, the brute-force source and ordinary internet traffic, so nothing ever
// points at a real address.
const (
	ipC2        = "203.0.113.45"  // attacker command-and-control / brute-force source
	ipC2Beacon  = "198.51.100.23" // beaconing destination, also a sample intel IP
	ipPhishHost = "203.0.113.77"  // host that served the malicious document
	ipExfil     = "198.51.100.50" // exfiltration destination (sample intel IP)
	ipUpdates   = "198.51.100.80" // a benign update service
)

// Host is one computer in the fictional company.
type Host struct {
	Name     string // short host name, also the Computer field on Windows
	IP       string
	OS       string // "windows" or "linux"
	Role     string // finance, it, server, dc, ot, etc. (for assets/priority)
	Priority string // asset priority: low, medium, high, critical
	Category string // asset category
	BUnit    string // business unit
	Location string
}

// FQDN returns the host's fully qualified name.
func (h Host) FQDN() string { return h.Name + "." + Domain }

// User is one person or service account.
type User struct {
	Login     string // sAMAccountName / Unix login, e.g. "alice.nguyen"
	Name      string // display name
	Dept      string
	Title     string
	Manager   string // manager's display name
	Priority  string // identity priority
	Watchlist bool
	Admin     bool     // a domain or Linux admin
	Hosts     []string // host names they usually sign in to
	LinuxUser bool     // uses the Linux hosts (sudo/ssh)
}

// Email returns the user's corp.example e-mail address.
func (u User) Email() string { return u.Login + "@" + Domain }

// Winuser returns the DOMAIN\login form Windows events and Sysmon use, so a
// person's risk adds up under one object across Security and Sysmon events.
func (u User) Winuser() string { return NetBIOS + "\\" + u.Login }

// org is the fixed set of users and hosts. It is deterministic so the same
// load always produces the same organisation; nothing here is random.
type org struct {
	Users []User
	Hosts []Host
	// OT hosts (a small plant-floor flavour, since the owner is an OT
	// security director). No detection targets them; they just add
	// realistic industrial-protocol traffic in the background.
	OT []Host
}

// buildOrg returns the fictional organisation: about 50 users and 40 hosts,
// including a small OT subnet. It takes no randomness, so it is identical
// on every load.
func buildOrg() *org {
	o := &org{}

	// --- People ---
	// A handful of named, obviously fictional people fill the key roles the
	// attack stories need; the rest are generated from fixed name lists so
	// searches, sign-ins and risk have ~50 distinct users.
	first := []string{"Alice", "Bob", "Carol", "Dan", "Erin", "Frank", "Grace", "Heidi",
		"Ivan", "Judy", "Mallory", "Niaj", "Olivia", "Peggy", "Rupert", "Sybil",
		"Trent", "Uma", "Victor", "Wendy", "Xavier", "Yara", "Zane", "Nadia",
		"Oscar", "Paula", "Quinn", "Ruth", "Sam", "Tara", "Umar", "Vera",
		"Walt", "Xena", "Yusuf", "Zoe", "Amara", "Bodhi", "Cleo", "Dimitri",
		"Esme", "Felix", "Gita", "Hugo", "Ines", "Jonas", "Kira", "Lars"}
	last := []string{"Nguyen", "Okafor", "Rivera", "Sato", "Thompson", "Ulrich", "Vasquez", "Waters",
		"Xu", "Yoon", "Zimmer", "Abara", "Bianchi", "Costa", "Delacroix", "Ericsson",
		"Fontaine", "Giordano", "Haas", "Ibrahim", "Jansen", "Kowalski", "Lindqvist", "Moreau",
		"Novak", "Ortiz", "Petrov", "Quill", "Romano", "Singh", "Tanaka", "Ueda",
		"Volkov", "Weber", "Yamada", "Zhao", "Andersen", "Brandt", "Cho", "Dubois",
		"Engel", "Falk", "Gallo", "Horvat", "Ismail", "Jung", "Keller", "Larsen"}
	depts := []string{"Finance", "IT", "Operations", "Engineering", "HR", "Sales", "Plant"}

	add := func(u User) { o.Users = append(o.Users, u) }

	// Named people the stories use.
	add(User{Login: "alice.nguyen", Name: "Alice Nguyen", Dept: "Finance", Title: "Financial Analyst",
		Manager: "Olivia Okafor", Priority: "medium", Hosts: []string{"ws-fin-07"}})
	add(User{Login: "bob.okafor", Name: "Bob Okafor", Dept: "IT", Title: "Systems Administrator",
		Manager: "Olivia Okafor", Priority: "high", Admin: true, LinuxUser: true,
		Hosts: []string{"ws-it-02", "db-01", "app-01"}})
	add(User{Login: "carol.rivera", Name: "Carol Rivera", Dept: "Engineering", Title: "Controls Engineer",
		Manager: "Victor Volkov", Priority: "high", Watchlist: true, LinuxUser: true,
		Hosts: []string{"eng-ws-01"}})
	add(User{Login: "dan.sato", Name: "Dan Sato", Dept: "IT", Title: "Domain Administrator",
		Manager: "Olivia Okafor", Priority: "critical", Admin: true, LinuxUser: true,
		Hosts: []string{"ws-it-01", "dc-01", "db-01", "app-01", "file-01"}})
	add(User{Login: "olivia.okafor", Name: "Olivia Okafor", Dept: "IT", Title: "IT Director",
		Manager: "", Priority: "high", Hosts: []string{"ws-it-03"}})
	add(User{Login: "victor.volkov", Name: "Victor Volkov", Dept: "Engineering", Title: "Plant Manager",
		Manager: "", Priority: "high", Hosts: []string{"eng-ws-02"}})
	add(User{Login: "svc-backup", Name: "svc-backup (service account)", Dept: "IT", Title: "Backup service account",
		Manager: "Dan Sato", Priority: "high", Admin: true, Hosts: []string{"file-01", "db-01"}})

	// Generated people. Deterministic: login from first+last, host chosen by
	// index so everyone lands on a real workstation.
	wsFinance := []string{"ws-fin-01", "ws-fin-02", "ws-fin-03", "ws-fin-04", "ws-fin-05", "ws-fin-06", "ws-fin-07"}
	wsIT := []string{"ws-it-01", "ws-it-02", "ws-it-03", "ws-it-04"}
	wsOps := []string{"ws-ops-01", "ws-ops-02", "ws-ops-03", "ws-ops-04", "ws-ops-05"}
	wsEng := []string{"eng-ws-01", "eng-ws-02", "eng-ws-03"}
	pools := [][]string{wsFinance, wsIT, wsOps, wsEng}
	seen := map[string]bool{}
	for _, u := range o.Users {
		seen[u.Login] = true
	}
	n := 0
	for i := 0; len(o.Users) < 52; i++ {
		f := first[i%len(first)]
		l := last[(i*7+3)%len(last)]
		login := fmt.Sprintf("%c%s", lower(f[0]), lowerAll(l))
		if i%3 == 0 {
			login = lowerAll(f) + "." + lowerAll(l)
		}
		if seen[login] {
			login = fmt.Sprintf("%s%d", login, i)
		}
		seen[login] = true
		dept := depts[i%len(depts)]
		pool := pools[i%len(pools)]
		host := pool[(i*5+1)%len(pool)]
		pr := "low"
		switch i % 5 {
		case 0:
			pr = "medium"
		case 3:
			pr = "low"
		}
		u := User{Login: login, Name: f + " " + l, Dept: dept, Title: titleFor(dept),
			Manager: "Olivia Okafor", Priority: pr, Hosts: []string{host}}
		if dept == "Engineering" || dept == "Plant" || dept == "Operations" {
			u.LinuxUser = i%2 == 0
		}
		add(u)
		n++
	}

	// --- Hosts ---
	addHost := func(h Host) { o.Hosts = append(o.Hosts, h) }
	// Finance workstations (Windows).
	for i, name := range wsFinance {
		addHost(Host{Name: name, IP: fmt.Sprintf("%s%d", netCompany, 20+i), OS: "windows",
			Role: "finance-workstation", Priority: "medium", Category: "workstation", BUnit: "Finance", Location: "HQ"})
	}
	// IT workstations (Windows).
	for i, name := range wsIT {
		pr := "medium"
		if name == "ws-it-01" {
			pr = "high" // the domain admin's workstation
		}
		addHost(Host{Name: name, IP: fmt.Sprintf("%s%d", netCompany, 30+i), OS: "windows",
			Role: "it-workstation", Priority: pr, Category: "workstation", BUnit: "IT", Location: "HQ"})
	}
	// Ops workstations (Windows).
	for i, name := range wsOps {
		addHost(Host{Name: name, IP: fmt.Sprintf("%s%d", netCompany, 40+i), OS: "windows",
			Role: "ops-workstation", Priority: "low", Category: "workstation", BUnit: "Operations", Location: "HQ"})
	}
	// Engineering workstations (Windows, one is the OT jump box).
	for i, name := range wsEng {
		addHost(Host{Name: name, IP: fmt.Sprintf("%s%d", netCompany, 60+i), OS: "windows",
			Role: "engineering-workstation", Priority: "high", Category: "workstation", BUnit: "Engineering", Location: "Plant"})
	}
	// Servers.
	addHost(Host{Name: "dc-01", IP: netCompany + "110", OS: "windows", Role: "domain-controller",
		Priority: "critical", Category: "domain-controller", BUnit: "IT", Location: "Data centre"})
	addHost(Host{Name: "dc-02", IP: netCompany + "111", OS: "windows", Role: "domain-controller",
		Priority: "critical", Category: "domain-controller", BUnit: "IT", Location: "Data centre"})
	addHost(Host{Name: "file-01", IP: netCompany + "120", OS: "windows", Role: "file-server",
		Priority: "high", Category: "server", BUnit: "IT", Location: "Data centre"})
	addHost(Host{Name: "app-01", IP: netCompany + "130", OS: "linux", Role: "app-server",
		Priority: "high", Category: "server", BUnit: "IT", Location: "Data centre"})
	addHost(Host{Name: "web-01", IP: netCompany + "131", OS: "linux", Role: "web-server",
		Priority: "high", Category: "server", BUnit: "IT", Location: "Data centre"})
	addHost(Host{Name: "db-01", IP: netCompany + "140", OS: "linux", Role: "database",
		Priority: "critical", Category: "server", BUnit: "IT", Location: "Data centre"})
	// The network sensor: Zeek and Suricata on a mirror port.
	addHost(Host{Name: "nsm-01", IP: netCompany + "155", OS: "linux", Role: "network-sensor",
		Priority: "medium", Category: "server", BUnit: "IT", Location: "Data centre"})
	addHost(Host{Name: "jump-01", IP: netCompany + "150", OS: "linux", Role: "bastion",
		Priority: "high", Category: "server", BUnit: "IT", Location: "Data centre"})

	// --- OT / plant floor ---
	o.OT = append(o.OT,
		Host{Name: "hist-01", IP: netCompany + "210", OS: "windows", Role: "ot-historian",
			Priority: "high", Category: "ot-historian", BUnit: "Plant", Location: "Plant DMZ"},
		Host{Name: "hmi-01", IP: netCompany + "220", OS: "windows", Role: "ot-hmi",
			Priority: "high", Category: "ot-hmi", BUnit: "Plant", Location: "Plant floor"},
		Host{Name: "hmi-02", IP: netCompany + "221", OS: "windows", Role: "ot-hmi",
			Priority: "high", Category: "ot-hmi", BUnit: "Plant", Location: "Plant floor"},
		Host{Name: "plc-01", IP: netCompany + "230", OS: "linux", Role: "ot-plc",
			Priority: "critical", Category: "ot-plc", BUnit: "Plant", Location: "Plant floor"},
		Host{Name: "plc-02", IP: netCompany + "231", OS: "linux", Role: "ot-plc",
			Priority: "critical", Category: "ot-plc", BUnit: "Plant", Location: "Plant floor"},
		Host{Name: "plc-03", IP: netCompany + "232", OS: "linux", Role: "ot-plc",
			Priority: "critical", Category: "ot-plc", BUnit: "Plant", Location: "Plant floor"},
	)
	return o
}

func titleFor(dept string) string {
	switch dept {
	case "Finance":
		return "Accountant"
	case "IT":
		return "IT Specialist"
	case "Engineering":
		return "Engineer"
	case "HR":
		return "HR Coordinator"
	case "Sales":
		return "Account Executive"
	case "Plant":
		return "Plant Operator"
	}
	return "Analyst"
}

// host returns a host by name, or a zero Host.
func (o *org) host(name string) Host {
	for _, h := range o.Hosts {
		if h.Name == name {
			return h
		}
	}
	for _, h := range o.OT {
		if h.Name == name {
			return h
		}
	}
	return Host{Name: name}
}

// userByLogin returns the user with a login, or a User with that login set.
func (o *org) userByLogin(login string) User {
	for _, u := range o.Users {
		if u.Login == login {
			return u
		}
	}
	return User{Login: login, Name: login}
}

// windowsHosts and linuxHosts return the non-OT hosts of each kind.
func (o *org) windowsHosts() []Host { return filterOS(o.Hosts, "windows") }
func (o *org) linuxHosts() []Host   { return filterOS(o.Hosts, "linux") }

func filterOS(hs []Host, os string) []Host {
	var out []Host
	for _, h := range hs {
		if h.OS == os {
			out = append(out, h)
		}
	}
	return out
}

func lower(b byte) byte {
	if b >= 'A' && b <= 'Z' {
		return b + ('a' - 'A')
	}
	return b
}

func lowerAll(s string) string {
	b := []byte(s)
	for i := range b {
		b[i] = lower(b[i])
	}
	return string(b)
}
