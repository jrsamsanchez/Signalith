package vulnscan

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"time"
)

// Check is one thing a scanner needs, whether it has it, why it matters
// and how to fix it.
type Check struct {
	ID     string `json:"id"`
	Title  string `json:"title"`
	State  string `json:"state"` // ok, warn, fail or info
	Detail string `json:"detail"`
	Why    string `json:"why"`
	// Fix is what to do, one step per line; empty when nothing is
	// needed.
	Fix []string `json:"fix,omitempty"`
	// Required checks must pass before scans can run.
	Required bool `json:"required"`
}

// Check states.
const (
	CheckOK   = "ok"
	CheckWarn = "warn"
	CheckFail = "fail"
	CheckInfo = "info"
)

// Checker checks the machine scans run on.
type Checker struct {
	// FindNmap finds Nmap; nil is FindNmap.
	FindNmap func() string
	// Version and SelfTest run Nmap; nil runs it for real.
	Version  func(ctx context.Context, path string) (string, error)
	SelfTest func(ctx context.Context, path string) error
	NVD      *NVD
	// GOOS overrides runtime.GOOS (tests).
	GOOS string
	// Docker says Signalith runs in its container image.
	Docker bool
	// OpenVAS is this server's OpenVAS, when set up.
	OpenVAS *OpenVAS
	// Reach finds how this server reaches an address; nil is LocalRoute.
	Reach func(ctx context.Context, entry string) Route
}

func (c *Checker) goos() string {
	if c.GOOS != "" {
		return c.GOOS
	}
	return runtime.GOOS
}

// installNmap is how to install Nmap where Signalith runs.
func (c *Checker) installNmap() []string {
	if c.Docker {
		return []string{
			"Signalith's container image includes Nmap. Pull the latest image and restart: docker compose pull, then docker compose up -d.",
		}
	}
	if c.goos() == "windows" {
		return []string{
			"Download the latest stable Nmap installer (nmap-…-setup.exe) from https://nmap.org/download.html#windows.",
			"Run it as an administrator and keep the default choices, including Npcap.",
			"Come back to this page and click Check again. You do not need to restart Signalith.",
		}
	}
	return []string{
		"Install Nmap with your package manager: sudo apt install nmap (Debian, Ubuntu) or sudo dnf install nmap (Red Hat, Rocky, Alma, Fedora).",
		"Come back to this page and click Check again. You do not need to restart Signalith.",
	}
}

// Run checks the machine, and whether it reaches mine, the networks it
// scans. path is where Nmap was found, or "".
func (c *Checker) Run(ctx context.Context, set Settings, mine []Target) (checks []Check, path string) {
	find := c.FindNmap
	if find == nil {
		find = FindNmap
	}
	path = find()
	nmap := Check{ID: "nmap", Title: "Nmap is installed", Required: true,
		Why: "Signalith uses Nmap, the free and open-source network scanner, to find the hosts on your networks, their open ports and the software that answers on each one."}
	if path == "" {
		nmap.State, nmap.Detail = CheckFail, "Nmap was not found on this server."
		nmap.Fix = c.installNmap()
		checks = append(checks, nmap, Check{ID: "nmap_runs", Title: "Nmap can run a scan", State: CheckInfo, Required: true,
			Detail: "Checked once Nmap is installed.", Why: "A quick scan of this server itself makes sure Nmap works under the account Signalith runs as."})
	} else {
		ver := c.Version
		if ver == nil {
			ver = NmapVersion
		}
		v, err := ver(ctx, path)
		switch {
		case err != nil:
			nmap.State, nmap.Detail = CheckFail, "Nmap is at "+path+" but did not start: "+err.Error()
			nmap.Fix = c.installNmap()
		case !VersionAtLeast(v, MinNmapVersion):
			nmap.State, nmap.Detail = CheckWarn, fmt.Sprintf("Nmap %s at %s. It works, but versions before %s recognize fewer services and software versions.", v, path, MinNmapVersion)
			nmap.Fix = c.installNmap()
		default:
			nmap.State, nmap.Detail = CheckOK, fmt.Sprintf("Nmap %s at %s.", v, path)
		}
		checks = append(checks, nmap)
		runs := Check{ID: "nmap_runs", Title: "Nmap can run a scan", Required: true,
			Why: "A quick scan of this server itself makes sure Nmap works under the account Signalith runs as."}
		if nmap.State == CheckFail {
			runs.State, runs.Detail = CheckInfo, "Checked once Nmap starts."
		} else {
			test := c.SelfTest
			if test == nil {
				test = selfTest
			}
			if err := test(ctx, path); err != nil {
				runs.State, runs.Detail = CheckFail, "The test scan failed: "+err.Error()
				if c.goos() == "windows" {
					runs.Fix = []string{"Reinstall Nmap from https://nmap.org/download.html#windows as an administrator, with Npcap.", "Then click Check again."}
				} else {
					runs.Fix = []string{"Run nmap -sT -p 1 127.0.0.1 as the account Signalith runs as to see the full error.", "Reinstall Nmap if it reports missing files, then click Check again."}
				}
			} else {
				runs.State, runs.Detail = CheckOK, "A test scan of this server worked."
			}
		}
		checks = append(checks, runs)
	}

	cve := Check{ID: "cve", Title: "CVE lookups reach the National Vulnerability Database",
		Why: "To name the vulnerabilities (CVEs) that apply, Signalith looks up the software versions scans find in the U.S. National Vulnerability Database. " +
			"It sends only product names and versions, such as openbsd openssh 8.2, never addresses or host names. Without it, scans still list hosts, open ports and software."}
	switch {
	case !set.CVELookup:
		cve.State, cve.Detail = CheckInfo, "CVE lookups are turned off in the scan settings."
	case c.NVD == nil:
		cve.State, cve.Detail = CheckInfo, "CVE lookups are not available on this server."
	default:
		pctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		err := c.NVD.Ping(pctx)
		cancel()
		if err != nil {
			cve.State, cve.Detail = CheckWarn, "The lookup failed: "+err.Error()
			if errors.Is(err, ErrNVDUnreachable) || errors.Is(err, context.DeadlineExceeded) {
				cve.Fix = []string{
					"Allow outbound HTTPS (port 443) from this server to " + NVDHost + ".",
					"If this server reaches the internet through a proxy, set HTTPS_PROXY for the Signalith service.",
					"Then click Check again.",
				}
			}
		} else {
			cve.State, cve.Detail = CheckOK, "The database answered."
		}
	}
	checks = append(checks, cve)

	key := Check{ID: "nvd_key", Title: "NVD API key",
		Why: "Without a key the database allows 5 lookups every 30 seconds, so the first scan of a network with a lot of different software takes longer. Lookups are kept for a day, so later scans are fast either way."}
	switch {
	case c.NVD != nil && c.NVD.HasKey():
		key.State, key.Detail = CheckOK, "An API key is set, so lookups run about ten times faster."
	default:
		key.State, key.Detail = CheckInfo, "No API key is set. That is fine; lookups are just slower."
		key.Fix = []string{
			"Request a free key at https://nvd.nist.gov/developers/request-an-api-key.",
			"Enter it as NVD API key in Settings, on the Server tab under Vulnerability scans. It is used from the next lookup, with no restart.",
		}
	}
	checks = append(checks, key)

	checks = append(checks, c.openVASCheck(ctx, mine))

	nets := Check{ID: "networks", Title: "Networks to scan",
		Why: "Signalith scans only the networks you list, on the schedule you pick. Only list networks you own or have permission to scan. " +
			"Each network is scanned by one server: pick, for each, a server that can reach it, such as one inside a segmented network zone."}
	enabled := 0
	for _, t := range mine {
		if t.Enabled {
			enabled++
		}
	}
	switch {
	case len(set.Targets) == 0:
		nets.State, nets.Detail = CheckInfo, "No networks yet. Add one to start scanning."
	case len(mine) == 0:
		nets.State, nets.Detail = CheckInfo, "This server scans none of the networks; other servers scan them."
	case enabled == 0:
		nets.State, nets.Detail = CheckInfo, fmt.Sprintf("This server scans %d %s, all paused.", len(mine), plural(len(mine), "network", "networks"))
	default:
		nets.State, nets.Detail = CheckOK, fmt.Sprintf("This server scans %d %s on a schedule.", enabled, plural(enabled, "network", "networks"))
	}
	checks = append(checks, nets)
	for _, t := range mine {
		checks = append(checks, c.reachCheck(ctx, t))
	}
	return checks, path
}

// Ready reports whether every required check passed.
func Ready(checks []Check) bool {
	for _, c := range checks {
		if c.Required && c.State != CheckOK && c.State != CheckWarn {
			return false
		}
	}
	return true
}

// selfTest scans one port of this server, the same way real scans run.
func selfTest(ctx context.Context, path string) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	r := &Runner{Path: path}
	_, err := r.Scan(ctx, Target{Networks: []string{"127.0.0.1"}, Ports: "1"}, nil)
	if errors.Is(err, context.DeadlineExceeded) {
		return errors.New("Nmap did not finish a one-port test scan in 30 seconds")
	}
	if err != nil {
		return errors.New(strings.TrimPrefix(err.Error(), "Nmap stopped with an error: "))
	}
	return nil
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// openVASCheck says whether OpenVAS, optional, is set up and answers.
func (c *Checker) openVASCheck(ctx context.Context, mine []Target) Check {
	ck := Check{ID: "openvas", Title: "OpenVAS for deeper scans",
		Why: "OpenVAS (Greenbone Community Edition) tests each host for thousands of known weaknesses, such as missing patches, default passwords and weak TLS settings, " +
			"where Nmap only reads software versions. It is much slower and sends far more traffic, so only networks with Also scan with OpenVAS turned on use it, on the server that scans them."}
	wanted := 0
	for _, t := range mine {
		if t.OpenVAS {
			wanted++
		}
	}
	setup := []string{
		"Install Greenbone Community Edition on this server, or where this server can reach its gvmd: https://greenbone.github.io/docs/latest/ (the Docker containers are the quickest).",
		"Make a gvmd user for Signalith, such as: gvmd --create-user=signalith --password='a long password'.",
		"Give Signalith the address of gvmd and that user: set SIGNALITH_OPENVAS_ADDRESS to gvmd's socket (such as /run/gvmd/gvmd.sock) or host:port of its TLS port (9390), " +
			"SIGNALITH_OPENVAS_USERNAME and SIGNALITH_OPENVAS_PASSWORD for the Signalith service, or vulns.openvas_address, vulns.openvas_username and vulns.openvas_password in signalith.yaml.",
		"Restart Signalith, then edit a network on the Vulnerabilities page and turn on Also scan with OpenVAS.",
	}
	if c.Docker {
		setup[2] += " In Docker, also mount the volume that holds gvmd's socket into the Signalith container."
	}
	if !c.OpenVAS.Configured() {
		ck.State, ck.Detail, ck.Fix = CheckInfo, "Not set up. It is optional: Nmap scans work without it.", setup
		if wanted > 0 {
			ck.State = CheckWarn
			ck.Detail = fmt.Sprintf("Not set up, but %d %s this server scans %s for it, so only Nmap runs there.", wanted, plural(wanted, "network", "networks"), plural(wanted, "asks", "ask"))
		}
		return ck
	}
	vctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	v, tests, err := c.OpenVAS.Ready(vctx)
	cancel()
	if err != nil {
		ck.State, ck.Detail = CheckWarn, err.Error()
		ck.Fix = []string{
			"Check that gvmd runs and that " + c.OpenVAS.Address + " is its socket or TLS port, readable by the account Signalith runs as.",
			"Check the user name and password (SIGNALITH_OPENVAS_USERNAME and SIGNALITH_OPENVAS_PASSWORD).",
			"Then click Check again.",
		}
		return ck
	}
	if tests == 0 {
		ck.State = CheckWarn
		ck.Detail = fmt.Sprintf("OpenVAS answered at %s (GMP %s) but is still loading its feed of tests, so it cannot scan yet.", c.OpenVAS.Address, v)
		ck.Fix = []string{
			"Wait for Greenbone to finish loading its feed. A new install takes up to an hour; the gvmd log says when it is done.",
			"Then click Check again.",
		}
		return ck
	}
	ck.State = CheckOK
	ck.Detail = fmt.Sprintf("OpenVAS answered at %s (GMP %s, %d tests ready).", c.OpenVAS.Address, v, tests)
	if wanted > 0 {
		ck.Detail += fmt.Sprintf(" %d %s this server scans %s it.", wanted, plural(wanted, "network", "networks"), plural(wanted, "uses", "use"))
	}
	return ck
}
