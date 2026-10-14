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

// Run checks the machine. path is where Nmap was found, or "".
func (c *Checker) Run(ctx context.Context, set Settings) (checks []Check, path string) {
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
	case c.NVD != nil && c.NVD.APIKey != "":
		key.State, key.Detail = CheckOK, "An API key is set, so lookups run about ten times faster."
	default:
		key.State, key.Detail = CheckInfo, "No API key is set. That is fine; lookups are just slower."
		key.Fix = []string{
			"Request a free key at https://nvd.nist.gov/developers/request-an-api-key.",
			"Set it in the SIGNALITH_NVD_API_KEY environment variable of the Signalith service, then restart it.",
		}
	}
	checks = append(checks, key)

	nets := Check{ID: "networks", Title: "Networks to scan",
		Why: "Signalith scans only the networks you list, on the schedule you pick. Only list networks you own or have permission to scan."}
	enabled := 0
	for _, t := range set.Targets {
		if t.Enabled {
			enabled++
		}
	}
	switch {
	case len(set.Targets) == 0:
		nets.State, nets.Detail = CheckInfo, "No networks yet. Add one to start scanning."
	case enabled == 0:
		nets.State, nets.Detail = CheckInfo, fmt.Sprintf("%d %s listed, all paused.", len(set.Targets), plural(len(set.Targets), "network", "networks"))
	default:
		nets.State, nets.Detail = CheckOK, fmt.Sprintf("%d %s scheduled.", enabled, plural(enabled, "network", "networks"))
	}
	checks = append(checks, nets)
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
