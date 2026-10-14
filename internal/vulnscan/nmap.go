package vulnscan

import (
	"bufio"
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

// MinNmapVersion is the oldest Nmap the page accepts without a warning:
// older ones know fewer services and versions.
const MinNmapVersion = "7.80"

// nmapPlaces are where Nmap's installers put it, tried after the PATH (a
// Windows service does not see a PATH change until Windows restarts).
func nmapPlaces() []string {
	if runtime.GOOS == "windows" {
		var out []string
		for _, env := range []string{"ProgramFiles(x86)", "ProgramFiles", "ProgramW6432"} {
			if d := os.Getenv(env); d != "" {
				out = append(out, filepath.Join(d, "Nmap", "nmap.exe"))
			}
		}
		return append(out, `C:\Program Files (x86)\Nmap\nmap.exe`, `C:\Program Files\Nmap\nmap.exe`)
	}
	return []string{"/usr/bin/nmap", "/usr/local/bin/nmap", "/opt/homebrew/bin/nmap", "/snap/bin/nmap"}
}

// FindNmap returns the path of the Nmap program, or "" when it is not
// installed. SIGNALITH_NMAP names it when it is somewhere else.
func FindNmap() string {
	if p := os.Getenv("SIGNALITH_NMAP"); p != "" {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p
		}
		return ""
	}
	if p, err := exec.LookPath("nmap"); err == nil {
		if abs, err := filepath.Abs(p); err == nil {
			return abs
		}
		return p
	}
	for _, p := range nmapPlaces() {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p
		}
	}
	return ""
}

var nmapVersionRE = regexp.MustCompile(`Nmap version (\d+\.\d+[A-Za-z0-9.]*)`)

// NmapVersion runs "nmap --version" and returns the version it prints.
func NmapVersion(ctx context.Context, path string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, path, "--version").CombinedOutput()
	if m := nmapVersionRE.FindSubmatch(out); m != nil {
		return string(m[1]), nil
	}
	if err != nil {
		return "", fmt.Errorf("%s --version failed: %v %s", path, err, firstLine(out))
	}
	return "", fmt.Errorf("%s --version did not say which version it is", path)
}

// VersionAtLeast compares dotted versions such as 7.94 and 7.80.
func VersionAtLeast(v, min string) bool { return compareVersions(v, min) >= 0 }

// Args returns Nmap's command line for a network. Scans use TCP connect
// (-sT --unprivileged): they work the same on Windows and Linux, as any
// account, with no packet capture driver or raw sockets. -sV asks each open
// port which software and version answers, which is what CVEs are matched
// to. Results go to standard output as XML, with progress every 15
// seconds.
func Args(t Target) []string {
	a := []string{"-oX", "-", "--no-stylesheet", "--stats-every", "15s", "--unprivileged", "-sT", "-sV", "--open",
		// Hosts that answer on any of these ports count as up, which finds
		// Windows hosts that do not answer ping.
		"-PS21,22,23,25,80,135,139,443,445,3389,8080,8443"}
	switch t.Ports {
	case PortsTop100:
		a = append(a, "--top-ports", "100")
	case PortsTop1000, "":
		a = append(a, "--top-ports", "1000")
	case PortsAll:
		a = append(a, "-p-")
	default:
		a = append(a, "-p", t.Ports)
	}
	if t.Gentle {
		// Slow and light: one probe at a time, at most 20 packets a second,
		// only the likeliest version probes.
		a = append(a, "-T2", "--max-rate", "20", "--max-parallelism", "1", "--max-retries", "1", "--version-light", "--host-timeout", "60m")
	} else {
		a = append(a, "-T4", "--version-intensity", "7", "--max-retries", "2", "--host-timeout", "30m")
	}
	if len(t.Exclude) > 0 {
		a = append(a, "--exclude", strings.Join(t.Exclude, ","))
	}
	return append(a, t.Networks...)
}

// Progress is how far a running scan is.
type Progress struct {
	Percent float64   `json:"percent"`
	Task    string    `json:"task,omitempty"`
	ETA     time.Time `json:"eta,omitzero"`
	// HostsUp counts the hosts found so far.
	HostsUp int `json:"hosts_up"`
}

// Runner runs Nmap. Tests replace Exec.
type Runner struct {
	Path string
	// Exec starts the program; nil uses os/exec.
	Exec func(ctx context.Context, path string, args []string) (stdout io.ReadCloser, wait func() (stderr []byte, err error), err error)
}

func execNmap(ctx context.Context, path string, args []string) (io.ReadCloser, func() ([]byte, error), error) {
	cmd := exec.CommandContext(ctx, path, args...)
	var stderr limitedBuffer
	cmd.Stderr = &stderr
	cmd.WaitDelay = 10 * time.Second
	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, nil, err
	}
	return out, func() ([]byte, error) { err := cmd.Wait(); return stderr.Bytes(), err }, nil
}

// Scan runs Nmap on a network, calling progress as it goes, and returns
// the hosts it found up.
func (r *Runner) Scan(ctx context.Context, t Target, progress func(Progress)) ([]ScannedHost, error) {
	if r.Path == "" {
		return nil, errors.New("Nmap is not installed on the scanning server")
	}
	start := r.Exec
	if start == nil {
		start = execNmap
	}
	out, wait, err := start(ctx, r.Path, Args(t))
	if err != nil {
		return nil, fmt.Errorf("could not start Nmap: %w", err)
	}
	hosts, perr := parseNmap(out, progress)
	// Drain what is left so Nmap is not stuck writing.
	_, _ = io.Copy(io.Discard, out)
	_ = out.Close()
	stderr, werr := wait()
	if ctx.Err() != nil {
		return hosts, ctx.Err()
	}
	if werr != nil {
		msg := firstLine(stderr)
		if msg == "" {
			msg = werr.Error()
		}
		return hosts, fmt.Errorf("Nmap stopped with an error: %s", msg)
	}
	if perr != nil {
		return hosts, fmt.Errorf("could not read Nmap's results: %w", perr)
	}
	return hosts, nil
}

// limitedBuffer keeps the first 64 KB written to it.
type limitedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *limitedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if room := 64<<10 - l.b.Len(); room > 0 {
		l.b.Write(p[:min(len(p), room)])
	}
	return len(p), nil
}

func (l *limitedBuffer) Bytes() []byte {
	l.mu.Lock()
	defer l.mu.Unlock()
	return bytes.Clone(l.b.Bytes())
}

// firstLine is the first line of a program's output that says something,
// skipping Nmap's banner.
func firstLine(b []byte) string {
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		l := strings.TrimSpace(sc.Text())
		if l == "" || strings.HasPrefix(l, "Starting Nmap") || strings.HasPrefix(l, "WARNING: Could not import all necessary Npcap") {
			continue
		}
		if len(l) > 300 {
			l = l[:300] + "…"
		}
		return l
	}
	return ""
}

// ScannedHost is one host a scan found up.
type ScannedHost struct {
	Address  string    `json:"address"`
	Hostname string    `json:"hostname,omitempty"`
	MAC      string    `json:"mac,omitempty"`
	Vendor   string    `json:"vendor,omitempty"`
	Services []Service `json:"services"`
}

// Service is an open port and what answers on it.
type Service struct {
	Port      int    `json:"port"`
	Transport string `json:"transport"`
	Name      string `json:"name,omitempty"`
	Product   string `json:"product,omitempty"`
	Version   string `json:"version,omitempty"`
	Extra     string `json:"extra,omitempty"`
	// Tunnel is ssl when the service runs over TLS.
	Tunnel string   `json:"tunnel,omitempty"`
	CPEs   []string `json:"cpes,omitempty"`
}

// Nmap's XML (-oX), the parts read here.
type xmlHost struct {
	Status struct {
		State string `xml:"state,attr"`
	} `xml:"status"`
	Addresses []struct {
		Addr   string `xml:"addr,attr"`
		Type   string `xml:"addrtype,attr"`
		Vendor string `xml:"vendor,attr"`
	} `xml:"address"`
	Hostnames []struct {
		Name string `xml:"name,attr"`
		Type string `xml:"type,attr"`
	} `xml:"hostnames>hostname"`
	Ports []struct {
		Protocol string `xml:"protocol,attr"`
		PortID   int    `xml:"portid,attr"`
		State    struct {
			State string `xml:"state,attr"`
		} `xml:"state"`
		Service struct {
			Name      string   `xml:"name,attr"`
			Product   string   `xml:"product,attr"`
			Version   string   `xml:"version,attr"`
			ExtraInfo string   `xml:"extrainfo,attr"`
			Tunnel    string   `xml:"tunnel,attr"`
			CPEs      []string `xml:"cpe"`
		} `xml:"service"`
	} `xml:"ports>port"`
}

type xmlProgress struct {
	Task    string  `xml:"task,attr"`
	Percent float64 `xml:"percent,attr"`
	Etc     int64   `xml:"etc,attr"`
}

// maxHosts bounds what one scan keeps: a /16 has 65536 addresses.
const maxHosts = 70000

// parseNmap reads Nmap's XML as it comes.
func parseNmap(r io.Reader, progress func(Progress)) ([]ScannedHost, error) {
	dec := xml.NewDecoder(r)
	dec.Strict = false
	var hosts []ScannedHost
	finished := false
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return hosts, err
		}
		se, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}
		switch se.Name.Local {
		case "host":
			var h xmlHost
			if err := dec.DecodeElement(&h, &se); err != nil {
				return hosts, err
			}
			if sh, ok := h.scanned(); ok && len(hosts) < maxHosts {
				hosts = append(hosts, sh)
				if progress != nil {
					progress(Progress{Percent: -1, HostsUp: len(hosts)})
				}
			}
		case "taskprogress":
			var p xmlProgress
			if err := dec.DecodeElement(&p, &se); err == nil && progress != nil {
				pr := Progress{Percent: p.Percent, Task: p.Task, HostsUp: len(hosts)}
				if p.Etc > 0 {
					pr.ETA = time.Unix(p.Etc, 0)
				}
				progress(pr)
			}
		case "finished":
			finished = true
		}
	}
	if !finished {
		return hosts, errors.New("the results end before the scan finished")
	}
	return hosts, nil
}

func (h xmlHost) scanned() (ScannedHost, bool) {
	if h.Status.State != "up" {
		return ScannedHost{}, false
	}
	var sh ScannedHost
	for _, a := range h.Addresses {
		switch a.Type {
		case "ipv4", "ipv6":
			if sh.Address == "" {
				sh.Address = a.Addr
			}
		case "mac":
			sh.MAC, sh.Vendor = a.Addr, a.Vendor
		}
	}
	if sh.Address == "" {
		return ScannedHost{}, false
	}
	for _, n := range h.Hostnames {
		if n.Type == "user" || sh.Hostname == "" {
			sh.Hostname = n.Name
		}
	}
	sh.Services = []Service{}
	for _, p := range h.Ports {
		if p.State.State != "open" {
			continue
		}
		s := Service{Port: p.PortID, Transport: p.Protocol, Name: p.Service.Name, Product: p.Service.Product,
			Version: p.Service.Version, Extra: p.Service.ExtraInfo, Tunnel: p.Service.Tunnel}
		for _, c := range p.Service.CPEs {
			if c = strings.TrimSpace(c); c != "" {
				s.CPEs = append(s.CPEs, c)
			}
		}
		sh.Services = append(sh.Services, s)
	}
	return sh, true
}

// compareVersions compares versions part by part: numbers as numbers,
// letters as text, and a number above letters (1.0 > 1.0beta).
func compareVersions(a, b string) int {
	pa, pb := versionParts(a), versionParts(b)
	for i := 0; i < max(len(pa), len(pb)); i++ {
		var x, y string
		if i < len(pa) {
			x = pa[i]
		}
		if i < len(pb) {
			y = pb[i]
		}
		if x == y {
			continue
		}
		xn, xerr := strconv.ParseUint(x, 10, 64)
		yn, yerr := strconv.ParseUint(y, 10, 64)
		switch {
		case xerr == nil && yerr == nil:
			if xn < yn {
				return -1
			}
			return 1
		case x == "":
			// 1.0 vs 1.0.1: shorter is older; 1.0 vs 1.0rc1: a release
			// is newer than its pre-release.
			if yerr != nil && isPre(y) {
				return 1
			}
			return -1
		case y == "":
			if xerr != nil && isPre(x) {
				return -1
			}
			return 1
		case xerr == nil:
			return 1
		case yerr == nil:
			return -1
		default:
			if x < y {
				return -1
			}
			return 1
		}
	}
	return 0
}

func isPre(s string) bool {
	for _, p := range []string{"alpha", "beta", "rc", "pre", "dev", "a", "b"} {
		if s == p {
			return true
		}
	}
	return false
}

// versionParts splits 7.4p1 into 7, 4, p, 1.
func versionParts(v string) []string {
	v = strings.ToLower(strings.TrimSpace(v))
	var parts []string
	cur := []rune{}
	kind := 0 // 1 digits, 2 letters
	flush := func() {
		if len(cur) > 0 {
			parts = append(parts, string(cur))
			cur = cur[:0]
		}
	}
	for _, r := range v {
		k := 0
		switch {
		case r >= '0' && r <= '9':
			k = 1
		case r >= 'a' && r <= 'z':
			k = 2
		}
		if k == 0 {
			flush()
			kind = 0
			continue
		}
		if k != kind {
			flush()
		}
		kind = k
		cur = append(cur, r)
	}
	flush()
	// Leading zeros do not matter: 7.04 is 7.4.
	for i, p := range parts {
		if t := strings.TrimLeft(p, "0"); t != p && p[0] == '0' {
			if t == "" {
				t = "0"
			}
			if _, err := strconv.Atoi(t); err == nil {
				parts[i] = t
			}
		}
	}
	return parts
}
