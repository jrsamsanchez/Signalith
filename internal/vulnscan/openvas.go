package vulnscan

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

// OpenVAS runs deeper scans with OpenVAS, through the Greenbone Vulnerability
// Manager (gvmd) and its Greenbone Management Protocol (GMP): an XML
// command, then an XML answer, over a Unix socket or TLS.
//
// OpenVAS is optional. It tests for thousands of known weaknesses by
// probing them (missing patches, default passwords, weak TLS), where Nmap
// only reads software versions. It is much slower and heavier on the
// network, so a network turns it on by itself.
type OpenVAS struct {
	// Address is gvmd's Unix socket (/run/gvmd/gvmd.sock) or host:port of
	// its TLS port (usually 9390).
	Address  string
	Username string
	Password string
	// CAFile verifies gvmd's TLS certificate; empty uses the system's.
	CAFile string
	// Poll is how often a running scan is looked at (default 15 seconds).
	Poll time.Duration
	// Dial overrides how gvmd is reached (tests).
	Dial func(ctx context.Context) (net.Conn, error)
}

// IDs of objects every Greenbone install has.
const (
	gvmConfigFullAndFast = "daba56c8-73ec-11df-a475-002264764cea"
	gvmScannerOpenVAS    = "08b69003-5fc2-4037-a479-93b440211c73"
	gvmPortsIANATCP      = "33d0cd82-57c6-11e1-8ed1-406186ea4fc5"
	gvmPortsAllTCP       = "fd591a34-56fd-11e1-9f27-406186ea4fc5"
	// minQoD leaves out results OpenVAS is unsure of, as its own reports
	// do by default.
	minQoD = 70
)

// Configured reports whether OpenVAS is set up on this server.
func (o *OpenVAS) Configured() bool { return o != nil && o.Address != "" && o.Username != "" }

// gmpConn is one signed-in GMP session.
type gmpConn struct {
	c   net.Conn
	dec *xml.Decoder
}

func (o *OpenVAS) dial(ctx context.Context) (net.Conn, error) {
	if o.Dial != nil {
		return o.Dial(ctx)
	}
	var d net.Dialer
	if strings.HasPrefix(o.Address, "/") || strings.HasPrefix(o.Address, "unix:") || strings.HasPrefix(o.Address, `\\`) {
		return d.DialContext(ctx, "unix", strings.TrimPrefix(o.Address, "unix:"))
	}
	host, _, err := net.SplitHostPort(o.Address)
	if err != nil {
		return nil, fmt.Errorf("OpenVAS address %q is neither a socket path nor host:port", o.Address)
	}
	cfg := &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}
	if o.CAFile != "" {
		pem, err := os.ReadFile(o.CAFile)
		if err != nil {
			return nil, fmt.Errorf("OpenVAS CA file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("OpenVAS CA file has no certificate")
		}
		cfg.RootCAs = pool
	}
	return (&tls.Dialer{NetDialer: &d, Config: cfg}).DialContext(ctx, "tcp", o.Address)
}

// open connects and signs in.
func (o *OpenVAS) open(ctx context.Context) (*gmpConn, error) {
	c, err := o.dial(ctx)
	if err != nil {
		return nil, fmt.Errorf("could not reach OpenVAS at %s: %w", o.Address, err)
	}
	g := &gmpConn{c: c, dec: xml.NewDecoder(c)}
	var auth gmpStatus
	if err := g.do(ctx, gmpAuth{Username: o.Username, Password: o.Password}, &auth); err != nil {
		c.Close()
		return nil, err
	}
	return g, nil
}

func (g *gmpConn) Close() error { return g.c.Close() }

// gmpStatus is the status every GMP answer carries.
type gmpStatus struct {
	Status     string `xml:"status,attr"`
	StatusText string `xml:"status_text,attr"`
}

func (s gmpStatus) err(what string) error {
	if strings.HasPrefix(s.Status, "2") {
		return nil
	}
	if s.Status == "400" && strings.Contains(strings.ToLower(s.StatusText), "authentication") {
		return errors.New("OpenVAS refused the user name or password")
	}
	return fmt.Errorf("OpenVAS refused %s: %s %s", what, s.Status, s.StatusText)
}

type statusOf interface{ status() gmpStatus }

func (s gmpStatus) status() gmpStatus { return s }

// do sends one command and reads its answer into out.
func (g *gmpConn) do(ctx context.Context, cmd any, out statusOf) error {
	dl, ok := ctx.Deadline()
	if !ok {
		dl = time.Now().Add(2 * time.Minute)
	}
	_ = g.c.SetDeadline(dl)
	b, err := xml.Marshal(cmd)
	if err != nil {
		return err
	}
	if _, err := g.c.Write(b); err != nil {
		return fmt.Errorf("OpenVAS connection: %w", err)
	}
	if err := g.dec.Decode(out); err != nil {
		if errors.Is(err, io.EOF) {
			return errors.New("OpenVAS closed the connection")
		}
		return fmt.Errorf("OpenVAS answer: %w", err)
	}
	name := strings.TrimPrefix(fmt.Sprintf("%T", cmd), "vulnscan.")
	return out.status().err(name)
}

// GMP commands and answers, as far as Signalith uses them.
type gmpAuth struct {
	XMLName  xml.Name `xml:"authenticate"`
	Username string   `xml:"credentials>username"`
	Password string   `xml:"credentials>password"`
}

type gmpGetVersion struct {
	XMLName xml.Name `xml:"get_version"`
}

type gmpVersion struct {
	gmpStatus
	Version string `xml:"version"`
}

type gmpRef struct {
	ID string `xml:"id,attr"`
}

type gmpCreateTarget struct {
	XMLName      xml.Name `xml:"create_target"`
	Name         string   `xml:"name"`
	Comment      string   `xml:"comment"`
	Hosts        string   `xml:"hosts"`
	ExcludeHosts string   `xml:"exclude_hosts,omitempty"`
	PortRange    string   `xml:"port_range,omitempty"`
	PortList     *gmpRef  `xml:"port_list,omitempty"`
	AliveTests   string   `xml:"alive_tests"`
}

type gmpCreateTask struct {
	XMLName xml.Name `xml:"create_task"`
	Name    string   `xml:"name"`
	Comment string   `xml:"comment"`
	Config  gmpRef   `xml:"config"`
	Target  gmpRef   `xml:"target"`
	Scanner gmpRef   `xml:"scanner"`
}

type gmpCreated struct {
	gmpStatus
	ID string `xml:"id,attr"`
}

type gmpStartTask struct {
	XMLName xml.Name `xml:"start_task"`
	TaskID  string   `xml:"task_id,attr"`
}

type gmpStarted struct {
	gmpStatus
	ReportID string `xml:"report_id"`
}

type gmpStopTask struct {
	XMLName xml.Name `xml:"stop_task"`
	TaskID  string   `xml:"task_id,attr"`
}

type gmpGetTasks struct {
	XMLName xml.Name `xml:"get_tasks"`
	TaskID  string   `xml:"task_id,attr"`
}

type gmpTasks struct {
	gmpStatus
	Task struct {
		Status   string `xml:"status"`
		Progress string `xml:"progress"`
	} `xml:"task"`
}

type gmpDelete struct {
	XMLName  xml.Name
	TaskID   string `xml:"task_id,attr,omitempty"`
	TargetID string `xml:"target_id,attr,omitempty"`
	Ultimate string `xml:"ultimate,attr"`
}

type gmpGetReports struct {
	XMLName          xml.Name `xml:"get_reports"`
	ReportID         string   `xml:"report_id,attr"`
	Filter           string   `xml:"filter,attr"`
	Details          string   `xml:"details,attr"`
	IgnorePagination string   `xml:"ignore_pagination,attr"`
}

type gmpReports struct {
	gmpStatus
	Results []gmpResult `xml:"report>report>results>result"`
}

type gmpResult struct {
	Host struct {
		Address  string `xml:",chardata"`
		Hostname string `xml:"hostname"`
	} `xml:"host"`
	Port string `xml:"port"`
	NVT  struct {
		OID      string `xml:"oid,attr"`
		Name     string `xml:"name"`
		Family   string `xml:"family"`
		Tags     string `xml:"tags"`
		Solution string `xml:"solution"`
		Refs     []struct {
			Type string `xml:"type,attr"`
			ID   string `xml:"id,attr"`
		} `xml:"refs>ref"`
	} `xml:"nvt"`
	Severity    string `xml:"severity"`
	QoD         int    `xml:"qod>value"`
	Description string `xml:"description"`
}

// Version asks OpenVAS which GMP version it speaks, after signing in: the
// setup check.
func (o *OpenVAS) Version(ctx context.Context) (string, error) {
	g, err := o.open(ctx)
	if err != nil {
		return "", err
	}
	defer g.Close()
	var v gmpVersion
	if err := g.do(ctx, gmpGetVersion{}, &v); err != nil {
		return "", err
	}
	return strings.TrimSpace(v.Version), nil
}

// Finding is one weakness OpenVAS found on a host.
type Finding struct {
	Address   string
	Hostname  string
	Port      int // 0 for the host itself (general/tcp, general/icmp)
	Transport string
	Vuln      Vuln
}

// Scan scans t with OpenVAS's "Full and fast" configuration and returns
// what it found. progress, when set, is called with the percent done. The
// task and target it makes are removed afterwards, whatever happens.
func (o *OpenVAS) Scan(ctx context.Context, t Target, name string, progress func(float64)) ([]Finding, error) {
	g, err := o.open(ctx)
	if err != nil {
		return nil, err
	}
	defer g.Close()
	tgt := gmpCreateTarget{Name: name, Comment: "Made by Signalith for one scan; removed when it ends.",
		Hosts: strings.Join(t.Networks, ","), ExcludeHosts: strings.Join(t.Exclude, ","), AliveTests: "Scan Config Default"}
	switch t.Ports {
	case PortsAll:
		tgt.PortList = &gmpRef{ID: gvmPortsAllTCP}
	case PortsTop100, PortsTop1000, "":
		tgt.PortList = &gmpRef{ID: gvmPortsIANATCP}
	default:
		tgt.PortRange = "T:" + t.Ports
	}
	var created gmpCreated
	if err := g.do(ctx, tgt, &created); err != nil {
		return nil, err
	}
	targetID := created.ID
	// Clean up on a fresh connection when ctx ended.
	cleanup := func(taskID string) {
		cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer cancel()
		c := g
		if ctx.Err() != nil {
			nc, err := o.open(cctx)
			if err != nil {
				return
			}
			defer nc.Close()
			c = nc
		}
		var st gmpStatus
		if taskID != "" {
			_ = c.do(cctx, gmpStopTask{TaskID: taskID}, &st)
			_ = c.do(cctx, gmpDelete{XMLName: xml.Name{Local: "delete_task"}, TaskID: taskID, Ultimate: "1"}, &st)
		}
		_ = c.do(cctx, gmpDelete{XMLName: xml.Name{Local: "delete_target"}, TargetID: targetID, Ultimate: "1"}, &st)
	}
	task := gmpCreateTask{Name: name, Comment: tgt.Comment, Config: gmpRef{ID: gvmConfigFullAndFast},
		Target: gmpRef{ID: targetID}, Scanner: gmpRef{ID: gvmScannerOpenVAS}}
	if err := g.do(ctx, task, &created); err != nil {
		cleanup("")
		return nil, err
	}
	taskID := created.ID
	defer cleanup(taskID)
	var started gmpStarted
	if err := g.do(ctx, gmpStartTask{TaskID: taskID}, &started); err != nil {
		return nil, err
	}
	poll := o.Poll
	if poll <= 0 {
		poll = 15 * time.Second
	}
	for {
		var ts gmpTasks
		if err := g.do(ctx, gmpGetTasks{TaskID: taskID}, &ts); err != nil {
			return nil, err
		}
		switch ts.Task.Status {
		case "Done":
			return o.results(ctx, g, started.ReportID)
		case "Stopped", "Interrupted", "Stop Requested":
			return nil, fmt.Errorf("the OpenVAS scan ended as %s; OpenVAS's own log says why", strings.ToLower(ts.Task.Status))
		}
		if p, err := strconv.ParseFloat(ts.Task.Progress, 64); err == nil && p >= 0 && progress != nil {
			progress(p)
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(poll):
		}
	}
}

func (o *OpenVAS) results(ctx context.Context, g *gmpConn, reportID string) ([]Finding, error) {
	var rep gmpReports
	err := g.do(ctx, gmpGetReports{ReportID: reportID, Details: "1", IgnorePagination: "1",
		Filter: fmt.Sprintf("apply_overrides=1 min_qod=%d levels=hml rows=-1 first=1", minQoD)}, &rep)
	if err != nil {
		return nil, err
	}
	return findings(rep.Results), nil
}

// findings reads OpenVAS's results, leaving out the ones it is unsure of
// and the ones that are only information.
func findings(results []gmpResult) []Finding {
	var out []Finding
	for _, r := range results {
		sev, err := strconv.ParseFloat(strings.TrimSpace(r.Severity), 64)
		if err != nil || !(sev > 0 && sev <= 10) || r.QoD < minQoD {
			continue
		}
		f := Finding{Address: strings.TrimSpace(r.Host.Address), Hostname: strings.TrimSpace(r.Host.Hostname)}
		f.Port, f.Transport = splitPort(r.Port)
		v := Vuln{Source: SourceOpenVAS, OID: r.NVT.OID, Name: strings.TrimSpace(r.NVT.Name), CVSS: sev, Severity: severityOf(sev)}
		var cves []string
		for _, ref := range r.NVT.Refs {
			if strings.EqualFold(ref.Type, "cve") {
				cves = append(cves, ref.ID)
			}
		}
		sort.Strings(cves)
		if len(cves) > 0 {
			v.CVE = cves[len(cves)-1]
			v.CVEs = cves
		}
		v.Description = tag(r.NVT.Tags, "summary")
		if v.Description == "" {
			v.Description = strings.TrimSpace(r.Description)
		}
		v.Description = truncate(v.Description, 2000)
		v.Solution = truncate(strings.TrimSpace(r.NVT.Solution), 1000)
		if v.Solution == "" {
			v.Solution = truncate(tag(r.NVT.Tags, "solution"), 1000)
		}
		if f.Address == "" {
			continue
		}
		f.Vuln = v
		out = append(out, f)
	}
	return out
}

// splitPort reads "443/tcp"; "general/tcp" is the host itself.
func splitPort(p string) (int, string) {
	num, tr, _ := strings.Cut(strings.TrimSpace(p), "/")
	n, err := strconv.Atoi(num)
	if err != nil {
		n = 0
	}
	return n, tr
}

// tag reads one key of an NVT's tags, written key=value|key=value.
func tag(tags, key string) string {
	for _, kv := range strings.Split(tags, "|") {
		if k, v, ok := strings.Cut(kv, "="); ok && k == key {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func severityOf(score float64) string {
	switch {
	case score >= 9:
		return "critical"
	case score >= 7:
		return "high"
	case score >= 4:
		return "medium"
	default:
		return "low"
	}
}

// MergeOpenVAS adds what OpenVAS found to the hosts Nmap found: to the
// open port it names, a port of its own when Nmap did not list it, or the
// host itself (port 0). A CVE already matched from the software version is
// not listed twice.
func MergeOpenVAS(hosts []*Host, found []Finding, t Target, scanID string, at time.Time) []*Host {
	byAddr := map[string]*Host{}
	for _, h := range hosts {
		byAddr[h.Address] = h
	}
	for _, f := range found {
		h := byAddr[f.Address]
		if h == nil {
			h = &Host{ID: HostID(t.ID, f.Address), TargetID: t.ID, TargetName: t.Name, Address: f.Address, Hostname: f.Hostname,
				ScanID: scanID, FirstSeen: at, LastSeen: at, Services: []HostService{}}
			byAddr[f.Address] = h
			hosts = append(hosts, h)
		}
		i := -1
		for j := range h.Services {
			if h.Services[j].Port == f.Port && (f.Transport == "" || h.Services[j].Transport == f.Transport) {
				i = j
				break
			}
		}
		if i < 0 {
			svc := Service{Port: f.Port, Transport: f.Transport}
			if f.Port == 0 {
				svc.Name = "host"
			}
			h.Services = append(h.Services, HostService{Service: svc})
			i = len(h.Services) - 1
		}
		dup := false
		for _, v := range h.Services[i].Vulns {
			if (f.Vuln.CVE != "" && v.CVE == f.Vuln.CVE) || (f.Vuln.OID != "" && v.OID == f.Vuln.OID) {
				dup = true
				break
			}
		}
		if !dup {
			h.Services[i].Vulns = append(h.Services[i].Vulns, f.Vuln)
		}
	}
	for _, h := range hosts {
		sort.SliceStable(h.Services, func(a, b int) bool { return h.Services[a].Port < h.Services[b].Port })
		for i := range h.Services {
			vs := h.Services[i].Vulns
			sort.SliceStable(vs, func(a, b int) bool {
				if vs[a].KEV != vs[b].KEV {
					return vs[a].KEV
				}
				return vs[a].CVSS > vs[b].CVSS
			})
		}
	}
	SortHosts(hosts)
	return hosts
}

// Recount sums the hosts' CVEs and weaknesses up again, each host's and
// all of them.
func Recount(hosts []*Host) Counts {
	var total Counts
	for _, h := range hosts {
		h.Counts, h.MaxCVSS = Counts{Hosts: 1}, 0
		for _, svc := range h.Services {
			if svc.Port > 0 {
				h.Counts.Services++
			}
			for _, v := range svc.Vulns {
				h.Counts.add(v.Severity, v.KEV)
				total.add(v.Severity, v.KEV)
				h.MaxCVSS = max(h.MaxCVSS, v.CVSS)
			}
		}
		total.Services += h.Counts.Services
	}
	total.Hosts = len(hosts)
	return total
}
