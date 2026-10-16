package vulnscan

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"slices"
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
	// Log hears of what could not be removed from OpenVAS; nil uses
	// slog's default.
	Log *slog.Logger
}

// scanComment marks what Signalith makes in OpenVAS for one scan, so that
// whatever a scan could not remove is found and removed later.
const scanComment = "Made by Signalith for one scan; removed when it ends."

func (o *OpenVAS) log() *slog.Logger {
	if o.Log != nil {
		return o.Log
	}
	return slog.Default()
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
		// Not the marshaling error itself: a command may carry a password
		// or key, and the error ends up in the log and on the page.
		return fmt.Errorf("the OpenVAS command %T could not be written", cmd)
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
	SSHLogin     *gmpSSH  `xml:"ssh_credential,omitempty"`
	SMBLogin     *gmpRef  `xml:"smb_credential,omitempty"`
}

type gmpSSH struct {
	ID   string `xml:"id,attr"`
	Port int    `xml:"port"`
}

// gmpCreateCredential makes the login OpenVAS signs in to hosts with:
// type up is a user name and password, usk a user name and SSH key.
type gmpCreateCredential struct {
	XMLName  xml.Name `xml:"create_credential"`
	Name     string   `xml:"name"`
	Comment  string   `xml:"comment"`
	Type     string   `xml:"type"`
	Login    string   `xml:"login"`
	Password string   `xml:"password,omitempty"`
	Key      *gmpKey  `xml:"key,omitempty"`
}

type gmpKey struct {
	Private string `xml:"private"`
	Phrase  string `xml:"phrase,omitempty"`
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
	XMLName      xml.Name
	TaskID       string `xml:"task_id,attr,omitempty"`
	TargetID     string `xml:"target_id,attr,omitempty"`
	CredentialID string `xml:"credential_id,attr,omitempty"`
	Ultimate     string `xml:"ultimate,attr"`
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

type gmpGetConfigs struct {
	XMLName  xml.Name `xml:"get_configs"`
	ConfigID string   `xml:"config_id,attr"`
}

type gmpConfigs struct {
	gmpStatus
	Config struct {
		NVTCount struct {
			N string `xml:",chardata"`
		} `xml:"nvt_count"`
	} `xml:"config"`
}

// ErrFeedLoading is returned while a Greenbone install is still loading
// its feed: it cannot scan until then.
var ErrFeedLoading = errors.New("OpenVAS has not finished loading its feed of tests yet, so it cannot scan. " +
	"A new Greenbone install takes up to an hour; Settings > Scanners shows when it is ready")

// feedTests is how many tests the "Full and fast" scan configuration has:
// 0 while the feed is still loading.
func (g *gmpConn) feedTests(ctx context.Context) (int, error) {
	var c gmpConfigs
	if err := g.do(ctx, gmpGetConfigs{ConfigID: gvmConfigFullAndFast}, &c); err != nil {
		if c.Status == "404" {
			return 0, nil
		}
		return 0, err
	}
	n, _ := strconv.Atoi(strings.TrimSpace(c.Config.NVTCount.N))
	return n, nil
}

// Ready signs in and reports the GMP version and how many tests a scan
// runs, 0 while the feed is still loading: the setup check.
func (o *OpenVAS) Ready(ctx context.Context) (version string, tests int, err error) {
	g, err := o.open(ctx)
	if err != nil {
		return "", 0, err
	}
	defer g.Close()
	var v gmpVersion
	if err := g.do(ctx, gmpGetVersion{}, &v); err != nil {
		return "", 0, err
	}
	tests, err = g.feedTests(ctx)
	return strings.TrimSpace(v.Version), tests, err
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
// what it found, signing in to the hosts with the logins given. progress,
// when set, is called with the percent done. The task, target and logins
// it makes in OpenVAS are removed afterwards, on a connection of their
// own; what cannot be removed then is left to Sweep.
func (o *OpenVAS) Scan(ctx context.Context, t Target, name string, logins ScanLogins, progress func(float64)) ([]Finding, error) {
	g, err := o.open(ctx)
	if err != nil {
		return nil, err
	}
	defer g.Close()
	if n, err := g.feedTests(ctx); err != nil {
		return nil, err
	} else if n == 0 {
		return nil, ErrFeedLoading
	}
	tgt := gmpCreateTarget{Name: name, Comment: scanComment,
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
	var credIDs []string
	var targetID string
	// Clean up on a fresh connection: the scan's own may be the reason it
	// ended (gvmd restarted, or the connection broke).
	cleanup := func(taskID string) {
		cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Minute)
		defer cancel()
		c := g
		if nc, err := o.open(cctx); err == nil {
			defer nc.Close()
			c = nc
		}
		o.remove(cctx, c, taskID, targetID, credIDs)
	}
	for _, l := range []*Login{logins.SSH, logins.SMB} {
		if l == nil {
			continue
		}
		cred := gmpCreateCredential{Name: name + " " + l.Kind, Comment: tgt.Comment, Type: "up", Login: l.Username, Password: l.Secret}
		if l.Auth == AuthKey {
			cred.Type, cred.Password, cred.Key = "usk", "", &gmpKey{Private: l.Secret, Phrase: l.Passphrase}
		}
		if err := g.do(ctx, cred, &created); err != nil {
			cleanup("")
			return nil, fmt.Errorf("the %s login was not taken: %w", loginWord(l.Kind), err)
		}
		credIDs = append(credIDs, created.ID)
		if l.Kind == LoginSSH {
			port := l.Port
			if port == 0 {
				port = 22
			}
			tgt.SSHLogin = &gmpSSH{ID: created.ID, Port: port}
		} else {
			tgt.SMBLogin = &gmpRef{ID: created.ID}
		}
	}
	if err := g.do(ctx, tgt, &created); err != nil {
		cleanup("")
		return nil, err
	}
	targetID = created.ID
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

// remove stops and deletes a scan's task, then its target, then its
// logins (a target that uses one cannot go before it), and logs what it
// could not remove: a login left in OpenVAS is a secret left behind.
func (o *OpenVAS) remove(ctx context.Context, c *gmpConn, taskID, targetID string, credIDs []string) {
	var st gmpStatus
	if taskID != "" {
		_ = c.do(ctx, gmpStopTask{TaskID: taskID}, &st)
		// A task still stopping cannot be deleted yet, nor its target and
		// logins after it: try again for a while.
		wait := min(max(o.Poll, 10*time.Millisecond), 2*time.Second)
		var err error
		for try := 0; ; try++ {
			err = c.do(ctx, gmpDelete{XMLName: xml.Name{Local: "delete_task"}, TaskID: taskID, Ultimate: "1"}, &st)
			if err == nil || try == 29 || !sleepCtx(ctx, wait) {
				break
			}
		}
		if err != nil {
			o.log().Warn("vulnerability scans: could not remove an OpenVAS task; it is removed before the next scan", "task", taskID, "err", err)
		}
	}
	if targetID != "" {
		if err := c.do(ctx, gmpDelete{XMLName: xml.Name{Local: "delete_target"}, TargetID: targetID, Ultimate: "1"}, &st); err != nil {
			o.log().Warn("vulnerability scans: could not remove an OpenVAS target; it is removed before the next scan", "target", targetID, "err", err)
		}
	}
	for _, id := range credIDs {
		if err := c.do(ctx, gmpDelete{XMLName: xml.Name{Local: "delete_credential"}, CredentialID: id, Ultimate: "1"}, &st); err != nil {
			o.log().Warn("vulnerability scans: could not remove a scan login from OpenVAS; it is removed before the next scan", "credential", id, "err", err)
		}
	}
}

type gmpGetByFilter struct {
	XMLName xml.Name
	Filter  string `xml:"filter,attr"`
}

type gmpObject struct {
	ID      string `xml:"id,attr"`
	Name    string `xml:"name"`
	Comment string `xml:"comment"`
}

type gmpObjects struct {
	gmpStatus
	Tasks       []gmpObject `xml:"task"`
	Targets     []gmpObject `xml:"target"`
	Credentials []gmpObject `xml:"credential"`
}

// Sweep removes the tasks, targets and logins that scans made in OpenVAS
// and could not remove, such as when the server stopped mid-scan. live
// says whether the scan with that ID is still queued or running, on any
// server, as several may share one OpenVAS: its objects are kept. It
// returns how many objects it removed.
func (o *OpenVAS) Sweep(ctx context.Context, live func(scanID string) bool) (int, error) {
	g, err := o.open(ctx)
	if err != nil {
		return 0, err
	}
	defer g.Close()
	// The scan ID is the last word of the name; a login's name ends with
	// its kind after it.
	scanOf := func(ob gmpObject, login bool) (string, bool) {
		if ob.Comment != scanComment || !strings.HasPrefix(ob.Name, "Signalith ") {
			return "", false
		}
		f := strings.Fields(ob.Name)
		if login {
			f = f[:len(f)-1]
		}
		if len(f) < 2 {
			return "", false
		}
		return f[len(f)-1], true
	}
	var found [3][]string
	for i, cmd := range []string{"get_tasks", "get_targets", "get_credentials"} {
		var l gmpObjects
		if err := g.do(ctx, gmpGetByFilter{XMLName: xml.Name{Local: cmd}, Filter: "name~Signalith rows=-1"}, &l); err != nil {
			return 0, err
		}
		for _, ob := range slices.Concat(l.Tasks, l.Targets, l.Credentials) {
			if id, ok := scanOf(ob, i == 2); ok && !live(id) {
				found[i] = append(found[i], ob.ID)
			}
		}
	}
	for _, id := range found[0] {
		o.remove(ctx, g, id, "", nil)
	}
	for _, id := range found[1] {
		o.remove(ctx, g, "", id, nil)
	}
	o.remove(ctx, g, "", "", found[2])
	n := len(found[0]) + len(found[1]) + len(found[2])
	if n > 0 {
		o.log().Info("vulnerability scans: removed what earlier scans left in OpenVAS", "tasks", len(found[0]), "targets", len(found[1]), "logins", len(found[2]))
	}
	return n, nil
}

// sleepCtx waits for d, and reports false if ctx ends first.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

func loginWord(kind string) string {
	if kind == LoginSMB {
		return "Windows"
	}
	return "SSH"
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
			SortVulns(h.Services[i].Vulns)
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
		h.Counts, h.MaxCVSS, h.MaxEPSS = Counts{Hosts: 1}, 0, 0
		for _, svc := range h.Services {
			if svc.Port > 0 {
				h.Counts.Services++
			}
			for _, v := range svc.Vulns {
				h.Counts.add(v.Severity, v.KEV)
				total.add(v.Severity, v.KEV)
				if !v.KEV && v.Likely() {
					h.Counts.Likely++
					total.Likely++
				}
				h.MaxCVSS = max(h.MaxCVSS, v.CVSS)
				h.MaxEPSS = max(h.MaxEPSS, v.EPSS)
			}
		}
		total.Services += h.Counts.Services
	}
	total.Hosts = len(hosts)
	return total
}
