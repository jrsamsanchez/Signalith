//go:build greenbone

package vulnscan

import (
	"context"
	"encoding/xml"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"
	"time"
)

// TestGreenbone runs a real OpenVAS scan through a real Greenbone
// Community Edition: deploy/ci/greenbone/compose.yaml, started by
// .github/workflows/greenbone.yml. It waits for the feed to load, scans
// the two vulnerable targets there, and checks what comes back.
//
//	SIGNALITH_GREENBONE_SOCKET   gvmd's socket (default /tmp/gvmd/gvmd.sock)
//	SIGNALITH_GREENBONE_USER     default admin
//	SIGNALITH_GREENBONE_PASSWORD default admin
//	SIGNALITH_GREENBONE_TARGETS  default 172.29.0.50,172.29.0.51
//	SIGNALITH_GREENBONE_SSH_KEY  the private key the SSH target lets
//	                             signalith-scan sign in with; unset skips
//	                             the signed-in scan
//	SIGNALITH_GREENBONE_SSH      the SSH target (default 172.29.0.52)
//	SIGNALITH_GREENBONE_REPORT   a Markdown file to write the findings to
func TestGreenbone(t *testing.T) {
	env := func(k, def string) string {
		if v := os.Getenv(k); v != "" {
			return v
		}
		return def
	}
	ov := &OpenVAS{Address: env("SIGNALITH_GREENBONE_SOCKET", "/tmp/gvmd/gvmd.sock"),
		Username: env("SIGNALITH_GREENBONE_USER", "admin"), Password: env("SIGNALITH_GREENBONE_PASSWORD", "admin"),
		Poll: 10 * time.Second}
	targets := strings.Split(env("SIGNALITH_GREENBONE_TARGETS", "172.29.0.50,172.29.0.51"), ",")
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Minute)
	defer cancel()

	// gvmd answers once it has started and made its admin user.
	var version string
	waitFor(ctx, t, 30*time.Minute, "gvmd to answer", func() (bool, string) {
		v, err := ov.Version(ctx)
		if err != nil {
			return false, err.Error()
		}
		version = v
		return true, ""
	})
	t.Logf("gvmd speaks GMP %s", version)

	// "Full and fast" fills with tests once gvmd has read them from the
	// scanner, which takes a while after a first start.
	waitFor(ctx, t, 90*time.Minute, "the feed to load", func() (bool, string) {
		_, n, err := ov.Ready(ctx)
		if err != nil {
			return false, err.Error()
		}
		return n >= 1000, fmt.Sprintf("Full and fast has %d tests", n)
	})

	// The setup check Signalith runs on the Scanners page.
	if ck := (&Checker{OpenVAS: ov}).openVASCheck(ctx, []Target{{OpenVAS: true}}); ck.State != CheckOK {
		t.Errorf("setup check = %s: %s", ck.State, ck.Detail)
	} else {
		t.Logf("setup check: %s", ck.Detail)
	}

	start := time.Now()
	last := -1.0
	found, err := ov.Scan(ctx, Target{Networks: targets, Ports: "80,6379"}, "Signalith Greenbone check", ScanLogins{}, func(p float64) {
		if p >= last+10 {
			t.Logf("scan %.0f%% after %s", p, time.Since(start).Round(time.Second))
			last = p
		}
	})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	took := time.Since(start).Round(time.Second)
	t.Logf("scan done in %s with %d findings", took, len(found))
	writeReport(t, env("SIGNALITH_GREENBONE_REPORT", ""), version, took, found)

	if left, err := leftovers(ctx, ov, "Signalith Greenbone check"); err != nil || left != 0 {
		t.Errorf("tasks and targets left behind = %d, %v", left, err)
	}
	byHost := map[string]int{}
	for _, f := range found {
		t.Logf("found %s port %d/%s: %s %.1f %s %v (%s)", f.Address, f.Port, f.Transport, f.Vuln.Severity, f.Vuln.CVSS, f.Vuln.Name, f.Vuln.CVEs, f.Vuln.OID)
		byHost[f.Address]++
		if f.Vuln.OID == "" || f.Vuln.Name == "" || f.Vuln.Severity == "" || f.Vuln.Source != SourceOpenVAS {
			t.Errorf("incomplete finding %+v", f)
		}
	}
	if byHost[targets[0]] == 0 {
		t.Errorf("nothing found on %s (Apache 2.4.49); findings by host: %v", targets[0], byHost)
	}
	// What Signalith shows: merged into the hosts and counted.
	hosts := MergeOpenVAS(nil, found, Target{ID: "gb", Name: "Greenbone check"}, "s1", time.Now())
	t.Logf("as hosts: %+v", Recount(hosts))

	// Signed in over SSH with a key, OpenVAS reads the installed packages
	// and reports the ones with security advisories, which it cannot see
	// from outside.
	keyFile := env("SIGNALITH_GREENBONE_SSH_KEY", "")
	if keyFile == "" {
		t.Log("SIGNALITH_GREENBONE_SSH_KEY is not set: no signed-in scan")
		return
	}
	key, err := os.ReadFile(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	sshHost := env("SIGNALITH_GREENBONE_SSH", "172.29.0.52")
	start = time.Now()
	login := &Login{Kind: LoginSSH, Username: "signalith-scan", Auth: AuthKey, Port: 22, Secret: string(key)}
	signed, err := ov.Scan(ctx, Target{Networks: []string{sshHost}, Ports: "22"}, "Signalith Greenbone signed-in check", ScanLogins{SSH: login}, func(float64) {})
	if err != nil {
		t.Fatalf("signed-in scan: %v", err)
	}
	advisories := 0
	for _, f := range signed {
		if strings.Contains(f.Vuln.Name, "Security Advisory") {
			advisories++
		}
	}
	t.Logf("signed-in scan done in %s with %d findings, %d from security advisories", time.Since(start).Round(time.Second), len(signed), advisories)
	appendReport(t, env("SIGNALITH_GREENBONE_REPORT", ""), sshHost, signed, advisories)
	if advisories == 0 {
		t.Errorf("the signed-in scan of %s found no package advisories: OpenVAS did not sign in", sshHost)
	}
	if left, err := leftovers(ctx, ov, "Signalith Greenbone signed-in check"); err != nil || left != 0 {
		t.Errorf("tasks, targets and logins left behind = %d, %v", left, err)
	}
}

// appendReport adds the signed-in scan's findings to the report.
func appendReport(t *testing.T, path, host string, found []Finding, advisories int) {
	if path == "" {
		return
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0o644)
	if err != nil {
		t.Errorf("report: %v", err)
		return
	}
	defer f.Close()
	fmt.Fprintf(f, "\n## Signed-in scan over SSH (%s)\n\n%d findings, %d from package security advisories.\n\n", host, len(found), advisories)
	n := 0
	for _, x := range found {
		if n == 15 {
			fmt.Fprintf(f, "\nand %d more.\n", len(found)-n)
			break
		}
		fmt.Fprintf(f, "- %s %.1f: %s\n", x.Vuln.Severity, x.Vuln.CVSS, strings.ReplaceAll(x.Vuln.Name, "|", "/"))
		n++
	}
}

// waitFor calls ok until it reports true, logging its note now and then.
func waitFor(ctx context.Context, t *testing.T, limit time.Duration, what string, ok func() (bool, string)) {
	t.Helper()
	start := time.Now()
	lastLog := time.Time{}
	for {
		done, note := ok()
		if done {
			t.Logf("%s: ready after %s", what, time.Since(start).Round(time.Second))
			return
		}
		if time.Since(lastLog) >= time.Minute {
			t.Logf("waiting for %s (%s): %s", what, time.Since(start).Round(time.Second), note)
			lastLog = time.Now()
		}
		if time.Since(start) > limit || ctx.Err() != nil {
			t.Fatalf("gave up waiting for %s after %s: %s", what, limit, note)
		}
		time.Sleep(15 * time.Second)
	}
}

type gmpGetByFilter struct {
	XMLName xml.Name
	Filter  string `xml:"filter,attr"`
}

type gmpList struct {
	gmpStatus
	Tasks       []gmpRef `xml:"task"`
	Targets     []gmpRef `xml:"target"`
	Credentials []gmpRef `xml:"credential"`
}

// leftovers counts the tasks, targets and logins named name.
func leftovers(ctx context.Context, ov *OpenVAS, name string) (int, error) {
	g, err := ov.open(ctx)
	if err != nil {
		return 0, err
	}
	defer g.Close()
	n := 0
	for _, cmd := range []string{"get_tasks", "get_targets", "get_credentials"} {
		var l gmpList
		filter := fmt.Sprintf("name=%q rows=-1", name)
		if cmd == "get_credentials" {
			// Logins are named for the scan and their kind.
			filter = fmt.Sprintf("name~%q rows=-1", name)
		}
		if err := g.do(ctx, gmpGetByFilter{XMLName: xml.Name{Local: cmd}, Filter: filter}, &l); err != nil {
			return 0, err
		}
		n += len(l.Tasks) + len(l.Targets) + len(l.Credentials)
	}
	return n, nil
}

// writeReport writes the findings as Markdown, for the job summary and
// docs.
func writeReport(t *testing.T, path, version string, took time.Duration, found []Finding) {
	if path == "" {
		return
	}
	sort.Slice(found, func(i, j int) bool {
		if found[i].Vuln.CVSS != found[j].Vuln.CVSS {
			return found[i].Vuln.CVSS > found[j].Vuln.CVSS
		}
		return found[i].Address+found[i].Vuln.Name < found[j].Address+found[j].Vuln.Name
	})
	var b strings.Builder
	fmt.Fprintf(&b, "## OpenVAS scan through Greenbone Community Edition\n\nGMP %s, scan took %s, %d findings with QoD %d or more.\n\n", version, took, len(found), minQoD)
	b.WriteString("| Host | Port | Severity | CVSS | Finding | CVEs |\n|---|---|---|---|---|---|\n")
	for _, f := range found {
		port := "host"
		if f.Port > 0 {
			port = fmt.Sprintf("%d/%s", f.Port, f.Transport)
		}
		fmt.Fprintf(&b, "| %s | %s | %s | %.1f | %s | %s |\n", f.Address, port, f.Vuln.Severity, f.Vuln.CVSS,
			strings.ReplaceAll(f.Vuln.Name, "|", "/"), strings.Join(f.Vuln.CVEs, ", "))
	}
	if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
		t.Errorf("report: %v", err)
	}
}
