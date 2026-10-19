package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/config"
)

// validateConfig writes a signalith.yaml with its folders in a temporary
// folder, extra added, and returns its path and the loaded config.
func validateConfig(t *testing.T, url, extra string) (string, *config.Config) {
	t.Helper()
	path := sampleConfig(t, url)
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(extra); err != nil {
		t.Fatal(err)
	}
	f.Close()
	c, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	return path, c
}

func writeTestFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestValidateReportsWhatIsSetUp(t *testing.T) {
	fos := newFakeOpenSearch(t)
	path, c := validateConfig(t, fos.URL, "syslog:\n  udp: 127.0.0.1:5514\n  allow: [10.0.0.0/8]\n"+
		"intel:\n  feeds:\n    - name: test-feed\n      url: https://feeds.example.test/ips.txt\n      type: ip\n")
	writeTestFile(t, c.NotifyFile(), `channels:
  - id: hook
    name: SOAR
    type: webhook
    url: https://soar.example.test/hook
rules: []
`)
	writeTestFile(t, c.TicketingFile(), "connections: []\n")
	writeTestFile(t, c.PlaybooksFile(), "playbooks: []\n")
	out, err := capture(t, func() error { return cmdValidate([]string{"-c", path}) })
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	for _, want := range []string{
		path + " is valid.",
		"detections loaded",
		"0 assets and 0 identities loaded from " + c.LookupsDir(),
		"0 local users and 0 directory users",
		"1 threat intel feeds (1 in signalith.yaml, 0 added on the Threat intel page), 1 enabled.",
		"1 notification channels and 0 rules (0 on), set on the Notifications page.",
		"Syslog receiver on ",
		"accepting 10.0.0.0/8.",
		"Note: over UDP a sender's address can be forged",
		"0 custom dashboards loaded from ",
		"OpenSearch at " + fos.URL + " is ",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("validate lacks %q:\n%s", want, out)
		}
	}
	for _, absent := range []string{"Warning: OpenSearch", "playbooks (", "ticketing connections"} {
		if strings.Contains(out, absent) {
			t.Errorf("validate shows %q:\n%s", absent, out)
		}
	}
}

func TestValidateWarnsAboutFilesItCannotRead(t *testing.T) {
	path, c := validateConfig(t, "http://127.0.0.1:1", "")
	writeTestFile(t, c.NotifyFile(), "channels: [unclosed")
	writeTestFile(t, c.TicketingFile(), "connections: [\n")
	writeTestFile(t, c.PlaybooksFile(), "playbooks: [:")
	out, err := capture(t, func() error { return cmdValidate([]string{"-c", path}) })
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	for _, want := range []string{
		path + " is valid.",
		"Syslog receiver is off",
		"Warning: OpenSearch is not reachable yet: ",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("validate lacks %q:\n%s", want, out)
		}
	}
	// One warning for each of the three files.
	for _, f := range []string{c.NotifyFile(), c.TicketingFile(), c.PlaybooksFile()} {
		if !strings.Contains(out, filepath.Base(f)) {
			t.Errorf("no warning about %s:\n%s", f, out)
		}
	}
}

func TestValidateRefusesBrokenDetectionsAndDashboards(t *testing.T) {
	path, c := validateConfig(t, "http://127.0.0.1:1", "")
	writeTestFile(t, filepath.Join(c.DetectionsDir(), "broken.yaml"), "name: [\n")
	out, err := capture(t, func() error { return cmdValidate([]string{"-c", path}) })
	if err == nil || !strings.Contains(err.Error(), "1 detection file(s) in "+c.DetectionsDir()+" need fixing") || !strings.Contains(out, "Detection error: ") {
		t.Errorf("broken detection: %v\n%s", err, out)
	}
	if err := os.Remove(filepath.Join(c.DetectionsDir(), "broken.yaml")); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(c.DashboardsDir(), "broken.yaml"), "title: [\n")
	out, err = capture(t, func() error { return cmdValidate([]string{"-c", path}) })
	if err == nil || !strings.Contains(err.Error(), "dashboard file(s) in") || !strings.Contains(out, "Dashboard error: ") {
		t.Errorf("broken dashboard: %v\n%s", err, out)
	}
}

// The installers' -syslog-ports and -web-ports print only the ports.
func TestValidatePortsForInstallers(t *testing.T) {
	path, _ := validateConfig(t, "http://127.0.0.1:1", "server:\n  listen: 127.0.0.1:9000\nsyslog:\n  tcp: 0.0.0.0:5514\n")
	out, err := capture(t, func() error { return cmdValidate([]string{"-c", path, "-syslog-ports"}) })
	if err != nil || out != "tcp 5514 any\n" {
		t.Errorf("-syslog-ports: %v %q", err, out)
	}
	out, err = capture(t, func() error { return cmdValidate([]string{"-c", path, "-web-ports"}) })
	if err != nil || !strings.HasPrefix(out, "web 9000 local\n") || strings.Contains(out, "valid") {
		t.Errorf("-web-ports: %v %q", err, out)
	}
	missing := filepath.Join(t.TempDir(), "missing.yaml")
	if _, err := capture(t, func() error { return cmdValidate([]string{"-c", missing, "-syslog-ports"}) }); err == nil {
		t.Error("-syslog-ports with no config file")
	}
}

// -file names the Settings page's file the service uses.
func TestValidateWithSettingsFile(t *testing.T) {
	path, _ := validateConfig(t, "http://127.0.0.1:1", "")
	file := filepath.Join(t.TempDir(), "page.yaml")
	page := &config.PageSettings{}
	page.Set("search.max_events", 4321, "alice", time.Now())
	if err := config.WritePageSettings(file, page); err != nil {
		t.Fatal(err)
	}
	out, err := capture(t, func() error { return cmdValidate([]string{"-c", path, "-file", file}) })
	if err != nil || !strings.Contains(out, "Changed on the Settings page ("+file+"): search.max_events.") {
		t.Errorf("validate -file: %v\n%s", err, out)
	}
	if strings.Contains(out, "Note: The Signalith service") {
		t.Errorf("a note about the service's file with -file given:\n%s", out)
	}
}
