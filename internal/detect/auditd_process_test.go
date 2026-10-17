package detect

import (
	"os"
	"path"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/query"
	"github.com/jrsamsanchez/signalith/internal/search"
	"github.com/jrsamsanchez/signalith/internal/sigmacheck"
)

// TestLinuxProcessRulesFireOnAuditd: the SigmaHQ Linux process creation
// rules and Splunk's Linux process rules, tested on Sysmon for Linux
// events, fire the same way on the program starts Signalith joins from
// auditd's records, for every test event whose fields auditd records too.
func TestLinuxProcessRulesFireOnAuditd(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	rules, cases, all := 0, 0, 0
	for dir, p := range readManifests(t) {
		if p.Format == "splunk" {
			var err error
			if p.macros, err = loadMacros(packFS, dir); err != nil {
				t.Fatal(err)
			}
		}
		for _, r := range p.Rules {
			if !strings.HasPrefix(r.File, "proc_creation_lnx_") && !strings.HasPrefix(r.File, "linux_") {
				continue
			}
			src, err := packFS.ReadFile(path.Join(dir, "rules", r.File))
			if err != nil {
				t.Fatal(err)
			}
			d, err := PackDetection(p, r, src)
			if err != nil {
				t.Fatalf("%s: %v", r.ID, err)
			}
			q, err := query.Parse(d.Query)
			if err != nil {
				t.Fatalf("%s: %v", r.ID, err)
			}
			data, err := os.ReadFile(path.Join(dir, "tests", strings.TrimSuffix(r.File, ".yml")+".json"))
			if err != nil {
				t.Fatal(err)
			}
			tf, err := sigmacheck.DecodeTestFile(data)
			if err != nil {
				t.Fatal(err)
			}
			n := 0
			for i, c := range tf.Cases {
				ev, ok := c.AuditdProcessStart("test-host", now)
				if !ok {
					continue
				}
				n++
				if !strings.EqualFold(ev.Model, q.Datamodel) {
					t.Fatalf("%s: program start in %s, the rule reads %s", r.ID, ev.Model, q.Datamodel)
				}
				m, err := search.MatchDoc(q.Search, ev.Document())
				if err != nil {
					t.Fatalf("%s: %v", r.ID, err)
				}
				if m != c.Expect {
					t.Errorf("%s (%s) case %d: the detection says %v for %v, stored as %v", r.ID, r.File, i, m, c.Data, ev.Fields)
				}
			}
			if n > 0 || strings.HasPrefix(r.File, "proc_creation_lnx_") {
				all++
			}
			if n > 0 {
				rules++
				cases += n
			}
		}
	}
	if rules == 0 || rules != all {
		t.Errorf("%d of the %d Linux process creation rules checked on auditd", rules, all)
	}
	t.Logf("%d rules, %d test events", rules, cases)
}
