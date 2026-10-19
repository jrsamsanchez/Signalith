package splcheck

import (
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/sigmacheck"
)

// A rule with no test event it finds says why, naming its events' source.
func TestNoEventsReason(t *testing.T) {
	parse := func(search string) *Rule {
		t.Helper()
		r, err := Parse(rule(search), testMacros)
		if err != nil {
			t.Fatalf("%s: %v", search, err)
		}
		return r
	}
	r := parse("| tstats count from datamodel=Endpoint.Processes where Processes.process_name=cmd.exe by Processes.dest")
	if got := NoEventsReason(r, nil); !strings.Contains(got, "no Windows event as Signalith stores it matches the rule") {
		t.Errorf("no events = %q", got)
	}
	web := parse("| tstats count from datamodel=Web where Web.status=500 by Web.dest")
	if got := NoEventsReason(web, nil); !strings.Contains(got, "no web access log event") {
		t.Errorf("web = %q", got)
	}
	cases := Cases(r)
	if got := NoEventsReason(r, cases); !strings.Contains(got, "later stages keep none") {
		t.Errorf("found events = %q", got)
	}
	// A later stats by a field none of the events has.
	grouped := parse("| tstats count from datamodel=Endpoint.Processes where Processes.process_name=cmd.exe by Processes.dest Processes.process_name\n| `drop_dm_object_name(Processes)`\n| stats count by nosuchfield")
	if got := NoEventsReason(grouped, Cases(grouped)); !strings.Contains(got, "groups by nosuchfield") {
		t.Errorf("stats = %q", got)
	}
	// A later where that keeps none of them.
	kept := parse("| tstats count from datamodel=Endpoint.Processes where Processes.process_name=cmd.exe by Processes.dest Processes.process_name\n| `drop_dm_object_name(Processes)`\n| where process_name=\"never\"")
	if got := NoEventsReason(kept, Cases(kept)); !strings.Contains(got, `later where process_name="never" keeps none`) {
		t.Errorf("where = %q", got)
	}
	// An outlier test needs a baseline.
	outlier := parse("| tstats count from datamodel=Endpoint.Processes where Processes.process_name=cmd.exe by Processes.dest Processes.process_name\n| `drop_dm_object_name(Processes)`\n| stats stdev(count) as s by dest\n| where s > 100")
	if got := NoEventsReason(outlier, Cases(outlier)); !strings.Contains(got, "baseline") {
		t.Errorf("outlier = %q", got)
	}
	// A join's events that do not share a value.
	joined := parse(joinMain + "| join process_guid [" + joinSub + "]")
	var alone []sigmacheck.Case
	for _, c := range Cases(joined) {
		c.With = nil
		alone = append(alone, c)
	}
	if got := NoEventsReason(joined, alone); !strings.Contains(got, "join joins") {
		t.Errorf("join = %q", got)
	}
}

// Lookup tables Signalith cannot read as Splunk does are refused.
func TestParseLookupRefusals(t *testing.T) {
	for _, c := range []struct{ meta, csv, want string }{
		{"name: [", "a\n", ""},
		{"bogus: 1\nname: a\nlookup_type: csv\n", "a\n", "lookup setting bogus is not supported"},
		{"lookup_type: csv\n", "a\n", "the lookup has no name"},
		{"name: a\nlookup_type: csv\nmin_matches: 1\ndefault_match: 'say \"x\"'\n", "a\nx\n", "default_match"},
		{"name: a\nlookup_type: csv\n", "a,b\n\"x\n", "lookup a"},
	} {
		if _, err := ParseLookup([]byte(c.meta), []byte(c.csv)); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%q: err = %v, want %q", c.meta, err, c.want)
		}
	}
	l, err := ParseLookup([]byte("name: a\nlookup_type: csv\nmin_matches: 1\ndefault_match: unknown\nmax_matches: 2\n"), []byte("k,v\n x ,y\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !l.HasDefault || l.Default != "unknown" || l.MaxMatches != 2 || !l.padded["k"] {
		t.Errorf("lookup = %+v", l)
	}
}

// A lookup stage that names a table it cannot read, or a column the
// table lacks, is refused.
func TestLookupStageRefusals(t *testing.T) {
	lookups := testLookups(t, [2]string{pipesMeta, pipesCSV}, [2]string{"name: padded\nlookup_type: csv\n", "pipe,tool\n x ,y\n"})
	for stage, want := range map[string]string{
		"lookup pipes nosuch AS pipe_name OUTPUT tool": "has no column nosuch",
		"lookup missing pipe AS pipe_name OUTPUT tool": "missing",
		"lookup padded pipe AS pipe_name OUTPUT tool":  "spaces around them",
	} {
		src := rule("`sysmon` EventCode=17 | stats count by dest pipe_name | " + stage + " | where isnotnull(tool)")
		if _, err := ParseWith(src, testMacros, ParseOptions{Lookups: lookups, LookupErrors: map[string]error{"missing": errMissing}}); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: err = %v, want %q", stage, err, want)
		}
	}
}

var errMissing = errString("a kvstore lookup")

type errString string

func (e errString) Error() string { return string(e) }
