package detect

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/datamodel"
	"github.com/jrsamsanchez/signalith/internal/findings"
	"github.com/jrsamsanchez/signalith/internal/intel"
	"github.com/jrsamsanchez/signalith/internal/query"
	"github.com/jrsamsanchez/signalith/internal/search"
)

func TestBuiltinsCompile(t *testing.T) {
	ds, err := Builtin()
	if err != nil {
		t.Fatal(err)
	}
	if len(ds) != 32 {
		t.Fatalf("%d built-in detections, want 32", len(ds))
	}
	eng := &search.Engine{Intel: intel.NewStore(intel.NewMemory())}
	for _, d := range ds {
		q, err := query.Parse(d.Query)
		if err != nil {
			t.Errorf("%s: %v", d.ID, err)
			continue
		}
		if _, err := eng.Compile(q); err != nil {
			t.Errorf("%s: compile: %v", d.ID, err)
		}
		if len(d.MITRE) == 0 && !slices.Contains(d.Tags, "risk-incident") && !slices.Contains(d.Tags, "threat-intel") {
			t.Errorf("%s has no ATT&CK mapping", d.ID)
		}
		// A transforming query only returns the columns it names, so
		// title tokens must be among them.
		transforming := len(q.Commands) > 0 && (q.Commands[0].Name() == "stats" || q.Commands[0].Name() == "top")
		for _, tok := range tokenPattern.FindAllStringSubmatch(d.Title, -1) {
			if transforming && !strings.Contains(d.Query, tok[1]) {
				t.Errorf("%s: title token $%s$ is not in the query", d.ID, tok[1])
			}
		}
	}
}

func TestValidate(t *testing.T) {
	d := &Detection{ID: "X", Query: "earliest=-1h | stats", Schedule: "10s", Lookback: "5", Severity: "urgent", MITRE: []string{"TA0001"}}
	err := d.Validate()
	ve, ok := err.(*ValidationError)
	if !ok {
		t.Fatalf("err = %v", err)
	}
	want := []string{"id must", "title is required", "query", "schedule must be at least", "lookback", "severity", "mitre"}
	if len(ve.Problems) != len(want) {
		t.Fatalf("problems = %q", ve.Problems)
	}
	for i, w := range want {
		if !strings.Contains(ve.Problems[i], w) {
			t.Errorf("problem %d = %q, want %q", i, ve.Problems[i], w)
		}
	}
	d = &Detection{ID: "ok-rule", Title: "t", Query: "user=x earliest=-1h"}
	d.Defaults()
	if err := d.Validate(); err == nil || !strings.Contains(err.Error(), "earliest") {
		t.Errorf("earliest in query allowed: %v", err)
	}
}

func TestParseDuration(t *testing.T) {
	for in, want := range map[string]time.Duration{"30s": 30 * time.Second, "5m": 5 * time.Minute, "2h": 2 * time.Hour, "1d": 24 * time.Hour, "1w": 168 * time.Hour} {
		if got, err := ParseDuration(in); err != nil || got != want {
			t.Errorf("%s = %v %v", in, got, err)
		}
	}
	if _, err := ParseDuration("5 minutes"); err == nil {
		t.Error("accepted 5 minutes")
	}
}

func TestLibraryOverrideAndDelete(t *testing.T) {
	dir := t.TempDir()
	lib, problems, err := NewLibrary(dir)
	if err != nil || len(problems) > 0 {
		t.Fatal(err, problems)
	}
	b, err := lib.Get("auth-brute-force")
	if err != nil || b.Source != "builtin" || !b.Enabled {
		t.Fatalf("builtin = %+v %v", b, err)
	}
	// Turning it off unchanged records only the choice, not a copy.
	b.Enabled = false
	if err := lib.Put(b); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "auth-brute-force.yaml")); !os.IsNotExist(err) {
		t.Fatalf("turning a built-in off wrote an override: %v", err)
	}
	lib, _, _ = NewLibrary(dir)
	got, _ := lib.Get("auth-brute-force")
	if got.Source != "builtin" || got.Enabled {
		t.Fatalf("after turning off = %+v", got)
	}
	// Back on: the choice equals the default, so its file goes.
	if err := lib.SetEnabled([]string{"auth-brute-force"}, true); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, StateDir, "auth-brute-force.yaml")); !os.IsNotExist(err) {
		t.Fatalf("state file kept: %v", err)
	}

	// Editing it makes an override.
	b.Enabled = false
	b.Severity = "high"
	if err := lib.Put(b); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "auth-brute-force.yaml")); err != nil {
		t.Fatal(err)
	}
	// Reload from disk to prove the override persists.
	lib, _, _ = NewLibrary(dir)
	got, _ = lib.Get("auth-brute-force")
	if got.Source != "override" || got.Enabled || got.Severity != "high" {
		t.Fatalf("override = %+v", got)
	}
	if err := lib.Delete("auth-brute-force"); err != nil {
		t.Fatal(err)
	}
	got, _ = lib.Get("auth-brute-force")
	if got.Source != "builtin" || !got.Enabled {
		t.Fatalf("after revert = %+v", got)
	}
	if err := lib.Delete("auth-brute-force"); err == nil {
		t.Error("deleted a built-in")
	}

	custom := &Detection{ID: "my-rule", Title: "Mine", Query: "user=bob"}
	if err := lib.Put(custom); err != nil {
		t.Fatal(err)
	}
	got, _ = lib.Get("my-rule")
	if got.Source != "custom" || got.Schedule != "5m" || got.Severity != "medium" {
		t.Errorf("defaults not applied: %+v", got)
	}
	if err := lib.Put(&Detection{ID: "bad rule"}); err == nil {
		t.Error("saved an invalid detection")
	}

	// A broken file is reported, not fatal.
	os.WriteFile(filepath.Join(dir, "broken.yaml"), []byte("id: broken\nbogus: 1\n"), 0o600)
	lib, problems, err = NewLibrary(dir)
	if err != nil || len(problems) != 1 {
		t.Fatalf("problems = %v, err = %v", problems, err)
	}
	if _, err := lib.Get("my-rule"); err != nil {
		t.Error("valid custom rule not loaded next to a broken one")
	}
}

type fakeRunner struct {
	rows []search.Row
	mu   sync.Mutex // the scheduler runs detections in parallel
	last *query.Query
}

func (f *fakeRunner) Execute(_ context.Context, q *query.Query) (*search.Result, error) {
	f.mu.Lock()
	f.last = q
	f.mu.Unlock()
	return &search.Result{Kind: "table", Rows: f.rows}, nil
}

func TestSchedulerRaisesAndThrottles(t *testing.T) {
	lib, _, _ := NewLibrary("")
	now := time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)
	run := &fakeRunner{rows: []search.Row{
		{"src": "203.0.113.9", "dest": "web1", "count": int64(40), "users": int64(3)},
		{"src": "198.51.100.1", "dest": "web1", "count": int64(12), "users": int64(1)},
	}}
	store := findings.NewMemory()
	s := &Scheduler{Library: lib, Engine: run, Findings: store, Now: func() time.Time { return now }}
	d, _ := lib.Get("auth-brute-force")

	res, err := s.Run(context.Background(), d)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 2 || res.Throttled != 0 {
		t.Fatalf("first run = %+v", res)
	}
	if run.last.Earliest != "2026-10-11T11:45:00Z" || run.last.Latest != "2026-10-11T12:00:00Z" {
		t.Errorf("window = %s .. %s", run.last.Earliest, run.last.Latest)
	}
	f := res.Findings[0]
	if f.Title != "Brute force against web1 from 203.0.113.9" || f.Severity != "medium" || f.Status != findings.StatusNew {
		t.Errorf("finding = %+v", f)
	}
	if f.Entities["src"] != "203.0.113.9" || f.Entities["dest"] != "web1" {
		t.Errorf("entities = %v", f.Entities)
	}
	if !strings.Contains(f.Query, "src=203.0.113.9") || strings.Contains(f.Query, "stats") {
		t.Errorf("drilldown = %q", f.Query)
	}

	// Five minutes later the same sources are throttled (window 1h).
	now = now.Add(5 * time.Minute)
	res, _ = s.Run(context.Background(), d)
	if len(res.Findings) != 0 || res.Throttled != 2 {
		t.Fatalf("second run = %+v", res)
	}
	// After the throttle window they fire again.
	now = now.Add(time.Hour)
	res, _ = s.Run(context.Background(), d)
	if len(res.Findings) != 2 {
		t.Fatalf("third run = %+v", res)
	}
	st := s.Status()["auth-brute-force"]
	if st.LastFindings != 2 || !st.NextRun.Equal(now.Add(5*time.Minute)) {
		t.Errorf("state = %+v", st)
	}
}

func TestRunDueRespectsScheduleAndEnabled(t *testing.T) {
	lib, _, _ := NewLibrary("")
	now := time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)
	s := &Scheduler{Library: lib, Engine: &fakeRunner{}, Findings: findings.NewMemory(), Now: func() time.Time { return now }}
	s.RunDue(context.Background())
	st := s.Status()
	if _, ran := st["change-account-deleted"]; ran {
		t.Error("disabled detection ran")
	}
	first := st["auth-brute-force"].LastRun
	if first.IsZero() {
		t.Fatal("enabled detection did not run")
	}
	now = now.Add(time.Minute)
	s.RunDue(context.Background())
	if !s.Status()["auth-brute-force"].LastRun.Equal(first) {
		t.Error("ran again before its schedule")
	}
	now = now.Add(5 * time.Minute)
	s.RunDue(context.Background())
	if s.Status()["auth-brute-force"].LastRun.Equal(first) {
		t.Error("did not run when due")
	}
}

func TestRunCapsFindings(t *testing.T) {
	lib, _, _ := NewLibrary("")
	var rows []search.Row
	for i := 0; i < 10; i++ {
		rows = append(rows, search.Row{"src": i, "dest": "x"})
	}
	s := &Scheduler{Library: lib, Engine: &fakeRunner{rows: rows}, Findings: findings.NewMemory(), MaxFindingsPerRun: 3}
	d, _ := lib.Get("auth-brute-force")
	res, err := s.Run(context.Background(), d)
	if err != nil || len(res.Findings) != 3 || !res.Capped {
		t.Fatalf("res = %+v, %v", res, err)
	}
}

func TestDrilldownTop(t *testing.T) {
	q, _ := query.Parse(`datamodel=Endpoint user=bob | top process_name by dest`)
	got := Drilldown(q, map[string]any{"process_name": "cmd.exe", "dest": "WS1", "count": 3}).String()
	if got != `datamodel=Endpoint user=bob process_name=cmd.exe dest=WS1` {
		t.Errorf("drilldown = %q", got)
	}
	q, _ = query.Parse(`datamodel=Change action=created | head 5`)
	if got := Drilldown(q, nil).String(); got != `datamodel=Change action=created` {
		t.Errorf("events drilldown = %q", got)
	}
}

func TestRenderTitle(t *testing.T) {
	got := RenderTitle("$user$ on $dest$ ($count$, $missing$)", map[string]any{"user": "bob", "dest": "WS1", "count": int64(4)})
	if got != "bob on WS1 (4, unknown)" {
		t.Errorf("title = %q", got)
	}
}

const sigmaEncoded = `
title: Suspicious Encoded PowerShell Command Line
id: ca2092a1-c273-4878-9b4b-0d60115bf5ea
status: test
description: Detects suspicious powershell process starts with base64 encoded commands
tags:
  - attack.execution
  - attack.t1059.001
logsource:
  category: process_creation
  product: windows
detection:
  selection_img:
    - Image|endswith:
        - '\powershell.exe'
        - '\pwsh.exe'
    - OriginalFileName: 'PowerShell.EXE'
  selection_cli:
    CommandLine|contains|windash: ' -enc '
  filter_main:
    ParentImage|startswith: 'C:\Program Files\Okta\'
    User: null
  condition: all of selection_* and not 1 of filter_*
falsepositives:
  - Admin scripts
level: high
`

func TestConvertSigma(t *testing.T) {
	res, err := ConvertSigma([]byte(sigmaEncoded))
	if err != nil {
		t.Fatal(err)
	}
	d := res.Detection
	if d.ID != "sigma-suspicious-encoded-powershell-command-line" || d.Severity != "high" || d.Enabled {
		t.Errorf("detection = %+v", d)
	}
	if len(d.MITRE) != 1 || d.MITRE[0] != "T1059.001" {
		t.Errorf("mitre = %v", d.MITRE)
	}
	q, err := query.Parse(d.Query)
	if err != nil {
		t.Fatalf("converted query does not parse: %v\n%s", err, d.Query)
	}
	s := q.String()
	for _, want := range []string{
		"datamodel=Endpoint",
		"process_name=powershell.exe",
		"process_name=pwsh.exe",
		`process="* -enc *"`,
		`process="* /enc *"`,
		`parent_process_path="C:\\Program Files\\Okta\\*"`,
		"NOT",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("query missing %s:\n%s", want, s)
		}
	}
	if len(res.Warnings) != 0 {
		t.Errorf("warnings = %v", res.Warnings)
	}
	if _, err := (&search.Engine{}).Compile(q); err != nil {
		t.Errorf("compile: %v", err)
	}
	// Round trip: the stored query parses back to the same thing.
	q2, _ := query.Parse(s)
	if q2.String() != s {
		t.Errorf("round trip changed query:\n%s\n%s", s, q2.String())
	}
}

func TestConvertSigmaUnsupported(t *testing.T) {
	for name, rule := range map[string]string{
		"regex":       "title: x\ndetection:\n  sel:\n    CommandLine|re: 'a.*b'\n  condition: sel\n",
		"aggregation": "title: x\ndetection:\n  sel:\n    EventID: 4625\n  condition: sel | count() by IpAddress > 10\n",
		"unknown sel": "title: x\ndetection:\n  sel:\n    EventID: 4625\n  condition: other\n",
		"not sigma":   "hello: world\n",
	} {
		if _, err := ConvertSigma([]byte(rule)); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
	res, err := ConvertSigma([]byte("title: Failed logons\nlogsource:\n  product: windows\n  service: security\ndetection:\n  sel:\n    EventID: 4625\n  keywords:\n    - 'bad stuff'\n  condition: sel or keywords\n"))
	if err != nil {
		t.Fatal(err)
	}
	res2, err := ConvertSigma([]byte("title: W\nlogsource:\n  category: process_creation\ndetection:\n  sel:\n    - Image|endswith: '\\\\whoami.exe'\n    - OriginalFileName: whoami.exe\n  condition: sel\n"))
	if err != nil || res2.Detection.Query != "datamodel=Endpoint process_name=whoami.exe OR original_file_name=whoami.exe" {
		t.Errorf("query = %v %+v", err, res2.Detection.Query)
	}
	if !strings.Contains(res.Detection.Query, "signature_id=4625") || !strings.Contains(res.Detection.Query, `"*bad stuff*"`) {
		t.Errorf("query = %s", res.Detection.Query)
	}
}

func TestCoverage(t *testing.T) {
	ds := []*Detection{
		{ID: "a", MITRE: []string{"T1110.003"}, Enabled: true},
		{ID: "b", MITRE: []string{"T1110"}, Enabled: false},
		{ID: "c", MITRE: []string{"T1490"}, Enabled: false},
		{ID: "d", MITRE: []string{"T9999"}, Enabled: true},
	}
	cov := ComputeCoverage(ds)
	if cov.Summary.Enabled != 1 || cov.Summary.Available != 1 || cov.Summary.Techniques < 150 {
		t.Errorf("summary = %+v", cov.Summary)
	}
	if cov.Unknown["T9999"] != "d" {
		t.Errorf("unknown = %v", cov.Unknown)
	}
	var found bool
	for _, tac := range cov.Tactics {
		for _, te := range tac.Techniques {
			if te.ID == "T1110" {
				found = true
				if tac.Short != "credential-access" || len(te.Enabled) != 1 || len(te.Disabled) != 1 || te.Subs[0] != "T1110.003" {
					t.Errorf("T1110 = %+v in %s", te, tac.Short)
				}
			}
		}
	}
	if !found {
		t.Error("T1110 missing from matrix")
	}
}

// losingRunner is a search during which this server loses the job role.
type losingRunner struct {
	fakeRunner
	lose func()
}

func (r *losingRunner) Execute(ctx context.Context, q *query.Query) (*search.Result, error) {
	r.lose()
	return r.fakeRunner.Execute(ctx, q)
}

// A server that no longer runs the background jobs starts no scheduled
// run, and one that loses them during a run writes no findings. A run
// someone starts by hand is not fenced.
func TestSchedulerAsksAllowed(t *testing.T) {
	lib, _, _ := NewLibrary("")
	now := time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)
	store := findings.NewMemory()
	var allowed atomic.Bool
	runner := &losingRunner{fakeRunner: fakeRunner{rows: []search.Row{{"src": "203.0.113.9", "dest": "web1"}}}, lose: func() { allowed.Store(false) }}
	s := &Scheduler{Library: lib, Engine: runner, Findings: store, Now: func() time.Time { return now }, Allowed: allowed.Load}
	s.RunDue(context.Background())
	if len(s.Status()) != 0 {
		t.Fatalf("ran while not allowed: %+v", s.Status())
	}
	allowed.Store(true)
	s.RunDue(context.Background())
	failed := 0
	for _, st := range s.Status() {
		if strings.Contains(st.LastError, "no longer runs the background jobs") {
			failed++
		}
	}
	if failed == 0 {
		t.Fatalf("state %+v", s.Status())
	}
	if list, _, _ := store.Search(context.Background(), findings.Filter{}); len(list) != 0 {
		t.Fatalf("%d findings written after the role was lost", len(list))
	}
	d, _ := lib.Get("auth-brute-force")
	if res, err := s.Run(context.Background(), d); err != nil || len(res.Findings) != 1 {
		t.Fatalf("a run by hand: %+v %v", res, err)
	}
}

// Every ATT&CK ID a built-in detection names is in the bundled matrix.
func TestBuiltinTechniquesKnown(t *testing.T) {
	ds, err := Builtin()
	if err != nil {
		t.Fatal(err)
	}
	if cov := ComputeCoverage(ds); len(cov.Unknown) > 0 {
		t.Errorf("unknown ATT&CK IDs (technique -> detection): %v", cov.Unknown)
	}
}

// Every field a built-in detection filters or groups on exists in its data
// model, or is a common field, so a typo cannot leave a detection that
// never fires.
func TestBuiltinFieldsExist(t *testing.T) {
	ds, err := Builtin()
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range ds {
		q, err := query.Parse(d.Query)
		if err != nil {
			t.Errorf("%s: %v", d.ID, err)
			continue
		}
		if q.Datamodel == "" {
			continue
		}
		if _, ok := datamodel.Get(q.Datamodel); !ok {
			t.Errorf("%s: unknown data model %s", d.ID, q.Datamodel)
			continue
		}
		known := map[string]bool{}
		for _, f := range datamodel.FieldsFor(q.Datamodel) {
			known[f.Name] = true
		}
		for _, f := range leadingFields(q) {
			if !known[f] {
				t.Errorf("%s: field %s is not in data model %s", d.ID, f, q.Datamodel)
			}
		}
	}
}

// leadingFields returns the fields a query's search and its first
// aggregating command read.
func leadingFields(q *query.Query) []string {
	var out []string
	var walk func(e query.Expr)
	walk = func(e query.Expr) {
		switch x := e.(type) {
		case *query.And:
			for _, c := range x.Children {
				walk(c)
			}
		case *query.Or:
			for _, c := range x.Children {
				walk(c)
			}
		case *query.Not:
			walk(x.Child)
		case *query.Compare:
			out = append(out, x.Field)
		case *query.In:
			out = append(out, x.Field)
		}
	}
	if q.Search != nil {
		walk(q.Search)
	}
	if len(q.Commands) > 0 {
		switch c := q.Commands[0].(type) {
		case *query.Stats:
			for _, a := range c.Aggs {
				if a.Field != "" {
					out = append(out, a.Field)
				}
			}
			out = append(out, c.By...)
		case *query.Timechart:
			for _, a := range c.Aggs {
				if a.Field != "" {
					out = append(out, a.Field)
				}
			}
			if c.By != "" {
				out = append(out, c.By)
			}
		case *query.Top:
			out = append(out, c.Fields...)
			out = append(out, c.By...)
		}
	}
	return out
}

func TestConvertSigmaAntivirus(t *testing.T) {
	res, err := ConvertSigma([]byte("title: Mimikatz found by antivirus\nlogsource:\n  category: antivirus\ndetection:\n  sel:\n    Signature|contains: Mimikatz\n    Filename|endswith: '.exe'\n  condition: sel\nlevel: high\n"))
	if err != nil {
		t.Fatal(err)
	}
	q := res.Detection.Query
	for _, want := range []string{"datamodel=Malware", "signature=*Mimikatz*", "file_path=*.exe"} {
		if !strings.Contains(q, want) {
			t.Errorf("query missing %s: %s", want, q)
		}
	}
	for _, w := range res.Warnings {
		if strings.Contains(w, "no Signalith mapping") || strings.Contains(w, "no Signalith data model") {
			t.Errorf("unexpected warning: %s", w)
		}
	}
	if _, err := (&search.Engine{}).Compile(mustParse(t, q)); err != nil {
		t.Errorf("compile: %v", err)
	}
}

func mustParse(t *testing.T, s string) *query.Query {
	t.Helper()
	q, err := query.Parse(s)
	if err != nil {
		t.Fatalf("%s: %v", s, err)
	}
	return q
}

func TestBaseTitle(t *testing.T) {
	for in, want := range map[string]string{
		"Encoded PowerShell command on $dest$":                                       "Encoded PowerShell command",
		"Brute force against $dest$ from $src$":                                      "Brute force",
		"Malware found on $dest$ ($signature$)":                                      "Malware found",
		"Account $object$ created on $dest$":                                         "Account created",
		"Threat intel match on $threat_match_field$ $threat_match_value$ ($source$)": "Threat intel match",
		"Scheduled task created on $dest$ by $user$":                                 "Scheduled task created",
		"$user$ logged on with $method$":                                             "Logged on",
		"$dest$":                                                                     "dest",
		"No tokens at all":                                                           "No tokens at all",
		"éclair eaten on $dest$":                                                     "Éclair eaten",
	} {
		if got := BaseTitle(in); got != want {
			t.Errorf("BaseTitle(%q) = %q, want %q", in, got, want)
		}
	}
	d := &Detection{Title: "$a$ did $b$", Name: "Something done"}
	if d.BaseTitle() != "Something done" {
		t.Errorf("name not used: %q", d.BaseTitle())
	}
}

// Every built-in detection has a clean name for views that count it
// across hosts: no $field$ tokens, and more than one word, so a title
// that starts with a token and reads badly without it gets a name.
func TestBuiltinBaseTitles(t *testing.T) {
	lib, _, err := NewLibrary("")
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]string{}
	for _, d := range lib.List() {
		if d.Source != "builtin" {
			continue
		}
		b := d.BaseTitle()
		if strings.Contains(b, "$") || len(strings.Fields(b)) < 2 {
			t.Errorf("%s: base title %q", d.ID, b)
		}
		if other, dup := seen[b]; dup {
			t.Errorf("%s and %s share the base title %q", d.ID, other, b)
		}
		seen[b] = d.ID
	}
	bad := &Detection{ID: "abc", Title: "x", Name: "on $dest$", Query: "*", Schedule: "5m", Lookback: "5m", Severity: "low"}
	if err := bad.Validate(); err == nil || !strings.Contains(err.Error(), "name must not use") {
		t.Errorf("token in name: %v", err)
	}
}

// Sysmon log sources other than process creation map onto their own data
// models, only see their own event IDs, and map fields by log source.
func TestConvertSigmaSysmonLogSources(t *testing.T) {
	r, err := ConvertSigmaWith([]byte(`title: Run key
logsource: {product: windows, category: registry_set}
detection:
  sel:
    TargetObject|contains: '\CurrentVersion\Run\'
    Image|endswith: '\powershell.exe'
    Details|startswith: 'C:\Users\'
  condition: sel
`), SigmaOptions{Strict: true})
	if err != nil {
		t.Fatal(err)
	}
	want := `datamodel=Registry (sourcetype=WinEventLog:* AND signature_id IN (13)) (registry_value_data=C:\Users\* AND process_name=powershell.exe AND registry_path=*\CurrentVersion\Run\*)`
	if r.Detection.Query != want {
		t.Errorf("query = %s\nwant    %s", r.Detection.Query, want)
	}
	r, err = ConvertSigmaWith([]byte(`title: LSASS access
logsource: {product: windows, category: process_access}
detection:
  sel:
    TargetImage|endswith: '\lsass.exe'
    GrantedAccess: '0x1410'
  condition: sel
`), SigmaOptions{Strict: true})
	if err != nil {
		t.Fatal(err)
	}
	if q := r.Detection.Query; !strings.Contains(q, "datamodel=Endpoint") || !strings.Contains(q, "signature_id IN (10)") || !strings.Contains(q, "target_process_name=lsass.exe") {
		t.Errorf("query = %s", q)
	}
	r, err = ConvertSigmaWith([]byte(`title: Mimikatz in a script
logsource: {product: windows, category: ps_script, definition: 'Script Block Logging must be enabled'}
detection:
  sel:
    ScriptBlockText|contains: 'Invoke-Mimikatz'
  condition: sel
`), SigmaOptions{Strict: true})
	if err != nil {
		t.Fatal(err)
	}
	if want := `datamodel=Script (sourcetype=WinEventLog:* AND signature_id IN (4104)) script_block_text=*Invoke-Mimikatz*`; r.Detection.Query != want {
		t.Errorf("query = %s\nwant    %s", r.Detection.Query, want)
	}
	// In image_load, Description is the DLL's, not the process's: no mapping.
	if _, err := ConvertSigmaWith([]byte(`title: x
logsource: {product: windows, category: image_load}
detection:
  sel:
    Description: 'x'
  condition: sel
`), SigmaOptions{Strict: true}); err == nil || !strings.Contains(err.Error(), "Description has no Signalith mapping in image_load") {
		t.Errorf("err = %v", err)
	}
}
