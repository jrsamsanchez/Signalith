// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package security

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/secrets"
)

func TestFixFirstOrder(t *testing.T) {
	list := []Check{
		{ID: "a", State: Attention, Rank: 5},
		{ID: "b", State: Risk, Rank: 9},
		{ID: "c", State: Good, Rank: 1},
		{ID: "d", State: Unknown, Rank: 2},
		{ID: "e", State: Attention, Rank: 3},
		{ID: "f", State: Risk, Rank: 1},
	}
	if got := FixFirst(list); !slices.Equal(got, []string{"f", "b", "e", "a"}) {
		t.Errorf("%v", got)
	}
	if got := FixFirst(nil); got == nil || len(got) != 0 {
		t.Errorf("%v", got)
	}
}

func TestEvaluate(t *testing.T) {
	f := goodFacts(t, "")
	f.Config.Server.TLS.Mode = "off" // transit.https at risk
	f.Key.Unused = []string{"/x/master.key"}
	f.Disks = []Disk{{Kind: DiskVirtual}}
	r := Evaluate(f)
	if r.Summary.Risk != 1 || r.Summary.Attention != 1 || r.Summary.Unknown != 1 {
		t.Errorf("summary %+v", r.Summary)
	}
	if !slices.Equal(r.FixFirst, []string{"transit.https", "rest.master_key"}) {
		t.Errorf("fix first %v", r.FixFirst)
	}
	if !slices.Equal(r.AtRisk(), []string{"transit.https"}) {
		t.Errorf("at risk %v", r.AtRisk())
	}
	total := r.Summary.Risk + r.Summary.Attention + r.Summary.Unknown + r.Summary.Good
	if total != len(r.Checks) {
		t.Errorf("%d counted, %d checks", total, len(r.Checks))
	}
	// Groups in page order, worst first within each, then by rank.
	last := -1
	for i, c := range r.Checks {
		g := groupIndex(c.Group)
		if g < last {
			t.Fatalf("%s out of group order", c.ID)
		}
		if g == last && i > 0 {
			p := r.Checks[i-1]
			if p.State.order() > c.State.order() || p.State == c.State && p.Rank > c.Rank {
				t.Errorf("%s before %s", p.ID, c.ID)
			}
		}
		last = g
	}
	// HTTPS off: the protections that need it aren't listed.
	for _, s := range r.AlwaysOn {
		if strings.Contains(s, "HSTS") {
			t.Error("HSTS listed with HTTPS off")
		}
	}
	if len(r.NotChecked) != 5 || r.CA == nil {
		t.Errorf("not checked %d, ca %v", len(r.NotChecked), r.CA)
	}
	if !strings.Contains(r.CA.Current.Subject, "Signalith Local CA") || r.CA.ScopeSetting != "standard" {
		t.Errorf("ca %+v", r.CA)
	}
	// Hidden checks are left out entirely.
	if r.Find("use.confidential_vm") != nil || r.Find("accounts.directory") != nil {
		t.Error("a hidden check is in the report")
	}
}

func TestReportJSON(t *testing.T) {
	f := goodFacts(t, "")
	f.Config.OpenSearch.TLSSkipVerify = true
	r := Evaluate(f)
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"checked_at", "server", "summary", "fix_first", "groups", "checks", "always_on", "not_checked", "ca"} {
		if _, ok := m[k]; !ok {
			t.Errorf("no %s", k)
		}
	}
	if _, ok := m["others"]; ok {
		t.Error("others without a cluster")
	}
	var c map[string]any
	for _, x := range m["checks"].([]any) {
		if x.(map[string]any)["id"] == "transit.opensearch" {
			c = x.(map[string]any)
		}
	}
	fix := c["fix"].(map[string]any)
	if fix["label"] != "How to fix" || fix["page"] != nil || fix["setting"] != "opensearch.tls_skip_verify" || fix["locked_by"] != "" {
		t.Errorf("fix %v", fix)
	}
	if _, ok := fix["commands"].(map[string]any); !ok {
		t.Errorf("commands %v", fix["commands"])
	}
	if d := c["details"].([]any); len(d) != 0 {
		t.Errorf("details %v", d)
	}
	if c["tip"] != nil {
		t.Errorf("tip %v", c["tip"])
	}
	ca := m["ca"].(map[string]any)
	if _, ok := ca["seen_names"]; !ok {
		t.Error("the server's report has no seen_names")
	}
	// The CLI's leaves out what only the server sees.
	f.Runtime = nil
	b, _ = json.Marshal(Evaluate(f))
	if strings.Contains(string(b), "seen_names") || strings.Contains(string(b), "refusals") {
		t.Errorf("CLI report: %s", b)
	}
}

func TestTypographic(t *testing.T) {
	f := goodFacts(t, "")
	f.Config.Server.TLS.Mode = "off"
	r := Evaluate(f).Typographic()
	c := r.Find("transit.https")
	if strings.Contains(c.Line, "'") || strings.Contains(c.Fix.Steps[0], "'") {
		t.Errorf("%q %q", c.Line, c.Fix.Steps)
	}
	f.Key.Perm.OtherRead = true
	f.Key.Source.Path = "/srv/it's/master.key"
	r = Evaluate(f).Typographic()
	k := r.Find("rest.master_key")
	if !strings.Contains(k.Fix.Commands["linux"], `'/srv/it'\''s/master.key'`) {
		t.Errorf("commands changed: %q", k.Fix.Commands["linux"])
	}
	if !strings.Contains(r.Find("transit.certificate").Line, "’") {
		t.Error("no typographic apostrophe")
	}
}

func TestDeniedAndTimedOut(t *testing.T) {
	f := goodFacts(t, "")
	f.Server.OS = "windows"
	f.deny("host.files")
	f.TimedOut = map[string]bool{"rest.disk": true}
	r := Evaluate(f)
	if c := r.Find("host.files"); c.State != Unknown || c.Line != "Run signalith security in a PowerShell opened as Administrator to check this." {
		t.Errorf("%+v", c)
	}
	if c := r.Find("rest.disk"); c.State != Unknown || c.Line != TimedOutLine || c.Fix.Label != "How to check" {
		t.Errorf("%+v", c)
	}
}

func TestGather(t *testing.T) {
	f := &Facts{}
	slow := make(chan struct{})
	defer close(slow)
	start := time.Now()
	Gather(context.Background(), f, 300*time.Millisecond, []Collector{
		{Name: "fast", Checks: []string{"a"}, Run: func(context.Context) func(*Facts) {
			return func(f *Facts) { f.ConfidentialVM = "first" }
		}},
		{Name: "second", Checks: []string{"b"}, Run: func(context.Context) func(*Facts) {
			return func(f *Facts) { f.ConfidentialVM += ",second" }
		}},
		{Name: "stuck", Checks: []string{"c", "d"}, Run: func(context.Context) func(*Facts) {
			<-slow // an OS call that ignores its context
			return func(f *Facts) { f.ConfidentialVM = "late" }
		}},
		{Name: "own limit", Checks: []string{"e"}, Timeout: 50 * time.Millisecond, Run: func(ctx context.Context) func(*Facts) {
			<-ctx.Done()
			return nil
		}},
		{Name: "panics", Checks: []string{"f"}, Run: func(context.Context) func(*Facts) { panic("boom") }},
	})
	if time.Since(start) > 2*time.Second {
		t.Errorf("took %v", time.Since(start))
	}
	if f.ConfidentialVM != "first,second" {
		t.Errorf("applied %q", f.ConfidentialVM)
	}
	for _, id := range []string{"c", "d", "e", "f"} {
		if !f.TimedOut[id] {
			t.Errorf("%s not timed out", id)
		}
	}
	if f.TimedOut["a"] || f.TimedOut["b"] {
		t.Errorf("%v", f.TimedOut)
	}
}

func TestHostCollectors(t *testing.T) {
	c := loadConfig(t, httpsAuto+"opensearch:\n  url: http://127.0.0.1:1\n  password: "+sentinelOS+"\n")
	state := c.StateDir()
	if err := os.MkdirAll(filepath.Join(state, "tls"), 0o700); err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(state, "tls", "server.key")
	if err := os.WriteFile(key, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	h := Host{Config: c, GOOS: "linux", PID: "self", Account: Account{UID: os.Getuid(), GID: os.Getgid()}, Getenv: func(string) string { return "" }}
	f := NewFacts(h, now, ServerInfo{Name: "t", OS: goosForTest()})
	Gather(context.Background(), f, 10*time.Second, HostCollectors(h, false))
	if len(f.TimedOut) != 0 {
		t.Errorf("timed out: %v", f.TimedOut)
	}
	if len(f.Secrets.Stored) != 1 || f.Secrets.Stored[0].State != secrets.Plain || len(f.Disks) == 0 || !f.Files.Known {
		t.Errorf("secrets %+v disks %+v files %+v", f.Secrets, f.Disks, f.Files)
	}
	if !errors.Is(f.Key.SourceErr, secrets.ErrNoKey) {
		t.Errorf("key %v", f.Key.SourceErr)
	}
	if goosForTest() != "windows" {
		found := false
		for _, p := range f.Files.Problems {
			if p.Path == key && p.Read && p.Everyone {
				found = true
			}
		}
		if !found {
			t.Errorf("a key readable by everyone was not found: %+v", f.Files.Problems)
		}
	}
	noSecrets(t, Evaluate(f))
}
