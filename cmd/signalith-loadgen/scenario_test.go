package main

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParseScenario(t *testing.T) {
	t.Setenv("LOADGEN_TEST_TARGET", "https://siem-a:8443")
	s, err := parseScenario([]byte(`
name: t
targets: [${LOADGEN_TEST_TARGET}]
phases:
  - {name: warm, for: 30s, agents: {n: 2, rate: 10}}
  - {name: idle, for: 2m}
faults:
  - {at: 1m, kind: kill9, target: leader, cmd: "kill -9 $(cat {server}.pid)"}
criteria:
  - {name: events_lost, max: 0}
  - {name: page_p95_ms}
`))
	if err != nil {
		t.Fatal(err)
	}
	if s.Targets[0] != "https://siem-a:8443" {
		t.Errorf("targets %v: ${VAR} not replaced", s.Targets)
	}
	if s.Phases[1].For.D() != 2*time.Minute || s.duration() != 150*time.Second {
		t.Errorf("durations %v %v", s.Phases[1].For.D(), s.duration())
	}
	if s.Faults[0].Cmd != "kill -9 $(cat {server}.pid)" {
		t.Errorf("shell text changed: %q", s.Faults[0].Cmd)
	}
	if *s.Criteria[0].Max != 0 || s.Criteria[1].Max != nil {
		t.Errorf("criteria %+v", s.Criteria)
	}
}

func TestScenarioErrors(t *testing.T) {
	for name, tc := range map[string]struct{ yaml, want string }{
		"unknown criterion": {`name: t
phases: [{name: a, for: 1s}]
criteria: [{name: nope, max: 1}]`, `unknown name "nope"`},
		"unknown field": {`name: t
phases: [{name: a, for: 1s, agentz: {}}]`, "agentz"},
		"bad duration": {`name: t
phases: [{name: a, for: soon}]`, "not a duration"},
		"no phases":    {`name: t`, "at least one phase"},
		"fault late":   {"name: t\nphases: [{name: a, for: 10s}]\nfaults: [{at: 20s, kind: cmd, cmd: x}]", "after the last phase"},
		"fault kind":   {"name: t\nphases: [{name: a, for: 10s}]\nfaults: [{at: 1s, kind: meteor, cmd: x}]", "kind must be"},
		"no cmd":       {"name: t\nphases: [{name: a, for: 10s}]\nfaults: [{at: 1s, kind: kill9, target: leader}]", "cmd is required"},
		"phase twice":  {"name: t\nphases: [{name: a, for: 1s}, {name: a, for: 1s}]", "used twice"},
		"no phase":     {"name: t\nphases: [{name: a, for: 1s}]\ncriteria: [{name: page_p95_ms, phase: b}]", `no phase "b"`},
		"cookie":       {"name: t\nphases: [{name: a, for: 1s}]\ncriteria: [{name: os_ops_per_random_cookie, max: 0}]", "needs phase and baseline"},
		"syslog proto": {"name: t\nphases: [{name: a, for: 1s, syslog: {proto: smoke, sources: 1, rate: 1}}]", "proto must be"},
		"agents rate":  {"name: t\nphases: [{name: a, for: 1s, agents: {n: 3}}]", "rate is required"},
		"churn":        {"name: t\nphases: [{name: a, for: 1s, churn: {key: k, every: 1s, values: [1]}}]", "at least two values"},
		"seed path":    {"name: t\nseed: [{method: GET, path: /x}]\nphases: [{name: a, for: 1s}]", "must start with /api/"},
	} {
		_, err := parseScenario([]byte(tc.yaml))
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: got %v, want %q", name, err, tc.want)
		}
	}
}

// Every scenario in loadtest/ loads, so the nightly job never fails on a
// typo.
func TestLoadtestScenariosLoad(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("..", "..", "loadtest", "*.yaml"))
	if err != nil || len(files) < 8 {
		t.Fatalf("scenario files: %v %v", files, err)
	}
	for _, f := range files {
		if _, err := loadScenario(f); err != nil {
			t.Errorf("%s: %v", f, err)
		}
	}
}

func TestCriteriaDescribed(t *testing.T) {
	for name, what := range criteria {
		if what == "" {
			t.Errorf("%s has no description", name)
		}
	}
	for name := range clusterOnly {
		if _, ok := criteria[name]; !ok {
			t.Errorf("cluster-only %s is not a criterion", name)
		}
	}
}
