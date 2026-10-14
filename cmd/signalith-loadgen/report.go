package main

import (
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"sort"
	"strings"
	"time"
)

// Criterion results.
const (
	statusPass   = "pass"
	statusFail   = "fail"
	statusSkip   = "skip"
	statusRecord = "record"
)

// Report is what a run found.
type Report struct {
	Run      string    `json:"run"`
	Scenario string    `json:"scenario"`
	Started  time.Time `json:"started"`
	Ended    time.Time `json:"ended"`
	Targets  []string  `json:"targets"`
	// Cluster is true when the targets are several servers sharing work;
	// Servers names them.
	Cluster bool     `json:"cluster"`
	Servers []string `json:"servers,omitempty"`
	// Skipped says why the scenario was not run at all.
	Skipped  string            `json:"skipped,omitempty"`
	Phases   []PhaseReport     `json:"phases,omitempty"`
	Faults   []FaultResult     `json:"faults,omitempty"`
	Verify   *Verdict          `json:"verify,omitempty"`
	Criteria []CriterionResult `json:"criteria,omitempty"`
	Notes    []string          `json:"notes,omitempty"`
	Pass     bool              `json:"pass"`
}

// PhaseReport is one phase's numbers.
type PhaseReport struct {
	Name      string                    `json:"name"`
	Seconds   float64                   `json:"seconds"`
	Counts    map[string]int64          `json:"counts,omitempty"`
	Latencies map[string]LatencySummary `json:"latencies_ms,omitempty"`
	Values    map[string]float64        `json:"values,omitempty"`
}

// CriterionResult is one criterion as measured.
type CriterionResult struct {
	Name     string   `json:"name"`
	Phase    string   `json:"phase,omitempty"`
	Measured *float64 `json:"measured,omitempty"`
	Limit    string   `json:"limit,omitempty"`
	Status   string   `json:"status"`
	Note     string   `json:"note,omitempty"`
}

// judge compares a measured value with a criterion's limits.
func judge(c Criterion, value float64, skip string) CriterionResult {
	res := CriterionResult{Name: c.Name, Phase: c.Phase, Limit: limitText(c)}
	if skip != "" {
		res.Status, res.Note = statusSkip, skip
		return res
	}
	v := math.Round(value*1000) / 1000
	res.Measured = &v
	switch {
	case c.Max == nil && c.Min == nil:
		res.Status = statusRecord
	case math.IsNaN(value):
		res.Status = statusFail
	case c.Max != nil && value > *c.Max, c.Min != nil && value < *c.Min:
		res.Status = statusFail
	default:
		res.Status = statusPass
	}
	return res
}

func limitText(c Criterion) string {
	var parts []string
	if c.Min != nil {
		parts = append(parts, fmt.Sprintf(">= %g", *c.Min))
	}
	if c.Max != nil {
		parts = append(parts, fmt.Sprintf("<= %g", *c.Max))
	}
	return strings.Join(parts, " and ")
}

// finish works out whether the run passed.
func (r *Report) finish() {
	r.Pass = true
	for _, c := range r.Criteria {
		if c.Status == statusFail {
			r.Pass = false
		}
	}
}

// WriteText writes the report for people.
func (r *Report) WriteText(w io.Writer) {
	fmt.Fprintf(w, "\nScenario %s, run %s\n", r.Scenario, r.Run)
	if r.Skipped != "" {
		fmt.Fprintf(w, "SKIPPED: %s\n", r.Skipped)
		return
	}
	kind := "one server (not a cluster)"
	if r.Cluster {
		kind = fmt.Sprintf("a cluster of %d servers (%s)", len(r.Servers), strings.Join(r.Servers, ", "))
	}
	fmt.Fprintf(w, "Targets: %s, %s\n", strings.Join(r.Targets, ", "), kind)
	for _, p := range r.Phases {
		fmt.Fprintf(w, "\nPhase %s (%.0fs)\n", p.Name, p.Seconds)
		names := make([]string, 0, len(p.Counts))
		for n := range p.Counts {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			fmt.Fprintf(w, "  %-32s %d\n", n, p.Counts[n])
		}
		names = names[:0]
		for n := range p.Latencies {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			l := p.Latencies[n]
			fmt.Fprintf(w, "  %-32s n=%d p50=%gms p95=%gms p99=%gms max=%gms\n", n+" time", l.Count, l.P50, l.P95, l.P99, l.Max)
		}
	}
	for _, f := range r.Faults {
		fmt.Fprintf(w, "\nFault %s on %s at %.0fs", f.Kind, orNone(f.Server), f.At)
		switch {
		case f.Skipped != "":
			fmt.Fprintf(w, ": skipped, %s", f.Skipped)
		case f.Error != "":
			fmt.Fprintf(w, ": %s", f.Error)
		}
		if f.TakeoverSeconds != nil {
			fmt.Fprintf(w, "; %s took over after %.1fs", orNone(f.NewLeader), *f.TakeoverSeconds)
		}
		fmt.Fprintln(w)
	}
	if v := r.Verify; v != nil {
		fmt.Fprintf(w, "\nVerify: %d events acknowledged, %d copies stored, %d lost, %d duplicated, %d stored without an answer\n",
			v.Acked, v.Stored, v.Lost, v.Duplicated, v.Unacked)
		for _, e := range v.Examples {
			fmt.Fprintf(w, "  %s\n", e)
		}
	}
	fmt.Fprintln(w)
	for _, c := range r.Criteria {
		name := c.Name
		if c.Phase != "" {
			name += " (" + c.Phase + ")"
		}
		measured := "-"
		if c.Measured != nil {
			measured = fmt.Sprintf("%g", *c.Measured)
		}
		line := fmt.Sprintf("%-6s %-44s measured %-10s", strings.ToUpper(c.Status), name, measured)
		if c.Limit != "" {
			line += " limit " + c.Limit
		}
		if c.Note != "" {
			line += "  (" + c.Note + ")"
		}
		fmt.Fprintln(w, strings.TrimRight(line, " "))
	}
	for _, n := range r.Notes {
		fmt.Fprintf(w, "Note: %s\n", n)
	}
	if r.Pass {
		fmt.Fprintln(w, "\nRESULT: PASS")
	} else {
		fmt.Fprintln(w, "\nRESULT: FAIL")
	}
}

// WriteJSON saves the report as JSON.
func (r *Report) WriteJSON(path string) error {
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}
