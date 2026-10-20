// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package detect

import (
	_ "embed"
	"encoding/json"
	"sort"
	"strings"
	"sync"
)

// attack.json is a compact extract of the MITRE ATT&CK Enterprise matrix
// (https://attack.mitre.org), © The MITRE Corporation, reproduced under
// the ATT&CK terms of use.
//
//go:embed attack.json
var attackJSON []byte

// ics.json is the same extract of the ATT&CK for ICS matrix, for
// detections on industrial networks.
//
//go:embed ics.json
var icsJSON []byte

// Tactic is an ATT&CK tactic, a column of the matrix.
type Tactic struct {
	ID    string `json:"id"`
	Short string `json:"short"`
	Name  string `json:"name"`
}

// Technique is an ATT&CK technique or sub-technique.
type Technique struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	Tactics []string `json:"tactics"` // tactic short names
}

// Catalog is the ATT&CK matrix.
type Catalog struct {
	Version    string      `json:"version"`
	Tactics    []Tactic    `json:"tactics"`
	Techniques []Technique `json:"techniques"`
	// Revoked maps technique IDs ATT&CK has retired to the technique that
	// replaced them (T1562.001 Disable or Modify Tools is T1685 since
	// version 19), so rules written for an older version still count.
	Revoked map[string]string `json:"revoked"`

	byID map[string]*Technique
}

var (
	catalogOnce sync.Once
	catalog     *Catalog
	icsOnce     sync.Once
	icsCatalog  *Catalog
)

// ATTACK returns the embedded ATT&CK (Enterprise) catalog.
func ATTACK() *Catalog {
	catalogOnce.Do(func() { catalog = loadCatalog("attack.json", attackJSON) })
	return catalog
}

// ICS returns the embedded ATT&CK for ICS catalog. Its technique IDs
// (T0800 to T0895, and the T1691 to T1701 range ATT&CK now shares with
// ICS) do not overlap the Enterprise ones Signalith's catalog holds.
func ICS() *Catalog {
	icsOnce.Do(func() { icsCatalog = loadCatalog("ics.json", icsJSON) })
	return icsCatalog
}

func loadCatalog(name string, b []byte) *Catalog {
	var c Catalog
	if err := json.Unmarshal(b, &c); err != nil {
		panic("detect: bad embedded " + name + ": " + err.Error())
	}
	c.byID = make(map[string]*Technique, len(c.Techniques))
	for i := range c.Techniques {
		c.byID[c.Techniques[i].ID] = &c.Techniques[i]
	}
	return &c
}

// AnyTechnique looks up a technique in the Enterprise matrix, then in
// the ICS one.
func AnyTechnique(id string) (*Technique, bool) {
	if t, ok := ATTACK().Technique(id); ok {
		return t, true
	}
	return ICS().Technique(id)
}

// Technique looks up a technique by ID, or by an ID ATT&CK has retired
// for the technique that replaced it.
func (c *Catalog) Technique(id string) (*Technique, bool) {
	id = strings.ToUpper(id)
	if t, ok := c.byID[id]; ok {
		return t, true
	}
	t, ok := c.byID[c.Revoked[id]]
	return t, ok
}

// Coverage is the ATT&CK matrix annotated with the detections that cover
// each technique, like the ES MITRE ATT&CK framework dashboard.
type Coverage struct {
	Version string            `json:"version"`
	Tactics []TacticCoverage  `json:"tactics"`
	Summary CoverageSummary   `json:"summary"`
	Unknown map[string]string `json:"unknown,omitempty"` // technique ID -> enabled detection that used it
	// ICS is the ATT&CK for ICS matrix, when a detection uses it.
	ICS *Coverage `json:"ics,omitempty"`
}

// TacticCoverage is one column.
type TacticCoverage struct {
	Tactic
	Techniques []TechniqueCoverage `json:"techniques"`
	Covered    int                 `json:"covered"` // techniques with an enabled detection
}

// TechniqueCoverage is one cell. Detections on sub-techniques count for
// their parent.
type TechniqueCoverage struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Enabled  []string `json:"enabled,omitempty"`  // enabled detection IDs
	Disabled []string `json:"disabled,omitempty"` // disabled detection IDs
	Subs     []string `json:"subs,omitempty"`     // covered sub-technique IDs
}

// CoverageSummary counts top-level techniques.
type CoverageSummary struct {
	Techniques int `json:"techniques"`
	Enabled    int `json:"enabled"`   // covered by an enabled detection
	Available  int `json:"available"` // covered only by disabled detections
}

// ComputeCoverage maps detections onto the Enterprise matrix, and onto
// the ICS matrix too when a detection uses one of its techniques.
func ComputeCoverage(ds []*Detection) *Coverage {
	out := coverageOf(ATTACK(), ICS(), ds)
	for _, d := range ds {
		for _, id := range d.MITRE {
			if _, ok := ICS().Technique(id); ok {
				out.ICS = coverageOf(ICS(), ATTACK(), ds)
				return out
			}
		}
	}
	return out
}

// coverageOf maps detections onto c's matrix. A technique of other (the
// other matrix) is not reported as unknown.
func coverageOf(c, other *Catalog, ds []*Detection) *Coverage {
	type cell struct {
		enabled, disabled map[string]bool
		subs              map[string]bool
	}
	cells := map[string]*cell{}
	get := func(id string) *cell {
		if x, ok := cells[id]; ok {
			return x
		}
		x := &cell{enabled: map[string]bool{}, disabled: map[string]bool{}, subs: map[string]bool{}}
		cells[id] = x
		return x
	}
	out := &Coverage{Version: c.Version}
	for _, d := range ds {
		for _, id := range d.MITRE {
			t, ok := c.Technique(id)
			if !ok {
				if _, theirs := other.Technique(id); theirs {
					continue
				}
				// Only a detection that runs is worth a warning: content
				// packs are off until turned on.
				if d.Enabled {
					if out.Unknown == nil {
						out.Unknown = map[string]string{}
					}
					out.Unknown[id] = d.ID
				}
				continue
			}
			id = t.ID
			parent, _, isSub := strings.Cut(id, ".")
			x := get(parent)
			if isSub {
				x.subs[id] = true
			}
			if d.Enabled {
				x.enabled[d.ID] = true
			} else {
				x.disabled[d.ID] = true
			}
		}
	}
	keys := func(m map[string]bool) []string {
		var s []string
		for k := range m {
			s = append(s, k)
		}
		sort.Strings(s)
		return s
	}
	counted := map[string]bool{}
	for _, tac := range c.Tactics {
		tc := TacticCoverage{Tactic: tac}
		for _, t := range c.Techniques {
			if strings.Contains(t.ID, ".") || !contains(t.Tactics, tac.Short) {
				continue
			}
			cov := TechniqueCoverage{ID: t.ID, Name: t.Name}
			if x, ok := cells[t.ID]; ok {
				cov.Enabled, cov.Disabled, cov.Subs = keys(x.enabled), keys(x.disabled), keys(x.subs)
			}
			if len(cov.Enabled) > 0 {
				tc.Covered++
			}
			if !counted[t.ID] {
				counted[t.ID] = true
				out.Summary.Techniques++
				if len(cov.Enabled) > 0 {
					out.Summary.Enabled++
				} else if len(cov.Disabled) > 0 {
					out.Summary.Available++
				}
			}
			tc.Techniques = append(tc.Techniques, cov)
		}
		out.Tactics = append(out.Tactics, tc)
	}
	return out
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}
