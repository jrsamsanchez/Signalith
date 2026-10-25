// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package vulnscan

import (
	"math"
	"strings"
)

// CVSS3Score is the base score of a CVSS 3.0 or 3.1 vector, such as
// CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H (9.8), and its version.
// Distribution advisories give the vector, not the score. ok is false for
// anything else, such as a CVSS 4 vector or one missing a base metric.
func CVSS3Score(vector string) (score float64, version string, ok bool) {
	parts := strings.Split(strings.TrimSpace(vector), "/")
	if len(parts) < 9 {
		return 0, "", false
	}
	switch parts[0] {
	case "CVSS:3.0":
		version = "3.0"
	case "CVSS:3.1":
		version = "3.1"
	default:
		return 0, "", false
	}
	m := map[string]string{}
	for _, p := range parts[1:] {
		k, v, cut := strings.Cut(p, ":")
		if !cut {
			return 0, "", false
		}
		if _, dup := m[k]; !dup {
			m[k] = v
		}
	}
	weights := map[string]map[string]float64{
		"AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
		"AC": {"L": 0.77, "H": 0.44},
		"UI": {"N": 0.85, "R": 0.62},
		"C":  {"H": 0.56, "L": 0.22, "N": 0},
		"I":  {"H": 0.56, "L": 0.22, "N": 0},
		"A":  {"H": 0.56, "L": 0.22, "N": 0},
	}
	w := map[string]float64{}
	for k, table := range weights {
		x, known := table[m[k]]
		if !known {
			return 0, "", false
		}
		w[k] = x
	}
	changed := false
	switch m["S"] {
	case "U":
	case "C":
		changed = true
	default:
		return 0, "", false
	}
	var pr float64
	switch m["PR"] {
	case "N":
		pr = 0.85
	case "L":
		pr = 0.62
		if changed {
			pr = 0.68
		}
	case "H":
		pr = 0.27
		if changed {
			pr = 0.5
		}
	default:
		return 0, "", false
	}
	iss := 1 - (1-w["C"])*(1-w["I"])*(1-w["A"])
	impact := 6.42 * iss
	if changed {
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	}
	if impact <= 0 {
		return 0, version, true
	}
	exploit := 8.22 * w["AV"] * w["AC"] * pr * w["UI"]
	if changed {
		return roundUp(math.Min(1.08*(impact+exploit), 10)), version, true
	}
	return roundUp(math.Min(impact+exploit, 10)), version, true
}

// roundUp is CVSS 3.1's Roundup: the smallest number with one decimal
// that is at least x, without floating point surprises.
func roundUp(x float64) float64 {
	n := int64(math.Round(x * 100000))
	if n%10000 == 0 {
		return float64(n) / 100000
	}
	return float64(n/10000+1) / 10
}
