// Package checks holds the configuration checks Signalith runs on hosts
// through osquery. Linux checks are based on rules from the SCAP Security
// Guide (ComplianceAsCode, BSD-3-Clause): each one names the SSG rule it
// follows in RuleID and carries the NIST SP 800-53 references that rule
// lists. The SSG publishes no macOS or Windows content, so the macOS and
// Windows checks are written by Signalith from vendor hardening guidance;
// their RuleID is empty and their references are the NIST controls they
// clearly support. All titles, descriptions and remediations are Signalith's
// own wording.
//
// Every check is a single osquery query that returns exactly one row with
// two columns: result ('pass', 'fail' or 'n/a') and detail (empty when the
// check passes, otherwise a short explanation). A check returns 'n/a' when
// the software or setting it inspects is not present on the host, for
// example the SSH server checks on a host without /etc/ssh/sshd_config.
//
// Known limits of the Linux checks: SSH settings and /etc/login.defs are read
// through osquery's augeas table, so osqueryd must be able to find its augeas
// lenses (--augeas_lenses); when it cannot, those checks report 'n/a'. Only
// the main sshd_config file is read, not files pulled in with Include.
package checks

import (
	"fmt"
	"sort"
	"strings"
)

// Check is one configuration check.
type Check struct {
	ID          string   // stable, lowercase [a-z0-9-], unique, e.g. "linux-sshd-disable-root-login"
	Title       string   // what a passing host does, plain English, e.g. "SSH does not allow root to sign in"
	Platform    string   // "linux", "windows" or "darwin"
	Severity    string   // "low", "medium" or "high"
	RuleID      string   // the SCAP Security Guide rule ID it is based on, e.g. "sshd_disable_root_login"; empty when none
	References  []string // NIST SP 800-53 control IDs, e.g. "AC-6(2)" (from the SSG rule's references); may be empty
	Description string   // one or two sentences on why it matters
	Remediation string   // how to fix it, concrete (command or setting)
	SQL         string   // osquery SQL returning exactly one row with columns result ('pass', 'fail' or 'n/a') and detail (text, '' when passing)
}

// Platforms are the platform values a Check can have.
var Platforms = []string{"darwin", "linux", "windows"}

// Severities are the severity values a Check can have.
var Severities = []string{"low", "medium", "high"}

// All returns every check, sorted by platform then ID.
func All() []Check {
	var out []Check
	for _, set := range [][]Check{linuxChecks, windowsChecks, darwinChecks} {
		for _, c := range set {
			c.References = append([]string(nil), c.References...)
			out = append(out, c)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Platform != out[j].Platform {
			return out[i].Platform < out[j].Platform
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// For returns the checks for one platform ("linux", "windows", "darwin").
func For(platform string) []Check {
	var out []Check
	for _, c := range All() {
		if c.Platform == platform {
			out = append(out, c)
		}
	}
	return out
}

// refs splits a comma-separated list of NIST control IDs.
func refs(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts
}

// sqlQuote quotes s as an SQL string literal.
func sqlQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}

// verdict builds the common outer query shape: the inner SELECT computes
// named values once, then naCond, passCond and the detail expressions decide
// the single result row. naCond may be empty when the check always applies.
func verdict(inner, naCond, naDetail, passCond, failDetail string) string {
	var b strings.Builder
	b.WriteString("SELECT\n  CASE")
	if naCond != "" {
		fmt.Fprintf(&b, " WHEN %s THEN 'n/a'", naCond)
	}
	fmt.Fprintf(&b, " WHEN %s THEN 'pass' ELSE 'fail' END AS result,\n  CASE", passCond)
	if naCond != "" {
		fmt.Fprintf(&b, " WHEN %s THEN %s", naCond, naDetail)
	}
	fmt.Fprintf(&b, " WHEN %s THEN '' ELSE %s END AS detail\nFROM (%s) AS s", passCond, failDetail, inner)
	return b.String()
}
