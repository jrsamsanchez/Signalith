package checks

import (
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"
)

var idPattern = regexp.MustCompile(`^[a-z0-9-]+$`)

// nistPattern accepts NIST SP 800-53 control IDs as the SSG writes them,
// such as "AC-6", "AC-6(2)", "IA-5(1)(c)", "AC-17(a)" or "CM-6.1(iv)".
var nistPattern = regexp.MustCompile(`^[A-Z]{2}-\d+(\.\d+)?(\s?\([0-9a-z]+\))*$`)

func TestChecksWellFormed(t *testing.T) {
	all := All()
	if len(all) == 0 {
		t.Fatal("no checks")
	}
	seen := map[string]bool{}
	for _, c := range all {
		if !idPattern.MatchString(c.ID) {
			t.Errorf("%q: ID does not match %s", c.ID, idPattern)
		}
		if seen[c.ID] {
			t.Errorf("%q: duplicate ID", c.ID)
		}
		seen[c.ID] = true
		if !slices.Contains(Platforms, c.Platform) {
			t.Errorf("%s: bad platform %q", c.ID, c.Platform)
		}
		if !strings.HasPrefix(c.ID, c.Platform+"-") {
			t.Errorf("%s: ID should start with %q", c.ID, c.Platform+"-")
		}
		if !slices.Contains(Severities, c.Severity) {
			t.Errorf("%s: bad severity %q", c.ID, c.Severity)
		}
		for name, v := range map[string]string{"Title": c.Title, "Description": c.Description, "Remediation": c.Remediation, "SQL": c.SQL} {
			if strings.TrimSpace(v) == "" {
				t.Errorf("%s: empty %s", c.ID, name)
			}
		}
		if !strings.Contains(c.SQL, "result") || !strings.Contains(c.SQL, "detail") {
			t.Errorf("%s: SQL must produce result and detail columns", c.ID)
		}
		if c.RuleID != "" && !regexp.MustCompile(`^[a-z0-9_-]+$`).MatchString(c.RuleID) {
			t.Errorf("%s: odd RuleID %q", c.ID, c.RuleID)
		}
		if c.Platform == "linux" && c.RuleID == "" {
			t.Errorf("%s: Linux checks should name the SSG rule they follow", c.ID)
		}
		if c.Platform != "linux" && c.RuleID != "" {
			t.Errorf("%s: the SSG has no %s content, RuleID should be empty", c.ID, c.Platform)
		}
		for _, r := range c.References {
			if !nistPattern.MatchString(r) {
				t.Errorf("%s: reference %q is not a NIST SP 800-53 control ID", c.ID, r)
			}
		}
	}
}

func TestAllSorted(t *testing.T) {
	all := All()
	if !sort.SliceIsSorted(all, func(i, j int) bool {
		if all[i].Platform != all[j].Platform {
			return all[i].Platform < all[j].Platform
		}
		return all[i].ID < all[j].ID
	}) {
		t.Error("All() is not sorted by platform then ID")
	}
}

func TestFor(t *testing.T) {
	total := 0
	for _, p := range Platforms {
		cs := For(p)
		if len(cs) == 0 {
			t.Errorf("no checks for %s", p)
		}
		for _, c := range cs {
			if c.Platform != p {
				t.Errorf("For(%q) returned %s check %s", p, c.Platform, c.ID)
			}
		}
		total += len(cs)
	}
	if total != len(All()) {
		t.Errorf("For() over all platforms returned %d checks, All() %d", total, len(All()))
	}
	if len(For("plan9")) != 0 {
		t.Error("For(unknown platform) should be empty")
	}
}

func TestAllReturnsCopies(t *testing.T) {
	a := All()
	for i := range a {
		if len(a[i].References) > 0 {
			a[i].References[0] = "XX-0"
			break
		}
	}
	for _, c := range All() {
		if slices.Contains(c.References, "XX-0") {
			t.Fatal("changing a returned check's References changed the package data")
		}
	}
}

func TestModeWithin(t *testing.T) {
	got := modeWithin("mode", "0640")
	for _, want := range []string{"& ~6", "& ~4", "& ~0"} {
		if !strings.Contains(got, want) {
			t.Errorf("modeWithin(0640) = %s, missing %q", got, want)
		}
	}
}
