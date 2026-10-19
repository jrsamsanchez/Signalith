package splcheck

import (
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/sigmacheck"
)

// Macros and rules missing what they need are refused.
func TestParseMacroAndRuleRefusals(t *testing.T) {
	if _, err := ParseMacro([]byte("name: [")); err == nil {
		t.Error("a macro that is not YAML parsed")
	}
	if _, err := ParseMacro([]byte("definition: index=main\n")); err == nil || err.Error() != "macro has no name" {
		t.Errorf("unnamed macro: %v", err)
	}
	m, err := ParseMacro([]byte("name: m\ndefinition: index=main\n"))
	if err != nil || m.Name != "m" {
		t.Errorf("macro = %+v %v", m, err)
	}
	for _, src := range []string{
		"name: a\nsearch: x\n",
		"id: a\nsearch: x\n",
		"id: a\nname: a\n",
	} {
		if _, err := ParseWith([]byte(src), nil, ParseOptions{}); err == nil || !strings.Contains(err.Error(), "not a detection") {
			t.Errorf("%q: err = %v", src, err)
		}
	}
	if _, err := ParseWith([]byte("name: ["), nil, ParseOptions{}); err == nil {
		t.Error("a rule that is not YAML parsed")
	}
}

// OneDrive's records carry SharePoint's fields.
func TestO365CarriesOneDrive(t *testing.T) {
	if !o365Carries("OneDrive", "SiteUrl") || !o365Carries("SharePoint", "SiteUrl") {
		t.Error("OneDrive or SharePoint records lack SiteUrl")
	}
	if o365Carries("OneDrive", "MailboxOwnerUPN") {
		t.Error("OneDrive records carry an Exchange field")
	}
	if !o365Carries("Exchange", "UserId") {
		t.Error("the common schema's fields are not carried")
	}
}

// A threshold rule's test events together reach its threshold, and one
// alone does not.
func TestReaches(t *testing.T) {
	r, err := Parse(rule("| tstats count from datamodel=Endpoint.Processes where Processes.process_name=\"taskkill.exe\" by Processes.parent_process_name Processes.dest Processes.user _time span=1m | where count >=10 | `drop_dm_object_name(Processes)`"), testMacros)
	if err != nil {
		t.Fatal(err)
	}
	var pos []sigmacheck.Case
	for _, c := range Cases(r) {
		if c.Expect {
			pos = append(pos, c)
		}
	}
	if len(pos) == 0 {
		t.Fatal("no event the rule finds")
	}
	// Recorded events: ten of the same program stop on one host reach
	// count >= 10, nine do not.
	var events []sigmacheck.Case
	for range 10 {
		events = append(events, pos[0])
	}
	if !Reaches(r.Threshold, events) {
		t.Errorf("%d events do not reach the threshold", len(events))
	}
	if Reaches(r.Threshold, events[:9]) {
		t.Error("nine events reach count >= 10")
	}
}
