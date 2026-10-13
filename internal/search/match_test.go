package search

import (
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/query"
)

// MatchDoc evaluates the compiled OpenSearch query; the integration test
// (TestPackRulesAgainstOpenSearch) checks the same agreement on real
// indices.
func TestMatchDoc(t *testing.T) {
	doc := map[string]any{
		"process":      `findstr /S cpassword \\dc\sysvol\*.xml`,
		"process_name": "FindStr.exe",
		"dest_port":    int64(443),
		"src":          "10.1.2.3",
		"long":         strings.Repeat("a", 9000),
		"message":      "Sysmon event 1: findstr",
	}
	for q, want := range map[string]bool{
		`process="*\sysvol\*"`:                    true, // backslashes are literal
		`process="*\sysvol\*.xml"`:                true, // a * in the data is just a character
		`process="*sysvol?*"`:                     true,
		`process_name=findstr.exe`:                true, // terms ignore case
		`process_name=find*.EXE`:                  true,
		`process_name=findstr`:                    false,
		`dest_port=443`:                           true,
		`src=10.0.0.0/8`:                          true,
		`src=192.168.0.0/16`:                      false,
		`user=*`:                                  false,
		`process=*`:                               true,
		`long=*`:                                  false, // over ignore_above: not indexed
		`NOT process_name=cmd.exe`:                true,
		`process_name IN (cmd.exe, findstr.exe)`:  true,
		`(process_name=cmd.exe OR dest_port=443)`: true,
		`process_name=findstr.exe dest_port=80`:   false,
		`findstr`:                                 true,
	} {
		p, err := query.Parse(q)
		if err != nil {
			t.Fatalf("%s: %v", q, err)
		}
		got, err := MatchDoc(p.Search, doc)
		if err != nil || got != want {
			t.Errorf("%s = %v %v, want %v", q, got, err, want)
		}
	}
	// OpenSearch refuses a wildcard on a number field, so MatchDoc does too.
	p, _ := query.Parse(`dest_port=44*`)
	if _, err := MatchDoc(p.Search, doc); err == nil {
		t.Error("wildcard on a number field matched")
	}
}
