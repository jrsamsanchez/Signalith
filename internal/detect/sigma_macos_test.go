package detect

import (
	"strings"
	"testing"
)

// A macOS process creation rule reads only the program starts osquery
// reports from macOS, and a Linux one leaves them out.
func TestConvertSigmaMacOSProcessCreation(t *testing.T) {
	rule := func(product string) string {
		r, err := ConvertSigmaWith([]byte(`title: Keychain dump
logsource: {product: `+product+`, category: process_creation}
detection:
  sel:
    Image|endswith: '/security'
    CommandLine|contains: 'dump-keychain'
    ParentImage|endswith: '/bash'
  condition: sel
`), SigmaOptions{Strict: true})
		if err != nil {
			t.Fatal(err)
		}
		return r.Detection.Query
	}
	if q := rule("macos"); !strings.HasPrefix(q, "datamodel=Endpoint sourcetype=osquery:process_start ") ||
		!strings.Contains(q, "dump-keychain") || strings.Contains(q, "WinEventLog") {
		t.Errorf("macOS query = %s", q)
	}
	if q := rule("linux"); !strings.Contains(q, "WinEventLog:*") || !strings.Contains(q, "osquery:process_start") || !strings.Contains(q, "NOT") {
		t.Errorf("Linux query = %s", q)
	}
}
