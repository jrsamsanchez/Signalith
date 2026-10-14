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
		// A wildcard field indexes values of any length.
		"script_block_text": strings.Repeat("x", 9000) + ` Invoke-Mimikatz C:\Windows\Temp\a.ps1`,
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
		`script_block_text="*invoke-mimikatz*"`:   true,
		`script_block_text="*\Windows\Temp\*"`:    true,
		`script_block_text="*\Windows\System*"`:   false,
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

// A wildcard field takes backslash literally, a keyword as an escape, so a
// pattern with a backslash searches both ways (older days and OpenSearch
// before 2.15 have keywords); other fields search one way.
func TestWildcardFieldQuery(t *testing.T) {
	q := equalsQuery("script_block_text", `*\Temp\*`)
	should, _ := q["bool"].(map[string]any)["should"].([]any)
	if len(should) != 2 {
		t.Fatalf("query = %v", q)
	}
	values := []string{}
	for _, c := range should {
		w := c.(map[string]any)["wildcard"].(map[string]any)["script_block_text"].(map[string]any)
		values = append(values, w["value"].(string))
	}
	if values[0] != `*\\Temp\\*` || values[1] != `*\Temp\*` {
		t.Errorf("values = %q", values)
	}
	if q := equalsQuery("script_block_text", "*iex*"); q["wildcard"] == nil {
		t.Errorf("no backslash: %v", q)
	}
	if q := equalsQuery("process", `*\Temp\*`); q["wildcard"] == nil {
		t.Errorf("keyword field: %v", q)
	}
}

func TestWildcardFieldTerms(t *testing.T) {
	for src, want := range map[string]int{
		`script_block_text="*Invoke-Mimikatz*"`:                    13, // 15 characters, 13 three-character pieces
		`script_block_text IN ("*ab*", "*abcd*")`:                  2,
		`script_block_text="*\Temp\*" process="*very long value*"`: 8, // searched twice
		`NOT (script_block_text="abcde" OR user=x)`:                3,
	} {
		q, err := query.Parse(src)
		if err != nil {
			t.Fatal(err)
		}
		if got := WildcardFieldTerms(q.Search); got != want {
			t.Errorf("%s: %d, want %d", src, got, want)
		}
	}
}
