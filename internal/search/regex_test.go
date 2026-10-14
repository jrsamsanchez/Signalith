package search

import (
	"testing"

	"github.com/jrsamsanchez/signalith/internal/query"
)

func TestParseRegex(t *testing.T) {
	for _, c := range []struct{ pattern, lucene string }{
		{`abc`, `.*abc.*`},
		{`^C:\\Windows\\`, `C\:\\Windows\\.*`},
		{`\.exe$`, `.*\.exe`},
		{`a\d{2,3}b`, `.*a[0-9]{2,3}b.*`},
		{`(?i)cmd`, `.*[Cc][Mm][Dd].*`},
		{`x.y`, ".*x[^\n]y.*"},
		{`(foo|ba+r)?z`, `.*(foo|ba+r)?z.*`},
		{`[^a-c]`, `.*[^a-c].*`},
		{`a.*?b`, ".*a[^\n]*b.*"},
	} {
		re, err := ParseRegex(c.pattern)
		if err != nil {
			t.Errorf("%s: %v", c.pattern, err)
			continue
		}
		if re.Lucene != c.lucene {
			t.Errorf("%s: Lucene %q, want %q", c.pattern, re.Lucene, c.lucene)
		}
	}
	for _, bad := range []string{`\bword\b`, `a^b`, `(?m)^a`, `(`} {
		if _, err := ParseRegex(bad); err == nil {
			t.Errorf("%s: accepted", bad)
		}
	}
}

// The in-memory regexp query (what a real search runs) agrees with the
// pattern itself.
func TestRegexMatchDocAgrees(t *testing.T) {
	values := []string{"", "abc", "ABC", `C:\Windows\System32\cmd.exe`, "a12b", "a1234b", "x\ny", "xzy", "foobarz", "barz", "z", "d", "a\nb"}
	for _, p := range []string{`abc`, `(?i)abc`, `^C:\\Windows\\`, `\.exe$`, `a\d{2,3}b`, `x.y`, `(foo|ba+r)?z`, `^[^a-c]$`, `a.*?b`, `(?s)a.b`, `^$`} {
		re, err := ParseRegex(p)
		if err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		q, err := query.Parse(`f=~` + query.FormatValue(p))
		if err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		for _, v := range values {
			got, err := MatchDoc(q.Search, map[string]any{"f": v})
			if err != nil {
				t.Fatal(err)
			}
			if got != re.MatchString(v) {
				t.Errorf("%s on %q: search says %v, the pattern %v", p, v, got, !got)
			}
		}
	}
}
