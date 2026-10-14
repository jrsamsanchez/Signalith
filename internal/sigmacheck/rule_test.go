package sigmacheck

import (
	"reflect"
	"testing"
)

// The base64offset and windash expansions match pySigma's, the reference
// Sigma implementation.
func TestPatterns(t *testing.T) {
	_, got, err := Patterns([]string{"base64offset", "contains"}, "http://")
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"aHR0cDovL", "h0dHA6Ly", "odHRwOi8v"}; !reflect.DeepEqual(got, want) {
		t.Errorf("base64offset = %q, want %q", got, want)
	}
	_, got, _ = Patterns([]string{"windash", "contains"}, " -enc ")
	if want := []string{" -enc ", " /enc ", " –enc ", " —enc ", " ―enc "}; !reflect.DeepEqual(got, want) {
		t.Errorf("windash = %q", got)
	}
	// Only a dash that starts a word is expanded.
	_, got, _ = Patterns([]string{"windash"}, "a-b -c")
	if len(got) != 5 || got[1] != "a-b /c" {
		t.Errorf("windash in a word = %q", got)
	}
}

func TestMatch(t *testing.T) {
	r, err := Parse([]byte(`title: t
id: x
logsource: {category: process_creation, product: windows}
detection:
  img:
    - Image|endswith: '\cmd.exe'
    - OriginalFileName: Cmd.Exe
  cli:
    CommandLine|contains|all: [' /c ', 'whoami']
  filter_null:
    ParentImage: null
  filter_esc:
    CommandLine|contains: 'literal\*star'
  condition: img and cli and not 1 of filter_*
`))
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		ev   map[string]string
		want bool
	}{
		{map[string]string{"Image": `C:\WINDOWS\CMD.EXE`, "CommandLine": "cmd /c WHOAMI", "ParentImage": "x"}, true},
		{map[string]string{"OriginalFileName": "cmd.exe", "CommandLine": "cmd /c whoami", "ParentImage": "x"}, true},
		{map[string]string{"Image": `C:\cmd.exe`, "CommandLine": "cmd /c whoami"}, false},                     // no parent: filtered
		{map[string]string{"Image": `C:\cmd.exe`, "CommandLine": "cmd /c whoami", "ParentImage": "-"}, false}, // "-" is empty
		{map[string]string{"Image": `C:\cmd.exe`, "CommandLine": "cmd /c whoami literal*star", "ParentImage": "x"}, false},
		{map[string]string{"Image": `C:\cmd.exe`, "CommandLine": "cmd /c whoami literalXstar", "ParentImage": "x"}, true},
		{map[string]string{"Image": `C:\cmd.exe`, "CommandLine": "cmd /k whoami", "ParentImage": "x"}, false},
	} {
		if got, err := r.Match(c.ev); err != nil || got != c.want {
			t.Errorf("%v: %v %v, want %v", c.ev, got, err, c.want)
		}
	}
}

func TestSynthesize(t *testing.T) {
	r, err := Parse([]byte(`title: t
id: x
detection:
  sel:
    Image|endswith: '\rundll32.exe'
    CommandLine|contains: ' -sta '
  filter:
    ParentImage|startswith: 'C:\Program Files\'
  condition: sel and not filter
`))
	if err != nil {
		t.Fatal(err)
	}
	syn, err := r.Synthesize(1, nil, map[string]string{"ParentImage": `D:\app.exe`})
	if err != nil {
		t.Fatal(err)
	}
	if len(syn.Positive) == 0 {
		t.Fatal("no positives")
	}
	for _, ev := range syn.Positive {
		if m, _ := r.Match(ev); !m {
			t.Errorf("positive does not match: %s", String(ev))
		}
	}
	filtered := false
	for _, ev := range syn.Negative {
		if m, _ := r.Match(ev); m {
			t.Errorf("negative matches: %s", String(ev))
		}
		if p := ev["ParentImage"]; len(p) >= 17 && p[:17] == `C:\Program Files\` {
			filtered = true
		}
	}
	if !filtered {
		t.Errorf("no negative for the filter: %v", syn.Negative)
	}
	// Free-text rules get no events.
	kw, _ := Parse([]byte("title: k\ndetection:\n  keywords: [evil]\n  condition: keywords\n"))
	if _, err := kw.Synthesize(1); err == nil {
		t.Error("synthesized a keyword rule")
	}
}
