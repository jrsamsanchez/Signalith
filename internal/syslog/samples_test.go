package syslog

import (
	"fmt"
	"os"
	"strings"
	"testing"
)

// TestRealAVSamples runs real antivirus log lines from public sources
// (testdata/av-samples.txt) through the receiver and checks the fields
// each must give.
func TestRealAVSamples(t *testing.T) {
	b, err := os.ReadFile("testdata/av-samples.txt")
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{}
	source, n, malware := "", 0, 0
	for line := range strings.SplitSeq(string(b), "\n") {
		line = strings.TrimRight(line, "\r")
		switch {
		case strings.HasPrefix(line, "# source: "):
			source = strings.TrimPrefix(line, "# source: ")
		case strings.HasPrefix(line, "# want: "):
			k, v, _ := strings.Cut(strings.TrimPrefix(line, "# want: "), "=")
			want[k] = v
		case line == "" || strings.HasPrefix(line, "#"):
		default:
			if len(want) == 0 || source == "" {
				t.Fatalf("sample with no source or want: %.80s", line)
			}
			d := doc(line)
			for k, v := range want {
				if got := fmt.Sprint(d[k]); got != v {
					t.Errorf("%s\n%.120s\n%s = %q, want %q", source, line, k, got, v)
				}
			}
			if want["_model"] == "Malware" {
				checkMalware(t, line, d)
				malware++
			}
			n++
			want, source = map[string]any{}, ""
		}
	}
	if n < 50 || malware < 15 {
		t.Errorf("%d samples, %d Malware", n, malware)
	}
}
