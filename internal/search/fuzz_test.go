// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package search

import (
	"encoding/json"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/query"
)

var compileSeeds = []string{
	`datamodel=Authentication action=failure earliest=-24h latest=now`,
	`NOT user=root src IN (10.0.0.1, "10.0.0.2") "failed password" ssh*`,
	"datamodel=Authentication action=failure\n| stats count, dc(user) as users by src, dest\n| where count > 20 AND users >= 2\n| sort -count, src\n| head 5",
	`* | timechart span=1h count by action`,
	`* earliest=-30d | timechart avg(bytes)`,
	`* | timechart span=2mon count`,
	`* | top limit=3 user by host`,
	`process_path="C:\Windows\System32\cmd.exe" process="*\sysvol\*.xml"`,
	`index=signalith-* (user=admin OR user=root) NOT host="web 01"`,
	`index=other-*`,
	`process=~"(?i)curl .*://[0-9]{1,3}\\." | where x=~"^a+$"`,
	`script_block_text="*\Windows\Temp\*" event_data=*mimikatz*`,
	`src=10.0.0.0/8 dest=10.1.2.0/23 x=0.0.0.0/0 y=fe80::/10 z=2001:db8::1/128`,
	`_time>=-1d@d _time<now _raw="a b" _raw!=c bytes>1e3 n<=-1.5`,
	`* | where count > 1 | threatmatch | intel src`,
	`* | stats count by a | where count > 1`,
	`a=1 | where b=2 | where NOT c=3 | head 7 | table a`,
	`* | stats median(bytes), perc95(bytes), stdev(bytes), values(user), list(user), latest(_time) by src`,
	`* earliest=-1d | timechart span=1h perc99(bytes) by dest`,
	`* | transaction src maxspan=5m startswith=(dest_port=443) endswith="findstr" | where eventcount > 1`,
	`| inputlookup max=5 owners | stats count by team`,
	`* | join type=left max=0 src [search datamodel=Network_Traffic | stats sum(bytes) by src | join src [search index=other-*]]`,
}

// FuzzCompile checks that every query Parse accepts compiles to an
// OpenSearch request, or a clean error, without panicking; that the
// request encodes as JSON; and that the clause count and in-memory
// matching (MatchDoc) handle it too.
func FuzzCompile(f *testing.F) {
	for _, s := range compileSeeds {
		f.Add(s)
	}
	doc := map[string]any{
		"process":           `findstr /S cpassword \\dc\sysvol\*.xml`,
		"process_name":      "FindStr.exe",
		"dest_port":         int64(443),
		"bytes":             2.5,
		"src":               "10.1.2.3",
		"dest":              "fe80::1",
		"message":           "Sysmon event 1: findstr",
		"script_block_text": `Invoke-Mimikatz C:\Windows\Temp\a.ps1`,
		"@timestamp":        "2026-10-15T10:00:00Z",
	}
	f.Fuzz(func(t *testing.T, src string) {
		q, err := query.Parse(src)
		if err != nil {
			return
		}
		e := &Engine{}
		if p, err := e.Compile(q); err == nil {
			if _, err := json.Marshal(p.Body); err != nil {
				t.Fatalf("Compile(%q) body does not encode: %v", src, err)
			}
		}
		filters := []query.Expr{q.Search}
		for _, c := range q.Commands {
			if w, ok := c.(*query.Where); ok {
				filters = append(filters, w.Expr)
			}
		}
		for _, x := range filters {
			if n, err := Clauses(x); err == nil && n < 0 {
				t.Fatalf("Clauses(%q) = %d", src, n)
			}
			_, _ = MatchDoc(x, doc)
		}
	})
}

// FuzzParseRegex checks that a pattern ParseRegex accepts translates to
// a Lucene pattern that compiles and, read the way MatchDoc reads it,
// matches the same strings as the original.
func FuzzParseRegex(f *testing.F) {
	for _, s := range [][2]string{
		{`(?i)curl .*://[0-9]{1,3}\.`, "CURL http://10.0.0.1"},
		{`^a+$`, "aaa"},
		{`a|b(c|d)*e?`, "xbcdx"},
		{`[^\s"]{2,}x{3}`, "ab xxx"},
		{`(?i)[a-zå]+\.exe`, "ÅA.EXE"},
		{`\d\w\S.`, "1a!\n"},
		{`a{2,5}?b??`, "aaab"},
		{`\bword\b`, "a word"},
		{`(?m)^a$`, "a\nb"},
		{`\x{1F600}\p{Greek}`, "\U0001F600α"},
		{`[[:alpha:]]+\Q.*\E`, "ab.*"},
	} {
		f.Add(s[0], s[1])
	}
	f.Fuzz(func(t *testing.T, pattern, s string) {
		r, err := ParseRegex(pattern)
		if err != nil {
			return
		}
		lre, err := luceneRegexp(r.Lucene)
		if err != nil {
			t.Fatalf("ParseRegex(%q) wrote %q, which does not compile: %v", pattern, r.Lucene, err)
		}
		if got, want := lre.MatchString(s), r.MatchString(s); got != want {
			t.Fatalf("ParseRegex(%q) wrote %q, which matches %q: %v, want %v", pattern, r.Lucene, s, got, want)
		}
	})
}
