package search

import (
	"compress/gzip"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/internal/geoip"
	"github.com/jrsamsanchez/signalith/internal/geoip/geoiptest"
	"github.com/jrsamsanchez/signalith/internal/lookuptables"
)

// corpusSearch is one search of testdata/splunk_corpus.json.gz, which
// internal/search/splcorpus builds from Splunk's security_content.
type corpusSearch struct {
	Source string `json:"source"`
	Name   string `json:"name"`
	Search string `json:"search"`
}

func loadCorpus(t *testing.T) []corpusSearch {
	t.Helper()
	f, err := os.Open("testdata/splunk_corpus.json.gz")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	var c []corpusSearch
	if err := json.NewDecoder(zr).Decode(&c); err != nil {
		t.Fatal(err)
	}
	return c
}

// corpusLookups returns a store holding an empty table for each lookup
// table security_content defines (testdata/splunk_lookups.json), with
// its columns, as a Splunk server with the app installed has. Names
// Signalith does not take as table names are left out.
func corpusLookups(t *testing.T) *lookuptables.Store {
	t.Helper()
	raw, err := os.ReadFile("testdata/splunk_lookups.json")
	if err != nil {
		t.Fatal(err)
	}
	var tables map[string][]string
	if err := json.Unmarshal(raw, &tables); err != nil {
		t.Fatal(err)
	}
	s, err := lookuptables.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for name, cols := range tables {
		var b strings.Builder
		w := csv.NewWriter(&b)
		_ = w.Write(cols)
		w.Flush()
		_, _ = s.Put(name, []byte(b.String()))
	}
	return s
}

type emptyStore struct{}

func (emptyStore) Search(context.Context, string, map[string]any) (map[string]any, error) {
	return map[string]any{"hits": map[string]any{"total": map[string]any{"value": 0}, "hits": []any{}}}, nil
}

var (
	unknownCommandRE = regexp.MustCompile(`unknown command "([^"]+)"`)
	unknownOptionRE  = regexp.MustCompile(`unknown (\w+) option "?([^" ;]+)`)
	unknownFuncRE    = regexp.MustCompile(`unknown (?:eval )?function "?([\w.]+)`)
	positionRE       = regexp.MustCompile(`^at position \d+: `)
)

// corpusCause groups a search's failure by what Signalith lacks.
func corpusCause(src string, err error) string {
	msg := err.Error()
	switch m := unknownCommandRE.FindStringSubmatch(msg); {
	case strings.Contains(src, "`"):
		return "macro not expanded"
	case m != nil:
		return "unknown command: " + m[1]
	}
	if m := unknownOptionRE.FindStringSubmatch(msg); m != nil {
		return "unknown option: " + m[1] + " " + m[2]
	}
	if m := unknownFuncRE.FindStringSubmatch(msg); m != nil {
		return "unsupported function: " + m[1]
	}
	if strings.Contains(msg, "no lookup table") {
		return "lookup table missing"
	}
	return "other: " + positionRE.ReplaceAllString(msg, "")
}

// corpusGeoIP returns a small GeoIP city database, standing in for the
// GeoLite2 file a server is given, so iplocation searches run.
func corpusGeoIP(t *testing.T) *geoip.Store {
	t.Helper()
	b, err := geoiptest.Build("GeoLite2-City", map[string]geoiptest.City{
		"81.2.69.0/24": {City: "London", Country: "United Kingdom", CountryCode: "GB", Lat: 51.5, Lon: -0.09},
	})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "city.mmdb"), b, 0o600); err != nil {
		t.Fatal(err)
	}
	return geoip.Open(dir)
}

// TestSplunkCorpus runs every search of Splunk's security_content
// detections, baselines and dashboards through the parser and the
// engine, and fails when fewer pass than splunkCorpusPass. Set
// SPL_COMPAT_REPORT to a file to write the failures grouped by cause.
func TestSplunkCorpus(t *testing.T) {
	corpus := loadCorpus(t)
	lookups := corpusLookups(t)
	e := &Engine{Store: emptyStore{}, Lookups: lookups, GeoIP: corpusGeoIP(t)}
	pass := 0
	causes := map[string][]string{}
	for _, c := range corpus {
		_, err := e.Run(context.Background(), c.Search)
		if err == nil {
			pass++
			continue
		}
		cause := corpusCause(c.Search, err)
		causes[cause] = append(causes[cause], c.Source+": "+c.Name)
	}
	t.Logf("%d of %d searches pass (%.1f%%)", pass, len(corpus), 100*float64(pass)/float64(len(corpus)))
	if path := os.Getenv("SPL_COMPAT_REPORT"); path != "" {
		var keys []string
		for k := range causes {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool {
			if len(causes[keys[i]]) != len(causes[keys[j]]) {
				return len(causes[keys[i]]) > len(causes[keys[j]])
			}
			return keys[i] < keys[j]
		})
		var b strings.Builder
		fmt.Fprintf(&b, "%d of %d pass\n\n", pass, len(corpus))
		for _, k := range keys {
			fmt.Fprintf(&b, "%d\t%s\t(e.g. %s)\n", len(causes[k]), k, causes[k][0])
		}
		if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if pass < splunkCorpusPass {
		t.Errorf("%d searches pass, fewer than the %d that passed before; a change broke Splunk searches that ran", pass, splunkCorpusPass)
	}
}

// splunkCorpusPass is how many corpus searches passed when it was last
// raised. Raise it when a change makes more pass.
const splunkCorpusPass = 2089
