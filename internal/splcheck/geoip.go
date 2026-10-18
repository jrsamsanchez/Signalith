package splcheck

import (
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"
	"sync"

	"github.com/jrsamsanchez/signalith/internal/geoip"
	"github.com/jrsamsanchez/signalith/internal/geoip/geoiptest"
	"github.com/jrsamsanchez/signalith/internal/sigmacheck"
)

// A rule's iplocation runs, in its test events, against a small GeoIP
// database built here (TestGeoIP), so they need no downloaded file:
//
//   - each address of 203.0.113.0/24 is its own city (TestIP is one), in
//     a region and country, with coordinates, as a GeoLite2 City or
//     DB-IP Lite record is;
//   - 198.51.100.0/24 (TestCountryIP) is a country and nothing else, as
//     a GeoLite2 record of an address located only to its country is;
//   - 192.0.2.0/24 is a continent and nothing else;
//   - private addresses (TestPrivateIP) are not listed, as in every
//     GeoIP database.
const (
	TestIP        = "203.0.113.7"
	TestCountryIP = "198.51.100.7"
	TestPrivateIP = "10.20.30.4"
)

var (
	testGeoIPOnce sync.Once
	testGeoIP     *geoip.Store
)

// TestGeoIP is the GeoIP database a rule's iplocation reads in its test
// events.
func TestGeoIP() *geoip.Store {
	testGeoIPOnce.Do(func() {
		nets := map[string]geoiptest.City{
			"198.51.100.0/24": {Country: "Testland", CountryCode: "TL"},
			"192.0.2.0/24":    {Continent: "Europe"},
		}
		for i := range 256 {
			nets[fmt.Sprintf("203.0.113.%d/32", i)] = geoiptest.City{
				City: fmt.Sprintf("Testville %d", i), Region: "Test Region", Country: "Testland", CountryCode: "TL",
				Continent: "Europe", Timezone: "Europe/Paris", Lat: 48.5 + float64(i)/1000, Lon: 2.25,
			}
		}
		b, err := geoiptest.Build("GeoLite2-City", nets)
		if err == nil {
			testGeoIP, err = geoip.FromBytes(b)
		}
		if err != nil {
			panic("splcheck: building the test GeoIP database: " + err.Error())
		}
	})
	return testGeoIP
}

// Splunk's iplocation adds City, Country, Region, lat and lon for an
// address its database lists: each one it has no value for is there but
// empty (a country-level record's City is ""), and each replaces a value
// the event already had. An address it does not list (a private one) or
// a value that is not an address gets none, and a field the event
// already had keeps its value. Signalith's iplocation with no options
// does the same, so a rule's iplocation of a field runs as written.
var iplocationStageRe = regexp.MustCompile(`(?i)^iplocation\s+([A-Za-z_][\w.{}]*)$`)

// iplocationFields are the fields Splunk's iplocation adds.
var iplocationFields = []string{"City", "Region", "Country", "lat", "lon"}

// iplocationStage returns the stages Signalith runs for a later stage
// that is Splunk's iplocation of a field, false when s is not one. An
// iplocation with options (prefix=, allfields=, lang=) is refused.
func iplocationStage(s string) ([]string, bool, error) {
	if !strings.HasPrefix(strings.ToLower(s), "iplocation") {
		return nil, false, nil
	}
	m := iplocationStageRe.FindStringSubmatch(s)
	if m == nil {
		return nil, false, fmt.Errorf("search has a later stage Signalith does not run: %s (only iplocation of one field, with no options, is converted)", firstWords(s))
	}
	return []string{"iplocation " + m[1]}, true, nil
}

// wholeRowRe is a stage that reads every field a row has: fillnull with
// no fields, values(*), foreach *, table *.
var wholeRowRe = regexp.MustCompile(`(?i)^fillnull(\s+value\s*=\s*\S+)?\s*$|\(\s*\*\s*\)|^foreach\s+\*|^(table|fields)\s+\*`)

// iplocationLater returns an error for a stage after an iplocation that
// reads every field a row has: no test here shows that Signalith's rows
// then hold the fields Splunk's do (both add iplocation's fields as
// columns only when an address is located), so it is not converted.
func iplocationLater(s string) error {
	if wholeRowRe.MatchString(s) {
		return fmt.Errorf("search has a later stage Signalith reads differently after iplocation: %s reads every field a row has", firstWords(s))
	}
	return nil
}

// iplocationField is the field of a rule's iplocation, "" for none.
func (r *Rule) iplocationField() string {
	for _, s := range strings.Split(r.Post, "\n| ") {
		if rest, ok := strings.CutPrefix(s, "iplocation "); ok {
			return rest
		}
	}
	return ""
}

// IPLocation reports whether a rule's later stages run iplocation, which
// needs a GeoIP database.
func (r *Rule) IPLocation() bool { return r.iplocationField() != "" }

// locationNameRe is a field Splunk's iplocation adds, or a * that may
// stand for one.
var locationNameRe = regexp.MustCompile(`\b(City|Region|Country|lat|lon|Continent|Timezone|MetroCode)\b|\*`)

// readsLocation reports whether stages may read a field iplocation adds.
func readsLocation(stages []string) bool {
	for _, s := range stages {
		if locationNameRe.MatchString(postMacros.ReplaceAllString(s, "")) {
			return true
		}
	}
	return false
}

// elsewhere returns, for a rule that runs iplocation, its first test
// event that is found again from an address the test database locates
// only to its country (each of Splunk's fields but Country empty), and
// from a private address (no fields), each found or not as the rule's
// later stages say.
func (r *Rule) elsewhere(cases []sigmacheck.Case) []sigmacheck.Case {
	if !r.IPLocation() {
		return nil
	}
	for _, c := range cases {
		if !c.Expect {
			continue
		}
		var out []sigmacheck.Case
		for _, ip := range []string{TestCountryIP, TestPrivateIP} {
			alt := c
			alt.Data = maps.Clone(c.Data)
			moved := false
			for k, v := range alt.Data {
				if v == TestIP {
					alt.Data[k], moved = ip, true
				}
			}
			if !moved {
				return nil
			}
			docs, model := StoredCopies(alt)
			alt.Expect = InModel(r.Node, model) && !slices.ContainsFunc(docs, func(d map[string]any) bool { return !Eval(r.Where, View(d)) }) && r.KeepsAll(docs)
			out = append(out, alt)
		}
		return out
	}
	return nil
}
