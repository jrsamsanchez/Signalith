package search

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/query"
	sumidx "github.com/jrsamsanchez/signalith/internal/summary"
)

// summaryEngine has 48 hours of every model summarized.
func summaryEngine() *Engine {
	cov := &sumidx.Coverage{}
	now := time.Now().UTC()
	ranges := map[string][]sumidx.Range{}
	for _, m := range sumidx.Models() {
		ranges[m] = []sumidx.Range{{From: now.Add(-48 * time.Hour).Truncate(time.Hour), To: now.Add(-5 * time.Minute).Truncate(sumidx.Slot)}}
	}
	cov.Set(ranges)
	return &Engine{Opt: Options{IndexPrefix: "signalith", DefaultEarliest: "-24h", SummaryDays: 30}, Summaries: cov}
}

func TestSummaryPlan(t *testing.T) {
	e := summaryEngine()
	cases := map[string][]string{
		`datamodel=Authentication action=failure | stats count by src, user`:    {"Authentication"},
		`datamodel=Network_Traffic | stats sum(bytes) as b, count by dest_port`: {"Network_Traffic"},
		`datamodel=Authentication | timechart span=1h count by action`:          {"Authentication"},
		`datamodel=Authentication | chart count over src by action`:             {"Authentication"},
		`| tstats count from datamodel=Authentication by Authentication.src`:    {"Authentication"},
		`* | stats count by host`:                                               nil, // every model but Risk
		`datamodel=Authentication "failed password" | stats count`:              {},
		`datamodel=Authentication | stats dc(user)`:                             {},
		`datamodel=Authentication | stats count by process_id`:                  {},
		`datamodel=Authentication | timechart span=1m count`:                    {},
		`datamodel=Authentication | eval x=1 | stats count`:                     {},
		`datamodel=Authentication | head 5`:                                     {},
		`index=signalith-authentication-* | stats count`:                        {},
		`datamodel=Authentication _raw="*ssh*" | stats count`:                   {},
		`datamodel=Authentication earliest=-4h latest=-2h | stats count by src`: {"Authentication"},
		`datamodel=Authentication earliest=-30d@w | stats count`:                {},
		`datamodel=Network_Traffic | stats sum(bytes_in) by src`:                {"Network_Traffic"},
		`datamodel=Authentication | stats sum(bytes) by src`:                    {},
		`datamodel=Risk | stats sum(risk_score) by risk_object`:                 {"Risk"},
		`datamodel=Authentication earliest=-100d latest=-90d | stats count`:     {},
	}
	for src, want := range cases {
		q, err := query.Parse(src)
		if err != nil {
			t.Fatalf("%s: %v", src, err)
		}
		p, err := e.Compile(q)
		if err != nil {
			t.Fatalf("%s: %v", src, err)
		}
		if want == nil {
			if len(p.Summaries) == 0 || slices.Contains(p.Summaries, "Risk") {
				t.Errorf("%s: summaries %v", src, p.Summaries)
			}
			continue
		}
		if !slices.Equal(p.Summaries, want) && !(len(want) == 0 && len(p.Summaries) == 0) {
			t.Errorf("%s: summaries %v, want %v", src, p.Summaries, want)
		}
		if len(want) > 0 && !strings.HasSuffix(p.Index, ","+sumidx.IndexPattern("signalith")) {
			t.Errorf("%s: index %s", src, p.Index)
		}
		if len(want) == 0 && strings.Contains(p.Index, "_summary") {
			t.Errorf("%s: reads %s", src, p.Index)
		}
	}
}

// Without coverage, or with summaries off, nothing changes.
func TestSummaryPlanOff(t *testing.T) {
	src := `datamodel=Authentication | stats count by src`
	q, _ := query.Parse(src)
	e := summaryEngine()
	e.SetDefaults("-24h", 0, 0)
	if p, _ := e.Compile(q); len(p.Summaries) > 0 {
		t.Errorf("summary_days 0 still reads summaries")
	}
	if p := compile(t, src); len(p.Summaries) > 0 || strings.Contains(asJSON(p.Body), sumidx.ModelField) {
		t.Errorf("no coverage still reads summaries: %s", asJSON(p.Body))
	}
}

func TestResolveTime(t *testing.T) {
	now := time.Date(2026, 10, 17, 13, 47, 31, 0, time.UTC)
	cases := map[string]string{
		"":                     "2026-10-17T13:47:31Z",
		"now":                  "2026-10-17T13:47:31Z",
		"-24h":                 "2026-10-16T13:47:31Z",
		"-7d@d":                "2026-10-10T00:00:00Z",
		"@d":                   "2026-10-17T00:00:00Z",
		"-1mon@mon":            "2026-09-01T00:00:00Z",
		"-15m@m":               "2026-10-17T13:32:00Z",
		"+1h":                  "2026-10-17T14:47:31Z",
		"2026-10-01T00:00:00Z": "2026-10-01T00:00:00Z",
		"1760000000000":        "2025-10-09T08:53:20Z",
	}
	for in, want := range cases {
		got, ok := resolveTime(in, now)
		if !ok || got.Format(time.RFC3339) != want {
			t.Errorf("resolveTime(%q) = %v %v, want %s", in, got, ok, want)
		}
	}
	if got, ok := resolveTime("0", now); !ok || !got.IsZero() {
		t.Errorf("resolveTime(0) = %v %v", got, ok)
	}
	for _, bad := range []string{"-7d@w", "yesterday", "-x"} {
		if _, ok := resolveTime(bad, now); ok {
			t.Errorf("resolveTime(%q) is ok", bad)
		}
	}
}

func TestWholeSlots(t *testing.T) {
	for span, want := range map[string]bool{"5m": true, "10m": true, "1h": true, "1d": true, "1mon": true, "1m": false, "30s": false, "7m": false, "1w": true} {
		if got := wholeSlots(span); got != want {
			t.Errorf("wholeSlots(%s) = %v", span, got)
		}
	}
}
