package sigmacheck

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/jrsamsanchez/signalith/internal/ingest"
	"github.com/jrsamsanchez/signalith/internal/query"
	"github.com/jrsamsanchez/signalith/internal/search"
)

// Windows channels the test events come from.
const (
	SysmonChannel   = "Microsoft-Windows-Sysmon/Operational"
	SecurityChannel = "Security"
)

// TestFile holds a shipped rule's test events.
type TestFile struct {
	// Rule is the Sigma rule's id.
	Rule  string `json:"rule"`
	Cases []Case `json:"cases"`
}

// Case is one Windows event and whether the rule must match it.
type Case struct {
	Expect bool `json:"expect"`
	// Source is "synthesized" (made from the rule) or "sigmahq" (a real
	// event from SigmaHQ's regression data).
	Source  string            `json:"source"`
	Channel string            `json:"channel"`
	EventID string            `json:"event_id"`
	Data    map[string]string `json:"data"`
}

// Security 4688 data names and the Sigma process_creation fields they
// carry. User is left out: 4688 names the account without its domain.
var security4688 = map[string]string{
	"NewProcessName":    "Image",
	"CommandLine":       "CommandLine",
	"ParentProcessName": "ParentImage",
}

// SigmaView returns the case's event as Sigma field names, or false when
// the event's channel has no Sigma view here.
func (c Case) SigmaView() (map[string]string, bool) {
	switch {
	case strings.EqualFold(c.Channel, SysmonChannel):
		return c.Data, true
	case c.Channel == SecurityChannel && c.EventID == "4688":
		out := map[string]string{}
		for raw, sig := range security4688 {
			if v, ok := c.Data[raw]; ok {
				out[sig] = v
			}
		}
		return out, true
	}
	return nil, false
}

// Logsource event IDs: the Sysmon event a Sigma log source category is.
var sysmonEvents = map[string]string{
	"process_creation":   "1",
	"network_connection": "3",
}

// Bases are the fields a typical event of each log source has, for
// Synthesize: neutral values that the rule's own values override.
var Bases = map[string]map[string]string{
	"process_creation": {
		"User":              `CORP\tester`,
		"ProcessId":         "4242",
		"ParentProcessId":   "4100",
		"ParentImage":       `D:\apps\launcher\launcher.exe`,
		"ParentCommandLine": `"D:\apps\launcher\launcher.exe" --run`,
		"CurrentDirectory":  `D:\apps\work\`,
		"IntegrityLevel":    "Medium",
	},
	"network_connection": {
		"User":            `CORP\tester`,
		"ProcessId":       "4242",
		"Protocol":        "tcp",
		"Initiated":       "true",
		"SourceIp":        "192.0.2.10",
		"SourcePort":      "50123",
		"DestinationIp":   "198.51.100.20",
		"DestinationPort": "8443",
	},
}

// SysmonEventID returns the Sysmon event ID of a log source category.
func SysmonEventID(category string) (string, bool) {
	id, ok := sysmonEvents[category]
	return id, ok
}

// Cases turns synthesized events into test cases: each as a Sysmon event,
// and process creations whose fields Security 4688 also carries as a
// 4688 event too.
func Cases(category string, syn *Synthesis, fields []string) []Case {
	id, ok := sysmonEvents[category]
	if !ok {
		return nil
	}
	also4688 := category == "process_creation"
	for _, f := range fields {
		found := false
		for _, sig := range security4688 {
			if sig == f {
				found = true
			}
		}
		if !found {
			also4688 = false
		}
	}
	var out []Case
	add := func(expect bool, ev map[string]string) {
		out = append(out, Case{Expect: expect, Source: "synthesized", Channel: SysmonChannel, EventID: id, Data: ev})
		if also4688 {
			data := map[string]string{"SubjectUserName": "tester", "SubjectDomainName": "CORP"}
			for raw, sig := range security4688 {
				if v, ok := ev[sig]; ok {
					data[raw] = v
				}
			}
			out = append(out, Case{Expect: expect, Source: "synthesized", Channel: SecurityChannel, EventID: "4688", Data: data})
		}
	}
	for _, ev := range syn.Positive {
		add(true, ev)
	}
	for _, ev := range syn.Negative {
		add(false, ev)
	}
	return out
}

// Verify checks a converted detection filter against a rule's test
// events. Each event must be read the same way by the Sigma rule (Match)
// and, after the real Windows parser, by the filter (search.MatchDoc), and
// land in the detection's data model. It returns every disagreement.
func Verify(rule *Rule, datamodel string, filter query.Expr, tf *TestFile) []error {
	var errs []error
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	for i, c := range tf.Cases {
		where := fmt.Sprintf("case %d (%s %s %s, expect %v)", i, c.Source, c.Channel, c.EventID, c.Expect)
		view, ok := c.SigmaView()
		if !ok {
			errs = append(errs, fmt.Errorf("%s: no Sigma view of this channel", where))
			continue
		}
		if m, err := rule.Match(view); err != nil {
			errs = append(errs, fmt.Errorf("%s: Sigma: %v", where, err))
			continue
		} else if m != c.Expect {
			errs = append(errs, fmt.Errorf("%s: the Sigma rule says %v for %s", where, m, String(view)))
			continue
		}
		rec := ingest.WinEventRecord(c.Channel, c.EventID, "test-host", now, c.Data)
		ev := ingest.Normalize("win.events", rec, now)
		if datamodel != "" && !strings.EqualFold(ev.Model, datamodel) {
			errs = append(errs, fmt.Errorf("%s: the parser put the event in %s, not %s", where, ev.Model, datamodel))
			continue
		}
		m, err := search.MatchDoc(filter, ev.Document())
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %v", where, err))
			continue
		}
		if m != c.Expect {
			errs = append(errs, fmt.Errorf("%s: the detection says %v for %s", where, m, String(c.Data)))
		}
	}
	return errs
}

// EncodeTestFile writes a test file as JSON with one case per line, which
// keeps the files small and their diffs readable.
func EncodeTestFile(tf *TestFile) ([]byte, error) {
	var b bytes.Buffer
	rule, err := json.Marshal(tf.Rule)
	if err != nil {
		return nil, err
	}
	b.WriteString(`{"rule": ` + string(rule) + `, "cases": [`)
	for i, c := range tf.Cases {
		line, err := json.Marshal(c)
		if err != nil {
			return nil, err
		}
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString("\n  ")
		b.Write(line)
	}
	b.WriteString("\n]}\n")
	return b.Bytes(), nil
}

// DecodeTestFile reads a test file.
func DecodeTestFile(data []byte) (*TestFile, error) {
	var tf TestFile
	if err := json.Unmarshal(data, &tf); err != nil {
		return nil, err
	}
	return &tf, nil
}
