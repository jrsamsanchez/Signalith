package sigmacheck

import (
	"encoding/json"
	"maps"
	"strconv"
	"time"

	"github.com/jrsamsanchez/signalith/internal/endpoint"
	"github.com/jrsamsanchez/signalith/internal/ingest"
)

// MacOSChannel is macOS program starts, as osquery reads them from
// EndpointSecurity (es_process_events) for Signalith: each case's data are
// the result row's columns (path, cmdline, parent_path), its event ID
// "exec".
const MacOSChannel = endpoint.ProcessStartSourcetype

// OsqueryTag is the tag Record gives an osquery result line, which reaches
// Signalith through its osquery remote API rather than a log agent: the
// record is the line, with "line" holding its JSON text.
const OsqueryTag = "osquery"

// macOSColumns are the Sigma process_creation fields an osquery program
// start carries, by its result row's columns.
var macOSColumns = map[string]string{
	"Image":             "path",
	"CommandLine":       "cmdline",
	"ParentImage":       "parent_path",
	"ParentCommandLine": "parent_cmdline",
	"User":              "username",
	"CurrentDirectory":  "cwd",
	"ProcessId":         "pid",
	"ParentProcessId":   "parent",
}

// MacOSBases are Bases for macOS rules, as Sigma names the fields of an
// osquery program start.
var MacOSBases = map[string]map[string]string{
	"process_creation": {
		"Image":             "/usr/local/bin/helper",
		"User":              "tester",
		"ProcessId":         "4242",
		"ParentProcessId":   "4100",
		"ParentImage":       "/Applications/Launcher.app/Contents/MacOS/Launcher",
		"ParentCommandLine": "/Applications/Launcher.app/Contents/MacOS/Launcher --run",
		"CurrentDirectory":  "/Users/tester",
	},
}

// MacOSCases are Cases for a macOS rule: each synthesized event as an
// osquery program start. An event with a field osquery does not report is
// left out. osquery always reports the program and its arguments, the
// first of which is the program, so a program the event leaves open is a
// typical one (MacOSBases), and a command line it leaves open the
// program's path; the rule's verdict on the case can then differ from the
// synthesized one, so packgen asks the rule again (Rule.Match of
// SigmaView).
func MacOSCases(category string, syn *Synthesis, _ []string) []Case {
	if category != "process_creation" {
		return nil
	}
	var out []Case
	add := func(expect bool, ev map[string]string) {
		data := map[string]string{}
		for k, v := range ev {
			col, ok := macOSColumns[k]
			if !ok {
				return
			}
			data[col] = v
		}
		if _, ok := data["path"]; !ok {
			data["path"] = MacOSBases["process_creation"]["Image"]
		}
		if _, ok := data["cmdline"]; !ok && data["path"] != "" {
			data["cmdline"] = data["path"]
		}
		if _, ok := data["parent_cmdline"]; !ok && data["parent_path"] != "" {
			data["parent_cmdline"] = data["parent_path"]
		}
		out = append(out, Case{Expect: expect, Source: "synthesized", Channel: MacOSChannel, EventID: "exec", Data: data})
	}
	for _, ev := range syn.Positive {
		add(true, ev)
	}
	for _, ev := range syn.Negative {
		add(false, ev)
	}
	return out
}

// macOSView is an osquery program start's columns as Sigma's fields.
func macOSView(data map[string]string) map[string]string {
	out := map[string]string{}
	for sig, col := range macOSColumns {
		if v, ok := data[col]; ok {
			out[sig] = v
		}
	}
	return out
}

// OsqueryLine is a macOS program start case as osquery's TLS logger sends
// it: one row of Signalith's scheduled query, reported as added.
func OsqueryLine(host string, t time.Time, data map[string]string) json.RawMessage {
	cols := maps.Clone(data)
	if cols == nil {
		cols = map[string]string{}
	}
	cols["time"] = strconv.FormatInt(t.Unix(), 10)
	line, _ := json.Marshal(map[string]any{
		"name": endpoint.ProcessStartQuery, "unixTime": t.Unix(), "action": "added", "columns": cols,
		"decorations": map[string]string{"hostname": host},
	})
	return line
}

// macOSStored is a macOS program start case after the real osquery result
// parser, as a macOS host enrolled with Signalith reports it. A row the
// parser does not read is an event of no data model.
func macOSStored(host string, t time.Time, data map[string]string) ingest.Event {
	n := &endpoint.Node{ID: "test-" + host, Hostname: host, Platform: endpoint.Darwin}
	b := endpoint.ParseResults(n, []json.RawMessage{OsqueryLine(host, t, data)}, t)
	if len(b.Events) == 0 {
		return ingest.Event{Time: t, Fields: map[string]any{"host": host}}
	}
	return b.Events[0]
}
