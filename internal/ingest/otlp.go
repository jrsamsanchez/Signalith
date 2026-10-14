package ingest

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"time"
)

// OpenTelemetry logs arrive over OTLP/HTTP (POST /api/otlp/v1/logs) as an
// ExportLogsServiceRequest, in protobuf (what the Collector's otlphttp
// exporter sends) or JSON. Each log record comes with the resource that
// sent it (host.name, service.name, ...) and its instrumentation scope.
//
// Records from the Collector's own receivers for the sources Signalith
// already parses are mapped like the agent's records, so the built-in
// detections fire whichever agent collects them:
//
//   - windowseventlog: the body is a map with channel, event_id, computer
//     and event_data; it goes through the Windows parser.
//   - journald: the body is the journal entry (MESSAGE, _HOSTNAME, ...).
//   - syslog: the attributes hold appname, hostname, proc_id and message.
//   - filelog on syslog-format files (auth.log, secure): the body is the
//     line.
//
// Any other record is an Other event with its body as the message, its
// attributes and resource attributes as fields (dots become underscores,
// and common semantic-convention names map onto Signalith's field names)
// and its severity, service and trace context.

// otlpLog is one log record with the resource and scope it came in.
type otlpLog struct {
	resource  map[string]any
	scope     string
	time      uint64 // Unix nanoseconds; 0 when unset
	observed  uint64
	sevNum    int64
	sevText   string
	body      any // string, bool, int64, float64, []any or map[string]any
	attrs     map[string]any
	traceID   string // lower-case hex
	spanID    string
	eventName string
}

// IngestOTLP writes the log records of an OTLP/HTTP logs request body:
// protobuf, or JSON when isJSON. The whole body is checked first, as in
// IngestBody, so a refused request (a *BodyError) writes nothing.
func (p *Pipeline) IngestOTLP(ctx context.Context, body []byte, isJSON bool) (*Result, error) {
	walk := walkOTLPProto
	if isJSON {
		walk = walkOTLPJSON
	}
	n := 0
	if err := walk(body, false, func(*otlpLog, int) error {
		n++
		if n > MaxRecords {
			return tooLarge("the request has more than %d log records; send smaller batches (send_batch_max_size in the Collector's batch processor)", MaxRecords)
		}
		return nil
	}); err != nil {
		return nil, err
	}
	p.stats.Received.Add(int64(n))
	p.stats.LastSeen.Store(p.now().Unix())
	total := &Result{Received: n}
	if n == 0 {
		return total, nil
	}
	batch := make([]Event, 0, min(n, batchEvents))
	size, done := 0, 0
	flush := func() error {
		res, err := p.write(ctx, batch, nil)
		done += len(batch)
		clear(batch)
		batch, size = batch[:0], 0
		if err != nil {
			p.stats.Failed.Add(int64(n - done))
			return err
		}
		total.add(res)
		return nil
	}
	err := walk(body, true, func(l *otlpLog, rawSize int) error {
		batch = append(batch, otlpEvent(l, p.now()))
		total.noteHost(&batch[len(batch)-1])
		size += rawSize
		if len(batch) >= batchEvents || size >= batchBytes {
			return flush()
		}
		return nil
	})
	if err != nil {
		if _, bad := err.(*BodyError); bad {
			// The first pass read the same body without error.
			p.stats.Failed.Add(int64(n - done))
		}
		return nil, err
	}
	if len(batch) > 0 {
		if err := flush(); err != nil {
			return nil, err
		}
	}
	return total, nil
}

// otlpEvent maps one OTLP log record to an event.
func otlpEvent(l *otlpLog, now time.Time) Event {
	host, _ := l.resource["host.name"].(string)
	service, _ := l.resource["service.name"].(string)
	bodyMap, _ := l.body.(map[string]any)
	bodyText, _ := l.body.(string)

	var ev Event
	generic := false
	switch {
	case bodyMap != nil && has(bodyMap, "event_id") && has(bodyMap, "channel"):
		ev = otlpWindows(bodyMap)
	case bodyMap != nil && has(bodyMap, "MESSAGE"):
		ev = parseJournal(bodyMap)
	case has(l.attrs, "appname") && has(l.attrs, "message"):
		// The Collector's syslog receiver.
		h := str(l.attrs, "hostname")
		if h == "" {
			h = host
		}
		ev = ParseProgram(h, str(l.attrs, "appname"), str(l.attrs, "proc_id"), str(l.attrs, "message"), "syslog")
		if bodyText == "" {
			bodyText = str(l.attrs, "message")
		}
		ev.Fields["message"] = bodyText
	case bodyText != "" && syslogLine.MatchString(bodyText):
		ev = parseSyslogLine(bodyText, otlpFileSourcetype(l.attrs), now)
	default:
		generic = true
		ev = otlpGeneric(l)
	}
	if ev.Fields == nil {
		ev.Fields = map[string]any{}
	}
	f := ev.Fields
	if s, _ := f["host"].(string); s == "" && host != "" {
		f["host"] = host
	}
	if service != "" {
		f["service"] = service
	}
	if l.sevText != "" {
		f["severity"] = l.sevText
	} else if name := otlpSeverityName(l.sevNum); name != "" && generic {
		f["severity"] = name
	}
	if l.sevNum > 0 && generic {
		f["severity_id"] = l.sevNum
	}
	if l.traceID != "" {
		f["trace_id"] = l.traceID
	}
	if l.spanID != "" {
		f["span_id"] = l.spanID
	}
	if _, ok := f["message"].(string); !ok {
		f["message"] = otlpText(l.body)
	}
	// The record's own time when it has one, else what the parser read
	// from the log line, else when the Collector saw it.
	switch {
	case l.time > 0:
		ev.Time = otlpTime(l.time)
	case !ev.Time.IsZero():
	case l.observed > 0:
		ev.Time = otlpTime(l.observed)
	default:
		ev.Time = now.UTC()
	}
	if ev.Model == "" {
		ev.Model = "Other"
	}
	return ev
}

func otlpTime(ns uint64) time.Time {
	if ns > 1<<63-1 {
		ns = 1<<63 - 1
	}
	return time.Unix(0, int64(ns)).UTC()
}

// otlpFileSourcetype is the sourcetype of a syslog-format line from the
// Collector's filelog receiver: linux:auth for auth.log and secure, as
// the agent's.
func otlpFileSourcetype(attrs map[string]any) string {
	name := str(attrs, "log.file.name")
	if name == "" {
		name = baseName(str(attrs, "log.file.path"))
	}
	switch name {
	case "auth.log", "secure":
		return "linux:auth"
	}
	return "syslog"
}

// otlpSemconv maps OpenTelemetry semantic-convention attribute names onto
// the field names Signalith's data models and detections use.
var otlpSemconv = map[string]string{
	"user.name":                 "user",
	"enduser.id":                "user",
	"client.address":            "src",
	"source.address":            "src",
	"client.port":               "src_port",
	"source.port":               "src_port",
	"server.address":            "dest",
	"destination.address":       "dest",
	"server.port":               "dest_port",
	"destination.port":          "dest_port",
	"network.transport":         "transport",
	"http.request.method":       "http_method",
	"http.response.status_code": "status",
	"url.full":                  "url",
	"user_agent.original":       "http_user_agent",
	"process.pid":               "process_id",
	"process.executable.path":   "process_path",
	"process.command_line":      "process",
	"file.path":                 "file_path",
	"file.name":                 "file_name",
}

// otlpGeneric is an Other event: the body as the message (a map body's
// keys also as fields), and the attributes and resource attributes as
// fields.
func otlpGeneric(l *otlpLog) Event {
	f := map[string]any{"sourcetype": "otel"}
	if l.scope != "" {
		f["otel_scope"] = l.scope
	}
	if l.eventName != "" {
		f["signature"] = l.eventName
	}
	set := func(k string, v any, keep bool) {
		if name, ok := otlpSemconv[k]; ok {
			k = name
		} else {
			k = strings.ReplaceAll(k, ".", "_")
		}
		if _, taken := f[k]; taken && keep {
			return
		}
		f[k] = otlpFieldValue(v)
	}
	// The record's own attributes win over its body's keys, and both over
	// the resource's.
	for k, v := range l.attrs {
		set(k, v, false)
	}
	if m, ok := l.body.(map[string]any); ok {
		for k, v := range m {
			set(k, v, true)
		}
	}
	for k, v := range l.resource {
		if k == "host.name" || k == "service.name" {
			continue
		}
		set(k, v, true)
	}
	if p, ok := f["process_path"].(string); ok && !has(f, "process_name") {
		f["process_name"] = baseName(p)
	}
	f["message"] = otlpText(l.body)
	return Event{Model: "Other", Fields: f}
}

// otlpFieldValue keeps scalars and turns arrays and maps into JSON text.
func otlpFieldValue(v any) any {
	switch v.(type) {
	case map[string]any, []any:
		b, _ := json.Marshal(v)
		return string(b)
	}
	return v
}

// otlpText is a body as message text: a string as it is, anything else
// as JSON.
func otlpText(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return x
	}
	b, _ := json.Marshal(v)
	return string(b)
}

// otlpSeverityName is the short name of an OpenTelemetry severity number.
func otlpSeverityName(n int64) string {
	switch {
	case n >= 1 && n <= 4:
		return "TRACE"
	case n <= 8 && n > 0:
		return "DEBUG"
	case n <= 12 && n > 0:
		return "INFO"
	case n <= 16 && n > 0:
		return "WARN"
	case n <= 20 && n > 0:
		return "ERROR"
	case n <= 24 && n > 0:
		return "FATAL"
	}
	return ""
}

// otlpWindows maps a record from the Collector's windowseventlog receiver
// onto the agent's (Fluent Bit winevtlog) record and parses it.
//
// The receiver writes the event's data as event_data: a map of the named
// values (event_data_format: map, the default in recent versions), or a
// "data" list of one-entry maps in schema order (array, the only format
// in older versions). The Windows parser reads Security events by
// position, so named values are put in schema order with windowsSchema;
// Sysmon events are read from the named values directly.
func otlpWindows(b map[string]any) Event {
	channel := str(b, "channel")
	var eventID string
	switch id := b["event_id"].(type) {
	case map[string]any:
		eventID = str(id, "id")
	default:
		eventID = str(b, "event_id")
	}
	provider := ""
	if p, ok := b["provider"].(map[string]any); ok {
		provider = str(p, "name")
	}
	message := str(b, "message")

	values := map[string]string{}
	var ordered []any
	if ed, ok := b["event_data"].(map[string]any); ok {
		if list, ok := ed["data"].([]any); ok {
			for _, item := range list {
				m, _ := item.(map[string]any)
				for k, v := range m { // one entry
					ordered = append(ordered, otlpText(v))
					if k != "" {
						values[k] = otlpText(v)
					}
				}
			}
		} else {
			for k, v := range ed {
				if k == "name" || k == "binary" {
					continue
				}
				values[k] = otlpText(v)
			}
		}
	}
	if ordered == nil {
		if schema, ok := windowsSchemaFor(channel, eventID); ok {
			for _, name := range schema {
				ordered = append(ordered, values[name])
			}
		}
	}
	rec := map[string]any{
		"Channel":       channel,
		"Computer":      str(b, "computer"),
		"EventID":       eventID,
		"ProviderName":  provider,
		"TimeCreated":   str(b, "system_time"),
		"Message":       message,
		"StringInserts": ordered,
	}
	var named map[string]string
	if strings.EqualFold(channel, "Microsoft-Windows-Sysmon/Operational") {
		named = values
	}
	ev := parseWindowsWith(rec, named)
	if message != "" {
		ev.Fields["message"] = message
	} else {
		ev.Fields["message"] = otlpText(b)
	}
	return ev
}

// windowsSchemaFor returns the schema order of a channel's event, for the
// events the Windows parser reads by position.
func windowsSchemaFor(channel, eventID string) ([]string, bool) {
	switch {
	case channel == "Security":
		s, ok := windowsSchema[eventID]
		return s, ok
	case strings.EqualFold(channel, PowerShellChannel) && eventID == "4104":
		return scriptBlockSchema, true
	}
	return nil, false
}

// scriptBlockSchema is the order of PowerShell's script block event
// (4104): one part of a script that may be split over several events.
var scriptBlockSchema = []string{"MessageNumber", "MessageTotal", "ScriptBlockText", "ScriptBlockId", "Path"}

// windowsSchema lists, for the Security events the Windows parser reads,
// the names of the event's data values in schema order, up to the last
// one it reads.
var windowsSchema = map[string][]string{
	"4624": {"SubjectUserSid", "SubjectUserName", "SubjectDomainName", "SubjectLogonId", "TargetUserSid", "TargetUserName",
		"TargetDomainName", "TargetLogonId", "LogonType", "LogonProcessName", "AuthenticationPackageName", "WorkstationName",
		"LogonGuid", "TransmittedServices", "LmPackageName", "KeyLength", "ProcessId", "ProcessName", "IpAddress", "IpPort"},
	"4625": {"SubjectUserSid", "SubjectUserName", "SubjectDomainName", "SubjectLogonId", "TargetUserSid", "TargetUserName",
		"TargetDomainName", "Status", "FailureReason", "SubStatus", "LogonType", "LogonProcessName", "AuthenticationPackageName",
		"WorkstationName", "TransmittedServices", "LmPackageName", "KeyLength", "ProcessId", "ProcessName", "IpAddress", "IpPort"},
	"4688": {"SubjectUserSid", "SubjectUserName", "SubjectDomainName", "SubjectLogonId", "NewProcessId", "NewProcessName",
		"TokenElevationType", "ProcessId", "CommandLine", "TargetUserSid", "TargetUserName", "TargetDomainName", "TargetLogonId",
		"ParentProcessName"},
	"4663": {"SubjectUserSid", "SubjectUserName", "SubjectDomainName", "SubjectLogonId", "ObjectServer", "ObjectType",
		"ObjectName", "HandleId", "AccessList", "AccessMask", "ProcessId", "ProcessName"},
	"4698": {"SubjectUserSid", "SubjectUserName", "SubjectDomainName", "SubjectLogonId", "TaskName", "TaskContent"},
	"4720": {"TargetUserName", "TargetDomainName", "TargetSid", "SubjectUserSid", "SubjectUserName"},
	"4726": {"TargetUserName", "TargetDomainName", "TargetSid", "SubjectUserSid", "SubjectUserName"},
	"4728": {"MemberName", "MemberSid", "TargetUserName", "TargetDomainName", "TargetSid", "SubjectUserSid", "SubjectUserName"},
	"4732": {"MemberName", "MemberSid", "TargetUserName", "TargetDomainName", "TargetSid", "SubjectUserSid", "SubjectUserName"},
	"4756": {"MemberName", "MemberSid", "TargetUserName", "TargetDomainName", "TargetSid", "SubjectUserSid", "SubjectUserName"},
}

// hexID is an OTLP trace or span ID as lower-case hex, or "" when it is
// empty or all zeros (not set).
func hexID(b []byte) string {
	zero := true
	for _, c := range b {
		if c != 0 {
			zero = false
			break
		}
	}
	if zero {
		return ""
	}
	const digits = "0123456789abcdef"
	out := make([]byte, 2*len(b))
	for i, c := range b {
		out[2*i], out[2*i+1] = digits[c>>4], digits[c&15]
	}
	return string(out)
}

// otlpInt reads an OTLP JSON int64, which is written as a string but may
// arrive as a number.
func otlpInt(raw json.RawMessage) (int64, bool) {
	s := strings.Trim(string(raw), `"`)
	if n, err := strconv.ParseInt(s, 10, 64); err == nil {
		return n, true
	}
	if f, err := strconv.ParseFloat(s, 64); err == nil && f == float64(int64(f)) {
		return int64(f), true
	}
	return 0, false
}
