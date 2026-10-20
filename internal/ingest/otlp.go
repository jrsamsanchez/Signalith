// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package ingest

import (
	"cmp"
	"context"
	"encoding/json"
	"maps"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jrsamsanchez/signalith/internal/store"
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
// IngestBody, so a refused request (a *BodyError) writes nothing. A record
// that is too large, nests too deeply or doesn't decode is rejected on its
// own (Result.Rejected, which the handler reports as OTLP partialSuccess),
// so it doesn't make the sender drop the rest of its batch.
func (p *Pipeline) IngestOTLP(ctx context.Context, body []byte, isJSON bool) (*Result, error) {
	walk := walkOTLPProto
	if isJSON {
		walk = walkOTLPJSON
	}
	n := 0
	if err := walk(body, false, func(*otlpLog, int, *BodyError) error {
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
	ids := make([]string, 0, cap(batch))
	seed := bodySeed("otlp", body)
	size, done, pos := 0, 0, 0
	flush := func() error {
		res, err := p.write(ctx, batch, ids)
		done += len(batch)
		clear(batch)
		batch, ids, size = batch[:0], ids[:0], 0
		if err != nil {
			p.stats.Failed.Add(int64(n - done))
			return err
		}
		total.add(res)
		return nil
	}
	err := walk(body, true, func(l *otlpLog, rawSize int, bad *BodyError) error {
		// The record's place in the request gives its events their
		// document IDs, so a request the Collector sends again (after a
		// 503, or an answer it never got) is counted as duplicates instead
		// of being stored twice.
		pos++
		if bad != nil {
			done++
			p.stats.Failed.Add(1)
			total.add(&Result{Rejected: 1, Errors: []store.BulkItemError{{Reason: bad.Msg}}})
			return nil
		}
		evs := otlpEvents(l, p.now())
		if extra := len(evs) - 1; extra > 0 {
			// An Event Hub message's records count as received one by one.
			n += extra
			total.Received += extra
			p.stats.Received.Add(int64(extra))
		}
		// Each event takes its share of the record's size, and the batch
		// is written as soon as it is full, so a message split into many
		// records can't make an oversized bulk request.
		share := max(rawSize/max(len(evs), 1), 1)
		for i, ev := range evs {
			batch = append(batch, ev)
			ids = append(ids, subRecordID(seed, pos-1, i))
			total.noteHost(&batch[len(batch)-1])
			size += share
			if len(batch) >= batchEvents || size >= batchBytes {
				if err := flush(); err != nil {
					return err
				}
			}
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

// otlpEvents maps one OTLP log record to its events: one, each record of
// an Azure Event Hub message, the Google Cloud log entry of a Pub/Sub
// message, or each Okta System Log, Kubernetes audit or GitHub audit log event of a body
// that holds them.
func otlpEvents(l *otlpLog, now time.Time) []Event {
	parse := ParseAzure
	recs := azureFromOTLP(l.body)
	if recs == nil {
		if r := gcpFromOTLP(l.body); r != nil {
			parse, recs = ParseGCP, []map[string]any{r}
		}
	}
	if recs == nil {
		if rs := oktaFromOTLP(l.body); rs != nil {
			parse, recs = ParseOkta, rs
		}
	}
	if recs == nil {
		if rs := kubernetesFromOTLP(l.body); rs != nil {
			parse, recs = ParseKubernetes, rs
		}
	}
	if recs == nil {
		if rs := githubFromOTLP(l.body); rs != nil {
			parse, recs = ParseGitHub, rs
		}
	}
	if recs == nil {
		return []Event{otlpEvent(l, now)}
	}
	host, _ := l.resource["host.name"].(string)
	out := make([]Event, 0, len(recs))
	for _, r := range recs {
		ev := parse(r)
		if s, _ := ev.Fields["host"].(string); s == "" && host != "" {
			ev.Fields["host"] = host
		}
		// The record's own time, else when Event Hubs or Pub/Sub took the
		// message, or the Collector read it.
		switch {
		case !ev.Time.IsZero():
		case l.time > 0:
			ev.Time = otlpTime(l.time)
		case l.observed > 0:
			ev.Time = otlpTime(l.observed)
		default:
			ev.Time = now.UTC()
		}
		out = append(out, ev)
	}
	return out
}

// otlpEvent maps one OTLP log record to an event.
func otlpEvent(l *otlpLog, now time.Time) Event {
	host, _ := l.resource["host.name"].(string)
	service, _ := l.resource["service.name"].(string)
	bodyMap, _ := l.body.(map[string]any)
	bodyText, _ := l.body.(string)

	var trail map[string]any
	if strings.HasPrefix(bodyText, "{") && strings.Contains(bodyText, `"eventSource"`) {
		trail = cloudTrailText(bodyText)
	}
	var ev Event
	generic := false
	switch {
	case bodyMap != nil && has(bodyMap, "event_id") && has(bodyMap, "channel"):
		ev = otlpWindows(bodyMap)
	case isCloudTrailOTLP(l.attrs):
		// The Collector's aws_s3 receiver on CloudTrail's bucket, with the
		// aws_logs_encoding extension.
		var t time.Time
		if l.time > 0 {
			t = otlpTime(l.time)
		}
		ev = ParseCloudTrail(cloudTrailFromOTLP(l.attrs, l.resource, t))
	case bodyMap != nil && IsCloudTrailRecord(bodyMap):
		ev = ParseCloudTrail(bodyMap)
	case trail != nil:
		// A CloudTrail record as JSON text, as CloudWatch Logs passes it on.
		ev = ParseCloudTrail(trail)
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
	case bodyText != "" && isWebAccessFile(l.attrs):
		// The Collector's filelog receiver on a web server's access log.
		ev = parseWebRecord(map[string]any{"log": bodyText, "file": cmp.Or(str(l.attrs, "log.file.path"), str(l.attrs, "log.file.name")), "hostname": host})
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

// isWebAccessFile reports whether a filelog record is from a web server's
// access log (access.log, other_vhosts_access.log, access_log).
func isWebAccessFile(attrs map[string]any) bool {
	name := str(attrs, "log.file.name")
	if name == "" {
		name = baseName(str(attrs, "log.file.path"))
	}
	return strings.Contains(strings.ToLower(name), "access")
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
// Sysmon and Defender events are read from the named values directly.
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
	binary := ""
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
				if k == "binary" {
					binary = otlpText(v)
				}
				if k == "name" || k == "binary" {
					continue
				}
				values[k] = otlpText(v)
			}
		}
	}
	if ordered == nil {
		if schema, ok := windowsSchemaFor(channel, provider, eventID); ok {
			for _, name := range schema {
				ordered = append(ordered, values[name])
			}
		} else if channel == ApplicationChannel || strings.EqualFold(channel, CodeIntegrityChannel) ||
			strings.EqualFold(channel, WindowsPowerShellChannel) {
			// An Application, Code Integrity or Windows PowerShell
			// event's data is searched as a whole, so its values go in
			// by name.
			for _, k := range slices.Sorted(maps.Keys(values)) {
				ordered = append(ordered, values[k])
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
	if binary != "" {
		rec["Binary"] = binary
	}
	var named map[string]string
	if strings.EqualFold(channel, "Microsoft-Windows-Sysmon/Operational") || strings.EqualFold(channel, DefenderChannel) {
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

// windowsSchemaFor returns the schema order of a channel's event (from
// provider, "" for the channel's usual one), for the events the Windows
// parser reads by position.
func windowsSchemaFor(channel, provider, eventID string) ([]string, bool) {
	switch {
	case channel == "Security":
		if s, ok := windowsSchema[eventID]; ok {
			return s, true
		}
		e, ok := namedChannelEvent(channel, eventID)
		return e.data, ok
	case channel == SystemChannel && eventID == "7045" && (provider == "" || strings.EqualFold(provider, ServiceControlManager)):
		return serviceInstallSchema, true
	case channel == SystemChannel:
		e, ok := systemEventFor(provider, eventID)
		return e.data, ok
	case strings.EqualFold(channel, PowerShellChannel) && eventID == "4104":
		return scriptBlockSchema, true
	case strings.EqualFold(channel, PowerShellChannel) && eventID == "4103":
		return moduleLogSchema, true
	case IsNamedChannel(channel):
		e, ok := namedChannelEvent(channel, eventID)
		return e.data, ok
	}
	return nil, false
}

// scriptBlockSchema is the order of PowerShell's script block event
// (4104): one part of a script that may be split over several events.
var scriptBlockSchema = []string{"MessageNumber", "MessageTotal", "ScriptBlockText", "ScriptBlockId", "Path"}

// serviceInstallSchema is the order of the Service Control Manager's
// service installed event (System 7045).
var serviceInstallSchema = []string{"ServiceName", "ImagePath", "ServiceType", "StartType", "AccountName"}

// windowsSchema lists, for the Security events the Windows parser reads,
// the names of the event's data values in schema order, up to the last
// one it reads.
var windowsSchema = map[string][]string{
	"4624": {"SubjectUserSid", "SubjectUserName", "SubjectDomainName", "SubjectLogonId", "TargetUserSid", "TargetUserName",
		"TargetDomainName", "TargetLogonId", "LogonType", "LogonProcessName", "AuthenticationPackageName", "WorkstationName",
		"LogonGuid", "TransmittedServices", "LmPackageName", "KeyLength", "ProcessId", "ProcessName", "IpAddress", "IpPort",
		"ImpersonationLevel", "RestrictedAdminMode", "TargetOutboundUserName", "TargetOutboundDomainName", "VirtualAccount",
		"TargetLinkedLogonId", "ElevatedToken"},
	"4625": {"SubjectUserSid", "SubjectUserName", "SubjectDomainName", "SubjectLogonId", "TargetUserSid", "TargetUserName",
		"TargetDomainName", "Status", "FailureReason", "SubStatus", "LogonType", "LogonProcessName", "AuthenticationPackageName",
		"WorkstationName", "TransmittedServices", "LmPackageName", "KeyLength", "ProcessId", "ProcessName", "IpAddress", "IpPort"},
	"4688": {"SubjectUserSid", "SubjectUserName", "SubjectDomainName", "SubjectLogonId", "NewProcessId", "NewProcessName",
		"TokenElevationType", "ProcessId", "CommandLine", "TargetUserSid", "TargetUserName", "TargetDomainName", "TargetLogonId",
		"ParentProcessName"},
	"4663": {"SubjectUserSid", "SubjectUserName", "SubjectDomainName", "SubjectLogonId", "ObjectServer", "ObjectType",
		"ObjectName", "HandleId", "AccessList", "AccessMask", "ProcessId", "ProcessName"},
	"4648": {"SubjectUserSid", "SubjectUserName", "SubjectDomainName", "SubjectLogonId", "LogonGuid", "TargetUserName",
		"TargetDomainName", "TargetLogonGuid", "TargetServerName", "TargetInfo", "ProcessId", "ProcessName", "IpAddress", "IpPort"},
	"5156": {"ProcessID", "Application", "Direction", "SourceAddress", "SourcePort", "DestAddress", "DestPort", "Protocol",
		"FilterRTID", "LayerName", "LayerRTID"},
	"5157": {"ProcessID", "Application", "Direction", "SourceAddress", "SourcePort", "DestAddress", "DestPort", "Protocol",
		"FilterRTID", "LayerName", "LayerRTID"},
	"4656": {"SubjectUserSid", "SubjectUserName", "SubjectDomainName", "SubjectLogonId", "ObjectServer", "ObjectType",
		"ObjectName", "HandleId", "TransactionId", "AccessList", "AccessReason", "AccessMask", "PrivilegeList",
		"RestrictedSidCount", "ProcessId", "ProcessName"},
	"4657": {"SubjectUserSid", "SubjectUserName", "SubjectDomainName", "SubjectLogonId", "ObjectName", "ObjectValueName",
		"HandleId", "OperationType", "OldValueType", "OldValue", "NewValueType", "NewValue", "ProcessId", "ProcessName"},
	"4661": {"SubjectUserSid", "SubjectUserName", "SubjectDomainName", "SubjectLogonId", "ObjectServer", "ObjectType",
		"ObjectName", "HandleId", "TransactionId", "AccessList", "AccessMask", "PrivilegeList", "Properties",
		"RestrictedSidCount", "ProcessId", "ProcessName"},
	"4662": {"SubjectUserSid", "SubjectUserName", "SubjectDomainName", "SubjectLogonId", "ObjectServer", "ObjectType",
		"ObjectName", "OperationType", "HandleId", "AccessList", "AccessMask", "Properties"},
	"4768": {"TargetUserName", "TargetDomainName", "TargetSid", "ServiceName", "ServiceSid", "TicketOptions", "Status",
		"TicketEncryptionType", "PreAuthType", "IpAddress", "IpPort", "CertIssuerName", "CertSerialNumber", "CertThumbprint"},
	"4769": {"TargetUserName", "TargetDomainName", "ServiceName", "ServiceSid", "TicketOptions", "TicketEncryptionType",
		"IpAddress", "IpPort", "Status"},
	"4698": {"SubjectUserSid", "SubjectUserName", "SubjectDomainName", "SubjectLogonId", "TaskName", "TaskContent"},
	"5136": {"OpCorrelationID", "AppCorrelationID", "SubjectUserSid", "SubjectUserName", "SubjectDomainName", "SubjectLogonId",
		"DSName", "DSType", "ObjectDN", "ObjectGUID", "ObjectClass", "AttributeLDAPDisplayName", "AttributeSyntaxOID",
		"AttributeValue", "OperationType"},
	"5145": {"SubjectUserSid", "SubjectUserName", "SubjectDomainName", "SubjectLogonId", "ObjectType", "IpAddress", "IpPort",
		"ShareName", "ShareLocalPath", "RelativeTargetName", "AccessMask", "AccessList"},
	"4719": {"SubjectUserSid", "SubjectUserName", "SubjectDomainName", "SubjectLogonId", "CategoryId", "SubcategoryId",
		"SubcategoryGuid", "AuditPolicyChanges"},
	"4706": {"DomainName", "DomainSid", "TdoType", "TdoDirection", "TdoAttributes", "SidFilteringEnabled", "SubjectUserSid",
		"SubjectUserName", "SubjectDomainName", "SubjectLogonId"},
	"4794": {"SubjectUserSid", "SubjectUserName", "SubjectDomainName", "SubjectLogonId", "Workstation"},
	"4697": {"SubjectUserSid", "SubjectUserName", "SubjectDomainName", "SubjectLogonId", "ServiceName", "ServiceFileName",
		"ServiceType", "ServiceStartType", "ServiceAccount", "ClientProcessStartKey", "ClientProcessId", "ParentProcessId"},
	"4720": {"TargetUserName", "TargetDomainName", "TargetSid", "SubjectUserSid", "SubjectUserName", "SubjectDomainName",
		"SubjectLogonId", "PrivilegeList", "SamAccountName", "DisplayName", "UserPrincipalName", "HomeDirectory",
		"HomePath", "ScriptPath", "ProfilePath", "UserWorkstations", "PasswordLastSet", "AccountExpires",
		"PrimaryGroupId", "AllowedToDelegateTo", "OldUacValue", "NewUacValue", "UserAccountControl",
		"UserParameters", "SidHistory"},
	"4738": {"Dummy", "TargetUserName", "TargetDomainName", "TargetSid", "SubjectUserSid", "SubjectUserName",
		"SubjectDomainName", "SubjectLogonId", "PrivilegeList", "SamAccountName", "DisplayName", "UserPrincipalName",
		"HomeDirectory", "HomePath", "ScriptPath", "ProfilePath", "UserWorkstations", "PasswordLastSet",
		"AccountExpires", "PrimaryGroupId", "AllowedToDelegateTo", "OldUacValue", "NewUacValue",
		"UserAccountControl", "UserParameters", "SidHistory"},
	"4726": {"TargetUserName", "TargetDomainName", "TargetSid", "SubjectUserSid", "SubjectUserName", "SubjectDomainName",
		"SubjectLogonId"},
	"4722": {"TargetUserName", "TargetDomainName", "TargetSid", "SubjectUserSid", "SubjectUserName", "SubjectDomainName",
		"SubjectLogonId"},
	"4723": {"TargetUserName", "TargetDomainName", "TargetSid", "SubjectUserSid", "SubjectUserName", "SubjectDomainName",
		"SubjectLogonId", "PrivilegeList"},
	"4724": {"TargetUserName", "TargetDomainName", "TargetSid", "SubjectUserSid", "SubjectUserName", "SubjectDomainName",
		"SubjectLogonId"},
	"4725": {"TargetUserName", "TargetDomainName", "TargetSid", "SubjectUserSid", "SubjectUserName", "SubjectDomainName",
		"SubjectLogonId"},
	"4728": {"MemberName", "MemberSid", "TargetUserName", "TargetDomainName", "TargetSid", "SubjectUserSid", "SubjectUserName",
		"SubjectDomainName", "SubjectLogonId"},
	"4732": {"MemberName", "MemberSid", "TargetUserName", "TargetDomainName", "TargetSid", "SubjectUserSid", "SubjectUserName",
		"SubjectDomainName", "SubjectLogonId"},
	"4756": {"MemberName", "MemberSid", "TargetUserName", "TargetDomainName", "TargetSid", "SubjectUserSid", "SubjectUserName",
		"SubjectDomainName", "SubjectLogonId"},
	"4729": {"MemberName", "MemberSid", "TargetUserName", "TargetDomainName", "TargetSid", "SubjectUserSid", "SubjectUserName",
		"SubjectDomainName", "SubjectLogonId"},
	"4776": {"PackageName", "TargetUserName", "Workstation", "Status"},
	"4771": {"TargetUserName", "TargetSid", "ServiceName", "TicketOptions", "Status", "PreAuthType", "IpAddress", "IpPort",
		"CertIssuerName", "CertSerialNumber", "CertThumbprint"},
	"4741": {"TargetUserName", "TargetDomainName", "TargetSid", "SubjectUserSid", "SubjectUserName", "SubjectDomainName", "SubjectLogonId",
		"PrivilegeList", "SamAccountName", "DisplayName", "UserPrincipalName", "HomeDirectory",
		"HomePath", "ScriptPath", "ProfilePath", "UserWorkstations", "PasswordLastSet", "AccountExpires",
		"PrimaryGroupId", "AllowedToDelegateTo", "OldUacValue", "NewUacValue", "UserAccountControl",
		"UserParameters", "SidHistory", "LogonHours", "DnsHostName", "ServicePrincipalNames"},
	"4742": {"ComputerAccountChange", "TargetUserName", "TargetDomainName", "TargetSid", "SubjectUserSid", "SubjectUserName", "SubjectDomainName", "SubjectLogonId",
		"PrivilegeList", "SamAccountName", "DisplayName", "UserPrincipalName", "HomeDirectory",
		"HomePath", "ScriptPath", "ProfilePath", "UserWorkstations", "PasswordLastSet", "AccountExpires",
		"PrimaryGroupId", "AllowedToDelegateTo", "OldUacValue", "NewUacValue", "UserAccountControl",
		"UserParameters", "SidHistory", "LogonHours", "DnsHostName", "ServicePrincipalNames"},
	"4781": {"OldTargetUserName", "NewTargetUserName", "TargetDomainName", "TargetSid", "SubjectUserSid", "SubjectUserName", "SubjectDomainName", "SubjectLogonId",
		"PrivilegeList"},
	"4727": {"TargetUserName", "TargetDomainName", "TargetSid", "SubjectUserSid", "SubjectUserName", "SubjectDomainName", "SubjectLogonId", "PrivilegeList",
		"SamAccountName", "SidHistory"},
	"4737": {"TargetUserName", "TargetDomainName", "TargetSid", "SubjectUserSid", "SubjectUserName", "SubjectDomainName", "SubjectLogonId", "PrivilegeList",
		"SamAccountName", "SidHistory"},
	// The other groups created (4731 local, 4744 local distribution, 4749
	// global distribution, 4754 and 4759 universal, 4783 basic
	// application, 4790 LDAP query) have the data of 4727.
	"4731": groupCreatedSchema, "4744": groupCreatedSchema, "4749": groupCreatedSchema, "4754": groupCreatedSchema,
	"4759": groupCreatedSchema, "4783": groupCreatedSchema, "4790": groupCreatedSchema,
	"4730": {"TargetUserName", "TargetDomainName", "TargetSid", "SubjectUserSid", "SubjectUserName", "SubjectDomainName", "SubjectLogonId", "PrivilegeList"},
	"4798": {"TargetUserName", "TargetDomainName", "TargetSid", "SubjectUserSid", "SubjectUserName", "SubjectDomainName", "SubjectLogonId", "CallerProcessId",
		"CallerProcessName"},
	"4799": {"TargetUserName", "TargetDomainName", "TargetSid", "SubjectUserSid", "SubjectUserName", "SubjectDomainName", "SubjectLogonId", "CallerProcessId",
		"CallerProcessName"},
	"4886": {"RequestId", "Requester", "Attributes"},
	"4887": {"RequestId", "Requester", "Attributes", "Disposition", "SubjectKeyIdentifier", "Subject"},
	"1102": {"SubjectUserSid", "SubjectUserName", "SubjectDomainName", "SubjectLogonId"},
	"4699": {"SubjectUserSid", "SubjectUserName", "SubjectDomainName", "SubjectLogonId", "TaskName", "TaskContent"},
	"4701": {"SubjectUserSid", "SubjectUserName", "SubjectDomainName", "SubjectLogonId", "TaskName", "TaskContent"},
	"4702": {"SubjectUserSid", "SubjectUserName", "SubjectDomainName", "SubjectLogonId", "TaskName", "TaskContentNew"},
	"5140": {"SubjectUserSid", "SubjectUserName", "SubjectDomainName", "SubjectLogonId", "ObjectType", "IpAddress", "IpPort", "ShareName",
		"ShareLocalPath", "AccessMask", "AccessList"},
}

// groupCreatedSchema is the data of a group created (4727 and the like).
var groupCreatedSchema = []string{"TargetUserName", "TargetDomainName", "TargetSid", "SubjectUserSid", "SubjectUserName",
	"SubjectDomainName", "SubjectLogonId", "PrivilegeList", "SamAccountName", "SidHistory"}

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

// WindowsSecurityNames returns the names of a Security event's data
// values in schema order, for the events the Windows parser reads (by
// position or by name).
func WindowsSecurityNames(eventID string) []string {
	s, _ := windowsSchemaFor(SecurityChannel, "", eventID)
	return s
}

// WindowsEventNames returns the names of the data values of a System log
// event (of a provider, "" for the Service Control Manager) other than a
// service installed, or of an event of a log the parser reads by name
// (IsNamedChannel), in schema order, with the field each is stored as
// (SystemDataField, ChannelDataField); none for an event the parser does
// not read by name.
func WindowsEventNames(channel, provider, eventID string) (names, fields []string) {
	var s []string
	switch {
	case channel == SystemChannel && eventID != "7045":
		e, _ := systemEventFor(provider, eventID)
		s = e.data
	case IsNamedChannel(channel):
		e, _ := namedChannelEvent(channel, eventID)
		s = e.data
	}
	for _, n := range s {
		f, ok := SystemDataField(n)
		if channel != SystemChannel {
			f, ok = ChannelDataField(channel, n)
		}
		if ok {
			names, fields = append(names, n), append(fields, f)
		}
	}
	return names, fields
}
