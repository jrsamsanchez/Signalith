package syslog

import (
	"net/netip"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jrsamsanchez/signalith/internal/ingest"
)

// maxExtraFields caps the vendor-specific fields (cef_*, leef_* and sd_*) one
// message can add, so one sender cannot explode the index mapping.
const maxExtraFields = 64

// DefaultMaxAge is how old a message's own timestamp may be before the
// receive time is used instead: the same window as every other event (see
// ingest.TimeUsable). Events go to one index per day, so without a bound a
// sender could create an index for every day it names and use up the
// cluster's shard limit, which stops all ingestion.
const DefaultMaxAge = ingest.DefaultMaxEventAge

var facilityNames = [24]string{
	"kern", "user", "mail", "daemon", "auth", "syslog", "lpr", "news",
	"uucp", "cron", "authpriv", "ftp", "ntp", "audit", "alert", "clock",
	"local0", "local1", "local2", "local3", "local4", "local5", "local6", "local7",
}

var severityNames = [8]string{"emergency", "alert", "critical", "error", "warning", "notice", "informational", "debug"}

// Event turns a parsed message into an event for the ingest pipeline.
// sender is the address the message came from and received is when it
// arrived; they fill dvc, host when the message names none, and the time
// when the message has no usable timestamp. A message time older than
// maxAge (zero: DefaultMaxAge) or more than ingest.MaxEventAhead ahead is
// not used for the event time; it is kept in device_time instead.
func (m *Message) Event(sender netip.Addr, received time.Time, maxAge time.Duration) ingest.Event {
	if maxAge <= 0 {
		maxAge = DefaultMaxAge
	}
	senderIP := ""
	if sender.IsValid() {
		senderIP = sender.Unmap().WithZone("").String()
	}
	host := truncate(m.Hostname, maxHostLen)
	app := m.AppName
	if app == "" && m.Cisco != nil {
		app = m.Cisco.Facility
	}
	extra := 0
	wazuh := false
	var ev ingest.Event
	t := m.Time
	// structured is a CEF or LEEF record, mapped by its own keys.
	structured := func(f map[string]any, ct time.Time, rec avRecord) {
		// The record's own time (CEF rt, end or start, LEEF devTime) is
		// more precise than the syslog header, but an implausible one does
		// not replace a good header.
		if !ct.IsZero() && (plausible(ct, received, maxAge) || !plausible(t, received, maxAge)) {
			t = ct
		}
		if host == "" {
			host, _ = f["dvc_host"].(string)
		}
		model := "Other"
		switch {
		case classifyAV(rec, f):
			model = ingest.MalwareModel
		case f["src"] != nil && f["dest"] != nil:
			model = "Network_Traffic"
		}
		ev = ingest.Event{Model: model, Fields: f}
	}
	var rec avRecord
	kf := map[string]any{}
	switch {
	case m.CEF != nil:
		f := map[string]any{"app": app}
		structured(f, cefFieldsFor(m.CEF, f, &extra, received), avFromCEF(m.CEF))
	case m.LEEF != nil:
		f := map[string]any{"app": app}
		structured(f, leefFieldsFor(m.LEEF, f, &extra, received), avFromLEEF(m.LEEF))
	case isWazuh(m.Text, &wazuh, &ev):
		// A Wazuh manager's syslog output (format json): the alert names
		// the host it is about, and has its own time and severity.
		if !ev.Time.IsZero() && (plausible(ev.Time, received, maxAge) || !plausible(t, received, maxAge)) {
			t = ev.Time
		}
		if agent, _ := ev.Fields["host"].(string); agent != "" {
			host = truncate(agent, maxHostLen)
		}
	case esetThreat(m.Text, &rec):
		structured(map[string]any{"app": app, "sourcetype": "eset:protect"}, time.Time{}, rec)
	case kasperskyThreat(m, &rec, kf):
		kf["app"], kf["sourcetype"] = app, "kaspersky:syslog"
		structured(kf, time.Time{}, rec)
	case isEPO(app, m.Text):
		if host == "" {
			host = senderIP
		}
		model, f := parseEPO(m.Text)
		if model != ingest.MalwareModel {
			f["app"] = app
		}
		ev = ingest.Event{Model: model, Fields: f}
	default:
		if host == "" {
			host = senderIP
		}
		if isSEP(app, m.Text) {
			if f, ok := parseSEP(m.Text); ok {
				ev = ingest.Event{Model: ingest.MalwareModel, Fields: f}
				break
			}
		}
		ev = ingest.ParseProgram(host, app, m.ProcID, m.Text, "syslog")
	}
	f := ev.Fields
	if host == "" {
		host = senderIP
	}
	f["host"] = host
	f["dvc"] = senderIP
	// A batch mixes devices, so each event carries its own origin; syslog
	// has no agent token.
	ev.Origin = ingest.Origin{Intake: ingest.IntakeSyslog, Sender: senderIP}
	if m.Priority >= 0 {
		f["facility"] = facilityNames[m.Priority/8]
	}
	// CEF and LEEF carry their own severity, and an antivirus event's
	// severity is the product's rating of the threat, never the syslog
	// priority.
	if m.CEF == nil && m.LEEF == nil && !wazuh && ev.Model != ingest.MalwareModel {
		switch {
		case m.Priority >= 0:
			f["severity"] = severityNames[m.Priority%8]
			f["severity_id"] = int64(m.Priority % 8)
		case m.Cisco != nil:
			f["severity"] = severityNames[m.Cisco.Severity]
			f["severity_id"] = int64(m.Cisco.Severity)
		}
	}
	if m.MsgID != "" {
		f["msgid"] = m.MsgID
	}
	if m.Sequence != "" {
		if n, err := strconv.ParseInt(m.Sequence, 10, 64); err == nil {
			f["sequence"] = n
		}
	}
	if m.Cisco != nil {
		f["signature_id"] = m.Cisco.Facility + "-" + strconv.Itoa(m.Cisco.Severity) + "-" + m.Cisco.Mnemonic
		if f["vendor_product"] == nil {
			f["vendor_product"] = ciscoProduct(m.Cisco.Facility)
		}
	}
	for _, el := range m.Data {
		if el.ID == "timeQuality" {
			continue // about the sender's clock, not the event
		}
		id := fieldName(el.ID)
		for _, p := range el.Params {
			if p.Value != "" {
				addExtra(f, "sd_"+id+"_", p.Name, p.Value, &extra)
			}
		}
	}
	if !wazuh {
		f["message"] = m.Raw // a Wazuh alert keeps its own JSON
	}
	ev.Time = received.UTC()
	if plausible(t, received, maxAge) {
		ev.Time = t.UTC()
	} else if !t.IsZero() {
		ev.DeviceTime = t.UTC()
	}
	return ev
}

func ciscoProduct(facility string) string {
	switch strings.ToUpper(facility) {
	case "ASA", "PIX", "FWSM":
		return "Cisco ASA"
	case "FTD":
		return "Cisco Firepower Threat Defense"
	}
	return "Cisco"
}

// plausible reports whether a message time can be the event time: set, no
// older than maxAge (a clock never set, a replayed or forged message) and
// at most ingest.MaxEventAhead ahead. Keeping event times in this window
// bounds the daily indices syslog can write to.
func plausible(t, received time.Time, maxAge time.Duration) bool {
	return ingest.TimeUsable(t, received, maxAge)
}

// maxHostLen is the longest host name kept, the DNS limit.
const maxHostLen = 255

// truncate cuts s to at most n bytes without splitting a character.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

// isExtra reports whether a field is vendor-specific (cef_*, leef_* or
// sd_*), the kind the receiver limits per day so the index mapping stays
// small.
func isExtra(name string) bool {
	return strings.HasPrefix(name, "cef_") || strings.HasPrefix(name, "leef_") || strings.HasPrefix(name, "sd_")
}

// isWazuh reports whether text is a Wazuh JSON alert, and parses it into ev.
func isWazuh(text string, wazuh *bool, ev *ingest.Event) bool {
	w, ok := ingest.ParseWazuhText(text)
	if ok {
		*wazuh, *ev = true, w
	}
	return ok
}
