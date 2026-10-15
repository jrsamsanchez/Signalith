package syslog

import (
	"strings"

	"github.com/jrsamsanchez/signalith/internal/ingest"
)

// Trellix (McAfee) ePolicy Orchestrator forwards events over TLS syslog as
// one XML document per message, from the program EPOEvents. Only a few
// leaf tags are needed, so they are read with a bounded search for each
// <Tag>...</Tag> instead of an XML parser: no nesting, no entities beyond
// the five predefined ones, and never more than the first 64 KB.

const (
	epoMaxText  = 64 << 10
	epoMaxValue = 4 << 10
)

// isEPO reports whether a message is an ePO event.
func isEPO(app, text string) bool {
	// The root is <EPOevent> or <EPOEvent>, depending on the product.
	return strings.EqualFold(app, "EPOEvents") || strings.Contains(strings.ToLower(text[:min(len(text), 1<<10)]), "<epoevent>")
}

var epoUnescape = strings.NewReplacer("&lt;", "<", "&gt;", ">", "&amp;", "&", "&quot;", `"`, "&apos;", "'")

// epoValue returns the text of the first <tag>...</tag> in s.
func epoValue(s, tag string) string {
	open := "<" + tag + ">"
	i := strings.Index(s, open)
	if i < 0 {
		return ""
	}
	s = s[i+len(open):]
	j := strings.Index(s, "</"+tag+">")
	if j < 0 {
		return ""
	}
	return epoClean(s[:j])
}

func epoClean(v string) string {
	if len(v) > epoMaxValue {
		v = v[:epoMaxValue]
	}
	return ingest.CapValue(epoUnescape.Replace(v))
}

// epoAttr returns the value of the first name="..." attribute in s.
func epoAttr(s, name string) string {
	key := " " + name + `="`
	i := strings.Index(s, key)
	if i < 0 {
		return ""
	}
	s = s[i+len(key):]
	j := strings.IndexByte(s, '"')
	if j < 0 {
		return ""
	}
	return epoClean(s[:j])
}

// epoActions maps the ending of ThreatActionTaken resource IDs, such as
// IDS_ALERT_ACT_TAK_DEL.
var epoActions = []struct{ suffix, action string }{
	{"_DEL", "deleted"}, {"_CLE", "cleaned"}, {"_DEN", "blocked"}, {"_BLK", "blocked"}, {"_MOV", "quarantined"}, {"_QUA", "quarantined"},
}

// epoSeverity maps ePO's ThreatSeverity (0 most severe) onto ours.
func epoSeverity(v string) string {
	switch strings.TrimSpace(v) {
	case "0", "1":
		return "critical"
	case "2":
		return "high"
	case "3":
		return "medium"
	case "4", "5", "6":
		return "low"
	}
	return ""
}

// parseEPO maps an ePO event onto the Malware data model (threats and
// failed updates) or, for anything else, Other with the same fields.
func parseEPO(text string) (string, map[string]any) {
	s := truncate(text, epoMaxText)
	f := map[string]any{"sourcetype": "trellix:epo"}
	product := epoAttr(s, "ProductName")
	if product == "" {
		product = "Trellix ePO"
	}
	f["vendor_product"] = product
	sig := epoValue(s, "ThreatName")
	if sig == "_" {
		sig = "" // what Endpoint Security writes for events that name no threat
	}
	actionTaken := epoValue(s, "ThreatActionTaken")
	ingest.SetValue(f, "signature_id", epoValue(s, "EventID"))
	ingest.SetValue(f, "vendor_category", epoValue(s, "ThreatType"))
	if v := epoValue(s, "ThreatSeverity"); v != "" {
		f["vendor_severity"] = v
		if sev := epoSeverity(v); sev != "" {
			f["severity"] = sev
		}
	}
	ingest.SetValue(f, "vendor_action", actionTaken)
	ingest.SetValue(f, "dest", truncate(first(epoValue(s, "TargetHostName"), epoValue(s, "MachineName")), maxHostLen))
	ingest.SetValue(f, "dest_ip", epoValue(s, "IPAddress"))
	ingest.SetValue(f, "user", first(epoValue(s, "TargetUserName"), epoValue(s, "SourceUserName")))
	ingest.SetFilePath(f, epoValue(s, "TargetFileName"))
	ingest.SetFileHash(f, epoValue(s, "TargetHash"))
	ingest.SetProcessPath(f, epoValue(s, "SourceProcessName"))
	ingest.SetValue(f, "src_host", epoValue(s, "SourceHostName"))
	ingest.SetValue(f, "src", epoValue(s, "SourceIPV4"))
	ingest.SetValue(f, "detection_source", epoValue(s, "AnalyzerDetectionMethod"))

	category := strings.ToLower(epoValue(s, "ThreatCategory"))
	switch {
	case strings.HasPrefix(category, "av."):
		action := ""
		upper := strings.ToUpper(actionTaken)
		for _, a := range epoActions {
			if strings.HasSuffix(upper, a.suffix) {
				action = a.action
				break
			}
		}
		if action == "" {
			action = ingest.MalwareAction(actionTaken)
		}
		if strings.EqualFold(epoValue(s, "ThreatHandled"), "false") {
			action = "failed"
		}
		if sig == "" {
			sig = ingest.UnknownThreat
		}
		vc, _ := f["vendor_category"].(string)
		f["type"] = ingest.MalwareThreat
		f["action"] = action
		f["signature"] = sig
		f["category"] = ingest.MalwareCategory(sig, vc)
		return ingest.MalwareModel, f
	// Event 1119 is a failed update; other products say so in the name
	// or action.
	case strings.HasPrefix(category, "ops.update") && (epoValue(s, "EventID") == "1119" ||
		strings.Contains(strings.ToLower(sig), "fail") || strings.Contains(strings.ToLower(actionTaken), "fail")):
		f["type"] = ingest.MalwareHealth
		f["action"] = "update_failed"
		f["signature"] = "Definitions update failed"
		ingest.SetValue(f, "reason", sig)
		return ingest.MalwareModel, f
	}
	ingest.SetValue(f, "signature", sig)
	return "Other", f
}
