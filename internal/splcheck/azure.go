package splcheck

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/jrsamsanchez/signalith/internal/ingest"
	"github.com/jrsamsanchez/signalith/internal/sigmacheck"
)

// AzureNode is the node of Entra ID and Azure records (the
// azure_monitor_aad and azure_monitor_activity macros). A search names no
// event code. Its fields are the record's own (operationName,
// properties.status.errorCode, properties.targetResources{}.type), which
// Signalith keeps by the same names, and the CIM fields Splunk's add-on
// for Microsoft cloud services gives each record, which Signalith sets
// too.
const AzureNode = "Azure"

// azureSources are the Azure macros, with the sourcetype each searches.
var azureSources = map[string]string{
	"azure_monitor_aad":      ingest.AzureADSourcetype,
	"azure_monitor_activity": ingest.AzureActivitySourcetype,
}

// azureCIM are the CIM fields of an Azure record, with the Signalith
// field each is stored as.
var azureCIM = map[string]string{
	"action": "action", "status": "status", "user": "user", "src": "src", "src_ip": "src", "dest": "dest",
	"signature": "signature", "command": "command", "app": "app", "user_agent": "user_agent", "reason": "reason",
	"vendor_account": "vendor_account", "vendor_region": "vendor_region", "vendor_product": "vendor_product",
	"src_user": "src_user", "src_user_type": "src_user_type", "object": "object", "object_category": "object_category",
	"sourcetype": "sourcetype",
}

// cloudSource is a macro of Entra ID, Azure or Microsoft 365 records,
// whose searches may rename fields before stats and search again by the
// new names: its node, the sourcetype it searches, and the stored field
// of a name a stage reads after renames.
type cloudSource struct {
	node, sourcetype string
	field            func(name string, renames []rename) (string, bool)
}

// cloudSourceOf is the cloud source of a macro, or false when it is not
// one.
func cloudSourceOf(source string) (cloudSource, bool) {
	if st, ok := azureSources[source]; ok {
		return cloudSource{AzureNode, st, func(name string, renames []rename) (string, bool) {
			return azureField(azureUnrename(name, renames))
		}}, true
	}
	if source == o365Source {
		return cloudSource{O365Node, ingest.O365Sourcetype, func(name string, renames []rename) (string, bool) {
			return o365Field(o365Unrename(name, renames))
		}}, true
	}
	return cloudSource{}, false
}

// azureField is the stored field of an Azure search's field.
func azureField(name string) (string, bool) {
	if f, ok := azureCIM[name]; ok {
		return f, true
	}
	return name, ingest.AzureField(name)
}

// A rename stage: each old name, or pattern (properties.*), and its new
// one.
type rename struct{ from, to string }

var timeRe = regexp.MustCompile(`(^|[\s,])_time([\s,]|$)`)

var renamePairRe = regexp.MustCompile(`(?i)^\s*("[^"]+"|[^\s,"]+)\s+as\s+("[^"]+"|[^\s,"]+)\s*,?`)

// parseRename reads a rename stage's pairs.
func parseRename(s string) ([]rename, error) {
	s = strings.TrimSpace(renameRe.ReplaceAllString(s, ""))
	var out []rename
	for s != "" {
		m := renamePairRe.FindStringSubmatch(s)
		if m == nil {
			return nil, fmt.Errorf("rename %s is not supported", firstWords(s))
		}
		from, to := strings.Trim(m[1], `"`), strings.Trim(m[2], `"`)
		if strings.Count(from, "*") != strings.Count(to, "*") || strings.Count(from, "*") > 1 {
			return nil, fmt.Errorf("rename %s as %s is not supported", from, to)
		}
		out = append(out, rename{from, to})
		s = strings.TrimSpace(s[len(m[0]):])
	}
	return out, nil
}

// azureUnrename is the field a name a later stage reads had before the
// search's renames. rename properties.* as * renames only what is under
// properties: a CIM field (user) or a record's top-level field keeps its
// name.
func azureUnrename(name string, renames []rename) string {
	for i := len(renames) - 1; i >= 0; i-- {
		r := renames[i]
		pre, suf, wild := strings.Cut(r.to, "*")
		if !wild {
			if name == r.to {
				name = r.from
			}
			continue
		}
		if _, cim := azureCIM[name]; cim || ingest.AzureField(name) && !strings.Contains(name, ".") {
			continue
		}
		if len(name) > len(pre)+len(suf) && strings.HasPrefix(name, pre) && strings.HasSuffix(name, suf) {
			name = strings.Replace(r.from, "*", name[len(pre):len(name)-len(suf)], 1)
		}
	}
	return name
}

// resolveCloud replaces the fields of a stage of a cloud source's search
// after renames with the fields they are stored as.
func resolveCloud(e Expr, renames []rename, cs cloudSource) error {
	switch x := e.(type) {
	case *And:
		for _, k := range x.Kids {
			if err := resolveCloud(k, renames, cs); err != nil {
				return err
			}
		}
	case *Or:
		for _, k := range x.Kids {
			if err := resolveCloud(k, renames, cs); err != nil {
				return err
			}
		}
	case *Not:
		return resolveCloud(x.Kid, renames, cs)
	case *Cmp:
		name, _ := strings.CutPrefix(x.Field, rawFieldPrefix)
		f, ok := cs.field(name, renames)
		if !ok {
			return fmt.Errorf("field %s is not a field of %s events", name, cs.node)
		}
		x.Field = f
		if !x.Regex {
			// Signalith keeps values without the spaces around them, as
			// Entra ID's "Update application – Certificates and secrets
			// management " ends in one.
			for i, v := range x.Values {
				x.Values[i] = strings.TrimSpace(v)
			}
		}
	}
	return nil
}

// cloudThreshold reads the count of a cloud source's search, by the
// fields its renames read.
func cloudThreshold(stats string, span time.Duration, limits []Limit, renames []rename, cs cloudSource) (*Threshold, error) {
	m := statsSplitRe.FindStringSubmatch(stats)
	if m == nil {
		return nil, fmt.Errorf("a count must be by at least one field")
	}
	field := func(f string) (string, bool, error) {
		name, ok := cs.field(f, renames)
		if !ok {
			return "", false, fmt.Errorf("field %s has no Signalith mapping", f)
		}
		// Every record of a sourcetype has the same product.
		return name, name != "vendor_product", nil
	}
	aggs, err := parseAggs(m[1], func(f string) (string, error) {
		name, keep, err := field(f)
		if err == nil && !keep {
			err = fmt.Errorf("a count of %s is not supported", f)
		}
		return name, err
	})
	if err != nil {
		return nil, err
	}
	if spanRe.MatchString(m[2]) {
		return nil, fmt.Errorf("a raw count's span must come from bucket")
	}
	if !timeRe.MatchString(m[2]) {
		// A bucket only splits a count by _time: without it, the count
		// is over the rule's whole search.
		span = 0
	}
	by, _, err := parseBy(m[2], span > 0, field)
	if err != nil {
		return nil, err
	}
	return threshold(aggs, by, span, limits)
}

// azureRecord turns a field-level event into the Entra ID record that
// carries it: CIM fields back to the record fields they come from. Its
// category says which log it is in; without one, a sign-in is in the
// sign-in log and anything else in the audit log.
func azureRecord(ev map[string]string) sigmacheck.Case {
	data := map[string]string{}
	set := func(k, v string) {
		if v != "" && data[k] == "" {
			data[k] = v
		}
	}
	for k, v := range ev {
		if ingest.AzureField(k) {
			data[k] = v
		}
	}
	set("operationName", ev["signature"])
	set("operationName", ev["command"])
	cat := data["category"]
	service := "auditlogs"
	switch {
	case ev["sourcetype"] == ingest.AzureActivitySourcetype:
		service = "activitylogs"
	case strings.HasSuffix(cat, "SignInLogs"), cat == "" && data["operationName"] == "Sign-in activity":
		service = "signinlogs"
	case strings.HasSuffix(cat, "RiskEvents"):
		service = "riskdetection"
	}
	user := ev["user"]
	if user == "" {
		user = ev["src_user"]
	}
	src := ev["src"]
	if src == "" {
		src = ev["src_ip"]
	}
	switch service {
	case "signinlogs":
		set("properties.userPrincipalName", user)
		set("properties.ipAddress", src)
		set("properties.userAgent", ev["user_agent"])
		set("properties.appDisplayName", ev["app"])
		set("properties.resourceDisplayName", ev["dest"])
		set("properties.status.failureReason", ev["reason"])
		switch {
		case strings.EqualFold(ev["action"], "success"):
			set("properties.status.errorCode", "0")
		case strings.EqualFold(ev["action"], "failure"):
			set("properties.status.errorCode", "50126")
		}
		set("properties.status.errorCode", data["resultType"])
		set("properties.status.errorCode", "50126")
		set("resultType", data["properties.status.errorCode"])
		// What every sign-in has, so a count can group its test records.
		set("operationName", "Sign-in activity")
		set("properties.userPrincipalName", "tester@example.com")
		set("properties.ipAddress", "203.0.113.7")
		set("properties.appDisplayName", "Azure Portal")
		set("properties.appId", "c44b4083-3bb0-49c1-b47d-974e53cbdf3c")
		set("properties.userAgent", "Mozilla/5.0")
		set("properties.resourceDisplayName", "Windows Azure Service Management API")
	case "riskdetection":
		set("properties.userPrincipalName", user)
		set("properties.ipAddress", src)
		set("properties.userPrincipalName", "tester@example.com")
		set("properties.ipAddress", "203.0.113.7")
	case "auditlogs":
		app := strings.EqualFold(ev["src_user_type"], "servicePrincipal")
		for k := range data {
			app = app || strings.HasPrefix(k, "properties.initiatedBy.app.")
		}
		if app {
			set("properties.initiatedBy.app.displayName", ev["src_user"])
			set("properties.initiatedBy.app.displayName", ev["user"])
			set("properties.initiatedBy.app.displayName", "Tester App")
		} else {
			set("properties.initiatedBy.user.userPrincipalName", ev["src_user"])
			set("properties.initiatedBy.user.userPrincipalName", ev["user"])
			set("properties.initiatedBy.user.ipAddress", src)
			set("properties.initiatedBy.user.userPrincipalName", "admin@example.com")
		}
		set("properties.result", ev["status"])
		set("properties.result", "success")
		set("properties.targetResources{}.userPrincipalName", ev["object"])
		set("properties.userAgent", ev["user_agent"])
		set("properties.targetResources{}.displayName", "Tester App")
	}
	return sigmacheck.Case{Channel: sigmacheck.AzureChannel, EventID: service, Data: data}
}
