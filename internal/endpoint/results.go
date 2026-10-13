package endpoint

import (
	"encoding/json"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/jrsamsanchez/signalith/internal/endpoint/checks"
	"github.com/jrsamsanchez/signalith/internal/ingest"
)

// checkByID finds a configuration check by its ID.
var checkByID = func() map[string]checks.Check {
	m := map[string]checks.Check{}
	for _, c := range checks.All() {
		m[c.ID] = c
	}
	return m
}()

// logLine is one osquery result log entry, in event format (one row with
// its action) or snapshot format (every row).
type logLine struct {
	Name        string           `json:"name"`
	UnixTime    json.Number      `json:"unixTime"`
	Action      string           `json:"action"`
	Columns     map[string]any   `json:"columns"`
	Snapshot    []map[string]any `json:"snapshot"`
	Decorations map[string]any   `json:"decorations"`
	DiffResults *diffResults     `json:"diffResults"`
}

type diffResults struct {
	Added   []map[string]any `json:"added"`
	Removed []map[string]any `json:"removed"`
}

// Batch is what one result log request carried, sorted out.
type Batch struct {
	Events []ingest.Event
	// IPs are the host's addresses, when the batch had a snapshot of them.
	IPs []string
	// Checks are configuration check results that are new or changed.
	Checks []CheckResult
	// Skipped counts lines that were not results of Signalith's queries,
	// or could not be read.
	Skipped int
}

// maxRawBytes caps the raw text kept with each event.
const maxRawBytes = 8 << 10

// ParseResults turns result log lines from a host into events.
func ParseResults(n *Node, lines []json.RawMessage, now time.Time) *Batch {
	b := &Batch{}
	for _, raw := range lines {
		// The TLS logger sends each line as a JSON object; some versions
		// send it as a string holding one.
		if len(raw) > 0 && raw[0] == '"' {
			var s string
			if json.Unmarshal(raw, &s) != nil {
				b.Skipped++
				continue
			}
			raw = json.RawMessage(s)
		}
		var l logLine
		if json.Unmarshal(raw, &l) != nil || !strings.HasPrefix(l.Name, QueryPrefix) {
			b.Skipped++
			continue
		}
		name := strings.TrimPrefix(l.Name, QueryPrefix)
		at := now
		if sec, err := l.UnixTime.Int64(); err == nil && sec > 0 {
			at = time.Unix(sec, 0).UTC()
		}
		host := n.Hostname
		if h, ok := l.Decorations["hostname"].(string); ok && h != "" {
			host = h
		}
		rows := func(yield func(action string, cols map[string]any)) {
			switch {
			case l.Columns != nil:
				yield(l.Action, l.Columns)
			case l.Snapshot != nil:
				for _, c := range l.Snapshot {
					yield("snapshot", c)
				}
			case l.DiffResults != nil:
				for _, c := range l.DiffResults.Added {
					yield("added", c)
				}
				for _, c := range l.DiffResults.Removed {
					yield("removed", c)
				}
			}
		}
		if name == qAddrs {
			var ips []string
			for _, c := range collect(rows) {
				if a := str(c.cols, "address"); a != "" {
					ips = append(ips, a)
				}
			}
			if l.Snapshot != nil {
				b.IPs = append([]string{}, ips...)
			}
			continue
		}
		if id, ok := strings.CutPrefix(name, qCheck); ok {
			c, known := checkByID[id]
			for _, r := range collect(rows) {
				// A changed result comes as the old row removed and the
				// new one added; only the new one matters.
				if !known || r.action == "removed" {
					continue
				}
				res := CheckResult{ID: id, Result: str(r.cols, "result"), Detail: cut(str(r.cols, "detail"), 1000), At: at}
				if res.Result != "pass" && res.Result != "fail" && res.Result != "n/a" {
					res.Result = "error"
				}
				b.Checks = append(b.Checks, res)
				b.Events = append(b.Events, checkEvent(c, res, host, n))
			}
			continue
		}
		for _, r := range collect(rows) {
			ev, ok := toEvent(name, r.action, r.cols, host, n, at)
			if !ok {
				b.Skipped++
				continue
			}
			if len(raw) <= maxRawBytes {
				ev.Fields["_raw"] = string(raw)
			}
			b.Events = append(b.Events, ev)
		}
	}
	return b
}

type row struct {
	action string
	cols   map[string]any
}

func collect(seq func(func(string, map[string]any))) []row {
	var out []row
	seq(func(a string, c map[string]any) { out = append(out, row{a, c}) })
	return out
}

// str reads a column as text: osquery sends every column as a string,
// unless --log_numerics_as_numbers is on.
func str(cols map[string]any, k string) string {
	switch v := cols[k].(type) {
	case string:
		return v
	case json.Number:
		return v.String()
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(v)
	}
	return ""
}

func num(cols map[string]any, k string) (int64, bool) {
	n, err := strconv.ParseInt(str(cols, k), 10, 64)
	return n, err == nil
}

// toEvent maps one row of a Signalith query onto a data model.
func toEvent(name, action string, cols map[string]any, host string, n *Node, at time.Time) (ingest.Event, bool) {
	f := map[string]any{
		"host": host, "dest": host, "vendor_product": "osquery", "sourcetype": "osquery:" + name,
		"endpoint_id": n.ID,
	}
	// say names what happened: added and removed in words that fit the item.
	say := func(what, added, removed string) {
		f["signature"] = what + " " + map[string]string{"added": added, "removed": removed, "snapshot": "present"}[action]
	}
	set := func(field, col string) {
		if v := str(cols, col); v != "" {
			f[field] = v
		}
	}
	setNum := func(field, col string) {
		if v, ok := num(cols, col); ok {
			f[field] = v
		}
	}
	ev := ingest.Event{Time: at, Fields: f}
	if name == qFIM {
		return fimEvent(ev, n.Platform, cols)
	}
	ev.Model = "Inventory"
	switch action {
	case "added", "removed":
		f["action"] = action
	case "snapshot":
		f["action"] = "present"
	default:
		return ev, false
	}
	switch name {
	case qOS:
		f["inventory_type"] = "os"
		set("os", "name")
		set("os_version", "version")
		set("name", "name")
		set("version", "version")
		say("Operating system", "added", "removed")
	case qSoftware:
		f["inventory_type"] = "software"
		set("name", "name")
		set("version", "version")
		set("vendor", "vendor")
		set("path", "path")
		set("package_type", "package_type")
		say("Software", "installed", "removed")
	case qUsers:
		f["inventory_type"] = "user"
		set("user", "username")
		set("name", "username")
		set("path", "directory")
		say("Account", "added", "removed")
	case qPorts:
		f["inventory_type"] = "port"
		setNum("dest_port", "port")
		set("transport", "transport")
		set("process_name", "process_name")
		set("path", "path")
		set("name", "process_name")
		say("Listening port", "opened", "closed")
	case qServices:
		f["inventory_type"] = "service"
		set("name", "name")
		set("path", "path")
		set("status", "start_type")
		say("Service", "added", "removed")
	case qStartup:
		f["inventory_type"] = "startup"
		set("name", "name")
		set("path", "path")
		say("Startup item", "added", "removed")
	default:
		return ev, false
	}
	f["signature_id"] = "osquery:" + name
	return ev, true
}

// CheckResult is a host's latest result for one configuration check.
type CheckResult struct {
	ID     string    `json:"id"`
	Result string    `json:"result"` // pass, fail, n/a or error
	Detail string    `json:"detail,omitempty"`
	At     time.Time `json:"at"`
}

// checkEvent records a check result in Configuration_Check.
func checkEvent(c checks.Check, r CheckResult, host string, n *Node) ingest.Event {
	f := map[string]any{
		"host": host, "dest": host, "vendor_product": "osquery", "sourcetype": "osquery:check",
		"endpoint_id": n.ID, "check_id": c.ID, "check": c.Title, "result": r.Result, "severity": c.Severity,
		"os": c.Platform, "signature_id": c.ID, "signature": c.Title,
	}
	if c.RuleID != "" {
		f["rule_id"] = c.RuleID
		f["benchmark"] = "SCAP Security Guide"
	}
	if len(c.References) > 0 {
		f["reference"] = strings.Join(c.References, ", ")
	}
	if r.Detail != "" {
		f["detail"] = r.Detail
	}
	return ingest.Event{Time: r.At, Model: "Configuration_Check", Fields: f}
}

func cut(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// fimEvent maps a file_events (Linux, macOS) or ntfs_journal_events
// (Windows) row onto Filesystem.
func fimEvent(ev ingest.Event, platform string, cols map[string]any) (ingest.Event, bool) {
	f := ev.Fields
	ev.Model = "Filesystem"
	if sec, ok := num(cols, "time"); ok && sec > 0 {
		ev.Time = time.Unix(sec, 0).UTC()
	}
	vendor := str(cols, "action")
	p := str(cols, "target_path")
	if platform == Windows {
		p = str(cols, "path")
		if old := str(cols, "old_path"); old != "" {
			f["file_old_path"] = old
		}
	}
	if p == "" {
		return ev, false
	}
	f["file_path"] = p
	f["file_name"] = baseName(p)
	f["vendor_action"] = vendor
	f["action"] = fimAction(vendor)
	if h := str(cols, "sha256"); h != "" {
		f["file_hash"] = strings.ToLower(h)
	}
	if size, ok := num(cols, "size"); ok && f["action"] != "deleted" {
		f["file_size"] = size
	}
	if uid := str(cols, "uid"); uid != "" {
		f["user_id"] = uid
	}
	f["signature"] = "File " + f["action"].(string)
	f["signature_id"] = "osquery:fim"
	return ev, true
}

// fimAction maps osquery's file event actions onto created, modified,
// deleted or renamed.
func fimAction(a string) string {
	u := strings.ToUpper(a)
	switch {
	case u == "CREATED" || u == "MOVED_TO" || strings.Contains(u, "CREATION") || u == "FILERENAME_NEWNAME":
		return "created"
	case u == "DELETED" || u == "MOVED_FROM" || strings.Contains(u, "DELETE"):
		return "deleted"
	case strings.Contains(u, "RENAME"):
		return "renamed"
	}
	return "modified"
}

// baseName is the file name of a Windows or POSIX path.
func baseName(p string) string {
	if i := strings.LastIndexAny(p, `\/`); i >= 0 {
		return p[i+1:]
	}
	return path.Base(p)
}
