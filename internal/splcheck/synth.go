package splcheck

import (
	"fmt"
	"maps"
	"path"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/jrsamsanchez/signalith/internal/ingest"
	"github.com/jrsamsanchez/signalith/internal/query"
	"github.com/jrsamsanchez/signalith/internal/search"
	"github.com/jrsamsanchez/signalith/internal/sigmacheck"
)

// lit is one comparison in a term, possibly negated.
type lit struct {
	field  string
	values []string
	neg    bool // the event must not match
}

// terms lists conjunctions of comparisons that together reach every
// comparison of e: each OR branch and each IN value is in some term. It
// is not the full disjunctive form, which can be huge; an AND of ORs
// lines its branches up instead of multiplying them.
func terms(e Expr, neg bool) [][]lit {
	switch x := e.(type) {
	case *Not:
		return terms(x.Kid, !neg)
	case *Cmp:
		if x.Neg {
			// a != v is "a present and not v".
			if neg {
				return [][]lit{{{field: x.Field, values: x.Values}}, {{field: x.Field, values: nil, neg: true}}}
			}
			return [][]lit{{{field: x.Field, values: []string{"*"}}, {field: x.Field, values: x.Values, neg: true}}}
		}
		if neg {
			return [][]lit{{{field: x.Field, values: x.Values, neg: true}}}
		}
		var out [][]lit
		for _, v := range x.Values {
			out = append(out, []lit{{field: x.Field, values: []string{v}}})
		}
		return out
	case *And:
		if neg {
			return union(x.Kids, true)
		}
		return line(x.Kids, false)
	case *Or:
		if neg {
			return line(x.Kids, true)
		}
		return union(x.Kids, false)
	}
	return nil
}

func union(kids []Expr, neg bool) [][]lit {
	var out [][]lit
	for _, k := range kids {
		out = append(out, terms(k, neg)...)
	}
	return out
}

func line(kids []Expr, neg bool) [][]lit {
	var parts [][][]lit
	n := 0
	for _, k := range kids {
		t := terms(k, neg)
		if len(t) == 0 {
			return nil
		}
		parts = append(parts, t)
		n = max(n, len(t))
	}
	out := make([][]lit, n)
	for i := range n {
		for _, t := range parts {
			out[i] = append(out[i], t[i%len(t)]...)
		}
	}
	return out
}

// instantiate makes a value a pattern matches: each * becomes nothing at
// the ends and a space inside.
func instantiate(p string) string {
	if p == "*" {
		return "x"
	}
	// A * at either end becomes a letter so values keep their edges (a
	// command line does not start with a space); inside, a space.
	parts := strings.Split(p, "*")
	if parts[0] == "" && len(parts) > 1 {
		parts[0] = "x"
	}
	if n := len(parts) - 1; n > 0 && parts[n] == "" {
		parts[n] = "x"
	}
	return strings.Join(parts, " ")
}

// mutate makes a value close to v that a pattern written for v should
// not match: its last letter or digit changed.
func mutate(v string) string {
	r := []rune(v)
	for i := len(r) - 1; i >= 0; i-- {
		switch {
		case r[i] >= 'a' && r[i] <= 'y', r[i] >= 'A' && r[i] <= 'Y', r[i] >= '0' && r[i] <= '8':
			r[i]++
			return string(r)
		case r[i] == 'z' || r[i] == 'Z' || r[i] == '9':
			r[i] = 'q'
			return string(r)
		}
	}
	return v + "q"
}

// assign gives each field of a term a value matching its positive
// comparisons and none of its negated ones, or false when it finds none.
func assign(term []lit) (map[string]string, bool) {
	ev := map[string]string{}
	pos := map[string][]string{}
	neg := map[string][][]string{}
	absent := map[string]bool{}
	var fields []string
	for _, l := range term {
		if !slices.Contains(fields, l.field) {
			fields = append(fields, l.field)
		}
		switch {
		case l.neg && l.values == nil:
			absent[l.field] = true
		case l.neg:
			neg[l.field] = append(neg[l.field], l.values)
		default:
			pos[l.field] = append(pos[l.field], l.values[0])
		}
	}
	for _, f := range fields {
		if absent[f] {
			if len(pos[f]) > 0 {
				return nil, false
			}
			continue
		}
		ps := pos[f]
		if len(ps) == 0 {
			continue // only excluded values: leaving it out satisfies them
		}
		var cands []string
		parts := make([]string, len(ps))
		for i, p := range ps {
			parts[i] = instantiate(p)
		}
		cands = append(cands, strings.Join(parts, " "))
		cands = append(cands, parts...)
		found := false
		for _, c := range cands {
			ok := true
			for _, p := range ps {
				if !Glob(p, c) {
					ok = false
				}
			}
			for _, vs := range neg[f] {
				for _, p := range vs {
					if Glob(p, c) {
						ok = false
					}
				}
			}
			if ok {
				ev[f] = c
				found = true
				break
			}
		}
		if !found {
			return nil, false
		}
	}
	return ev, true
}

// Events are field-level test events for a where clause: a matching event
// for each term it can satisfy, and near misses with one value changed or
// one excluded value put in.
func Events(e Expr) (pos, neg []map[string]string) {
	seen := map[string]bool{}
	add := func(list *[]map[string]string, ev map[string]string) {
		k := key(ev)
		if seen[k] {
			return
		}
		seen[k] = true
		*list = append(*list, ev)
	}
	for _, term := range terms(e, false) {
		ev, ok := assign(term)
		if !ok {
			continue
		}
		add(&pos, ev)
		for _, l := range term {
			if l.neg {
				if l.values == nil {
					continue
				}
				// The excluded value itself.
				for _, p := range l.values {
					m := maps.Clone(ev)
					m[l.field] = instantiate(p)
					add(&neg, m)
				}
				continue
			}
			if v, ok := ev[l.field]; ok {
				m := maps.Clone(ev)
				m[l.field] = mutate(v)
				add(&neg, m)
				m = maps.Clone(ev)
				delete(m, l.field)
				add(&neg, m)
			}
		}
	}
	return pos, neg
}

func key(ev map[string]string) string {
	ks := slices.Sorted(maps.Keys(ev))
	var b strings.Builder
	for _, k := range ks {
		b.WriteString(k + "=" + ev[k] + "\x00")
	}
	return b.String()
}

// Windows events for a node, from field-level values, as Sysmon and the
// Security log record them: the parser then makes the fields Signalith
// stores, which are what the rule and the detection are both checked on.

const sysDir = `C:\Windows\System32\`

func imagePath(path, name string) string {
	switch {
	case path != "":
		return path
	case name != "":
		return sysDir + name
	}
	return ""
}

// records turns one field-level event into the Windows events that carry
// it.
func records(node string, ev map[string]string) []sigmacheck.Case {
	set := func(m map[string]string, k, v string) {
		if v != "" {
			m[k] = v
		}
	}
	switch node {
	case "Processes":
		s := map[string]string{"ProcessId": "4242", "ParentProcessId": "4000"}
		set(s, "Image", imagePath(ev["process_path"], ev["process_name"]))
		set(s, "CommandLine", ev["process"])
		set(s, "OriginalFileName", ev["original_file_name"])
		set(s, "ParentImage", imagePath(ev["parent_process_path"], ev["parent_process_name"]))
		set(s, "ParentCommandLine", ev["parent_process"])
		set(s, "User", ev["user"])
		set(s, "IntegrityLevel", ev["process_integrity_level"])
		set(s, "CurrentDirectory", ev["process_current_directory"])
		set(s, "ProcessId", ev["process_id"])
		set(s, "ParentProcessId", ev["parent_process_id"])
		out := []sigmacheck.Case{{Channel: sigmacheck.SysmonChannel, EventID: "1", Data: s}}
		// The Security log has fewer fields; it is checked too when the
		// event fits it.
		fits := true
		for f := range ev {
			if !slices.Contains([]string{"process", "process_path", "process_name", "parent_process_path", "parent_process_name"}, f) {
				fits = false
			}
		}
		if fits {
			w := map[string]string{"SubjectUserName": "tester", "SubjectDomainName": "CORP", "NewProcessId": "0x1092", "ProcessId": "0xfa0"}
			set(w, "NewProcessName", imagePath(ev["process_path"], ev["process_name"]))
			set(w, "CommandLine", ev["process"])
			set(w, "ParentProcessName", imagePath(ev["parent_process_path"], ev["parent_process_name"]))
			out = append(out, sigmacheck.Case{Channel: sigmacheck.SecurityChannel, EventID: "4688", Data: w})
		}
		return out
	case "Filesystem":
		s := map[string]string{"ProcessId": "4242"}
		set(s, "Image", imagePath(ev["process_path"], ev["process_name"]))
		set(s, "User", ev["user"])
		target := ev["file_path"]
		if target == "" && ev["file_name"] != "" {
			target = `C:\Users\Public\` + ev["file_name"]
		}
		set(s, "TargetFilename", target)
		id := "11"
		if a := strings.ToLower(ev["action"]); strings.HasPrefix(a, "delet") {
			id = "23"
		}
		out := []sigmacheck.Case{{Channel: sigmacheck.SysmonChannel, EventID: id, Data: s}}
		// When the rule names the folder and the file apart, the file goes
		// in the folder too.
		if name := ev["file_name"]; name != "" && ev["file_path"] != "" && !strings.EqualFold(path.Base(strings.ReplaceAll(target, `\`, "/")), name) {
			both := maps.Clone(s)
			both["TargetFilename"] = strings.TrimRight(target, `\`) + `\` + name
			out = append(out, sigmacheck.Case{Channel: sigmacheck.SysmonChannel, EventID: id, Data: both})
		}
		return out
	case "Registry":
		s := map[string]string{"ProcessId": "4242", "EventType": "SetValue"}
		set(s, "Image", imagePath(ev["process_path"], ev["process_name"]))
		set(s, "User", ev["user"])
		target := ev["registry_path"]
		// The path ends in the value's name, as Sysmon writes it.
		if v := ev["registry_value_name"]; target != "" && v != "" && !strings.HasSuffix(strings.ToLower(target), `\`+strings.ToLower(v)) {
			target = strings.TrimRight(target, `\`) + `\` + v
		}
		if target == "" {
			key := ev["registry_key_name"]
			if key == "" {
				key = "Run"
			}
			target = `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\` + key
			if v := ev["registry_value_name"]; v != "" {
				target += `\` + v
			}
		}
		set(s, "TargetObject", target)
		// Sysmon writes a DWORD as "DWORD (0x00000001)".
		data := ev["registry_value_data"]
		if len(data) == 10 && strings.HasPrefix(strings.ToLower(data), "0x") {
			data = "DWORD (" + data + ")"
		}
		set(s, "Details", data)
		id := "13"
		switch a := strings.ToLower(ev["action"]); {
		case strings.HasPrefix(a, "delet"):
			id, s["EventType"] = "12", "DeleteValue"
			delete(s, "Details")
		case strings.HasPrefix(a, "creat"):
			id, s["EventType"] = "12", "CreateKey"
			delete(s, "Details")
		}
		return []sigmacheck.Case{{Channel: sigmacheck.SysmonChannel, EventID: id, Data: s}}
	case "ImageLoad":
		s := map[string]string{"ProcessId": "4242", "ProcessGuid": "{6f1b4c2e-0d3a-4b8e-9c71-2a5d8e4f9b10}"}
		set(s, "Image", imagePath(ev["process_path"], ev["process_name"]))
		set(s, "ImageLoaded", ev["loaded_file_path"])
		set(s, "Signed", ev["signed"])
		set(s, "SignatureStatus", ev["signature_status"])
		set(s, "Signature", ev["signature"])
		return []sigmacheck.Case{{Channel: sigmacheck.SysmonChannel, EventID: "7", Data: s}}
	case "ProcessAccess":
		s := map[string]string{"SourceProcessId": "4242", "TargetProcessId": "640"}
		set(s, "SourceImage", ev["process_path"])
		set(s, "TargetImage", ev["target_process_path"])
		set(s, "GrantedAccess", ev["granted_access"])
		set(s, "CallTrace", ev["call_trace"])
		set(s, "SourceUser", ev["user"])
		id := ev[eventCode]
		if id != "8" {
			id = "10"
		}
		return []sigmacheck.Case{{Channel: sigmacheck.SysmonChannel, EventID: id, Data: s}}
	case "PowerShell":
		s := map[string]string{"MessageNumber": "1", "MessageTotal": "1", "ScriptBlockId": "6f1b4c2e-0d3a-4b8e-9c71-2a5d8e4f9b10"}
		set(s, "ScriptBlockText", ev["script_block_text"])
		return []sigmacheck.Case{{Channel: sigmacheck.PowerShellChannel, EventID: "4104", Data: s}}
	}
	return nil
}

// Stored is a case's event as Signalith stores it, after the real Windows
// parser, with its data model.
func Stored(c sigmacheck.Case) (map[string]any, string) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	rec := ingest.WinEventRecord(c.Channel, c.EventID, "test-host", now, c.Data)
	ev := ingest.Normalize("win.events", rec, now)
	return ev.Document(), ev.Model
}

// View is a stored event as the string field values a where clause reads.
func View(doc map[string]any) map[string]string {
	out := map[string]string{}
	for k, v := range doc {
		switch x := v.(type) {
		case nil:
		case string:
			if x != "" {
				out[k] = x
			}
		case []any:
			if len(x) > 0 {
				out[k] = fmt.Sprint(x[0])
			}
		default:
			out[k] = fmt.Sprint(x)
		}
	}
	// Splunk's Sysmon add-on keeps the number of "DWORD (0x00000001)" as
	// registry_value_data, so its rules compare with 0x00000001.
	if m := wordRe.FindStringSubmatch(out["registry_value_data"]); m != nil {
		out["registry_value_data"] = m[1]
	}
	return out
}

// wordRe is how Sysmon writes a DWORD or QWORD value's data.
var wordRe = regexp.MustCompile(`^[DQ]WORD \((0x[0-9a-fA-F]+)\)$`)

// Cases makes a rule's test events: each field-level event becomes the
// Windows events that carry it, and whether the rule must match each is
// what Eval says of the event as stored.
func Cases(r *Rule) []sigmacheck.Case {
	pos, neg := Events(r.Where)
	var out []sigmacheck.Case
	for _, ev := range append(pos, neg...) {
		for _, c := range records(r.Node, ev) {
			doc, model := Stored(c)
			c.Source = "synthesized"
			c.Expect = model == NodeModel[r.Node] && Eval(r.Where, View(doc))
			out = append(out, c)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Expect && !out[j].Expect })
	return out
}

// NodeModel is the Signalith data model of each node.
var NodeModel = map[string]string{"Processes": "Endpoint", "Filesystem": "Filesystem", "Registry": "Registry", "PowerShell": "Script", "ImageLoad": "Image_Load", "ProcessAccess": "Endpoint"}

// Verify checks a converted detection against a rule's test events: each
// event, as the real parser stores it, must be read the same way by the
// Splunk where clause (Eval) and by the detection's filter
// (search.MatchDoc), and as the test file says. It returns every
// disagreement.
func Verify(r *Rule, datamodel string, filter query.Expr, tf *sigmacheck.TestFile) []error {
	var errs []error
	for i, c := range tf.Cases {
		where := fmt.Sprintf("case %d (%s %s, expect %v)", i, c.Channel, c.EventID, c.Expect)
		doc, model := Stored(c)
		inModel := strings.EqualFold(model, NodeModel[r.Node])
		if got := inModel && Eval(r.Where, View(doc)); got != c.Expect {
			errs = append(errs, fmt.Errorf("%s: the Splunk rule says %v for %s", where, got, sigmacheck.String(View(doc))))
			continue
		}
		if !strings.EqualFold(model, datamodel) {
			if c.Expect {
				errs = append(errs, fmt.Errorf("%s: the parser put the event in %s, not %s", where, model, datamodel))
			}
			continue
		}
		m, err := search.MatchDoc(filter, doc)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %v", where, err))
			continue
		}
		if m != c.Expect {
			errs = append(errs, fmt.Errorf("%s: the detection says %v for %s", where, m, sigmacheck.String(c.Data)))
		}
	}
	return errs
}
