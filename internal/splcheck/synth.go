package splcheck

import (
	"fmt"
	"html"
	"maps"
	"math/rand"
	"net/netip"
	"path"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/jrsamsanchez/signalith/internal/query"
	"github.com/jrsamsanchez/signalith/internal/search"
	"github.com/jrsamsanchez/signalith/internal/sigmacheck"
)

// lit is one comparison in a term, possibly negated.
type lit struct {
	field  string
	values []string
	neg    bool // the event must not match
	re     bool // values are regular expressions
}

func (l lit) matches(p, v string) bool { return (&Cmp{Regex: l.re}).matches(p, v) }

// terms lists conjunctions of comparisons that together reach every
// comparison of e: each OR branch and each IN value is in some term. It
// is not the full disjunctive form, which can be huge; an AND of ORs
// lines its branches up instead of multiplying them.
func terms(e Expr, neg bool) [][]lit {
	switch x := e.(type) {
	case *Not:
		return terms(x.Kid, !neg)
	case *Cmp:
		re := x.Regex
		if x.Neg {
			// a != v is "a present and not v".
			if neg {
				return [][]lit{{{field: x.Field, values: x.Values, re: re}}, {{field: x.Field, values: nil, neg: true}}}
			}
			return [][]lit{{{field: x.Field, values: []string{"*"}}, {field: x.Field, values: x.Values, neg: true, re: re}}}
		}
		if neg {
			return [][]lit{{{field: x.Field, values: x.Values, neg: true, re: re}}}
		}
		var out [][]lit
		for _, v := range x.Values {
			out = append(out, []lit{{field: x.Field, values: []string{v}, re: re}})
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
	// An address range becomes an address in it.
	if pre, err := netip.ParsePrefix(p); err == nil {
		a := pre.Masked().Addr()
		if n := a.Next(); pre.Contains(n) {
			a = n
		}
		return a.String()
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

// example is a value a comparison's first value matches: a pattern
// instantiated, or an example of a regular expression.
func example(l lit, rng *rand.Rand) string {
	if !l.re {
		return instantiate(l.values[0])
	}
	s, err := sigmacheck.RegexExample(rng, l.values[0])
	if err != nil {
		return ""
	}
	return s
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
	pos := map[string][]lit{}
	neg := map[string][]lit{}
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
			neg[l.field] = append(neg[l.field], l)
		default:
			pos[l.field] = append(pos[l.field], lit{field: l.field, values: l.values[:1], re: l.re})
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
		// Several tries, since a regular expression's example is picked
		// at random.
		rng := rand.New(rand.NewSource(int64(len(f))))
		for try := 0; try < 8; try++ {
			parts := make([]string, len(ps))
			for i, p := range ps {
				parts[i] = example(p, rng)
			}
			cands = append(cands, strings.Join(parts, " "))
			cands = append(cands, parts...)
		}
		found := false
		for _, c := range cands {
			ok := true
			for _, p := range ps {
				if !p.matches(p.values[0], c) {
					ok = false
				}
			}
			for _, l := range neg[f] {
				for _, p := range l.values {
					if l.matches(p, c) {
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
					m[l.field] = example(lit{values: []string{p}, re: l.re}, rand.New(rand.NewSource(1)))
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
		set(s, "Description", ev["process_description"])
		set(s, "Product", ev["process_product"])
		set(s, "Company", ev["process_company"])
		set(s, "FileVersion", ev["process_file_version"])
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
		// A raw search names its event code.
		if c := ev[eventCode]; c == "11" || c == "23" || c == "26" {
			id = c
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
		// A raw search may name the type and names its event code.
		if t := ev["registry_event_type"]; t != "" {
			s["EventType"] = t
			switch t {
			case "CreateKey", "DeleteKey", "DeleteValue":
				id = "12"
				delete(s, "Details")
			case "RenameKey":
				id = "14"
			default:
				id = "13"
			}
		}
		if c := ev[eventCode]; (c == "12" || c == "13" || c == "14") && c != id {
			id = c
			switch c {
			case "12":
				s["EventType"] = "DeleteValue"
				if strings.HasPrefix(strings.ToLower(ev["action"]), "creat") {
					s["EventType"] = "CreateKey"
				}
				delete(s, "Details")
			case "13":
				s["EventType"] = "SetValue"
			case "14":
				s["EventType"] = "RenameKey"
			}
		}
		return []sigmacheck.Case{{Channel: sigmacheck.SysmonChannel, EventID: id, Data: s}}
	case "NetworkConnection", "All_Traffic":
		s := maps.Clone(sigmacheck.Bases["network_connection"])
		// A public address: rules leave out private and reserved ranges.
		s["DestinationIp"] = "93.184.216.34"
		set(s, "Image", imagePath(ev["process_path"], ev["process_name"]))
		set(s, "DestinationIp", ev["dest"])
		set(s, "DestinationPort", ev["dest_port"])
		set(s, "DestinationPortName", ev["dest_port_name"])
		set(s, "DestinationHostname", ev["dest_host"])
		set(s, "SourceIp", ev["src"])
		set(s, "SourcePort", ev["src_port"])
		return []sigmacheck.Case{{Channel: sigmacheck.SysmonChannel, EventID: "3", Data: s}}
	case "DnsQuery":
		s := maps.Clone(sigmacheck.Bases["dns_query"])
		set(s, "Image", imagePath(ev["process_path"], ev["process_name"]))
		set(s, "QueryName", ev["query"])
		return []sigmacheck.Case{{Channel: sigmacheck.SysmonChannel, EventID: "22", Data: s}}
	case "Logon":
		s := maps.Clone(sigmacheck.Bases[sigmacheck.SecurityCategory("4624")])
		set(s, "LogonType", ev["logon_type"])
		set(s, "TargetUserName", ev["user"])
		set(s, "AuthenticationPackageName", ev["authentication_method"])
		set(s, "LogonProcessName", ev["logon_process"])
		set(s, "IpAddress", ev["src"])
		set(s, "WorkstationName", ev["src_host"])
		set(s, "ProcessName", ev["process_path"])
		return []sigmacheck.Case{{Channel: sigmacheck.SecurityChannel, EventID: "4624", Data: s}}
	case "ImageLoad":
		s := map[string]string{"ProcessId": "4242", "ProcessGuid": "{6f1b4c2e-0d3a-4b8e-9c71-2a5d8e4f9b10}"}
		set(s, "Image", imagePath(ev["process_path"], ev["process_name"]))
		set(s, "ImageLoaded", ev["loaded_file_path"])
		set(s, "Signed", ev["signed"])
		set(s, "SignatureStatus", ev["signature_status"])
		set(s, "Signature", ev["signature"])
		set(s, "OriginalFileName", ev["loaded_original_file_name"])
		set(s, "Description", ev["loaded_file_description"])
		set(s, "Product", ev["loaded_file_product"])
		set(s, "Company", ev["loaded_file_company"])
		return []sigmacheck.Case{{Channel: sigmacheck.SysmonChannel, EventID: "7", Data: s}}
	case "ProcessAccess":
		s := map[string]string{"SourceProcessId": "4242", "TargetProcessId": "640"}
		set(s, "SourceImage", ev["process_path"])
		set(s, "TargetImage", ev["target_process_path"])
		set(s, "GrantedAccess", ev["granted_access"])
		set(s, "CallTrace", ev["call_trace"])
		set(s, "SourceUser", ev[RawUser])
		id := ev[eventCode]
		if id != "8" {
			id = "10"
		}
		return []sigmacheck.Case{{Channel: sigmacheck.SysmonChannel, EventID: id, Data: s}}
	case "PowerShell":
		s := map[string]string{"MessageNumber": "1", "MessageTotal": "1", "ScriptBlockId": "6f1b4c2e-0d3a-4b8e-9c71-2a5d8e4f9b10"}
		set(s, "ScriptBlockText", ev["script_block_text"])
		return []sigmacheck.Case{{Channel: sigmacheck.PowerShellChannel, EventID: "4104", Data: s}}
	case "TaskCreated":
		s := map[string]string{
			"SubjectUserSid": "S-1-5-21-1004336348-1177238915-682003330-1104", "SubjectUserName": "alice",
			"SubjectDomainName": "CORP", "SubjectLogonId": "0x3e7", "TaskName": `\Updater`, "TaskContent": taskXML,
		}
		set(s, "SubjectUserName", ev["user"])
		set(s, "TaskName", ev["task_name"])
		if ev["task_command"] != "" || ev["task_arguments"] != "" {
			cmd := ev["task_command"]
			if cmd == "" {
				cmd = `C:\Windows\System32\cmd.exe`
			}
			action := "<Command>" + html.EscapeString(cmd) + "</Command>"
			if a := ev["task_arguments"]; a != "" {
				action += "<Arguments>" + html.EscapeString(a) + "</Arguments>"
			}
			s["TaskContent"] = `<?xml version="1.0" encoding="UTF-16"?><Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">` +
				`<Actions Context="Author"><Exec>` + action + `</Exec></Actions></Task>`
		}
		set(s, "TaskContent", ev["task_content"])
		return []sigmacheck.Case{{Channel: sigmacheck.SecurityChannel, EventID: "4698", Data: s}}
	case "ObjectAccess":
		s := map[string]string{
			"SubjectUserSid": "S-1-5-21-1004336348-1177238915-682003330-1104", "SubjectUserName": "alice",
			"SubjectDomainName": "CORP", "SubjectLogonId": "0x3e7", "ObjectServer": "Security", "HandleId": "0x1f4",
			"AccessList": "%%4416", "AccessMask": "0x1", "ProcessId": "0x1092", "ProcessName": `C:\Tools\tool.exe`,
			"ObjectType": "File", "ObjectName": `C:\Users\alice\Documents\notes.txt`,
		}
		set(s, "ObjectType", ev["object_type"])
		set(s, "AccessList", ev["access_list"])
		set(s, "AccessMask", ev["access_mask"])
		set(s, "ProcessName", imagePath(ev["process_path"], ev["process_name"]))
		name := ev["object_path"]
		// The add-on's file_path and file_name are a file's object name.
		if name == "" && ev["file_path"] != "" {
			name = ev["file_path"]
			s["ObjectType"] = "File"
		}
		if n := ev["file_name"]; n != "" {
			s["ObjectType"] = "File"
			if name == "" {
				name = `C:\Users\alice\Documents\` + n
			} else if !strings.HasSuffix(strings.ToLower(name), `\`+strings.ToLower(n)) {
				name = strings.TrimRight(name, `\`) + `\` + n
			}
		}
		// When the rule names the object's file name apart, it ends the path.
		if n := ev["object_name"]; n != "" && !strings.HasSuffix(strings.ToLower(name), `\`+strings.ToLower(n)) {
			if name == "" {
				name = path.Dir(strings.ReplaceAll(s["ObjectName"], `\`, "/"))
				name = strings.ReplaceAll(name, "/", `\`)
			}
			name = strings.TrimRight(name, `\`) + `\` + n
		}
		set(s, "ObjectName", name)
		out := []sigmacheck.Case{{Channel: sigmacheck.SecurityChannel, EventID: "4663", Data: s}}
		// A rule that does not name the type may be about a registry key.
		if ev["object_type"] == "" {
			key := maps.Clone(s)
			key["ObjectType"] = "Key"
			if name == "" {
				key["ObjectName"] = `\REGISTRY\MACHINE\SOFTWARE\Contoso`
			}
			out = append(out, sigmacheck.Case{Channel: sigmacheck.SecurityChannel, EventID: "4663", Data: key})
		}
		return out
	case "DirectoryChange":
		s := maps.Clone(sigmacheck.Bases[sigmacheck.SecurityCategory("5136")])
		set(s, "ObjectDN", ev["object"])
		set(s, "ObjectGUID", ev["ad_object_guid"])
		set(s, "ObjectClass", ev["ad_object_class"])
		set(s, "AttributeLDAPDisplayName", ev["ad_attribute"])
		set(s, "AttributeValue", ev["ad_value"])
		set(s, "OperationType", ev["ad_operation"])
		set(s, "SubjectUserName", ev["user"])
		return []sigmacheck.Case{{Channel: sigmacheck.SecurityChannel, EventID: "5136", Data: s}}
	case "ShareAccess":
		s := maps.Clone(sigmacheck.Bases[sigmacheck.SecurityCategory("5145")])
		set(s, "ShareName", ev["share_name"])
		set(s, "ShareLocalPath", ev["share_path"])
		set(s, "RelativeTargetName", ev["share_target"])
		set(s, "ObjectType", ev["object_type"])
		set(s, "IpAddress", ev["src"])
		set(s, "AccessMask", ev["access_mask"])
		set(s, "AccessList", ev["access_list"])
		set(s, "SubjectUserName", ev["user"])
		return []sigmacheck.Case{{Channel: sigmacheck.SecurityChannel, EventID: "5145", Data: s}}
	case "KerberosTGT", "KerberosService":
		id := map[string]string{"KerberosTGT": "4768", "KerberosService": "4769"}[node]
		s := maps.Clone(sigmacheck.Bases[sigmacheck.SecurityCategory(id)])
		set(s, "TargetUserName", ev["user"])
		set(s, "TargetSid", ev["user_sid"])
		set(s, "ServiceName", ev["kerberos_service"])
		set(s, "TicketOptions", ev["ticket_options"])
		set(s, "Status", ev["kerberos_status"])
		set(s, "TicketEncryptionType", ev["ticket_encryption_type"])
		set(s, "PreAuthType", ev["pre_auth_type"])
		set(s, "CertThumbprint", ev["cert_thumbprint"])
		set(s, "CertIssuerName", ev["cert_issuer"])
		// An IPv4 client is recorded as ::ffff:a.b.c.d.
		if v := ev["src"]; v != "" && !strings.Contains(v, ":") {
			set(s, "IpAddress", "::ffff:"+v)
		} else {
			set(s, "IpAddress", v)
		}
		return []sigmacheck.Case{{Channel: sigmacheck.SecurityChannel, EventID: id, Data: s}}
	case "UserChanged":
		s := maps.Clone(sigmacheck.Bases[sigmacheck.SecurityCategory("4738")])
		set(s, "TargetUserName", ev["object"])
		set(s, "TargetSid", ev["object_sid"])
		set(s, "SubjectUserName", ev["user"])
		set(s, "SamAccountName", ev["sam_account_name"])
		set(s, "UserAccountControl", ev["user_account_control"])
		set(s, "AllowedToDelegateTo", ev["allowed_to_delegate_to"])
		set(s, "OldUacValue", ev["old_uac_value"])
		set(s, "NewUacValue", ev["new_uac_value"])
		set(s, "SidHistory", ev["sid_history"])
		return []sigmacheck.Case{{Channel: sigmacheck.SecurityChannel, EventID: "4738", Data: s}}
	case "GroupMemberAdded":
		s := maps.Clone(sigmacheck.Bases[sigmacheck.SecurityCategory("4732")])
		set(s, "TargetUserName", ev["object"])
		set(s, "TargetSid", ev["object_sid"])
		set(s, "MemberSid", ev["member_sid"])
		set(s, "MemberName", ev["member"])
		set(s, "SubjectUserName", ev["user"])
		return []sigmacheck.Case{{Channel: sigmacheck.SecurityChannel, EventID: "4732", Data: s}}
	case "ServiceInstalled":
		s := map[string]string{
			"ServiceName": "ExampleUpdater", "ImagePath": `"C:\Program Files\Example\updater.exe" --service`,
			"ServiceType": "user mode service", "StartType": "auto start", "AccountName": "LocalSystem",
		}
		set(s, "ServiceName", ev["service_name"])
		set(s, "ImagePath", ev["service_path"])
		set(s, "ServiceType", ev["service_type"])
		set(s, "StartType", ev["service_start_type"])
		set(s, "AccountName", ev["service_account"])
		return []sigmacheck.Case{{Channel: sigmacheck.SystemChannel, EventID: "7045", Data: s}}
	}
	return nil
}

// taskXML is a scheduled task's definition, for test events whose rule
// does not name it.
const taskXML = `<?xml version="1.0" encoding="UTF-16"?><Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">` +
	`<Settings><Enabled>true</Enabled><Hidden>false</Hidden></Settings>` +
	`<Actions Context="Author"><Exec><Command>C:\Program Files\Updater\update.exe</Command></Exec></Actions></Task>`

// linuxRecords turns one field-level event into the Sysmon for Linux
// events that carry it.
func linuxRecords(node string, ev map[string]string) []sigmacheck.Case {
	set := func(m map[string]string, k, v string) {
		if v != "" {
			m[k] = v
		}
	}
	bin := func(path, name string) string {
		switch {
		case path != "":
			return path
		case name != "":
			return "/usr/bin/" + name
		}
		return ""
	}
	switch node {
	case "Processes":
		s := map[string]string{"ProcessId": "4242", "ParentProcessId": "4000", "User": "tester"}
		set(s, "Image", bin(ev["process_path"], ev["process_name"]))
		set(s, "CommandLine", ev["process"])
		set(s, "ParentImage", bin(ev["parent_process_path"], ev["parent_process_name"]))
		set(s, "ParentCommandLine", ev["parent_process"])
		set(s, "User", ev["user"])
		set(s, "CurrentDirectory", ev["process_current_directory"])
		set(s, "ProcessId", ev["process_id"])
		set(s, "ParentProcessId", ev["parent_process_id"])
		return []sigmacheck.Case{{Channel: sigmacheck.LinuxSysmonChannel, EventID: "1", Data: s}}
	case "Filesystem":
		s := map[string]string{"ProcessId": "4242", "User": "tester"}
		set(s, "Image", bin(ev["process_path"], ev["process_name"]))
		set(s, "User", ev["user"])
		target := ev["file_path"]
		if target == "" && ev["file_name"] != "" {
			target = "/tmp/" + ev["file_name"]
		} else if name := ev["file_name"]; name != "" && !strings.EqualFold(path.Base(target), name) {
			target = strings.TrimRight(target, "/") + "/" + name
		}
		set(s, "TargetFilename", target)
		id := "11"
		if a := strings.ToLower(ev["action"]); strings.HasPrefix(a, "delet") {
			id = "23"
		}
		return []sigmacheck.Case{{Channel: sigmacheck.LinuxSysmonChannel, EventID: id, Data: s}}
	}
	return nil
}

// Stored is a case's event as Signalith stores it, after the real Windows
// parser, with its data model.
func Stored(c sigmacheck.Case) (map[string]any, string) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	ev := c.Stored("test-host", now)
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
	// It reads Sysmon's user (NT AUTHORITY\SYSTEM) as the name alone.
	if u := out["user"]; u != "" {
		out[RawUser] = u
		out["user"] = u[strings.LastIndex(u, `\`)+1:]
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
		cs := records(r.Node, ev)
		if r.Linux {
			cs = linuxRecords(r.Node, ev)
		}
		for _, c := range cs {
			doc, model := Stored(c)
			c.Source = "synthesized"
			c.Expect = InModel(r.Node, model) && Eval(r.Where, View(doc))
			out = append(out, c)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Expect && !out[j].Expect })
	return out
}

// NodeModel is the Signalith data model of each node ("" for any).
var NodeModel = map[string]string{"Processes": "Endpoint", "Filesystem": "Filesystem", "Registry": "Registry", "PowerShell": "Script", "ImageLoad": "Image_Load", "ProcessAccess": "Endpoint", "NetworkConnection": "Network_Traffic", "All_Traffic": "Network_Traffic", "DnsQuery": "Network_Resolution", "Logon": "Authentication", "TaskCreated": "Change", "ObjectAccess": "", "ServiceInstalled": "Change", "DirectoryChange": "Change", "ShareAccess": "Filesystem", "KerberosTGT": "Authentication", "KerberosService": "Authentication", "UserChanged": "Change", "GroupMemberAdded": "Change"}

// AttackDataSource marks a test event recorded in a real attack (Splunk's
// attack_data, by internal/detect/attackgen).
const AttackDataSource = "attack_data"

// Reads reports whether Splunk's rule finds an event: one of its node's
// events whose stored fields match the where clause.
func Reads(r *Rule, c sigmacheck.Case) bool {
	doc, model := Stored(c)
	return InModel(r.Node, model) && slices.Contains(NodeEvents[r.Node], c.EventID) && Eval(r.Where, View(doc))
}

// NodeEvents are the Windows event IDs each node reads (as Splunk's
// add-ons map them to the data model).
var NodeEvents = map[string][]string{
	"Processes":         {"1", "4688"},
	"Filesystem":        {"11", "23", "26"},
	"Registry":          {"12", "13", "14"},
	"PowerShell":        {"4104"},
	"ImageLoad":         {"7"},
	"ProcessAccess":     {"8", "10"},
	"NetworkConnection": {"3"},
	"All_Traffic":       {"3"},
	"DnsQuery":          {"22"},
	"Logon":             {"4624"},
	"TaskCreated":       {"4698"},
	"ObjectAccess":      {"4663"},
	"ServiceInstalled":  {"7045"},
	"DirectoryChange":   {"5136"},
	"ShareAccess":       {"5145"},
	"KerberosTGT":       {"4768"},
	"KerberosService":   {"4769"},
	"UserChanged":       {"4738"},
	"GroupMemberAdded":  {"4732"},
}

// InModel reports whether an event of a data model is one a node reads.
// An object access is a file's (Filesystem) or a registry key's
// (Registry), and a rule may be about either.
func InModel(node, model string) bool {
	if node == "ObjectAccess" {
		return model == "Filesystem" || model == "Registry"
	}
	return strings.EqualFold(model, NodeModel[node])
}

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
		inModel := InModel(r.Node, model)
		if got := inModel && Eval(r.Where, View(doc)); got != c.Expect {
			errs = append(errs, fmt.Errorf("%s: the Splunk rule says %v for %s", where, got, sigmacheck.String(View(doc))))
			continue
		}
		if datamodel != "" && !strings.EqualFold(model, datamodel) || !inModel {
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
