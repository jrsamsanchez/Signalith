package sigmacheck

import (
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/ingest"
	"github.com/jrsamsanchez/signalith/internal/query"
)

// A repeated case's copies are spread over RepeatSpan, each with its Vary
// fields numbered, and none of its joined events.
func TestCopies(t *testing.T) {
	one := Case{Data: map[string]string{"a": "b"}, Repeat: 1, Vary: []string{"a"}, With: []Case{{}}, Then: []Case{{}}}
	cs, at := one.Copies()
	if len(cs) != 1 || at[0] != 0 || cs[0].Vary != nil || cs[0].Repeat != 0 || cs[0].With != nil || cs[0].Then != nil {
		t.Errorf("once = %+v %v", cs, at)
	}
	c := Case{Data: map[string]string{"User": "tester", "Computer": "WS$", "Other": "x"}, Repeat: 3,
		Vary: []string{"User", "Computer"}, Baseline: []Case{{}}}
	cs, at = c.Copies()
	if len(cs) != 3 {
		t.Fatalf("copies = %+v", cs)
	}
	for i, cp := range cs {
		n := string(rune('1' + i))
		if cp.Data["User"] != "tester"+n || cp.Data["Computer"] != "WS"+n+"$" || cp.Data["Other"] != "x" {
			t.Errorf("copy %d = %v", i, cp.Data)
		}
		if cp.Repeat != 0 || cp.Vary != nil || cp.Baseline != nil {
			t.Errorf("copy %d keeps its repeat: %+v", i, cp)
		}
		if want := RepeatSpan * time.Duration(i) / 3; at[i] != want {
			t.Errorf("copy %d at %v, want %v", i, at[i], want)
		}
	}
	if c.Data["User"] != "tester" {
		t.Error("copies changed the case's data")
	}
}

// Each channel's events are seen by Sigma's field names.
func TestSigmaView(t *testing.T) {
	data := map[string]string{"k": "v"}
	for _, c := range []struct {
		c    Case
		want map[string]string
	}{
		{Case{Channel: "zeek:dns", Data: data}, map[string]string{"k": "v"}},
		{Case{Channel: WebChannel, Data: map[string]string{"url": "/a/b?q=1", "http_method": "POST"}},
			map[string]string{"cs-uri-query": "/a/b?q=1", "c-uri": "/a/b?q=1", "cs-uri": "/a/b?q=1", "cs-uri-stem": "/a/b", "cs-method": "POST"}},
		{Case{Channel: CloudTrailChannel, Data: data}, map[string]string{"k": "v"}},
		{Case{Channel: GitHubChannel, Data: data}, map[string]string{"k": "v"}},
		{Case{Channel: MacOSChannel, Data: map[string]string{"path": "/bin/ls", "junk": "x"}}, map[string]string{"Image": "/bin/ls"}},
		{Case{Channel: AuditdChannel, EventID: "EXECVE", Data: map[string]string{"a0": "ls"}}, map[string]string{"type": "EXECVE", "a0": "ls"}},
		{Case{Channel: SysmonChannel, EventID: "1", Data: data}, map[string]string{"EventID": "1", "k": "v"}},
		{Case{Channel: PowerShellChannel, EventID: "4104", Data: data}, map[string]string{"EventID": "4104", "k": "v"}},
		{Case{Channel: DefenderChannel, EventID: "1116", Data: data}, map[string]string{"EventID": "1116", "k": "v"}},
		{Case{Channel: ApplicationChannel, EventID: "1000", Data: data}, map[string]string{"EventID": "1000", "k": "v"}},
		{Case{Channel: ingest.NamedChannelServices["wmi"], EventID: "5858", Data: data}, map[string]string{"EventID": "5858", "k": "v"}},
		{Case{Channel: SystemChannel, EventID: "7045", Data: data},
			map[string]string{"EventID": "7045", "k": "v", "Provider_Name": ingest.ServiceControlManager}},
		{Case{Channel: SystemChannel, EventID: "7045", Data: map[string]string{"Provider_Name": "Other"}},
			map[string]string{"EventID": "7045", "Provider_Name": "Other"}},
		{Case{Channel: SecurityChannel, EventID: "4688", Data: map[string]string{"NewProcessName": `C:\a.exe`, "SubjectUserName": "x"}},
			map[string]string{"EventID": "4688", "Image": `C:\a.exe`}},
		{Case{Channel: SecurityChannel, EventID: "4624", Data: data}, map[string]string{"EventID": "4624", "k": "v"}},
	} {
		got, ok := c.c.SigmaView()
		if !ok || !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s %s: %v %v, want %v", c.c.Channel, c.c.EventID, got, ok, c.want)
		}
	}
	for _, c := range []Case{
		{Channel: SecurityChannel, EventID: "9999"},
		{Channel: PowerShellChannel, EventID: "1"},
		{Channel: "Unknown"},
		{Channel: AuditdChannel, Data: map[string]string{"_raw": "not an audit line"}},
	} {
		if v, ok := c.SigmaView(); ok {
			t.Errorf("%s %s has a view: %v", c.Channel, c.EventID, v)
		}
	}
	// A recorded audit line is read by the real parser.
	line := ingest.AuditdLine("EXECVE", time.Now().Add(-time.Hour), map[string]string{"argc": "1", "a0": "id"})
	v, ok := Case{Channel: AuditdChannel, EventID: "EXECVE", Data: map[string]string{"_raw": line}}.SigmaView()
	if !ok || v["a0"] != "id" || v["type"] != "EXECVE" {
		t.Errorf("recorded audit line: %v %v", v, ok)
	}
}

// Each channel's records reach the real parser with its own tag and land
// in the data model its parser gives them.
func TestRecordAndStored(t *testing.T) {
	now := time.Now().Add(-time.Hour)
	for _, c := range []struct {
		c     Case
		tag   string
		model string
	}{
		{Case{Channel: SysmonChannel, EventID: "1", Data: map[string]string{"Image": `C:\Windows\cmd.exe`}}, "win.events", "Endpoint"},
		{Case{Channel: LinuxSysmonChannel, EventID: "1", Data: map[string]string{"Image": "/usr/bin/id"}}, "linux.journal", "Endpoint"},
		{Case{Channel: AuditdChannel, EventID: "EXECVE", Data: map[string]string{"argc": "1", "a0": "id"}}, "linux.audit", ""},
		{Case{Channel: WebChannel, EventID: "access", Data: map[string]string{"url": "/x", "http_method": "GET", "status": "200"}}, ingest.WebTag, "Web"},
		{Case{Channel: CloudTrailChannel, Data: map[string]string{"eventName": "ConsoleLogin", "eventSource": "signin.amazonaws.com"}}, ingest.CloudTrailTag, "Authentication"},
		{Case{Channel: CloudTrailChannel, Data: map[string]string{"_raw": `{"eventName":"ConsoleLogin","eventSource":"signin.amazonaws.com","eventTime":"` + now.UTC().Format(time.RFC3339) + `"}`}}, ingest.CloudTrailTag, "Authentication"},
		{Case{Channel: AzureChannel, EventID: "signinlogs", Data: map[string]string{"ResultType": "50126"}}, ingest.AzureTag, ""},
		{Case{Channel: O365Channel, Data: map[string]string{"Operation": "UserLoggedIn"}}, ingest.O365Tag, ""},
		{Case{Channel: GCPChannel, Data: map[string]string{"gcp.audit.method_name": "SetIamPolicy"}}, ingest.GCPTag, ""},
		{Case{Channel: WorkspaceChannel, Data: map[string]string{"eventName": "login_success"}}, ingest.GCPTag, ""},
		{Case{Channel: OktaChannel, Data: map[string]string{"eventType": "user.session.start"}}, ingest.OktaTag, ""},
		{Case{Channel: KubernetesChannel, Data: map[string]string{"verb": "create"}}, ingest.KubernetesTag, ""},
		{Case{Channel: GitHubChannel, Data: map[string]string{"action": "repo.destroy"}}, ingest.GitHubTag, ""},
		{Case{Channel: MacOSChannel, EventID: "exec", Data: map[string]string{"path": "/bin/ls", "cmdline": "ls"}}, OsqueryTag, "Endpoint"},
	} {
		tag, rec := c.c.Record("host-1", now)
		if tag != c.tag || rec == nil {
			t.Errorf("%s: tag %q, want %q (%v)", c.c.Channel, tag, c.tag, rec)
			continue
		}
		ev := c.c.Stored("host-1", now)
		if c.model != "" && ev.Model != c.model {
			t.Errorf("%s: model %q, want %q: %v", c.c.Channel, ev.Model, c.model, ev.Fields)
		}
	}
	// A recorded cloud record that is not JSON is sent as a message.
	tag, rec := Case{Channel: OktaChannel, Data: map[string]string{"_raw": "not json"}}.Record("host-1", now)
	if tag != ingest.OktaTag || rec["message"] != "not json" || rec["hostname"] != "host-1" {
		t.Errorf("raw okta: %s %v", tag, rec)
	}
	// A macOS row the parser does not read is no data model's event.
	ev := Case{Channel: MacOSChannel, Data: nil}.Stored("mbp", now)
	if ev.Model != "" || ev.Fields["host"] != "mbp" {
		t.Errorf("empty macOS row: %s %v", ev.Model, ev.Fields)
	}
}

// The categories' channels, events and the derived categories.
func TestCategories(t *testing.T) {
	for cat, want := range map[string]string{
		"ps_script": PowerShellChannel, "ps_module": PowerShellChannel, "powershell_classic": WindowsPowerShellChannel,
		"ps_classic_start": WindowsPowerShellChannel, "system": SystemChannel, "system_event": SystemChannel,
		"application": ApplicationChannel, "code_integrity": CodeIntegrityChannel, "windefend": DefenderChannel,
		"webserver": WebChannel, "cloudtrail": CloudTrailChannel, "m365": O365Channel, ingest.GCPService: GCPChannel,
		ingest.OktaService: OktaChannel, ingest.KubernetesService: KubernetesChannel, ingest.GitHubService: GitHubChannel,
		"signinlogs": AzureChannel, ingest.WorkspaceServices[0]: WorkspaceChannel,
		"firewall_as": ingest.NamedChannelServices["firewall-as"], SecurityCategory("4624"): SecurityChannel,
		"process_creation": SysmonChannel,
	} {
		if got := Channel(cat); got != want {
			t.Errorf("Channel(%s) = %s, want %s", cat, got, want)
		}
	}
	if got := SecurityCategory("4656", "4663"); got != "security_4656_4663" {
		t.Errorf("SecurityCategory = %s", got)
	}
	if id, ok := SysmonEventID(SecurityCategory("4656", "4663")); !ok || id != "4663" {
		t.Errorf("group event = %s %v", id, ok)
	}
	if _, ok := SysmonEventID("nope"); ok {
		t.Error("unknown category has an event")
	}
	if got := SysmonEventIDs("registry_event"); !reflect.DeepEqual(got, []string{"13", "12", "14"}) {
		t.Errorf("registry_event IDs = %v", got)
	}
	if got := SysmonEventIDs("process_creation"); !reflect.DeepEqual(got, []string{"1"}) {
		t.Errorf("process_creation IDs = %v", got)
	}
	if SysmonEventIDs("nope") != nil {
		t.Error("unknown category has IDs")
	}
	for _, c := range []struct {
		ids  []string
		want string
	}{{nil, "sysmon_event"}, {[]string{"27", "29"}, "sysmon_file_block"}, {[]string{"27", "16"}, "sysmon_event"}} {
		if got := SysmonServiceCategory(c.ids...); got != c.want {
			t.Errorf("SysmonServiceCategory(%v) = %s", c.ids, got)
		}
	}
	for _, c := range []struct {
		ids  []string
		want string
	}{{nil, "system"}, {[]string{"7045", "7036"}, "system"}, {[]string{"7036"}, "system_event"}} {
		if got := SystemCategory(c.ids...); got != c.want {
			t.Errorf("SystemCategory(%v) = %s", c.ids, got)
		}
	}
}

// Synthesized events become cases on the category's channel, with a
// Security 4688 copy of a process creation 4688 carries.
func TestCasesOn(t *testing.T) {
	syn := &Synthesis{
		Positive: []map[string]string{{"Image": `C:\a.exe`, "CommandLine": "a"}},
		Negative: []map[string]string{{"Image": `C:\b.exe`}},
	}
	cs := Cases("process_creation", syn, []string{"Image", "CommandLine"})
	if len(cs) != 4 || cs[0].Channel != SysmonChannel || cs[1].Channel != SecurityChannel || cs[1].EventID != "4688" ||
		cs[1].Data["NewProcessName"] != `C:\a.exe` || !cs[1].Expect || cs[3].Expect {
		t.Errorf("process cases = %+v", cs)
	}
	// A field 4688 lacks keeps them Sysmon events only.
	if cs := Cases("process_creation", syn, []string{"Image", "Hashes"}); len(cs) != 2 {
		t.Errorf("with Hashes: %+v", cs)
	}
	if cs := LinuxCases("process_creation", syn, nil); len(cs) != 2 || cs[0].Channel != LinuxSysmonChannel {
		t.Errorf("linux = %+v", cs)
	}
	if Cases("nope", syn, nil) != nil {
		t.Error("cases of an unknown category")
	}

	// A rule naming event IDs: each event is one, and a near miss without
	// one is dropped, as is a legacy Security event.
	ids := &Synthesis{
		Positive: []map[string]string{{"EventID": "4624", "LogonType": "3"}, {"EventID": "528"}},
		Negative: []map[string]string{{"LogonType": "3"}},
	}
	cs = Cases(SecurityCategory("4624"), ids, []string{"EventID", "LogonType"})
	if len(cs) != 1 || cs[0].EventID != "4624" || cs[0].Data["EventID"] != "" || ids.Positive[0]["EventID"] != "4624" {
		t.Errorf("security cases = %+v", cs)
	}
	// A System log near miss without its provider is dropped too.
	sys := &Synthesis{Positive: []map[string]string{{"Provider_Name": "x"}}, Negative: []map[string]string{{"ServiceName": "y"}}}
	if cs := Cases("system", sys, []string{"Provider_Name"}); len(cs) != 1 || cs[0].EventID != "7045" {
		t.Errorf("system cases = %+v", cs)
	}
	// A web request's W3C fields become the Web data model's.
	web := &Synthesis{Positive: []map[string]string{{"cs-uri-stem": "/admin", "cs-method": "GET"}, {"cs-uri-query": "/a?b", "cs-uri-stem": "/a"}}}
	cs = Cases("webserver", web, nil)
	if len(cs) != 2 || cs[0].Channel != WebChannel || cs[0].Data["url"] != "/admin" || cs[0].Data["http_method"] != "GET" ||
		cs[1].Data["url"] != "/a?b" || cs[0].Data["uri_path"] != "" {
		t.Errorf("web cases = %+v", cs)
	}
}

// An audit rule's events are records of the type it names, or EXECVE when
// it names arguments, with the arguments before the highest filled in.
func TestAuditdCases(t *testing.T) {
	syn := &Synthesis{
		Positive: []map[string]string{{"a2": "-rf", "exe": "/bin/rm"}, {"type": "path", "name": "/etc/shadow"}, {"comm": "x"}},
		Negative: []map[string]string{{"a10x": "y"}},
	}
	cs := AuditdCases("auditd", syn, []string{"a2", "type"})
	if len(cs) != 3 {
		t.Fatalf("cases = %+v", cs)
	}
	if c := cs[0]; c.EventID != "EXECVE" || c.Data["a0"] != "arg" || c.Data["a1"] != "arg" || c.Data["a2"] != "-rf" || c.Data["argc"] != "3" || !c.Expect {
		t.Errorf("execve = %+v", c)
	}
	if c := cs[1]; c.EventID != "PATH" || c.Data["type"] != "" || c.Data["name"] != "/etc/shadow" {
		t.Errorf("path = %+v", c)
	}
	if c := cs[2]; c.EventID != "SYSCALL" {
		t.Errorf("syscall = %+v", c)
	}
	// Without type among the rule's fields, a near miss keeps its record.
	cs = AuditdCases("auditd", syn, nil)
	if len(cs) != 4 || cs[3].EventID != "SYSCALL" || cs[3].Expect {
		t.Errorf("near miss = %+v", cs)
	}
	for k, want := range map[string]int{"a0": 0, "a12": 12} {
		if n, ok := auditArg(k); !ok || n != want {
			t.Errorf("auditArg(%s) = %d %v", k, n, ok)
		}
	}
	for _, k := range []string{"a", "b1", "a1b", "argc"} {
		if _, ok := auditArg(k); ok {
			t.Errorf("auditArg(%s) is an argument", k)
		}
	}
}

// Verify finds every way a detection and the rule disagree.
func TestVerify(t *testing.T) {
	r := mustParse(t, `title: t
id: 00000000-0000-0000-0000-000000000002
logsource: {category: process_creation, product: windows}
detection:
  sel:
    Image|endswith: '\cmd.exe'
    CommandLine|contains: 'whoami'
  condition: sel
`)
	good, err := query.Parse(`process_name="cmd.exe" process="*whoami*"`)
	if err != nil {
		t.Fatal(err)
	}
	pos := Case{Expect: true, Source: "synthesized", Channel: SysmonChannel, EventID: "1",
		Data: map[string]string{"Image": `C:\Windows\System32\cmd.exe`, "CommandLine": "cmd /c whoami"}}
	neg := Case{Expect: false, Source: "synthesized", Channel: SysmonChannel, EventID: "1",
		Data: map[string]string{"Image": `C:\Windows\System32\cmd.exe`, "CommandLine": "cmd /c dir"}}
	tf := &TestFile{Rule: r.ID, Cases: []Case{pos, neg}}
	if errs := Verify(r, "Endpoint", good.Search, tf); len(errs) != 0 {
		t.Errorf("good detection: %v", errs)
	}

	// A detection that ignores the command line matches the negative.
	loose, _ := query.Parse(`process_name="cmd.exe"`)
	errs := Verify(r, "Endpoint", loose.Search, tf)
	if len(errs) != 1 || !strings.Contains(errs[0].Error(), "case 1") || !strings.Contains(errs[0].Error(), "the detection says true") {
		t.Errorf("loose detection: %v", errs)
	}

	wrong := pos
	wrong.Expect = false
	noView := Case{Expect: true, Channel: "Unknown"}
	other := pos
	other.Channel, other.EventID = WebChannel, "access"
	other.Data = map[string]string{"url": "/whoami", "http_method": "GET", "status": "200"}
	kw := mustParse(t, "title: k\ndetection:\n  keywords: [x]\n  condition: keywords\n")
	errs = Verify(r, "Endpoint", good.Search, &TestFile{Cases: []Case{wrong, noView}})
	if len(errs) != 2 || !strings.Contains(errs[0].Error(), "the Sigma rule says true") || !strings.Contains(errs[1].Error(), "no Sigma view") {
		t.Errorf("rule disagreements: %v", errs)
	}
	if errs := Verify(kw, "", good.Search, &TestFile{Cases: []Case{pos}}); len(errs) != 1 || !strings.Contains(errs[0].Error(), "Sigma:") {
		t.Errorf("keyword rule: %v", errs)
	}
	// An event of another data model: wrong only for a positive.
	webRule := mustParse(t, "title: t\ndetection:\n  sel: {cs-uri-query|contains: whoami}\n  condition: sel\n")
	errs = Verify(webRule, "Endpoint", good.Search, &TestFile{Cases: []Case{other}})
	if len(errs) != 1 || !strings.Contains(errs[0].Error(), "the parser put the event in Web") {
		t.Errorf("other data model: %v", errs)
	}
	// A filter the matcher cannot evaluate is an error of its own.
	bad := &query.Compare{Field: "process_name", Op: "~~", Value: "x"}
	if errs := Verify(r, "", bad, &TestFile{Cases: []Case{pos}}); len(errs) != 1 {
		t.Errorf("bad filter: %v", errs)
	}
}

// A test file survives its one-case-per-line encoding.
func TestTestFileRoundTrip(t *testing.T) {
	tf := &TestFile{Rule: "r-1", Cases: []Case{
		{Expect: true, Source: "synthesized", Channel: SysmonChannel, EventID: "1", Data: map[string]string{"Image": "a"}, Repeat: 3, Vary: []string{"Image"}},
		{Expect: false, Source: "sigmahq", Channel: SecurityChannel, EventID: "4624", Data: map[string]string{"LogonType": "3"},
			Then: []Case{{Channel: SecurityChannel, EventID: "4625"}}, Later: 5},
	}}
	b, err := EncodeTestFile(tf)
	if err != nil {
		t.Fatal(err)
	}
	if lines := strings.Count(string(b), "\n"); lines != 4 {
		t.Errorf("%d lines:\n%s", lines, b)
	}
	got, err := DecodeTestFile(b)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, tf) {
		t.Errorf("round trip = %+v", got)
	}
	empty, err := EncodeTestFile(&TestFile{Rule: "x"})
	if err != nil || string(empty) != "{\"rule\": \"x\", \"cases\": [\n]}\n" {
		t.Errorf("empty = %q %v", empty, err)
	}
	if _, err := DecodeTestFile([]byte("{")); err == nil {
		t.Error("decoded bad JSON")
	}
	if !slices.Contains(SecurityEvents, "4624") {
		t.Error("4624 is not a Security event")
	}
}
