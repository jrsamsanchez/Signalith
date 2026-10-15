package splcheck

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// splunkPack is the built-in Splunk content pack, the source of seeds.
var splunkPack = filepath.Join("..", "detect", "packs", "splunk")

// fuzzMacros are the pack's macros and the tests' own.
func fuzzMacros(f *testing.F) map[string]*Macro {
	f.Helper()
	out := map[string]*Macro{}
	for k, v := range testMacros {
		out[k] = v
	}
	files, err := filepath.Glob(filepath.Join(splunkPack, "macros", "*.yml"))
	if err != nil || len(files) == 0 {
		f.Fatalf("no macros: %v", err)
	}
	for _, file := range files {
		src, err := os.ReadFile(file)
		if err != nil {
			f.Fatal(err)
		}
		m, err := ParseMacro(src)
		if err != nil {
			f.Fatalf("%s: %v", file, err)
		}
		out[m.Name] = m
	}
	return out
}

// fuzzRules returns about every n-th rule of the pack.
func fuzzRules(f *testing.F, n int) [][]byte {
	f.Helper()
	files, err := filepath.Glob(filepath.Join(splunkPack, "rules", "*.yml"))
	if err != nil || len(files) == 0 {
		f.Fatalf("no rules: %v", err)
	}
	slices.Sort(files)
	var out [][]byte
	for i := 0; i < len(files); i += max(len(files)/n, 1) {
		src, err := os.ReadFile(files[i])
		if err != nil {
			f.Fatal(err)
		}
		out = append(out, src)
	}
	return out
}

var fuzzSearches = []string{
	"| tstats `security_content_summariesonly` count from datamodel=Endpoint.Processes where\n`process_reg` AND Processes.process IN (\"*add*\", \"*HKCR\\\\*\",)\n```a comment with a ` in it```\nNOT Processes.user=\"SYSTEM\" Processes.parent_process_name!=explorer.exe\nby Processes.dest Processes.user\n| `drop_dm_object_name(Processes)`\n| `security_content_ctime(firstTime)`\n| `test_rule_filter`",
	"| tstats count min(_time) as firstTime from datamodel=Endpoint.Registry where Registry.registry_path=\"*\\\\Run\\\\*\" by Registry.dest _time span=1h | where count > 5 | `x_filter`",
	"| tstats count from datamodel=Network_Traffic.All_Traffic where All_Traffic.dest_port=445 All_Traffic.dest_ip=10.0.0.0/8 by All_Traffic.src_ip | where isnotnull(app)",
	"`sysmon` EventCode=10 TargetImage=*lsass.exe CallTrace=*dbgcore.dll* OR CallTrace=*dbghelp.dll* | stats count min(_time) as firstTime by dest | `x_filter`",
	"`wineventlog_security` EventCode=4698 | xmlkv Message | search Command IN (\"*powershell*\") | stats count by dest",
	"`linux_auditd` type=EXECVE a0=useradd | rename host as dest | stats count by dest",
	"| tstats count from datamodel=Endpoint.Processes where Processes.process_name=cmd.exe by Processes.dest | regex process=\"(?i)\\s/c\\s\" | where match(process_name, \"^c\")",
	"| tstats count from datamodel=Endpoint.Filesystem where Filesystem.file_path=\"*\\\\temp\\\\*\" by Filesystem.dest | eval x=bitand(1,2) | where x>0",
}

// FuzzParse checks that Parse never panics or hangs on a detection, and
// that a rule it accepts can be evaluated.
func FuzzParse(f *testing.F) {
	macros := fuzzMacros(f)
	for _, src := range fuzzRules(f, 20) {
		f.Add(src)
	}
	for _, s := range fuzzSearches {
		f.Add(rule(s))
	}
	ev := map[string]string{"process_name": "reg.exe", "process": `reg add HKCR\x`, "user": "alice", "dest": "10.1.2.3"}
	f.Fuzz(func(t *testing.T, src []byte) {
		r, err := Parse(src, macros)
		if err != nil {
			return
		}
		if r.Where == nil {
			t.Fatalf("Parse(%q) has no where clause", src)
		}
		Eval(r.Where, ev)
	})
}

// FuzzParseWhere checks a where clause on its own, over each node.
func FuzzParseWhere(f *testing.F) {
	macros := fuzzMacros(f)
	for _, s := range []string{
		"`process_reg` AND Processes.process IN (\"*add*\", \"*HKCR\\\\*\",) NOT Processes.user=\"SYSTEM\" Processes.parent_process_name!=explorer.exe",
		`(Processes.process_name=a.exe OR Processes.original_file_name="b \" \= \\ c") AND NOT (Processes.process=*x* Processes.process=*\\users\\public\\*)`,
		`Registry.registry_path="*\\Run\\*" Registry.registry_value_data=1`,
		`All_Traffic.dest_ip=10.0.0.0/8 All_Traffic.dest_port IN (445, 139) All_Traffic.app=*\\svchost.exe`,
		"`powershell` Processes.process=*-enc*",
		`Processes.process=a\/b`, `Processes.process<1`, `Processes.x=`,
	} {
		f.Add(s, "Processes")
	}
	nodes := []string{"Processes", "Filesystem", "Registry", "All_Traffic"}
	ev := map[string]string{"process_name": "reg.exe", "process": `reg add HKCR\x`, "user": "alice", "dest": "10.1.2.3"}
	f.Fuzz(func(t *testing.T, s, node string) {
		if !slices.Contains(nodes, node) {
			node = nodes[len(node)%len(nodes)]
		}
		e, err := ParseWhere(s, node, macros)
		if err != nil {
			return
		}
		if e == nil {
			t.Fatalf("ParseWhere(%q) = nil", s)
		}
		Eval(e, ev)
	})
}
