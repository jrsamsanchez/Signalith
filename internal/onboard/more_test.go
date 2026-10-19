package onboard

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/detect"
	"github.com/jrsamsanchez/signalith/internal/ingest"
	"github.com/jrsamsanchez/signalith/internal/syslog"
)

// TestCheckEveryProblem: one call names each problem a parser has.
func TestCheckEveryProblem(t *testing.T) {
	var maps []Mapping
	for i := range MaxMappings + 1 {
		maps = append(maps, Mapping{From: "f" + strconv.Itoa(i), To: "user"})
	}
	maps = append(maps, Mapping{From: "bad name", To: "user"})
	var apps []string
	for i := range MaxSyslogApps + 1 {
		apps = append(apps, "app"+strings.Repeat("a", i))
	}
	kv := Parser{Name: "ok-name", Sourcetype: "acme:x", Model: "Authentication", Format: FormatKV, KVSeparator: "=", Delimiter: "#",
		Description: strings.Repeat("d", MaxDescription+1), VendorProduct: strings.Repeat("v", 129), Mappings: maps, SyslogApps: apps}
	err := kv.Validate()
	for _, want := range []string{"description can be at most", "product name can be at most", "Pairs are separated", "rename at most", `"bad name" is not a valid field name`, "syslog programs"} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("missing %q in %v", want, err)
		}
	}
	var in *InputError
	if !errors.As(err, &in) {
		t.Errorf("not an InputError: %T", err)
	}

	cols := make([]string, MaxColumns+1)
	for i := range cols {
		cols[i] = "c" + strconv.Itoa(i)
	}
	cols = append(cols, "", "bad name", "c1")
	csv := Parser{Name: "ok-name", Sourcetype: "acme:x", Model: "Other", Format: FormatCSV, Delimiter: ",", Columns: cols}
	err = csv.Validate()
	for _, want := range []string{"at most 128 columns", `"bad name" is not a valid field name`, `"c1" is used twice`} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("missing %q in %v", want, err)
		}
	}

	// Normalize fills the separators a format needs.
	p := Parser{Name: " Acme ", Format: " KV "}
	p.Normalize()
	if p.Name != "acme" || p.KVSeparator != "=" || p.Tag() != "custom.acme" {
		t.Errorf("kv normalized %+v %s", p, p.Tag())
	}
	p = Parser{Format: "csv"}
	p.Normalize()
	if p.Delimiter != "," {
		t.Errorf("csv delimiter %q", p.Delimiter)
	}
}

func TestCompilePatternErrors(t *testing.T) {
	for pattern, want := range map[string]string{
		"   ":                             "Write a regular expression",
		"(?P<a>x":                         "does not compile",
		"(?P<a>x){1,200}":                 "at most 100",
		"(?P<datamodel>x)":                "not a valid field name",
		"x+":                              "at least one named group",
		strings.Repeat("x", MaxPattern+1): "at most 2000 characters",
	} {
		if _, err := compilePattern(pattern); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%.20q = %v, want %q", pattern, err, want)
		}
	}
	if _, err := Compile(Parser{Sourcetype: "x", Model: "Other", Format: FormatRegex, Pattern: "x+"}); err == nil {
		t.Error("compiled a pattern with no groups")
	}
}

// TestParseRecordStructured: a record with no line is read as JSON,
// flattened for a JSON parser and kept as text for another.
func TestParseRecordStructured(t *testing.T) {
	at := time.Now().Add(-time.Hour)
	c, err := Compile(Parser{Sourcetype: "acme:api", Model: "Authentication", Format: FormatJSON, Mappings: []Mapping{{From: "who", To: "user"}}})
	if err != nil {
		t.Fatal(err)
	}
	rec := map[string]any{"who": "bob", "n": 3, "list": []any{1, 2}, "skip": nil,
		"a": map[string]any{"b": map[string]any{"c": map[string]any{"d": map[string]any{"e": 1}}}}}
	ev, drop := c.ParseRecord(rec, at)
	if drop || ev.Fields["user"] != "bob" || ev.Fields["list"] != "[1,2]" || ev.Fields["a.b.c.d"] != `{"e":1}` || ev.Fields["sourcetype"] != "acme:api" {
		t.Errorf("json record = %v %v", ev.Fields, drop)
	}
	if _, ok := ev.Fields["skip"]; ok {
		t.Error("a null value was kept")
	}
	if !strings.Contains(ev.Fields["message"].(string), `"who":"bob"`) {
		t.Errorf("message = %v", ev.Fields["message"])
	}

	text, _ := Compile(Parser{Sourcetype: "acme:api", Model: "Other", Format: FormatText})
	ev, _ = text.ParseRecord(map[string]any{"x": "y"}, at)
	if ev.Fields["message"] != `{"x":"y"}` {
		t.Errorf("text record = %v", ev.Fields)
	}

	// JSON numbers: integers, decimals and ones too large for either.
	ev, _ = c.ParseLine(`{"i": 7, "f": 1.5, "big": 1e400, "who": "amy"}`, at)
	if ev.Fields["i"] != int64(7) || ev.Fields["f"] != 1.5 || ev.Fields["big"] != "1e400" {
		t.Errorf("numbers = %#v", ev.Fields)
	}

	// Many fields stop at maxFields.
	big := map[string]any{}
	for i := range maxFields + 20 {
		big["k"+strings.Repeat("x", i)] = "v"
	}
	f := map[string]any{}
	flatten(f, "", big, 0)
	if len(f) != maxFields {
		t.Errorf("flattened %d fields", len(f))
	}
	b, _ := json.Marshal(big)
	if ev, _ := c.ParseLine(string(b), at); len(ev.Fields) > maxFields+3 {
		t.Errorf("a line gave %d fields", len(ev.Fields))
	}
	var line strings.Builder
	for i := range maxFields + 20 {
		line.WriteString("k" + strings.Repeat("x", i) + "=v ")
	}
	kv, _ := Compile(Parser{Sourcetype: "x", Model: "Other", Format: FormatKV})
	if ev, _ := kv.ParseLine(line.String(), at); len(ev.Fields) > maxFields+3 {
		t.Errorf("a kv line gave %d fields", len(ev.Fields))
	}
}

func TestFinishNames(t *testing.T) {
	at := time.Now().Add(-time.Hour)
	c, _ := Compile(Parser{Sourcetype: "x", Model: "Authentication", Format: FormatJSON, Mappings: []Mapping{{From: "a_b", To: "user"}}})
	// "a b" becomes a_b and is renamed; "@@" is no name; "9x" gains an f;
	// "a..b" loses a dot; a second user is not kept over the first; a
	// field Signalith sets is dropped.
	ev := c.finish(map[string]any{"a b": "bob", "--": "x", "9 x": "y", "a..b": "z", "datamodel": "main"}, "raw", time.Time{}, "", "", at)
	if ev.Fields["user"] != "bob" || ev.Fields["f9_x"] != "y" || ev.Fields["a.b"] != "z" {
		t.Errorf("fields = %v", ev.Fields)
	}
	for _, k := range []string{"--", "", "datamodel"} {
		if _, ok := ev.Fields[k]; ok {
			t.Errorf("%q kept", k)
		}
	}
	ev = c.finish(map[string]any{"user": "amy", "a_b": "bob"}, "raw", time.Time{}, "", "", at)
	if ev.Fields["user"] != "amy" && ev.Fields["user"] != "bob" {
		t.Errorf("user = %v", ev.Fields["user"])
	}
	if got := SanitizeName("--"); got != "" {
		t.Errorf("SanitizeName(--) = %q", got)
	}
	// A CSV delimiter that is no rune, and a row the reader refuses.
	if got := csvRow("a,b", "\xff"); len(got) != 2 {
		t.Errorf("csvRow = %v", got)
	}
	if got := csvRow("", ","); len(got) != 1 {
		t.Errorf("csvRow empty = %v", got)
	}
}

// TestMatchDetectionsShapes: OR and NOT filters, sourcetype lists, and
// the order of what is listed.
func TestMatchDetectionsShapes(t *testing.T) {
	ds := []*detect.Detection{
		{ID: "or", Title: "B or", Query: `datamodel=Authentication (user=root OR app=ssh)`},
		{ID: "not", Title: "A not", Query: `datamodel=Authentication src=* NOT dest=x`},
		{ID: "in-ours", Title: "C in", Query: `datamodel=Authentication sourcetype IN ("acme:*", "other") src=*`},
		{ID: "in-theirs", Title: "D theirs", Query: `datamodel=Authentication sourcetype IN ("okta:*") src=*`},
		{ID: "src-in", Title: "E src in", Query: `datamodel=Authentication src IN (10.0.0.1, 10.0.0.2)`},
		{ID: "glob-mid", Title: "F mid", Query: `datamodel=Authentication sourcetype="ac*:v*n" src=*`},
		{ID: "glob-miss", Title: "G miss", Query: `datamodel=Authentication sourcetype="ac*:zz*q" src=*`},
		{ID: "glob-exact", Title: "H exact", Query: `datamodel=Authentication sourcetype="acme:vpn" src=*`},
		{ID: "two-missing", Title: "I two", Query: `datamodel=Authentication src=* reason=* signature=*`},
		{ID: "one-missing-a", Title: "J a", Query: `datamodel=Authentication src=* reason=*`},
		{ID: "one-missing-b", Title: "K b", Query: `datamodel=Authentication src=* reason=* user=*`},
		{ID: "one-missing-c", Title: "L c", Query: `datamodel=Authentication src=* signature=*`},
		{ID: "src-twice", Title: "M twice", Query: `datamodel=Authentication src=* src!=10.9.9.9`},
		{ID: "bad", Title: "bad", Query: `datamodel=Authentication (`},
	}
	docs := []map[string]any{{"user": "bob", "src": "10.0.0.1", "app": "vpn"}}
	cov := MatchDetections(ds, "Authentication", "acme:vpn", docs)
	ids := map[string]DetectionRef{}
	for _, d := range cov.List {
		ids[d.ID] = d
	}
	for _, id := range []string{"or", "not", "in-ours", "src-in", "glob-mid", "glob-exact", "src-twice"} {
		if _, ok := ids[id]; !ok {
			t.Errorf("%s not ready: %+v", id, cov.List)
		}
	}
	for _, id := range []string{"in-theirs", "glob-miss", "bad"} {
		if _, ok := ids[id]; ok {
			t.Errorf("%s listed", id)
		}
	}
	// Those that fire come first, then by title.
	if cov.List[0].Fires == 0 || ids["src-in"].Fires != 1 {
		t.Errorf("order %+v", cov.List)
	}
	for i := 1; i < len(cov.List); i++ {
		a, b := cov.List[i-1], cov.List[i]
		if (a.Fires > 0) == (b.Fires > 0) && a.Title > b.Title {
			t.Errorf("%s before %s", a.Title, b.Title)
		}
	}
	if len(cov.Partial) != 4 || len(cov.Partial[len(cov.Partial)-1].Missing) != 2 {
		t.Errorf("partial %+v", cov.Partial)
	}
	if len(cov.Unlock) != 2 || cov.Unlock[0] != (Unlock{Field: "reason", Count: 2}) || cov.Unlock[1] != (Unlock{Field: "signature", Count: 1}) {
		t.Errorf("unlock %+v", cov.Unlock)
	}

	for pattern, want := range map[string]bool{"abc": true, "ab": false, "a*": true, "*c": true, "a*x*c": false, "a*b*": true, "x*": false} {
		if globMatch(pattern, "abc") != want {
			t.Errorf("globMatch(%q) = %v", pattern, !want)
		}
	}
}

// TestInferShapes: the token kinds a free-text pattern is written from.
func TestInferShapes(t *testing.T) {
	if _, ok := inferPattern(nil); ok {
		t.Error("a pattern from no lines")
	}
	lines := []string{
		`acmed[211]: [core] conn 10.0.0.1:5000 -> 10.0.0.2:443 bytes 120 took 1.5 "GET / HTTP/1.1"`,
		`acmed[212]: [auth] conn 10.0.0.3:5001 -> 10.0.0.4:22 bytes 98 took 0.5 "GET /x HTTP/1.1"`,
		`acmed[213]: [core] conn 10.0.0.5:5002 -> 10.0.0.6:80 bytes 7 took 2.0 "GET /y HTTP/1.1"`,
	}
	inf, ok := inferPattern(lines)
	if !ok || inf.matched != 3 {
		t.Fatalf("inferred %+v %v", inf, ok)
	}
	re := regexp.MustCompile(inf.pattern)
	m := re.FindStringSubmatch(lines[1])
	got := map[string]string{}
	for i, n := range re.SubexpNames() {
		if n != "" {
			got[n] = m[i]
		}
	}
	if got["app"] != "acmed" || got["process_id"] != "212" {
		t.Errorf("program and pid from %s: %v", inf.pattern, got)
	}
	vals := strings.Join(func() []string {
		var out []string
		for _, v := range got {
			out = append(out, v)
		}
		return out
	}(), " ")
	for _, want := range []string{"auth", "10.0.0.3", "5001", "10.0.0.4", "22", "98", "0.5"} {
		if !strings.Contains(" "+vals+" ", " "+want+" ") {
			t.Errorf("no %q in %v (%s)", want, got, inf.pattern)
		}
	}

	// Lines of different lengths: the start lines up, the rest is detail.
	mixed := []string{
		"ERROR 12 disk full on sda",
		"WARN 13 cpu hot",
		"INFO 14 all good here today friends",
		"DEBUG 15 x",
	}
	inf, ok = inferPattern(mixed)
	if !ok || !strings.Contains(inf.pattern, "detail") {
		t.Fatalf("mixed %+v %v", inf, ok)
	}
	re = regexp.MustCompile(inf.pattern)
	for _, l := range mixed {
		if !re.MatchString(l) {
			t.Errorf("%q not read by %s", l, inf.pattern)
		}
	}
}

func TestFileStoreErrors(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.json")
	os.WriteFile(bad, []byte("{"), 0o600)
	st := NewFileStore(bad)
	if st.Err() == nil || !strings.Contains(st.Err().Error(), "bad.json") {
		t.Errorf("err = %v", st.Err())
	}
	err := st.Put(context.Background(), Parser{Name: "x1", Sourcetype: "x", Model: "Other", Format: FormatText}, "admin")
	if err == nil || !strings.Contains(err.Error(), "could not be read") {
		t.Errorf("put on an unread file = %v", err)
	}
	// A folder where the file belongs cannot be read or written.
	if _, err := ReadFile(dir); err == nil {
		t.Error("read a folder")
	}

	ok := NewFileStore(filepath.Join(dir, "p.json"))
	if ok.Err() != nil {
		t.Fatal(ok.Err())
	}
	// A file in the way of the write.
	os.Mkdir(filepath.Join(dir, "p.json"), 0o750)
	os.WriteFile(filepath.Join(dir, "p.json", "inside"), []byte("x"), 0o600)
	if err := ok.Put(context.Background(), Parser{Name: "x1", Sourcetype: "x", Model: "Other", Format: FormatText}, "admin"); err == nil {
		t.Error("wrote over a folder")
	}
	if len(ok.List()) != 0 {
		t.Error("a failed write was kept")
	}
}

func TestRegistryEdges(t *testing.T) {
	st := NewFileStore("")
	reg := NewRegistry(st)
	if reg.Store() != Store(st) {
		t.Error("Store")
	}
	at := time.Now().Add(-time.Hour)
	msg := func(s string) (*syslog.Message, *ingest.Event) {
		m := syslog.Parse([]byte(s), at)
		ev := m.Event(netip.MustParseAddr("192.0.2.1"), at, 0)
		return &m, &ev
	}
	// No parser names a program.
	m, ev := msg("<134>Oct 16 14:05:09 fw01 acmefw: user=bob")
	reg.Syslog(m, ev)
	if ev.Fields["user"] == "bob" {
		t.Error("parsed with no parsers")
	}

	ctx := context.Background()
	for _, p := range []Parser{
		{Name: "cef", Sourcetype: "x:cef", Model: "Other", Format: FormatCEF, SyslogApps: []string{"cefapp"}},
		{Name: "rx", Sourcetype: "x:rx", Model: "Other", Format: FormatRegex, Pattern: `user=(?P<user>\w+)`, SyslogApps: []string{"rxapp"}},
		{Name: "csv", Sourcetype: "x:csv", Model: "Other", Format: FormatCSV, Columns: []string{"user", "src"}, SyslogApps: []string{"csvapp"}},
	} {
		if err := st.Put(ctx, p, "admin"); err != nil {
			t.Fatal(err)
		}
	}
	m, ev = msg("<134>Oct 16 14:05:09 fw01 cefapp: user=bob")
	reg.Syslog(m, ev)
	if ev.Fields["sourcetype"] != "syslog" {
		t.Errorf("a CEF parser read plain syslog: %v", ev.Fields)
	}
	m, ev = msg("<134>Oct 16 14:05:09 fw01 rxapp: user=" + strings.Repeat("b", maxSyslogRegexInput+10))
	reg.Syslog(m, ev)
	if u, _ := ev.Fields["user"].(string); ev.Fields["sourcetype"] != "x:rx" || len(u) >= maxSyslogRegexInput {
		t.Errorf("regex syslog: %d %v", len(u), ev.Fields["sourcetype"])
	}
	// A CSV header line is no event: the message is left as it is.
	m, ev = msg("<134>Oct 16 14:05:09 fw01 csvapp: user,src")
	reg.Syslog(m, ev)
	if ev.Fields["sourcetype"] != "syslog" {
		t.Errorf("a header line was parsed: %v", ev.Fields)
	}
	// A line with a usable time takes it.
	when := at.Add(-time.Minute).UTC().Truncate(time.Second)
	st.Put(ctx, Parser{Name: "rx", Sourcetype: "x:rx", Model: "Other", Format: FormatRegex, Pattern: `user=(?P<user>\w+) when=(?P<when>\S+)`,
		SyslogApps: []string{"rxapp"}, TimeField: "when"}, "admin")
	m, ev = msg("<134>" + at.Format(time.Stamp) + " fw01 rxapp: user=amy when=" + when.Format(time.RFC3339))
	reg.Syslog(m, ev)
	if ev.Fields["user"] != "amy" || !ev.Time.Equal(when) {
		t.Errorf("timed syslog %v at %v, want %v", ev.Fields, ev.Time, when)
	}
}
