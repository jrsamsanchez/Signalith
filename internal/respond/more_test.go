package respond

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/jrsamsanchez/signalith/internal/store"
	"github.com/jrsamsanchez/signalith/internal/users"
)

func fields(ps []Problem) string {
	var out []string
	for _, p := range ps {
		out = append(out, p.Field)
	}
	return strings.Join(out, ",")
}

func TestProblemsOfEachSetting(t *testing.T) {
	good := func() Connector {
		c := hookAction("http://127.0.0.1:1")
		c.Normalize()
		return c
	}
	if p := func() []Problem { c := good(); return c.Problems() }(); len(p) != 0 {
		t.Fatalf("good action has problems: %v", p)
	}
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("x")}))
	badCert := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("not der")}))
	many := map[string]string{}
	for i := range 21 {
		many[fmt.Sprintf("X-H%d", i)] = "v"
	}
	cases := []struct {
		name   string
		change func(c *Connector)
		field  string
		msg    string
	}{
		{"label", func(c *Connector) { c.Label = strings.Repeat("l", 101) }, "label", "at most 100"},
		{"description", func(c *Connector) { c.Description = strings.Repeat("d", 501) }, "description", "at most 500"},
		{"target", func(c *Connector) { c.Target = "planet" }, "target", "choose what it acts on"},
		{"sealed password", func(c *Connector) { c.Password = "enc:v1:abc" }, "password", "encrypted values"},
		{"kind", func(c *Connector) { c.Kind = "email" }, "kind", "choose disable_user"},
		{"method", func(c *Connector) { c.Method = "TRACE" }, "method", "GET, POST"},
		{"no url", func(c *Connector) { c.URL = "" }, "url", "enter the URL"},
		{"long url", func(c *Connector) { c.URL = "http://x/" + strings.Repeat("a", 2000) + "{{.ip}}" }, "url", "at most 2000"},
		{"bad url template", func(c *Connector) { c.URL = "http://x/{{.ip" }, "url", ""},
		{"body format", func(c *Connector) { c.BodyFormat = "xml" }, "body_format", "json, form or text"},
		{"long body", func(c *Connector) { c.Body = strings.Repeat("b", 16<<10+1) }, "body", "at most 16 KB"},
		{"bad body template", func(c *Connector) { c.Body = "{{.ip" }, "body", ""},
		{"body not json", func(c *Connector) { c.Body = `{"a": {{.ip}}}` }, "body", "not valid JSON"},
		{"GET with body", func(c *Connector) { c.Method = "GET" }, "body", "a GET request has no body"},
		{"no target", func(c *Connector) { c.URL, c.Body = "http://x/a", "" }, "url", "use the target"},
		{"many headers", func(c *Connector) { c.Headers = many }, "headers", "at most 20 headers"},
		{"header name", func(c *Connector) { c.Headers = map[string]string{"Bad Header": "v"} }, "headers", "not a header name"},
		{"reserved header", func(c *Connector) { c.Headers = map[string]string{"Host": "v"} }, "headers", "sets Host itself"},
		{"auth twice", func(c *Connector) { c.Headers = map[string]string{"Authorization": "Bearer abcdef"} }, "headers", "not both"},
		{"header value", func(c *Connector) { c.Headers = map[string]string{"X-Key": "a\nb"} }, "headers", "one line"},
		{"username", func(c *Connector) { c.Username = "a:b" }, "username", "without a colon"},
		{"password only", func(c *Connector) { c.Username = "" }, "username", "enter the user name"},
		{"ca junk", func(c *Connector) { c.CACert = "junk\n" }, "ca_cert", "PEM form"},
		{"ca key", func(c *Connector) { c.CACert = keyPEM }, "ca_cert", "holds a private key"},
		{"ca bad cert", func(c *Connector) { c.CACert = badCert }, "ca_cert", "could not be read"},
	}
	for _, tc := range cases {
		c := good()
		tc.change(&c)
		ps := c.Problems()
		found := false
		for _, p := range ps {
			if p.Field == tc.field && strings.Contains(p.Message, tc.msg) {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: problems %v", tc.name, ps)
		}
	}

	user := Connector{Name: "dis", Kind: KindDisableUser, Target: TargetUser, Operation: OpDisable}
	if ps := user.Problems(); len(ps) != 0 {
		t.Fatalf("good disable_user: %v", ps)
	}
	for _, tc := range []struct {
		change func(c *Connector)
		want   string
	}{
		{func(c *Connector) { c.Operation = "toggle" }, "operation"},
		{func(c *Connector) { c.Target = TargetIP }, "target"},
		{func(c *Connector) { c.BindDN = "not a dn" }, "bind_dn"},
		{func(c *Connector) { c.BindDN = "CN=svc,DC=corp,DC=example" }, "bind_password"},
		{func(c *Connector) { c.BindDN, c.BindPassword = "CN=svc,DC=corp,DC=example", "enc:v2:xx" }, "bind_password"},
		{func(c *Connector) { c.DisableAttribute = "1bad" }, "disable_attribute"},
		{func(c *Connector) { c.DisableValue = strings.Repeat("v", 201) }, "disable_value"},
	} {
		c := user
		tc.change(&c)
		if got := fields(c.Problems()); got != tc.want {
			t.Errorf("disable_user problems = %q, want %q", got, tc.want)
		}
	}

	script := Connector{Name: "s", Kind: KindScript, Target: TargetHost, Program: "isolate.sh", TimeoutSeconds: 30}
	if ps := script.Problems(); len(ps) != 0 {
		t.Fatalf("good script: %v", ps)
	}
	for prog, want := range map[string]string{"": "enter the program", strings.Repeat("p", 501): "at most 500", "/bin/sh": "relative",
		"C:x.ps1": "relative", "a/../../x": ".. is not allowed"} {
		c := script
		c.Program = prog
		if ps := c.Problems(); len(ps) != 1 || !strings.Contains(ps[0].Message, want) {
			t.Errorf("program %q: %v", prog, ps)
		}
	}
	script.TimeoutSeconds = MaxScriptTimeout + 1
	if got := fields(script.Problems()); got != "timeout_seconds" {
		t.Errorf("timeout = %q", got)
	}
}

func TestRunRefusesBadRequests(t *testing.T) {
	ctx := context.Background()
	off := false
	tag := Connector{Name: "tag", Label: "Tag", Kind: KindHTTP, Target: TargetAny, Method: "POST", AllowLoopback: true, URL: "http://127.0.0.1:1/{{.target}}", Disruptive: &off}
	disabled := hookAction("http://127.0.0.1:1")
	disabled.Name, disabled.Enabled = "off", &off
	r, _ := runnerWith(t, hookAction("http://127.0.0.1:1"), tag, disabled)
	r.Log = slog.New(slog.DiscardHandler)
	actor := Actor{Name: "ann"}
	for _, tc := range []struct {
		req   Request
		field string
		msg   string
	}{
		{Request{Actor: actor}, "action", "choose an action"},
		{Request{Action: "block"}, "actor", "needs an actor"},
		{Request{Action: "off", Target: "203.0.113.7", Actor: actor}, "action", "turned off"},
		{Request{Action: "tag", Target: "203.0.113.7", TargetKind: "planet", Actor: actor}, "target_kind", "must be ip"},
		{Request{Action: "block", Target: "203.0.113.7", TargetKind: TargetUser, Actor: actor}, "target", "acts on a IP address, not a user name"},
		{Request{Action: "block", Target: "203.0.113.7", Reason: strings.Repeat("r", MaxReason+1), Actor: actor}, "reason", "at most"},
		{Request{Action: "block", Target: "203.0.113.7", Reason: "x", FindingID: "F\x00", Actor: actor}, "finding_id", "not valid"},
		{Request{Action: "block", Target: "203.0.113.7", Reason: "x", CaseID: strings.Repeat("c", 201), Actor: actor}, "case_id", "not valid"},
	} {
		_, err := r.Run(ctx, tc.req)
		var re *RequestError
		if !errors.As(err, &re) || re.Field != tc.field || !strings.Contains(re.Msg, tc.msg) {
			t.Errorf("%+v: %v", tc.req, err)
		}
	}
	if _, err := r.Run(ctx, Request{Action: "nope", Actor: actor}); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown action = %v", err)
	}
	// An action on anything takes the kind it is given, when it is one.
	run, err := r.Run(ctx, Request{Action: "tag", Target: "web01", TargetKind: TargetHost, Actor: Actor{Name: "pb", Automatic: true, ApprovedBy: "ann"}})
	if err != nil || run.TargetKind != TargetHost || !run.Automatic || run.Author() != "playbook pb" {
		t.Errorf("tag = %+v %v", run, err)
	}

	r.Store = nil
	_, err = r.Run(ctx, Request{Action: "block", Target: "203.0.113.7", Reason: "x", Actor: actor})
	var ae *AuditError
	if !errors.As(err, &ae) || !strings.HasPrefix(err.Error(), "The run could not be written to the audit log") || errors.Unwrap(err) == nil {
		t.Errorf("no store = %v", err)
	}
}

// failStore fails its first n Puts, or every Put after the first.
type failStore struct {
	Memory
	failFinal bool
	puts      int
}

func (f *failStore) Put(ctx context.Context, run *Run, done bool) error {
	f.puts++
	if f.failFinal && done {
		return errors.New("disk full")
	}
	return f.Memory.Put(ctx, run, done)
}

func TestRunFinalRecordFails(t *testing.T) {
	k := newHook(t, func(w http.ResponseWriter, _ *http.Request) {})
	r, _ := runnerWith(t, hookAction(k.srv.URL))
	fs := &failStore{failFinal: true}
	r.Store = fs
	r.Log = slog.New(slog.DiscardHandler)
	run, err := r.Run(context.Background(), Request{Action: "block", Target: "203.0.113.7", Reason: "x", Actor: Actor{Name: "ann"}})
	if err != nil || run.Status != StatusSucceeded || len(run.RecordErrors) != 1 || !strings.Contains(run.RecordErrors[0], "disk full") {
		t.Errorf("run = %+v %v", run, err)
	}
}

func TestDescribe(t *testing.T) {
	r := &Runner{}
	dis := Connector{Kind: KindDisableUser, Operation: OpDisable}
	if got := r.Describe(dis, "jdoe"); got != "Disable the directory account of jdoe." {
		t.Errorf("no directory: %q", got)
	}
	r.Directory = func() users.LDAPSettings {
		return users.LDAPSettings{Type: users.TypeActiveDirectory, UserBaseDN: "OU=People,DC=corp,DC=example,DC=com"}
	}
	if got := r.Describe(dis, "jdoe"); got != "Disable the AD account of jdoe in corp.example.com." {
		t.Errorf("AD: %q", got)
	}
	r.Directory = func() users.LDAPSettings { return users.LDAPSettings{Type: users.TypeOpenLDAP} }
	dis.Operation = OpEnable
	if got := r.Describe(dis, "jdoe"); got != "Enable the directory account of jdoe." {
		t.Errorf("OpenLDAP enable: %q", got)
	}
	h := Connector{Kind: KindHTTP, Method: "PUT", URL: "https://fw.example:8443/api/{{.ip}}"}
	if got := r.Describe(h, "1.2.3.4"); got != "Send PUT to fw.example:8443 for 1.2.3.4." {
		t.Errorf("http: %q", got)
	}
	s := Connector{Kind: KindScript, Program: "isolate.ps1"}
	if got := r.Describe(s, "web01"); got != "Run isolate.ps1 on this Signalith server with web01." {
		t.Errorf("script: %q", got)
	}
	if got := r.Describe(Connector{Kind: "other", Label: "Thing"}, "x"); got != "Thing for x." {
		t.Errorf("other: %q", got)
	}
}

func TestRunTextAndHelpers(t *testing.T) {
	run := &Run{ActionLabel: "Block IP", TargetKind: TargetIP, Target: "203.0.113.7", Status: StatusFailed, Summary: "POST answered 500.",
		Error: "The server had a problem.", ApprovedBy: "ann", Reason: "brute force", Actor: "bob"}
	want := "Ran Block IP on IP address 203.0.113.7: failed. POST answered 500. The server had a problem. Approved by ann. Reason: brute force"
	if got := run.Text(); got != want {
		t.Errorf("Text = %q", got)
	}
	if run.Author() != "bob" {
		t.Errorf("Author = %q", run.Author())
	}
	run.Reason = strings.Repeat("é", 3000)
	if got := run.Text(); len(got) > 4000+len("…") || !strings.HasSuffix(got, "…") {
		t.Errorf("long Text = %d bytes", len(got))
	}
	if cut("aé", 2) != "a…" || cut("ab", 5) != "ab" {
		t.Error("cut")
	}
	for kind, noun := range map[string]string{TargetDomain: "domain", TargetHost: "host name", "": "target"} {
		if kindNoun(kind) != noun {
			t.Errorf("kindNoun(%q)", kind)
		}
	}
	if (Actor{Name: "x", Automatic: true}).Label() != "playbook x" || (Actor{Name: "x"}).Label() != "x" {
		t.Error("Actor.Label")
	}
	out := cleanOutput("a\r\nb\x01c\tok "+strings.Repeat("é", MaxOutput), nil)
	if !strings.HasPrefix(out, "a\nb�c\tok ") || !strings.HasSuffix(out, "[… output cut at 16 KB]") {
		t.Errorf("cleanOutput = %q…", out[:20])
	}
	if strings.Contains(out, "\r") {
		t.Error("carriage return kept")
	}
	c := Connector{Headers: map[string]string{"Authorization": "Bearer tok-123456"}}
	if got := scrub("sent tok-123456", c.secretValues()); got != "sent [hidden]" {
		t.Errorf("bearer token not hidden: %q", got)
	}
}

func TestLimiterForgetsIdleActors(t *testing.T) {
	var l limiter
	old := time.Now().Add(-time.Hour)
	for i := range 1001 {
		l.allow(fmt.Sprint("user:", i), old)
	}
	if !l.allow("user:new", time.Now()) {
		t.Fatal("refused")
	}
	if len(l.runs) != 1 {
		t.Errorf("idle actors kept: %d", len(l.runs))
	}
}

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

func TestDescribeHTTPError(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want string
	}{
		{&blockedError{msg: "blocked."}, "blocked."},
		{&url.Error{Op: "Post", URL: "http://x/?key=s", Err: &redirectError{to: "https://evil"}}, "redirected to https://evil"},
		{context.DeadlineExceeded, "did not answer within"},
		{&net.DNSError{Name: "fw.example", Err: "no such host"}, "Could not find the server fw.example"},
		{&net.OpError{Op: "dial", Err: timeoutErr{}}, "did not answer within"},
		{&net.OpError{Op: "dial", Err: syscall.ECONNREFUSED}, "refused the connection"},
		{x509.UnknownAuthorityError{}, "not from a trusted authority"},
		{x509.HostnameError{Certificate: &x509.Certificate{}, Host: "x"}, "for another name"},
		{x509.CertificateInvalidError{Cert: &x509.Certificate{}, Reason: x509.Expired}, "is not valid ("},
		{tls.RecordHeaderError{Msg: "first record does not look like a TLS handshake"}, "did not answer with HTTPS"},
		{&url.Error{Op: "Post", URL: "http://x/?key=secret", Err: errors.New("boom")}, "The request failed: boom"},
	} {
		got := describeHTTPError(tc.err)
		if !strings.Contains(got, tc.want) || strings.Contains(got, "secret") {
			t.Errorf("%T: %q", tc.err, got)
		}
	}
	if (&blockedError{msg: "m"}).Error() != "m" {
		t.Error("blockedError")
	}
}

// recDoer records OpenSearch requests and fails when told to.
type recDoer struct {
	paths  []string
	bodies []any
	err    error
	reply  string
}

func (d *recDoer) Do(_ context.Context, method, path string, body, out any) error {
	d.paths = append(d.paths, method+" "+path)
	d.bodies = append(d.bodies, body)
	if d.err != nil {
		return d.err
	}
	if out != nil && d.reply != "" {
		return json.Unmarshal([]byte(d.reply), out)
	}
	return nil
}

func TestOpenSearchIndexAndLimits(t *testing.T) {
	ctx := context.Background()
	d := &recDoer{}
	s := NewOpenSearch(d, "sig")
	if err := s.EnsureIndex(ctx); err != nil || d.paths[0] != "PUT /sig_actions" {
		t.Fatalf("ensure = %v %v", err, d.paths)
	}
	props := d.bodies[0].(map[string]any)["mappings"].(map[string]any)["properties"].(map[string]any)
	if props["output"].(map[string]any)["index"] != false || props["actor"].(map[string]any)["type"] != "keyword" {
		t.Errorf("mappings = %v", props)
	}
	d.err = &store.Error{Status: 400, Body: "resource_already_exists_exception"}
	if err := s.EnsureIndex(ctx); err != nil {
		t.Errorf("existing = %v", err)
	}
	d.err = &store.Error{Status: 500, Body: "boom"}
	if err := s.EnsureIndex(ctx); err == nil {
		t.Error("error not returned")
	}
	d.err, d.paths = nil, nil
	d.reply = `{"sig_actions":{"settings":{"index":{"number_of_replicas":"0"}}}}`
	if err := s.Replicate(ctx); err != nil || len(d.paths) != 2 {
		t.Errorf("replicate = %v %v", err, d.paths)
	}
	for limit, want := range map[int]int{0: 50, 9999: 500, 7: 7} {
		d.bodies, d.reply = nil, `{"hits":{"hits":[]}}`
		if _, err := s.List(ctx, Filter{Limit: limit}); err != nil {
			t.Fatal(err)
		}
		if got := d.bodies[0].(map[string]any)["size"]; got != want {
			t.Errorf("limit %d: size %v", limit, got)
		}
	}
}

func TestActionsFileErrors(t *testing.T) {
	dir := t.TempDir()
	a := &Actions{File: dir} // a folder, not a file
	_, err := a.List()
	var fe *FileError
	if !errors.As(err, &fe) || !strings.Contains(fe.Error(), "could not be read") || errors.Unwrap(fe) == nil {
		t.Errorf("folder = %v", err)
	}
	if _, _, err := a.Get("x"); err == nil {
		t.Error("Get on a bad file")
	}
	if err := (&Actions{}).Save(make([]Connector, MaxActions+1)); err == nil || !strings.Contains(err.Error(), "at most") {
		t.Errorf("too many = %v", err)
	}
	bad := dir + string(os.PathSeparator) + "actions.yaml"
	if err := os.WriteFile(bad, []byte("actions: [:"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := (&Actions{File: bad}).List(); !errors.As(err, &fe) || !strings.Contains(err.Error(), "yaml") {
		t.Errorf("bad YAML = %v", err)
	}
}

func TestViewsAndInfos(t *testing.T) {
	off := false
	h := hookAction("http://127.0.0.1:1")
	hidden := hookAction("http://127.0.0.1:1")
	hidden.Name, hidden.Enabled = "hidden", &off
	dis := Connector{Name: "dis", Label: "Disable", Kind: KindDisableUser, Target: TargetUser}
	scr := Connector{Name: "iso", Label: "Isolate", Kind: KindScript, Target: TargetHost, Program: "missing.sh"}
	r, _ := runnerWith(t, h, hidden, dis, scr)
	r.ScriptsDir = t.TempDir()
	infos, err := r.Infos()
	if err != nil {
		t.Fatal(err)
	}
	if len(infos) != 3 {
		t.Fatalf("infos = %+v", infos)
	}
	byName := map[string]Info{}
	for _, i := range infos {
		byName[i.Name] = i
	}
	if byName["block"].Problem != "" || !strings.HasPrefix(byName["block"].What, "Send POST to 127.0.0.1:1 for {target}") {
		t.Errorf("block = %+v", byName["block"])
	}
	if byName["dis"].Problem != "this server has no directory settings" {
		t.Errorf("dis = %+v", byName["dis"])
	}
	if !strings.Contains(byName["iso"].Problem, "not in the scripts folder") {
		t.Errorf("iso = %+v", byName["iso"])
	}

	v := r.ViewOf(h)
	if !v.PasswordSet || v.BindPasswordSet || len(v.Headers) != 1 || v.Headers[0] != (HeaderView{Name: "X-Api-Key", Set: true}) || !v.Disruptive || !v.Enabled {
		t.Errorf("view = %+v", v)
	}
	raw, _ := json.Marshal(v)
	if strings.Contains(string(raw), "sekrit") {
		t.Errorf("view shows a secret: %s", raw)
	}

	// A directory that is not Active Directory needs the attribute; one
	// without a bind account needs one.
	r.Directory = func() users.LDAPSettings {
		return users.LDAPSettings{Type: users.TypeOpenLDAP, URL: "ldaps://ldap.example", UserBaseDN: "dc=example,dc=com"}
	}
	if p := r.problemOf(dis); !strings.Contains(p, "not Active Directory") {
		t.Errorf("openldap = %q", p)
	}
	dis.DisableAttribute = "nsAccountLock"
	if p := r.problemOf(dis); !strings.Contains(p, "bind DN") {
		t.Errorf("no bind = %q", p)
	}
}

func TestTestReportsProblems(t *testing.T) {
	ctx := context.Background()
	r, _ := runnerWith(t)
	r.Protected = []string{"127.0.0.1:9200"}
	if rep := r.Test(ctx, Connector{Name: "x", Kind: "email", Target: TargetIP}, "", false, "admin"); rep.OK || rep.Steps[0].Step != "settings" {
		t.Errorf("bad settings = %+v", rep)
	}
	dis := Connector{Name: "dis", Kind: KindDisableUser, Target: TargetUser}
	if rep := r.Test(ctx, dis, "jdoe", false, "admin"); rep.OK || !strings.Contains(rep.Message, "no directory settings") {
		t.Errorf("no directory = %+v", rep)
	}
	for u, want := range map[string]string{
		"http://169.254.169.254/x/{{.ip}}": "does not send response actions to 169.254.169.254",
		"http://127.0.0.1:9200/x/{{.ip}}":  "the OpenSearch database",
	} {
		c := Connector{Name: "h", Kind: KindHTTP, Target: TargetIP, Method: "POST", URL: u, AllowLoopback: true}
		rep := r.Test(ctx, c, "", false, "admin")
		if rep.OK || !strings.Contains(rep.Message, want) || rep.Request == nil || !strings.Contains(rep.Request.URL, "/x/") {
			t.Errorf("%s: %+v", u, rep)
		}
	}
	// Without "allow this server's own addresses", loopback is refused
	// with a hint; a host name is looked up first.
	c := Connector{Name: "h", Kind: KindHTTP, Target: TargetIP, Method: "POST", URL: "http://localhost:1/x/{{.ip}}"}
	if rep := r.Test(ctx, c, "203.0.113.1", false, "admin"); rep.OK || !strings.Contains(rep.Message, "Allow this server's own addresses") {
		t.Errorf("loopback = %+v", rep)
	}
	// Sending without an audit log is refused.
	c.AllowLoopback = true
	r.Store = nil
	if rep := r.Test(ctx, c, "203.0.113.1", true, "admin"); rep.OK || rep.Steps[len(rep.Steps)-1].Step != "send" || !strings.Contains(rep.Message, "audit log") {
		t.Errorf("no store = %+v", rep)
	}
}
