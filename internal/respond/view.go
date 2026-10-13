package respond

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/jrsamsanchez/signalith/internal/intel"
	"github.com/jrsamsanchez/signalith/internal/redact"
	"github.com/jrsamsanchez/signalith/internal/users"
)

// What the page sees of an action: every setting but the secrets, which
// show only whether they are set. A change sends each secret again, or
// asks to keep the saved one; a saved secret is only kept while the
// action still sends it to the same server (an HTTP action's scheme, host
// and port, a disable_user action's bind DN), so whoever can change an
// action cannot have its key sent somewhere else.

// HeaderView is a header of an HTTP action as the page sees it.
type HeaderView struct {
	Name string `json:"name"`
	Set  bool   `json:"set"`
}

// View is an action as the page sees it.
type View struct {
	Connector
	Disruptive      bool         `json:"disruptive"`
	Enabled         bool         `json:"enabled"`
	Headers         []HeaderView `json:"headers"`
	PasswordSet     bool         `json:"password_set"`
	BindPasswordSet bool         `json:"bind_password_set"`
	// Locked lists secrets that could not be decrypted and must be
	// entered again.
	Locked []string `json:"locked,omitempty"`
	// Problem says why the action cannot run as it is, such as a
	// directory without encryption; "" when it can.
	Problem string `json:"problem,omitempty"`
	// What says what a run does, with {target} for the target.
	What string `json:"what"`
}

// ViewOf returns an action as the page sees it.
func (r *Runner) ViewOf(c Connector) View {
	v := View{Connector: c.Clone(), Disruptive: c.IsDisruptive(), Enabled: c.IsEnabled(), Headers: []HeaderView{},
		PasswordSet: c.Password != "", BindPasswordSet: c.BindPassword != "", Locked: r.Actions.Locked(c.Name),
		What: r.Describe(c, "{target}")}
	names := make([]string, 0, len(c.Headers))
	for k := range c.Headers {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		v.Headers = append(v.Headers, HeaderView{Name: k, Set: c.Headers[k] != ""})
	}
	v.Problem = r.problemOf(c)
	return v
}

// problemOf says why an action cannot run as it is, or "".
func (r *Runner) problemOf(c Connector) string {
	switch c.Kind {
	case KindDisableUser:
		s, err := r.directory()
		if err != nil {
			return err.Error()
		}
		if p := users.WriteProblem(s); p != "" {
			return p
		}
		if s.Type != users.TypeActiveDirectory && c.DisableAttribute == "" {
			return "This directory is not Active Directory: set the attribute and value that switch an account off."
		}
		if c.BindDN == "" && s.BindDN == "" {
			return "Enter the bind DN and password of an account allowed to change accounts."
		}
	case KindScript:
		if _, err := ResolveProgram(r.ScriptsDir, c.Program); err != nil {
			return sentence(err.Error())
		}
	}
	return ""
}

func sentence(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return s
	}
	s = strings.ToUpper(s[:1]) + s[1:]
	if !strings.HasSuffix(s, ".") {
		s += "."
	}
	return s
}

// Info is an action as analysts see it in the Respond menu.
type Info struct {
	Name        string `json:"name"`
	Label       string `json:"label"`
	Description string `json:"description,omitempty"`
	Kind        string `json:"kind"`
	Target      string `json:"target"`
	Disruptive  bool   `json:"disruptive"`
	What        string `json:"what"`
	Problem     string `json:"problem,omitempty"`
}

// Infos lists the actions analysts may run, in the file's order.
func (r *Runner) Infos() ([]Info, error) {
	list, err := r.Actions.List()
	out := []Info{}
	for _, c := range list {
		if !c.IsEnabled() {
			continue
		}
		p := r.problemOf(c)
		if l := r.Actions.Locked(c.Name); len(l) > 0 {
			p = "An admin must enter its " + strings.Join(l, " and ") + " again."
		}
		out = append(out, Info{Name: c.Name, Label: c.Label, Description: c.Description, Kind: c.Kind, Target: c.Target,
			Disruptive: c.IsDisruptive(), What: r.Describe(c, "{target}"), Problem: p})
	}
	return out, err
}

// SecretInput is a secret as the page sends it: a new value, or Keep for
// the saved one. Neither removes it.
type SecretInput struct {
	Value string `json:"value,omitempty"`
	Keep  bool   `json:"keep,omitempty"`
}

// HeaderInput is a header as the page sends it.
type HeaderInput struct {
	Name  string `json:"name"`
	Value string `json:"value,omitempty"`
	Keep  bool   `json:"keep,omitempty"`
}

// Input is an action as the page sends it.
type Input struct {
	Connector
	Disruptive   *bool         `json:"disruptive"`
	Enabled      *bool         `json:"enabled"`
	Headers      []HeaderInput `json:"headers"`
	Password     SecretInput   `json:"password"`
	BindPassword SecretInput   `json:"bind_password"`
}

// Merge turns what the page sent into actions, filling the secrets it
// asked to keep from saved. A secret is kept only by an action of the
// same name that still sends it to the same place.
func Merge(saved []Connector, in []Input) ([]Connector, error) {
	byName := map[string]Connector{}
	for _, c := range saved {
		byName[c.Name] = c
	}
	out := make([]Connector, 0, len(in))
	for _, i := range in {
		c := i.Connector.Clone()
		c.Disruptive, c.Enabled = i.Disruptive, i.Enabled
		c.Headers, c.Password, c.BindPassword = nil, "", ""
		c.Normalize()
		old, had := byName[c.Name]
		if had {
			old.Normalize()
		}
		fail := func(field, msg string) error {
			return &SettingsError{Action: c.Name, Problems: []Problem{{Field: field, Message: msg}}}
		}
		sameHTTP := had && old.Kind == KindHTTP && c.Kind == KindHTTP && origin(old.URL) != "" && origin(old.URL) == origin(c.URL)
		keep := func(field, label, savedValue string, ok bool) (string, error) {
			if !had || savedValue == "" {
				return "", fail(field, "there is no saved "+label+" to keep; enter it")
			}
			if !ok {
				return "", fail(field, "enter the "+label+" again: the action now sends it somewhere else")
			}
			return savedValue, nil
		}
		for _, h := range i.Headers {
			name := strings.TrimSpace(h.Name)
			if name == "" {
				continue
			}
			if c.Headers == nil {
				c.Headers = map[string]string{}
			}
			key := canonicalHeader(name)
			if h.Keep && h.Value == "" {
				v, err := keep("headers", "value of "+key, old.Headers[key], sameHTTP)
				if err != nil {
					return nil, err
				}
				c.Headers[key] = v
				continue
			}
			if h.Value == "" {
				return nil, fail("headers", "enter a value for "+key)
			}
			c.Headers[key] = h.Value
		}
		switch {
		case i.Password.Value != "":
			c.Password = i.Password.Value
		case i.Password.Keep:
			v, err := keep("password", "password", old.Password, sameHTTP && old.Username == c.Username)
			if err != nil {
				return nil, err
			}
			c.Password = v
		}
		switch {
		case i.BindPassword.Value != "":
			c.BindPassword = i.BindPassword.Value
		case i.BindPassword.Keep:
			same := had && old.Kind == KindDisableUser && c.Kind == KindDisableUser && strings.EqualFold(old.BindDN, c.BindDN)
			v, err := keep("bind_password", "bind password", old.BindPassword, same)
			if err != nil {
				return nil, err
			}
			c.BindPassword = v
		}
		// Settings of other kinds are dropped, so they are not kept
		// unseen.
		switch c.Kind {
		case KindHTTP:
			c.Program, c.TimeoutSeconds, c.Operation, c.BindDN, c.BindPassword, c.DisableAttribute, c.DisableValue = "", 0, "", "", "", "", ""
		case KindScript:
			c.Method, c.URL, c.Headers, c.Username, c.Password, c.Body, c.BodyFormat, c.CACert, c.AllowLoopback = "", "", nil, "", "", "", "", "", false
			c.Operation, c.BindDN, c.BindPassword, c.DisableAttribute, c.DisableValue = "", "", "", "", ""
		case KindDisableUser:
			c.Method, c.URL, c.Headers, c.Username, c.Password, c.Body, c.BodyFormat, c.CACert, c.AllowLoopback = "", "", nil, "", "", "", "", "", false
			c.Program, c.TimeoutSeconds = "", 0
		}
		c.Normalize()
		out = append(out, c)
	}
	return out, nil
}

func canonicalHeader(name string) string {
	c := Connector{Headers: map[string]string{name: "x"}}
	c.Normalize()
	for k := range c.Headers {
		return k
	}
	return name
}

// TestReport is the result of testing an action.
type TestReport struct {
	OK      bool   `json:"ok"`
	Message string `json:"message"`
	// Steps are what was checked, in order.
	Steps []users.Step `json:"steps"`
	// Request is what an HTTP action would send.
	Request *RequestPreview `json:"request,omitempty"`
	// Run is the run an HTTP test that was sent made.
	Run *Run `json:"run,omitempty"`
}

// RequestPreview shows an HTTP action's request with secrets hidden.
type RequestPreview struct {
	Method  string   `json:"method"`
	URL     string   `json:"url"`
	Headers []string `json:"headers"`
	Body    string   `json:"body,omitempty"`
}

// Test checks an action without changing anything, as far as its kind
// allows: a disable_user action connects and signs in as its account and
// finds the target account; a script action finds its program; an HTTP
// action fills in its request and checks the server's address. With send,
// an HTTP action really sends its request (the admin was asked first); it
// is recorded in the audit log like any run, by actor.
func (r *Runner) Test(ctx context.Context, c Connector, target string, send bool, actor string) TestReport {
	c.Normalize()
	rep := TestReport{Steps: []users.Step{}}
	step := func(name string, ok bool, msg string) {
		rep.Steps = append(rep.Steps, users.Step{Step: name, OK: ok, Message: sentence(msg)})
	}
	if p := c.Problems(); len(p) > 0 {
		rep.Message = sentence(p[0].Field + ": " + p[0].Message)
		step("settings", false, rep.Message)
		return rep
	}
	step("settings", true, "The settings are complete.")
	kind := c.Target
	if kind == TargetAny {
		kind = GuessKind(target)
	}
	if strings.TrimSpace(target) != "" {
		t, err := ValidateTarget(kind, target)
		if err != nil {
			rep.Message = sentence(err.Error())
			step("target", false, rep.Message)
			return rep
		}
		target = t
	}
	switch c.Kind {
	case KindDisableUser:
		s, err := r.directory()
		if err == nil {
			var steps []users.Step
			steps, err = users.CheckWriteAccount(ctx, s, accountChange(c, target, true))
			rep.Steps = append(rep.Steps, steps...)
		}
		if err != nil {
			var de *users.DirectoryError
			msg := err.Error()
			if errors.As(err, &de) {
				msg = de.Message
			}
			rep.Message = sentence(msg)
			step("directory", false, rep.Message)
			return rep
		}
		rep.OK = true
		rep.Message = "The account can sign in to the directory. Whether it may change accounts shows only when the action runs: check that it was delegated \"Read/Write userAccountControl\"."
		if s, _ := r.directory(); s.Type != "" && s.Type != users.TypeActiveDirectory {
			rep.Message = "The account can sign in to the directory. Whether it may change " + c.DisableAttribute + " shows only when the action runs."
		}
	case KindScript:
		full, err := ResolveProgram(r.ScriptsDir, c.Program)
		if err != nil {
			rep.Message = sentence(err.Error())
			step("program", false, rep.Message)
			return rep
		}
		name, args := scriptCommand(full, "<target>")
		step("program", true, "Found "+full+".")
		rep.OK = true
		rep.Message = "The program is in the scripts folder and can run: " + strings.Join(append([]string{name}, args...), " ") + ". It was not run."
	case KindHTTP:
		if target == "" {
			target = sampleValues[placeholderFor(kind)]
		}
		v := valuesFor(kind, target, "", "", actor, "test from the Response actions page")
		req, body, err := buildRequest(ctx, c, v)
		if err != nil {
			rep.Message = sentence(err.Error())
			step("request", false, rep.Message)
			return rep
		}
		prev := &RequestPreview{Method: req.Method, URL: redact.URL(req.URL.String()), Body: scrub(body, c.secretValues()), Headers: []string{}}
		for k := range req.Header {
			v := req.Header.Get(k)
			if k == "Authorization" || c.Headers[k] != "" {
				v = "[hidden]"
			}
			prev.Headers = append(prev.Headers, k+": "+v)
		}
		sort.Strings(prev.Headers)
		rep.Request = prev
		if err := r.checkHost(ctx, c, req.URL); err != nil {
			rep.Message = sentence(err.Error())
			step("address", false, rep.Message)
			return rep
		}
		step("address", true, "Signalith may send to "+req.URL.Hostname()+".")
		if !send {
			rep.OK = true
			rep.Message = "The request is ready. It was not sent."
			return rep
		}
		run, err := r.testRun(ctx, c, kind, target, actor)
		if err != nil {
			rep.Message = sentence(err.Error())
			step("send", false, rep.Message)
			return rep
		}
		rep.Run = run
		rep.OK = run.Status == StatusSucceeded
		rep.Message = run.Summary
		if run.Error != "" {
			rep.Message = run.Error
		}
		step("send", rep.OK, rep.Message)
	}
	return rep
}

// checkHost looks the URL's host up and checks each address as a request
// would.
func (r *Runner) checkHost(ctx context.Context, c Connector, u *url.URL) error {
	host := u.Hostname()
	var addrs []netip.Addr
	if a, err := netip.ParseAddr(host); err == nil {
		addrs = []netip.Addr{a}
	} else {
		ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		if err != nil {
			return fmt.Errorf("could not find the server %s (DNS): %v", host, err)
		}
		addrs = ips
	}
	for _, a := range addrs {
		if err := intel.CheckAddr(a, c.AllowLoopback); err != nil {
			var be *intel.BlockedError
			if errors.As(err, &be) {
				msg := fmt.Sprintf("Signalith does not send response actions to %s, %s", be.Addr, be.Why)
				if be.Loopback {
					msg += `; to reach a service on this server, tick "Allow this server's own addresses"`
				}
				return errors.New(msg)
			}
			return err
		}
	}
	port := u.Port()
	if port == "" {
		port = map[string]string{"http": "80", "https": "443"}[u.Scheme]
	}
	if slices.ContainsFunc(r.Protected, func(p string) bool { return strings.EqualFold(p, net.JoinHostPort(host, port)) }) {
		return fmt.Errorf("%s is the OpenSearch database Signalith keeps its data in; actions never send to it", host)
	}
	return nil
}

// testRun sends an HTTP action's request for a test, recorded in the
// audit log like any run.
func (r *Runner) testRun(ctx context.Context, c Connector, kind, target, actor string) (*Run, error) {
	if r.Store == nil {
		return nil, &AuditError{Err: errors.New("there is no audit log")}
	}
	if !r.limiter.allow("user:"+strings.ToLower(actor), r.clock()) {
		return nil, ErrRateLimited
	}
	start := r.clock()
	run := &Run{ID: NewRunID(start), Action: c.Name, ActionLabel: c.Label, Kind: c.Kind, Target: target, TargetKind: kind,
		Actor: actor, Reason: "Test from the Response actions page", Status: StatusRunning, Server: r.Server, Started: start}
	ctx = context.WithoutCancel(ctx)
	if err := r.Store.Put(ctx, run, false); err != nil {
		return nil, &AuditError{Err: err}
	}
	r.log().Info("response action test sent", "audit", true, "run", run.ID, "action", c.Name, "target", target, "actor", actor)
	res := r.runHTTP(ctx, c, valuesFor(kind, target, "", "", actor, run.Reason))
	r.finish(run, c, res)
	if err := r.Store.Put(ctx, run, true); err != nil {
		run.RecordErrors = append(run.RecordErrors, "Its result could not be written to the audit log: "+err.Error())
	}
	return run, nil
}

// finish fills a run's result.
func (r *Runner) finish(run *Run, c Connector, res result) {
	run.Finished = r.clock()
	run.DurationMS = run.Finished.Sub(run.Started).Milliseconds()
	run.Summary = scrub(res.summary, c.secretValues())
	run.Output = cleanOutput(res.output, c.secretValues())
	if res.err != nil {
		run.Status = StatusFailed
		run.Error = scrub(res.err.Error(), c.secretValues())
	} else {
		run.Status = StatusSucceeded
	}
}
