// Command signalith-loadgen puts load on Signalith servers and checks how
// they hold up: simulated agents, syslog devices, people using the pages,
// password guessing and settings changes, against one server or several
// behind a load balancer, with faults such as killing the server that
// runs the jobs. It reads a scenario file (see loadtest/), runs it, and
// reports each pass criterion. It uses only the servers' public
// interfaces, and reads OpenSearch only to count what was stored.
//
//	signalith-loadgen run     -f loadtest/s3-idle.yaml [-target https://lb:8443] [-json out.json]
//	signalith-loadgen agents  -n 500 -rate 5000 -token-file t.txt -for 10m
//	signalith-loadgen syslog  -proto tcp -sources 1000 -rate 2000 -syslog-target host:6514 -for 10m
//	signalith-loadgen users   -n 50 -create -admin-file a.txt -for 10m
//	signalith-loadgen brute   -accounts 20 -sources 500 -rate 50 -admin-file a.txt -for 2m
//	signalith-loadgen churn   -every 5s -key search.max_events -values 5000,5001 -admin-file a.txt -for 10m
//	signalith-loadgen verify  -run <id> -opensearch https://os:9200 [-os-ca .. -os-cert .. -os-key ..]
//	signalith-loadgen cleanup -run <id> -admin-file a.txt
//	signalith-loadgen check   loadtest/*.yaml
//
// Exit code 0 is a pass (or a scenario skipped because the servers lack a
// feature it needs), 1 a failed criterion, 2 an error.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"time"
)

const (
	exitPass  = 0
	exitFail  = 1
	exitError = 2
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr))
}

const usage = `Usage: signalith-loadgen <command> [flags]

Commands:
  run      run a scenario file (-f)
  agents   simulated Fluent Bit agents
  syslog   simulated syslog devices
  users    simulated people using the pages
  brute    wrong passwords against accounts made for the run
  churn    change one setting over and over
  verify   count a run's stored events (lost, duplicated)
  cleanup  remove the accounts and close the case a run made
  check    check scenario files without running them

Run "signalith-loadgen <command> -h" for a command's flags.
`

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return exitError
	}
	cmd, args := args[0], args[1:]
	switch cmd {
	case "run", "agents", "syslog", "users", "brute", "churn":
		return runCommand(ctx, cmd, args, stdout, stderr)
	case "verify":
		return verifyCommand(ctx, args, stdout, stderr)
	case "cleanup":
		return cleanupCommand(ctx, args, stdout, stderr)
	case "check":
		return checkCommand(args, stdout, stderr)
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usage)
		return exitPass
	}
	fmt.Fprintf(stderr, "unknown command %q\n\n%s", cmd, usage)
	return exitError
}

// common are the flags every command that drives load takes.
type common struct {
	file, targets, cas, admin, token, users, jsonOut, runID string
	osURL, osCA, osCert, osKey, osUser, prefix              string
	keep, quiet                                             bool
	forDur                                                  time.Duration
}

func (c *common) register(fs *flag.FlagSet, withFile bool) {
	if withFile {
		fs.StringVar(&c.file, "f", "", "scenario file")
	}
	fs.StringVar(&c.targets, "target", "", "server or load balancer addresses, comma separated (replaces the scenario's)")
	fs.StringVar(&c.cas, "ca", "", "CA files that sign the servers' certificates, comma separated")
	fs.StringVar(&c.admin, "admin-file", "", "file holding user:password of an admin")
	fs.StringVar(&c.token, "token-file", "", "file holding an agent token")
	fs.StringVar(&c.users, "users-file", "", "CSV of username,password for simulated users")
	fs.StringVar(&c.jsonOut, "json", "", "also write the report as JSON to this file")
	fs.StringVar(&c.runID, "run", "", "run ID (default: a new random one)")
	fs.StringVar(&c.osURL, "opensearch", "", "OpenSearch address, to verify stored events and count operations")
	fs.StringVar(&c.osCA, "os-ca", "", "OpenSearch CA file")
	fs.StringVar(&c.osCert, "os-cert", "", "OpenSearch client certificate")
	fs.StringVar(&c.osKey, "os-key", "", "OpenSearch client key")
	fs.StringVar(&c.osUser, "os-user-file", "", "file holding user:password for OpenSearch")
	fs.StringVar(&c.prefix, "prefix", "", "the servers' opensearch.index_prefix (default signalith)")
	fs.BoolVar(&c.keep, "keep", false, "keep the accounts and the case the run made")
	fs.BoolVar(&c.quiet, "q", false, "no progress lines")
	if !withFile {
		fs.DurationVar(&c.forDur, "for", time.Minute, "how long to run")
	}
}

// apply puts the flags over the scenario's own values.
func (c *common) apply(s *Scenario) {
	if c.targets != "" {
		s.Targets = splitComma(c.targets)
	}
	if c.cas != "" {
		s.CAFile, s.CAFiles = "", splitComma(c.cas)
	}
	set := func(dst *string, v string) {
		if v != "" {
			*dst = v
		}
	}
	set(&s.Credentials.AdminFile, c.admin)
	set(&s.Credentials.TokenFile, c.token)
	set(&s.Credentials.UsersFile, c.users)
	set(&s.OpenSearch.URL, c.osURL)
	set(&s.OpenSearch.CA, c.osCA)
	set(&s.OpenSearch.Cert, c.osCert)
	set(&s.OpenSearch.Key, c.osKey)
	set(&s.OpenSearch.UserFile, c.osUser)
	set(&s.OpenSearch.Prefix, c.prefix)
}

func splitComma(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func runCommand(ctx context.Context, cmd string, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	fs.SetOutput(stderr)
	var c common
	c.register(fs, cmd == "run")
	var (
		n, sources, batch, eventBytes, accounts     int
		rate                                        float64
		proto, format, syslogTargets, viaProxy, key string
		values, search                              string
		proxyV2, triage, create                     bool
		think, every                                time.Duration
	)
	switch cmd {
	case "agents":
		fs.IntVar(&n, "n", 100, "agents")
		fs.Float64Var(&rate, "rate", 1000, "events per second, all agents together")
		fs.IntVar(&batch, "batch", 0, "events per request (default: one request a second per agent)")
		fs.IntVar(&eventBytes, "event-bytes", 0, "pad each event to about this many bytes")
	case "syslog":
		fs.StringVar(&proto, "proto", "udp", "udp, tcp or tls")
		fs.IntVar(&sources, "sources", 100, "devices")
		fs.Float64Var(&rate, "rate", 1000, "messages per second, all devices together")
		fs.StringVar(&format, "format", "5424", "5424 or 3164")
		fs.StringVar(&syslogTargets, "syslog-target", "", "host:port of the syslog listeners, comma separated")
		fs.BoolVar(&proxyV2, "proxy-v2", false, "start each connection with a PROXY v2 header naming the device")
	case "users":
		fs.IntVar(&n, "n", 10, "users")
		fs.DurationVar(&think, "think", 5*time.Second, "time between one user's page loads")
		fs.BoolVar(&triage, "triage", false, "comment on the same findings and case")
		fs.BoolVar(&create, "create", false, "make analyst accounts for the run instead of -users-file")
		fs.StringVar(&search, "search", "", "query each page load runs")
	case "brute":
		fs.IntVar(&accounts, "accounts", 10, "accounts made for the run and attacked")
		fs.IntVar(&sources, "sources", 100, "source addresses (own loopback addresses for a local target)")
		fs.Float64Var(&rate, "rate", 20, "sign-in attempts per second")
		fs.StringVar(&viaProxy, "via-proxy", "", "send every attempt through a PROXY v2 header from this address")
	case "churn":
		fs.DurationVar(&every, "every", 5*time.Second, "time between changes")
		fs.StringVar(&key, "key", "search.max_events", "setting to change")
		fs.StringVar(&values, "values", "5000,5001", "values to cycle through, comma separated")
	}
	if err := fs.Parse(args); err != nil {
		return exitError
	}
	var s *Scenario
	if cmd == "run" {
		if c.file == "" {
			fmt.Fprintln(stderr, "run needs -f <scenario file>")
			return exitError
		}
		var err error
		if s, err = loadScenario(c.file); err != nil {
			fmt.Fprintf(stderr, "%s: %v\n", c.file, err)
			return exitError
		}
	} else {
		p := Phase{Name: cmd, For: Duration(c.forDur)}
		switch cmd {
		case "agents":
			p.Agents = &AgentLoad{N: n, Rate: rate, Batch: batch, EventBytes: eventBytes}
		case "syslog":
			p.Syslog = &SyslogLoad{Proto: proto, Sources: sources, Rate: rate, Format: format, ProxyV2: proxyV2}
		case "users":
			p.Users = &UserLoad{N: n, Think: Duration(think), Triage: triage, Create: create, Search: search}
		case "brute":
			p.Brute = &BruteLoad{Accounts: accounts, Sources: sources, Rate: rate, ViaProxy: viaProxy}
		case "churn":
			var vs []any
			for _, v := range splitComma(values) {
				if i, err := strconv.ParseInt(v, 10, 64); err == nil {
					vs = append(vs, i)
				} else {
					vs = append(vs, v)
				}
			}
			p.Churn = &ChurnLoad{Every: Duration(every), Key: key, Values: vs}
		}
		s = &Scenario{Name: cmd, Phases: []Phase{p}}
		ts := splitComma(syslogTargets)
		switch proto {
		case "udp":
			s.SyslogTargets.UDP = ts
		case "tcp":
			s.SyslogTargets.TCP = ts
		case "tls":
			s.SyslogTargets.TLS = ts
		}
	}
	c.apply(s)
	if err := s.validate(); err != nil {
		fmt.Fprintln(stderr, err)
		return exitError
	}
	if cmd == "syslog" && len(s.Targets) == 0 {
		// Syslog alone needs no web address.
		s.Targets = []string{"https://localhost:8080"}
	}
	opts := runOptions{RunID: c.runID, Keep: c.keep, Log: stderr}
	if c.quiet {
		opts.Log = nil
	}
	rep, err := runScenario(ctx, s, opts)
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return exitError
	}
	rep.WriteText(stdout)
	if c.jsonOut != "" {
		if err := rep.WriteJSON(c.jsonOut); err != nil {
			fmt.Fprintf(stderr, "error: %v\n", err)
			return exitError
		}
	}
	if !rep.Pass {
		return exitFail
	}
	return exitPass
}

func verifyCommand(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var c common
	c.register(fs, true)
	if err := fs.Parse(args); err != nil {
		return exitError
	}
	s := &Scenario{}
	if c.file != "" {
		var err error
		if s, err = loadScenario(c.file); err != nil {
			fmt.Fprintf(stderr, "%s: %v\n", c.file, err)
			return exitError
		}
	}
	c.apply(s)
	if c.runID == "" {
		fmt.Fprintln(stderr, "verify needs -run <id>")
		return exitError
	}
	r, err := newOSReader(s.OpenSearch)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitError
	}
	stored, _, err := r.storedCounts(ctx, c.runID)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitError
	}
	// Without the run's own record of what was acknowledged, every number
	// below an agent's highest stored one is taken as sent: a gap is an
	// event lost, or one refused or never sent.
	acked := map[int][]seqRange{}
	for a, seqs := range stored {
		var top int64
		for seq := range seqs {
			top = max(top, seq)
		}
		acked[a] = []seqRange{{1, top}}
	}
	v := compare(acked, stored)
	fmt.Fprintf(stdout, "Run %s: %d agents, %d events stored, %d missing below each agent's highest number, %d duplicated\n",
		c.runID, len(stored), v.Stored, v.Lost, v.Duplicated)
	for _, e := range v.Examples {
		fmt.Fprintf(stdout, "  %s\n", e)
	}
	if v.Lost > 0 || v.Duplicated > 0 {
		return exitFail
	}
	return exitPass
}

func cleanupCommand(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("cleanup", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var c common
	c.register(fs, true)
	if err := fs.Parse(args); err != nil {
		return exitError
	}
	s := &Scenario{}
	if c.file != "" {
		var err error
		if s, err = loadScenario(c.file); err != nil {
			fmt.Fprintf(stderr, "%s: %v\n", c.file, err)
			return exitError
		}
	}
	c.apply(s)
	if c.runID == "" || len(s.Targets) == 0 || s.Credentials.AdminFile == "" {
		fmt.Fprintln(stderr, "cleanup needs -run, -target and -admin-file")
		return exitError
	}
	tc, err := tlsConfig(s.caFiles())
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitError
	}
	user, pass, err := readLogin(s.Credentials.AdminFile)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitError
	}
	sess := newSession(s.Targets[0], newTransport(tc, nil), user, pass)
	var list struct {
		Users []struct {
			Username string `json:"username"`
		} `json:"users"`
	}
	if err := sess.Do(ctx, http.MethodGet, "/api/users", nil, &list); err != nil {
		fmt.Fprintln(stderr, err)
		return exitError
	}
	failed := false
	prefix := "lg-" + c.runID + "-"
	for _, u := range list.Users {
		if strings.HasPrefix(u.Username, prefix) {
			if err := sess.Do(ctx, http.MethodDelete, "/api/users/"+url.PathEscape(u.Username), nil, nil); err != nil {
				fmt.Fprintf(stderr, "%s: %v\n", u.Username, err)
				failed = true
			} else {
				fmt.Fprintf(stdout, "removed account %s\n", u.Username)
			}
		}
	}
	var cases struct {
		Cases []struct {
			ID    string `json:"id"`
			Title string `json:"title"`
		} `json:"cases"`
	}
	if err := sess.Do(ctx, http.MethodGet, "/api/cases?status=new,in_progress,pending&q="+url.QueryEscape(caseTitle(c.runID)), nil, &cases); err == nil {
		closed := "closed"
		for _, cs := range cases.Cases {
			if cs.Title == caseTitle(c.runID) {
				if err := sess.Do(ctx, http.MethodPatch, "/api/cases/"+url.PathEscape(cs.ID), map[string]any{"status": &closed}, nil); err != nil {
					failed = true
				} else {
					fmt.Fprintf(stdout, "closed case %s\n", cs.ID)
				}
			}
		}
	}
	fmt.Fprintln(stdout, "Events the run sent are left to the retention policy.")
	if failed {
		return exitError
	}
	return exitPass
}

func checkCommand(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "check needs scenario files")
		return exitError
	}
	code := exitPass
	for _, f := range args {
		if _, err := loadScenario(f); err != nil {
			fmt.Fprintf(stderr, "%s: %v\n", f, err)
			code = exitError
			continue
		}
		fmt.Fprintf(stdout, "%s: ok\n", f)
	}
	return code
}
