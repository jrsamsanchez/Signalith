// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package agentd

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"path"
	"regexp"
	"strings"

	"github.com/jrsamsanchez/signalith/internal/agentproto"
)

// Fluent Bit runs as root (SYSTEM on Windows), so the agent only runs a
// configuration that reads logs and sends them to the Signalith server
// it was installed for: someone who took over Signalith cannot use it to
// run programs, load plugins, read or write files outside the agent's
// own, or send what it reads elsewhere (ASI-03). Every section, plugin
// and setting is on an allowlist; what Signalith does not write is
// refused.
var (
	// fbService are the [SERVICE] settings allowed. No log file, pid
	// file, parsers, plugins, HTTP server or hot reload.
	fbService = keys("flush", "grace", "log_level", "storage.path", "storage.sync", "storage.checksum",
		"storage.max_chunks_up", "storage.backlog.mem_limit", "daemon")
	fbInputs = map[string]map[string]bool{
		"tail": keys("tag", "path", "path_key", "exclude_path", "db", "db.sync", "db.locking", "read_from_head",
			"skip_long_lines", "skip_empty_lines", "buffer_chunk_size", "buffer_max_size", "mem_buf_limit",
			"refresh_interval", "rotate_wait", "ignore_older", "storage.type", "storage.pause_on_chunks_overlimit"),
		"systemd": keys("tag", "path", "db", "db.sync", "read_from_tail", "systemd_filter", "systemd_filter_type",
			"max_entries", "max_fields", "strip_underscores", "lowercase", "storage.type", "mem_buf_limit"),
		"winevtlog": keys("tag", "channels", "db", "interval_sec", "interval_nsec", "read_existing_events",
			"render_event_as_xml", "use_ansi", "string_inserts", "ignore_missing_channels", "storage.type", "mem_buf_limit"),
	}
	fbFilters = map[string]map[string]bool{
		"grep":            keys("match", "regex", "exclude", "logical_op"),
		"sysinfo":         keys("match", "hostname_key", "os_name_key", "os_version_key", "kernel_version_key", "fluentbit_version_key"),
		"record_modifier": keys("match", "record", "remove_key", "allowlist_key"),
	}
	// fbOutput are the http output's settings allowed: no client
	// certificate, proxy or basic auth, and tls.ca_file and tls.vhost
	// only as checked below.
	fbOutput = keys("match", "host", "port", "uri", "format", "header", "header_tag", "json_date_key", "json_date_format",
		"compress", "retry_limit", "workers", "storage.total_limit_size", "net.keepalive", "net.keepalive_idle_timeout",
		"net.keepalive_max_recycle", "net.connect_timeout", "tls", "tls.verify", "tls.verify_hostname", "tls.vhost", "tls.ca_file")
	// fbHeaders are the headers the output may send, with the value
	// each must have ("" for any value without a variable).
	fbHeaders = map[string]string{
		"authorization":      "Bearer ${SIGNALITH_TOKEN}",
		"x-signalith-agent":  "${HOSTNAME}",
		"x-signalith-config": "",
	}
	// shortName is a Windows 8.3 short name (PROGRA~3), which could name
	// a folder the denylist names in full.
	shortName = regexp.MustCompile(`~[0-9]`)
)

func keys(ks ...string) map[string]bool {
	m := map[string]bool{"name": true}
	for _, k := range ks {
		m[k] = true
	}
	return m
}

// fbRules are what a configuration is checked against: the server the
// agent was installed for, the folders Fluent Bit may keep its buffer
// and databases in, the certificate authority files it may trust, and
// the computer's system (linux or windows).
type fbRules struct {
	server string
	states []string
	caFile []string
	goos   string
}

// checkFluentBit checks the Fluent Bit configuration conf, in Fluent
// Bit's classic format, against r.
func checkFluentBit(conf string, r fbRules) error {
	u, err := url.Parse(r.server)
	if err != nil || u.Hostname() == "" {
		return fmt.Errorf("the agent's server address %q is not valid", r.server)
	}
	type section struct {
		kind string
		line int
		kv   map[string][]string
	}
	var sections []*section
	var cur *section
	for i, line := range strings.Split(strings.ReplaceAll(conf, "\r\n", "\n"), "\n") {
		n := i + 1
		line = strings.TrimSpace(line)
		switch {
		case line == "" || strings.HasPrefix(line, "#"):
			continue
		case strings.HasPrefix(line, "@"):
			return fmt.Errorf("line %d: %s is not allowed", n, strings.Fields(line)[0])
		case strings.HasPrefix(line, "["):
			kind := strings.ToLower(strings.TrimSpace(strings.Trim(line, "[]")))
			switch {
			case !strings.HasSuffix(line, "]"), kind != "service" && kind != "input" && kind != "filter" && kind != "output":
				return fmt.Errorf("line %d: the section %s is not allowed", n, line)
			}
			cur = &section{kind: kind, line: n, kv: map[string][]string{}}
			sections = append(sections, cur)
			continue
		}
		if cur == nil {
			return fmt.Errorf("line %d: a setting outside any section", n)
		}
		k, v, _ := strings.Cut(strings.Join(strings.Fields(line), " "), " ")
		k = strings.ToLower(k)
		if strings.Contains(v, "${") && !(cur.kind == "output" && k == "header") {
			// Fluent Bit fills variables in after this check.
			return fmt.Errorf("line %d: %s uses a variable", n, k)
		}
		cur.kv[k] = append(cur.kv[k], v)
	}

	outputs := 0
	for _, s := range sections {
		one := func(k string) string {
			if v := s.kv[k]; len(v) > 0 {
				return v[len(v)-1]
			}
			return ""
		}
		name := strings.ToLower(one("name"))
		where := fmt.Sprintf("line %d [%s]", s.line, strings.ToUpper(s.kind))
		var allowed map[string]bool
		switch s.kind {
		case "service":
			allowed = fbService
			if d := one("daemon"); d != "" && fbOn(d) {
				return fmt.Errorf("%s: daemon must be off", where)
			}
		case "input":
			if allowed = fbInputs[name]; allowed == nil {
				return fmt.Errorf("%s: the input %q is not allowed", where, name)
			}
		case "filter":
			if allowed = fbFilters[name]; allowed == nil {
				return fmt.Errorf("%s: the filter %q is not allowed", where, name)
			}
		case "output":
			outputs++
			if name != "http" {
				return fmt.Errorf("%s: the output %q is not allowed", where, name)
			}
			allowed = fbOutput
		}
		for k := range s.kv {
			if !allowed[k] {
				return fmt.Errorf("%s: %s is not allowed", where, k)
			}
		}
		// Files Fluent Bit writes: in the agent's own folder.
		for _, k := range []string{"db", "storage.path"} {
			for _, p := range s.kv[k] {
				if err := plainPath(p, r.goos); err != nil {
					return fmt.Errorf("%s: %s: %w", where, k, err)
				}
				if !under(p, r.states, r.goos) {
					return fmt.Errorf("%s: %s %q is outside %s", where, k, p, strings.Join(r.states, " and "))
				}
			}
		}
		// Files it reads: logs, not secrets.
		for _, k := range []string{"path", "exclude_path"} {
			for _, paths := range s.kv[k] {
				for _, p := range strings.Split(paths, ",") {
					if p = strings.TrimSpace(p); p == "" {
						continue
					}
					if err := plainPath(p, r.goos); err != nil {
						return fmt.Errorf("%s: %s: %w", where, k, err)
					}
					if k == "path" && agentproto.SecretPath(cleanPath(p, r.goos), r.goos) {
						return fmt.Errorf("%s: %q may hold secrets", where, p)
					}
				}
			}
		}
		if s.kind != "output" {
			continue
		}
		host := one("host")
		if !strings.EqualFold(host, u.Hostname()) {
			return fmt.Errorf("%s: it sends to %q, not to %s", where, host, u.Hostname())
		}
		if !fbOn(one("tls")) || !fbOn(one("tls.verify")) {
			return fmt.Errorf("%s: it must send over TLS that checks the certificate", where)
		}
		if uri := one("uri"); uri != "" && !strings.HasPrefix(uri, "/api/") {
			return fmt.Errorf("%s: it sends to %q, not to Signalith's API", where, uri)
		}
		ca := s.kv["tls.ca_file"]
		for _, f := range ca {
			if !samePath(f, r.caFile, r.goos) {
				return fmt.Errorf("%s: tls.ca_file must be the agent's own %s", where, r.caFile[0])
			}
		}
		// Another name to check the certificate against only with the
		// agent's own certificate authority, for a server reached by its
		// address: with the computer's trusted authorities it would let
		// any certificate for that name stand in for Signalith.
		for _, v := range s.kv["tls.vhost"] {
			if !strings.EqualFold(v, host) && (net.ParseIP(host) == nil || len(ca) == 0) {
				return fmt.Errorf("%s: tls.vhost %q is not the server's name", where, v)
			}
		}
		for _, h := range s.kv["header"] {
			k, v, _ := strings.Cut(h, " ")
			want, ok := fbHeaders[strings.ToLower(k)]
			if !ok || want != "" && v != want || want == "" && strings.Contains(v, "$") {
				return fmt.Errorf("%s: the header %s is not allowed", where, k)
			}
		}
	}
	if outputs != 1 {
		return errors.New("it must have one output, to Signalith")
	}
	return nil
}

// plainPath refuses a path Fluent Bit could read other than as written:
// relative, with .., ~ or a pattern in braces, a Windows device path,
// short name or alternate data stream.
func plainPath(p, goos string) error {
	switch {
	case strings.Contains(p, ".."), strings.ContainsAny(p, "{}$\x00"):
		return fmt.Errorf("%q must not use .., braces or variables", p)
	case goos == "windows":
		if len(p) < 3 || p[1] != ':' || p[2] != '\\' && p[2] != '/' {
			return fmt.Errorf(`%q must start with a drive, such as C:\`, p)
		}
		if strings.Contains(p[2:], ":") || strings.HasPrefix(p, `\\`) || shortName.MatchString(p) {
			return fmt.Errorf("%q must be a plain path, without a short name or stream", p)
		}
	case !strings.HasPrefix(p, "/"):
		return fmt.Errorf("%q must start with /", p)
	case strings.Contains(p, "~"):
		return fmt.Errorf("%q must not use ~", p)
	}
	return nil
}

// cleanPath is p as one form of path: forward slashes, and on Windows
// lower case.
func cleanPath(p, goos string) string {
	if goos == "windows" {
		return path.Clean(strings.ToLower(strings.ReplaceAll(p, `\`, "/")))
	}
	return path.Clean(p)
}

// under reports whether p is in one of the folders dirs.
func under(p string, dirs []string, goos string) bool {
	for _, d := range dirs {
		if strings.HasPrefix(cleanPath(p, goos), cleanPath(d, goos)+"/") {
			return true
		}
	}
	return false
}

// samePath reports whether p is one of the files fs.
func samePath(p string, fs []string, goos string) bool {
	for _, f := range fs {
		if cleanPath(p, goos) == cleanPath(f, goos) {
			return true
		}
	}
	return false
}

// fbOn reports whether a Fluent Bit switch is on.
func fbOn(v string) bool {
	switch strings.ToLower(v) {
	case "on", "true", "yes", "1":
		return true
	}
	return false
}
