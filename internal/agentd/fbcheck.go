// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package agentd

import (
	"errors"
	"fmt"
	"net/url"
	"path"
	"strings"

	"github.com/jrsamsanchez/signalith/internal/agentproto"
)

// Fluent Bit runs as root (SYSTEM on Windows), so the agent only runs a
// configuration that reads logs and sends them to the Signalith server
// it was installed for: someone who took over Signalith cannot use it to
// run programs, load plugins, read secret files or send what it reads
// elsewhere (ASI-03).
var (
	fbSections = map[string]bool{"service": true, "input": true, "filter": true, "output": true, "parser": true, "multiline_parser": true}
	fbInputs   = map[string]bool{"tail": true, "systemd": true, "winevtlog": true}
	fbFilters  = map[string]bool{"grep": true, "record_modifier": true, "modify": true, "nest": true, "parser": true, "sysinfo": true}
	// fbServiceKeys load programs or open a port.
	fbServiceKeys = map[string]bool{"plugins_file": true, "streams_file": true, "http_server": true, "http_listen": true, "http_port": true,
		"hot_reload": true}
)

// checkFluentBit checks the Fluent Bit configuration conf, in Fluent
// Bit's classic format, against what the agent runs: inputs that read
// logs (tail, systemd, winevtlog) and no file that holds secrets, filters
// that change records, and one http output to server's host, over TLS
// that checks the certificate. Fluent Bit's databases and buffer stay in
// one of the folders states.
func checkFluentBit(conf, server string, states []string, goos string) error {
	u, err := url.Parse(server)
	if err != nil || u.Hostname() == "" {
		return fmt.Errorf("the agent's server address %q is not valid", server)
	}
	norm := func(p string) string {
		if goos == "windows" {
			return path.Clean(strings.ToLower(strings.ReplaceAll(p, `\`, "/")))
		}
		return path.Clean(p)
	}
	inState := func(p string) bool {
		for _, st := range states {
			if strings.HasPrefix(norm(p), norm(st)+"/") {
				return true
			}
		}
		return false
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
			if !strings.HasSuffix(line, "]") || !fbSections[kind] {
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
		for _, k := range []string{"db", "storage.path"} {
			for _, p := range s.kv[k] {
				if !inState(p) {
					return fmt.Errorf("%s: %s %q is outside %s", where, k, p, strings.Join(states, " and "))
				}
			}
		}
		switch s.kind {
		case "service":
			for k := range s.kv {
				if fbServiceKeys[k] {
					return fmt.Errorf("%s: %s is not allowed", where, k)
				}
			}
		case "input":
			if !fbInputs[name] {
				return fmt.Errorf("%s: the input %q is not allowed", where, name)
			}
			for _, paths := range s.kv["path"] {
				for _, p := range strings.Split(paths, ",") {
					if p = strings.TrimSpace(p); p != "" && agentproto.SecretPath(p, goos) {
						return fmt.Errorf("%s: %q may hold secrets", where, p)
					}
				}
			}
		case "filter":
			if !fbFilters[name] {
				return fmt.Errorf("%s: the filter %q is not allowed", where, name)
			}
		case "output":
			outputs++
			if name != "http" {
				return fmt.Errorf("%s: the output %q is not allowed", where, name)
			}
			if h := one("host"); !strings.EqualFold(h, u.Hostname()) {
				return fmt.Errorf("%s: it sends to %q, not to %s", where, h, u.Hostname())
			}
			if !fbOn(one("tls")) || !fbOn(one("tls.verify")) {
				return fmt.Errorf("%s: it must send over TLS that checks the certificate", where)
			}
			for _, k := range []string{"proxy", "http_proxy"} {
				if len(s.kv[k]) > 0 {
					return fmt.Errorf("%s: %s is not allowed", where, k)
				}
			}
		}
	}
	if outputs != 1 {
		return errors.New("it must have one output, to Signalith")
	}
	return nil
}

// fbOn reports whether a Fluent Bit switch is on.
func fbOn(v string) bool {
	switch strings.ToLower(v) {
	case "on", "true", "yes", "1":
		return true
	}
	return false
}
