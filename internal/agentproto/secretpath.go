// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package agentproto

import (
	"path"
	"strings"
)

// SecretPath reports whether the file path or pattern p, on goos (linux
// or windows), names or can match a file that holds secrets: the agents'
// own configuration and token, Signalith's, password and key stores.
// Signalith refuses to write such a path into a log input, and the
// Signalith Agent refuses a Fluent Bit configuration that tails one
// (ASI-03).
func SecretPath(p, goos string) bool {
	deny := linuxDenied
	if goos == "windows" {
		if len(p) < 3 || p[1] != ':' {
			return true
		}
		// Windows paths do not care about case, the kind of slash or, here,
		// the drive.
		p = "?" + strings.ToLower(strings.ReplaceAll(p[1:], `\`, "/"))
		deny = windowsDenied
	}
	return secretPath(p, deny)
}

// Files and folders that hold secrets. Folders end in /.
var (
	linuxDenied = []string{"/etc/fluent-bit/", "/var/lib/fluent-bit/", "/etc/td-agent-bit/", "/etc/signalith/", "/var/lib/signalith/",
		"/etc/signalith-agent/", "/var/lib/signalith-agent/", "/etc/signalith-sensor/",
		"/etc/shadow", "/etc/gshadow", "/etc/shadow-", "/etc/gshadow-", "/etc/sudoers", "/etc/sudoers.d/", "/etc/ssh/", "/root/",
		"/proc/", "/sys/", "/dev/", "/etc/ssl/private/", "/etc/pki/"}
	windowsDenied = []string{"?:/program files/fluent-bit/", "?:/programdata/fluent-bit/", "?:/programdata/signalith/", "?:/program files/signalith/",
		"?:/programdata/signalith agent/", "?:/program files/signalith agent/",
		"?:/windows/system32/config/", "?:/windows/ntds/", "?:/users/*/.ssh/", "?:/programdata/ssh/"}
)

// secretPath reports whether p names, or as a pattern can match, a denied
// file or something in a denied folder, or a key file.
func secretPath(p string, deny []string) bool {
	if ext := strings.ToLower(path.Ext(p)); ext == ".key" || ext == ".pfx" || ext == ".p12" || ext == ".kdbx" {
		return true
	}
	for _, d := range deny {
		if strings.HasSuffix(d, "/") {
			// In the folder: the path, or the part of a pattern before its
			// first wildcard, is under it, or the pattern's folder matches it.
			lit := p
			if i := strings.IndexAny(p, "*?["); i >= 0 {
				lit = p[:i]
			}
			if m, _ := path.Match(d+"*", lit); m || strings.HasPrefix(lit, d) || strings.HasPrefix(lit+"/", d) {
				return true
			}
			for dir := path.Dir(p); dir != "/" && dir != "."; dir = path.Dir(dir) {
				dd := strings.TrimSuffix(d, "/")
				if m, _ := path.Match(dd, dir); m {
					return true
				}
				if m, _ := path.Match(dir, dd); m {
					return true
				}
			}
			continue
		}
		if m, _ := path.Match(p, d); m || p == d {
			return true
		}
	}
	return false
}
