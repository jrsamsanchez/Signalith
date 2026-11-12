// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package agentproto

import (
	"path"
	"regexp"
	"strings"
)

// SecretPath reports whether the file path or pattern p, on goos (linux
// or windows), names or can match a file that holds secrets: the agents'
// own configuration and token, Signalith's, password and key stores.
// Signalith refuses to write such a path into a log input, and the
// Signalith Agent refuses a Fluent Bit configuration that tails one
// (ASI-03).
func SecretPath(p, goos string) bool {
	// A path that could name a file other than as written (.., ~, a
	// relative path) counts as one.
	if strings.Contains(p, "..") {
		return true
	}
	deny := linuxDenied
	if goos == "windows" {
		// So does a device path, a short name such as PROGRA~3 or an
		// alternate data stream.
		if len(p) < 3 || p[1] != ':' || strings.Contains(p[2:], ":") || shortName.MatchString(p) {
			return true
		}
		// Windows paths do not care about case, the kind of slash or, here,
		// the drive.
		p = "?" + strings.ToLower(strings.ReplaceAll(p[1:], `\`, "/"))
		deny = windowsDenied
	}
	if goos != "windows" && (!strings.HasPrefix(p, "/") || strings.Contains(p, "~")) {
		return true
	}
	return secretPath(p, deny)
}

// shortName is a Windows 8.3 short name.
var shortName = regexp.MustCompile(`~[0-9]`)

// Files and folders that hold secrets. Folders end in /.
var (
	linuxDenied = []string{"/etc/fluent-bit/", "/var/lib/fluent-bit/", "/etc/td-agent-bit/", "/etc/signalith/", "/var/lib/signalith/",
		"/etc/signalith-agent/", "/var/lib/signalith-agent/", "/etc/signalith-sensor/",
		"/etc/shadow", "/etc/gshadow", "/etc/shadow-", "/etc/gshadow-", "/etc/sudoers", "/etc/sudoers.d/", "/etc/ssh/", "/root/",
		"/proc/", "/sys/", "/dev/", "/etc/ssl/private/", "/etc/pki/",
		// Credential files of users, services and tools (ING-217).
		"/home/*/.ssh/", "/home/*/.aws/", "/home/*/.kube/", "/home/*/.docker/", "/home/*/.gnupg/", "/home/*/.azure/",
		"/home/*/.config/gcloud/", "/home/*/.netrc", "/home/*/.pgpass", "/home/*/.my.cnf", "/home/*/.git-credentials",
		"/home/*/.bash_history", "/home/*/.zsh_history", "/home/*/.mysql_history", "/home/*/.psql_history",
		"/etc/krb5.keytab", "/etc/wireguard/", "/etc/kubernetes/", "/etc/letsencrypt/", "/etc/sssd/", "/etc/openvpn/",
		"/etc/mysql/debian.cnf", "/var/lib/samba/private/"}
	windowsDenied = []string{"?:/program files/fluent-bit/", "?:/programdata/fluent-bit/", "?:/programdata/signalith/", "?:/program files/signalith/",
		"?:/programdata/signalith agent/", "?:/program files/signalith agent/",
		"?:/windows/system32/config/", "?:/windows/ntds/", "?:/users/*/.ssh/", "?:/programdata/ssh/",
		// Credential files of users, services and browsers (ING-217).
		"?:/users/*/.aws/", "?:/users/*/.kube/", "?:/users/*/.docker/", "?:/users/*/.azure/",
		"?:/users/*/appdata/roaming/microsoft/credentials/", "?:/users/*/appdata/local/microsoft/credentials/",
		"?:/users/*/appdata/roaming/microsoft/protect/", "?:/users/*/appdata/local/google/chrome/user data/",
		"?:/users/*/appdata/local/microsoft/edge/user data/", "?:/users/*/appdata/roaming/mozilla/firefox/profiles/",
		"?:/inetpub/wwwroot/web.config"}
)

// secretPath reports whether p names, or as a pattern can match, a denied
// file or something in a denied folder, or a key file.
func secretPath(p string, deny []string) bool {
	if ext := strings.ToLower(path.Ext(p)); ext == ".key" || ext == ".pfx" || ext == ".p12" || ext == ".kdbx" || ext == ".keytab" || ext == ".ovpn" {
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
		// The pattern matches the file, or the file, named for every
		// user (/home/*/.netrc), matches the path.
		if m, _ := path.Match(p, d); m || p == d {
			return true
		}
		if m, _ := path.Match(d, p); m {
			return true
		}
	}
	return false
}
