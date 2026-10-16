package agents

import (
	"errors"
	"fmt"
	"net"
	"strings"
)

// The osquery option: hosts run osquery and Signalith is their management
// server, through osquery's TLS remote API. Add data hands out a setup
// script that saves three files next to osquery (the flags that point it
// at Signalith, the enroll secret, and the CA certificate) and restarts
// it. The host then enrolls, gets its own node key, and fetches what to
// collect from Signalith; nothing else is configured on the host.

// osqueryFiles are where each platform's osquery package keeps its flags,
// and where the enroll secret and CA certificate are saved next to them.
type osqueryFiles struct {
	dir, flags, secret, ca string
}

var osqueryPaths = map[string]osqueryFiles{
	"linux": {"/etc/osquery", "/etc/osquery/osquery.flags", "/etc/osquery/signalith-enroll-secret", "/etc/osquery/signalith-ca.pem"},
	"darwin": {"/var/osquery", "/var/osquery/osquery.flags", "/var/osquery/signalith-enroll-secret",
		"/var/osquery/signalith-ca.pem"},
	"windows": {`C:\Program Files\osquery`, `C:\Program Files\osquery\osquery.flags`,
		`C:\Program Files\osquery\signalith-enroll-secret`, `C:\Program Files\osquery\signalith-ca.pem`},
}

// OsqueryRoutes are the routes the flags point osquery at.
const (
	osqueryEnroll = "/api/osquery/enroll"
	osqueryConfig = "/api/osquery/config"
	osqueryLog    = "/api/osquery/log"
	osqueryRead   = "/api/osquery/distributed/read"
	osqueryWrite  = "/api/osquery/distributed/write"
)

// OsqueryFlags returns the flags that make osquery use Signalith as its
// management server: hostPort is where it connects (and the name it checks
// the certificate for), ca the CA certificate file ("" to use the
// system's).
func OsqueryFlags(platform, hostPort, secretPath, ca string) string {
	flags := []string{
		"--tls_hostname=" + hostPort,
	}
	if ca != "" {
		flags = append(flags, "--tls_server_certs="+ca)
	}
	flags = append(flags,
		"--enroll_secret_path="+secretPath,
		"--enroll_tls_endpoint="+osqueryEnroll,
		// One record per machine, even after osquery is reinstalled.
		"--host_identifier=uuid",
		"--config_plugin=tls",
		"--config_tls_endpoint="+osqueryConfig,
		"--config_refresh=300",
		"--config_accelerated_refresh=60",
		"--logger_plugin=tls",
		"--logger_tls_endpoint="+osqueryLog,
		"--logger_tls_period=10",
		"--disable_distributed=false",
		"--distributed_plugin=tls",
		"--distributed_interval=10",
		"--distributed_tls_max_attempts=3",
		"--distributed_tls_read_endpoint="+osqueryRead,
		"--distributed_tls_write_endpoint="+osqueryWrite,
		"--disable_events=false",
	)
	// File integrity monitoring: inotify on Linux, FSEvents on macOS and
	// the NTFS journal on Windows.
	if platform == "windows" {
		flags = append(flags, "--enable_ntfs_event_publisher=true")
	} else {
		flags = append(flags, "--enable_file_events=true")
	}
	flags = append(flags, "--utc")
	return strings.Join(flags, "\n") + "\n"
}

func generateOsquery(o Options) (*Agent, error) {
	u, err := ParseServerURL(o.ServerURL)
	if err != nil {
		return nil, fmt.Errorf("server address %q: %w", o.ServerURL, err)
	}
	if u.Scheme != "https" {
		return nil, errors.New("osquery only talks to its management server over HTTPS; use an https:// address")
	}
	if o.Token == "" {
		return nil, errors.New("no agent token given")
	}
	if strings.ContainsAny(o.Token, "\r\n'") {
		return nil, errors.New("the agent token has a quote or line break, which a setup script cannot hold; use a token of letters and digits")
	}
	platform := o.Platform
	if platform == "" {
		platform = "linux"
	}
	files, ok := osqueryPaths[platform]
	if !ok {
		return nil, fmt.Errorf("unknown platform %q; use linux, windows or darwin", platform)
	}
	host, port := u.Hostname(), u.Port()
	if port == "" {
		port = "443"
	}
	// osquery checks the server's certificate against the name it
	// connects to, with no way to check another name: an IP address works
	// only with Signalith's own CA, which puts that address in the
	// certificate and vouches for nothing else.
	if ip := net.ParseIP(host); ip != nil && !ip.IsLoopback() && !o.OwnCA {
		return nil, fmt.Errorf("%w: osquery checks the certificate against the address it connects to, and the certificate at %s comes from a certificate authority "+
			"that also vouches for other computers. Use a host name the certificate covers as the address", ErrNoNameToCheck, host)
	}
	hostPort := host
	if strings.Contains(host, ":") {
		hostPort = "[" + host + "]"
	}
	hostPort += ":" + port

	a := &Agent{OS: "osquery", ServerURL: u.Scheme + "://" + u.Host, ServerLoopback: IsLoopback(u)}
	ca := strings.TrimSpace(o.CA)
	caPath := ""
	if ca != "" {
		a.CA = ca + "\n"
		caPath = files.ca
		a.CAPath = files.ca
	}
	flags := OsqueryFlags(platform, hostPort, files.secret, caPath)
	install := map[string]string{
		"linux":   "Install osquery 5 on the host from https://osquery.io/downloads (the .deb package on Debian and Ubuntu, the .rpm on Red Hat, Fedora and SUSE).",
		"windows": "Install osquery 5 on the host from https://osquery.io/downloads (the .msi package).",
		"darwin":  "Install osquery 5 on the host from https://osquery.io/downloads (the .pkg package).",
	}[platform]
	a.Steps = []string{install}
	switch platform {
	case "windows":
		a.ConfigPath = "signalith-osquery-setup.ps1"
		a.Config = osqueryPowerShell(files, flags, o.Token, a.CA)
		a.Steps = append(a.Steps, "Download the setup script below. It saves Signalith's CA certificate, the enroll secret and osquery's flags in "+files.dir+
			", lets only SYSTEM and Administrators read the secret, and restarts osquery.")
		a.ConfigStep = len(a.Steps)
		a.Steps = append(a.Steps, `Run it in an elevated PowerShell from your Downloads folder: powershell -ExecutionPolicy Bypass -File "$env:USERPROFILE\Downloads\signalith-osquery-setup.ps1"`)
	default:
		a.ConfigPath = "signalith-osquery-setup.sh"
		a.Config = osqueryShell(platform, files, flags, o.Token, a.CA)
		a.Steps = append(a.Steps, "Download the setup script below. It saves Signalith's CA certificate, the enroll secret and osquery's flags in "+files.dir+
			", lets only root read the secret, and restarts osquery.")
		a.ConfigStep = len(a.Steps)
		a.Steps = append(a.Steps, "Run it as root from the folder you saved it in: sudo sh signalith-osquery-setup.sh")
		if platform == "darwin" {
			a.Steps = append(a.Steps, "Give osqueryd Full Disk Access (System Settings, Privacy & Security, Full Disk Access, add /opt/osquery/lib/osquery.app), so it can watch files and read inventory.")
		}
	}
	a.Steps = append(a.Steps, "The host appears on the Endpoints page within a minute, and its inventory and file changes in Search soon after.")
	return a, nil
}

// heredoc is the end marker of the files in the shell script; no line of
// a token or certificate can be it.
const heredoc = "SIGNALITH_EOF"

func osqueryShell(platform string, f osqueryFiles, flags, token, ca string) string {
	var b strings.Builder
	b.WriteString("#!/bin/sh\n")
	b.WriteString("# Signalith osquery setup, generated by Signalith. Run as root on each host after installing osquery.\n")
	b.WriteString("# Keep this file private: it holds the enroll secret.\n")
	b.WriteString("set -eu\n")
	fmt.Fprintf(&b, "install -d -m 0755 %s\n", f.dir)
	b.WriteString("umask 077\n")
	fmt.Fprintf(&b, "cat > %s <<'%s'\n%s\n%s\n", f.secret, heredoc, token, heredoc)
	fmt.Fprintf(&b, "chmod 0600 %s\n", f.secret)
	if ca != "" {
		fmt.Fprintf(&b, "cat > %s <<'%s'\n%s%s\n", f.ca, heredoc, ca, heredoc)
		fmt.Fprintf(&b, "chmod 0644 %s\n", f.ca)
	}
	fmt.Fprintf(&b, "cat > %s <<'%s'\n%s%s\n", f.flags, heredoc, flags, heredoc)
	fmt.Fprintf(&b, "chmod 0644 %s\n", f.flags)
	if platform == "darwin" {
		b.WriteString("plist=/Library/LaunchDaemons/io.osquery.agent.plist\n")
		b.WriteString("cp /var/osquery/io.osquery.agent.plist \"$plist\"\n")
		b.WriteString("launchctl unload \"$plist\" 2>/dev/null || true\n")
		b.WriteString("launchctl load -w \"$plist\"\n")
	} else {
		b.WriteString("systemctl enable osqueryd\n")
		b.WriteString("systemctl restart osqueryd\n")
	}
	b.WriteString("echo \"osquery now reports to Signalith. The host appears on the Endpoints page within a minute.\"\n")
	return b.String()
}

func osqueryPowerShell(f osqueryFiles, flags, token, ca string) string {
	var b strings.Builder
	b.WriteString("# Signalith osquery setup, generated by Signalith. Run in an elevated PowerShell after installing osquery.\n")
	b.WriteString("# Keep this file private: it holds the enroll secret.\n")
	b.WriteString("$ErrorActionPreference = 'Stop'\n")
	fmt.Fprintf(&b, "$dir = '%s'\n", f.dir)
	b.WriteString("if (-not (Test-Path $dir)) { throw \"osquery is not installed in $dir; install it first from https://osquery.io/downloads\" }\n")
	// Here-strings keep the text as it is; ASCII without a byte order
	// mark, which osquery reads.
	fmt.Fprintf(&b, "Set-Content -Path '%s' -Encoding ascii -NoNewline -Value @'\n%s\n'@\n", f.secret, token)
	// Only SYSTEM and Administrators may read the secret (by their SIDs,
	// whose names differ in other languages).
	fmt.Fprintf(&b, "icacls '%s' /inheritance:r /grant:r '*S-1-5-18:F' '*S-1-5-32-544:F' | Out-Null\n", f.secret)
	if ca != "" {
		fmt.Fprintf(&b, "Set-Content -Path '%s' -Encoding ascii -Value @'\n%s'@\n", f.ca, ca)
	}
	fmt.Fprintf(&b, "Set-Content -Path '%s' -Encoding ascii -Value @'\n%s'@\n", f.flags, flags)
	b.WriteString("Set-Service osqueryd -StartupType Automatic\n")
	b.WriteString("Restart-Service osqueryd\n")
	b.WriteString("Write-Host 'osquery now reports to Signalith. The host appears on the Endpoints page within a minute.'\n")
	return b.String()
}
