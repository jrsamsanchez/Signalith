// Package agents generates Fluent Bit and OpenTelemetry Collector
// configurations, and osquery setups, so nobody has to write agent config
// by hand: pick the OS, copy the file, restart the agent.
package agents

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode"
)

// TokenPlaceholder stands for the agent token in a configuration made for
// the Add data page, which puts a new token in its place when the
// configuration is copied or downloaded (see internal/agenttokens). It
// needs no quoting in any of the configurations or scripts.
const TokenPlaceholder = "@@AGENT_TOKEN@@"

// Options select what an agent collects.
type Options struct {
	OS        string // "linux", "windows", "otel" (an OpenTelemetry Collector) or "osquery"
	ServerURL string // Signalith public URL
	Token     string // agent token (TokenPlaceholder for the Add data page)
	// LinuxSource is "file" (tail /var/log/auth.log and /var/log/secure),
	// "journal" (systemd journal, for distros without rsyslog) or "wazuh"
	// (tail a Wazuh manager's alerts.json; Fluent Bit only).
	LinuxSource string
	// Sysmon adds the Sysmon operational channel on Windows, and Sysmon
	// for Linux's events (from the systemd journal) on Linux.
	Sysmon bool
	// PowerShell adds Windows PowerShell's operational channel, where
	// script block logging writes the scripts that run (event 4104).
	PowerShell bool
	// CollectorOS is where the OpenTelemetry Collector runs, for OS
	// "otel": "linux" (the default) or "windows".
	CollectorOS string
	// Platform is the host osquery runs on, for OS "osquery": "linux" (the
	// default), "windows" or "darwin".
	Platform string
	// CA is the certificate authority, in PEM, that the agent checks the
	// server's certificate with over https: Signalith's own, or the root
	// of the admin's certificate. Empty when the agent's system already
	// trusts the server's certificate, unless CAUnknown.
	CA string
	// CAUnknown means the server's certificate is from a private CA that
	// Signalith does not have (server.tls_cert without its chain): the
	// agent still reads tls.ca_file, and a step says to put that CA there.
	CAUnknown bool
	// OwnCA means the certificate comes from Signalith's own CA, which
	// vouches only for this server, so checking who issued it is enough
	// when the agent reaches the server by IP address.
	OwnCA bool
	// CertNames are the DNS names the server's certificate covers. With
	// any other CA, an agent that reaches the server by IP address checks
	// the certificate against the first one it can use (see VerifyName).
	CertNames []string
	// Version is the Signalith version that made the configuration, and
	// CAPin the first 16 hex digits (lower case) of the SHA-256 of the
	// certificate authority it pins, "" when it pins none. NextCAPin is
	// the one prepared to replace it, when CA has both. The agent sends
	// them with every batch (X-Signalith-Config), so the Endpoints page
	// can tell which agents need a new configuration.
	Version   string
	CAPin     string
	NextCAPin string
}

// ConfigHeader is the value of the X-Signalith-Config header for a
// configuration made by version that pins the CAs pins (none, or "" for
// none): "ca=<pin>,<pin>;v=<version>", or "v=<version>" alone.
func ConfigHeader(version string, pins ...string) string {
	if version == "" {
		version = "dev"
	}
	pins = slices.DeleteFunc(slices.Clone(pins), func(p string) bool { return p == "" })
	if len(pins) == 0 {
		return "v=" + version
	}
	return "ca=" + strings.Join(pins, ",") + ";v=" + version
}

// ErrNoNameToCheck is returned when an agent would reach the server by IP
// address with nothing to tie the certificate to this server.
var ErrNoNameToCheck = errors.New("agents can't check that the certificate belongs to this server")

// Where the agent keeps the CA certificate it checks the server with.
const (
	LinuxCAPath   = "/etc/fluent-bit/signalith-ca.pem"
	WindowsCAPath = `C:\Program Files\fluent-bit\conf\signalith-ca.pem`
)

// WazuhAlertsPath is where a Wazuh manager writes its alerts, one JSON
// alert per line.
const WazuhAlertsPath = "/var/ossec/logs/alerts/alerts.json"

// Agent is a generated agent setup.
type Agent struct {
	OS         string `json:"os"`
	ConfigPath string `json:"config_path"`
	Config     string `json:"config"`
	// ServerURL is the address the config sends to, and ServerLoopback
	// says it only works on the Signalith machine itself (localhost).
	ServerURL      string   `json:"server_url"`
	ServerLoopback bool     `json:"server_loopback"`
	Steps          []string `json:"steps"`
	// ConfigStep is the step (from 1) that saves the config file, and
	// CAStep the one that saves the CA certificate (0: none).
	ConfigStep int `json:"config_step"`
	CAStep     int `json:"ca_step,omitempty"`
	// CAPath is where the agent reads the CA certificate, and CA the
	// certificate to save there; CAFingerprint is its SHA-256, for
	// checking it out of band.
	CAPath        string `json:"ca_path,omitempty"`
	CA            string `json:"ca,omitempty"`
	CAFingerprint string `json:"ca_fingerprint,omitempty"`
}

var hostLabel = regexp.MustCompile(`^[A-Za-z0-9_]([A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?$`)

// ParseServerURL checks an address agents send to: http or https, a host
// name or IP address and an optional port, nothing else. It is strict
// because the host and port are written into a config file.
func ParseServerURL(raw string) (*url.URL, error) {
	if raw == "" {
		return nil, errors.New("address is empty; use one such as https://192.168.1.20:8080")
	}
	if len(raw) > 300 {
		return nil, errors.New("address is too long")
	}
	for _, r := range raw {
		if unicode.IsSpace(r) || unicode.IsControl(r) {
			return nil, errors.New("address must not contain spaces or line breaks")
		}
	}
	if strings.ContainsAny(raw, "?#") {
		return nil, errors.New("address must not include ? or #")
	}
	if l := strings.ToLower(raw); !strings.HasPrefix(l, "http://") && !strings.HasPrefix(l, "https://") {
		return nil, errors.New("address needs http:// or https:// at the start")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, errors.New("address is not valid; use one such as https://192.168.1.20:8080")
	}
	if u.User != nil {
		return nil, errors.New("address must not include a user name or password")
	}
	if u.Host == "" {
		return nil, errors.New("address needs a host name or IP address, such as https://192.168.1.20:8080")
	}
	if u.Path != "" && u.Path != "/" {
		return nil, errors.New("address must not include a path; agents always send to /api/ingest")
	}
	if port := u.Port(); port != "" || strings.HasSuffix(u.Host, ":") {
		if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 || strconv.Itoa(n) != port {
			return nil, errors.New("port must be a number from 1 to 65535")
		}
	}
	if host := u.Hostname(); !validHost(host, strings.HasPrefix(u.Host, "[")) {
		return nil, fmt.Errorf("%q is not a host name or IP address", host)
	}
	return u, nil
}

// validHost accepts an IPv4 address, a bracketed IPv6 address (no zone) or
// a DNS name made of letters, digits, - and _. A name ending in a number
// must be a whole IPv4 address, so 127.1 or 300.1.1.1 are refused.
func validHost(host string, bracketed bool) bool {
	if bracketed {
		return strings.Contains(host, ":") && net.ParseIP(host) != nil
	}
	if host == "" || len(host) > 253 {
		return false
	}
	labels := strings.Split(host, ".")
	for _, l := range labels {
		if !hostLabel.MatchString(l) {
			return false
		}
	}
	if strings.Trim(labels[len(labels)-1], "0123456789") == "" {
		ip := net.ParseIP(host)
		return ip != nil && ip.To4() != nil
	}
	return true
}

// IsLoopback reports whether only the Signalith machine itself can use the
// address: localhost, 127.0.0.0/8 or ::1 (and 0.0.0.0 or ::, which mean
// "this machine" too).
func IsLoopback(u *url.URL) bool {
	h := strings.ToLower(u.Hostname())
	if h == "localhost" || strings.HasSuffix(h, ".localhost") {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && (ip.IsLoopback() || ip.IsUnspecified())
}

// Generate returns a Fluent Bit config and install steps.
func Generate(o Options) (*Agent, error) {
	switch o.OS {
	case "otel":
		return generateOTel(o)
	case "osquery":
		return generateOsquery(o)
	}
	u, err := ParseServerURL(o.ServerURL)
	if err != nil {
		return nil, fmt.Errorf("server address %q: %w", o.ServerURL, err)
	}
	if o.Token == "" {
		return nil, errors.New("no agent token given")
	}
	host := u.Hostname()
	port := u.Port()
	tls := "Off"
	if u.Scheme == "https" {
		tls = "On"
		if port == "" {
			port = "443"
		}
	} else if port == "" {
		port = "80"
	}

	// Over loopback nothing sits in between, so only an address that
	// crosses the network needs the check.
	if ip := net.ParseIP(host); tls == "On" && ip != nil && !ip.IsLoopback() && !o.OwnCA && verifyName(host, o) == "" {
		return nil, fmt.Errorf("%w: the certificate at %s comes from a certificate authority that also vouches for other computers, "+
			"and it has no host name to check. Use a host name the certificate covers as the address, or a certificate that includes one", ErrNoNameToCheck, host)
	}

	var b strings.Builder
	a := &Agent{OS: o.OS, ServerURL: u.Scheme + "://" + u.Host, ServerLoopback: IsLoopback(u)}
	// Over https the agent checks the server's certificate against the CA
	// saved next to its config, unless its system trusts it already.
	useCA := u.Scheme == "https" && (strings.TrimSpace(o.CA) != "" || o.CAUnknown)
	if useCA {
		a.CA = strings.TrimSpace(o.CA)
		if a.CA != "" {
			a.CA += "\n"
		}
	}
	switch o.OS {
	case "linux":
		a.ConfigPath = "/etc/fluent-bit/fluent-bit.conf"
		if o.LinuxSource == "wazuh" {
			b.WriteString("# Signalith agent for a Wazuh manager: sends its alerts. Generated by Signalith.\n")
		} else {
			b.WriteString("# Signalith agent for Linux, generated by Signalith.\n")
		}
		b.WriteString(section("SERVICE", [][2]string{
			{"Flush", "5"}, {"Log_Level", "info"},
			{"storage.path", "/var/lib/fluent-bit/signalith-buffer"},
			{"storage.sync", "normal"},
		}))
		if o.LinuxSource == "wazuh" {
			// The manager writes one JSON alert per line. The line is sent
			// as it is, under the Wazuh tag, and Signalith decodes it, so
			// no parsers file is needed. Alerts can be long (full_log), so
			// lines up to 1 MB are read and longer ones skipped.
			b.WriteString(section("INPUT", [][2]string{
				{"Name", "tail"}, {"Tag", "wazuh"},
				{"Path", WazuhAlertsPath},
				{"DB", "/var/lib/fluent-bit/signalith-wazuh.db"},
				{"Buffer_Chunk_Size", "64k"},
				{"Buffer_Max_Size", "1M"},
				{"Skip_Long_Lines", "On"},
				{"storage.type", "filesystem"},
			}))
		} else if o.LinuxSource == "journal" {
			journal := [][2]string{
				{"Name", "systemd"}, {"Tag", "linux.journal"},
				{"DB", "/var/lib/fluent-bit/signalith-journal.db"},
				{"Systemd_Filter", "SYSLOG_IDENTIFIER=sshd"},
				{"Systemd_Filter", "SYSLOG_IDENTIFIER=sudo"},
				{"Systemd_Filter", "SYSLOG_IDENTIFIER=su"},
				{"Systemd_Filter", "SYSLOG_IDENTIFIER=useradd"},
				{"Systemd_Filter", "SYSLOG_IDENTIFIER=userdel"},
				{"Systemd_Filter", "SYSLOG_IDENTIFIER=usermod"},
				{"Systemd_Filter", "SYSLOG_IDENTIFIER=gpasswd"},
				// ClamAV: on-access and on-demand scans, and definition
				// updates. Red Hat-family systems log them here only.
				{"Systemd_Filter", "SYSLOG_IDENTIFIER=clamd"},
				{"Systemd_Filter", "SYSLOG_IDENTIFIER=clamonacc"},
				{"Systemd_Filter", "SYSLOG_IDENTIFIER=freshclam"},
			}
			if o.Sysmon {
				journal = append(journal, [2]string{"Systemd_Filter", "SYSLOG_IDENTIFIER=sysmon"})
			}
			b.WriteString(section("INPUT", append(journal, [][2]string{
				{"Read_From_Tail", "On"},
				{"storage.type", "filesystem"},
			}...)))
			// clamd checks its database every few minutes; those lines
			// say nothing and would be most of the volume.
			b.WriteString(section("FILTER", [][2]string{
				{"Name", "grep"}, {"Match", "linux.journal"},
				{"Exclude", "MESSAGE ^SelfCheck"},
			}))
		} else {
			if o.Sysmon {
				// Sysmon for Linux logs through syslog into the journal; only
				// its events are read from there.
				b.WriteString(section("INPUT", [][2]string{
					{"Name", "systemd"}, {"Tag", "linux.journal"},
					{"DB", "/var/lib/fluent-bit/signalith-sysmon.db"},
					{"Systemd_Filter", "SYSLOG_IDENTIFIER=sysmon"},
					{"Read_From_Tail", "On"},
					{"storage.type", "filesystem"},
				}))
			}
			b.WriteString(section("INPUT", [][2]string{
				{"Name", "tail"}, {"Tag", "linux.auth"},
				{"Path", "/var/log/auth.log,/var/log/secure"},
				{"DB", "/var/lib/fluent-bit/signalith-auth.db"},
				{"storage.type", "filesystem"},
			}))
			// ClamAV's own log files (clamd, clamonacc, freshclam). Path_Key
			// says which file a line came from, and the host name is added
			// because the lines carry none. A host without ClamAV has no
			// such files, which the tail input ignores.
			b.WriteString(section("INPUT", [][2]string{
				{"Name", "tail"}, {"Tag", "linux.clamav"},
				{"Path", "/var/log/clamav/*.log"},
				{"Path_Key", "file"},
				{"DB", "/var/lib/fluent-bit/signalith-clamav.db"},
				{"storage.type", "filesystem"},
			}))
			b.WriteString(section("FILTER", [][2]string{
				{"Name", "sysinfo"}, {"Match", "linux.clamav"},
				{"hostname_key", "hostname"},
			}))
			b.WriteString(section("FILTER", [][2]string{
				{"Name", "grep"}, {"Match", "linux.clamav"},
				{"Exclude", "log SelfCheck"},
			}))
		}
		// Only root may read the config: it holds the agent token.
		a.Steps = []string{"Install Fluent Bit (3.1 or later): curl https://raw.githubusercontent.com/fluent/fluent-bit/master/install.sh | sh"}
		if o.LinuxSource == "wazuh" {
			a.Steps = []string{"On the Wazuh manager (not on each Wazuh agent), install Fluent Bit (3.1 or later): curl https://raw.githubusercontent.com/fluent/fluent-bit/master/install.sh | sh"}
		}
		if o.Sysmon && o.LinuxSource != "wazuh" {
			a.Steps = append(a.Steps, "Install Sysmon for Linux (open source, github.com/Sysinternals/SysmonForLinux) and start it with a configuration (sudo sysmon -accepteula -i config.xml), so process, network and file events are recorded")
		}
		if useCA {
			a.CAPath = LinuxCAPath
			a.Steps = append(a.Steps, caStep(a, "signalith-ca.pem"))
		}
		a.Steps = append(a.Steps, "Save the configuration below as fluent-bit.conf.")
		a.ConfigStep = len(a.Steps)
		if useCA {
			a.Steps = append(a.Steps, "From the folder you saved both files in, put them in place. Only root can read the configuration, since it holds the agent token: "+
				"sudo install -m 644 -o root -g root signalith-ca.pem "+LinuxCAPath+" && sudo install -m 600 -o root -g root fluent-bit.conf "+a.ConfigPath)
		} else {
			a.Steps = append(a.Steps, "From the folder you saved it in, put it in place. Only root can read it, since it holds the agent token: "+
				"sudo install -m 600 -o root -g root fluent-bit.conf "+a.ConfigPath)
		}
		done := "Events appear in Search within a minute; check the Health page if they do not."
		if o.LinuxSource == "wazuh" {
			done = "New Wazuh alerts appear in Search within a minute (search sourcetype=wazuh:alerts); alerts raised before Fluent Bit started are not sent. Check the Health page if nothing arrives."
		}
		a.Steps = append(a.Steps,
			"Restart the agent: sudo systemctl enable --now fluent-bit && sudo systemctl restart fluent-bit",
			done)
	case "windows":
		a.ConfigPath = `C:\Program Files\fluent-bit\conf\fluent-bit.conf`
		// Microsoft Defender is always collected: it is part of every
		// supported Windows version, needs no install and logs little.
		channels := "Security,Microsoft-Windows-Windows Defender/Operational"
		if o.Sysmon {
			channels += ",Microsoft-Windows-Sysmon/Operational"
		}
		if o.PowerShell {
			channels += ",Microsoft-Windows-PowerShell/Operational"
		}
		b.WriteString("# Signalith agent for Windows, generated by Signalith.\n")
		b.WriteString(section("SERVICE", [][2]string{
			{"Flush", "5"}, {"Log_Level", "info"},
			{"storage.path", `C:\ProgramData\fluent-bit\signalith-buffer`},
		}))
		b.WriteString(section("INPUT", [][2]string{
			{"Name", "winevtlog"}, {"Tag", "win.events"},
			{"Channels", channels},
			// Without this, a host with no Defender (Server Core with the
			// feature removed) or no Sysmon stops the input from starting.
			{"Ignore_Missing_Channels", "On"},
			{"Interval_Sec", "1"},
			{"String_Inserts", "On"},
			{"DB", `C:\ProgramData\fluent-bit\signalith-winevtlog.sqlite`},
			{"storage.type", "filesystem"},
		}))
		if o.Sysmon {
			a.Steps = append(a.Steps, "Install Sysmon with a config such as SwiftOnSecurity's sysmon-config, so process and network events are recorded")
		}
		if o.PowerShell {
			a.Steps = append(a.Steps, scriptBlockLoggingStep)
		}
		a.Steps = append(a.Steps, "Install Fluent Bit for Windows, 3.1 or later (64-bit installer), from https://docs.fluentbit.io/manual/installation/windows")
		files := "fluent-bit.conf"
		if useCA {
			a.CAPath = WindowsCAPath
			a.Steps = append(a.Steps, caStep(a, "signalith-ca.pem"))
			files = "signalith-ca.pem, fluent-bit.conf"
		}
		a.Steps = append(a.Steps, "Save the configuration below as fluent-bit.conf.")
		a.ConfigStep = len(a.Steps)
		// A browser cannot save into Program Files, so the files are
		// copied there. Only SYSTEM and Administrators may then read the
		// config, which holds the agent token (Program Files lets every
		// user read), and the buffer, which holds Security log events
		// (ProgramData does too). The accounts are given by their SIDs,
		// whose names differ in other languages.
		a.Steps = append(a.Steps,
			"In an elevated PowerShell, put them in place from your Downloads folder, and let only SYSTEM and Administrators read the configuration and the agent's buffer, "+
				"since they hold the agent token and Security log events: "+
				`cd "$env:USERPROFILE\Downloads"`+"\n"+
				"Copy-Item "+files+` 'C:\Program Files\fluent-bit\conf\' -Force`+"\n"+
				`icacls '`+a.ConfigPath+`' /inheritance:r /grant:r '*S-1-5-18:F' '*S-1-5-32-544:F'`+"\n"+
				`New-Item -ItemType Directory -Force 'C:\ProgramData\fluent-bit' | Out-Null`+"\n"+
				`icacls 'C:\ProgramData\fluent-bit' /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F'`,
			`Register and start the service in an elevated PowerShell (if the agent is already installed, run Restart-Service fluent-bit instead): New-Service fluent-bit -BinaryPathName '"C:\Program Files\fluent-bit\bin\fluent-bit.exe" -c "C:\Program Files\fluent-bit\conf\fluent-bit.conf"' -StartupType Automatic; Start-Service fluent-bit`,
			"Events appear in Search within a minute; check the Health page if they do not.")
	default:
		return nil, fmt.Errorf("unknown os %q; use linux or windows", o.OS)
	}
	out := [][2]string{
		{"Name", "http"}, {"Match", "*"},
		{"Host", host}, {"Port", port},
		{"URI", "/api/ingest"},
		{"Format", "json"},
		{"Header", "Authorization Bearer " + o.Token},
		{"Header_Tag", "X-Signalith-Tag"},
		// The computer's name, and what this configuration expects, so
		// the Endpoints page lists each agent once and can say when one
		// needs a new configuration. Only labels: never used to let
		// anyone in. Fluent Bit fills in ${HOSTNAME} itself when it is
		// not set (env_preset in src/flb_env.c calls gethostname). On
		// Windows, where services have no HOSTNAME, that works too:
		// flb_create (src/flb_lib.c) starts Winsock before
		// flb_config_init makes the environment.
		{"Header", "X-Signalith-Agent ${HOSTNAME}"},
		{"Header", "X-Signalith-Config " + ConfigHeader(o.Version, o.CAPin, o.NextCAPin)},
		{"tls", tls}, {"tls.verify", "On"},
	}
	if a.CAPath != "" {
		out = append(out, [2]string{"tls.ca_file", a.CAPath})
	}
	// The name the agent asks the server for, and checks the server's
	// certificate is for: tls.verify alone only checks who issued it, so
	// with a public or company CA any certificate it issued would do.
	// An IP address is not a valid name for SNI, and Fluent Bit cannot
	// check one against a certificate. That is safe with Signalith's own
	// CA, which vouches for nothing else; with any other, the agent asks
	// for and checks a name the certificate carries instead.
	if tls == "On" {
		if name := verifyName(host, o); name != "" {
			out = append(out, [2]string{"tls.vhost", name}, [2]string{"tls.verify_hostname", "On"})
		}
	}
	out = append(out, [2]string{"Retry_Limit", "False"})
	b.WriteString(section("OUTPUT", out))
	a.Config = b.String()
	return a, nil
}

// verifyName returns the name an agent sending to host checks the
// server's certificate against: host itself when it is a name; for an IP
// address, none with Signalith's own CA, else the first of CertNames that
// is a plain host name (not a wildcard or localhost), or "" when there is
// none.
func verifyName(host string, o Options) string {
	if net.ParseIP(host) == nil {
		return host
	}
	if o.OwnCA {
		return ""
	}
	for _, n := range o.CertNames {
		n = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(n), "."))
		if n == "localhost" || strings.HasSuffix(n, ".localhost") || net.ParseIP(n) != nil || !validHost(n, false) {
			continue
		}
		return n
	}
	return ""
}

// caStep is the step that saves the CA certificate as name, and records
// its number.
func caStep(a *Agent, name string) string {
	a.CAStep = len(a.Steps) + 1
	if a.CA == "" {
		return "Save the certificate of the CA that issued Signalith's certificate as " + name +
			". The agent uses it to check it's talking to this server. Signalith's certificate file (server.tls_cert) doesn't include it, so get it from whoever issued the certificate."
	}
	return "Save Signalith's CA certificate as " + name + ". The agent uses it to check it's talking to this server."
}

func section(name string, kv [][2]string) string {
	var b strings.Builder
	b.WriteString("\n[" + name + "]\n")
	for _, p := range kv {
		fmt.Fprintf(&b, "    %-20s %s\n", p[0], p[1])
	}
	return b.String()
}

// scriptBlockLoggingStep turns on PowerShell script block logging, which
// is off by default, so the scripts that run are recorded.
const scriptBlockLoggingStep = `Turn on PowerShell script block logging, so the scripts that run are recorded (or use Group Policy: Administrative Templates > Windows Components > Windows PowerShell > Turn on PowerShell Script Block Logging). In an elevated PowerShell: $k = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'; New-Item -Path $k -Force | Out-Null; Set-ItemProperty -Path $k -Name EnableScriptBlockLogging -Value 1`
