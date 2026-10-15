package clusterinstall

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strings"

	"github.com/jrsamsanchez/signalith/internal/agents"
)

// SensorLine is what the network sensor's pasted line is made from (Add
// data > Network sensor > Set up a new sensor).
type SensorLine struct {
	// URL is the address the sensor sends to and downloads the script
	// from (https://siem:8080).
	URL string
	// Version is this server's version, which the script reports in the
	// sensor's status line.
	Version string
	// CASHA256 is the SHA-256 (hex) of the certificate authority the
	// sensor pins, and NextCASHA256 the one prepared to replace it; both
	// empty when the server's certificate is from a public CA the sensor
	// already trusts.
	CASHA256, NextCASHA256 string
	// Interface is the capture port, "" to choose on the sensor.
	Interface string
	// Networks are "your networks", comma-separated CIDRs; "" uses the
	// script's default (the private ranges).
	Networks string
	// Zeek and Suricata are the tools to install (at least one), and
	// Protocols also sends Suricata's protocol logs when both run.
	Zeek, Suricata, Protocols bool
	// Docker runs the three programs in containers instead.
	Docker bool
}

// SensorCommands is the sensor's pasted line, and a note for the page.
type SensorCommands struct {
	Linux        string `json:"linux"`
	Note         string `json:"note"`
	ScriptSHA256 string `json:"script_sha256"`
}

// SensorSystems are the systems the sensor install script supports, as
// the page and the docs say them.
const SensorSystems = "Ubuntu 22.04 or 24.04, Debian 12, Rocky Linux 9 or AlmaLinux 9 (64-bit x86 or ARM)"

var (
	// ifaceText is a Linux network interface name: at most 15
	// characters, none a shell reads specially.
	ifaceText = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,15}$`)
	// maxNetworks caps the CIDRs one line carries.
	maxNetworks = 64
)

// FieldError is a value the page shows under its field.
type FieldError struct {
	Field string
	Err   error
}

func (e *FieldError) Error() string { return e.Err.Error() }
func (e *FieldError) Unwrap() error { return e.Err }

// CleanNetworks checks a comma-separated list of CIDRs and writes it in
// canonical form ("10.0.0.0/8,fd00::/8"), so the line carries only
// digits, letters, dots, colons, slashes and commas.
func CleanNetworks(s string) (string, error) {
	var out []string
	for part := range strings.SplitSeq(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		p, err := netip.ParsePrefix(part)
		if err != nil {
			return "", fmt.Errorf("%q is not a network such as 192.168.1.0/24", part)
		}
		out = append(out, p.Masked().String())
	}
	if len(out) > maxNetworks {
		return "", fmt.Errorf("at most %d networks", maxNetworks)
	}
	return strings.Join(out, ","), nil
}

func (l *SensorLine) check() error {
	if err := checkURL(l.URL); err != nil {
		return &FieldError{Field: "server", Err: err}
	}
	if !versionText.MatchString(l.Version) {
		return errors.New("not a version")
	}
	for _, sum := range []string{l.CASHA256, l.NextCASHA256} {
		if sum != "" && !hexText.MatchString(sum) {
			return errors.New("not a SHA-256")
		}
	}
	if l.NextCASHA256 != "" && l.CASHA256 == "" {
		return errors.New("a next certificate authority without a current one")
	}
	if l.Interface != "" && !ifaceText.MatchString(l.Interface) {
		return &FieldError{Field: "interface", Err: errors.New("a port name has at most 15 letters, digits and . _ : -, such as ens192")}
	}
	nets, err := CleanNetworks(l.Networks)
	if err != nil {
		return &FieldError{Field: "networks", Err: err}
	}
	l.Networks = nets
	if !l.Zeek && !l.Suricata {
		return &FieldError{Field: "tools", Err: errors.New("pick Zeek, Suricata or both: the tools to install on the sensor")}
	}
	return nil
}

// SensorLines makes the network sensor's pasted line: it downloads the
// sensor install script, checks its SHA-256 and runs it with sudo, giving
// it the sensor's agent token on its standard input (here
// agents.TokenPlaceholder, which the page replaces with a new token when
// the line is copied). As for Add a server, the download does not check
// the server's certificate, which the new machine does not trust yet: the
// SHA-256 checks the script, and the script checks the certificate
// authority against --ca-sha256 before it trusts it.
func SensorLines(l SensorLine) (SensorCommands, error) {
	if err := l.check(); err != nil {
		return SensorCommands{}, err
	}
	base := strings.TrimSuffix(l.URL, "/")
	sha := scriptSHA.Sensor
	line := fmt.Sprintf("f=$(mktemp) && curl -fsSk --proto '=https' %s/api/sensor/install.sh -o \"$f\" && echo \"%s  $f\" | sha256sum -c --quiet && echo '%s' | sudo sh \"$f\" --role sensor --from %s",
		base, sha, agents.TokenPlaceholder, base)
	if l.CASHA256 != "" {
		line += " --ca-sha256 " + l.CASHA256
	}
	if l.NextCASHA256 != "" {
		line += " --next-ca-sha256 " + l.NextCASHA256
	}
	line += " --version " + l.Version + " --token -"
	if l.Interface != "" {
		line += " --interface " + l.Interface
	}
	if l.Networks != "" {
		line += " --networks " + l.Networks
	}
	switch {
	case !l.Zeek:
		line += " --no-zeek"
	case !l.Suricata:
		line += " --no-suricata"
	case l.Protocols:
		line += " --suricata-protocols"
	}
	note := "Runs on " + SensorSystems + ". The line holds a new token for this sensor: anyone with it can send data as this sensor, so don't share it."
	if l.Docker {
		line += " --docker"
		note = "Runs on Linux with Docker Engine 24 or later and Docker Compose v2 (not Docker Desktop, which cannot listen on a physical port). The line holds a new token for this sensor: anyone with it can send data as this sensor, so don't share it."
	}
	return SensorCommands{Linux: line, Note: note, ScriptSHA256: sha}, nil
}
