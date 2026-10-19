package deploy

import (
	"regexp"
	"strings"
	"testing"
)

// A new Windows install takes syslog over TLS only: plain syslog over UDP
// and TCP is unencrypted and can be forged, so install.ps1 leaves it off
// unless -SyslogUdp or -SyslogTcp names an address, passes the values to
// signalith init as they are (an empty one stays empty), and opens the
// firewall only for the listeners the config turns on.
func TestInstallPS1SyslogTLSOnlyByDefault(t *testing.T) {
	ps1 := strings.ReplaceAll(string(InstallPS1), "\r\n", "\n")
	param := func(name string) string {
		t.Helper()
		m := regexp.MustCompile(`(?m)^\s*\[string\]\$` + name + `\s*=\s*"([^"]*)"`).FindStringSubmatch(ps1)
		if m == nil {
			t.Fatalf("install.ps1 has no [string]$%s parameter", name)
		}
		return m[1]
	}
	for name, want := range map[string]string{"SyslogUdp": "", "SyslogTcp": "", "SyslogTls": "0.0.0.0:6514"} {
		if got := param(name); got != want {
			t.Errorf("-%s defaults to %q, want %q", name, got, want)
		}
	}
	// -flag=value keeps an empty value, which PowerShell would drop as a
	// separate argument, and init's own default would then apply.
	for _, arg := range []string{`"-syslog-udp=$SyslogUdp"`, `"-syslog-tcp=$SyslogTcp"`, `"-syslog-tls=$SyslogTls"`} {
		if !strings.Contains(ps1, arg) {
			t.Errorf("install.ps1 does not pass %s to signalith init", arg)
		}
	}
	// The syslog firewall rules come from the listeners the config has on.
	if !strings.Contains(ps1, "validate -c $config -syslog-ports") || strings.Contains(ps1, "-LocalPort 514") {
		t.Error("install.ps1 must open syslog ports only for the listeners signalith validate -syslog-ports lists")
	}
}
