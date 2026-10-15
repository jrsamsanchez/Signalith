package agents

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// otelConfig parses a generated Collector config.
func otelConfig(t *testing.T, a *Agent) map[string]any {
	t.Helper()
	var m map[string]any
	if err := yaml.Unmarshal([]byte(a.Config), &m); err != nil {
		t.Fatalf("not YAML: %v\n%s", err, a.Config)
	}
	return m
}

func dig(m map[string]any, path ...string) any {
	var v any = m
	for _, k := range path {
		mm, ok := v.(map[string]any)
		if !ok {
			return nil
		}
		v = mm[k]
	}
	return v
}

func TestOTelLinux(t *testing.T) {
	// A token that needs quoting must stay exactly the token.
	token := `tok-"odd"\token: #1`
	a, err := Generate(Options{OS: "otel", ServerURL: "https://siem.corp.example:8080", Token: token, CA: "-----BEGIN CERTIFICATE-----\nAAA\n-----END CERTIFICATE-----"})
	if err != nil {
		t.Fatal(err)
	}
	m := otelConfig(t, a)
	exp := "exporters"
	if got := dig(m, exp, "otlphttp/signalith", "logs_endpoint"); got != "https://siem.corp.example:8080/api/otlp/v1/logs" {
		t.Errorf("endpoint = %v", got)
	}
	if got := dig(m, exp, "otlphttp/signalith", "headers", "Authorization"); got != "Bearer "+token {
		t.Errorf("token = %q", got)
	}
	if got := dig(m, exp, "otlphttp/signalith", "tls", "ca_file"); got != OTelLinuxCAPath || a.CAPath != OTelLinuxCAPath || a.CAStep == 0 {
		t.Errorf("ca_file = %v, CAPath %q, CAStep %d", got, a.CAPath, a.CAStep)
	}
	if dig(m, "receivers", "filelog/auth") == nil || dig(m, "receivers", "otlp") == nil {
		t.Errorf("receivers = %v", m["receivers"])
	}
	recv, _ := dig(m, "service", "pipelines", "logs/signalith", "receivers").([]any)
	if len(recv) != 2 || recv[0] != "filelog/auth" {
		t.Errorf("pipeline receivers = %v", recv)
	}
	if a.ConfigPath != OTelLinuxConfig || a.ConfigStep == 0 || !strings.Contains(a.Steps[a.ConfigStep-1], "config.yaml") {
		t.Errorf("config step: %q %d %v", a.ConfigPath, a.ConfigStep, a.Steps)
	}
	if !strings.Contains(strings.Join(a.Steps, "\n"), "-g otelcol-contrib config.yaml") {
		t.Errorf("steps = %v", a.Steps)
	}

	// The journal instead of files.
	a, _ = Generate(Options{OS: "otel", LinuxSource: "journal", ServerURL: "http://192.0.2.1:8080", Token: "t"})
	m = otelConfig(t, a)
	ids, _ := dig(m, "receivers", "journald", "identifiers").([]any)
	if len(ids) == 0 || dig(m, "receivers", "filelog/auth") != nil || dig(m, exp, "otlphttp/signalith", "tls") != nil {
		t.Errorf("journal config:\n%s", a.Config)
	}
}

func TestOTelWindows(t *testing.T) {
	a, err := Generate(Options{OS: "otel", CollectorOS: "windows", Sysmon: true, PowerShell: true, ServerURL: "https://siem:8080", Token: "t", CA: "x"})
	if err != nil {
		t.Fatal(err)
	}
	m := otelConfig(t, a)
	if dig(m, "receivers", "windowseventlog/security", "channel") != "Security" ||
		dig(m, "receivers", "windowseventlog/system", "channel") != "System" ||
		dig(m, "receivers", "windowseventlog/application", "channel") != "Application" ||
		dig(m, "receivers", "windowseventlog/codeintegrity", "channel") != "Microsoft-Windows-CodeIntegrity/Operational" ||
		dig(m, "receivers", "windowseventlog/firewall", "channel") != "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall" ||
		dig(m, "receivers", "windowseventlog/bits", "channel") != "Microsoft-Windows-Bits-Client/Operational" ||
		dig(m, "receivers", "windowseventlog/appx", "channel") != "Microsoft-Windows-AppXDeploymentServer/Operational" ||
		dig(m, "receivers", "windowseventlog/wmi", "channel") != "Microsoft-Windows-WMI-Activity/Operational" ||
		dig(m, "receivers", "windowseventlog/rdp", "channel") != "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" ||
		dig(m, "receivers", "windowseventlog/mitigations", "channel") != "Microsoft-Windows-Security-Mitigations/KernelMode" ||
		dig(m, "receivers", "windowseventlog/sysmon", "channel") != "Microsoft-Windows-Sysmon/Operational" ||
		dig(m, "receivers", "windowseventlog/powershell", "channel") != "Microsoft-Windows-PowerShell/Operational" {
		t.Errorf("receivers = %v", m["receivers"])
	}
	if dig(m, "exporters", "otlphttp/signalith", "tls", "ca_file") != OTelWindowsCAPath {
		t.Errorf("ca_file = %v", dig(m, "exporters", "otlphttp/signalith", "tls", "ca_file"))
	}
	if dig(m, "extensions", "file_storage/signalith", "directory") != otelWindowsState {
		t.Errorf("storage = %v", dig(m, "extensions"))
	}
	if !strings.Contains(strings.Join(a.Steps, " "), "EnableScriptBlockLogging") {
		t.Errorf("no script block logging step: %q", a.Steps)
	}
	a, _ = Generate(Options{OS: "otel", CollectorOS: "windows", ServerURL: "https://siem:8080", Token: "t"})
	if strings.Contains(a.Config, "powershell") || strings.Contains(strings.Join(a.Steps, " "), "ScriptBlock") {
		t.Errorf("PowerShell off:\n%s", a.Config)
	}
	if strings.Contains(a.Config, "sysmon") || strings.Contains(strings.Join(a.Steps, " "), "Sysmon") {
		t.Errorf("Sysmon off:\n%s", a.Config)
	}
	if _, err := Generate(Options{OS: "otel", CollectorOS: "mac", ServerURL: "https://siem:8080", Token: "t"}); err == nil {
		t.Error("unknown collector OS accepted")
	}
	if _, err := Generate(Options{OS: "otel", ServerURL: "https://siem:8080\nx: 1", Token: "t"}); err == nil {
		t.Error("an address that breaks the YAML was accepted")
	}
}
