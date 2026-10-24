// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0

package clusterinstall

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/jrsamsanchez/signalith/deploy"
	"github.com/jrsamsanchez/signalith/internal/agents"
)

const caSum = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"

func TestSensorLines(t *testing.T) {
	c, err := SensorLines(SensorLine{URL: "https://siem:8080/", Version: "1.6.0", CASHA256: caSum, Zeek: true, Suricata: true,
		Interface: "ens192", Networks: " 10.1.0.0/16, fd00::/8 "})
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(deploy.SensorInstallSH)
	if c.ScriptSHA256 != hex.EncodeToString(sum[:]) || c.ScriptSHA256 != ScriptSHA256().Sensor {
		t.Errorf("script SHA-256 %s", c.ScriptSHA256)
	}
	for _, want := range []string{"curl -fsSk --proto '=https' https://siem:8080/api/sensor/install.sh -o \"$f\"", c.ScriptSHA256 + "  $f", "sha256sum -c --quiet",
		"echo '" + agents.TokenPlaceholder + "' | sudo sh \"$f\" --role sensor --from https://siem:8080 --ca-sha256 " + caSum + " --version 1.6.0 --token -",
		" --interface ens192", " --networks 10.1.0.0/16,fd00::/8"} {
		if !strings.Contains(c.Linux, want) {
			t.Errorf("line has no %q:\n%s", want, c.Linux)
		}
	}
	for _, not := range []string{"--next-ca-sha256", "--no-zeek", "--no-suricata", "--suricata-protocols", "--docker", "--ot", "8080//"} {
		if strings.Contains(c.Linux, not) {
			t.Errorf("line has %q:\n%s", not, c.Linux)
		}
	}
	if !strings.Contains(c.Note, "Ubuntu 22.04") || !strings.Contains(c.Note, "don't share it") || !strings.Contains(c.Note, "Zeek's packages are for Ubuntu and Debian only") {
		t.Errorf("note %q", c.Note)
	}
	// A leading space keeps the line, and its token, out of bash's history.
	if !strings.HasPrefix(c.Linux, " f=$(mktemp) && ") || !strings.Contains(c.Note, "history") {
		t.Errorf("line %q / note %q", c.Linux, c.Note)
	}
	// While Zeek's signing key is not pinned in the script, the note says
	// to pick Docker or leave Zeek out.
	if unpinned := strings.Join(SensorUnpinned(), " "); strings.Contains(unpinned, "KEY_FPR_ZEEK_OBS") != strings.Contains(c.Note, "cannot install Zeek from packages yet") {
		t.Errorf("unpinned %s, note %q", unpinned, c.Note)
	}

	// A public CA: no pin. Docker, one tool, the next CA, protocols.
	c, _ = SensorLines(SensorLine{URL: "https://siem.example.com", Version: "dev", Suricata: true, Docker: true})
	if strings.Contains(c.Linux, "--ca-sha256") || !strings.HasSuffix(c.Linux, "--token - --no-zeek --docker") || !strings.Contains(c.Note, "Docker Desktop") || strings.Contains(c.Note, "cannot install") {
		t.Errorf("docker: %s / %s", c.Linux, c.Note)
	}
	c, _ = SensorLines(SensorLine{URL: "https://siem:8080", Version: "1.6.0", CASHA256: caSum, NextCASHA256: strings.Repeat("a", 64), Zeek: true})
	if !strings.Contains(c.Linux, "--ca-sha256 "+caSum+" --next-ca-sha256 "+strings.Repeat("a", 64)) || !strings.HasSuffix(c.Linux, "--no-suricata") {
		t.Errorf("next CA: %s", c.Linux)
	}
	c, _ = SensorLines(SensorLine{URL: "https://siem:8080", Version: "1.6.0", Zeek: true, Suricata: true, Protocols: true})
	if !strings.HasSuffix(c.Linux, "--suricata-protocols") {
		t.Errorf("protocols: %s", c.Linux)
	}
	c, _ = SensorLines(SensorLine{URL: "https://siem:8080", Version: "1.6.0", Zeek: true, Suricata: true, OT: true, Docker: true})
	if !strings.HasSuffix(c.Linux, "--token - --ot --docker") {
		t.Errorf("industrial protocols: %s", c.Linux)
	}
}

// Nothing reaches the sensor's line that a shell would read as more than
// a word; errors the page shows under a field name it.
func TestSensorLinesRefuse(t *testing.T) {
	good := SensorLine{URL: "https://siem:8080", Version: "1.6.0", Zeek: true, Suricata: true}
	for name, c := range map[string]struct {
		change func(l *SensorLine)
		field  string
	}{
		"http":         {func(l *SensorLine) { l.URL = "http://siem:8080" }, "server"},
		"quote":        {func(l *SensorLine) { l.URL = "https://siem:8080'" }, "server"},
		"dollar":       {func(l *SensorLine) { l.URL = "https://$(id):8080" }, "server"},
		"space":        {func(l *SensorLine) { l.URL = "https://siem :8080" }, "server"},
		"path":         {func(l *SensorLine) { l.URL = "https://siem:8080/x" }, "server"},
		"version":      {func(l *SensorLine) { l.Version = "1.6; id" }, ""},
		"ca":           {func(l *SensorLine) { l.CASHA256 = "XYZ" }, ""},
		"next alone":   {func(l *SensorLine) { l.NextCASHA256 = caSum }, ""},
		"iface space":  {func(l *SensorLine) { l.Interface = "ens 192" }, "interface"},
		"iface subst":  {func(l *SensorLine) { l.Interface = "$(reboot)" }, "interface"},
		"iface long":   {func(l *SensorLine) { l.Interface = "abcdefghijklmnop" }, "interface"},
		"iface semi":   {func(l *SensorLine) { l.Interface = "eth0;id" }, "interface"},
		"cidr junk":    {func(l *SensorLine) { l.Networks = "10.0.0.0/8;reboot" }, "networks"},
		"cidr no mask": {func(l *SensorLine) { l.Networks = "10.0.0.1" }, "networks"},
		"cidr quote":   {func(l *SensorLine) { l.Networks = "'10.0.0.0/8'" }, "networks"},
		"no tools":     {func(l *SensorLine) { l.Zeek, l.Suricata = false, false }, "tools"},
	} {
		l := good
		c.change(&l)
		_, err := SensorLines(l)
		if err == nil {
			t.Errorf("%s: accepted %+v", name, l)
			continue
		}
		var fe *FieldError
		if got := ""; errors.As(err, &fe) {
			got = fe.Field
			if got != c.field {
				t.Errorf("%s: field %q, want %q", name, got, c.field)
			}
		} else if c.field != "" {
			t.Errorf("%s: %v has no field, want %q", name, err, c.field)
		}
	}
	// Networks are written in their canonical form.
	if n, err := CleanNetworks("10.1.2.3/8, ,FD00::1/8"); err != nil || n != "10.0.0.0/8,fd00::/8" {
		t.Errorf("networks %q %v", n, err)
	}
}
