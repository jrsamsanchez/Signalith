package syslog

import (
	"strings"
	"testing"
)

// A Wazuh manager with <syslog_output><format>json</format> sends each
// alert as JSON after a short "ossec:" tag.
const wazuhSSHFail = `{"timestamp":"2026-10-12T13:58:59.250+0000","rule":{"level":5,"description":"sshd: authentication failed.","id":"5760",` +
	`"mitre":{"id":["T1110.001"],"tactic":["Credential Access"]},"groups":["syslog","sshd","authentication_failed"]},` +
	`"agent":{"id":"001","name":"web-01","ip":"10.0.0.21"},"manager":{"name":"wazuh-manager"},"id":"1791813539.4711",` +
	`"full_log":"Oct 12 13:58:59 web-01 sshd[2290]: Failed password for root from 203.0.113.9 port 40022 ssh2",` +
	`"decoder":{"parent":"sshd","name":"sshd"},"data":{"srcip":"203.0.113.9","srcport":"40022","dstuser":"root"},"location":"/var/log/auth.log"}`

const wazuhRootcheck = `{"timestamp":"2026-10-12T13:59:30.000+0000","rule":{"level":13,"description":"Host-based anomaly detection event (rootcheck).",` +
	`"id":"510","groups":["ossec","rootcheck"]},"agent":{"id":"002","name":"db-01"},"manager":{"name":"wazuh-manager"},"id":"1791813570.6000",` +
	`"full_log":"Trojaned version of file '/bin/ls' detected.","decoder":{"name":"rootcheck"},"location":"rootcheck"}`

func TestWazuhSyslogJSON(t *testing.T) {
	for _, line := range []string{
		"<132>Oct 12 13:59:00 wazuh-manager ossec: " + wazuhSSHFail,
		"<132>1 2026-10-12T13:59:00Z wazuh-manager ossec - - - " + wazuhSSHFail,
		"<132>" + wazuhSSHFail + "\n",
	} {
		d := doc(line)
		check(t, line, d, map[string]any{
			"_model": "Authentication", "action": "failure", "user": "root", "src": "203.0.113.9", "app": "sshd",
			"host": "web-01", "dest": "web-01", "dvc": "192.0.2.50", "signature_id": "5760", "vendor_product": "Wazuh",
			"sourcetype": "wazuh:alerts", "wazuh_agent_id": "001", "@timestamp": "2026-10-12T13:58:59.25Z", "message": wazuhSSHFail,
			"facility": "local0",
		})
		if _, ok := d["severity"]; ok {
			t.Errorf("%s: syslog severity on an Authentication event: %v", line, d["severity"])
		}
	}

	// Severity comes from the rule level, not the syslog priority; a
	// trojaned file is a Malware threat.
	line := "<132>Oct 12 13:59:31 wazuh-manager ossec: " + wazuhRootcheck
	check(t, line, doc(line), map[string]any{
		"_model": "Malware", "type": "threat", "severity": "critical", "file_path": "/bin/ls", "host": "db-01",
		"description": "Host-based anomaly detection event (rootcheck).", "@timestamp": "2026-10-12T13:59:30Z",
	})
}

func TestWazuhSyslogNotAlerts(t *testing.T) {
	for _, line := range []string{
		// JSON that is not a Wazuh alert, and an alert cut short.
		`<134>Oct 12 13:59:00 app1 svc: {"level":"info","msg":"started"}`,
		"<132>Oct 12 13:59:00 wazuh-manager ossec: " + wazuhSSHFail[:len(wazuhSSHFail)/2],
	} {
		d := doc(line)
		if d["sourcetype"] != "syslog" || d["vendor_product"] == "Wazuh" || !strings.HasPrefix(d["message"].(string), "<1") {
			t.Errorf("%s: %v", line, d)
		}
	}
}
