# Wazuh alerts

If you already run Wazuh, Signalith can take in the alerts your Wazuh manager raises. They are
mapped onto Signalith's data models, so logons from Wazuh show up next to logons from Fluent
Bit, file integrity alerts land in Filesystem, configuration assessment results in
Configuration_Check, antivirus alerts in Malware, and everything else in Alerts. Detections, dashboards and searches work on
them like on any other event.

## What to know first

- **Wazuh agents keep reporting to a Wazuh manager.** Wazuh agents only talk to a Wazuh manager,
  over Wazuh's own encrypted protocol, and Signalith does not speak it. Signalith takes the alerts
  from the manager, so you keep the manager (and its rules, decoders and agent enrollment) running.
- **Alerts, not every event.** The manager writes an alert when an event matches one of its rules
  at or above its alert level (`log_alert_level`, 3 by default). Events that match no rule stay on
  the manager and are not sent.
- **New alerts only.** Alerts raised before you set this up are not sent.

There are two ways to send alerts. Use Fluent Bit unless you cannot install anything on the
manager.

| | Fluent Bit on the manager | The manager's syslog output |
| --- | --- | --- |
| Install | Fluent Bit on the manager | nothing |
| Transport | HTTPS to `/api/ingest`, checking Signalith's certificate | syslog over UDP, unencrypted |
| Buffering | kept on disk and sent again if Signalith is down | none: alerts sent while Signalith is unreachable are lost |
| Long alerts | up to 1 MB each | very long alerts can be cut short (see below) |

## Fluent Bit on the Wazuh manager

Open **Add data**, pick **Wazuh** and follow the steps. In short, on the machine that runs the
Wazuh manager:

1. Install Fluent Bit 3.1 or later:
   `curl https://raw.githubusercontent.com/fluent/fluent-bit/master/install.sh | sh`
2. Save Signalith's CA certificate as `signalith-ca.pem` (when Signalith uses HTTPS).
3. Save the generated configuration as `fluent-bit.conf`.
4. Put both in place:
   `sudo install -m 644 -o root -g root signalith-ca.pem /etc/fluent-bit/signalith-ca.pem && sudo install -m 600 -o root -g root fluent-bit.conf /etc/fluent-bit/fluent-bit.conf`
5. Restart Fluent Bit:
   `sudo systemctl enable --now fluent-bit && sudo systemctl restart fluent-bit`

The configuration tails the file the manager writes its alerts to, one JSON alert per line, and
sends each line with the tag `wazuh`. The page fills in the address, ingest token and
certificate checks; the input part looks like this:

```ini
[INPUT]
    Name                 tail
    Tag                  wazuh
    Path                 /var/ossec/logs/alerts/alerts.json
    DB                   /var/lib/fluent-bit/signalith-wazuh.db
    Buffer_Chunk_Size    64k
    Buffer_Max_Size      1M
    Skip_Long_Lines      On
    storage.type         filesystem
```

`alerts.json` is written when `<jsonout_output>yes</jsonout_output>` is set under `<global>` in
the manager's `/var/ossec/etc/ossec.conf`, which is the default. Fluent Bit runs as root, so it
can read the file; it follows the file when the manager rotates it each day.

If Fluent Bit already runs on the manager for something else, add the `[INPUT]` above and the
`[OUTPUT]` from the generated file to your own configuration instead. Keep the tag `wazuh`: it is
how Signalith knows the lines are Wazuh alerts.

## The manager's syslog output (no agent)

The Wazuh manager can send each alert as JSON over syslog to Signalith's
[syslog receiver](https://github.com/jrsamsanchez/Signalith/blob/main/README.md#syslog). In `/var/ossec/etc/ossec.conf` on the manager, add:

```xml
<ossec_config>
  <syslog_output>
    <server>192.168.1.20</server>
    <port>514</port>
    <format>json</format>
  </syslog_output>
</ossec_config>
```

with Signalith's address as `server` (the **Syslog** option on **Add data** shows it), then turn
on the manager's syslog client and restart it:

```sh
sudo /var/ossec/bin/wazuh-control enable client-syslog
sudo systemctl restart wazuh-manager
```

Add `<level>7</level>` inside `<syslog_output>` to send only alerts of that rule level and above.

Signalith recognizes a syslog message whose text is a Wazuh JSON alert (an object with `rule` and
`agent`) and maps it exactly like an alert sent by Fluent Bit. `host` is the Wazuh agent the alert
is about, and `dvc` is the manager that sent it.

The manager sends syslog over UDP, unencrypted and without retries, so use this route on a network
you trust. Very long alerts (with a long `full_log`) can be cut short by the manager's syslog
output; a cut alert is not valid JSON, so it is stored as a plain syslog event (searchable by its
text, but not mapped). The Fluent Bit route does not have this limit.

## How alerts are mapped

Every Wazuh alert gets these fields, whatever model it lands in:

| Field | From the alert |
| --- | --- |
| `_time` | `timestamp` |
| `host`, `dest` | `agent.name` |
| `signature_id` | `rule.id` |
| `signature` | `rule.description` |
| `vendor_product` | `Wazuh` |
| `sourcetype` | `wazuh:alerts` |
| `_raw` | the whole alert, as JSON |
| `mitre`, `mitre_tactic` | `rule.mitre.id`, `rule.mitre.tactic` (lists) |
| `wazuh_rule_level` | `rule.level` (0 to 15) |
| `wazuh_rule_groups` | `rule.groups` (a list) |
| `wazuh_agent_id`, `wazuh_agent_name`, `wazuh_agent_ip` | `agent.id`, `agent.name`, `agent.ip` |
| `wazuh_manager` | `manager.name` |
| `wazuh_decoder` | `decoder.name` |
| `wazuh_location` | `location`, such as `/var/log/auth.log` or `EventChannel` |

Then the alert goes to the first model that fits:

**Filesystem**: file integrity monitoring (syscheck) alerts.

| Field | From the alert |
| --- | --- |
| `action` | `syscheck.event`: `added` becomes `created`; `modified`, `deleted` |
| `file_path`, `file_name` | `syscheck.path`, and its last part |
| `file_hash` | `syscheck.sha256_after`, lower case |
| `file_size` | `syscheck.size_after` |
| `user` | `syscheck.audit.user.name` (who-data), else `syscheck.uname_after` (the file's owner) |
| `process_path`, `process_name`, `process_id` | `syscheck.audit.process.name`, its file name, `syscheck.audit.process.id` |

**Registry**: syscheck alerts about Windows registry keys and values (rule group
`syscheck_registry`, or a path starting with `HKEY_`): `action`, `registry_path`,
`registry_key_name`, `registry_value_name` (`syscheck.value_name`), `user` and process as above.

**Configuration_Check**: Security Configuration Assessment results (`data.sca.type` is `check`).

| Field | From the alert |
| --- | --- |
| `check_id` | `data.sca.check.id` |
| `check` | `data.sca.check.title` |
| `result` | `data.sca.check.result` (or `status` on older managers): `passed` is `pass`, `failed` is `fail`, `not applicable` is `n/a` |
| `reference` | `data.sca.check.compliance`, such as `cis: 5.2.8; pci_dss_v4.0: 7.2.1` |
| `detail` | `data.sca.check.reason` |
| `benchmark` | `data.sca.policy`, the policy name |

`rule_id` is left empty: it is for SCAP Security Guide rules. SCA scan summaries go to Alerts.

**Windows events** (`data.win.system`): Signalith's own Windows parser reads them, from the event
data Wazuh sends by name, so they get the same fields as events from Fluent Bit on Windows:
4624 and 4625 logons go to Authentication, 4688 process creation to Endpoint, account and group
changes (4720, 4726, 4728, 4732, 4756) to Change, and Sysmon 1 and 3 to Endpoint and
Network_Traffic. The Windows event ID is kept in `wazuh_win_event_id`. Other Windows events
continue below.

**Authentication**: alerts whose rule groups include `authentication_success`,
`authentication_failed`, `authentication_failures` or `invalid_login` (sshd, PAM, sudo, su,
Windows and others).

| Field | From the alert |
| --- | --- |
| `action` | `success` or `failure`, from the rule group |
| `app` | `decoder.parent`, else `decoder.name`, such as `sshd` or `pam` |
| `user` | `data.dstuser`, else `data.srcuser`, else `data.win.eventdata.targetUserName` |
| `src_user` | `data.srcuser`, when it differs from `data.dstuser` (sudo, su) |
| `src`, `src_port` | `data.srcip`, `data.srcport` (Windows: `ipAddress`, `ipPort`) |

**Malware**: antivirus alerts, so they are found with every other antivirus's (see the
Malware dashboard):

- Wazuh's ClamAV integration (rule groups `clamd` or `freshclam`): the ClamAV message in
  `full_log` is read like a ClamAV log, giving `signature`, `file_path`, `action` and, for
  definition updates, `type=health`. `vendor_product` is `ClamAV`.
- VirusTotal matches (`data.virustotal.malicious` is 1): `signature` says how many engines
  flagged the file, with `file_path`, `file_md5`, `file_sha1` and the report in `url`.
- Rootcheck's trojaned files: `category=trojan`, with the file from `data.file` or `full_log`.
  Other rootcheck findings go to Alerts.

The rule's description is kept in `description`, and `severity` comes from `rule.level` as for
Alerts (0 to 3 counts as `low`).

**Alerts**: everything else.

| Field | From the alert |
| --- | --- |
| `app` | `wazuh` |
| `id` | `id`, the alert's own ID |
| `description` | `rule.description` |
| `severity` | from `rule.level`: 0 to 3 `informational`, 4 to 6 `low`, 7 to 9 `medium`, 10 to 12 `high`, 13 to 15 `critical` |
| `severity_id` | `rule.level` |
| `type` | `rule.groups`, joined with commas |
| `src` | `data.srcip` |
| `user` | `data.dstuser`, else `data.srcuser`, else the Windows target or subject user |

Anything not mapped stays in `_raw`, so you can still find it by text, for example
`sourcetype=wazuh:alerts "Trojaned version"`.

## Checking it works

Search `sourcetype=wazuh:alerts` over the last hour. To see what kinds of alerts arrive:

```
sourcetype=wazuh:alerts | stats count by datamodel, signature
```

A line under the `wazuh` tag that is not a Wazuh alert is kept in Other with sourcetype
`wazuh:alerts`. If nothing arrives, check the Health page and Fluent Bit's log
(`journalctl -u fluent-bit`) on the manager; for the syslog route, the **Syslog** option on
**Add data** shows the messages arriving from the manager.
