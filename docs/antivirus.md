# Antivirus logs

Signalith collects what your antivirus finds and does: malware it found and
whether it removed it, protection rules that blocked something, and the
health of the antivirus itself (turned off, exclusions added, definitions
out of date). Every antivirus event goes into the **Malware** data model
(`datamodel=Malware`, kept in the `<index_prefix>-malware-YYYY.MM.DD`
indices and listed as **Malware** on the Data retention page). The built-in
[Malware dashboard](#the-malware-dashboard) shows it at a glance, and
[eight built-in detections](#detections) raise findings for malware that
was not removed, outbreaks across several hosts, ransomware, and antivirus
being turned off or given exclusions.

Three ways in:

| Product | How it gets here | Set up |
| --- | --- | --- |
| Microsoft Defender Antivirus | The Windows agent or the OpenTelemetry Collector, with no extra setup | [Microsoft Defender](#microsoft-defender) |
| ClamAV | The Linux agent | [ClamAV](#clamav) |
| Symantec, Trend Micro, Sophos, Trellix (McAfee) ePO, ESET, CrowdStrike, SentinelOne, Kaspersky, Bitdefender and any product that sends CEF or LEEF | Syslog from the product's management console | [Antivirus consoles](#antivirus-consoles-over-syslog) |

The steps for each, with this server's address and ports filled in, are on
**Add data › Antivirus** in the web UI.

## Microsoft Defender

The Windows agent reads the `Microsoft-Windows-Windows Defender/Operational`
event log next to the Security log, so every host with the agent sends its
Defender events. Hosts without Defender (for example Server Core with the
feature removed) are skipped quietly: the agent still starts and still sends
the Security log.

The [OpenTelemetry Collector](opentelemetry.md)'s Windows configuration reads
the same log (Collector Contrib 0.129 or later, which skips a missing Defender
log with a warning). Its events are mapped the same way, whether or not the
Collector renders the event message.

| Event IDs | What it means | `type` | `action` |
| --- | --- | --- | --- |
| 1006, 1116 | Malware or unwanted software found | threat | detected |
| 1015 | Suspicious behaviour found | threat | detected (category `behavior`) |
| 1007, 1117 | Defender acted on it | threat | what it did: quarantined, deleted, cleaned, blocked or allowed |
| 1008, 1118, 1119 | Defender tried to act on it and failed | threat | failed (`reason` says why) |
| 1009 | A file was restored from quarantine | threat | restored |
| 1121, 1122 | An attack surface reduction rule blocked or audited something | rule | blocked, audited |
| 1123, 1124, 1127, 1128 | Controlled folder access blocked or audited a change | rule | blocked, audited |
| 1125, 1126 | Network protection blocked or audited a web address | rule | audited, blocked |
| 2000, 2002 | Definitions or engine updated | health | updated |
| 2001, 2003, 2004, 2006 | Definitions, engine or platform update failed | health | update_failed |
| 3002, 5008 | Real-time protection or the engine failed | health | engine_failed |
| 5000, 5009, 5011 | Protection turned on | health | enabled |
| 5001, 5010, 5012 | Protection turned off | health | disabled |
| 5004 | A real-time protection setting changed | health | modified |
| 5007 | A setting changed: an exclusion added or removed, protection turned off by a setting, or anything else | health | exclusion_added, exclusion_removed, disabled or modified |
| 5013 | Tamper protection blocked a change | health | tamper_blocked |
| 1150, 1151 | Defender's regular health report; 1151 with definitions 7 or more days old | health | status, or outdated |

Other Defender event IDs are kept in the Other data model, searchable with
`sourcetype="WinEventLog:Microsoft-Windows-Windows Defender/Operational"`.

### Updating an agent installed before antivirus support

Fluent Bit does not fetch its configuration, so an agent set up before this
version keeps sending the Security log only. On **Add data › Windows**,
download the configuration again, copy it over
`C:\Program Files\fluent-bit\conf\fluent-bit.conf`, then in PowerShell as
administrator run:

```powershell
Restart-Service fluent-bit
```

## ClamAV

The Linux agent reads ClamAV's own log files, `/var/log/clamav/*.log`
(`clamav.log` from the scanner daemon, `freshclam.log` from the updater and
`clamonacc.log` from on-access scanning). It sends:

- `FOUND` lines: malware found, with the file and, when ClamAV gives them,
  its MD5 and size;
- `moved to`, `Removed.` and `Can't move`/`Can't remove` lines: what happened
  to the file. By default `clamd`, `clamonacc` and `clamdscan` only report
  what they find, so a `FOUND` line with none of these after it means the
  file is still on the host, and raises the high `malware-left-clamav`
  finding. To have ClamAV move what it finds, run `clamdscan` with
  `--move=/var/lib/clamav/quarantine`, or set `OnAccessPrevention yes` for
  on-access scanning;
- freshclam updates and update errors, and ClamAV's warning that its
  definitions are more than 7 days old.

Its routine `SelfCheck` lines are dropped at the agent.

**Red Hat, Rocky, AlmaLinux and Fedora** run ClamAV with logging to the
system journal instead of `/var/log/clamav`. On **Add data › Linux**, choose
**Read from: systemd journal**; the agent then also reads the journal
entries of `clamd`, `clamonacc` and `freshclam`.

Only `clamd`, `clamonacc` and `freshclam` write logs. A plain `clamscan` run
prints to the terminal and writes no log, so scan with `clamdscan` (which
asks `clamd`) to have results reach Signalith.

### Updating an agent installed before antivirus support

On **Add data › Linux**, download the configuration again, then put it in
place and restart the agent:

```sh
sudo install -m 600 -o root -g root fluent-bit.conf /etc/fluent-bit/fluent-bit.conf && sudo systemctl restart fluent-bit
```

## Antivirus consoles over syslog

Most endpoint protection products send events from their management console
rather than from each computer. Point the console at Signalith's syslog
receiver (see [Syslog](sending-data.md#syslog) for turning it on). **Add data ›
Antivirus** has the steps for each product with your address and port filled
in; consoles send over TCP when it is on, otherwise UDP.

| Product | Format | Where to turn it on |
| --- | --- | --- |
| Symantec Endpoint Protection | Symantec's own (`SymantecServer`) | Endpoint Protection Manager: Admin › Servers › Local Site › Configure External Logging; tick **Risk** on the Log Filter tab, and **Client System** for failed definition updates |
| Trend Micro Apex One | CEF | Apex Central: Administration › Settings › Syslog Settings; log format CEF, log type **Detections** |
| Trend Micro Deep Security | CEF | Deep Security Manager: a syslog configuration in CEF format, used for the policy's anti-malware events |
| Sophos Central | CEF | Sophos's SIEM script ([Sophos-Central-SIEM-Integration](https://github.com/sophos/Sophos-Central-SIEM-Integration)), run every 5 minutes on a Linux server |
| Trellix (McAfee) ePO | Trellix's own (XML) | ePO: Menu › Configuration › Registered Servers › New Server › Syslog Server. **Needs syslog over TLS** |
| ESET PROTECT | JSON or LEEF | More › Settings › Advanced Settings › Syslog server, then **Export logs to Syslog** in JSON or LEEF with **Detections** ticked |
| CrowdStrike Falcon | CEF | The Falcon SIEM Connector on a Linux server, with `output_format = cef` |
| SentinelOne | CEF | Settings › Integrations › Syslog, then tick Syslog for the threat notifications |
| Kaspersky Security Center | CEF, or Kaspersky's own syslog format | Administration Server properties › SIEM (ArcSight, CEF format), then **Export to SIEM system using Syslog** on the threat events of the policy |
| Bitdefender GravityZone | CEF | Bitdefender's Event Push connector, with syslog output in CEF |
| Anything else | CEF or LEEF | The product's syslog or SIEM export |

**Trellix ePO** only sends over TLS. Set `syslog.tls` (for example
`0.0.0.0:6514`) on the Settings page, register Signalith in ePO by a name or
address its certificate covers, and click **Test Connection**. See
[docs/https.md](https.md#agents-and-syslog) for the certificate.

For any other product, Signalith files an event under Malware when the event
names the threat (a custom string labelled *Threat Name*, *Virus Name*,
*Malware Name*, *Detection Name* or *Risk Name*, for example
`cs1Label=Threat Name cs1=Trojan.Agent`), or when its category says virus or
malware and it names a file. A threat name of `None`, `N/A`, `-` or
`unknown` doesn't count. Web proxies, firewalls and mail gateways (such as
Zscaler, which sends `threatname=None` with every web request) stay where they
are, and so do web requests from products that don't call themselves
antivirus. Everything else stays searchable in Network_Traffic or Other, with
`sourcetype=cef` or `sourcetype=leef`.

The parsers are tested against real logs these products published or other
projects collected (Symantec, Trellix ePO, ESET, CrowdStrike, Trend Micro Deep
Security, Kaspersky, Sophos and ClamAV), kept in the repository under
`internal/syslog/testdata`.

For console events, `dest` is the computer the event is about (from the
event's destination or computer name), not the console that sent it.

## Fields

Every Malware event has `type` and `action`, and a `signature`: the threat
name for threats (`Unknown threat` when the product gave none), the rule name
for rules, and a plain event name such as *Antivirus exclusion added* for
health events. The common fields `_time`, `host`, `sourcetype`, `vendor_product`,
`signature_id` (the Defender event ID, or the product's event ID) and `_raw`
are there too.

| `type` | Meaning | `action` values |
| --- | --- | --- |
| `threat` | Malware or unwanted software was found | `detected`, `blocked`, `quarantined`, `deleted`, `cleaned`, `allowed`, `failed`, `restored` |
| `rule` | A protection rule acted (attack surface reduction, controlled folder access, network protection) | `blocked`, `audited` |
| `health` | The antivirus itself changed or has a problem | `disabled`, `enabled`, `exclusion_added`, `exclusion_removed`, `modified`, `update_failed`, `updated`, `outdated`, `engine_failed`, `tamper_blocked`, `status` |

**Malware not removed** means `action IN (allowed, failed, restored)`: the
antivirus left the file alone, failed to clean it, or someone restored it from
quarantine. The detections, the dashboard and the Ask box all use this set.

| Field | Description | Example |
| --- | --- | --- |
| `type` | Kind of event: threat (malware found), rule (a protection rule acted) or health (the antivirus itself changed or has a problem) | `threat` |
| `action` | What happened, such as quarantined, failed, disabled or exclusion_added | `quarantined` |
| `vendor_action` | The action as the product wrote it | `Quarantine` |
| `threat_id` | The product's ID for the threat | `2147729891` |
| `category` | Kind of threat: virus, worm, trojan, ransomware, backdoor, spyware, adware, pua, exploit, hacktool, behavior, test or other | `trojan` |
| `vendor_category` | The threat category as the product wrote it | `Tool` |
| `severity` | How serious the product rates it: low, medium, high or critical | `high` |
| `vendor_severity` | The severity as the product wrote it | `Severe` |
| `dest` | Host the event is about | `ws-fin-07` |
| `dest_ip` | Address of that host, when the product sends one | `192.0.2.27` |
| `user` | Account involved, such as the user who opened the file | `CORP\alice.nguyen` |
| `src` | Address the threat came from, when the product says | `203.0.113.45` |
| `src_host` | Host the threat came from, when the product says | `file-01` |
| `url` | Web address the threat came from or was blocked at | |
| `file_name` | File name of the threat | `invoice.exe` |
| `file_path` | Full path of the threat | `C:\Users\alice.nguyen\Downloads\invoice.exe` |
| `file_hash` | File hash as the product sent it | |
| `file_md5`, `file_sha1`, `file_sha256` | The hash split by kind, lower case | |
| `file_size` | File size in bytes | `68` |
| `process` | Command line of the process involved | |
| `process_name` | Executable file name of the process involved | `winword.exe` |
| `process_path` | Executable path of the process involved | |
| `process_id` | Process ID | `4120` |
| `rule` | Protection rule that acted | `Office app started a child process` |
| `rule_id` | ID of that rule (for attack surface reduction, its GUID) | `d4f940ab-401b-4efc-aadc-ad5f3c50688a` |
| `setting` | Setting that changed, as the product wrote it | |
| `exclusion` | What an added or removed exclusion lets through | `C:\ProgramData\SyncSvc` |
| `exclusion_type` | Kind of exclusion: path, extension, process or ip | `path` |
| `signature_version` | Version of the antivirus definitions | `1.419.2361.0` |
| `engine_version` | Version of the scan engine | `1.1.24090.11` |
| `product_version` | Version of the antivirus product | `4.18.24090.11` |
| `signature_age_days` | Age of the definitions in days, when the product reports it | `9` |
| `reason` | Error or reason text from the product | `The process cannot access the file` |
| `detection_source` | Which scan or feature found it | `Real-Time Protection` |

The `file_md5`, `file_sha1` and `file_sha256` fields are checked against
threat intel hashes by `threatmatch` and `intel` (see
[threat-intel.md](threat-intel.md)).

## Searching

| To find | Search |
| --- | --- |
| Malware the antivirus did not remove, by host | `datamodel=Malware type=threat action IN (allowed, failed, restored) \| stats count by dest, signature` |
| The same threat on several hosts | `datamodel=Malware type=threat category!=test \| stats dc(dest) as hosts, count by signature \| where hosts >= 2 \| sort -hosts` |
| Exclusions added, and what they let through | `datamodel=Malware type=health action=exclusion_added \| table _time, dest, user, exclusion_type, exclusion` |
| Hosts whose definitions are old or failing to update | `datamodel=Malware type=health action IN (outdated, update_failed) \| stats count by dest, vendor_product, signature \| sort -count` |
| Attack surface reduction blocks by rule | `datamodel=Malware type=rule action=blocked \| stats count, dc(dest) as hosts by rule \| sort -count` |
| Everything the antivirus said about one host | `datamodel=Malware dest=ws-fin-07 \| table _time, type, action, signature, file_path, user` |

The Ask box understands questions such as *malware not removed in the last 7
days*, *hosts where antivirus was turned off* and *asr blocks by rule*.

## Detections

All ten are on by default. Edit or turn them off on the Detections page.

| ID | Severity | What it means | What to do |
| --- | --- | --- | --- |
| `malware-not-removed` | high | Antivirus found malware but did not remove it: the clean-up failed, someone allowed the file, or it was restored from quarantine. | Open the host's events around this time to see whether the file ran. Run a full scan, remove the file by hand or reimage the host. If someone allowed the file on purpose, check that it really is safe. |
| `malware-left-clamav` | high | ClamAV found malware but only reported it, so the file is still on the host. | Search `datamodel=Malware dest="<the host>" file_path="<the path>"` for the threat's name. Remove or quarantine the file by hand, then find out how it got there. To have ClamAV move what it finds, see [ClamAV](#clamav). |
| `malware-detected` | low | Antivirus found malware. Most products block, quarantine, delete or clean it straight away; when one did not, `malware-not-removed` or `malware-left-clamav` is raised as well. Ransomware has its own finding. | Check where the file came from (`file_path`, `url`, `user`). Repeated finds on one host, or the same threat on other hosts, mean something keeps bringing it back. An EICAR detection (category `test`) is someone testing the antivirus; close it as benign. |
| `malware-outbreak` | high | The same threat was found on three or more hosts within a day. Test files, adware and potentially unwanted apps are left out. | Search `datamodel=Malware signature="<the threat>"` to list the hosts and file paths. A common path (a file share, a download folder) or a common sender shows where it spreads from. |
| `malware-ransomware` | critical | Antivirus found ransomware. Even when it was removed, more may be running or waiting on the network. | Isolate the host now. Check other hosts for the same threat and for shadow copy deletion, and check the file shares this user can write to. |
| `av-protection-disabled` | high | Real-time protection, scanning or tamper protection was turned off. | Ask who changed it. If another antivirus product was just installed, Defender turning itself off is expected; close this as benign. Otherwise turn protection back on and look at what ran on the host just before. |
| `av-tamper-blocked` | medium | Tamper protection blocked an attempt to change the antivirus. The antivirus stayed on. | Look at `setting` to see what was blocked. If it fires on many hosts after a Group Policy, Intune or SCCM change, the policy is fighting tamper protection; fix the policy and close these as benign. On a single host with no policy change, check what ran there just before. |
| `av-exclusion-added` | medium | A folder, file type, process or address was excluded from antivirus scanning. | Check the exclusion against your approved list. Exclusions for temporary, download or ProgramData folders, or for script hosts such as `powershell.exe`, are rarely legitimate. |
| `av-definitions-failing` | low | Definitions failed to update at least twice in a day, or are a week or more old. | Check that the host can reach its update source (proxy, firewall, disk space). Several hosts at once usually means the update server or mirror is down. |
| `av-rule-block` | medium | A Windows protection rule (attack surface reduction or controlled folder access) blocked something that rarely happens in normal work, such as an Office document starting PowerShell. | The block worked, but whatever tried it is still on the host. Look at `process_name` (what tried) and `file_path` (what it tried to start or change). |

`av-rule-block` leaves out three attack surface reduction rules that also
block routine software: *Credential theft from LSASS*, *Rare or untrusted
executable* and *Untrusted program from USB*. They are still in the data
(`datamodel=Malware type=rule`). The rules it covers map to these ATT&CK
techniques:

| Rule | Technique |
| --- | --- |
| Vulnerable signed driver | T1068 |
| Persistence through WMI event subscription | T1546.003 |
| Adobe Reader started a child process, Office app started a child process, Office app created executable content, Script launched downloaded executable content | T1204.002 |
| Executable content from email, Office communication app started a child process | T1566.001 |
| Obfuscated script | T1027 |
| Office app injected code into another process | T1055 |
| Process creation from PsExec or WMI | T1047 |
| Reboot into Safe Mode | T1688 |
| Copied or impersonated system tool | T1036 |
| Webshell creation on a server | T1505.003 |
| Office macro called Win32 APIs | T1106 |
| Ransomware protection, Controlled folder access | T1486 |

Sigma rules with `logsource: category: antivirus` convert to
`datamodel=Malware` searches (see [detections.md](detections.md#sigma-rules)).

## The Malware dashboard

**Dashboards › Malware** is built in and opens on the last 7 days:

| Panel | Shows |
| --- | --- |
| Hosts with malware | Hosts with any threat (EICAR tests left out), compared with the period before |
| Hosts with malware not removed | Hosts where a threat was allowed, failed to clean or was restored |
| Hosts with protection off or tampered with | Hosts where protection was turned off or tamper protection blocked a change |
| Malware found over time, by what the antivirus did | Threats per hour or day, one line per action |
| Top threats | The threats on the most hosts, and how often each was found |
| Hosts with the most malware | The hosts with the most threats |
| Malware not removed | Each threat not removed, with host, user and file |
| Threats by category | Trojan, ransomware, PUA and so on |
| Events by product | Which antivirus products are sending |
| Protection rule blocks | Attack surface reduction and controlled folder access blocks by rule |
| Antivirus health problems | Protection off, tampering, exclusions, failed updates, old definitions and engine failures, by host |

Defender logs each threat twice, once when it finds it and once when it acts.
The charts count only the second, so each threat counts once.

Until antivirus events arrive, the dashboard says so above its panels, with a
button that opens **Add data › Antivirus** (for admins).

The dashboard can't be edited. To change it, choose **Make a copy** (analysts
and admins, when custom dashboards are on): the copy, *Malware (copy)*, is a
custom dashboard you can edit, add panels to and delete. **Download YAML**
saves its definition. See [dashboards.md](dashboards.md).

## Testing with the EICAR test file

The EICAR test file is a harmless file that every antivirus treats as malware,
made for checking that detection works. Download it from
[eicar.org](https://www.eicar.org/) on a test host:

- **Microsoft Defender:** download it in a browser. Defender removes it and
  the event shows in Search (`datamodel=Malware`) within a minute.
- **ClamAV:** download it and scan it with `clamdscan`:

  ```sh
  curl -fsSO https://secure.eicar.org/eicar.com.txt; clamdscan --fdpass eicar.com.txt; rm -f eicar.com.txt
  ```

The detection has category `test`, so it raises a low `malware-detected`
finding (close it as benign) and does not count on the dashboard's malware
panels. On ClamAV, `clamdscan` only reports the file unless you add
`--move` or `--remove`, so the test also raises `malware-left-clamav`; the
command above deletes the file afterwards, so close that one as benign too.

## Troubleshooting

**Nothing arrives.** Search `datamodel=Malware earliest=-1h`. For agents,
check the host on the Health page and that the agent runs
(`Get-Service fluent-bit` or `systemctl status fluent-bit`). For consoles,
open **Add data › Syslog**: the *See it arrive* box shows whether the console's
address has sent anything, and anything turned away, such as a sender not in
`syslog.allow`.

**Defender events are missing but the Security log arrives.** The agent still
has its old configuration. Download it again and restart the agent (see
[Updating an agent](#updating-an-agent-installed-before-antivirus-support)).
Search `sourcetype="WinEventLog:Microsoft-Windows-Windows Defender/Operational"`
to check.

**ClamAV on Red Hat, Rocky, AlmaLinux or Fedora sends nothing.** ClamAV logs
to the journal there: choose **Read from: systemd journal** on **Add data ›
Linux**, download the configuration and restart the agent. Remember that
`clamscan` writes no log; use `clamdscan`.

**Console events land in Other or Network_Traffic instead of Malware.** The
event did not say it was about malware. Check the console sends its threat or
detection events (not only audit or system events) in CEF or LEEF, and that
each names the threat. Search `sourcetype=cef` or `sourcetype=leef` to see what
arrived, and compare it with the format in [Antivirus consoles](#antivirus-consoles-over-syslog).

**Trellix ePO can't connect (Test Connection fails).** ePO needs syslog over
TLS: set `syslog.tls` on the Settings page and restart, allow that port
(6514 by default) through the firewall, and register Signalith by a name or
address Signalith's certificate covers (see
[docs/https.md](https.md#agents-and-syslog)).
