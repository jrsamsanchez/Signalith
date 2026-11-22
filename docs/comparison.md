---
description: How Signalith compares with Wazuh, Security Onion, Elastic Security, OpenSearch Security Analytics, Splunk Enterprise Security and hosted SIEMs, including where Signalith is weaker.
---

# How Signalith compares

There are several good SIEMs you can run yourself, and the right one depends on what you
need. This page is a fair, plain comparison to help you choose, including where Signalith
is the weaker pick. It reflects each project's public documentation as of November 2026;
features and licenses change, so check the projects' own pages before you decide. If
something here is wrong or out of date, please
[open an issue](https://github.com/jrsamsanchez/Signalith/issues/new/choose).

## What Signalith is trying to be

Signalith's goal is a SIEM that anyone can stand up and use, especially now that AI can
help: easy to configure, easy to query, and ready for AI. It is a general-purpose SIEM
for Windows and Linux under the Apache License 2.0. It stores events in OpenSearch,
collects them with Fluent Bit, syslog and OpenTelemetry, and adds the security layer on
top: a pipe-style search language, plain-English questions that become searches,
detection content from SigmaHQ and Splunk Security Content, a findings queue, risk-based
alerting, threat intel, cases, response actions and dashboards. It also takes in cloud
audit logs and uses [osquery](endpoints.md) for file integrity monitoring, inventory and
configuration checks. The server is one Go program with the web UI built in.

## Where Signalith is weaker today

- **It is new.** The first release was in October 2026. No install outside the
  maintainer's lab has run it for long, and its community is small.
- **One maintainer.** It is a personal project, built in the open by one person with heavy
  help from an AI coding assistant, Claude Code ([Built with AI](built-with-ai.md)). Every change goes through automated
  tests in CI, but there is no company behind it and no paid support.
- **No outside security review yet.** One is planned before 1.0 (see the
  [roadmap](roadmap.md)). Signalith holds no certifications; its
  [compliance reports](compliance.md) help you gather evidence for your own audit.
- **No hosted service.** You run it yourself.
- **Several servers is a preview.** One server is the recommended setup for now
  ([multi-server](multi-server.md)).
- **Pack rules need tuning.** Every content pack rule is off until an admin turns it
  on, many need Sysmon or extra Windows audit policy, and no false-positive rate has
  been measured on real networks yet. The tests show that each converted rule matches
  the original rule's logic, mostly on events generated from the rule itself.
- **No machine-learning analytics.** [Behavior baselines](baselines.md) are a small
  set of threshold checks, not user and entity behavior analytics.
- **Search has limits.** Commands that work on single events rather than counts
  (such as `dedup`, `transaction` and `join`) read at most 10,000 events and mark
  the result as sampled ([query language](query-language.md)).
- **Fewer integrations.** It has a few dozen data sources and a short list of
  [response actions](response-actions.md), and three fixed [roles](users.md) with no
  custom ones.
- **No EDR.** The [Signalith Agent](signalith-agent.md) installs and manages Fluent Bit
  and [osquery](endpoints.md) on Windows, Linux and macOS, but it collects no data
  itself, has no host-side active response and runs on no other platforms.
- **No full packet capture.** The [network sensor](network-sensor.md) runs Zeek and
  Suricata, but does not keep packets.
- **Lab sizing depends on the events.** With small 500-byte test events, one 2-core
  Signalith server in front of two 8-core OpenSearch nodes stored about 21,500 events
  a second for 4 hours, and three servers stored 25,000 a second. A 7-day soak of recorded Windows and Sysmon events on the same lab
  stored about 1,280 a second, bound by OpenSearch's network disks
  ([performance](performance.md#a-week-of-recorded-windows-events)).
- **The Windows installer is not code-signed yet** ([code signing policy](code-signing.md)).

## At a glance

| | Signalith | Wazuh | Security Onion | Elastic Security | Splunk Enterprise Security |
| --- | --- | --- | --- | --- | --- |
| License | Apache 2.0 | GPLv2 (manager and agent); indexer and dashboard Apache 2.0 | Elastic License 2.0 for its own and Elastic parts | Elastic License 2.0, SSPL or AGPLv3 for Elasticsearch and Kibana; some features need a paid subscription | Commercial |
| Main focus | General SIEM with detection content, triage and AI help | Host security: agents, integrity monitoring, configuration checks, active response | Network security monitoring, hunting and incident response | Search, SIEM and endpoint security at large scale | Enterprise SIEM and SOC workflows |
| Storage | OpenSearch | Wazuh indexer (built on OpenSearch) | Elasticsearch | Elasticsearch | Splunk Enterprise or Splunk Cloud |
| Runs on | Windows or Linux server, Docker or Kubernetes | Linux servers (agents on many systems) | Its own Linux distribution on dedicated machines | Linux, Windows, macOS, or Elastic Cloud | Linux or Windows, or Splunk Cloud |
| Search | Pipe-style language, plain-English questions, visual builder | OpenSearch Dashboards queries | Its own Hunt and Dashboards views over Elasticsearch | KQL, Lucene, EQL, ES&#124;QL | SPL |
| Detection content | About 3,900 SigmaHQ and Splunk Security Content rules, off until you turn them on; Sigma import | Wazuh rules and decoders | Suricata, Zeek, Sigma and YARA rules | Elastic's prebuilt rules | Splunk's detection content |
| Endpoint agent | Signalith Agent running Fluent Bit and osquery (no EDR) | Wazuh agent | Elastic Agent | Elastic Agent with Elastic Defend | Universal Forwarder |
| Maturity | New (2026), one maintainer | Many years, large community, company-backed | Many years, company-backed | Many years, company-backed | Many years, vendor-backed |

## Wazuh

[Wazuh](https://wazuh.com) is a mature, widely used open-source security platform with
its own agent for Windows, Linux, macOS and other systems. Its strengths are on the host:
file integrity monitoring, configuration assessment against CIS benchmarks, vulnerability
detection and active response that can block an IP or stop a process on the machine
itself. It has a large community and commercial support.

Choose Wazuh if host monitoring and response on the endpoint matter most, or you need
agents on platforms Signalith does not cover. Signalith leans toward search, detection
content, triage and investigation, and it can [take in Wazuh alerts](wazuh.md), so the two
can run side by side.

## Security Onion

[Security Onion](https://securityonion.net) is a mature platform for network security
monitoring, threat hunting and incident response. It brings full packet capture, Zeek,
Suricata, host data through Elastic Agent, and case management, and installs as its own
Linux distribution. Its own components are under the Elastic License 2.0, which allows
free use but is not an OSI-approved open-source license. It has training, hardware and
support from the company behind it.

Choose Security Onion if network visibility and packet capture are the heart of what you
need. Signalith has a lighter [network sensor](network-sensor.md) (Zeek and Suricata,
without packet capture), runs on Windows as well as Linux, and is Apache 2.0.

## Elastic Security

[Elastic Security](https://www.elastic.co/security) is a SIEM and endpoint security
product built on Elasticsearch and Kibana, proven at very large scale. It has a strong
detection engine with prebuilt rules, several query languages, and Elastic Defend for
endpoint protection. Elasticsearch and Kibana are available under the Elastic License
2.0, the SSPL or the AGPLv3; some security features need a paid subscription, and Elastic
Cloud is a hosted option.

Choose Elastic Security for very large deployments, an integrated EDR, or a vendor with a
long track record. Signalith is smaller and simpler, uses OpenSearch, is Apache 2.0 with
no paid tier, and checks every pack rule in CI against test events.

## OpenSearch Security Analytics

[OpenSearch](https://opensearch.org) has a built-in Security Analytics plugin with Sigma
rules, detectors, findings and correlations. If you already run OpenSearch and want
detection inside OpenSearch Dashboards, it is worth a look. Signalith runs on OpenSearch
too and adds its own collection setup, search language, data models, triage queue, risk
scoring, cases and response actions in one application.

## Splunk Enterprise Security

[Splunk Enterprise Security](https://www.splunk.com/en_us/products/enterprise-security.html)
is a commercial SIEM used by many security teams, with a long track record, a large app
ecosystem, the SPL search language and vendor support. Choose it when you want a proven
enterprise product with support behind it.

Signalith is not related to Splunk. Two facts may matter if your team knows Splunk: its
search is pipe-style and will feel familiar to SPL users (it does not match every SPL
command; [Splunk SPL compatibility](compatibility.md) lists what runs and what differs),
and it can run detection rules from Splunk's open-source
[security_content](https://github.com/splunk/security_content) project, which is under
the Apache License 2.0. Splunk, Splunk Enterprise Security and SPL are trademarks or
registered trademarks of Splunk LLC, a Cisco company. Signalith is not affiliated with,
endorsed by or sponsored by Splunk or Cisco.

## Signalith may fit if

- You want a free, Apache 2.0 SIEM that runs on a Windows or Linux server, or in Docker
  with two commands after you clone the repository ([getting started](getting-started.md)).
- You want to ask questions in plain English, or connect an AI model or AI tools
  ([Investigate with AI](investigate.md), [AI tools](ai-tools.md)), with nothing sent
  to a model unless you turn it on.
- You want thousands of community detection rules you can switch on, starting with a
  set of about 140, with a triage queue, risk scoring and cases around them
  ([detections](detections.md)).
- You are comfortable with a young project and want to help shape it.

## Hosted SIEMs

Microsoft Sentinel, Google Security Operations, CrowdStrike Falcon Next-Gen SIEM and
Palo Alto Networks Cortex XSIAM are commercial services their vendors run for you, and
Splunk and Elastic offer hosted options too. They bring very large scale, behavior
analytics, AI triage, hundreds of integrations, certifications and vendor support.
Choose one when you want those and do not want to run the SIEM yourself. Signalith is
self-hosted only and is much smaller on every one of those counts.

Other names worth knowing include IBM QRadar, Graylog Security and SIEMonster; each
project's own documentation is the best guide to what it does today.
