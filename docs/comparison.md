---
description: How Signalith compares with Wazuh, Security Onion, Elastic Security, OpenSearch Security Analytics and Splunk Enterprise Security, including where Signalith is weaker.
---

# How Signalith compares

There are several good SIEMs you can run yourself, and the right one depends on what you
need. This page is a fair, plain comparison to help you choose, including where Signalith
is the weaker pick. It reflects each project's public documentation as of October 2026;
features and licenses change, so check the projects' own pages before you decide. If
something here is wrong or out of date, please
[open an issue](https://github.com/jrsamsanchez/Signalith/issues/new/choose).

## What Signalith is trying to be

Signalith's goal is a SIEM that anyone can stand up and use, especially now that AI can
help: easy to configure, easy to query, and ready for AI. It is a general-purpose SIEM
for Windows and Linux under the Apache License 2.0. It stores events in OpenSearch,
collects them with Fluent Bit, syslog and OpenTelemetry, and adds the security layer on
top: a pipe-style search language, plain-English questions that become searches, tested
detection content from SigmaHQ and Splunk Security Content, a findings queue, risk-based
alerting, threat intel, cases, response actions and dashboards. The server is one Go
program with the web UI built in.

## Where Signalith is weaker today

- **It is new.** The first release was in October 2026. It has no long record in large
  production deployments, and its community is small.
- **One maintainer.** It is a personal project, built in the open by one person with heavy
  help from an AI coding assistant (Claude Code). Every change goes through automated
  tests in CI, but there is no company behind it and no paid support.
- **No outside security review yet.** One is planned before 1.0 (see the
  [roadmap](roadmap.md)).
- **No EDR.** The [Signalith Agent](signalith-agent.md) installs and manages Fluent Bit
  and [osquery](endpoints.md) on Windows, Linux and macOS, but it collects no data
  itself, has no host-side active response and runs on no other platforms.
- **No full packet capture.** The [network sensor](network-sensor.md) runs Zeek and
  Suricata, but does not keep packets.
- **Lab sizing depends on the events.** With small 500-byte test events, one 2-core
  Signalith server stored about 21,500 events a second for 4 hours, and three stored
  25,000 a second. A 7-day soak of recorded Windows and Sysmon events on the same lab
  stored about 1,280 a second, bound by OpenSearch's network disks
  ([performance](performance.md#a-week-of-recorded-windows-events)).
- **The Windows installer is not code-signed yet** ([code signing policy](code-signing.md)).

## At a glance

| | Signalith | Wazuh | Security Onion | Elastic Security | Splunk Enterprise Security |
| --- | --- | --- | --- | --- | --- |
| License | Apache 2.0 | GPLv2 (manager and agent); indexer and dashboard Apache 2.0 | Elastic License 2.0 for its own and Elastic parts | Elastic License 2.0, SSPL or AGPLv3 for Elasticsearch and Kibana; some features need a paid subscription | Commercial |
| Main focus | General SIEM with detection content, triage and AI help | Host security: agents, integrity monitoring, configuration checks, active response | Network security monitoring, hunting and incident response | Search, SIEM and endpoint security at large scale | Enterprise SIEM and SOC workflows |
| Storage | OpenSearch | Wazuh indexer (built on OpenSearch) | Elasticsearch | Elasticsearch | Splunk Enterprise or Splunk Cloud |
| Runs on | Windows or Linux server, or Docker | Linux servers (agents on many systems) | Its own Linux distribution on dedicated machines | Linux, Windows, macOS, or Elastic Cloud | Linux or Windows, or Splunk Cloud |
| Search | Pipe-style language, plain-English questions, visual builder | OpenSearch Dashboards queries | Its own Hunt and Dashboards views over Elasticsearch | KQL, Lucene, EQL, ES&#124;QL | SPL |
| Detection content | Thousands of tested SigmaHQ and Splunk Security Content rules, Sigma import | Wazuh rules and decoders | Suricata, Zeek, Sigma and YARA rules | Elastic's prebuilt rules | Splunk's detection content |
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
no paid tier, and ships rule packs with test events that prove each rule fires.

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
search is pipe-style and will feel familiar to SPL users (it does not claim SPL
compatibility), and it can run detection rules from Splunk's open-source
[security_content](https://github.com/splunk/security_content) project, which is under
the Apache License 2.0. Splunk, Splunk Enterprise Security and SPL are trademarks or
registered trademarks of Splunk LLC, a Cisco company. Signalith is not affiliated with,
endorsed by or sponsored by Splunk or Cisco.

## Signalith may fit if

- You want a free, Apache 2.0 SIEM that runs on a Windows or Linux server, or in Docker,
  in two commands ([getting started](getting-started.md)).
- You want to ask questions in plain English, or connect an AI model or AI tools
  ([Investigate with AI](investigate.md), [AI tools](ai-tools.md)), with nothing sent
  anywhere unless you turn it on.
- You want thousands of tested community detection rules ready to switch on, with a
  triage queue, risk scoring and cases around them ([detections](detections.md)).
- You are comfortable with a young project and want to help shape it.

Other names worth knowing include Graylog Security and SIEMonster; each project's own
documentation is the best guide to what it does today.
