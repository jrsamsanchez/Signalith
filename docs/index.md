---
title: Signalith documentation
description: Signalith is an open-source SIEM for Windows and Linux, built on OpenSearch, Fluent Bit and Sigma.
hide:
  - navigation
  - toc
---

<div class="sg-hero" markdown>

<span class="sg-eyebrow">Open-source SIEM &middot; Apache 2.0</span>

# Signalith documentation

<p class="sg-lead">Signalith collects logs from Windows, Linux, network devices, web servers,
network sensors and OpenTelemetry, stores them in OpenSearch, and adds the security layer
on top: a pipe-based query language, thousands of tested detections with a triage queue,
risk-based alerting, threat intel, vulnerability scanning, dashboards and investigation
cases. It is one Go program with the web UI built in, running as a Windows service, a
systemd unit or a container, on one server or several.</p>

[Get started](getting-started.md){ .md-button .md-button--primary }
[See the roadmap](roadmap.md){ .md-button }
[GitHub](https://github.com/jrsamsanchez/Signalith){ .md-button }

</div>

## Where to go next

<div class="grid cards" markdown>

-   :material-rocket-launch-outline:{ .lg } **Getting started**

    ---

    Run it with Docker in two commands, or install it on Linux or Windows next to
    OpenSearch. Sample data with attacks hidden in it lets you try everything at once.

    [:octicons-arrow-right-24: Install and first steps](getting-started.md)

-   :material-transit-connection-variant:{ .lg } **Data intake**

    ---

    Fluent Bit agents for Windows and Linux, syslog and CEF from network devices,
    OpenTelemetry logs, web server access logs, osquery, Wazuh and antivirus.

    [:octicons-arrow-right-24: Agents and syslog](sending-data.md)

-   :material-database-search-outline:{ .lg } **Search**

    ---

    A query language that reads like SPL, plain-English questions that become queries,
    and a visual builder.

    [:octicons-arrow-right-24: Query language](query-language.md)

-   :material-shield-search:{ .lg } **Detect and triage**

    ---

    Built-in detections and tested SigmaHQ and Splunk content packs mapped to MITRE
    ATT&CK, a findings queue, risk scores and threat intel matching.

    [:octicons-arrow-right-24: Detections](detections.md)

-   :material-creation-outline:{ .lg } **Investigate with AI**

    ---

    One click on a finding asks an AI model of your choice for a verdict and a timeline,
    and AI tools such as Claude can read Signalith over MCP.

    [:octicons-arrow-right-24: Investigate with AI](investigate.md)

-   :material-lan:{ .lg } **Network sensor**

    ---

    Zeek and Suricata on a sensor plugged into a mirror port, installed with one line,
    with a Network dashboard.

    [:octicons-arrow-right-24: Network sensor](network-sensor.md)

-   :material-radar:{ .lg } **Vulnerability scanning**

    ---

    Nmap scans matched to CVEs, a scanner in each network zone, and OpenVAS as an option
    for deeper scans.

    [:octicons-arrow-right-24: Vulnerability scanning](vulnerabilities.md)

-   :material-view-dashboard-outline:{ .lg } **Dashboards**

    ---

    The security posture, network, vulnerability and malware dashboards, and dashboards
    of your own, kept as YAML files you can review in Git.

    [:octicons-arrow-right-24: Dashboards](dashboards.md)

-   :material-server-network:{ .lg } **Several servers**

    ---

    Add a server with one line on Linux, Windows or Docker. Servers share settings,
    users and detections, take over each other's jobs and upgrade one at a time.

    [:octicons-arrow-right-24: Adding servers](multi-server.md)

-   :material-account-key-outline:{ .lg } **Administration**

    ---

    Settings, users and roles, Active Directory sign-in, agent tokens, data retention
    and archives, and sizing.

    [:octicons-arrow-right-24: Server settings](settings.md)

-   :material-lock-outline:{ .lg } **Security**

    ---

    HTTPS by default, encrypted secrets and archives, a secured OpenSearch with its own
    certificates, and a built-in check of how your server is set up.

    [:octicons-arrow-right-24: Security checks](security.md)

-   :material-map-marker-path:{ .lg } **Roadmap**

    ---

    What is done, what is being built now, and what comes after.

    [:octicons-arrow-right-24: Roadmap](roadmap.md)

</div>

## How it fits together

```text
Fluent Bit agents ──HTTPS──▶ signalith (Go) ──REST──▶ OpenSearch
 (Windows, Linux)            ingest, parse,          events by data model and day
network sensors ───HTTPS───▶ query compiler,
syslog devices ─UDP/TCP/TLS▶ detections,
OTLP collectors ──HTTPS────▶ web UI and API ◀── analyst browser
                             (one server or several)
```

Signalith is a personal open-source project by Samuel Sanchez Jr., licensed under
[Apache 2.0](https://github.com/jrsamsanchez/Signalith/blob/main/LICENSE). Questions,
bug reports and ideas are welcome on
[GitHub](https://github.com/jrsamsanchez/Signalith/issues); see
[Contributing](https://github.com/jrsamsanchez/Signalith/blob/main/CONTRIBUTING.md) to help
out, and the [security policy](https://github.com/jrsamsanchez/Signalith/blob/main/SECURITY.md)
to report a weakness privately.

## Trademarks

Signalith is an independent project. It is not affiliated with, endorsed by or sponsored
by Splunk or Cisco, and contains no Splunk software code. Its optional Splunk Security
Content pack ships detection rules from Splunk's open-source
[security_content](https://github.com/splunk/security_content) project under the Apache
License 2.0 (see
[NOTICE](https://github.com/jrsamsanchez/Signalith/blob/main/NOTICE)). Splunk, Splunk
Enterprise Security and SPL are trademarks or registered trademarks of Splunk LLC, a Cisco
company, in the United States and other countries; they are named here only to describe the
rules Signalith can run and its search syntax. OpenSearch, Fluent Bit, Sigma and MITRE
ATT&CK are trademarks of their respective owners.
