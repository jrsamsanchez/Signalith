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

<p class="sg-lead">Signalith collects logs from Windows, Linux, network devices and
OpenTelemetry, stores them in OpenSearch, and adds the security layer on top: a pipe-based
query language, scheduled detections with a triage queue, Sigma rule import, risk-based
alerting, threat intel, dashboards and investigation cases. It is one Go program with the
web UI built in, running as a Windows service, a systemd unit or a container.</p>

[Get started](getting-started.md){ .md-button .md-button--primary }
[See the roadmap](roadmap.md){ .md-button }
[GitHub](https://github.com/jrsamsanchez/Signalith){ .md-button }

</div>

## Where to go next

<div class="grid cards" markdown>

-   :material-rocket-launch-outline:{ .lg } **Getting started**

    ---

    Run it with Docker in two commands, or install it on Linux or Windows next to
    OpenSearch.

    [:octicons-arrow-right-24: Install and first steps](getting-started.md)

-   :material-transit-connection-variant:{ .lg } **Data intake**

    ---

    Fluent Bit agents for Windows and Linux, syslog and CEF from network devices,
    and OpenTelemetry logs over OTLP.

    [:octicons-arrow-right-24: Agents and syslog](sending-data.md)

-   :material-database-search-outline:{ .lg } **Search**

    ---

    A query language that reads like SPL, plain-English questions that become queries,
    and a visual builder.

    [:octicons-arrow-right-24: Query language](query-language.md)

-   :material-shield-search:{ .lg } **Detect and triage**

    ---

    Scheduled detections mapped to MITRE ATT&CK, Sigma import, a findings queue,
    risk scores and threat intel matching.

    [:octicons-arrow-right-24: Detections](detections.md)

-   :material-view-dashboard-outline:{ .lg } **Dashboards**

    ---

    The security posture dashboard and dashboards of your own, kept as YAML files
    you can review in Git.

    [:octicons-arrow-right-24: Dashboards](dashboards.md)

-   :material-flask-outline:{ .lg } **Try it with sample data**

    ---

    A week of made-up activity for a fictional company, with attacks hidden in it.
    One click loads it, one click removes it.

    [:octicons-arrow-right-24: Sample data](sample-data.md)

-   :material-account-key-outline:{ .lg } **Administration**

    ---

    Settings, users and roles, Active Directory sign-in, several servers sharing one
    OpenSearch, and data retention.

    [:octicons-arrow-right-24: Server settings](settings.md)

-   :material-lock-outline:{ .lg } **Security**

    ---

    HTTPS by default, encrypted secrets, a secured OpenSearch, and a built-in check of
    how your server is set up.

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
syslog devices ─UDP/TCP/TLS▶ query compiler,
OTLP collectors ──HTTPS────▶ web UI and API ◀── analyst browser
```

Signalith is a personal open-source project by Samuel Sanchez Jr., licensed under
[Apache 2.0](https://github.com/jrsamsanchez/Signalith/blob/main/LICENSE). Questions,
bug reports and ideas are welcome on
[GitHub](https://github.com/jrsamsanchez/Signalith/issues); see
[Contributing](https://github.com/jrsamsanchez/Signalith/blob/main/CONTRIBUTING.md) to help
out, and the [security policy](https://github.com/jrsamsanchez/Signalith/blob/main/SECURITY.md)
to report a weakness privately.
