---
hide:
  - navigation
description: What Signalith does today, what is being built now, and what comes next.
---

# Roadmap

Signalith aims to be a complete, general-purpose open-source SIEM: collect events from
the systems you run, find the attacks in them, and help you respond. This page says
where it stands. It has no dates: Signalith is a personal project built in the open,
and things ship when they are ready and tested.

Ideas and requests are welcome as
[feature requests](https://github.com/jrsamsanchez/Signalith/issues/new/choose) on GitHub.

## Done <span class="sg-pill sg-pill--done">Available</span> { #done data-toc-label="Done" }

The first three phases are complete, and the fourth has started.

**Search foundation**

- Fluent Bit agents for Windows and Linux, set up from the **Add data** page, plus
  [syslog and CEF](sending-data.md#syslog) from network devices and
  [OpenTelemetry](opentelemetry.md) logs over OTLP.
- Parsing into CIM-style data models (Authentication, Endpoint, Network traffic, Change).
- A pipe-based [query language](query-language.md) that reads like SPL, plain-English
  questions that become queries, a visual query builder, and an optional AI model.
- A Docker quick start and installers for Linux (systemd) and Windows (service).

**Detect and triage**

- Scheduled [detections](detections.md) mapped to MITRE ATT&CK, with throttling, a
  findings queue for triage, and an ATT&CK coverage map.
- [Sigma](https://github.com/SigmaHQ/sigma) rule import.

**Security depth**

- Risk-based alerting with asset and identity context.
- [Threat intel](threat-intel.md) feeds (lists, CSV, STIX, TAXII 2.1) matched against
  your events.
- A security posture dashboard and [dashboards](dashboards.md) of your own.
- [Sample data](sample-data.md) with attacks hidden in it, to try everything out.

**Respond and scale** (started)

- Investigation cases that collect findings, notes, searches and evidence.
- Several Signalith [servers](servers.md) sharing one OpenSearch, taking over each
  other's background jobs.

**Built in from the start**

- HTTPS by default, a secured OpenSearch, and [encrypted](encryption.md) passwords and
  keys.
- [Users and roles](users.md), with Active Directory and LDAP sign-in.
- [Data retention](retention.md) policies with archives and a disk guard.
- A [security check](security.md) of how each server is set up.

## Being built now <span class="sg-pill sg-pill--now">In progress</span> { #now data-toc-label="Being built now" }

**Detection content pack with rule tests**
:   A large, curated set of detections built on community Sigma content, each one with
    test events that prove it fires, checked on every change. Tuning and suppression of
    noisy rules, and signed content updates so new rules arrive without upgrading
    Signalith.

**Endpoint visibility with osquery**
:   File integrity monitoring, hardware and software inventory, and configuration checks
    against published security baselines, from [osquery](https://osquery.io) on Windows
    and Linux, with agents managed from Signalith.

**Alerts and response actions**
:   Send findings to email, webhooks, Slack and Microsoft Teams. Act on them from
    Signalith: disable a directory account, block an IP address, isolate a host or run
    a script, alone or as playbooks, with an approval step where it matters.

**Releases, packages and documentation**
:   Numbered releases with signed `.deb`, `.rpm` and `.msi` packages and a software bill
    of materials (SBOM), this documentation site, and a contributor guide.

## Next <span class="sg-pill sg-pill--next">Planned</span> { #next data-toc-label="Next" }

**Compliance content and evidence export**
:   Detections and reports mapped to PCI DSS 4.0, NIST SP 800-53, CIS Controls v8, HIPAA,
    ISO/IEC 27001 and SOC 2, compliance dashboards, retention presets, and evidence an
    auditor can take away.

**Load testing and an OpenSearch cluster guide**
:   A load test run in CI with the numbers published, so you know what one server
    handles, plus a guide to running OpenSearch as a cluster, and backup and restore.

**Add a server**
:   Adding a Signalith server to an existing install from the UI, with settings shared
    between servers instead of copied by hand.

## Later <span class="sg-pill sg-pill--later">Exploring</span> { #later data-toc-label="Later" }

**Network sensor**
:   An optional sensor role running [Zeek](https://zeek.org) and
    [Suricata](https://suricata.io) with the free Emerging Threats Open rules, feeding
    network events and alerts into Signalith.

**Vulnerability scanning**
:   Network discovery and scanning with [Nmap](https://nmap.org) by default, and
    [OpenVAS](https://www.openvas.org) as an option for deeper scans, with the results
    added to asset context and risk.

**Hardening and 1.0**
:   Fuzzing of every parser that reads data from the network, an outside security
    review, a public demo, and then version 1.0.
