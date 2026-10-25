# Outbound connections

This page lists every address outside your network that Signalith, its agents and its
installers can connect to, when they do, and what they send. It also says how to run
Signalith with no outbound connections at all.

Most connections happen only after you set something up. One is on by default: the IP
database for [behavior baselines](baselines.md), downloaded the first time someone
signs in from an internet address.

## The server

Only the server that runs the background jobs makes the scheduled downloads below (see
[Servers](servers.md#the-background-jobs)). Every server keeps the result in OpenSearch,
so the others use the same copy.

| Host | When it is contacted | What is sent | Proxy | Without it |
| --- | --- | --- | --- | --- |
| `iptoasn.com` | **On by default.** Behavior baselines and their country and network checks are on, and **IP database** is empty, which means `https://iptoasn.com/data/ip2asn-combined.tsv.gz`. The first download happens when an hour's sign-ins include one from an internet address; then once a week, and again an hour after a failed try | A GET of the whole file, with `User-Agent: Signalith`. Nothing about your users or network | Yes | **IP database** `file:<name>` (a file in the `ipdb` folder of the lookups folder), a mirror's https address, or `off` ([The IP database](baselines.md#the-ip-database)) |
| `github.com` (the `content` release), and the GitHub file download host it redirects to | **Off by default.** When an admin clicks **Check for updates** on the Detections page, or once a day with **Content pack updates** (`detections.content_updates`) set to **Daily** | A GET of `signalith-content.tar.gz` and its `.sig` | Yes | Keep **Manual** (the default) and use **Upload update...**, or set **Content update address** (`detections.content_url`) to a copy on your own web server ([Content updates](detections.md#content-updates)) |
| `www.cisa.gov` (KEV catalog) and `epss.empiricalsecurity.com` (EPSS scores) | **Off until you add a scan network.** Once at least one network is set up for [vulnerability scanning](vulnerabilities.md), or the [package check](vulnerabilities.md#installed-packages-on-linux-hosts) has checked a host, once a day, and again an hour after a failed try | A GET of the whole catalog and the whole score list. Nothing about your network | Yes | **Known exploited catalog address** (`vulns.kev_url`) and **EPSS scores address** (`vulns.epss_url`): the full path of a file you copy in, or a mirror. Without either, a KEV copy built into Signalith stands in, and EPSS scores are left out ([KEV and EPSS](vulnerabilities.md#which-vulnerabilities-to-fix-first-kev-and-epss)) |
| `services.nvd.nist.gov` | **Off until you scan.** When a scan finds software with a version and CVE lookups are on (they are by default). Answers are kept for a day | The vendor and product name of each piece of software found, as a CPE match such as `cpe:2.3:a:openbsd:openssh`, and your NVD API key if you set one. Not the version, and no addresses or host names | Yes | **CVE database address** (`vulns.nvd_url`) for a mirror, or turn off **Look up CVEs in the National Vulnerability Database** in **Scanner setup**. Scans still list hosts, ports and software ([CVE lookups and privacy](vulnerabilities.md#cve-lookups-and-privacy)) |
| `osv-vulnerabilities.storage.googleapis.com` (OSV.dev) | **Off until a Linux host runs osquery.** When a Linux host enrolled on the Endpoints page has listed its packages and CVE lookups are on (they are by default): once a day for each Debian, Ubuntu, Red Hat, AlmaLinux or Rocky Linux release your hosts run, and again an hour after a failed try | A GET of that release's whole advisory file, such as `Debian:12/all.zip`. Nothing about your hosts | Yes | **Distribution advisories address** (`vulns.osv_url`): a mirror, a folder of files you copy in, or `off` ([Installed packages](vulnerabilities.md#installed-packages-on-linux-hosts)) |
| Threat intel feeds you add: the catalog's `feodotracker.abuse.ch`, `urlhaus.abuse.ch`, `bazaar.abuse.ch`, `rules.emergingthreats.net`, `www.spamhaus.org`, `openphish.com`, `cinsscore.com` (plain HTTP), `lists.blocklist.de`, `raw.githubusercontent.com` (FireHOL), `check.torproject.org`, or any URL or TAXII server | **Off until you add a feed.** On each feed's schedule, or **Refresh now** | A GET of the feed, with the API key header you gave it, if any | Yes | Feeds from files, or from URLs and TAXII servers on your own network ([Threat intel](threat-intel.md)) |
| Your AI provider: `api.anthropic.com`, `api.openai.com`, or the address you set (the page offers OpenRouter, Groq, Mistral AI and Google Gemini, and Ollama, LM Studio and vLLM on your own hardware) | **Off by default** (**Provider** is **Off**). When someone uses Ask, Investigate with AI, Improve with AI or a detection draft with a model set up | See [Where your data goes](data-residency.md) | Yes | Leave **Provider** off: Ask, detection drafts and parser suggestions then use their offline rules, and Investigate with AI is not offered. Or use a model on your own network |
| Notification channels: `hooks.slack.com`, your Teams webhook, or for the Teams app `login.microsoftonline.com` and Bot Framework (`api.botframework.com`, `login.botframework.com`, `smba.trafficmanager.net`); your SMTP server; your webhook URLs | **Off until you add a channel** and a rule sends to it | A finding's title, urgency, severity, detection, ATT&CK techniques, user, host, source and destination, risk score and a link. Never the event ([Notifications](notifications.md)) | Yes | Don't add channels, or use ones on your own network |
| Your Jira or ServiceNow | **Off until you add a connection** | A case's title, severity, status, description, notes and a link ([Ticketing](ticketing.md)) | Yes | Don't add a connection, or use one on your own network |
| The firewalls, SOAR and directories your response actions name | **Off until an admin sets up an action**, and then only when an analyst runs it, or a playbook step does | The target (an IP, domain, user or host) and what the action's template adds ([Response actions](response-actions.md)) | **No.** Response actions ignore `HTTPS_PROXY` | Don't set up actions that reach outside |
| Your directory and sign-in provider: an LDAP or Active Directory server, an OIDC provider (such as `login.microsoftonline.com` or `accounts.google.com`), a SAML identity provider's metadata address | **Off until you set up** [directory sign-in](users.md#sign-in-with-active-directory-or-ldap) or [single sign-on](sso.md) | Sign-in requests and lookups of the user signing in | OIDC and SAML: yes. LDAP connects directly | Use a directory or identity provider on your own network |
| Microsoft 365 (`login.microsoftonline.com`, `manage.office.com`, or your government cloud's addresses) and your Okta organization | **Off until you set them up** on Add data | An app's credentials, and requests for the audit log | Yes | These are cloud services: leave them off in an air-gapped install |
| Your OpenSearch, and the other Signalith servers | Always | Your events and settings | OpenSearch: only through **opensearch.proxy** (`SIGNALITH_OPENSEARCH_PROXY`), never `HTTPS_PROXY`. Between servers: never | They are on your network |

The agents send only to your Signalith server: their events, their status, and requests
for their configuration. Agent updates come from your server too: each release carries
the agent programs and their signed manifest, and the server hands them out
([Updates](signalith-agent.md#updates)). A server built from source has none, and its
agents don't update themselves.

The web pages load nothing from other sites: their content security policy allows only
the Signalith server itself. Links to the documentation, GitHub, MITRE ATT&CK and the NVD
open in your browser only when you click them.

### Proxy

Where the table says **Yes**, the server uses the proxy in `HTTPS_PROXY`, `HTTP_PROXY` and
`NO_PROXY`. Set them in the service's environment: `Environment=` lines of the
`signalith` systemd unit on Linux, or the **Environment** value of the **Signalith**
service in the Windows registry. Downloads of feeds, the IP database and notifications
are still checked against private and metadata addresses when they go through a proxy
([Network access and safety](threat-intel.md#network-access-and-safety)).

## Installers

| Host | When it is contacted | What is sent | Proxy | Without it |
| --- | --- | --- | --- | --- |
| `signalith.io` (`/apt`, `/rpm`) | When you add Signalith's apt or dnf repository, and on each `apt update` or `dnf upgrade` after | Package manager requests | Your package manager's | Download the `.deb` or `.rpm` elsewhere and install the file ([Install from packages](install-packages.md)) |
| `github.com` (releases) | When you download a package, the `.msi`, `SHA256SUMS` or an SBOM | A download | Your browser's | Copy the files over |
| `artifacts.opensearch.org` | The Windows installer, from 0.3.1, on a new install unless you give `OPENSEARCHURL`. Also on an upgrade from 0.3.0 or older that never reached an OpenSearch | A GET of `opensearch-3.9.0-windows-x64.zip`, which must match the SHA-512 pinned in Signalith | Behind a proxy, download the zip yourself and use the option to the right | `OPENSEARCHZIP=<path to the zip>` with `msiexec`, or `-OpenSearchZip` with `install.ps1` ([OpenSearch on Windows](install-packages.md#opensearch-on-windows)) |
| `ghcr.io` (`jrsamsanchez/signalith` image, Helm chart `oci://ghcr.io/jrsamsanchez/charts/signalith`) and Docker Hub (`opensearchproject/opensearch:3.9.0`) | The Docker quick start and the Helm chart, on each pull | Image pulls | Docker's or Kubernetes' | Helm: set `image.repository` and `opensearch.image.repository` to your own registry. The Docker quick start pulls the Signalith image on every `up` (`pull_policy: always`), so it needs a registry it can reach: for a computer without internet access, use the packages instead |

### Signalith Agent install line

| Host | When it is contacted | What is sent | Proxy | Without it |
| --- | --- | --- | --- | --- |
| `packages.fluentbit.io` | Linux: always (the line adds Fluent Bit's repository). Windows: always, unless you give `-FluentBitZip` | Package manager requests, or a GET of the pinned zip | The computer's | Windows: `-FluentBitZip <path>` and `-FluentBitSha256`. Linux: the line has no offline option; set Fluent Bit up by hand ([Agents and syslog](sending-data.md)) |
| `pkg.osquery.io` | Linux with `--osquery`. Windows with `-Osquery`, unless you give `-OsqueryMsi`. macOS, unless osquery is already in `/opt/osquery` | Package manager requests, or a GET of the pinned package | The computer's | Windows: `-OsqueryMsi <path>` and `-OsquerySha256`. macOS: install osquery's own signed package first. Linux: leave out `--osquery` |
| `download.sysinternals.com` | Windows with `-Sysmon`, when Sysmon is not installed yet | A GET of `Sysmon.zip` | The computer's | Install Sysmon yourself first; the agent collects its log whenever it is installed. There is no `-SysmonZip` |

The agent program itself comes from your Signalith server, not from the internet
([Computers without internet access](signalith-agent.md#computers-without-internet-access)).

### Network sensor install line

The [sensor's install line](network-sensor.md#what-it-installs-and-from-where) adds
the publishers' package repositories: `download.opensuse.org` (Zeek),
`ppa.launchpadcontent.net` and `keyserver.ubuntu.com` (Suricata on Ubuntu),
`deb.debian.org` (Debian 12 backports), `download.copr.fedorainfracloud.org` (Suricata on
Rocky, Alma and RHEL, which also needs EPEL turned on), and `packages.fluentbit.io`.
With `--docker`, it pulls `zeek/zeek`, `jasonish/suricata` and `fluent/fluent-bit` from
Docker Hub, pinned by digest. It has no offline or mirror option.

Once running, the sensor downloads the Emerging Threats Open rules from
`rules.emergingthreats.net` once a day with `suricata-update`. `--local-rules` adds rules
of your own, but does not replace ET Open. Its tuning comes from your Signalith server.

## No telemetry

Signalith sends nothing to the Signalith project. It has no usage statistics, no crash
reports and no check for new versions. The only project address it contacts is the
GitHub content release above, and only when you ask it to. Your events stay in the
OpenSearch you run.

## Air-gapped install

These steps give a server, and its agents, no outbound connections beyond your own
network.

1. **Install the server from files.** Download the `.deb`, `.rpm` or `.msi` and
   `SHA256SUMS` on another computer, [check them](install-packages.md#check-a-download)
   and copy them over. On Linux, install OpenSearch from your own copy. On Windows, give
   the OpenSearch zip with `OPENSEARCHZIP` (from 0.3.1), or your own OpenSearch with
   `OPENSEARCHURL`. On Kubernetes, push both images to your registry and set
   `image.repository` and `opensearch.image.repository`.
2. **IP database.** Under **Settings > Behavior baselines**, set **IP database** to
   `file:ip2asn-combined.tsv.gz` and put the file in the `ipdb` folder of the lookups
   folder (`/var/lib/signalith/lookups/ipdb/` on Linux) on each server that can run the
   background jobs. Or set it to `off`: the country and network checks then wait.
3. **Content updates.** Leave **Content pack updates** on **Manual** and don't click
   **Check for updates**. To update, download `signalith-content.tar.gz` and its `.sig`
   elsewhere and use **Upload update...** on the Detections page, or
   `signalith content install`. Or set **Content update address** to a copy on your own
   web server.
4. **Vulnerability scans.** If you scan, set **Known exploited catalog address** and
   **EPSS scores address** to the full paths of copies you bring in each day, and either
   set **CVE database address** to an NVD mirror or turn off **Look up CVEs in the
   National Vulnerability Database** in **Scanner setup**. These are on the **Server** tab
   of [Settings](settings.md), under **Vulnerability scans** (or `vulns.kev_url`,
   `vulns.epss_url` and `vulns.nvd_url`). With Linux hosts on the Endpoints page, set
   **Distribution advisories address** (`vulns.osv_url`) to a folder you copy each
   release's `all.zip` into, or to `off`.
5. **Threat intel.** Add feeds only from files, or from addresses and TAXII servers on
   your network.
6. **AI.** Leave **Provider** off under **Settings > AI assistant**, or point **Address**
   at a model on your network.
7. **Everything else you add** (notification channels, ticketing, response actions,
   directory and single sign-on) must name systems on your network. Leave Microsoft 365
   and Okta off.
8. **Agents.** On Windows, give `-FluentBitZip` (and `-OsqueryMsi` with `-Osquery`), and
   install Sysmon yourself if you want it. On macOS, install osquery first. On Linux, the
   install line needs `packages.fluentbit.io`; install Fluent Bit from your own package
   mirror and set it up by hand instead ([Agents and syslog](sending-data.md)). The
   Signalith Agent itself is not used then.
9. **Network sensors.** The sensor's install line needs the internet and has no offline
   option yet, so an air-gapped network has no supported sensor install.

To check, watch the firewall for connections from the Signalith servers to anything but
OpenSearch, the other servers and the systems you set up. **Scanner setup** and the
baselines page say when a download could not be made.

## Related

- [Where your data goes](data-residency.md): what each feature sends, and where.
- [Threat model](threat-model.md#outbound-requests-and-supply-chain)
- [Code signing policy](code-signing.md#privacy)
