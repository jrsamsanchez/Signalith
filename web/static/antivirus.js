// Add data: Antivirus. One tab per product: Microsoft Defender and ClamAV
// come in through the Fluent Bit agent, the others send syslog (CEF, LEEF
// or their own format) from their management console. The syslog setups
// use the address and ports of the Syslog option (syslogDest and friends
// in app.js), and show the syslog-off steps instead while syslog is off.
// Everything lives in one function scope; antivirusOpen is the way in.
(() => {
  'use strict';

  const productKey = 'signalith.avProduct';
  const av = { h: null, shape: '', product: 'defender', ticker: null, busy: false, observer: null, failed: '' };
  try { av.product = localStorage.getItem(productKey) || 'defender'; } catch (_) { /* storage may be blocked */ }

  const body = () => $('antivirus-body');
  const shown = () => currentPage === 'data' && !$('antivirus-setup').classList.contains('hidden');
  const b = (t) => el('b', {}, t);
  const code = (t) => slCode(t);
  const step = (n, ...parts) => el('li', { class: 'agent-step' }, el('span', { class: 'agent-step__num' }, n),
    el('div', { class: 'agent-step__body' }, ...parts.filter(Boolean)));
  const text = (...parts) => el('p', { class: 'agent-step__text' }, ...parts);
  const steps = (...items) => el('ol', { class: 'agent-steps av-steps', role: 'list' }, ...items.map((parts, i) => step(i + 1, ...[].concat(parts))));
  // A button that opens another source card on this page.
  const sourceButton = (src, label) => el('div', {}, el('button', { class: 'btn btn--secondary btn--sm', type: 'button', onclick: () => {
    pickDataSource(src);
    loadDataSource();
    $('agent-setup').scrollIntoView({ block: 'nearest' });
  } }, icon(src === 'windows' ? 'monitor' : 'square-terminal'), label));

  // antivirusOpen shows the setup. While it is open it re-reads
  // api/health every 5 seconds, so turning syslog on shows the steps.
  async function antivirusOpen() {
    if (!av.ticker) av.ticker = setInterval(tick, 1000);
    if (!av.h) skeleton();
    av.shape = '';
    // Learn the address agents use, the default for consoles too.
    try { await syslogGuessHost(); } catch (_) { /* the browser's address is the guess */ }
    await poll();
  }
  window.antivirusOpen = antivirusOpen;

  let tried = 0;
  function tick() {
    if (!shown()) {
      clearInterval(av.ticker);
      av.ticker = null;
      return;
    }
    if (!document.hidden && Date.now() - tried >= 5000) poll();
  }

  async function poll() {
    if (av.busy) return;
    av.busy = true;
    tried = Date.now();
    try {
      av.h = await api('api/health');
      av.failed = '';
      if (typeof renderHealthCard === 'function') renderHealthCard(av.h);
    } catch (e) {
      if (!av.h) av.failed = e.message || 'The Signalith server did not respond.';
    } finally {
      av.busy = false;
    }
    render();
  }

  // host is where consoles send: the address in "Devices send to" on the
  // Syslog option, else the one agents use.
  function host() {
    const st = syslogState.host;
    if (st && !syslogHostProblem(st.includes(':') ? '[' + st + ']' : st)) return st;
    const h = (syslogSavedHost() || syslogDefaultHost()).replace(/^\[|\]$/g, '');
    return h && !syslogHostProblem(h.includes(':') ? '[' + h + ']' : h) ? h : location.hostname;
  }

  function skeleton() {
    const bar = (w, cls) => el('span', { class: 'skeleton' + (cls ? ' ' + cls : ''), style: 'width:' + w });
    body().setAttribute('aria-busy', 'true');
    body().replaceChildren(el('div', { class: 'av-sk' }, bar('100%', 'av-sk-tabs')),
      el('ol', { class: 'agent-steps', role: 'list' }, ...['52%', '64%', '40%'].map((w) => el('li', { class: 'agent-step' },
        el('span', { class: 'agent-step__num' }), el('div', { class: 'agent-step__body' }, bar(w), bar('100%', 'agent-skel-well'))))));
  }

  // render rebuilds the card only when what it shows changed, so the open
  // tab, focus and copy buttons survive the polling.
  function render() {
    if (av.failed) {
      av.shape = '';
      body().removeAttribute('aria-busy');
      body().replaceChildren(el('div', { class: 'empty empty--compact', 'data-tone': 'danger', role: 'alert' },
        el('span', { class: 'empty__icon' }, icon('circle-alert')),
        el('div', { class: 'empty__title' }, 'Couldn’t load the antivirus setup'),
        el('p', { class: 'empty__text' }, av.failed),
        el('div', { class: 'empty__actions' }, el('button', { class: 'btn btn--secondary btn--sm', type: 'button', onclick: () => { skeleton(); poll(); } }, icon('refresh-cw'), 'Try again'))));
      return;
    }
    if (!av.h) return;
    const sl = av.h.syslog || {};
    const shape = JSON.stringify([sl.enabled, sl.listeners, host(), av.h.runtime, av.h.runtime && av.h.runtime.addresses]);
    if (shape === av.shape) return;
    av.shape = shape;
    build(sl);
  }

  function build(sl) {
    const d = syslogDest(sl);
    d.host = host();
    const products = productList(d, sl);
    if (!products.some((p) => p.id === av.product)) av.product = products[0].id;
    const tabs = el('div', { class: 'tabs sl-tabs', role: 'tablist', 'aria-label': 'Antivirus product' });
    const panel = el('div', { class: 'sl-panel av-panel', role: 'tabpanel', id: 'av-panel', tabindex: '0' });
    const pick = (id, focus) => {
      av.product = id;
      try { localStorage.setItem(productKey, id); } catch (_) { /* storage may be blocked */ }
      tabs.querySelectorAll('[role=tab]').forEach((t) => {
        const on = t.dataset.product === id;
        t.setAttribute('aria-selected', String(on));
        t.tabIndex = on ? 0 : -1;
        if (on && focus) t.focus({ preventScroll: true });
        if (on) {
          panel.setAttribute('aria-labelledby', t.id);
          syslogRevealTab(tabs, t);
        }
      });
      const p = products.find((x) => x.id === id);
      panel.replaceChildren(...productPanel(p, d, sl));
    };
    for (const p of products) {
      const t = el('button', { class: 'tab', type: 'button', role: 'tab', id: 'av-tab-' + p.id, 'data-product': p.id, 'aria-controls': 'av-panel', title: p.title || p.label }, p.label);
      t.addEventListener('click', () => pick(p.id));
      tabs.append(t);
    }
    tabs.addEventListener('keydown', (e) => {
      const list = [...tabs.querySelectorAll('[role=tab]')];
      const i = list.indexOf(document.activeElement);
      const to = { ArrowRight: i + 1, ArrowLeft: i - 1, Home: 0, End: list.length - 1 }[e.key];
      if (i < 0 || to === undefined) return;
      e.preventDefault();
      pick(list[(to + list.length) % list.length].dataset.product, true);
    });
    // syslogTabBar keeps one resize observer; give it ours to replace and
    // leave the Syslog option's own in place.
    const theirs = syslogState.tabsObserver;
    syslogState.tabsObserver = av.observer;
    const bar = syslogTabBar(tabs);
    av.observer = syslogState.tabsObserver;
    syslogState.tabsObserver = theirs;
    body().removeAttribute('aria-busy');
    body().replaceChildren(bar, panel);
    pick(av.product);
  }

  // productPanel is one product's steps and the "Check it works" row. A
  // syslog product shows where it sends first, or the steps that turn
  // syslog on while it is off.
  function productPanel(p, d, sl) {
    const check = el('div', { class: 'av-check' },
      el('span', { class: 'av-check__icon' }, icon('circle-check')),
      el('div', { class: 'av-check__text' }, el('b', {}, 'Check it works'), el('span', {}, p.check || 'Once the console sends its next detection, it shows in Search within a minute.')),
      el('button', { class: 'btn btn--secondary btn--sm', type: 'button', onclick: () => openSearch('datamodel=Malware', '-1h') }, icon('search'), 'Open in Search'));
    if (!p.syslog) return [p.render(), check];
    if (!sl.enabled) return [el('div', { class: 'av-off' }, ...syslogOff(av.h))];
    const out = p.render();
    if (out.blocked) return [...[].concat(out.blocked)];
    return [dest(d, out.proto), out.steps, check];
  }

  // dest is the line above a console's steps: where it sends, and how to
  // change that.
  function dest(d, proto) {
    const ips = (av.h.runtime && av.h.runtime.addresses) || [];
    const loop = agentLoopbackHost(d.host.includes(':') ? '[' + d.host + ']' : d.host);
    const line = el('div', { class: 'av-dest' },
      el('span', { class: 'av-dest__label' }, 'Consoles send to'),
      el('span', { class: 'badge badge--mono' }, syslogHostPort(d.host, d[proto])),
      el('span', { class: 'badge badge--outline' }, syslogProto[proto]),
      el('button', { class: 'link-btn av-dest__change', type: 'button', onclick: () => { openSyslogSetup(); } }, 'Change address'));
    if (!loop) return line;
    // localhost only works from this computer: offer its network addresses.
    const use = (ip) => el('button', { class: 'link-btn mono sl-ip', type: 'button', title: 'Use ' + ip, onclick: () => {
      syslogHostEl.value = ip;
      syslogHostChanged();
      render();
    } }, ip);
    const list = [];
    ips.forEach((ip, i) => list.push(i ? (i === ips.length - 1 ? ' or ' : ', ') : '', use(ip)));
    return el('div', { class: 'av-dest-wrap' }, line, el('p', { class: 'hint', 'data-tone': 'warning' }, icon('triangle-alert'), el('span', {},
      `Your console can’t reach ${d.host}. `, ...(list.length ? ['Use this computer’s network address: ', ...list, '.']
        : ['Choose Change address and enter this computer’s network address, such as ', code('192.168.1.20'), '.']))));
  }

  // ---------- products ----------
  // Each syslog product's render returns { proto, steps }, or { blocked }
  // with a note when the protocol it needs is off. Consoles send over TCP
  // when it is on (no lost lines), else UDP.
  function productList(d) {
    const p = d.tcp ? 'tcp' : d.udp ? 'udp' : '';
    const P = p.toUpperCase();
    const hostC = () => code(d.host);
    const portC = () => code(d[p]);
    const protoC = () => code(P);
    const none = { blocked: slNote('Only syslog over TLS is on, and this console needs UDP or TCP. Set syslog.udp or syslog.tcp on the Settings page to turn one on.') };
    const syslogProduct = (id, label, title, fn) => ({ id, label, title, syslog: true, render: () => (p ? { proto: p, steps: fn() } : none) });
    const config = (lines) => agentSetupCommand(lines.join('\n'), 'Copy settings');
    return [
      { id: 'defender', label: 'Microsoft Defender', title: 'Microsoft Defender Antivirus, through the Windows agent',
        check: 'The test detection shows in Search within a minute of Defender removing the file.', render: () => steps(
          [text('The Windows agent collects Microsoft Defender events. If a host doesn’t have the agent yet, set it up from the Windows card. The OpenTelemetry Collector’s Windows configuration collects them too.'),
            sourceButton('windows', 'Set up the Windows agent')],
          [text('Already running the agent from before this update? Download the configuration again from the Windows card, copy it over ',
            code('C:\\Program Files\\fluent-bit\\conf\\fluent-bit.conf'), ', then restart the agent in PowerShell as administrator:'),
          agentSetupCommand('Restart-Service fluent-bit')],
          [text('To test it, open ', el('a', { href: 'https://www.eicar.org/', target: '_blank', rel: 'noopener noreferrer' }, 'eicar.org', icon('arrow-up-right', 'icon--xs')),
            ' in a browser on that host and download the test file. Defender removes it straight away.')]) },
      { id: 'clamav', label: 'ClamAV', title: 'ClamAV on Linux, through the Linux agent',
        check: 'The test detection shows in Search within a minute of the scan.', render: () => steps(
          [text('The Linux agent collects ClamAV events from ', code('/var/log/clamav'), '. On Red Hat, Rocky, AlmaLinux and Fedora, ClamAV writes to the system journal instead, so choose ',
            b('Read from: systemd journal'), ' on the Linux card.'), sourceButton('linux', 'Set up the Linux agent')],
          [text('Already running the agent from before this update? Download the configuration again from the Linux card, then put it in place and restart the agent:'),
            agentSetupCommand('sudo install -m 600 -o root -g root fluent-bit.conf /etc/fluent-bit/fluent-bit.conf && sudo systemctl restart fluent-bit')],
          [text('To test it, download the harmless test file and scan it:'),
            agentSetupCommand('curl -fsSO https://secure.eicar.org/eicar.com.txt; clamdscan --fdpass eicar.com.txt; rm -f eicar.com.txt', 'Copy commands')]) },
      syslogProduct('symantec', 'Symantec', 'Symantec Endpoint Protection Manager', () => steps(
        text('In Symantec Endpoint Protection Manager, go to ', slMenu('Admin', 'Servers'), ', select ', b('Local Site'), ', and click ', b('Configure External Logging'), '.'),
        text('On the ', b('General'), ' tab, tick ', b('Enable Transmission of Logs to a Syslog Server'), '. Set ', b('Syslog Server'), ' to ', hostC(),
          ', ', b('Destination Port'), ' to ', portC(), ' and the protocol to ', protoC(), '.'),
        text('On the ', b('Log Filter'), ' tab, tick ', b('Risk'), ', and ', b('Client System'), ' for failed definition updates, then click ', b('OK'), '.'))),
      syslogProduct('trend', 'Trend Micro', 'Trend Micro Apex One, through Apex Central (CEF)', () => steps(
        text('In Apex Central, go to ', slMenu('Administration', 'Settings', 'Syslog Settings'), '.'),
        text('Tick ', b('Enable syslog forwarding'), '. Set ', b('Server address'), ' to ', hostC(), ', ', b('Port'), ' to ', portC(), ', ', b('Protocol'), ' to ', protoC(),
          ' and ', b('Log format'), ' to ', code('CEF'), '.'),
        text('Under ', b('Log type'), ', tick ', b('Detections'), ', then click ', b('Save'), '.'))),
      syslogProduct('sophos', 'Sophos', 'Sophos Central, through Sophos’s SIEM script (CEF)', () => steps(
        text('In Sophos Central, go to ', slMenu('Global Settings', 'API Credentials Management'), ', click ', b('Add Credential'), ', choose the ',
          b('Service Principal Read-Only'), ' role and copy the Client ID and Client Secret.'),
        [text('On a Linux server with Python 3, download Sophos’s SIEM script and set these lines in ', code('/opt/sophos-siem/config.ini'), ':'),
          agentSetupCommand('git clone https://github.com/sophos/Sophos-Central-SIEM-Integration.git /opt/sophos-siem'),
          config(['client_id = <your Client ID>', 'client_secret = <your Client Secret>', 'format = cef', 'filename = syslog',
            `address = ${syslogHostPort(d.host, d[p])}`, `socktype = ${p}`])],
        [text('Run it every 5 minutes: add this line with ', code('sudo crontab -e'), ':'),
          agentSetupCommand('*/5 * * * * cd /opt/sophos-siem && python3 siem.py', 'Copy line')])),
      { id: 'epo', label: 'Trellix (McAfee) ePO', title: 'Trellix or McAfee ePolicy Orchestrator, over TLS', syslog: true, render() {
        if (!d.tls) return { blocked: slNote('Trellix ePO sends syslog only over TLS, and TLS syslog is off here. Set syslog.tls on the Settings page to turn it on.') };
        return { proto: 'tls', steps: steps(
          text('In ePO, go to ', slMenu('Menu', 'Configuration', 'Registered Servers'), ' and click ', b('New Server'), '. Choose ', b('Syslog Server'),
            ', name it ', code('Signalith'), ', and click ', b('Next'), '.'),
          text('Set ', b('Server name'), ' to ', hostC(), ' and ', b('Port'), ' to ', code(d.tls), '. Turn on ', b('Enable event forwarding'), ', click ',
            b('Test Connection'), ', then click ', b('Save'), '.')) };
      } },
      syslogProduct('eset', 'ESET', 'ESET PROTECT (JSON or LEEF)', () => steps(
        text('In ESET PROTECT, go to ', slMenu('More', 'Settings', 'Advanced Settings', 'Syslog server'), '. Turn on ', b('Use Syslog server'), ' and set ',
          b('Host'), ' to ', hostC(), ', ', b('Port'), ' to ', portC(), ' and ', b('Transport'), ' to ', protoC(), '.'),
        text('In the same page under ', b('Logging'), ', turn on ', b('Export logs to Syslog'), ', set ', b('Exported logs format'), ' to ', code('JSON'), ' or ', code('LEEF'),
          ', tick ', b('Detections'), ', and click ', b('Save'), '.'))),
      syslogProduct('crowdstrike', 'CrowdStrike', 'CrowdStrike Falcon, through the Falcon SIEM Connector (CEF)', () => steps(
        text('In the Falcon console, go to ', slMenu('Support and resources', 'API clients and keys'), ', click ', b('Add new API client'), ', tick ',
          b('Read'), ' for ', b('Event streams'), ', and copy the Client ID and Secret.'),
        [text('On a Linux server, install the Falcon SIEM Connector (', slMenu('Support and resources', 'Tool downloads'), ') and set these lines in ',
          code('/opt/crowdstrike/etc/cs.falconhoseclient.cfg'), ':'),
        config(['client_id = <your Client ID>', 'client_secret = <your Secret>', 'output_format = cef', 'send_to_syslog_server = true',
          `host = ${d.host}`, `port = ${d[p]}`, `protocol = ${p}`])],
        [text('Start it:'), agentSetupCommand('sudo systemctl restart cs.falconhoseclientd')])),
      syslogProduct('sentinelone', 'SentinelOne', 'SentinelOne (CEF)', () => steps(
        text('In the SentinelOne console, go to ', slMenu('Settings', 'Integrations', 'Syslog'), '. Turn it on, set ', b('Host'), ' to ',
          code(syslogHostPort(d.host, d[p])), ', choose ', code('CEF'), ' as the format, and click ', b('Save'), '.'),
        text('Go to ', slMenu('Settings', 'Notifications'), '. For each threat notification you want (at least ', b('New threat'), ' and ',
          b('Threat mitigation status'), '), tick ', b('Syslog'), '.'))),
      syslogProduct('kaspersky', 'Kaspersky', 'Kaspersky Security Center (CEF)', () => steps(
        text('In Kaspersky Security Center Web Console, open the Administration Server properties and go to ', b('SIEM'), '. Turn on ',
          b('Automatically export events to SIEM system database'), ', set ', b('SIEM system'), ' to ', code('ArcSight (CEF format)'), ', ', b('Address'), ' to ', hostC(),
          ', ', b('Port'), ' to ', portC(), ' and ', b('Protocol'), ' to ', protoC(), ', and click ', b('Save'), '.'),
        text('Open your Kaspersky Endpoint Security policy, go to ', b('Event configuration'), ', select the threat events (Threat detected, Object disinfected, Object deleted, Object quarantined, Object not disinfected), tick ',
          b('Export to SIEM system using Syslog'), ', and click ', b('Save'), '.'))),
      syslogProduct('bitdefender', 'Bitdefender', 'Bitdefender GravityZone, through the Event Push connector (CEF)', () => steps(
        text('In GravityZone, go to ', slMenu('My Account', 'API keys'), ', click ', b('Add'), ', tick ', b('Event Push Service API'), ', and copy the key.'),
        text('Install Bitdefender’s Event Push connector on a Linux server (search for “GravityZone Event Push Service connector” in Bitdefender’s help center), and set its output to syslog in CEF format, sending to ',
          hostC(), ', port ', portC(), ', ', protoC(), '. Turn on the events ', code('av'), ', ', code('avc'), ', ', code('hd'), ', ', code('antiexploit'), ' and ',
          code('ransomware-mitigation'), '.'))),
      syslogProduct('other', 'Other', 'Any other antivirus that sends CEF or LEEF', () => steps(
        text('In your product’s management console, find its syslog or SIEM export and send CEF or LEEF to ', hostC(), ', port ', portC(), ', ', protoC(), '.'),
        text('Signalith files an event under Malware when it names the threat (for example ', code('cs1Label=Threat Name cs1=Trojan.Agent'),
          ') or its category says virus or malware and it names a file. Everything else stays searchable with ', code('sourcetype=cef'), ' or ', code('sourcetype=leef'), '.'))),
    ];
  }
})();
