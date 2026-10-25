// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0
// Vulnerabilities page (analysts and admins): what the network scans
// found. Hosts lists every host up on a scanned network, worst first, and
// opens one for its open ports and the CVEs in the software on them;
// Networks lists what is scanned and when, with Scan now; Scans is the
// history. Setup (admins) checks the scanning server: Nmap, CVE lookups,
// and what each one is for. Settings > Scanners (admins) lists every
// server as a scanner: the networks it scans, whether it reaches them,
// and what it still needs.
'use strict';

(function () {
  const SEV = ['critical', 'high', 'medium', 'low'];
  const DAYS = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];
  const PORTS = [['top100', 'The 100 most common ports'], ['top1000', 'The 1,000 most common ports (recommended)'], ['all', 'All 65,535 ports (slow)'], ['custom', 'Only these ports…']];
  const STATE = { queued: 'Waiting to start', running: 'Scanning', done: 'Finished', failed: 'Failed', stopped: 'Stopped', interrupted: 'Cut off' };
  const STATE_TONE = { done: 'success', failed: 'danger', interrupted: 'warning', stopped: '', queued: 'accent', running: 'accent' };
  const S = { tab: 'hosts', data: null, setup: null, find: '', network: '', vulnOnly: false, poll: null, loading: false };

  pageHooks.push((name) => {
    if (name === 'scanners') loadScanners(false);
    if (name !== 'vulns') {
      stopPoll();
      return;
    }
    load();
  });

  const tabs = { hosts: $('vs-tab-hosts'), networks: $('vs-tab-networks'), scans: $('vs-tab-scans') };
  const panels = { hosts: $('vs-panel-hosts'), networks: $('vs-panel-networks'), scans: $('vs-panel-scans') };
  Object.entries(tabs).forEach(([k, t]) => t.addEventListener('click', () => showTab(k)));
  document.querySelector('.vs-tabs').addEventListener('keydown', (ev) => {
    if (ev.key !== 'ArrowRight' && ev.key !== 'ArrowLeft') return;
    const keys = Object.keys(tabs);
    const i = keys.indexOf(S.tab) + (ev.key === 'ArrowRight' ? 1 : -1);
    const next = keys[(i + keys.length) % keys.length];
    showTab(next);
    tabs[next].focus();
  });
  $('vs-add').addEventListener('click', () => editNetwork(null));
  $('vs-setup').addEventListener('click', () => openSetup());

  function showTab(name) {
    S.tab = name;
    for (const [k, t] of Object.entries(tabs)) {
      t.setAttribute('aria-selected', String(k === name));
      t.tabIndex = k === name ? 0 : -1;
      panels[k].hidden = k !== name;
    }
    render();
  }

  // addScanner opens Settings > Servers > Add a server with Vulnerability
  // scanner picked.
  function addScanner() {
    if (typeof window.openAddServer === 'function') window.openAddServer('scanner');
    else showPage('servers');
  }

  // ---------- servers as scanners ----------
  // servers is every server that can scan; a network names one by its id,
  // and "" is the one running the background jobs.
  const servers = () => (S.data && S.data.servers) || [];
  const multi = () => servers().length > 1;
  const jobServer = () => servers().find((sv) => sv.runs_jobs);
  const serverOf = (n) => (n.scanner ? servers().find((sv) => sv.id === n.scanner) : jobServer());
  // dedicated is the servers added as scanners.
  const dedicated = () => servers().filter((sv) => sv.scanner && sv.state !== 'removed');
  // idleServer is a server no network uses while a scanner exists: its
  // missing setup is information, not an error.
  const idleServer = (sv) => !!sv && dedicated().length > 0 && !sv.networks.length && sv.online && sv.state !== 'removed' && sv.ready === false;
  // firstScanner is the scanner a new network is scanned by unless the
  // admin picks another: a ready one if any.
  const firstScanner = () => {
    const list = dedicated();
    return (list.find((sv) => sv.online && sv.ready) || list[0] || {}).id || '';
  };

  // scannersCard lists every server that can scan, with its state and
  // networks: Scan now for one that has networks, Add a network for one
  // that has none.
  function scannersCard() {
    const list = [...servers()].filter((sv) => sv.state !== 'removed' || sv.networks.length)
      .sort((a, b) => (!!b.scanner - !!a.scanner) || ((b.networks.length > 0) - (a.networks.length > 0)) || (!!b.runs_jobs - !!a.runs_jobs) || a.name.localeCompare(b.name));
    const row = (sv) => {
      const st = idleServer(sv) ? { label: 'Not needed', tone: '' } : scannerState(sv);
      const nets = sv.networks;
      const what = nets.length ? 'Scans ' + nets.map((n) => n.name + (n.enabled ? '' : ' (paused)')).join(', ')
        : sv.scanner ? 'No network uses it yet. Add one to scan from it.' : sv.runs_jobs ? 'Scans the networks that name no scanner; none do now.' : 'No network uses it.';
      const acts = [];
      if (can('admin') && sv.state !== 'removed') {
        if (nets.length) {
          const targets = S.data.targets.filter((t) => nets.some((n) => n.id === t.id));
          const busy = targets.some((t) => t.active);
          acts.push(el('button', { class: 'btn btn--secondary btn--sm', type: 'button', ...(busy ? { disabled: '', title: 'A scan is already running or waiting' } : {}),
            onclick: (ev) => scanAll(sv, targets, ev.currentTarget) }, icon('play'), busy ? 'Scanning' : 'Scan now'));
        } else if (sv.scanner || !dedicated().length) {
          acts.push(el('button', { class: 'btn ' + (sv.scanner ? 'btn--primary' : 'btn--secondary') + ' btn--sm', type: 'button', onclick: () => editNetwork(null, sv.runs_jobs && !sv.scanner ? '' : sv.id) }, icon('plus'), 'Add a network'));
        }
      }
      return el('li', { class: 'vs-scanner', 'data-state': st.tone || 'none' },
        el('span', { class: 'vs-scanner__icon' }, icon(sv.scanner ? 'radar' : 'server')),
        el('div', { class: 'vs-scanner__text' },
          el('div', { class: 'vs-scanner__name' }, el('b', {}, sv.name),
            sv.scanner ? el('span', { class: 'badge badge--accent' }, 'Scanner') : null,
            sv.self ? el('span', { class: 'badge' }, 'This server') : null,
            el('span', { class: 'badge' + (st.tone ? ' badge--' + st.tone : '') }, st.label)),
          el('span', { class: 'vs-muted' }, what)),
        el('div', { class: 'vs-scanner__acts' }, ...acts));
    };
    return el('div', { class: 'card vs-scanners' }, el('div', { class: 'card__body' },
      el('div', { class: 'vs-setup__head' }, el('div', {},
        el('h3', { class: 'vs-setup__title' }, 'Scanners'),
        el('p', { class: 'vs-muted' }, 'Each network is scanned by the server picked under Scanned by. ',
          can('admin') ? el('a', { href: '#scanners', 'data-page': 'scanners' }, 'Settings > Scanners') : null, can('admin') ? ' shows what each one needs.' : null))),
      el('ul', { class: 'vs-scanners__list', role: 'list' }, ...list.map(row))));
  }

  async function scanAll(sv, targets, btn) {
    btn.disabled = true;
    try {
      for (const t of targets) await api('api/vulns/networks/' + encodeURIComponent(t.id) + '/scan', {});
      toast((targets.length === 1 ? targets[0].name : targets.length + ' networks') + ' will be scanned by ' + sv.name + ' in a few seconds.', null, { title: 'Scan started' });
      await load();
    } catch (e) {
      btn.disabled = false;
      toast(e.message, null, { tone: 'danger', title: 'Couldn’t start the scan' });
    }
  }

  // scannerState is a server's state as a scanner, for a badge.
  function scannerState(sv) {
    if (!sv) return { label: 'No server', tone: 'warning' };
    if (sv.state === 'removed') return { label: 'Removed', tone: 'danger' };
    if (!sv.online) return { label: 'Offline', tone: 'danger' };
    if (sv.ready === undefined || sv.ready === null) return { label: 'Not checked yet', tone: '' };
    return sv.ready ? { label: 'Ready', tone: 'success' } : { label: 'Needs setup', tone: 'warning' };
  }

  function scannerName(n) {
    if (!n.scanner) {
      const j = jobServer();
      return j ? j.name + ' (runs the background jobs)' : 'The server that runs the background jobs';
    }
    const sv = serverOf(n);
    return sv ? sv.name : 'A removed server';
  }

  // ---------- loading ----------
  async function load() {
    if (S.loading) return;
    S.loading = true;
    if (!S.data) Object.values(panels).forEach((p) => p.replaceChildren(skeleton()));
    try {
      S.data = await api('api/vulns');
      if (can('admin') && !S.setup && !S.data.targets.length) await loadSetup(false);
      render();
    } catch (e) {
      if (!S.data) panels[S.tab].replaceChildren(failed(e, load));
    } finally {
      S.loading = false;
    }
    schedulePoll();
  }

  async function loadSetup(fresh) {
    try {
      S.setup = await api('api/vulns/setup' + (fresh ? '?fresh=1' : ''));
    } catch (e) {
      S.setup = { error: e.message };
    }
    return S.setup;
  }

  // While a scan runs or waits, the page follows it.
  function schedulePoll() {
    stopPoll();
    if (currentPage !== 'vulns' || !S.data) return;
    const busy = S.data.targets.some((t) => t.active);
    S.poll = setTimeout(load, busy ? 4000 : 30000);
  }

  function stopPoll() {
    clearTimeout(S.poll);
    S.poll = null;
  }

  function skeleton() {
    const bar = (w) => el('span', { class: 'skeleton', style: 'width:' + w });
    return el('div', { class: 'card vs-skel' }, ...['42%', '64%', '50%', '58%'].map((w) => el('div', { class: 'vs-skel__row' }, bar(w))));
  }

  function failed(e, retry) {
    return el('div', { class: 'card' }, el('div', { class: 'empty', 'data-tone': 'danger', role: 'alert' },
      el('span', { class: 'empty__icon' }, icon('circle-alert')),
      el('div', { class: 'empty__title' }, 'Couldn’t load the scan results'),
      el('p', { class: 'empty__text' }, e.message || 'The Signalith server did not respond.'),
      el('div', { class: 'empty__actions' }, el('button', { class: 'btn btn--secondary btn--sm', type: 'button', onclick: retry }, icon('refresh-cw'), 'Try again'))));
  }

  function render() {
    const d = S.data;
    if (!d) return;
    const hostCount = $('vs-host-count');
    hostCount.textContent = d.hosts.length;
    hostCount.classList.toggle('hidden', !d.hosts.length);
    const netCount = $('vs-net-count');
    netCount.textContent = d.targets.length;
    netCount.classList.toggle('hidden', !d.targets.length);
    $('vs-add').classList.toggle('hidden', !can('admin') || !d.targets.length);
    // The sample data's hosts show with no network set up.
    if (!d.targets.length && (S.tab !== 'hosts' || !d.hosts.length)) {
      panels[S.tab].replaceChildren(gettingStarted());
      return;
    }
    if (S.tab === 'hosts') renderHosts();
    if (S.tab === 'networks') renderNetworks();
    if (S.tab === 'scans') renderScans();
  }

  // ---------- getting started ----------
  function gettingStarted() {
    if (!can('admin')) {
      return el('div', { class: 'card' }, el('div', { class: 'empty' },
        el('span', { class: 'empty__icon' }, icon('scan-search')),
        el('div', { class: 'empty__title' }, 'No networks are scanned yet'),
        el('p', { class: 'empty__text' }, 'An admin can set up scans here. Results show up on this page once the first scan finishes.')));
    }
    const rep = S.setup && S.setup.report;
    const ready = rep && rep.ready;
    if (dedicated().length) {
      const pick = firstScanner();
      const sv = servers().find((x) => x.id === pick);
      return el('div', { class: 'vs-start' },
        el('div', { class: 'card vs-start__intro' }, el('div', { class: 'card__body' },
          el('span', { class: 'vs-start__icon' }, icon('scan-search')),
          el('div', {},
            el('h3', { class: 'vs-start__title' }, 'Find vulnerable software on your networks'),
            el('p', { class: 'vs-start__text' }, 'Your scanners run Nmap on the networks you give them, on a schedule. They find the hosts that are up, their open ports and the software on each, ' +
              'then match the versions to known vulnerabilities (CVEs). Findings for the worst ones go to the Findings queue.'),
            el('ol', { class: 'vs-steps' },
              el('li', {}, el('b', {}, 'Pick a scanner. '), 'Below: the servers that can scan and whether each is ready.'),
              el('li', {}, el('b', {}, 'Add a network for it. '), 'Name it, list its addresses, pick when to scan. Scanned by is set to the scanner.'),
              el('li', {}, el('b', {}, 'Scan. '), 'Click Scan now, or wait for the schedule.'))))),
        scannersCard(),
        el('div', { class: 'vs-start__cta' },
          el('button', { class: 'btn btn--primary', type: 'button', onclick: () => editNetwork(null, pick) }, icon('plus'), 'Add a network' + (sv ? ' for ' + sv.name : '')),
          sv && !sv.ready ? el('span', { class: 'hint' }, icon('info'), 'You can add networks now; scans start once ' + sv.name + ' is ready.') : null));
    }
    return el('div', { class: 'vs-start' },
      el('div', { class: 'card vs-start__intro' }, el('div', { class: 'card__body' },
        el('span', { class: 'vs-start__icon' }, icon('scan-search')),
        el('div', {},
          el('h3', { class: 'vs-start__title' }, 'Find vulnerable software on your networks'),
          el('p', { class: 'vs-start__text' }, 'Signalith scans the networks you list with Nmap, on a schedule. It finds the hosts that are up, their open ports and the software on each, ' +
            'then matches the versions to known vulnerabilities (CVEs). Findings for the worst ones go to the Findings queue.'),
          el('ol', { class: 'vs-steps' },
            el('li', {}, el('b', {}, 'Check this server. '), 'Below: what scanning needs and why. Fix anything marked red.'),
            el('li', {}, el('b', {}, 'Add a network. '), 'Name it, list its addresses, pick when to scan.'),
            el('li', {}, el('b', {}, 'Scan. '), 'Click Scan now, or wait for the schedule.'))))),
      setupCard(true),
      el('div', { class: 'vs-start__cta' },
        el('button', { class: 'btn btn--primary', type: 'button', onclick: () => editNetwork(null) }, icon('plus'), 'Add a network'),
        rep && !ready ? el('span', { class: 'hint' }, icon('info'), 'You can add networks now; scans start once the red items are fixed.') : null));
  }

  // ---------- setup ----------
  const CHECK_ICON = { ok: 'circle-check', warn: 'triangle-alert', fail: 'circle-x', info: 'info' };

  function setupCard(inline) {
    const box = el('div', { class: 'card vs-setup' });
    const draw = () => {
      const s = S.setup;
      if (!s) {
        box.replaceChildren(el('div', { class: 'card__body vs-setup__loading' }, el('span', { class: 'pulse', 'data-state': 'warn' }), 'Checking this server…'));
        loadSetup(false).then(draw);
        return;
      }
      if (s.error) {
        box.replaceChildren(el('div', { class: 'card__body' }, el('p', { class: 'field-error' }, icon('circle-alert'), s.error)));
        return;
      }
      const rep = s.report;
      const where = s.here ? 'this server' : (rep && rep.server) || s.scanner_server || 'the server that runs the background jobs';
      const again = el('button', { class: 'btn btn--secondary btn--sm', type: 'button' }, icon('refresh-cw'), 'Check again');
      again.addEventListener('click', async () => {
        again.disabled = true;
        again.replaceChildren(icon('refresh-cw'), 'Checking…');
        await loadSetup(true);
        draw();
        if (!inline) render();
      });
      const head = el('div', { class: 'vs-setup__head' },
        el('div', {},
          el('h3', { class: 'vs-setup__title' }, rep ? (rep.ready ? 'Ready to scan' : 'Scanning needs attention') : 'Not checked yet'),
          el('p', { class: 'vs-muted' }, rep ? 'Scans run on ' + where + '. Checked ' + ago(rep.at) + '.' :
            'Scans run on ' + where + ', which has not checked itself yet.')),
        s.here ? again : null);
      if (!rep) {
        box.replaceChildren(el('div', { class: 'card__body' }, head));
        return;
      }
      // With a scanner added and no network left for this server, its
      // checks are information only.
      const idle = !rep.ready && idleServer(jobServer());
      if (idle) {
        head.querySelector('.vs-setup__title').textContent = 'Not needed on ' + where;
        head.querySelector('.vs-muted').textContent = 'No network uses ' + where + ', so scanning does not need it. Its checks matter only if you pick it to scan a network. Checked ' + ago(rep.at) + '.';
      }
      box.replaceChildren(el('div', { class: 'card__body' }, head,
        el('ul', { class: 'vs-checks', role: 'list' }, ...rep.checks.map((c) => checkRow(c, draw, idle, idle)))));
    };
    draw();
    return box;
  }

  // checkRow is one check; quiet leaves optional warnings closed, as on
  // the Scanners page, where every server repeats them.
  // idle: the server scans no network, so a failed check is only
  // information, shown closed and neutral.
  function checkRow(c, redraw, quiet, idle) {
    const state = idle && (c.state === 'fail' || c.state === 'warn') ? 'info' : c.state;
    const open = state === 'fail' || (state === 'warn' && (!quiet || c.required));
    const extra = [];
    if (c.id === 'cve' && S.data) extra.push(lookupSwitch(redraw));
    return el('li', { class: 'vs-check', 'data-state': state },
      el('details', open ? { open: '' } : {},
        el('summary', {},
          el('span', { class: 'vs-check__icon' }, icon(CHECK_ICON[state] || 'info')),
          el('span', { class: 'vs-check__text' }, el('b', {}, c.title), el('span', {}, c.detail)),
          c.required ? null : el('span', { class: 'badge' }, 'Optional'),
          icon('chevron-down', 'icon--sm chev')),
        el('div', { class: 'vs-check__more' },
          el('p', {}, el('b', {}, 'Why: '), c.why),
          c.fix && c.fix.length ? el('div', {}, el('b', {}, c.state === 'ok' || c.state === 'info' ? 'To change it' : 'How to fix it'),
            el('ol', { class: 'vs-fix' }, ...c.fix.map((f) => el('li', {}, linkify(f))))) : null,
          ...extra)));
  }

  // linkify turns the https:// addresses in a sentence into links.
  function linkify(text) {
    const out = [];
    let last = 0;
    for (const m of text.matchAll(/https:\/\/[^\s)]+[^\s).,]/g)) {
      out.push(text.slice(last, m.index), el('a', { href: m[0], target: '_blank', rel: 'noopener noreferrer' }, m[0].replace('https://', '')));
      last = m.index + m[0].length;
    }
    out.push(text.slice(last));
    return el('span', {}, ...out);
  }

  function lookupSwitch(redraw) {
    const sw = el('input', { type: 'checkbox' });
    sw.checked = S.data.settings.cve_lookup;
    sw.addEventListener('change', async () => {
      sw.disabled = true;
      try {
        await saveSettings({ ...S.data.settings, cve_lookup: sw.checked });
        await loadSetup(true);
        redraw();
        toast(sw.checked ? 'Scans look CVEs up from now on.' : 'Scans list software without looking CVEs up.', null, { title: 'Saved' });
      } catch (e) {
        sw.checked = !sw.checked;
        toast(e.message, null, { tone: 'danger', title: 'Couldn’t save' });
      } finally {
        sw.disabled = false;
      }
    });
    return el('label', { class: 'switch vs-check__switch' }, sw, 'Look up CVEs in the National Vulnerability Database');
  }

  async function openSetup() {
    const dlg = $('vs-setup-dialog');
    dlg.replaceChildren(
      el('div', { class: 'modal__head' }, el('div', {},
        el('h3', { class: 'modal__title', id: 'vs-setup-title' }, 'Scanner setup'),
        el('p', { class: 'modal__desc' }, 'What scanning needs on the scanning server, why, and how to fix anything missing.')),
      el('button', { class: 'btn btn--ghost btn--icon btn--sm modal__close', type: 'button', 'aria-label': 'Close', onclick: () => dlg.close() }, icon('x'))),
      el('div', { class: 'modal__body vs-setup__body' }, dedicated().length ? scannersCard() : null, setupCard(false),
        multi() ? el('p', { class: 'hint vs-setup__more' }, icon('radar'), el('span', {}, 'This checks the server that runs the background jobs. ',
          el('a', { href: '#scanners', 'data-page': 'scanners', onclick: () => dlg.close() }, 'Settings > Scanners'), ' checks every server that scans a network.')) : null),
      el('div', { class: 'modal__foot' }, el('button', { class: 'btn btn--secondary', type: 'button', onclick: () => dlg.close() }, 'Close')));
    if (!dlg.open) dlg.showModal();
  }

  // ---------- hosts ----------
  function renderHosts() {
    const d = S.data;
    const t = d.totals;
    const findEl = el('input', { class: 'input', type: 'search', placeholder: 'Find a host, port or CVE', 'aria-label': 'Find a host, port or CVE', autocomplete: 'off', spellcheck: 'false' });
    findEl.value = S.find;
    const listEl = el('div', { class: 'card vs-hosts' });
    findEl.addEventListener('input', () => { S.find = findEl.value; drawHosts(listEl); });
    const nets = el('select', { class: 'select', 'aria-label': 'Network' }, el('option', { value: '' }, 'All networks'), ...d.targets.map((n) => el('option', { value: n.id }, n.name)));
    nets.value = S.network;
    nets.addEventListener('change', () => { S.network = nets.value; drawHosts(listEl); });
    const only = el('input', { type: 'checkbox' });
    only.checked = S.vulnOnly;
    only.addEventListener('change', () => { S.vulnOnly = only.checked; drawHosts(listEl); });
    panels.hosts.replaceChildren(...[
      bannerFor(d),
      el('div', { class: 'vs-kpis' },
        kpi('Known exploited', t.kev, 'kev', 'CVEs attackers are using now'),
        kpi('Likely exploited', t.likely || 0, 'likely', 'EPSS ' + pct(likelyEPSS(d)) + ' or more'),
        kpi('Critical', t.critical, 'critical', 'CVSS 9.0 and up'),
        kpi('High', t.high, 'high', 'CVSS 7.0 to 8.9'),
        kpi('Medium and low', t.medium + t.low, 'medium', 'CVSS below 7.0'),
        kpi('Hosts', t.hosts, '', t.services.toLocaleString() + ' open ' + (t.services === 1 ? 'port' : 'ports'))),
      el('div', { class: 'toolbar vs-toolbar', role: 'search' },
        el('div', { class: 'input-wrap' }, icon('search'), findEl),
        d.targets.length > 1 ? nets : null,
        el('label', { class: 'switch' }, only, 'Only hosts with CVEs')),
      listEl].filter(Boolean));
    drawHosts(listEl);
  }

  function bannerFor(d) {
    const running = d.targets.filter((n) => n.active);
    if (running.length) {
      return el('div', { class: 'alert vs-running', 'data-tone': 'info' }, el('span', { class: 'pulse', 'data-state': 'warn' }),
        el('div', {}, el('b', {}, running.map((n) => n.name).join(', ') + (running.length === 1 ? ' is' : ' are') + ' being scanned.'),
          el('p', {}, 'Results replace the earlier ones when the scan finishes.')));
    }
    if (!can('admin')) return null;
    if (multi()) {
      const stuck = servers().filter((sv) => sv.networks.length && (sv.state === 'removed' || !sv.online || sv.ready === false));
      if (!stuck.length) return null;
      return el('div', { class: 'alert', 'data-tone': 'warning' }, icon('triangle-alert'), el('div', {},
        el('b', {}, stuck.map((sv) => sv.name + ' (' + scannerState(sv).label.toLowerCase() + ')').join(', ') + (stuck.length === 1 ? ' scans ' : ' scan ') +
          'networks but cannot run scans right now.'),
        el('p', {}, el('a', { href: '#scanners', 'data-page': 'scanners' }, 'Open Settings > Scanners'), ' to see what is missing.')));
    }
    if (d.scanner && !d.scanner.ready) {
      return el('div', { class: 'alert', 'data-tone': 'warning' }, icon('triangle-alert'), el('div', {},
        el('b', {}, 'Scans cannot run on ' + d.scanner.server + ' right now.'),
        el('p', {}, el('a', { href: '#', onclick: (ev) => { ev.preventDefault(); openSetup(); } }, 'Open the scanner setup'), ' to see what is missing.')));
    }
    return null;
  }

  function kpi(label, value, sev, foot) {
    const attrs = { class: 'card vs-kpi' };
    if (sev) attrs['data-sev'] = sev;
    if (!value) attrs['data-zero'] = '';
    return el('div', attrs,
      el('div', { class: 'vs-kpi__label' }, sev ? el('span', { class: 'vs-dot' }) : icon('server'), label),
      el('div', { class: 'vs-kpi__value num' }, value.toLocaleString()),
      el('div', { class: 'vs-kpi__foot' }, foot));
  }

  function drawHosts(listEl) {
    const d = S.data;
    const q = S.find.trim().toLowerCase();
    const rows = d.hosts.filter((h) => (!S.network || h.target_id === S.network) && (!S.vulnOnly || h.counts.critical + h.counts.high + h.counts.medium + h.counts.low) &&
      (!q || [h.hostname, h.address, h.target_name, h.vendor, h.top_cve, ...h.ports.map(String)].some((v) => v && String(v).toLowerCase().includes(q))));
    if (!d.hosts.length) {
      const scanned = d.scans.some((s) => s.state === 'done');
      listEl.replaceChildren(el('div', { class: 'empty' },
        el('span', { class: 'empty__icon' }, icon('scan-search')),
        el('div', { class: 'empty__title' }, scanned ? 'No hosts were up' : 'No scan has finished yet'),
        el('p', { class: 'empty__text' }, scanned ? 'The last scans found no host that answered. Check the addresses on the Networks tab.' :
          'Hosts show up here when a network’s first scan finishes.'),
        can('admin') && !scanned ? el('div', { class: 'empty__actions' }, el('button', { class: 'btn btn--secondary btn--sm', type: 'button', onclick: () => showTab('networks') }, 'Go to Networks')) : null));
      return;
    }
    if (!rows.length) {
      listEl.replaceChildren(el('div', { class: 'empty empty--compact' }, el('div', { class: 'empty__title' }, 'No host matches')));
      return;
    }
    const tbody = el('tbody', {}, ...rows.slice(0, 1000).map((h) => {
      const tr = el('tr', { tabindex: '0', class: 'vs-row', 'aria-label': 'Open ' + (h.hostname || h.address) },
        el('td', { 'data-label': 'Host' }, el('div', { class: 'vs-name' }, h.hostname || h.address),
          el('div', { class: 'vs-sub mono' }, h.hostname ? h.address : h.vendor || '')),
        el('td', { 'data-label': 'Worst', class: 'vs-c-worst' }, worst(h)),
        el('td', { 'data-label': 'CVEs', class: 'vs-c-cves' }, cveCounts(h.counts)),
        el('td', { 'data-label': 'Open ports', class: 'mono vs-c-ports' }, h.target_id === 'installed-packages' ? el('span', { class: 'vs-muted' }, 'Packages') : portsText(h.ports)),
        el('td', { 'data-label': 'Network', class: 'vs-c-net' }, h.target_name),
        el('td', { 'data-label': 'Seen', class: 'vs-c-seen vs-muted' }, ago(h.last_seen)));
      tr.addEventListener('click', () => openHost(h.id));
      tr.addEventListener('keydown', (ev) => { if (ev.key === 'Enter') openHost(h.id); });
      return tr;
    }));
    listEl.replaceChildren(...[el('div', { class: 'table-wrap' }, el('table', { class: 'table vs-table' },
      el('thead', {}, el('tr', {}, el('th', {}, 'Host'), el('th', { class: 'vs-c-worst' }, 'Worst'), el('th', { class: 'vs-c-cves' }, 'CVEs'),
        el('th', { class: 'vs-c-ports' }, 'Open ports'), el('th', { class: 'vs-c-net' }, 'Network'), el('th', { class: 'vs-c-seen' }, 'Seen'))),
      tbody)), rows.length > 1000 ? el('div', { class: 'table-foot' }, 'Showing the first 1,000 of ' + rows.length.toLocaleString() + ' hosts. Narrow the list with Find.') : null].filter(Boolean));
  }

  function sevOf(score) {
    if (score >= 9) return 'critical';
    if (score >= 7) return 'high';
    if (score >= 4) return 'medium';
    return 'low';
  }

  const cap = (s) => (s ? s.charAt(0).toUpperCase() + s.slice(1) : s);

  function worst(h) {
    const total = h.counts.critical + h.counts.high + h.counts.medium + h.counts.low;
    if (!total) return el('span', { class: 'vs-muted' }, 'None found');
    const sev = sevOf(h.max_cvss);
    return el('span', { class: 'vs-worst' }, el('span', { class: 'sev', 'data-sev': sev }, cap(sev)), el('span', { class: 'vs-score num' }, h.max_cvss.toFixed(1)));
  }

  function cveCounts(c) {
    const parts = [];
    if (c.kev) parts.push(el('span', { class: 'badge vs-kev', title: 'In CISA’s Known Exploited Vulnerabilities catalog' }, icon('flag'), c.kev + ' exploited'));
    if (c.likely) parts.push(el('span', { class: 'badge vs-likely', title: 'Not yet known exploited, but EPSS gives a ' + pct(likelyEPSS(S.data)) + ' or higher chance of exploitation in the next 30 days' }, c.likely + ' likely'));
    for (const s of SEV) if (c[s]) parts.push(el('span', { class: 'vs-count', 'data-sev': s, title: c[s] + ' ' + s }, el('span', { class: 'vs-dot' }), c[s]));
    return parts.length ? el('span', { class: 'vs-counts' }, ...parts) : el('span', { class: 'vs-muted' }, '—');
  }

  // EPSS is a probability; show it the way FIRST does, as a percentage.
  function pct(p) {
    const n = p * 100;
    return (n >= 10 || n === 0 ? n.toFixed(0) : n < 0.1 ? '<0.1' : n.toFixed(1)) + '%';
  }

  function likelyEPSS(d) {
    return (d && d.exploits && d.exploits.likely_epss) || 0.1;
  }

  // Exploit intelligence on one vulnerability: the KEV flag, the
  // ransomware note and the EPSS chance, for the row's summary line.
  function exploitBadges(v) {
    const out = [];
    if (v.source === 'package') out.push(el('span', { class: 'badge badge--accent', title: 'The installed package is older than ' + v.fixed + ', the version ' + v.ecosystem + ' fixed it in.' }, 'Package'));
    if (v.distro) out.push(el('span', { class: 'badge', title: 'Matched by version alone. ' + v.distro + ' fixes CVEs in its own builds without changing the version, so this may be fixed already: check the package’s changelog or run a signed-in OpenVAS scan.' }, 'Version only (' + v.distro + ')'));
    if (v.kev) {
      out.push(el('span', { class: 'badge vs-kev', title: 'Added to CISA’s Known Exploited Vulnerabilities catalog on ' + v.kev_added + (v.kev_due ? '; US federal agencies must fix it by ' + v.kev_due : '') }, icon('flag'), 'Exploited'));
      if (v.ransomware) out.push(el('span', { class: 'badge vs-kev', title: 'CISA knows of ransomware campaigns using this vulnerability' }, 'Ransomware'));
    }
    if (v.epss) {
      const likely = !v.kev && v.epss >= likelyEPSS(S.data);
      out.push(el('span', { class: 'badge vs-epss' + (likely ? ' vs-likely' : ''), title: 'FIRST EPSS: ' + pct(v.epss) + ' chance of exploitation in the next 30 days, higher than ' + pct(v.epss_percentile || 0) + ' of all CVEs' }, 'EPSS ' + pct(v.epss)));
    }
    return out;
  }

  function exploitNote(v) {
    return [v.kev ? 'Known exploited since ' + v.kev_added : '', v.kev && v.kev_due ? 'CISA fix-by date ' + v.kev_due : '', v.kev && v.ransomware ? 'Used by ransomware' : '',
      v.epss ? 'EPSS ' + pct(v.epss) + ' (' + Math.floor((v.epss_percentile || 0) * 100) + 'th percentile)' : ''].filter(Boolean);
  }

  function portsText(ports) {
    if (!ports.length) return el('span', { class: 'vs-muted' }, 'None open');
    const shown = ports.slice(0, 6).join(', ');
    return ports.length > 6 ? shown + ' +' + (ports.length - 6) : shown;
  }

  // ---------- one host ----------
  async function openHost(id) {
    const dlg = $('vs-host');
    dlg.replaceChildren(el('div', { class: 'modal__body' }, skeleton()));
    if (!dlg.open) dlg.showModal();
    let h;
    try {
      h = (await api('api/vulns/hosts/' + encodeURIComponent(id))).host;
    } catch (e) {
      dlg.replaceChildren(modalHead('Host', '', 'vs-host-title'), el('div', { class: 'modal__body' }, el('p', { class: 'field-error' }, icon('circle-alert'), e.message)));
      return;
    }
    const fact = (k, v) => (v ? [el('dt', {}, k), el('dd', {}, v)] : []);
    const total = h.counts.critical + h.counts.high + h.counts.medium + h.counts.low;
    dlg.replaceChildren(
      modalHead(h.hostname || h.address, [h.hostname ? h.address : '', h.target_name].filter(Boolean).join(' · '), 'vs-host-title'),
      el('div', { class: 'modal__body vs-host__body' },
        el('dl', { class: 'vs-facts' },
          ...fact('Address', h.address),
          ...fact('Name', h.hostname),
          ...fact('Hardware', [h.mac, h.vendor].filter(Boolean).join(' · ')),
          ...fact('Network', h.target_name),
          ...fact('First seen', new Date(h.first_seen).toLocaleString()),
          ...fact('Last scanned', new Date(h.last_seen).toLocaleString()),
          ...fact('Findings', total ? cveCounts(h.counts) : 'None found')),
        el('div', { class: 'vs-host__links' },
          el('a', { href: '#search', onclick: (ev) => { ev.preventDefault(); dlg.close(); openSearch('datamodel=Vulnerabilities dest_ip=' + h.address, '-30d'); } }, icon('search'), 'Scan history in Search')),
        h.services.length ? el('div', { class: 'vs-services' }, ...h.services.map(serviceBlock))
          : el('p', { class: 'vs-muted' }, h.target_id === 'installed-packages' ? 'No installed package is older than the version its distribution fixed a CVE in.' : 'The host answered, but none of the scanned ports was open.')),
      el('div', { class: 'modal__foot' }, el('button', { class: 'btn btn--secondary', type: 'button', onclick: () => dlg.close() }, 'Close')));
  }

  function modalHead(title, sub, id) {
    return el('div', { class: 'modal__head' },
      el('div', {}, el('h3', { class: 'modal__title', id }, title), sub ? el('p', { class: 'modal__desc' }, sub) : null),
      el('button', { class: 'btn btn--ghost btn--icon btn--sm modal__close', type: 'button', 'aria-label': 'Close', onclick: (ev) => ev.target.closest('dialog').close() }, icon('x')));
  }

  function serviceBlock(s) {
    const pkg = !s.port && s.name === 'package';
    const what = s.port || pkg ? [s.product, s.version].filter(Boolean).join(' ') || s.name || 'Unknown service' : 'The host itself';
    const vulns = s.vulns || [];
    return el('section', { class: 'vs-svc' },
      el('div', { class: 'vs-svc__head' },
        el('span', { class: 'vs-port mono' }, s.port ? s.port + '/' + s.transport : pkg ? 'Package' : 'Host'),
        el('div', { class: 'vs-svc__what' }, el('b', {}, what),
          el('span', { class: 'vs-muted' }, [s.port ? s.name : '', s.tunnel === 'ssl' ? 'over TLS' : '', s.extra].filter(Boolean).join(' · '))),
        vulns.length ? el('span', { class: 'badge badge--danger' }, vulns.length + (vulns.length === 1 ? ' finding' : ' findings')) : el('span', { class: 'badge badge--success' }, 'No known CVEs')),
      vulns.length ? el('ul', { class: 'vs-vulns', role: 'list' }, ...vulns.slice(0, 200).map(vulnRow)) : null,
      vulns.length > 200 ? el('p', { class: 'hint' }, 'And ' + (vulns.length - 200) + ' more. Search shows them all.') : null);
  }

  function vulnRow(v) {
    const ov = v.source === 'openvas';
    const nvd = v.cve ? el('p', {}, el('a', { href: 'https://nvd.nist.gov/vuln/detail/' + encodeURIComponent(v.cve), target: '_blank', rel: 'noopener noreferrer' },
      'Read about ' + v.cve + ' in the National Vulnerability Database', icon('external-link', 'icon--xs'))) : null;
    if (ov) {
      return el('li', { class: 'vs-vuln' },
        el('details', {},
          el('summary', {},
            el('span', { class: 'sev', 'data-sev': SEV.includes(v.severity) ? v.severity : 'low' }, cap(v.severity)),
            el('span', { class: 'vs-score num', title: 'Severity score from OpenVAS' }, v.cvss ? v.cvss.toFixed(1) : '–'),
            v.cve ? el('span', { class: 'vs-vuln__id mono' }, v.cve) : null,
            el('span', { class: 'badge badge--accent', title: 'Found by an OpenVAS test' }, 'OpenVAS'),
            ...exploitBadges(v),
            el('span', { class: 'vs-vuln__desc' }, v.name || v.description || ''),
            icon('chevron-down', 'icon--sm chev')),
          el('div', { class: 'vs-vuln__more' },
            el('p', {}, el('b', {}, v.name || 'OpenVAS finding')),
            v.description ? el('p', {}, v.description) : null,
            v.solution ? el('p', {}, el('b', {}, 'How to fix it: '), v.solution) : null,
            el('p', { class: 'vs-muted' }, ['OpenVAS test ' + v.oid, v.cves && v.cves.length > 1 ? 'Also ' + v.cves.filter((c) => c !== v.cve).join(', ') : '', ...exploitNote(v)].filter(Boolean).join(' · ')),
            nvd)));
    }
    return el('li', { class: 'vs-vuln' },
      el('details', {},
        el('summary', {},
          el('span', { class: 'sev', 'data-sev': SEV.includes(v.severity) ? v.severity : 'low' }, cap(v.severity)),
          el('span', { class: 'vs-score num', title: 'CVSS ' + (v.cvss_version || '') + ' base score' }, v.cvss ? v.cvss.toFixed(1) : '–'),
          el('span', { class: 'vs-vuln__id mono' }, v.cve),
          ...exploitBadges(v),
          el('span', { class: 'vs-vuln__desc' }, v.description || ''),
          icon('chevron-down', 'icon--sm chev')),
        el('div', { class: 'vs-vuln__more' },
          v.description ? el('p', {}, v.description) : null,
          el('p', { class: 'vs-muted' }, [v.published ? 'Published ' + v.published : '', ...exploitNote(v),
            v.source === 'package' ? 'Fixed in ' + v.fixed + ' on ' + v.ecosystem + (v.advisory ? ' (' + v.advisory + ')' : '') : 'Matched ' + v.cpe].filter(Boolean).join(' · ')),
          el('p', {}, el('a', { href: 'https://nvd.nist.gov/vuln/detail/' + encodeURIComponent(v.cve), target: '_blank', rel: 'noopener noreferrer' }, 'Read about ' + v.cve + ' in the National Vulnerability Database', icon('external-link', 'icon--xs'))))));
  }

  // ---------- networks ----------
  function scheduleText(n) {
    const s = n.schedule;
    const hour = String(s.hour).padStart(2, '0') + ':00';
    if (s.every === 'manual') return 'Only when you click Scan now';
    if (s.every === 'weekly') return 'Every ' + DAYS[s.weekday] + ' at ' + hour;
    return 'Every day at ' + hour;
  }

  function portsLabel(p) {
    const known = PORTS.find(([v]) => v === p);
    return known ? known[1].replace(' (recommended)', '') : 'Ports ' + p;
  }

  function renderNetworks() {
    const d = S.data;
    panels.networks.replaceChildren(...[multi() ? scannersCard() : null, el('div', { class: 'vs-nets' }, ...d.targets.map(networkCard)),
      el('p', { class: 'hint' }, icon('clock'), 'Times are in the scanning server’s time zone.')].filter(Boolean));
  }

  function networkCard(n) {
    const a = n.active;
    const last = n.last_scan;
    let status;
    if (a) {
      const p = a.progress || {};
      const pct = a.state === 'running' && p.percent > 0 ? Math.round(p.percent) : null;
      status = el('div', { class: 'vs-net__status' },
        el('span', { class: 'pulse', 'data-state': 'warn' }),
        el('span', {}, a.state === 'running' ? (p.task === 'OpenVAS' ? 'OpenVAS scanning' : 'Scanning') + (pct !== null ? ', ' + pct + '%' : '…') + (p.hosts_up ? ' · ' + p.hosts_up + ' up so far' : '') + (multi() && a.scanner ? ' on ' + a.scanner : '') :
          waitingText(n)),
        pct !== null ? el('span', { class: 'vs-progress', role: 'progressbar', 'aria-valuenow': pct, 'aria-valuemin': 0, 'aria-valuemax': 100, 'aria-label': 'Scan progress' }, el('span', { style: 'width:' + pct + '%' })) : null);
    } else if (last) {
      status = el('div', { class: 'vs-net__status' },
        el('span', { class: 'badge' + (STATE_TONE[last.state] ? ' badge--' + STATE_TONE[last.state] : '') }, STATE[last.state] || last.state),
        el('span', { class: 'vs-muted' }, ago(last.finished_at || last.created_at)));
    } else {
      status = el('div', { class: 'vs-net__status vs-muted' }, 'Not scanned yet');
    }
    const actions = [];
    if (can('admin')) {
      if (a) actions.push(el('button', { class: 'btn btn--secondary btn--sm', type: 'button', onclick: (ev) => stopScan(a, ev.currentTarget) }, icon('circle-x'), 'Stop'));
      else actions.push(el('button', { class: 'btn btn--secondary btn--sm', type: 'button', onclick: (ev) => scanNow(n, ev.currentTarget) }, icon('play'), 'Scan now'));
      actions.push(el('button', { class: 'btn btn--ghost btn--sm', type: 'button', onclick: () => editNetwork(n) }, icon('pencil'), 'Edit'));
    }
    const lastProblem = !a && last && (last.error || last.openvas_error || last.cve_error);
    return el('article', { class: 'card vs-net' }, el('div', { class: 'card__body' },
      el('div', { class: 'vs-net__head' },
        el('div', { class: 'vs-net__title' }, el('h3', {}, n.name),
          n.enabled ? null : el('span', { class: 'badge' }, 'Paused'),
          n.gentle ? el('span', { class: 'badge badge--accent', title: 'Scans slowly with fewer probes' }, 'Gentle') : null,
          n.openvas ? el('span', { class: 'badge badge--accent', title: 'Also scanned with OpenVAS' }, 'OpenVAS') : null,
          n.openvas && (n.ssh_login || n.smb_login || n.esxi_login || n.snmp_login) ? el('span', { class: 'badge', title: 'OpenVAS signs in to its hosts' }, 'Signed-in scan') : null),
        el('div', { class: 'vs-net__actions' }, ...actions)),
      el('p', { class: 'vs-net__addrs mono' }, n.networks.join(', ') + (n.exclude && n.exclude.length ? '  (skipping ' + n.exclude.join(', ') + ')' : '')),
      el('dl', { class: 'vs-net__facts' },
        el('dt', {}, 'When'), el('dd', {}, n.enabled ? scheduleText(n) : 'Paused: no scheduled scans'),
        n.enabled && n.next_run ? el('dt', {}, 'Next') : null, n.enabled && n.next_run ? el('dd', {}, new Date(n.next_run).toLocaleString([], { weekday: 'short', hour: '2-digit', minute: '2-digit', month: 'short', day: 'numeric' })) : null,
        el('dt', {}, 'Ports'), el('dd', {}, portsLabel(n.ports)),
        multi() || n.scanner ? el('dt', {}, 'Scanned by') : null,
        multi() || n.scanner ? el('dd', { class: 'vs-net__scanner' }, scannerName(n), scannerBadge(serverOf(n))) : null,
        el('dt', {}, 'Found'), el('dd', {}, n.hosts ? el('span', { class: 'vs-found' }, n.hosts + (n.hosts === 1 ? ' host' : ' hosts') + ', ', cveCounts(n.counts)) : '—')),
      status,
      lastProblem ? el('p', { class: last.error ? 'field-error' : 'hint' }, icon(last.error ? 'circle-alert' : 'info'), last.error || (last.openvas_error ? 'OpenVAS: ' + last.openvas_error : 'CVE lookups: ' + last.cve_error)) : null));
  }

  // scannerBadge flags a scanner that cannot scan now; a ready one needs
  // no badge.
  function scannerBadge(sv) {
    const st = scannerState(sv);
    if (st.tone === 'success' || !can('admin')) return null;
    return el('span', { class: 'badge' + (st.tone ? ' badge--' + st.tone : '') }, st.label);
  }

  function waitingText(n) {
    const sv = serverOf(n);
    if (multi() && sv && (sv.state === 'removed' || !sv.online)) return 'Waiting for ' + sv.name + ', which is ' + scannerState(sv).label.toLowerCase();
    return multi() && sv ? 'Waiting to start on ' + sv.name : 'Waiting to start';
  }

  async function scanNow(n, btn) {
    btn.disabled = true;
    try {
      await api('api/vulns/networks/' + encodeURIComponent(n.id) + '/scan', {});
      toast(n.name + ' will be scanned in a few seconds.', null, { title: 'Scan started' });
      await load();
    } catch (e) {
      btn.disabled = false;
      toast(e.message, null, { tone: 'danger', title: 'Couldn’t start the scan' });
    }
  }

  async function stopScan(sc, btn) {
    btn.disabled = true;
    try {
      await api('api/vulns/scans/' + encodeURIComponent(sc.id) + '/stop', {});
      toast('The scan stops within a few seconds. Earlier results are kept.', null, { title: 'Stopping' });
      await load();
    } catch (e) {
      btn.disabled = false;
      toast(e.message, null, { tone: 'danger', title: 'Couldn’t stop the scan' });
    }
  }

  async function saveSettings(settings) {
    const out = await api('api/vulns/settings', { settings, version: S.data.version }, 'PUT');
    S.data = out;
    return out;
  }

  // ---------- add or edit a network ----------
  function newID() {
    const b = new Uint8Array(6);
    crypto.getRandomValues(b);
    return 'n-' + Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
  }

  // scanner, for a new network, is the server to scan it from; left out,
  // a dedicated scanner if there is one.
  function editNetwork(n, scanner) {
    const dlg = $('vs-net-dialog');
    const isNew = !n;
    const t = n || { id: newID(), name: '', networks: [], exclude: [], ports: 'top1000', gentle: false, enabled: true, schedule: { every: 'daily', hour: 1, weekday: 0 },
      scanner: scanner === undefined ? firstScanner() : scanner };
    const name = el('input', { class: 'input', id: 'vs-name', maxlength: '80', placeholder: 'Office LAN', autocomplete: 'off', required: '' });
    name.value = t.name;
    const addrs = el('textarea', { class: 'textarea mono', id: 'vs-addrs', rows: '4', spellcheck: 'false', placeholder: '192.168.1.0/24\n10.0.5.10-50\nfileserver.corp.example' });
    addrs.value = t.networks.join('\n');
    const skip = el('textarea', { class: 'textarea mono', id: 'vs-skip', rows: '2', spellcheck: 'false', placeholder: '192.168.1.1' });
    skip.value = (t.exclude || []).join('\n');
    const known = PORTS.some(([v]) => v === t.ports && v !== 'custom');
    const ports = el('select', { class: 'select select--block', id: 'vs-ports' }, ...PORTS.map(([v, l]) => el('option', { value: v }, l)));
    ports.value = known ? t.ports : 'custom';
    const custom = el('input', { class: 'input mono', id: 'vs-custom', placeholder: '22,80,443,3389,8000-8100', 'aria-label': 'Ports to scan' });
    custom.value = known ? '' : t.ports;
    const customWrap = el('div', { class: 'field' }, custom, el('p', { class: 'hint' }, 'Ports and ranges, separated by commas.'));
    const syncPorts = () => { customWrap.hidden = ports.value !== 'custom'; };
    ports.addEventListener('change', syncPorts);
    syncPorts();
    const every = el('select', { class: 'select', id: 'vs-every', 'aria-label': 'How often' },
      el('option', { value: 'daily' }, 'Every day'), el('option', { value: 'weekly' }, 'Every week'), el('option', { value: 'manual' }, 'Only when I click Scan now'));
    every.value = t.schedule.every;
    const day = el('select', { class: 'select', 'aria-label': 'Day' }, ...DAYS.map((dname, i) => el('option', { value: String(i) }, 'on ' + dname)));
    day.value = String(t.schedule.weekday);
    const hour = el('select', { class: 'select', 'aria-label': 'Time' }, ...Array.from({ length: 24 }, (_, h) => el('option', { value: String(h) }, 'at ' + String(h).padStart(2, '0') + ':00')));
    hour.value = String(t.schedule.hour);
    const syncEvery = () => { day.hidden = every.value !== 'weekly'; hour.hidden = every.value === 'manual'; };
    every.addEventListener('change', syncEvery);
    syncEvery();
    let scannerSel = null;
    if (multi() || t.scanner) {
      const j = jobServer();
      const opt = (value, label, sv) => el('option', { value }, label + (sv ? ' · ' + scannerState(sv).label : ''));
      scannerSel = el('select', { class: 'select select--block', id: 'vs-scanner' },
        opt('', 'Whichever server runs the background jobs' + (j ? ' (now ' + j.name + ')' : ''), null),
        ...servers().map((sv) => opt(sv.id, sv.name + (sv.self ? ' (this server)' : sv.scanner ? ' (scanner)' : ''), sv)));
      scannerSel.value = t.scanner || '';
    }
    const gentle = el('input', { type: 'checkbox' });
    gentle.checked = t.gentle;
    const deep = el('input', { type: 'checkbox' });
    deep.checked = !!t.openvas;
    // OpenVAS sends far more traffic than a gentle scan allows.
    const gentleOff = () => {
      if (gentle.checked) deep.checked = false;
      deep.disabled = gentle.checked;
    };
    gentle.addEventListener('change', gentleOff);
    gentleOff();
    // The logins OpenVAS signs in with, filled in once they load.
    const loginSel = (id, kind, value) => {
      const sel = el('select', { class: 'select select--block', id }, el('option', { value: '' }, 'None: scan from outside only'));
      if (value) sel.append(el('option', { value }, 'Loading…'));
      sel.value = value || '';
      loadLogins(false).then(({ logins }) => {
        sel.replaceChildren(el('option', { value: '' }, 'None: scan from outside only'),
          ...logins.filter((l) => l.kind === kind).map((l) => el('option', { value: l.id }, l.name + ' (' + (l.username || 'community') + ')' + (l.readable ? '' : ' · enter again'))));
        if (value && !logins.some((l) => l.id === value)) sel.append(el('option', { value }, 'A removed login'));
        sel.value = value || '';
      }).catch(() => {});
      return sel;
    };
    const sshLogin = loginSel('vs-ssh-login', 'ssh', t.ssh_login);
    const smbLogin = loginSel('vs-smb-login', 'smb', t.smb_login);
    const esxiLogin = loginSel('vs-esxi-login', 'esxi', t.esxi_login);
    const snmpLogin = loginSel('vs-snmp-login', 'snmp', t.snmp_login);
    const loginsWrap = el('div', { class: 'vs-logins' },
      el('div', { class: 'field' }, el('label', { class: 'label', for: 'vs-ssh-login' }, 'Sign in to Linux hosts with'), sshLogin),
      el('div', { class: 'field' }, el('label', { class: 'label', for: 'vs-smb-login' }, 'Sign in to Windows hosts with'), smbLogin),
      el('div', { class: 'field' }, el('label', { class: 'label', for: 'vs-esxi-login' }, 'Sign in to VMware ESXi hosts with'), esxiLogin),
      el('div', { class: 'field' }, el('label', { class: 'label', for: 'vs-snmp-login' }, 'Sign in to network devices (SNMP) with'), snmpLogin,
        el('p', { class: 'hint' }, 'With an SNMP login, OpenVAS also checks UDP 161: on Top 100, Top 1000 or All ports it scans all TCP ports and the 100 most-used UDP ports, which is much more traffic. ' +
          'On fragile networks, pick your own ports instead; UDP 161 is added to them.')),
      el('p', { class: 'hint' }, el('span', {}, 'Optional: signed in, OpenVAS checks installed patches and settings. Add logins on ',
        el('a', { href: '#scanners', 'data-page': 'scanners', onclick: () => dlg.close() }, 'Settings > Scanners'), '.')));
    const syncLogins = () => { loginsWrap.hidden = !deep.checked; };
    deep.addEventListener('change', syncLogins);
    gentle.addEventListener('change', syncLogins);
    syncLogins();
    const enabled = el('input', { type: 'checkbox' });
    enabled.checked = t.enabled;
    const allowed = el('input', { type: 'checkbox', id: 'vs-allowed' });
    const err = el('p', { class: 'field-error hidden', role: 'alert' });
    const save = el('button', { class: 'btn btn--primary', type: 'submit' }, isNew ? 'Add network' : 'Save');
    const lines = (v) => v.split(/[\n,]/).map((x) => x.trim()).filter(Boolean);
    dlg.replaceChildren(el('form', { method: 'dialog', novalidate: '' },
      el('div', { class: 'modal__head' }, el('div', {},
        el('h3', { class: 'modal__title', id: 'vs-net-title' }, isNew ? 'Add a network to scan' : 'Edit ' + t.name),
        el('p', { class: 'modal__desc' }, 'Signalith finds the hosts that are up, their open ports and the software on them, then looks up known vulnerabilities.')),
      el('button', { class: 'btn btn--ghost btn--icon btn--sm modal__close', type: 'button', 'aria-label': 'Close', onclick: () => dlg.close() }, icon('x'))),
      el('div', { class: 'modal__body vs-form' },
        el('div', { class: 'field' }, el('label', { class: 'label', for: 'vs-name' }, 'Name'), name),
        el('div', { class: 'field' }, el('label', { class: 'label', for: 'vs-addrs' }, 'Addresses to scan'), addrs,
          el('p', { class: 'hint' }, 'One per line: an address, a network such as 192.168.1.0/24 (up to a /16), a range such as 10.0.5.10-50, or a host name.')),
        el('details', { class: 'vs-more', ...(t.exclude && t.exclude.length ? { open: '' } : {}) }, el('summary', {}, 'Addresses to skip'),
          el('div', { class: 'field' }, skip, el('p', { class: 'hint' }, 'Hosts that must never be scanned, such as fragile devices or ones you have no permission for.'))),
        el('div', { class: 'field' }, el('label', { class: 'label', for: 'vs-ports' }, 'Ports'), ports), customWrap,
        scannerSel ? el('div', { class: 'field' }, el('label', { class: 'label', for: 'vs-scanner' }, 'Scanned by'), scannerSel,
          el('p', { class: 'hint' }, el('span', {}, 'Pick a server that can reach these addresses, such as one inside this network’s zone. ',
            el('a', { href: '#scanners', 'data-page': 'scanners', onclick: () => dlg.close() }, 'Settings > Scanners'), ' shows what each server needs.'))) :
          el('p', { class: 'hint vs-zone-hint' }, icon('network'), el('span', {}, 'Network in a separate zone that this server cannot reach? ',
            el('a', { href: '#servers', onclick: (ev) => { ev.preventDefault(); dlg.close(); addScanner(); } }, 'Add a scanner'), ' inside it, then pick it here to scan from there.')),
        el('div', { class: 'field' }, el('label', { class: 'label', for: 'vs-every' }, 'When'), el('div', { class: 'vs-when' }, every, day, hour),
          el('p', { class: 'hint' }, 'In the scanning server’s time zone. Pick a quiet hour: scans add some network traffic.')),
        el('label', { class: 'switch vs-switch' }, gentle, el('span', {}, el('b', {}, 'Gentle mode'),
          el('span', { class: 'vs-muted' }, 'Scans slowly, one probe at a time, for networks with fragile devices such as old printers or building controllers. Takes several times longer.'))),
        el('label', { class: 'switch vs-switch' }, deep, el('span', {}, el('b', {}, 'Also scan with OpenVAS'),
          el('span', { class: 'vs-muted' }, 'Optional and deeper: after Nmap, OpenVAS tests each host for thousands of known weaknesses, such as missing patches and default passwords. ' +
            'Much slower, and only on a scanner where OpenVAS is set up (Settings > Scanners says how). Not with Gentle mode.'))),
        loginsWrap,
        isNew ? null : el('label', { class: 'switch vs-switch' }, enabled, el('span', {}, el('b', {}, 'Scan on schedule'), el('span', { class: 'vs-muted' }, 'Off pauses scheduled scans; Scan now still works.'))),
        isNew ? el('label', { class: 'vs-allowed' }, allowed, el('span', {}, 'I own these networks, or have permission to scan them. Scanning networks you do not own can be against the law.')) : null,
        err),
      el('div', { class: 'modal__foot' },
        isNew ? null : el('button', { class: 'btn btn--ghost vs-danger', type: 'button', onclick: () => confirmDelete(t) }, icon('trash-2'), 'Remove'),
        el('span', { class: 'spacer' }),
        el('button', { class: 'btn btn--ghost', type: 'button', onclick: () => dlg.close() }, 'Cancel'), save)));
    dlg.querySelector('form').addEventListener('submit', async (ev) => {
      ev.preventDefault();
      const fail = (msg, field) => {
        err.replaceChildren(icon('circle-alert'), msg);
        err.classList.remove('hidden');
        if (field) field.focus();
      };
      if (!name.value.trim()) return fail('Give the network a name, such as Office LAN.', name);
      if (!lines(addrs.value).length) return fail('List at least one address, network or host name to scan.', addrs);
      if (ports.value === 'custom' && !custom.value.trim()) return fail('List the ports to scan, or pick one of the choices.', custom);
      if (isNew && !allowed.checked) return fail('Confirm that you may scan these networks.', allowed);
      const next = {
        ...t, name: name.value.trim(), networks: lines(addrs.value), exclude: lines(skip.value),
        ports: ports.value === 'custom' ? custom.value.replace(/\s+/g, '') : ports.value, gentle: gentle.checked, openvas: deep.checked, enabled: isNew ? true : enabled.checked,
        schedule: { every: every.value, hour: +hour.value, weekday: +day.value },
      };
      if (scannerSel) next.scanner = scannerSel.value;
      next.ssh_login = deep.checked ? sshLogin.value : '';
      next.smb_login = deep.checked ? smbLogin.value : '';
      next.esxi_login = deep.checked ? esxiLogin.value : '';
      next.snmp_login = deep.checked ? snmpLogin.value : '';
      const targets = S.data.settings.targets.filter((x) => x.id !== t.id);
      const at = S.data.settings.targets.findIndex((x) => x.id === t.id);
      targets.splice(at < 0 ? targets.length : at, 0, next);
      save.disabled = true;
      try {
        await saveSettings({ ...S.data.settings, targets });
        dlg.close();
        if (isNew) {
          toast(next.name + ' was added. Scan it now, or wait for its schedule.', { label: 'Scan now', run: () => scanNow({ id: next.id, name: next.name }, el('button')) }, { title: 'Network added' });
          S.tab = 'networks';
        } else {
          toast('Changes apply from the next scan.', null, { title: 'Saved' });
        }
        showTab(S.tab);
      } catch (e) {
        fail(e.message);
      } finally {
        save.disabled = false;
      }
    });
    dlg.showModal();
    if (isNew) name.focus();
  }

  function confirmDelete(t) {
    const dlg = $('vs-confirm');
    dlg.replaceChildren(el('form', { method: 'dialog' },
      el('div', { class: 'modal__head' }, el('div', {},
        el('h3', { class: 'modal__title', id: 'vs-confirm-title' }, 'Remove ' + t.name + '?'),
        el('p', { class: 'modal__desc', id: 'vs-confirm-desc' }, 'It is no longer scanned, and its hosts leave this page. Events its scans wrote stay in Search.'))),
      el('div', { class: 'modal__foot' },
        el('button', { class: 'btn btn--ghost', type: 'button', onclick: () => dlg.close() }, 'Cancel'),
        el('button', { class: 'btn btn--danger', type: 'submit', onclick: async (ev) => {
          ev.preventDefault();
          try {
            await saveSettings({ ...S.data.settings, targets: S.data.settings.targets.filter((x) => x.id !== t.id) });
            dlg.close();
            $('vs-net-dialog').close();
            toast(t.name + ' was removed.');
            render();
          } catch (e) {
            toast(e.message, null, { tone: 'danger', title: 'Couldn’t remove the network' });
          }
        } }, icon('trash-2'), 'Remove'))));
    dlg.showModal();
  }

  // ---------- scan history ----------
  function duration(sc) {
    if (!sc.started_at) return '';
    const end = sc.finished_at ? new Date(sc.finished_at) : new Date();
    const s = Math.max(0, Math.round((end - new Date(sc.started_at)) / 1000));
    if (s < 60) return s + 's';
    if (s < 3600) return Math.round(s / 60) + ' min';
    return (s / 3600).toFixed(1) + ' h';
  }

  function renderScans() {
    const scans = S.data.scans;
    if (!scans.length) {
      panels.scans.replaceChildren(el('div', { class: 'card' }, el('div', { class: 'empty empty--compact' },
        el('span', { class: 'empty__icon' }, icon('history')), el('div', { class: 'empty__title' }, 'No scans yet'))));
      return;
    }
    panels.scans.replaceChildren(el('div', { class: 'card' }, el('div', { class: 'table-wrap' }, el('table', { class: 'table vs-scans' },
      el('thead', {}, el('tr', {}, el('th', {}, 'Network'), el('th', {}, 'Result'), el('th', {}, 'Started'), el('th', {}, 'Took'), el('th', {}, 'Found'),
        multi() ? el('th', {}, 'Scanner') : null, el('th', {}, 'Started by'))),
      el('tbody', {}, ...scans.map((sc) => el('tr', {},
        el('td', { 'data-label': 'Network' }, sc.target_name),
        el('td', { 'data-label': 'Result' }, el('span', { class: 'badge' + (STATE_TONE[sc.state] ? ' badge--' + STATE_TONE[sc.state] : '') }, STATE[sc.state] || sc.state),
          sc.error ? el('div', { class: 'vs-scan-err' }, sc.error) : null,
          sc.openvas_error ? el('div', { class: 'vs-muted vs-scan-err' }, 'OpenVAS: ' + sc.openvas_error) : null,
          sc.cve_error ? el('div', { class: 'vs-muted vs-scan-err' }, 'CVE lookups: ' + sc.cve_error) : null),
        el('td', { 'data-label': 'Started', class: 'vs-muted' }, sc.started_at ? new Date(sc.started_at).toLocaleString() : 'Not yet'),
        el('td', { 'data-label': 'Took', class: 'num' }, duration(sc)),
        el('td', { 'data-label': 'Found' }, sc.state === 'done' ? el('span', { class: 'vs-found' }, sc.counts.hosts + (sc.counts.hosts === 1 ? ' host ' : ' hosts '), cveCounts(sc.counts)) : '—'),
        multi() ? el('td', { 'data-label': 'Scanner', class: 'vs-muted' }, sc.scanner || '—') : null,
        el('td', { 'data-label': 'Started by', class: 'vs-muted' }, sc.trigger === 'schedule' ? 'Schedule' : sc.requested_by || 'Scan now'))))))));
  }
  // ---------- Settings > Scanners ----------
  const SC = { data: null, loading: false, poll: null };

  async function loadScanners(fresh) {
    const box = $('sc-page');
    clearTimeout(SC.poll);
    if (SC.loading) return;
    SC.loading = true;
    if (!SC.data) box.replaceChildren(skeleton());
    try {
      const [data, logins] = await Promise.all([api('api/vulns/scanners' + (fresh ? '?fresh=1' : '')), loadLogins(true).catch(() => null)]);
      SC.data = data;
      if (logins) SC.logins = logins;
      box.removeAttribute('aria-busy');
      renderScanners();
    } catch (e) {
      if (!SC.data) box.replaceChildren(failed(e, () => loadScanners(false)));
    } finally {
      SC.loading = false;
    }
    // Servers check themselves every few minutes, and every 30 seconds
    // while something is missing: follow them.
    if (currentPage === 'scanners') SC.poll = setTimeout(() => loadScanners(false), 30000);
  }

  function renderScanners() {
    // Dedicated scanners first, so whether one exists shows at a glance,
    // then servers that scan a network, then the server running the
    // background jobs, then by name.
    const list = [...SC.data.servers].sort((a, b) => (!!b.scanner - !!a.scanner) || ((b.networks.length > 0) - (a.networks.length > 0)) ||
      (!!b.runs_jobs - !!a.runs_jobs) || a.name.localeCompare(b.name));
    const dedicated = list.some((sv) => sv.scanner);
    const scanning = list.filter((sv) => sv.networks.length);
    const intro = el('div', { class: 'card sc-intro' }, el('div', { class: 'card__body' },
      el('span', { class: 'vs-start__icon' }, icon('radar')),
      el('div', {},
        el('h3', { class: 'vs-start__title' }, 'Scan every network zone from inside it'),
        el('p', { class: 'vs-start__text' }, 'A scan only sees the hosts and ports its server can reach. For a network behind a firewall, such as a plant floor or a lab, ' +
          'run a Signalith server inside it and let that server scan it. Results from every scanner land on the same Vulnerabilities page, in Findings and in the asset list.'),
        el('ol', { class: 'vs-steps' },
          el('li', {}, el('b', {}, 'Add a scanner inside the zone. '), el('a', { href: '#servers', onclick: (ev) => { ev.preventDefault(); addScanner(); } }, 'Add a server'),
            ' and pick Vulnerability scanner. A scanner joins these servers but never runs the background jobs.'),
          el('li', {}, el('b', {}, 'Install Nmap on it. '), 'Its card below says whether it has what scanning needs, and how to fix anything red.'),
          el('li', {}, el('b', {}, 'Pick it for the zone’s networks. '), 'On ', el('a', { href: '#vulns', 'data-page': 'vulns' }, 'Vulnerabilities'),
            ' > Networks, edit a network and choose the server under Scanned by.')))));
    const needs = el('div', { class: 'card sc-needs' }, el('div', { class: 'card__head' }, el('div', {},
      el('h3', { class: 'card__title' }, 'What each scanner needs'),
      el('p', { class: 'card__sub' }, 'Every server checks itself every few minutes. Expand a check below for why it matters and how to fix it.'))),
    el('div', { class: 'table-wrap' }, el('table', { class: 'table sc-needs__table' },
      el('thead', {}, el('tr', {}, el('th', {}, 'What'), el('th', {}, 'Why'), el('th', {}, 'Needed'))),
      el('tbody', {},
        needRow('Nmap 7.80 or later', 'Finds the hosts, open ports and software versions on a network.', 'Yes'),
        needRow('Network reach', 'The server must reach the networks it scans. Firewalls between them hide hosts and ports.', 'Yes'),
        needRow('Outbound HTTPS to services.nvd.nist.gov', 'Looks the software versions up in the National Vulnerability Database to name the CVEs.', 'No: scans still list hosts, ports and software'),
        needRow('An NVD API key', 'Makes the first CVE lookups about ten times faster. One key serves every server.', 'No'),
        needRow('OpenVAS (Greenbone Community Edition)', 'Deeper scans for the networks that turn it on: tests each host for thousands of known weaknesses. Set up on the server that scans them.', 'No')))));
    const cards = list.map((sv) => scannerCard(sv, dedicated));
    // Once a scanner has been added, the servers come before the how-to.
    $('sc-page').replaceChildren(...[dedicated ? null : intro,
      list.length < 2 ? el('div', { class: 'alert', 'data-tone': 'info' }, icon('info'), el('div', {},
        el('b', {}, 'This is your only server, so it scans every network.'),
        el('p', {}, 'To scan a network it cannot reach, ', el('a', { href: '#servers', 'data-page': 'servers' }, 'add a server'), ' inside that network’s zone.'))) : null,
      el('h3', { class: 'sc-heading' }, list.length === 1 ? 'Your server' : list.length + ' servers', el('span', { class: 'vs-muted' },
        scanning.length ? ' · ' + scanning.length + ' scanning' : ' · none scans a network yet')),
      el('div', { class: 'sc-list' }, ...cards),
      SC.logins ? loginsCard() : null,
      dedicated ? intro : null,
      needs].filter(Boolean));
  }

  // ---------- scan logins ----------
  // The SSH, Windows, ESXi and SNMP accounts OpenVAS signs in with. Their
  // keys and passwords are write-only: the server never sends them back.
  const LOGIN_TYPES = [['ssh-key', 'Linux or Unix, SSH key (recommended)'], ['ssh-password', 'Linux or Unix, SSH password'], ['smb', 'Windows account (SMB)'],
    ['esxi', 'VMware ESXi account'], ['snmp-v3', 'Network devices, SNMPv3 (recommended)'], ['snmp-community', 'Network devices, SNMPv1/v2c (not encrypted)']];
  // The kind a login type saves as, and back.
  const loginKind = (v) => v.startsWith('ssh-') ? 'ssh' : v.startsWith('snmp-') ? 'snmp' : v;
  const typeOf = (l) => l.kind === 'ssh' || l.kind === 'snmp' ? l.kind + '-' + l.auth : l.kind;
  let loginsReq = null;

  // loadLogins fetches the scan logins once per page view; fresh fetches
  // them again.
  function loadLogins(fresh) {
    if (fresh || !loginsReq) {
      loginsReq = api('api/vulns/logins').catch((e) => { loginsReq = null; throw e; });
    }
    return loginsReq;
  }

  function secretName(auth) {
    return { key: 'private key', v3: 'password', community: 'community' }[auth] || 'password';
  }

  function loginType(l) {
    return { smb: 'Windows', esxi: 'ESXi', 'snmp-v3': 'SNMPv3', 'snmp-community': 'SNMP community', 'ssh-key': 'SSH key' }[typeOf(l)] || 'SSH password';
  }

  function loginsCard() {
    const { logins, can_save: canSave } = SC.logins;
    const add = el('button', { class: 'btn btn--secondary btn--sm', type: 'button', onclick: () => editLogin(null) }, icon('plus'), 'Add a login');
    add.disabled = !canSave;
    const rows = logins.map((l) => el('li', { class: 'sc-login' },
      el('span', { class: 'sc-login__icon' }, icon({ smb: 'monitor', esxi: 'server', snmp: 'router' }[l.kind] || 'key-round')),
      el('div', { class: 'sc-login__main' },
        el('div', { class: 'sc-login__name' }, el('b', {}, l.name), el('span', { class: 'badge' }, loginType(l)),
          l.readable ? null : el('span', { class: 'badge badge--warning', title: 'This server cannot decrypt it' }, 'Enter again')),
        el('p', { class: 'vs-muted' }, l.username ? 'Signs in as ' : 'Signs in with a community', l.username ? el('span', { class: 'mono' }, l.username) : null, l.kind === 'ssh' && l.port !== 22 ? ' on port ' + l.port : '',
          ' · ', l.used_by.length ? 'Used by ' + l.used_by.join(', ') : 'No network uses it yet',
          ' · Changed ', ago(l.updated_at), l.updated_by ? ' by ' + l.updated_by : ''),
        l.readable ? null : el('p', { class: 'hint' }, icon('circle-alert'), 'This server cannot decrypt it, so scans skip OpenVAS for its networks. Edit it and enter the ' + secretName(l.auth) + (l.auth === 'v3' ? 's' : '') + ' again.')),
      el('button', { class: 'btn btn--ghost btn--sm', type: 'button', onclick: () => editLogin(l) }, icon('pencil'), 'Edit')));
    return el('section', { class: 'card sc-logins', 'aria-labelledby': 'sc-logins-title' },
      el('div', { class: 'card__head' }, el('div', {},
        el('h3', { class: 'card__title', id: 'sc-logins-title' }, 'Scan logins for OpenVAS'),
        el('p', { class: 'card__sub' }, 'Optional. With a login, OpenVAS signs in to each host and checks its installed patches and settings, which finds far more than a scan from outside. ' +
          'Keys and passwords are encrypted and never shown again. Pick a login for a network when you edit it on Vulnerabilities > Networks. ',
          el('a', { href: 'https://github.com/jrsamsanchez/signalith/blob/main/docs/vulnerabilities.md#credentialed-openvas-scans', target: '_blank', rel: 'noopener noreferrer' }, 'Which accounts to create', icon('external-link', 'icon--xs')))),
        add),
      el('div', { class: 'card__body' }, canSave ? null : el('div', { class: 'alert', 'data-tone': 'warning' }, icon('circle-alert'),
        el('div', {}, 'This server has no encryption key for scan logins, so none can be saved. Its master key could not be read; see the server log.')),
      logins.length ? el('ul', { class: 'sc-login-list', role: 'list' }, ...rows) : el('p', { class: 'vs-muted' }, 'No scan logins yet. Scans still work without them, from outside each host.')));
  }

  function editLogin(l) {
    const dlg = $('sc-login-dialog');
    const isNew = !l;
    const id = l ? l.id : 'l-' + newID().slice(2);
    const type = el('select', { class: 'select select--block', id: 'sc-login-type' }, ...LOGIN_TYPES.map(([v, label]) => el('option', { value: v }, label)));
    type.value = l ? typeOf(l) : 'ssh-key';
    // A login's kind is fixed once saved: networks name it for SSH, Windows, ESXi or SNMP.
    if (l) [...type.options].forEach((o) => { o.disabled = loginKind(o.value) !== l.kind; });
    const name = el('input', { class: 'input', id: 'sc-login-name', maxlength: '80', placeholder: 'Linux servers', autocomplete: 'off' });
    name.value = l ? l.name : '';
    const user = el('input', { class: 'input mono', id: 'sc-login-user', maxlength: '200', placeholder: 'signalith-scan', autocomplete: 'off', spellcheck: 'false' });
    user.value = l ? l.username : '';
    const port = el('input', { class: 'input num', id: 'sc-login-port', type: 'number', min: '1', max: '65535', inputmode: 'numeric' });
    port.value = l && l.port ? String(l.port) : '22';
    // Write-only: never filled in from the saved login.
    const keyBox = el('textarea', { class: 'textarea mono', id: 'sc-login-key', rows: '6', spellcheck: 'false', autocomplete: 'off', placeholder: '-----BEGIN OPENSSH PRIVATE KEY-----' });
    const pass = el('input', { class: 'input', id: 'sc-login-pass', type: 'password', maxlength: '256', autocomplete: 'new-password' });
    const phrase = el('input', { class: 'input', id: 'sc-login-phrase', type: 'password', maxlength: '256', autocomplete: 'new-password' });
    const privacy = el('input', { class: 'input', id: 'sc-login-privacy', type: 'password', maxlength: '256', autocomplete: 'new-password' });
    const clearPhrase = el('input', { type: 'checkbox' });
    const userHint = el('p', { class: 'hint' });
    // OpenVAS hands every host it scans what the login signs in with: a
    // password can be kept by a host that is not what it seems, a key
    // cannot.
    const passWarn = el('div', { class: 'alert', 'data-tone': 'warning' }, icon('triangle-alert'), el('div', {},
      el('b', {}, 'A key is safer. '), 'With a password, every host in the network receives it when OpenVAS signs in, so a host that is not what it seems can keep it. ' +
        'Use a key where you can, and an account that is a plain user on each host.'));
    const smbWarn = el('p', { class: 'hint' }, icon('info'), el('span', {}, 'Every Windows host scanned receives this account’s sign-in. Use an account made for scanning, for this zone only, ' +
      'and see the guide for the Windows settings that keep it safe.'));
    const esxiWarn = el('p', { class: 'hint' }, icon('info'), el('span', {}, 'Every ESXi host scanned receives this password. Make a local account with a read-only role on each host, ' +
      'not root; the guide says how.'));
    // SNMPv1/v2c sends the community in the clear, and it often grants
    // more than reading: offered only with a warning.
    const communityWarn = el('div', { class: 'alert', 'data-tone': 'warning' }, icon('triangle-alert'), el('div', {},
      el('b', {}, 'Use SNMPv3 where you can. '), 'A v1/v2c community crosses the network unencrypted to every device scanned, so anyone on the path can read it. ' +
        'Use only a read-only community made for scanning, never one that can write, and limit it to the scanning server’s address on the devices.'));
    const keyWrap = el('div', { class: 'field' }, el('label', { class: 'label', for: 'sc-login-key' }, 'Private key'), keyBox,
      el('p', { class: 'hint' }, l ? 'Leave empty to keep the saved key. ' : '', 'Paste the whole private key file. Signalith never shows it again.'));
    const phraseWrap = el('div', { class: 'field' }, el('label', { class: 'label', for: 'sc-login-phrase' }, 'Key passphrase'), phrase,
      el('p', { class: 'hint' }, l && l.has_passphrase ? 'Leave empty to keep the saved passphrase.' : 'Only if the key has one.'),
      l && l.has_passphrase ? el('label', { class: 'vs-allowed' }, clearPhrase, el('span', {}, 'The key no longer has a passphrase')) : null);
    const passLabel = el('label', { class: 'label', for: 'sc-login-pass' }, 'Password');
    const passHint = el('p', { class: 'hint' });
    const passWrap = el('div', { class: 'field' }, passLabel, pass, passHint);
    const privacyWrap = el('div', { class: 'field' }, el('label', { class: 'label', for: 'sc-login-privacy' }, 'Privacy password'), privacy,
      el('p', { class: 'hint' }, l && l.auth === 'v3' ? 'Leave empty to keep the saved one. ' : '',
        'Encrypts what the device sends (AES). At least 8 characters, and not the same as the authentication password.'));
    const portWrap = el('div', { class: 'field' }, el('label', { class: 'label', for: 'sc-login-port' }, 'SSH port'), port);
    const userWrap = el('div', { class: 'field' }, el('label', { class: 'label', for: 'sc-login-user' }, 'User name'), user, userHint);
    const sync = () => {
      const v = type.value;
      keyWrap.hidden = phraseWrap.hidden = v !== 'ssh-key';
      passWrap.hidden = v === 'ssh-key';
      portWrap.hidden = !v.startsWith('ssh-');
      passWarn.hidden = v !== 'ssh-password';
      smbWarn.hidden = v !== 'smb';
      esxiWarn.hidden = v !== 'esxi';
      communityWarn.hidden = v !== 'snmp-community';
      privacyWrap.hidden = v !== 'snmp-v3';
      userWrap.hidden = v === 'snmp-community';
      const keep = l && typeOf(l) === v ? 'Leave empty to keep the saved one. ' : '';
      passLabel.textContent = { 'snmp-v3': 'Authentication password', 'snmp-community': 'Community' }[v] || 'Password';
      passHint.textContent = keep + (v === 'snmp-v3' ? 'Signs in with SHA. At least 8 characters. ' : v === 'snmp-community' ? 'A long random read-only community, at least 8 characters. ' : '') +
        'Signalith never shows it again.';
      name.placeholder = { smb: 'Windows servers', esxi: 'ESXi hosts', 'snmp-v3': 'Plant switches', 'snmp-community': 'Old printers' }[v] || 'Linux servers';
      user.placeholder = v === 'smb' ? 'CORP\\svc-signalith-scan' : 'signalith-scan';
      userHint.textContent = v === 'smb' ? 'A domain account as DOMAIN\\name, or a local account by name alone.'
        : v === 'snmp-v3' ? 'The SNMPv3 user set up on the devices.' : 'The account it signs in to each host as.';
    };
    type.addEventListener('change', sync);
    sync();
    const err = el('p', { class: 'field-error hidden', role: 'alert' });
    const save = el('button', { class: 'btn btn--primary', type: 'submit' }, isNew ? 'Add login' : 'Save');
    dlg.replaceChildren(el('form', { method: 'dialog', novalidate: '' },
      el('div', { class: 'modal__head' }, el('div', {},
        el('h3', { class: 'modal__title', id: 'sc-login-title' }, isNew ? 'Add a scan login' : 'Edit ' + l.name),
        el('p', { class: 'modal__desc' }, 'Use an account made only for scanning, with the least access it needs. Saved encrypted; only admins can change it.')),
      el('button', { class: 'btn btn--ghost btn--icon btn--sm modal__close', type: 'button', 'aria-label': 'Close', onclick: () => dlg.close() }, icon('x'))),
      el('div', { class: 'modal__body vs-form' },
        el('div', { class: 'field' }, el('label', { class: 'label', for: 'sc-login-type' }, 'Hosts it signs in to'), type), passWarn, smbWarn, esxiWarn, communityWarn,
        el('div', { class: 'field' }, el('label', { class: 'label', for: 'sc-login-name' }, 'Name'), name),
        userWrap,
        portWrap, keyWrap, phraseWrap, passWrap, privacyWrap, err),
      el('div', { class: 'modal__foot' },
        isNew ? null : el('button', { class: 'btn btn--ghost vs-danger', type: 'button', onclick: () => confirmDeleteLogin(l) }, icon('trash-2'), 'Remove'),
        el('span', { class: 'spacer' }),
        el('button', { class: 'btn btn--ghost', type: 'button', onclick: () => dlg.close() }, 'Cancel'), save)));
    dlg.querySelector('form').addEventListener('submit', async (ev) => {
      ev.preventDefault();
      const fail = (msg, field) => {
        err.replaceChildren(icon('circle-alert'), msg);
        err.classList.remove('hidden');
        if (field) field.focus();
      };
      const v = type.value;
      if (!name.value.trim()) return fail('Give the login a name, such as Linux servers.', name);
      if (v !== 'snmp-community' && !user.value.trim()) return fail('Enter the user name it signs in as.', user);
      const kind = loginKind(v);
      const body = { name: name.value.trim(), kind, username: v === 'snmp-community' ? '' : user.value.trim(),
        auth: kind === 'ssh' || kind === 'snmp' ? v.slice(kind.length + 1) : 'password' };
      if (kind === 'ssh') body.port = +port.value || 22;
      if (v === 'ssh-key') {
        body.secret = keyBox.value.trim() ? keyBox.value.trim() + '\n' : '';
        body.passphrase = phrase.value;
        body.clear_passphrase = clearPhrase.checked;
      } else {
        body.secret = pass.value;
        if (v === 'snmp-v3') body.privacy = privacy.value;
      }
      const changed = !l || typeOf(l) !== v;
      if (changed && !body.secret) return fail(v === 'ssh-key' ? 'Paste the private key.' : v === 'snmp-community' ? 'Enter the community.' : 'Enter the password.', v === 'ssh-key' ? keyBox : pass);
      if (changed && v === 'snmp-v3' && !body.privacy) return fail('Enter the privacy password.', privacy);
      save.disabled = true;
      try {
        await api('api/vulns/logins/' + encodeURIComponent(id), body, 'PUT');
        // Clear the secrets from the page as soon as they are saved.
        keyBox.value = pass.value = phrase.value = privacy.value = '';
        dlg.close();
        toast(isNew ? body.name + ' was added. Pick it for a network on Vulnerabilities > Networks.' : 'Used from the next scan.', null, { title: isNew ? 'Login added' : 'Saved' });
        SC.logins = await loadLogins(true);
        renderScanners();
      } catch (e) {
        save.disabled = false;
        fail(e.message);
      }
    });
    dlg.addEventListener('close', () => { keyBox.value = pass.value = phrase.value = privacy.value = ''; }, { once: true });
    dlg.showModal();
    (isNew ? name : user).focus();
  }

  function confirmDeleteLogin(l) {
    const dlg = $('sc-login-confirm');
    dlg.replaceChildren(el('form', { method: 'dialog' },
      el('div', { class: 'modal__head' }, el('div', {},
        el('h3', { class: 'modal__title', id: 'sc-login-confirm-title' }, 'Remove ' + l.name + '?'),
        el('p', { class: 'modal__desc', id: 'sc-login-confirm-desc' }, l.used_by.length
          ? 'First pick another login, or None, for ' + l.used_by.join(', ') + ' on Vulnerabilities > Networks.'
          : 'Its key or password is deleted from Signalith. Remember to remove the account from your hosts too.'))),
      el('div', { class: 'modal__foot' },
        el('button', { class: 'btn btn--ghost', type: 'button', onclick: () => dlg.close() }, 'Cancel'),
        l.used_by.length ? null : el('button', { class: 'btn btn--danger', type: 'submit', onclick: async (ev) => {
          ev.preventDefault();
          try {
            await api('api/vulns/logins/' + encodeURIComponent(l.id), undefined, 'DELETE');
            dlg.close();
            $('sc-login-dialog').close();
            toast(l.name + ' was removed.');
            SC.logins = await loadLogins(true);
            renderScanners();
          } catch (e) {
            toast(e.message, null, { tone: 'danger', title: 'Couldn’t remove the login' });
          }
        } }, icon('trash-2'), 'Remove'))));
    dlg.showModal();
  }

  function needRow(what, why, needed) {
    return el('tr', {}, el('td', { 'data-label': 'What' }, el('b', {}, what)), el('td', { 'data-label': 'Why', class: 'vs-muted' }, why),
      el('td', { 'data-label': 'Needed' }, needed === 'Yes' ? el('span', { class: 'badge badge--accent' }, 'Required') : el('span', { class: 'vs-muted' }, needed)));
  }

  // dedicated: a scanner server exists, so a server that scans no network
  // is not needed and its missing setup is not an error.
  function scannerCard(sv, dedicated) {
    const idle = dedicated && !sv.networks.length && sv.online && sv.state !== 'removed' && sv.ready === false;
    const st = idle ? { label: 'Not needed', tone: '' } : scannerState(sv);
    const rep = sv.report;
    const badges = [
      sv.scanner ? el('span', { class: 'badge badge--accent', title: 'Added as a scanner: it never runs the background jobs' }, 'Scanner') : null,
      sv.self ? el('span', { class: 'badge' }, 'This server') : null,
      sv.runs_jobs ? el('span', { class: 'badge', title: 'Scans the networks that name no scanner' }, 'Runs the background jobs') : null,
    ];
    const nets = sv.networks.length
      ? el('p', { class: 'sc-card__nets' }, icon('network'), el('span', {}, 'Scans ', ...sv.networks.flatMap((n, i) => [i ? ', ' : '', el('b', {}, n.name), n.enabled ? '' : ' (paused)'])))
      : el('p', { class: 'sc-card__nets vs-muted' }, icon('network'), el('span', {}, sv.runs_jobs ? 'Scans the networks that name no scanner; none do now.' : 'Scans no network yet.'));
    let sub;
    if (sv.state === 'removed') sub = 'This server was removed, but networks still name it. Edit them and pick another scanner.';
    else if (!sv.online) sub = 'Not running (' + sv.state + ').' + (sv.checked_at ? ' Last checked ' + ago(sv.checked_at) + '.' : '') + ' Its networks are not scanned until it is back.';
    else if (!rep) sub = 'Has not checked itself yet. A server checks itself a few seconds after it starts; one running an older version of Signalith does not.';
    else if (idle) sub = 'Not needed: no network uses this server. Its checks below matter only if you pick it to scan a network. Checked ' + ago(rep.at) + '.';
    else sub = 'Checked ' + ago(rep.at) + '.';
    const again = sv.self && sv.online ? el('button', { class: 'btn btn--secondary btn--sm', type: 'button' }, icon('refresh-cw'), 'Check again') : null;
    if (again) {
      again.addEventListener('click', async () => {
        again.disabled = true;
        again.replaceChildren(icon('refresh-cw'), 'Checking…');
        await loadScanners(true);
      });
    }
    const checks = rep && sv.state !== 'removed' ? rep.checks.filter((c) => c.id !== 'networks') : [];
    return el('article', { class: 'card sc-card', 'data-state': st.tone || 'none' }, el('div', { class: 'card__body' },
      el('div', { class: 'sc-card__head' },
        el('span', { class: 'sc-card__icon' }, icon(sv.scanner ? 'radar' : 'server')),
        el('div', { class: 'sc-card__title' },
          el('div', { class: 'sc-card__name' }, el('h3', {}, sv.name), ...badges.filter(Boolean)),
          el('p', { class: 'vs-muted' }, sub)),
        el('span', { class: 'badge' + (st.tone ? ' badge--' + st.tone : '') + ' sc-card__state' }, st.label),
        again),
      nets,
      checks.length ? el('ul', { class: 'vs-checks', role: 'list' }, ...checks.map((c) => checkRow(c, renderScanners, true, idle))) : null));
  }
})();
