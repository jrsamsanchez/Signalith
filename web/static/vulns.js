// Vulnerabilities page (analysts and admins): what the network scans
// found. Hosts lists every host up on a scanned network, worst first, and
// opens one for its open ports and the CVEs in the software on them;
// Networks lists what is scanned and when, with Scan now; Scans is the
// history. Setup (admins) checks the scanning server: Nmap, CVE lookups,
// and what each one is for.
'use strict';

(function () {
  const SEV = ['critical', 'high', 'medium', 'low'];
  const DAYS = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];
  const PORTS = [['top100', 'The 100 most common ports'], ['top1000', 'The 1,000 most common ports (recommended)'], ['all', 'All 65,535 ports (slow)'], ['custom', 'Only these ports…']];
  const STATE = { queued: 'Waiting to start', running: 'Scanning', done: 'Finished', failed: 'Failed', stopped: 'Stopped', interrupted: 'Cut off' };
  const STATE_TONE = { done: 'success', failed: 'danger', interrupted: 'warning', stopped: '', queued: 'accent', running: 'accent' };
  const S = { tab: 'hosts', data: null, setup: null, find: '', network: '', vulnOnly: false, poll: null, loading: false };

  pageHooks.push((name) => {
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
    if (!d.targets.length) {
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
      box.replaceChildren(el('div', { class: 'card__body' }, head,
        el('ul', { class: 'vs-checks', role: 'list' }, ...rep.checks.map((c) => checkRow(c, draw)))));
    };
    draw();
    return box;
  }

  function checkRow(c, redraw) {
    const open = c.state === 'fail' || c.state === 'warn';
    const extra = [];
    if (c.id === 'cve' && S.data) extra.push(lookupSwitch(redraw));
    return el('li', { class: 'vs-check', 'data-state': c.state },
      el('details', open ? { open: '' } : {},
        el('summary', {},
          el('span', { class: 'vs-check__icon' }, icon(CHECK_ICON[c.state] || 'info')),
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
      el('div', { class: 'modal__body vs-setup__body' }, setupCard(false)),
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
    if (d.scanner && !d.scanner.ready && can('admin')) {
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
        el('td', { 'data-label': 'Open ports', class: 'mono vs-c-ports' }, portsText(h.ports)),
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
    for (const s of SEV) if (c[s]) parts.push(el('span', { class: 'vs-count', 'data-sev': s, title: c[s] + ' ' + s }, el('span', { class: 'vs-dot' }), c[s]));
    return parts.length ? el('span', { class: 'vs-counts' }, ...parts) : el('span', { class: 'vs-muted' }, '—');
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
          ...fact('CVEs', total ? cveCounts(h.counts) : 'None found')),
        el('div', { class: 'vs-host__links' },
          el('a', { href: '#search', onclick: (ev) => { ev.preventDefault(); dlg.close(); openSearch('datamodel=Vulnerabilities dest_ip=' + h.address, '-30d'); } }, icon('search'), 'Scan history in Search')),
        h.services.length ? el('div', { class: 'vs-services' }, ...h.services.map(serviceBlock)) : el('p', { class: 'vs-muted' }, 'The host answered, but none of the scanned ports was open.')),
      el('div', { class: 'modal__foot' }, el('button', { class: 'btn btn--secondary', type: 'button', onclick: () => dlg.close() }, 'Close')));
  }

  function modalHead(title, sub, id) {
    return el('div', { class: 'modal__head' },
      el('div', {}, el('h3', { class: 'modal__title', id }, title), sub ? el('p', { class: 'modal__desc' }, sub) : null),
      el('button', { class: 'btn btn--ghost btn--icon btn--sm modal__close', type: 'button', 'aria-label': 'Close', onclick: (ev) => ev.target.closest('dialog').close() }, icon('x')));
  }

  function serviceBlock(s) {
    const what = [s.product, s.version].filter(Boolean).join(' ') || s.name || 'Unknown service';
    const vulns = s.vulns || [];
    return el('section', { class: 'vs-svc' },
      el('div', { class: 'vs-svc__head' },
        el('span', { class: 'vs-port mono' }, s.port + '/' + s.transport),
        el('div', { class: 'vs-svc__what' }, el('b', {}, what),
          el('span', { class: 'vs-muted' }, [s.name, s.tunnel === 'ssl' ? 'over TLS' : '', s.extra].filter(Boolean).join(' · '))),
        vulns.length ? el('span', { class: 'badge badge--danger' }, vulns.length + (vulns.length === 1 ? ' CVE' : ' CVEs')) : el('span', { class: 'badge badge--success' }, 'No known CVEs')),
      vulns.length ? el('ul', { class: 'vs-vulns', role: 'list' }, ...vulns.slice(0, 200).map(vulnRow)) : null,
      vulns.length > 200 ? el('p', { class: 'hint' }, 'And ' + (vulns.length - 200) + ' more. Search shows them all.') : null);
  }

  function vulnRow(v) {
    return el('li', { class: 'vs-vuln' },
      el('details', {},
        el('summary', {},
          el('span', { class: 'sev', 'data-sev': SEV.includes(v.severity) ? v.severity : 'low' }, cap(v.severity)),
          el('span', { class: 'vs-score num', title: 'CVSS ' + (v.cvss_version || '') + ' base score' }, v.cvss ? v.cvss.toFixed(1) : '–'),
          el('span', { class: 'vs-vuln__id mono' }, v.cve),
          v.kev ? el('span', { class: 'badge vs-kev', title: 'Added to CISA’s Known Exploited Vulnerabilities catalog on ' + v.kev_added }, icon('flag'), 'Exploited') : null,
          el('span', { class: 'vs-vuln__desc' }, v.description || ''),
          icon('chevron-down', 'icon--sm chev')),
        el('div', { class: 'vs-vuln__more' },
          v.description ? el('p', {}, v.description) : null,
          el('p', { class: 'vs-muted' }, [v.published ? 'Published ' + v.published : '', v.kev ? 'Known exploited since ' + v.kev_added : '', 'Matched ' + v.cpe].filter(Boolean).join(' · ')),
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
    panels.networks.replaceChildren(el('div', { class: 'vs-nets' }, ...d.targets.map(networkCard)),
      el('p', { class: 'hint' }, icon('clock'), 'Times are in the scanning server’s time zone.'));
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
        el('span', {}, a.state === 'running' ? 'Scanning' + (pct !== null ? ', ' + pct + '%' : '…') + (p.hosts_up ? ' · ' + p.hosts_up + ' up so far' : '') : 'Waiting to start'),
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
    const lastProblem = !a && last && (last.error || last.cve_error);
    return el('article', { class: 'card vs-net' }, el('div', { class: 'card__body' },
      el('div', { class: 'vs-net__head' },
        el('div', { class: 'vs-net__title' }, el('h3', {}, n.name),
          n.enabled ? null : el('span', { class: 'badge' }, 'Paused'),
          n.gentle ? el('span', { class: 'badge badge--accent', title: 'Scans slowly with fewer probes' }, 'Gentle') : null),
        el('div', { class: 'vs-net__actions' }, ...actions)),
      el('p', { class: 'vs-net__addrs mono' }, n.networks.join(', ') + (n.exclude && n.exclude.length ? '  (skipping ' + n.exclude.join(', ') + ')' : '')),
      el('dl', { class: 'vs-net__facts' },
        el('dt', {}, 'When'), el('dd', {}, n.enabled ? scheduleText(n) : 'Paused: no scheduled scans'),
        n.enabled && n.next_run ? el('dt', {}, 'Next') : null, n.enabled && n.next_run ? el('dd', {}, new Date(n.next_run).toLocaleString([], { weekday: 'short', hour: '2-digit', minute: '2-digit', month: 'short', day: 'numeric' })) : null,
        el('dt', {}, 'Ports'), el('dd', {}, portsLabel(n.ports)),
        el('dt', {}, 'Found'), el('dd', {}, n.hosts ? el('span', { class: 'vs-found' }, n.hosts + (n.hosts === 1 ? ' host' : ' hosts') + ', ', cveCounts(n.counts)) : '—')),
      status,
      lastProblem ? el('p', { class: last.error ? 'field-error' : 'hint' }, icon(last.error ? 'circle-alert' : 'info'), last.error || 'CVE lookups: ' + last.cve_error) : null));
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

  function editNetwork(n) {
    const dlg = $('vs-net-dialog');
    const isNew = !n;
    const t = n || { id: newID(), name: '', networks: [], exclude: [], ports: 'top1000', gentle: false, enabled: true, schedule: { every: 'daily', hour: 1, weekday: 0 } };
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
    const gentle = el('input', { type: 'checkbox' });
    gentle.checked = t.gentle;
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
        el('div', { class: 'field' }, el('label', { class: 'label', for: 'vs-every' }, 'When'), el('div', { class: 'vs-when' }, every, day, hour),
          el('p', { class: 'hint' }, 'In the scanning server’s time zone. Pick a quiet hour: scans add some network traffic.')),
        el('label', { class: 'switch vs-switch' }, gentle, el('span', {}, el('b', {}, 'Gentle mode'),
          el('span', { class: 'vs-muted' }, 'Scans slowly, one probe at a time, for networks with fragile devices such as old printers or building controllers. Takes several times longer.'))),
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
        ports: ports.value === 'custom' ? custom.value.replace(/\s+/g, '') : ports.value, gentle: gentle.checked, enabled: isNew ? true : enabled.checked,
        schedule: { every: every.value, hour: +hour.value, weekday: +day.value },
      };
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
      el('thead', {}, el('tr', {}, el('th', {}, 'Network'), el('th', {}, 'Result'), el('th', {}, 'Started'), el('th', {}, 'Took'), el('th', {}, 'Found'), el('th', {}, 'Started by'))),
      el('tbody', {}, ...scans.map((sc) => el('tr', {},
        el('td', { 'data-label': 'Network' }, sc.target_name),
        el('td', { 'data-label': 'Result' }, el('span', { class: 'badge' + (STATE_TONE[sc.state] ? ' badge--' + STATE_TONE[sc.state] : '') }, STATE[sc.state] || sc.state),
          sc.error ? el('div', { class: 'vs-scan-err' }, sc.error) : null,
          sc.cve_error ? el('div', { class: 'vs-muted vs-scan-err' }, 'CVE lookups: ' + sc.cve_error) : null),
        el('td', { 'data-label': 'Started', class: 'vs-muted' }, sc.started_at ? new Date(sc.started_at).toLocaleString() : 'Not yet'),
        el('td', { 'data-label': 'Took', class: 'num' }, duration(sc)),
        el('td', { 'data-label': 'Found' }, sc.state === 'done' ? el('span', { class: 'vs-found' }, sc.counts.hosts + (sc.counts.hosts === 1 ? ' host ' : ' hosts '), cveCounts(sc.counts)) : '—'),
        el('td', { 'data-label': 'Started by', class: 'vs-muted' }, sc.trigger === 'schedule' ? 'Schedule' : sc.requested_by || 'Scan now'))))))));
  }
})();
