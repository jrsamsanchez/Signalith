// Endpoints page (analysts and admins): hosts running osquery that report
// to Signalith. Hosts lists them and opens one for its facts and check
// results; Configuration checks shows each check across the hosts; Live
// query (admins) runs SQL on hosts now. "What hosts collect" (admins) sets
// the watched file paths and how often inventory and checks run.
'use strict';

(function () {
  const PLATFORM = { windows: 'Windows', linux: 'Linux', darwin: 'macOS' };
  const PLATFORM_ICON = { windows: 'monitor', linux: 'square-terminal', darwin: 'laptop' };
  const RESULT = { pass: 'Pass', fail: 'Fail', 'n/a': 'Not applicable', error: 'Error', pending: 'Not reported yet' };
  const RESULT_TONE = { pass: 'success', fail: 'danger', error: 'warning' };
  const EXAMPLES = [
    ['Installed software', "SELECT name, version FROM programs\nUNION ALL SELECT name, version FROM deb_packages\nUNION ALL SELECT name, version FROM rpm_packages\nUNION ALL SELECT name, bundle_short_version FROM apps;"],
    ['Listening ports', 'SELECT DISTINCT p.name, lp.port, lp.address FROM listening_ports lp JOIN processes p USING (pid) WHERE lp.port != 0;'],
    ['Logged-in users', 'SELECT user, host, time, tty FROM logged_in_users;'],
    ['Running processes', 'SELECT pid, name, path, cmdline FROM processes ORDER BY start_time DESC LIMIT 50;'],
    ['Find a file', "SELECT path, size, datetime(mtime, 'unixepoch') AS modified FROM file WHERE path LIKE '/tmp/%%';"],
  ];
  const S = { tab: 'hosts', hosts: null, checks: null, platform: '', find: '', checkPlatform: '', checkFail: true, query: null, poll: null, loading: false };

  pageHooks.push((name) => {
    if (name !== 'endpoints') {
      stopPoll();
      return;
    }
    showTab(S.tab);
  });

  const tabs = { hosts: $('ep-tab-hosts'), checks: $('ep-tab-checks'), query: $('ep-tab-query') };
  const panels = { hosts: $('ep-panel-hosts'), checks: $('ep-panel-checks'), query: $('ep-panel-query') };
  Object.entries(tabs).forEach(([k, t]) => t.addEventListener('click', () => showTab(k)));
  document.querySelector('.ep-tabs').addEventListener('keydown', (ev) => {
    if (ev.key !== 'ArrowRight' && ev.key !== 'ArrowLeft') return;
    const keys = Object.keys(tabs).filter((k) => getComputedStyle(tabs[k]).display !== 'none');
    const i = keys.indexOf(S.tab) + (ev.key === 'ArrowRight' ? 1 : -1);
    const next = keys[(i + keys.length) % keys.length];
    showTab(next);
    tabs[next].focus();
  });
  $('ep-add').addEventListener('click', () => openOsquerySetup());
  $('ep-settings').addEventListener('click', openSettings);

  function showTab(name) {
    if (name === 'query' && !can('admin')) name = 'hosts';
    S.tab = name;
    for (const [k, t] of Object.entries(tabs)) {
      t.setAttribute('aria-selected', String(k === name));
      t.tabIndex = k === name ? 0 : -1;
      panels[k].hidden = k !== name;
    }
    if (name !== 'query') stopPoll();
    if (name === 'hosts') loadHosts();
    if (name === 'checks') loadChecks();
    if (name === 'query') renderQuery();
  }

  // openOsquerySetup opens Add data on the osquery option.
  function openOsquerySetup() {
    const r = document.querySelector('input[name=os][value=osquery]');
    showPage('data');
    if (r && !r.checked) {
      r.checked = true;
      r.dispatchEvent(new Event('change'));
    }
  }

  // ---------- hosts ----------
  async function loadHosts() {
    if (!S.hosts) panels.hosts.replaceChildren(skeleton());
    try {
      S.hosts = await api('api/endpoints');
      renderHosts();
    } catch (e) {
      if (!S.hosts) panels.hosts.replaceChildren(failed(e, loadHosts));
    }
    // the failing count on the checks tab
    if (!S.checks) api('api/endpoints/checks').then((c) => { S.checks = c; countFails(); }).catch(() => {});
  }

  function skeleton() {
    const bar = (w) => el('span', { class: 'skeleton', style: 'width:' + w });
    return el('div', { class: 'card ep-skel' }, ...['40%', '62%', '50%', '56%'].map((w) => el('div', { class: 'ep-skel__row' }, bar(w))));
  }

  function failed(e, retry) {
    return el('div', { class: 'card' }, el('div', { class: 'empty', 'data-tone': 'danger', role: 'alert' },
      el('span', { class: 'empty__icon' }, icon('circle-alert')),
      el('div', { class: 'empty__title' }, 'Couldn’t load the endpoints'),
      el('p', { class: 'empty__text' }, e.message || 'The Signalith server did not respond.'),
      el('div', { class: 'empty__actions' }, el('button', { class: 'btn btn--secondary btn--sm', type: 'button', onclick: retry }, icon('refresh-cw'), 'Try again'))));
  }

  function emptyHosts() {
    return el('div', { class: 'card' }, el('div', { class: 'empty' },
      el('span', { class: 'empty__icon' }, icon('laptop')),
      el('div', { class: 'empty__title' }, 'No endpoints yet'),
      el('p', { class: 'empty__text' }, 'Install osquery on a Windows, Linux or Mac host and run the setup script from Add data. The host shows up here within a minute.'),
      can('admin') ? el('div', { class: 'empty__actions' }, el('button', { class: 'btn btn--primary btn--sm', type: 'button', onclick: openOsquerySetup }, icon('plus'), 'Add endpoints')) : null));
  }

  function seg(options, value, onPick, label) {
    const g = el('div', { class: 'seg seg--sm', role: 'group', 'aria-label': label });
    for (const [v, text] of options) {
      g.append(el('button', { type: 'button', 'aria-pressed': String(v === value), onclick: () => onPick(v) }, text));
    }
    return g;
  }

  function renderHosts() {
    const d = S.hosts;
    const count = $('ep-count');
    count.textContent = d.summary.total;
    count.classList.toggle('hidden', !d.summary.total);
    if (!d.endpoints.length) {
      panels.hosts.replaceChildren(emptyHosts());
      return;
    }
    const sum = d.summary;
    const findEl = el('input', { class: 'input', type: 'search', placeholder: 'Find a host', 'aria-label': 'Find a host', autocomplete: 'off', spellcheck: 'false' });
    findEl.value = S.find;
    const listEl = el('div', { class: 'card ep-hosts' });
    findEl.addEventListener('input', () => { S.find = findEl.value; drawList(listEl); });
    const plats = [['', 'All']].concat(['windows', 'linux', 'darwin'].filter((p) => sum[p]).map((p) => [p, PLATFORM[p] + ' ' + sum[p]]));
    const offline = sum.total - sum.online;
    panels.hosts.replaceChildren(
      el('div', { class: 'ep-summary' },
        el('span', { class: 'ep-stat' }, el('b', {}, sum.total.toLocaleString()), sum.total === 1 ? ' host' : ' hosts'),
        el('span', { class: 'ep-stat' }, el('span', { class: 'pulse' }), el('b', {}, sum.online.toLocaleString()), ' online'),
        offline ? el('span', { class: 'ep-stat' }, el('span', { class: 'pulse', 'data-state': 'idle' }), el('b', {}, offline.toLocaleString()), ' offline') : null),
      el('div', { class: 'toolbar ep-toolbar', role: 'search' },
        el('div', { class: 'input-wrap' }, icon('search'), findEl),
        plats.length > 2 ? seg(plats, S.platform, (v) => { S.platform = v; renderHosts(); }, 'Platform') : null),
      listEl);
    drawList(listEl);
  }

  function drawList(listEl) {
    const q = S.find.trim().toLowerCase();
    const rows = S.hosts.endpoints.filter((h) => (!S.platform || h.platform === S.platform) &&
      (!q || [h.hostname, h.os_name, h.address, ...(h.ips || [])].some((v) => v && v.toLowerCase().includes(q))));
    if (!rows.length) {
      listEl.replaceChildren(el('div', { class: 'empty empty--compact' }, el('div', { class: 'empty__title' }, 'No host matches')));
      return;
    }
    const fails = failsByHost();
    const tbody = el('tbody', {}, ...rows.map((h) => {
      const tr = el('tr', { tabindex: '0', class: 'ep-row', 'aria-label': 'Open ' + h.hostname },
        el('td', { 'data-label': 'Host' }, el('div', { class: 'ep-host-cell' },
          el('span', { class: 'ep-plat', title: PLATFORM[h.platform] || h.platform }, icon(PLATFORM_ICON[h.platform] || 'monitor')),
          el('div', {}, el('div', { class: 'ep-name' }, h.hostname), el('div', { class: 'ep-sub' }, [h.os_name, h.os_version].filter(Boolean).join(' '))))),
        el('td', { 'data-label': 'Status' }, el('span', { class: 'ep-online' }, el('span', { class: 'pulse', 'data-state': h.online ? '' : 'idle' }),
          h.online ? 'Online' : 'Last seen ' + ago(h.last_seen))),
        el('td', { 'data-label': 'Checks', class: 'ep-c-checks' }, fails.has(h.id)
          ? el('span', { class: 'badge badge--danger' }, fails.get(h.id) + ' failing')
          : el('span', { class: 'ep-muted' }, '—')),
        el('td', { 'data-label': 'Address', class: 'mono ep-c-addr' }, (h.ips && h.ips[0]) || h.address || ''),
        el('td', { 'data-label': 'osquery', class: 'ep-c-ver ep-muted' }, h.osquery_version || ''));
      tr.addEventListener('click', () => openHost(h.id));
      tr.addEventListener('keydown', (ev) => { if (ev.key === 'Enter') openHost(h.id); });
      return tr;
    }));
    listEl.replaceChildren(el('div', { class: 'table-wrap' }, el('table', { class: 'table ep-table' },
      el('thead', {}, el('tr', {}, el('th', {}, 'Host'), el('th', {}, 'Status'), el('th', { class: 'ep-c-checks' }, 'Checks'),
        el('th', { class: 'ep-c-addr' }, 'Address'), el('th', { class: 'ep-c-ver' }, 'osquery'))),
      tbody)));
  }

  function failsByHost() {
    const m = new Map();
    if (!S.checks) return m;
    for (const c of S.checks.checks) for (const f of c.failing) m.set(f.id, (m.get(f.id) || 0) + 1);
    return m;
  }

  function countFails() {
    const n = S.checks ? S.checks.totals.fail : 0;
    const c = $('ep-fail-count');
    c.textContent = n;
    c.classList.toggle('hidden', !n);
    if (S.tab === 'hosts' && S.hosts && S.hosts.endpoints.length) {
      const list = panels.hosts.querySelector('.ep-hosts');
      if (list) drawList(list);
    }
  }

  // ---------- one host ----------
  async function openHost(id) {
    const dlg = $('ep-host');
    dlg.replaceChildren(el('div', { class: 'modal__body' }, skeleton()));
    if (!dlg.open) dlg.showModal();
    let d;
    try {
      d = await api('api/endpoints/' + encodeURIComponent(id));
    } catch (e) {
      dlg.replaceChildren(head('Host', ''), el('div', { class: 'modal__body' }, el('p', { class: 'field-error' }, icon('circle-alert'), e.message)));
      return;
    }
    const h = d.endpoint;
    const fact = (k, v) => (v ? [el('dt', {}, k), el('dd', {}, v)] : []);
    const mem = h.memory_bytes ? Math.round(h.memory_bytes / 1073741824) + ' GB memory' : '';
    const order = { fail: 0, error: 1, pending: 2, pass: 3, 'n/a': 4 };
    const checks = (d.checks || []).slice().sort((a, b) => order[a.result] - order[b.result] || a.check.title.localeCompare(b.check.title));
    const failing = checks.filter((c) => c.result === 'fail').length;
    dlg.replaceChildren(
      head(h.hostname, [PLATFORM[h.platform], h.os_name, h.os_version].filter(Boolean).join(' · ')),
      el('div', { class: 'modal__body ep-host__body' },
        el('dl', { class: 'ep-facts' },
          ...fact('Status', h.online ? 'Online' : 'Offline, last seen ' + ago(h.last_seen)),
          ...fact('Addresses', (h.ips && h.ips.length ? h.ips : [h.address]).join(', ')),
          ...fact('Hardware', [h.hardware_vendor, h.hardware_model].filter(Boolean).join(' ')),
          ...fact('Processor', [h.cpu, mem].filter(Boolean).join(', ')),
          ...fact('Serial', h.serial),
          ...fact('osquery', h.osquery_version),
          ...fact('Enrolled', new Date(h.enrolled_at).toLocaleString()),
          ...fact('Configuration', h.config_at ? 'Fetched ' + ago(h.config_at) : 'Not fetched yet'),
          ...fact('Last osquery error', h.last_error ? h.last_error + ' (' + ago(h.last_error_at) + ')' : '')),
        el('div', { class: 'ep-host__links' },
          el('a', { href: '#search', onclick: (ev) => { ev.preventDefault(); dlg.close(); searchHost(h.hostname, 'Filesystem'); } }, icon('folder'), 'File changes'),
          el('a', { href: '#search', onclick: (ev) => { ev.preventDefault(); dlg.close(); searchHost(h.hostname, 'Inventory'); } }, icon('list'), 'Inventory changes'),
          can('admin') ? el('a', { href: '#', onclick: (ev) => { ev.preventDefault(); dlg.close(); S.query = { targets: [h.id], label: h.hostname }; showTab('query'); } }, icon('terminal'), 'Live query') : null),
        el('h4', { class: 'ep-h4' }, 'Configuration checks', failing ? el('span', { class: 'badge badge--danger' }, failing + ' failing') : null),
        checks.length ? el('ul', { class: 'ep-checks', role: 'list' }, ...checks.map(checkItem)) : el('p', { class: 'ep-muted' }, 'No checks for this platform.')),
      el('div', { class: 'modal__foot' },
        can('admin') ? el('button', { class: 'btn btn--ghost ep-danger', type: 'button', onclick: () => confirmRemove(h) }, icon('trash-2'), 'Remove') : null,
        el('span', { class: 'spacer' }),
        el('button', { class: 'btn btn--secondary', type: 'button', onclick: () => dlg.close() }, 'Close')));
  }

  function head(title, sub) {
    return el('div', { class: 'modal__head' },
      el('div', {}, el('h3', { class: 'modal__title', id: 'ep-host-title' }, title), sub ? el('p', { class: 'modal__desc' }, sub) : null),
      el('button', { class: 'btn btn--ghost btn--icon btn--sm modal__close', type: 'button', 'aria-label': 'Close', onclick: (ev) => ev.target.closest('dialog').close() }, icon('x')));
  }

  function checkItem(c) {
    const r = c.result;
    return el('li', { class: 'ep-check' },
      el('details', {},
        el('summary', {}, el('span', { class: 'ep-result', 'data-result': r }, RESULT[r] || r), el('span', { class: 'ep-check__title' }, c.check.title),
          el('span', { class: 'sev', 'data-sev': c.check.severity }, cap(c.check.severity)), icon('chevron-down', 'icon--sm chev')),
        el('div', { class: 'ep-check__more' },
          c.detail ? el('p', { class: 'ep-check__detail' }, c.detail) : null,
          el('p', {}, c.check.description),
          el('p', {}, el('b', {}, 'How to fix: '), c.check.remediation),
          refsLine(c.check))));
  }

  function refsLine(c) {
    const parts = [];
    if (c.rule_id) parts.push('SCAP Security Guide rule ' + c.rule_id);
    if (c.references && c.references.length) parts.push('NIST SP 800-53 ' + c.references.join(', '));
    return parts.length ? el('p', { class: 'ep-muted ep-refs' }, parts.join(' · ')) : null;
  }

  const cap = (s) => (s ? s.charAt(0).toUpperCase() + s.slice(1) : s);

  function searchHost(host, model) {
    const quoted = /^[\w.-]+$/.test(host) ? host : '"' + host.replace(/["\\]/g, '\\$&') + '"';
    openSearch(`datamodel=${model} dest=${quoted}`, '-7d');
  }

  function confirmRemove(h) {
    const dlg = $('ep-remove');
    const block = el('input', { type: 'checkbox', id: 'ep-block' });
    dlg.replaceChildren(
      el('form', { method: 'dialog' },
        el('div', { class: 'modal__head' }, el('div', {},
          el('h3', { class: 'modal__title', id: 'ep-remove-title' }, 'Remove ' + h.hostname + '?'),
          el('p', { class: 'modal__desc' }, 'Its key stops working at once. Events it already sent stay in Search.'))),
        el('div', { class: 'modal__body' },
          el('label', { class: 'switch' }, block, 'Block it from enrolling again'),
          el('p', { class: 'hint' }, 'Without this, a host that still runs osquery with the setup script enrolls again at its next contact. Blocked hosts can be let back in from this page.')),
        el('div', { class: 'modal__foot' },
          el('button', { class: 'btn btn--ghost', type: 'button', onclick: () => dlg.close() }, 'Cancel'),
          el('button', { class: 'btn btn--danger', type: 'submit', onclick: async (ev) => {
            ev.preventDefault();
            try {
              await api('api/endpoints/' + encodeURIComponent(h.id) + (block.checked ? '?block=true' : ''), undefined, 'DELETE');
              dlg.close();
              $('ep-host').close();
              toast(h.hostname + (block.checked ? ' was removed and blocked.' : ' was removed.'));
              S.hosts = null;
              loadHosts();
            } catch (e) {
              toast(e.message, null, { tone: 'danger', title: 'Couldn’t remove the host' });
            }
          } }, icon('trash-2'), 'Remove'))));
    dlg.showModal();
  }

  // ---------- configuration checks ----------
  async function loadChecks() {
    if (!S.checks) panels.checks.replaceChildren(skeleton());
    try {
      S.checks = await api('api/endpoints/checks');
      countFails();
      renderChecks();
    } catch (e) {
      if (!S.checks) panels.checks.replaceChildren(failed(e, loadChecks));
    }
  }

  function renderChecks() {
    const d = S.checks;
    if (!d.hosts) {
      panels.checks.replaceChildren(emptyHosts());
      return;
    }
    const plats = [...new Set(d.checks.filter((c) => Object.values(c.counts).some((n) => n)).map((c) => c.platform))];
    const t = d.totals;
    const shown = d.checks.filter((c) => (!S.checkPlatform || c.platform === S.checkPlatform) && plats.includes(c.platform) &&
      (!S.checkFail || c.counts.fail || c.counts.error));
    shown.sort((a, b) => b.counts.fail - a.counts.fail || sevRank(a.severity) - sevRank(b.severity) || a.title.localeCompare(b.title));
    const failOnly = el('input', { type: 'checkbox' });
    failOnly.checked = S.checkFail;
    failOnly.addEventListener('change', () => { S.checkFail = failOnly.checked; renderChecks(); });
    panels.checks.replaceChildren(...[
      d.enabled ? null : el('div', { class: 'alert', 'data-tone': 'warning' }, icon('triangle-alert'), el('div', {}, el('b', {}, 'Configuration checks are off.'),
        el('p', {}, 'Hosts keep their last results. Turn the checks on under What hosts collect.'))),
      el('div', { class: 'ep-summary' },
        el('span', { class: 'ep-stat' }, el('b', {}, t.fail.toLocaleString()), ' failing'),
        el('span', { class: 'ep-stat' }, el('b', {}, t.pass.toLocaleString()), ' passing'),
        t.pending ? el('span', { class: 'ep-stat ep-muted' }, t.pending.toLocaleString() + ' not reported yet') : null,
        el('span', { class: 'ep-muted ep-stat' }, 'Based on the SCAP Security Guide for Linux; Windows and macOS checks follow vendor hardening guidance.')),
      el('div', { class: 'toolbar ep-toolbar' },
        plats.length > 1 ? seg([['', 'All']].concat(plats.map((p) => [p, PLATFORM[p]])), S.checkPlatform, (v) => { S.checkPlatform = v; renderChecks(); }, 'Platform') : null,
        el('label', { class: 'switch' }, failOnly, 'Only checks that fail')),
      shown.length
        ? el('div', { class: 'card' }, el('ul', { class: 'ep-checks ep-checks--fleet', role: 'list' }, ...shown.map(fleetCheck)))
        : el('div', { class: 'card' }, el('div', { class: 'empty empty--compact' },
          el('span', { class: 'empty__icon' }, icon('circle-check')),
          el('div', { class: 'empty__title' }, S.checkFail ? (t.pass || t.fail ? 'No check fails' : 'No results yet') : 'No checks'),
          el('p', { class: 'empty__text' }, t.pass || t.fail ? '' : 'Hosts run the checks within the hour after they enroll.')))].filter(Boolean));
  }

  const sevRank = (s) => ({ high: 0, medium: 1, low: 2 }[s] ?? 3);

  function fleetCheck(c) {
    const n = c.counts;
    const total = n.pass + n.fail + n['n/a'] + n.error + n.pending;
    return el('li', { class: 'ep-check' },
      el('details', {},
        el('summary', {},
          el('span', { class: 'ep-plat ep-plat--sm', title: PLATFORM[c.platform] }, icon(PLATFORM_ICON[c.platform])),
          el('span', { class: 'ep-check__title' }, c.title),
          el('span', { class: 'sev', 'data-sev': c.severity }, cap(c.severity)),
          el('span', { class: 'ep-bar', title: `${n.fail} fail, ${n.pass} pass, ${n['n/a']} not applicable, ${n.pending} not reported yet` },
            el('span', { class: 'ep-bar__fail', style: `flex:${n.fail}` }), el('span', { class: 'ep-bar__pass', style: `flex:${n.pass}` }),
            el('span', { class: 'ep-bar__rest', style: `flex:${total - n.fail - n.pass}` })),
          el('span', { class: 'ep-check__count' }, n.fail ? n.fail + ' of ' + total + ' fail' : n.pass + ' of ' + total + ' pass'),
          icon('chevron-down', 'icon--sm chev')),
        el('div', { class: 'ep-check__more' },
          el('p', {}, c.description),
          el('p', {}, el('b', {}, 'How to fix: '), c.remediation),
          refsLine(c),
          c.failing.length ? el('div', { class: 'ep-failing' }, el('b', {}, 'Failing hosts'),
            el('ul', { role: 'list' }, ...c.failing.map((f) => el('li', {},
              el('a', { href: '#', onclick: (ev) => { ev.preventDefault(); openHost(f.id); } }, f.hostname),
              f.detail ? el('span', { class: 'ep-muted' }, ' · ' + f.detail) : null)))) : null)));
  }

  // ---------- live query ----------
  function renderQuery() {
    const hosts = S.hosts ? S.hosts.endpoints : null;
    if (!hosts) {
      panels.query.replaceChildren(skeleton());
      api('api/endpoints').then((d) => { S.hosts = d; if (S.tab === 'query') renderQuery(); }).catch((e) => panels.query.replaceChildren(failed(e, renderQuery)));
      return;
    }
    if (!hosts.length) {
      panels.query.replaceChildren(emptyHosts());
      return;
    }
    const sql = el('textarea', { class: 'textarea mono ep-sql', rows: '6', spellcheck: 'false', 'aria-label': 'SQL', placeholder: 'SELECT name, version FROM os_version;' });
    sql.value = (S.query && S.query.sql) || '';
    const target = el('select', { class: 'select', 'aria-label': 'Hosts' },
      el('option', { value: 'all' }, 'All hosts'),
      ...['windows', 'linux', 'darwin'].filter((p) => S.hosts.summary[p]).map((p) => el('option', { value: 'p:' + p }, 'All ' + PLATFORM[p] + ' hosts')),
      ...hosts.map((h) => el('option', { value: 'h:' + h.id }, h.hostname)));
    if (S.query && S.query.targets && S.query.targets.length === 1) target.value = 'h:' + S.query.targets[0];
    const online = el('input', { type: 'checkbox', checked: '' });
    const run = el('button', { class: 'btn btn--primary', type: 'button' }, icon('play'), 'Run');
    const out = el('div', { class: 'ep-results' });
    run.addEventListener('click', async () => {
      const body = { sql: sql.value, online: online.checked };
      const v = target.value;
      if (v === 'all') body.all = true;
      else if (v.startsWith('p:')) { body.all = true; body.platform = v.slice(2); } else body.targets = [v.slice(2)];
      run.disabled = true;
      try {
        const q = await api('api/endpoints/queries', body);
        S.query = { sql: sql.value, targets: body.targets, id: q.id };
        startPoll(q.id, out);
      } catch (e) {
        out.replaceChildren(el('p', { class: 'field-error', role: 'alert' }, icon('circle-alert'), e.message));
      } finally {
        run.disabled = false;
      }
    });
    sql.addEventListener('keydown', (ev) => { if (ev.key === 'Enter' && (ev.ctrlKey || ev.metaKey)) run.click(); });
    panels.query.replaceChildren(el('div', { class: 'card ep-query' },
      el('div', { class: 'card__body' },
        el('p', { class: 'ep-muted ep-query__lead' }, 'Run osquery SQL on hosts now. Online hosts answer within about 10 seconds. Every query is recorded in the audit log.'),
        el('div', { class: 'ep-examples' }, el('span', { class: 'ep-muted' }, 'Examples'),
          ...EXAMPLES.map(([label, text]) => el('button', { type: 'button', onclick: () => { sql.value = text; sql.focus(); } }, label))),
        sql,
        el('div', { class: 'ep-query__bar' }, target, el('label', { class: 'switch' }, online, 'Only hosts online now'), el('span', { class: 'spacer' }),
          el('a', { href: 'https://osquery.io/schema/', target: '_blank', rel: 'noopener noreferrer', class: 'ep-muted' }, 'Tables', icon('external-link', 'icon--xs')), run))),
      out);
    if (S.query && S.query.id) startPoll(S.query.id, out);
  }

  function stopPoll() {
    clearTimeout(S.poll);
    S.poll = null;
  }

  async function startPoll(id, out) {
    stopPoll();
    let d;
    try {
      d = await api('api/endpoints/queries/' + encodeURIComponent(id));
    } catch (e) {
      out.replaceChildren(el('p', { class: 'field-error' }, icon('circle-alert'), e.message));
      return;
    }
    if (S.tab !== 'query' || currentPage !== 'endpoints') return;
    renderResults(d, out);
    const waiting = d.query.targets.length - d.results.filter((r) => r.state !== 'sent').length;
    if (waiting > 0 && !d.expired) S.poll = setTimeout(() => startPoll(id, out), 2000);
  }

  function renderResults(d, out) {
    const names = new Map((S.hosts ? S.hosts.endpoints : []).map((h) => [h.id, h.hostname]));
    const byNode = new Map(d.results.map((r) => [r.node_id, r]));
    const done = d.results.filter((r) => r.state === 'done');
    const errors = d.results.filter((r) => r.state === 'error');
    const waiting = d.query.targets.filter((t) => !byNode.has(t) || byNode.get(t).state === 'sent');
    const cols = [];
    for (const r of done) for (const row of r.rows || []) for (const k of Object.keys(row)) if (!cols.includes(k)) cols.push(k);
    const rows = done.flatMap((r) => (r.rows || []).map((row) => [r.hostname, row]));
    const status = [
      `${done.length} of ${d.query.targets.length} ${d.query.targets.length === 1 ? 'host' : 'hosts'} answered`,
      rows.length + (rows.length === 1 ? ' row' : ' rows'),
    ];
    if (waiting.length) status.push(d.expired ? waiting.length + ' never answered' : 'waiting for ' + waiting.length);
    const truncated = done.some((r) => r.truncated);
    out.replaceChildren(...[
      el('div', { class: 'ep-summary' }, el('span', { class: 'ep-stat' }, status.join(' · ')),
        !d.expired && waiting.length ? el('span', { class: 'pulse', 'data-state': 'warn' }) : null,
        rows.length ? el('button', { class: 'btn btn--ghost btn--sm', type: 'button', onclick: () => downloadCSV(cols, rows) }, icon('download'), 'CSV') : null),
      errors.length ? el('div', { class: 'alert', 'data-tone': 'danger' }, icon('circle-alert'), el('div', {},
        ...errors.map((r) => el('p', {}, el('b', {}, r.hostname + ': '), r.error)))) : null,
      truncated ? el('p', { class: 'hint' }, icon('info'), 'Some hosts returned more than 1,000 rows or very long values; those were cut.') : null,
      rows.length ? el('div', { class: 'card' }, el('div', { class: 'table-wrap ep-results__wrap' }, el('table', { class: 'table ep-rtable' },
        el('thead', {}, el('tr', {}, el('th', {}, 'host'), ...cols.map((c) => el('th', {}, c)))),
        el('tbody', {}, ...rows.slice(0, 2000).map(([host, row]) => el('tr', {}, el('td', {}, host), ...cols.map((c) => el('td', { class: 'mono' }, row[c] ?? '')))))))) : null,
      waiting.length && d.expired ? el('p', { class: 'hint' }, 'Not answered: ' + waiting.map((t) => names.get(t) || t).join(', ')) : null].filter(Boolean));
  }

  function downloadCSV(cols, rows) {
    const esc = (v) => {
      let s = String(v ?? '');
      if (/^[=+\-@\t\r]/.test(s)) s = "'" + s; // keep spreadsheets from running it
      return /[",\n\r]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
    };
    const text = [['host', ...cols].map(esc).join(',')].concat(rows.map(([h, r]) => [h, ...cols.map((c) => r[c])].map(esc).join(','))).join('\r\n');
    const url = URL.createObjectURL(new Blob([text], { type: 'text/csv' }));
    const a = el('a', { href: url, download: 'live-query.csv', class: 'hidden' });
    document.body.append(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  // ---------- what hosts collect ----------
  async function openSettings() {
    const dlg = $('ep-settings-dialog');
    let d;
    try {
      d = await api('api/endpoints/settings');
    } catch (e) {
      toast(e.message, null, { tone: 'danger', title: 'Couldn’t load the settings' });
      return;
    }
    const s = d.settings;
    let plat = 'windows';
    const paths = { windows: (s.file_paths.windows || []).join('\n'), linux: (s.file_paths.linux || []).join('\n'), darwin: (s.file_paths.darwin || []).join('\n') };
    const excl = { windows: ((s.exclude_paths || {}).windows || []).join('\n'), linux: ((s.exclude_paths || {}).linux || []).join('\n'), darwin: ((s.exclude_paths || {}).darwin || []).join('\n') };
    const fim = el('input', { type: 'checkbox' });
    fim.checked = s.fim;
    const chk = el('input', { type: 'checkbox' });
    chk.checked = s.checks;
    const pathsEl = el('textarea', { class: 'textarea mono', rows: '7', spellcheck: 'false', id: 'ep-paths' });
    const exclEl = el('textarea', { class: 'textarea mono', rows: '2', spellcheck: 'false', id: 'ep-excl' });
    const every = (v, id) => {
      const sel = el('select', { class: 'select', id }, ...[[15, 'Every 15 minutes'], [30, 'Every 30 minutes'], [60, 'Every hour'], [240, 'Every 4 hours'], [1440, 'Once a day']]
        .map(([m, t]) => el('option', { value: String(m) }, t)));
      if (![15, 30, 60, 240, 1440].includes(v)) sel.append(el('option', { value: String(v) }, `Every ${v} minutes`));
      sel.value = String(v);
      return sel;
    };
    const inv = every(s.inventory_minutes, 'ep-inv');
    const chkEvery = every(s.check_minutes, 'ep-chk-every');
    const err = el('p', { class: 'field-error hidden', role: 'alert' });
    const platSeg = el('div', { class: 'ep-set__seg' });
    const showPlat = () => {
      pathsEl.value = paths[plat];
      exclEl.value = excl[plat];
      platSeg.replaceChildren(seg(['windows', 'linux', 'darwin'].map((p) => [p, PLATFORM[p]]), plat, (v) => {
        paths[plat] = pathsEl.value;
        excl[plat] = exclEl.value;
        plat = v;
        showPlat();
      }, 'Platform'));
    };
    showPlat();
    const restore = el('button', { class: 'btn btn--ghost btn--sm', type: 'button', onclick: () => {
      paths[plat] = d.defaults.file_paths[plat].join('\n');
      excl[plat] = ((d.defaults.exclude_paths || {})[plat] || []).join('\n');
      showPlat();
    } }, icon('rotate-ccw'), 'Use the defaults');
    const save = el('button', { class: 'btn btn--primary', type: 'submit' }, 'Save');
    dlg.replaceChildren(el('form', { method: 'dialog', novalidate: '' },
      el('div', { class: 'modal__head' }, el('div', {},
        el('h3', { class: 'modal__title', id: 'ep-set-title' }, 'What hosts collect'),
        el('p', { class: 'modal__desc' }, 'For every endpoint. Hosts pick up changes within 5 minutes.')),
      el('button', { class: 'btn btn--ghost btn--icon btn--sm modal__close', type: 'button', 'aria-label': 'Close', onclick: () => dlg.close() }, icon('x'))),
      el('div', { class: 'modal__body' },
        el('section', { class: 'ep-set__group' },
          el('label', { class: 'switch' }, fim, el('b', {}, 'Watch files for changes')),
          el('div', { class: 'ep-set__row' }, platSeg, restore),
          el('div', { class: 'field' }, el('label', { class: 'label', for: 'ep-paths' }, 'Watched paths, one per line'),
            pathsEl, el('p', { class: 'hint' }, '% matches names in one folder, %% matches everything below it, as in /etc/%%.')),
          el('div', { class: 'field' }, el('label', { class: 'label', for: 'ep-excl' }, 'Left out'), exclEl)),
        el('section', { class: 'ep-set__group ep-set__grid' },
          el('div', { class: 'field' }, el('label', { class: 'label', for: 'ep-inv' }, 'Look for software, account, port and service changes'), inv),
          el('div', { class: 'field' }, el('label', { class: 'switch' }, chk, 'Run configuration checks'), chkEvery)),
        err),
      el('div', { class: 'modal__foot' },
        el('button', { class: 'btn btn--ghost', type: 'button', onclick: () => dlg.close() }, 'Cancel'), save)));
    dlg.querySelector('form').addEventListener('submit', async (ev) => {
      ev.preventDefault();
      paths[plat] = pathsEl.value;
      excl[plat] = exclEl.value;
      const lines = (t) => t.split('\n').map((x) => x.trim()).filter(Boolean);
      const body = {
        version: d.version,
        settings: {
          fim: fim.checked, checks: chk.checked, inventory_minutes: +inv.value, check_minutes: +chkEvery.value,
          file_paths: Object.fromEntries(Object.entries(paths).map(([k, v]) => [k, lines(v)])),
          exclude_paths: Object.fromEntries(Object.entries(excl).map(([k, v]) => [k, lines(v)])),
        },
      };
      save.disabled = true;
      try {
        await api('api/endpoints/settings', body, 'PUT');
        dlg.close();
        toast('Hosts pick up the new settings within 5 minutes.', null, { title: 'Saved' });
        S.checks = null;
      } catch (e) {
        err.replaceChildren(icon('circle-alert'), e.message);
        err.classList.remove('hidden');
      } finally {
        save.disabled = false;
      }
    });
    dlg.showModal();
  }
})();
