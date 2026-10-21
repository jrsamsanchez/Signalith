// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0
// Audit page (admins): who changed what, on every server that shares this
// OpenSearch, searched by time, server, user, action and words. Users and
// Settings link here with a filter set (openAudit).
'use strict';

(function () {
  const A = { filters: {}, next: null, seq: 0, servers: null };
  const RANGES = [['1h', 'Last hour', 3600e3], ['24h', 'Last 24 hours', 864e5], ['7d', 'Last 7 days', 7 * 864e5],
    ['30d', 'Last 30 days', 30 * 864e5], ['all', 'All time', 0]];
  // Most records are found by their words; these actions are named.
  const ACTIONS = [['', 'All actions'], ['retention.', 'Data retention'], ['config.', 'Shared settings'], ['search.', 'Searches'],
    ['finding.', 'Findings'], ['case.', 'Cases'], ['detection.', 'Detections'], ['intel.', 'Threat intel'],
    ['audit.lost', 'Audit records lost'], ['audit.checkpoint', 'Audit checkpoints']];

  const page = () => $('page-audit');

  function since(f) {
    const r = RANGES.find((x) => x[0] === (f.range || '7d'));
    return r && r[2] ? new Date(Date.now() - r[2]).toISOString().replace(/\.\d+Z$/, 'Z') : '';
  }

  function query(after) {
    const f = A.filters;
    const p = new URLSearchParams();
    if (since(f)) p.set('from', since(f));
    for (const k of ['server', 'user', 'action', 'q']) if (f[k]) p.set(k, f[k]);
    p.set('size', '50');
    if (after) p.set('after', after);
    return '/api/audit?' + p.toString();
  }

  function select(id, label, opts, value) {
    const s = el('select', { id, class: 'select', 'aria-label': label });
    for (const [v, text] of opts) s.append(el('option', { value: v }, text));
    s.value = value || '';
    return s;
  }

  function renderFilters() {
    const f = A.filters;
    const servers = [['', 'All servers'], ...(A.servers || []).map((s) => [s, s])];
    if (f.server && !(A.servers || []).includes(f.server)) servers.push([f.server, f.server]);
    const actions = ACTIONS.slice();
    if (f.action && !actions.some((a) => a[0] === f.action)) actions.push([f.action, f.action]);
    const user = el('input', { id: 'au-user', class: 'input', type: 'search', placeholder: 'User', 'aria-label': 'User', autocomplete: 'off', spellcheck: 'false', value: f.user || '' });
    const text = el('input', { id: 'au-q', class: 'input', type: 'search', placeholder: 'Words in the message', 'aria-label': 'Words in the message', autocomplete: 'off', spellcheck: 'false', value: f.q || '' });
    const bar = el('form', { class: 'toolbar au-toolbar', role: 'search' },
      select('au-range', 'Time range', RANGES.map((r) => [r[0], r[1]]), f.range || '7d'),
      select('au-server', 'Server', servers, f.server),
      select('au-action', 'Action', actions, f.action),
      el('div', { class: 'input-wrap' }, icon('user'), user),
      el('div', { class: 'input-wrap' }, icon('search'), text),
      el('button', { class: 'btn', type: 'submit' }, 'Search'),
      el('button', { class: 'btn', type: 'button', id: 'au-verify', title: 'Check that no audit record in the time range was changed or removed' },
        icon('shield-check'), 'Check integrity'));
    bar.querySelector('#au-verify').addEventListener('click', verify);
    bar.addEventListener('change', (e) => { if (e.target.tagName === 'SELECT') bar.requestSubmit(); });
    bar.addEventListener('submit', (e) => {
      e.preventDefault();
      A.filters = { range: $('au-range').value, server: $('au-server').value, action: $('au-action').value,
        user: user.value.trim(), q: text.value.trim() };
      load();
    });
    return bar;
  }

  function row(ev) {
    const extra = Object.entries(ev.fields || {}).filter(([k]) => k !== 'act').slice(0, 6)
      .map(([k, v]) => k + '=' + v).join('  ');
    return el('tr', {},
      el('td', { 'data-label': 'Time', class: 'au-time' }, fmtTime(ev['@timestamp'])),
      el('td', { 'data-label': 'Server' }, ev.server || '—'),
      el('td', { 'data-label': 'User' }, ev.user || '—', ev.source_ip ? el('div', { class: 'au-muted' }, ev.source_ip) : null),
      el('td', { 'data-label': 'Action' }, ev.action ? el('code', {}, ev.action) : '—'),
      el('td', { 'data-label': 'What happened' }, ev.message, ev.target ? el('div', { class: 'au-muted' }, ev.target) : null,
        extra ? el('div', { class: 'au-muted au-fields' }, extra) : null));
  }

  function table(events) {
    return el('div', { class: 'table-wrap' }, el('table', { class: 'table au-table' },
      el('thead', {}, el('tr', {}, el('th', {}, 'Time'), el('th', {}, 'Server'), el('th', {}, 'User'), el('th', {}, 'Action'), el('th', {}, 'What happened'))),
      el('tbody', { id: 'au-rows' }, ...events.map(row))));
  }

  function more() {
    if (!A.next) return null;
    const b = el('button', { class: 'btn', type: 'button', id: 'au-more' }, 'Show older');
    b.addEventListener('click', async () => {
      b.disabled = true;
      const seq = ++A.seq;
      try {
        const res = await api(query(A.next));
        if (seq !== A.seq) return;
        $('au-rows').append(...res.events.map(row));
        A.next = res.next || null;
        b.replaceWith(more() || el('span'));
      } catch (e) {
        b.disabled = false;
        toast(e.message, null, { tone: 'danger', title: 'Couldn’t load more audit records' });
      }
    });
    return el('div', { class: 'table-foot' }, b);
  }

  // verify checks the chains of the records in the time range (and of the
  // server, when one is picked) and shows what it found above the list.
  async function verify() {
    const b = $('au-verify');
    const box = $('au-check');
    const f = A.filters;
    const p = new URLSearchParams();
    if (since(f)) p.set('from', since(f));
    if (f.server) p.set('server', f.server);
    b.disabled = true;
    box.replaceChildren(el('div', { class: 'card' }, el('div', { class: 'empty empty--compact' },
      el('span', { class: 'empty__icon' }, icon('shield')), el('div', { class: 'empty__title' }, 'Checking the audit records…'))));
    try {
      const res = await api('/api/audit/verify?' + p.toString());
      if (!res.enabled) {
        box.replaceChildren();
        return;
      }
      const r = res.report;
      const parts = [r.ok + ' signed and linked'];
      for (const [n, what] of [[r.edited, 'changed'], [r.stripped, 'with their signature removed, or put in'], [r.broken, 'not linked to the record before'], [r.missing, 'removed'],
        [r.truncated, 'servers with their latest records removed'], [r.dropped, 'dropped by a full spool or refused, and recorded'],
        [r.unverifiable, 'missing where nothing is signed, so a drop cannot be told from a removal'],
        [r.unsigned, 'unsigned'], [r.unknown_key, 'signed with a key this server does not hold']]) {
        if (n) parts.push(n + ' ' + what);
      }
      const text = r.records + ' records checked: ' + parts.join(', ') + '.' + (r.limited ? ' Only the oldest were read; pick a shorter range for the rest.' : '');
      const list = (r.problems || []).slice(0, 10).map((x) => el('li', {}, fmtTime(x.time) + ' · ' + (x.server || x.node_id) + ' · #' + x.seq + ': ' + x.detail));
      box.replaceChildren(el('div', { class: 'card' }, el('div', { class: 'empty empty--compact' },
        el('span', { class: 'empty__icon' }, icon(res.tampered ? 'shield-x' : 'shield-check')),
        el('div', { class: 'empty__title' }, res.tampered ? 'Audit records were changed or removed' : 'No audit record was changed or removed'),
        el('p', { class: 'empty__text' }, text),
        list.length ? el('ul', { class: 'empty__text au-problems' }, ...list) : null)));
    } catch (e) {
      box.replaceChildren(el('div', { class: 'card' }, el('div', { class: 'empty empty--compact' },
        el('span', { class: 'empty__icon' }, icon('circle-alert')), el('div', { class: 'empty__title' }, 'Couldn’t check the audit records'),
        el('p', { class: 'empty__text' }, e.message))));
    } finally {
      b.disabled = false;
    }
  }

  async function load() {
    $('au-check').replaceChildren();
    const root = $('au-body');
    const seq = ++A.seq;
    try {
      if (!A.servers) {
        A.servers = (await api('/api/audit/servers')).servers || [];
        $('au-filters').replaceChildren(renderFilters());
      }
      const res = await api(query());
      if (seq !== A.seq) return;
      if (!res.enabled) {
        $('au-filters').replaceChildren();
        root.replaceChildren(el('div', { class: 'card' }, el('div', { class: 'empty' },
          el('span', { class: 'empty__icon' }, icon('scroll-text')), el('div', { class: 'empty__title' }, 'Audit records are in the server log'),
          el('p', { class: 'empty__text' }, res.note))));
        return;
      }
      A.next = res.next || null;
      if (!res.events.length) {
        root.replaceChildren(el('div', { class: 'card' }, el('div', { class: 'empty empty--compact' },
          el('span', { class: 'empty__icon' }, icon('search')), el('div', { class: 'empty__title' }, 'No audit records match'))));
        return;
      }
      root.replaceChildren(el('div', { class: 'card' }, table(res.events), more()));
    } catch (e) {
      if (seq !== A.seq) return;
      root.replaceChildren(el('div', { class: 'card' }, el('div', { class: 'empty empty--compact' },
        el('span', { class: 'empty__icon' }, icon('circle-alert')), el('div', { class: 'empty__title' }, 'Couldn’t load the audit records'),
        el('p', { class: 'empty__text' }, e.message))));
    }
  }

  // openAudit opens the page with filters, for links from other pages.
  window.openAudit = function (filters) {
    A.filters = Object.assign({ range: '7d' }, filters || {});
    A.servers = null;
    showPage('audit');
  };

  pageHooks.push((name) => {
    if (name !== 'audit' || !page()) return;
    A.servers = null;
    load();
  });
})();
