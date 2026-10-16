// Servers page: the OpenSearch part of this server's side panel. It says how safe OpenSearch is from
// losing a node (health, nodes, disks, Signalith indices with no copy on
// another node) and which of this server's OpenSearch addresses it skips
// after a failure. With more than one data node and Replicas at 0, it
// offers to turn on automatic replicas through the Settings page's own
// save, so the change is checked and recorded as any other.
'use strict';

(function () {
  const REFRESH_MS = 10000;
  const O = { data: null, key: '', tried: 0, busy: false, failed: false, seq: 0, box: null, writable: null };
  // O.box is the part's element, kept across the panel's refreshes.

  const n = (v, one, many) => `${v} ${v === 1 ? one : many}`;
  const pct = (v) => (v == null ? '–' : `${Math.round(v)}%`);

  async function load() {
    if (O.busy) return;
    O.busy = true;
    O.tried = Date.now();
    const seq = ++O.seq;
    try {
      const d = await api('api/cluster/opensearch');
      if (seq !== O.seq) return;
      O.data = d;
      O.failed = false;
      if (d.suggest_auto && O.writable === null) await loadWritable();
    } catch (e) {
      if (seq !== O.seq) return;
      O.failed = !O.data;
    } finally {
      O.busy = false;
    }
    draw();
  }

  // loadWritable learns whether the shared settings can be changed now:
  // while a server only has its saved copy of them, they can't.
  async function loadWritable() {
    try {
      const v = await api('api/settings');
      O.writable = !(v.shared && v.writable === false);
    } catch (_) {
      O.writable = false;
    }
  }

  function summary(d) {
    const parts = ['OpenSearch ' + (d.status || 'unknown')];
    if (d.nodes != null) parts.push(n(d.nodes, 'node', 'nodes'));
    if (d.manager_eligible != null) parts.push(`${d.manager_eligible} can be cluster manager`);
    if (d.unassigned_shards) parts.push(n(d.unassigned_shards, 'shard', 'shards') + ' on no node');
    return parts.join(' · ');
  }

  function warning(text) {
    const cut = text.indexOf(': ');
    const dot = text.indexOf('. ');
    const at = cut > 0 && (dot < 0 || cut < dot) ? cut : dot;
    const title = at > 0 ? text.slice(0, at) + (at === dot ? '.' : '') : text;
    const body = at > 0 ? text.slice(at + 2) : '';
    return el('div', { class: 'alert', 'data-tone': 'warning' }, icon('triangle-alert'),
      el('div', {}, el('b', {}, title), body ? el('p', {}, ...withCode(body.charAt(0).toUpperCase() + body.slice(1))) : null));
  }

  function replicasOffer() {
    const btn = el('button', { type: 'button', class: 'btn btn--primary btn--sm' }, 'Use automatic replicas');
    btn.addEventListener('click', () => confirmAuto(btn));
    return el('div', { class: 'callout sv-os__offer' }, icon('copy'),
      el('div', {}, el('b', {}, 'Replicas are off. '),
        'OpenSearch has more than one data node, but Signalith asks it for no copies, so losing a node loses the events on it.'),
      O.writable ? btn : el('span', { class: 'hint' }, 'The shared settings can’t be changed right now.'));
  }

  function confirmAuto(from) {
    const d = modalDialog('sv-os-auto');
    const ok = el('button', { type: 'button', class: 'btn btn--primary' }, 'Use automatic replicas');
    const msg = el('div');
    fill(d, modalHead('sv-os-auto', 'Use automatic replicas?',
      'From the next day on, OpenSearch keeps one copy of each day’s events on another node. Days already stored keep the copies they have. Every server uses it after its next restart.', () => d.close()),
    el('div', { class: 'modal__body' }, msg),
    el('div', { class: 'modal__foot' }, el('button', { type: 'button', class: 'btn btn--ghost', onclick: () => d.close() }, 'Cancel'), ok));
    ok.addEventListener('click', async () => {
      const restore = busy(ok, 'Saving…');
      try {
        // The Settings page's own save, naming the version read, so a
        // change made meanwhile by someone else is not overwritten.
        const v = await api('api/settings');
        const body = { values: { 'opensearch.replicas': 'auto' } };
        const f = (v.sections || []).flatMap((s) => s.fields || []).find((x) => x.key === 'opensearch.replicas');
        if (v.shared && f && f.version != null) body.if_version = { 'opensearch.replicas': f.version };
        await api('api/settings', body, 'PUT');
      } catch (e) {
        restore();
        msg.replaceChildren(el('div', { class: 'alert', 'data-tone': 'danger', role: 'alert' }, icon('circle-alert'),
          el('div', {}, el('b', {}, 'Replicas were not changed.'), el('p', {}, e.status === 412 ? 'Someone changed them meanwhile. Check the Settings page.' : sentence(e.message)))));
        return;
      }
      d.close();
      toast('Replicas set to automatic. Each server uses it after its next restart.');
      O.key = '';
      load();
      if (from && from.isConnected) from.focus();
    });
    d.showModal();
  }

  function diskTable(d) {
    const rows = (d.disk || []).map((x) => {
      const past = x.used_percent != null && x.low != null && x.used_percent >= x.low;
      return el('tr', {},
        el('td', { 'data-col': 'node' }, el('span', { class: 'mono' }, x.node)),
        el('td', { 'data-col': 'used' }, past ? el('span', { class: 'badge badge--warning' }, pct(x.used_percent)) : pct(x.used_percent)),
        el('td', { 'data-col': 'marks', class: 'sv-os__dim' }, `${pct(x.low)} / ${pct(x.high)} / ${pct(x.flood)}`));
    });
    if (!rows.length) return null;
    return el('div', { class: 'table-wrap' }, el('table', { class: 'table sv-os__table' },
      el('thead', {}, el('tr', {}, el('th', { scope: 'col' }, 'Node'), el('th', { scope: 'col' }, 'Disk used'),
        el('th', { scope: 'col', title: 'OpenSearch’s disk watermarks: no new shards, shards move away, writes refused' }, 'Low / high / flood'))),
      el('tbody', {}, ...rows)));
  }

  function endpoints(d) {
    const list = d.endpoints || [];
    if (!list.length) return null;
    return el('div', { class: 'sv-os__part' },
      el('h4', { class: 'sv-os__h' }, list.length === 1 ? 'This server’s OpenSearch address' : 'This server’s OpenSearch addresses'),
      el('ul', { class: 'sv-os__list' }, ...list.map((e) => el('li', {},
        el('span', { class: 'mono sv-os__url' }, e.url),
        e.down
          ? el('span', { class: 'badge badge--danger', title: e.reason || '' }, `Skipped for ${e.retry_in_seconds || 1} s`)
          : el('span', { class: 'badge badge--outline' }, 'In use')))),
      list.length === 1 && (d.nodes || 0) > 1
        ? el('p', { class: 'hint' }, 'Add the other nodes under More addresses on the Settings page, so this server can use them when this one is down.')
        : null);
  }

  function noReplicas(d) {
    const list = d.no_replicas || [];
    if (!list.length || (d.data_nodes || 0) < 2) return null;
    const shown = list.slice(0, 20);
    return el('details', { class: 'sv-os__part' },
      el('summary', {}, n(list.length, 'index', 'indices') + ' with no copy on another node'),
      el('ul', { class: 'sv-os__list' }, ...shown.map((x) => el('li', { class: 'mono' }, x)),
        list.length > shown.length ? el('li', { class: 'hint' }, `and ${list.length - shown.length} more`) : null));
  }

  function draw() {
    const box = O.box;
    if (!box) return;
    const d = O.data;
    if (!d) {
      box.replaceChildren(O.failed ? el('p', { class: 'hint' }, 'OpenSearch’s details couldn’t be loaded.') : el('p', { class: 'hint' }, 'Loading OpenSearch…'));
      return;
    }
    const key = JSON.stringify([d, O.writable]);
    if (key === O.key) return;
    O.key = key;
    const parts = [];
    for (const w of d.warnings || []) parts.push(warning(w));
    if (d.suggest_auto) parts.push(replicasOffer());
    box.replaceChildren(el('p', { class: 'sv-os__sum' }, summary(d)),
      parts.length ? el('div', { class: 'sv-alerts sv-os__alerts' }, ...parts) : null,
      diskTable(d), endpoints(d), noReplicas(d));
  }

  // The part shows in this server's own side panel: the addresses are
  // this server's, and the rest is the OpenSearch every server shares.
  // The panel asks for it on every refresh; the answer is fetched again
  // at most every REFRESH_MS, and the same element is handed back.
  serverPanels.push((ctx) => {
    if (!ctx.s || !ctx.s.self) return null;
    if (!O.box) O.box = el('div', { class: 'sv-os' });
    if (!O.busy && Date.now() - O.tried >= REFRESH_MS) load();
    draw();
    return ctx.part('OpenSearch', O.box);
  });
})();
