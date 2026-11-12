// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0
// Data sources page (everyone): every host and source type that sent
// events in the last 7 days, when each was last heard from, how much it
// sends now against its usual, and which went quiet or changed sharply. A
// detection cannot fire on data that never arrives, so this is where to
// check that each source still sends. Opening a source shows its events
// per minute over the last hour, per hour over 7 days, and its latest
// events. It reads with the same searches anyone can run on the Search
// page, so it shows only what the viewer may search.
'use strict';

(function () {
  const SRC = { data: null, at: 0, busy: false, seq: 0, filter: '', text: '', ticker: null, error: '' };
  // What Signalith writes about itself, and its own scans, come and go by
  // design; they are left out as the "stopped sending" check leaves them.
  const BASE = 'NOT signalith_intake IN (signalith, scanner)';
  // A source is sending while it was heard from in the last 15 minutes,
  // quiet after that, and stopped after dashboards.stale_after (2h by
  // default, from api/health).
  const SENDING_FOR = 15 * 60;
  // A sharp change: the last hour at least 3 times its usual hour (and 60
  // events more), or a third of it or less (from at least 60 an hour).
  const SHARP = 3, SHARP_MIN = 60;

  pageHooks.push((name) => { if (name === 'sources') load(); });
  $('src-reload').addEventListener('click', () => load(true));
  const box = () => $('src-page');
  const n = (v) => Number(v || 0).toLocaleString();
  const key = (s) => s.host + '\u0000' + s.sourcetype;
  const spl = (field, v) => field + '=' + (typeof quoteValue === 'function' ? quoteValue(v) : JSON.stringify(String(v)));
  const sourceQuery = (s) => `${spl('host', s.host)} ${spl('sourcetype', s.sourcetype)}`;
  const sinceText = (secs) => (secs >= 86400 && secs % 86400 === 0 ? `${secs / 86400} ${secs === 86400 ? 'day' : 'days'}`
    : secs >= 3600 && secs % 3600 === 0 ? `${secs / 3600} ${secs === 3600 ? 'hour' : 'hours'}` : `${Math.round(secs / 60)} minutes`);

  async function load(force) {
    const st = SRC;
    if (!st.ticker) st.ticker = setInterval(tick, 1000);
    if (st.busy) return;
    if (!force && st.data && Date.now() - st.at < 30000) { render(); return; }
    const seq = ++st.seq;
    st.busy = true;
    if (!st.data) skeleton();
    $('src-reload').disabled = true;
    try {
      const run = (query, earliest) => api('api/search', { query: BASE + '\n| ' + query, earliest, time_zone: viewerZone() });
      const [week, day, hour, health] = await Promise.all([
        run('stats min(_time) as first_seen, max(_time) as last_seen, count(signalith_sample) as sample by host, sourcetype', '-7d'),
        run('stats count by host, sourcetype', '-24h'),
        run('stats count by host, sourcetype', '-1h'),
        api('api/health').catch(() => null),
      ]);
      if (seq !== st.seq) return;
      st.data = build(week, day, hour, (health && health.stale_after_seconds) || 7200);
      st.at = Date.now();
      st.error = '';
    } catch (e) {
      if (seq !== st.seq) return;
      st.error = e.message;
    } finally {
      if (seq === st.seq) { st.busy = false; $('src-reload').disabled = false; }
    }
    render();
  }

  // build joins the three counts into one row per source, with its state.
  function build(week, day, hour, stale) {
    const by = new Map();
    for (const r of week.rows || []) {
      if (r.host == null || r.sourcetype == null) continue;
      by.set(key(r), { host: String(r.host), sourcetype: String(r.sourcetype), first: Number(r.first_seen) * 1000, last: Number(r.last_seen) * 1000, sample: Number(r.sample) > 0, day: 0, hour: 0 });
    }
    for (const [res, f] of [[day, 'day'], [hour, 'hour']]) {
      for (const r of res.rows || []) { const s = by.get(key(r)); if (s) s[f] = Number(r.count) || 0; }
    }
    const now = Date.now();
    const list = [...by.values()];
    for (const s of list) {
      const age = (now - s.last) / 1000;
      s.state = s.sample ? 'sample' : age <= SENDING_FOR ? 'sending' : age <= stale ? 'quiet' : 'stopped';
      // The usual hour is the day before the last hour, when the source
      // was around all of it.
      s.usual = now - s.first >= 25 * 3600e3 ? Math.max(0, s.day - s.hour) / 23 : null;
      s.change = '';
      if (s.usual != null && !s.sample && s.state !== 'stopped') {
        if (s.hour >= s.usual * SHARP && s.hour - s.usual >= SHARP_MIN) s.change = 'up';
        else if (s.usual >= SHARP_MIN && s.hour <= s.usual / SHARP) s.change = 'down';
      }
      s.look = s.state === 'stopped' || !!s.change;
    }
    // Those that need a look first, then the busiest.
    // Sample data last: it is there to try things, not to watch.
    list.sort((a, b) => (a.sample - b.sample) || (b.look - a.look) || (b.hour - a.hour) || (b.day - a.day) || a.host.localeCompare(b.host));
    return { list, stale, truncated: !!(week.truncated || week.ranked) };
  }

  function tick() {
    if (currentPage !== 'sources') { clearInterval(SRC.ticker); SRC.ticker = null; return; }
    if (document.hidden || SRC.busy || !SRC.data) return;
    const live = $('src-live');
    if (live) live.textContent = 'Updated ' + ago(SRC.at);
    if (Date.now() - SRC.at >= 60000) load(true);
  }

  function skeleton() {
    box().setAttribute('aria-busy', 'true');
    box().replaceChildren(el('div', { class: 'kpis src-kpis' }, ...[0, 1, 2, 3].map(() => el('div', { class: 'card kpi' }, dxSkel('50%'), dxSkel('30%')))),
      el('div', { class: 'card src-skel' }, ...[0, 1, 2, 3, 4].map((i) => dxSkel(['70%', '55%', '62%', '48%', '66%'][i]))));
  }

  const STATE = {
    sending: ['', 'Sending'], quiet: ['idle', 'Quiet'], stopped: ['down', 'Stopped'], sample: ['idle', 'Sample data'],
  };
  function stateCell(s) {
    const [pulse, label] = STATE[s.state];
    const p = el('span', { class: 'pulse', 'aria-hidden': 'true' });
    if (pulse) p.dataset.state = pulse;
    return el('span', { class: 'hp-state' }, p, label);
  }
  function rateText(s) {
    const m = s.hour / 60;
    return m >= 10 ? Math.round(m).toLocaleString() : m >= 0.1 ? m.toFixed(1) : s.hour ? '<0.1' : '0';
  }
  function changeCell(s) {
    if (s.change === 'up') return el('span', { class: 'src-change', 'data-dir': 'up' }, icon('trending-up'), `${(s.hour / Math.max(s.usual, 1)).toFixed(1)}× usual`);
    if (s.change === 'down') return el('span', { class: 'src-change', 'data-dir': 'down' }, icon('trending-down'), s.hour ? `${Math.round((1 - s.hour / s.usual) * 100)}% below usual` : 'Nothing this hour');
    if (s.state === 'stopped') return el('span', { class: 'muted' }, 'Nothing');
    if (s.usual == null) return el('span', { class: 'muted', title: 'Seen for less than a day, so there is no usual yet' }, 'New');
    return el('span', { class: 'muted' }, 'Usual');
  }

  const FILTERS = [['', 'All'], ['look', 'Needs a look'], ['sending', 'Sending'], ['quiet', 'Quiet'], ['stopped', 'Stopped'], ['sample', 'Sample data']];
  const matches = (s, f) => !f || (f === 'look' ? s.look : s.state === f);

  function render() {
    if (currentPage !== 'sources') return;
    const b = box();
    b.removeAttribute('aria-busy');
    const d = SRC.data;
    if (!d) {
      b.replaceChildren(el('div', { class: 'card' }, dxEmpty({ tone: 'danger', icon: 'circle-alert', title: 'Couldn’t load the data sources', text: SRC.error, action: dxRetry(() => load(true)) })));
      return;
    }
    const list = d.list;
    const real = list.filter((s) => !s.sample);
    const count = (f) => list.filter((s) => matches(s, f)).length;
    const look = count('look');
    const perMin = real.reduce((a, s) => a + s.hour, 0) / 60;
    const kpis = el('div', { class: 'kpis src-kpis' },
      healthKpi('radio-tower', 'Sending now', n(count('sending')), `of ${n(real.length)} seen in 7 days`),
      healthKpi('triangle-alert', 'Need a look', n(look), look ? 'Stopped or sharply changed' : 'All as usual', look ? 'warning' : ''),
      healthKpi('circle-pause', 'Stopped', n(count('stopped')), `Nothing for ${sinceText(d.stale)} or more`, count('stopped') ? 'warning' : ''),
      healthKpi('activity', 'Events per minute', perMin >= 10 ? n(Math.round(perMin)) : perMin.toFixed(1), 'Over the last hour'));

    const notes = [];
    if (SRC.error) notes.push(dxAlert('warning', 'Couldn’t refresh.', SRC.error + ' What is shown is from ' + ago(SRC.at) + '.'));
    if (d.truncated) notes.push(dxAlert('info', 'Not every source is listed.', 'There are more host and source type pairs than one search returns. Search for a host to narrow the list.'));

    if (!list.length) {
      b.replaceChildren(kpis, el('div', { class: 'card' }, dxEmpty({ icon: 'radio-tower', title: 'No data in the last 7 days',
        text: 'Sources show here once they send events.', action: can('admin') ? { label: 'Add data', icon: 'plus', run: () => showPage('data') } : null })));
      return;
    }

    if (SRC.filter && !count(SRC.filter)) SRC.filter = '';
    const seg = el('div', { class: 'seg src-filter', role: 'group', 'aria-label': 'Show' }, ...FILTERS.map(([f, label]) => {
      const c = count(f);
      if (f && !c && f !== 'look') return null;
      const btn = el('button', { type: 'button', 'aria-pressed': String(SRC.filter === f), onclick: () => { SRC.filter = f; render(); } },
        label, el('span', { class: 'src-filter__n num' }, n(c)));
      if (f === 'look' && !c) btn.disabled = true;
      return btn;
    }));
    const find = el('input', { class: 'input', id: 'src-find', type: 'search', placeholder: 'Find a host or source type', 'aria-label': 'Find a host or source type', autocomplete: 'off', spellcheck: 'false', value: SRC.text });
    find.addEventListener('input', () => { SRC.text = find.value; drawRows(); });

    const tbody = el('tbody');
    const foot = el('div', { class: 'table-foot' }, el('span', { class: 'src-shown' }), el('span', { class: 'spacer' }), el('span', { class: 'live', id: 'src-live' }, 'Updated ' + ago(SRC.at)));
    const drawRows = () => {
      const q = SRC.text.trim().toLowerCase();
      const shown = list.filter((s) => matches(s, SRC.filter) && (!q || s.host.toLowerCase().includes(q) || s.sourcetype.toLowerCase().includes(q)));
      tbody.replaceChildren(...shown.slice(0, 500).map(row));
      if (!shown.length) tbody.append(el('tr', {}, el('td', { colspan: '6', class: 'muted src-none' }, 'No source matches.')));
      foot.firstChild.textContent = shown.length > 500 ? `Showing 500 of ${n(shown.length)}; narrow the search to see the rest` : `${n(shown.length)} ${shown.length === 1 ? 'source' : 'sources'}`;
    };
    const table = el('table', { class: 'table src-table' },
      el('thead', {}, el('tr', {},
        el('th', { scope: 'col', 'data-col': 'name' }, 'Source'), el('th', { scope: 'col', 'data-col': 'state' }, 'Status'),
        el('th', { scope: 'col', 'data-col': 'last' }, 'Last event'), el('th', { scope: 'col', class: 'num', 'data-col': 'rate' }, 'Per minute'),
        el('th', { scope: 'col', 'data-col': 'change' }, 'Last hour'), el('th', { scope: 'col', class: 'num', 'data-col': 'day' }, '24 hours'))),
      tbody);
    drawRows();
    b.replaceChildren(kpis, ...(notes.length ? [el('div', { class: 'src-notes' }, ...notes)] : []),
      el('div', { class: 'toolbar src-toolbar', role: 'search' }, el('div', { class: 'input-wrap' }, icon('search'), find), seg),
      el('div', { class: 'card' }, el('div', { class: 'table-wrap' }, table), foot),
      el('p', { class: 'hint src-how' }, `Stopped means nothing for ${sinceText(d.stale)} (Settings > Search > Quiet data source after). Last hour compares the last hour with the source’s usual hour over the day before. `,
        'The built-in detection ', el('a', { href: '#detections', onclick: (ev) => { ev.preventDefault(); if (typeof focusDetection === 'function') focusDetection('data-source-stopped'); } }, 'Data source stopped sending'),
        ' raises a finding when a source that sent all day stops.'));
  }

  function healthKpi(name, label, value, foot, tone) {
    const attrs = { class: 'card kpi' };
    if (tone) attrs['data-tone'] = tone;
    return el('div', attrs, el('div', { class: 'kpi__label' }, icon(name), label),
      el('div', { class: 'kpi__value num' }, value), el('div', { class: 'kpi__foot' }, foot));
  }

  function row(s) {
    const open = () => openSource(s);
    const tr = el('tr', { class: 'src-row' + (s.look ? ' is-look' : '') },
      el('td', { 'data-col': 'name' }, el('button', { type: 'button', class: 'src-name', onclick: open, title: 'Events per minute and the latest events' },
        el('span', { class: 'src-name__host' }, s.host), el('span', { class: 'src-name__type mono' }, s.sourcetype))),
      el('td', { 'data-col': 'state' }, stateCell(s)),
      el('td', { 'data-col': 'last', title: new Date(s.last).toLocaleString() }, ago(s.last)),
      el('td', { 'data-col': 'rate', class: 'num' }, rateText(s)),
      el('td', { 'data-col': 'change' }, changeCell(s)),
      el('td', { 'data-col': 'day', class: 'num' }, n(s.day)));
    tr.addEventListener('click', (ev) => { if (!ev.target.closest('button, a')) open(); });
    return tr;
  }

  // openSource shows one source: events per minute over the last hour,
  // per hour over 7 days, and its 10 latest events.
  async function openSource(s) {
    const dlg = $('src-dialog');
    const q = sourceQuery(s);
    const perMin = el('div', { class: 'src-chart', 'aria-busy': 'true' }, dxSkel('100%'));
    const perHour = el('div', { class: 'src-chart', 'aria-busy': 'true' }, dxSkel('100%'));
    const latest = el('div', { class: 'src-latest', 'aria-busy': 'true' }, dxSkel('80%'), dxSkel('60%'), dxSkel('70%'));
    const facts = dxKv([
      ['Status', stateCell(s)],
      ['Last event', el('span', { title: new Date(s.last).toLocaleString() }, `${ago(s.last)} · ${new Date(s.last).toLocaleString()}`)],
      ['Last hour', `${n(s.hour)} events${s.usual != null ? `, usually about ${n(Math.round(s.usual))}` : ''}`],
      ['Last 24 hours', `${n(s.day)} events`],
    ]);
    const lead = s.state === 'stopped' ? dxAlert('warning', `Nothing from it for ${ago(s.last).replace(' ago', '')}.`, 'Detections that need these events are blind until it sends again. Check the agent or device, then the network and firewall between it and Signalith.')
      : s.change === 'up' ? dxAlert('warning', 'Much more than usual this hour.', 'A burst can be an attack (a scan, brute force, malware) or a change such as new logging or a noisy fault. Open its events to see what grew.')
      : s.change === 'down' ? dxAlert('warning', 'Much less than usual this hour.', 'Part of its logging may have stopped: a service, a log channel, or a filter on the agent or the device. Open its events to see what is missing.')
      : s.sample ? dxAlert('info', 'Sample data.', 'Made-up events loaded to try Signalith. They stop when the sample was loaded, so this source is never called stopped.') : null;
    const close = dxBtn('ghost', '', () => dlg.close(), { sm: true, icon: 'x', title: 'Close' });
    fill(dlg, el('div', { class: 'modal__head' },
      el('div', { class: 'src-dlg__title' }, el('h2', { class: 'modal__title', id: 'src-dialog-title' }, s.host), el('p', { class: 'modal__desc mono' }, s.sourcetype)), close),
    el('div', { class: 'modal__body src-dlg' }, lead, facts,
      el('section', { class: 'section' }, el('h3', { class: 'section-title' }, 'Events per minute, last hour'), perMin),
      el('section', { class: 'section' }, el('h3', { class: 'section-title' }, 'Events per hour, last 7 days'), perHour),
      el('section', { class: 'section' }, el('div', { class: 'dx-sec-head' }, el('h3', { class: 'section-title' }, 'Latest events'),
        dxBtn('ghost', 'Open in Search', () => { dlg.close(); openSearch(q, '-24h'); }, { sm: true, icon: 'search' })), latest)),
    el('div', { class: 'modal__foot' }, el('button', { type: 'button', class: 'btn btn--secondary', onclick: () => dlg.close() }, 'Close')));
    if (!dlg.open) dlg.showModal();
    const search = (query, earliest) => api('api/search', { query, earliest, time_zone: viewerZone() });
    const chart = async (target, query, earliest, label) => {
      try {
        const res = await search(query, earliest);
        target.removeAttribute('aria-busy');
        drawTimeChart(target, res, { area: true, height: 160, label, emptyText: 'No events in this time range.' });
      } catch (e) {
        target.removeAttribute('aria-busy');
        target.replaceChildren(el('p', { class: 'muted' }, e.message));
      }
    };
    chart(perMin, q + ' | timechart span=1m count', '-60m', 'Events per minute');
    chart(perHour, q + ' | timechart span=1h count', '-7d', 'Events per hour');
    try {
      const res = await search(q + ' | head 10', '-7d');
      latest.removeAttribute('aria-busy');
      const rows = res.rows || [];
      latest.replaceChildren(rows.length ? el('ol', { class: 'src-events' }, ...rows.map((r) => el('li', {},
        el('time', { class: 'src-events__t mono', datetime: r._time }, new Date(r._time).toLocaleString()),
        el('code', { class: 'src-events__raw' }, String(r._raw != null ? r._raw : JSON.stringify(r)).slice(0, 600)))))
        : el('p', { class: 'muted' }, 'No events in the last 7 days.'));
    } catch (e) {
      latest.removeAttribute('aria-busy');
      latest.replaceChildren(el('p', { class: 'muted' }, e.message));
    }
  }
}());
