// Dashboards: the built-in security posture summary, built-in panel
// dashboards such as Malware (read-only; they can be copied), and custom
// dashboards of query panels. Charts here are drawn with the shared .chart, .rank,
// .tip and .legend components; app.js keeps the Search page's charts.
// Everything lives in one function scope so these helpers never collide
// with the other page scripts, which share the global scope.
(() => {
  'use strict';

  const LEVELS = ['critical', 'high', 'medium', 'low', 'informational'];
  const LEVEL_LABEL = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', informational: 'Info' };
  const levelClass = (u) => 'c-' + (u === 'informational' || !LEVELS.includes(u) ? 'info' : u);
  const VIZ_LABEL = { single: 'Single value', table: 'Table', bar: 'Bar chart', line: 'Line chart', area: 'Stacked columns' };
  const WIDTH_LABEL = { third: 'Third', half: 'Half', full: 'Full width' };
  const RANGE_LABEL = { '15m': '15 minutes', '1h': 'hour', '4h': '4 hours', '24h': '24 hours', '7d': '7 days', '30d': '30 days' };
  const TOP = 8; // rows in each ranked list on the posture dashboard
  const KPI_ICON = {
    open_findings: 'shield-alert', new_findings: 'inbox', closed_findings: 'circle-check',
    mean_time_to_triage: 'timer', mean_time_to_resolve: 'clock', events_ingested: 'database',
  };

  const dash = {
    list: [], // [{id, title, builtin, ...}]
    off: '', // why custom dashboards are unavailable on this server
    listError: '',
    problems: [], // dashboard files that could not be loaded
    current: 'posture',
    def: null, // the selected custom dashboard
    range: '24h',
    auto: false, // auto-refresh on
    every: 60, // auto-refresh interval in seconds
    seq: 0, // ignores responses to superseded loads
    timer: null,
    loaded: false,
    updated: 0,
    failed: null,
    sevs: null, // detection id -> severity, for the glyphs in Top detections
    sevsAt: 0,
  };

  // The three kinds of dashboard: posture (computed), built-in panel
  // dashboards and custom ones.
  const BUILTIN_ICON = { posture: 'shield', malware: 'bug' };
  const kindOf = (id) => {
    if (id === 'posture') return 'posture';
    const meta = dash.list.find((d) => d.id === id);
    return (meta && meta.builtin) || (dash.def && dash.def.id === id && dash.def.builtin) ? 'builtin' : 'custom';
  };
  const isBuiltinPanels = () => kindOf(dash.current) === 'builtin';

  // ---------- small helpers ----------
  const put = (n, ...kids) => n.replaceChildren(...kids.filter((k) => k != null));
  const num = (v) => { const n = Number(v); return isFinite(n) ? n : 0; };
  const fmtNum = (v) => (typeof v === 'number' ? v.toLocaleString(undefined, { maximumFractionDigits: 2 }) : fmtValue(v));
  const plural = (n, one, many) => `${fmtCompact(n)} ${n === 1 ? one : many}`;
  const rangeWords = (r) => RANGE_LABEL[r] || r;
  const lastRange = (r) => 'last ' + rangeWords(r);
  // earliestWords turns a panel's earliest ("-24h", "0") into "last 24 hours".
  const earliestWords = (e) => (!e || e === '0' ? 'all time' : /^-/.test(e) ? lastRange(e.slice(1)) : 'since ' + e);
  const attrs = (base, extra) => Object.assign(base, ...Object.entries(extra || {}).filter(([, v]) => v != null && v !== false).map(([k, v]) => ({ [k]: v === true ? '' : v })));
  const SVGNS = 'http://www.w3.org/2000/svg';
  function svg(parent, tag, a, text) {
    const n = document.createElementNS(SVGNS, tag);
    for (const [k, v] of Object.entries(a || {})) n.setAttribute(k, TEXT_ATTRS.has(k) ? visibleText(v) : v);
    if (text !== undefined) n.textContent = visibleText(text);
    if (parent) parent.append(n);
    return n;
  }

  // Line charts are SVG drawn at the holder's pixel width and redrawn when
  // it changes, so text stays crisp.
  const observer = typeof ResizeObserver === 'function' ? new ResizeObserver((entries) => {
    for (const e of entries) {
      const w = Math.round(e.contentRect.width);
      if (e.target._draw && w && w !== e.target._drawnWidth) e.target._draw();
    }
  }) : null;
  function keepWidth(holder, draw) {
    holder._draw = () => { holder._drawnWidth = Math.round(holder.clientWidth); draw(holder._drawnWidth || 600); };
    holder._draw();
    if (observer) observer.observe(holder);
  }
  function forget(box) {
    if (observer && box) box.querySelectorAll('.db-line, .db-axis').forEach((h) => observer.unobserve(h));
  }

  // fmtDuration renders seconds as 45s, 12m, 3h 12m or 2d 4h.
  function durationParts(sec) {
    if (sec < 60) return [[Math.round(sec), 's']];
    const mins = Math.round(sec / 60);
    if (mins < 60) return [[mins, 'm']];
    const hours = Math.round(sec / 3600);
    if (sec < 86400) {
      const h = Math.floor(mins / 60), m = mins % 60;
      return m && h < 10 ? [[h, 'h'], [m, 'm']] : [[hours, 'h']];
    }
    const d = Math.floor(hours / 24), h = hours % 24;
    return h && d < 10 ? [[d, 'd'], [h, 'h']] : [[Math.round(sec / 86400), 'd']];
  }
  const fmtDuration = (sec) => (sec == null || !isFinite(sec) ? '–' : durationParts(sec).map(([n, u]) => n + u).join(' '));

  // numberParts splits 4.2M into "4.2" and a small "M".
  function numberParts(v, unit) {
    if (v == null || v === '') return ['–'];
    if (unit === 'seconds') return durationParts(Number(v)).flatMap(([n, u], i) => [(i ? ' ' : '') + n, el('small', {}, u)]);
    if (typeof v !== 'number' && !isFinite(Number(v))) return [String(v)];
    const s = fmtCompact(v);
    const m = /^(-?[\d.,]+)([kMB])$/.exec(s);
    return m ? [m[1], el('small', {}, m[2])] : [s];
  }

  // niceStep picks a tick step of 1, 2, 2.5 or 5 times a power of ten so
  // that four steps cover top. Counts get whole-number steps.
  function niceStep(top, whole) {
    const raw = Math.max(top, whole ? 1 : 1e-9) / 4;
    const p = Math.pow(10, Math.floor(Math.log10(raw)));
    for (const m of [1, 2, 2.5, 5, 10]) {
      const s = m * p;
      if (s >= raw && (!whole || Number.isInteger(s))) return s;
    }
    return 10 * p;
  }

  // ---------- shared pieces of markup ----------
  function card({ title, sub, actions = [], legend, cls }, ...content) {
    const subEl = el('div', { class: 'card__sub' }, sub || '');
    const legendSlot = el('div', { class: 'db-legend-slot' }, legend || null);
    const c = el('section', { class: 'card' + (cls ? ' ' + cls : '') },
      el('div', { class: 'card__head' },
        el('div', {}, el('h2', { class: 'card__title', title }, title), subEl),
        el('div', { class: 'card__actions' }, legendSlot, ...actions)),
      ...content);
    c._sub = subEl;
    c._legend = legendSlot;
    return c;
  }
  const pageLink = (text, page) => el('a', { class: 'btn btn--ghost btn--sm', href: '#' + page, 'data-page': page }, text, icon('arrow-right'));
  const searchButton = (query, earliest, label) => el('button', {
    class: 'btn btn--ghost btn--icon btn--sm', type: 'button', title: label || 'Open in Search', 'aria-label': label || 'Open in Search',
    onclick: () => openSearch(query, earliest),
  }, icon('search'));
  const smallButton = (text, iconName, onclick) => el('button', { class: 'btn btn--secondary btn--sm', type: 'button', onclick }, iconName ? icon(iconName) : null, text);
  // retry reloads what failed: the dashboard's definition, or its data.
  const retry = () => smallButton('Try again', 'refresh-cw', () => (dash.current !== 'posture' && !dash.def ? showDashboard(dash.current) : reloadDashboard({ busy: true })));

  function emptyState(iconName, title, text, action, tone, hint) {
    return el('div', attrs({ class: 'empty empty--compact' }, { 'data-tone': tone }),
      el('span', { class: 'empty__icon' }, icon(iconName)),
      el('div', { class: 'empty__title' }, title),
      text ? el('p', { class: 'empty__text' }, text) : null,
      action ? el('div', { class: 'empty__actions' }, action) : null,
      hint ? el('p', { class: 'empty__hint' }, hint) : null);
  }
  const errorState = (title, text, action) => emptyState('circle-alert', title, text, action, 'danger');
  const sectionError = (rep, ...names) => names.map((n) => (rep.errors || {})[n]).filter(Boolean).join('\n');
  const cardAlert = (tone, text) => el('div', { class: 'alert db-card-alert', 'data-tone': tone }, icon({ danger: 'circle-alert', info: 'info' }[tone] || 'triangle-alert'), el('p', {}, text));

  const sk = (w, h) => el('span', { class: 'skeleton', style: `width:${w}` + (h ? `;height:${h}px` : '') });
  const skRank = (n) => el('ul', { class: 'rank', role: 'list', 'aria-hidden': 'true' },
    ...Array.from({ length: n }, (_, i) => el('li', {}, el('span', { class: 'rank__label' }, sk(60 + (i * 13) % 30 + '%')), sk('100%', 6), sk('100%'))));
  const skChart = () => el('div', { class: 'db-sk-chart', 'aria-hidden': 'true' }, sk('100%', 160));

  // showDetection opens the Detections page filtered to one rule.
  function showDetection(id) {
    if ($('d-filter')) $('d-filter').value = id;
    if ($('d-show')) $('d-show').value = '';
    showPage('detections');
  }
  const note = (text) => el('p', { class: 'db-note' }, text);

  // ---------- deltas ----------
  // deltaFoot describes the change from the previous period: an arrow, the
  // change (absolute for small counts, else a percentage) and words.
  function deltaFoot(cur, prev, { better = '', unit = 'count', range = '24h' } = {}) {
    const secs = unit === 'seconds';
    const fmt = secs ? fmtDuration : fmtCompact;
    const c = Number(cur), p = Number(prev);
    const title = `Previous ${rangeWords(range)}: ${fmt(p)}`;
    if (!isFinite(c) || !isFinite(p)) return null;
    const dir = Math.sign(c - p);
    if (dir === 0) return el('div', { class: 'kpi__foot', title }, el('span', {}, 'Same as prev ' + range));
    let text;
    if (p === 0 || (!secs && Math.abs(p) < 10)) text = fmt(Math.abs(c - p));
    else {
      const pct = Math.abs((c - p) / p * 100);
      text = (pct >= 10 ? Math.round(pct).toLocaleString() : pct.toFixed(1)) + '%';
    }
    const good = !better ? 'flat' : String((dir > 0) === (better === 'up'));
    return el('div', { class: 'kpi__foot', title },
      el('span', { class: 'delta', 'data-good': good }, icon(dir > 0 ? 'arrow-up-right' : 'arrow-down-right'), el('span', { class: 'sr-only' }, dir > 0 ? 'up ' : 'down '), text),
      el('span', {}, secs ? (dir > 0 ? 'slower' : 'faster') : 'vs prev ' + range));
  }

  // ---------- charts ----------
  // seriesData reads a timechart: series names (more than eight fold into
  // Other), one array of values per row, a colour class and a label each.
  function seriesData(res, opts = {}) {
    const rows = res.rows || [];
    let series = opts.series || (res.columns || []).filter((c) => c !== '_time');
    let extra = [];
    if (!opts.classFor && series.length > 8) { extra = series.slice(7); series = series.slice(0, 7); }
    const names = extra.length ? [...series, 'Other'] : series;
    const values = rows.map((r) => names.map((nm, si) => (si === series.length ? extra.reduce((a, c) => a + num(r[c]), 0) : num(r[nm]))));
    return {
      rows, names, values,
      cls: (si) => (opts.classFor ? opts.classFor(names[si]) : 's-' + (si + 1)),
      label: (si) => (opts.nameFor ? opts.nameFor(names[si]) : names[si]),
      times: rows.map((r) => new Date(r._time)),
    };
  }

  function legendEl(d, extra) {
    return el('div', { class: 'legend' + (extra ? ' ' + extra : '') },
      ...d.names.map((_, si) => el('span', { class: d.cls(si) }, el('i'), d.label(si))));
  }

  // Times on the x axis: hours and minutes within two days, else dates.
  function timeText(times, now) {
    const day = 86400e3;
    const n = times.length;
    const span = n > 1 ? times[n - 1] - times[0] : 0;
    const step = n > 1 ? times[1] - times[0] : 0;
    const hm = (d) => d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit', hourCycle: 'h23' });
    const md = (d) => d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
    return {
      axis: (i) => (isNaN(times[i]) ? '' : now && i === n - 1 && n > 2 ? 'now' : span >= 2 * day ? md(times[i]) : hm(times[i])),
      tip: (i) => {
        const d = times[i];
        if (isNaN(d)) return '';
        if (step >= day) return md(d);
        const start = span > day ? md(d) + ', ' + hm(d) : hm(d);
        const end = now && i === n - 1 ? 'now' : step ? hm(new Date(+d + step)) : '';
        return end ? `${start} – ${end}` : start;
      },
      bucket: step >= day ? 'day' : step >= 3600e3 ? (step === 3600e3 ? 'hour' : `${step / 3600e3} hours`) : step ? `${Math.round(step / 60e3)} minutes` : '',
    };
  }

  // labelIndexes picks which buckets get an x label: at most count, about
  // one per 72px of width, always the first and the last.
  const LABEL_PX = 72;
  function labelIndexes(n, count, width) {
    if (width) count = Math.min(count, Math.max(2, Math.floor(width / LABEL_PX)));
    if (n <= count) return [...Array(n).keys()];
    const step = Math.ceil(n / count);
    const out = [];
    for (let i = 0; i <= n - 1 - Math.ceil(step * 0.8); i += step) out.push(i);
    out.push(n - 1);
    return out;
  }

  function fillTip(tip, title, totalText, d, i) {
    put(tip,
      el('div', { class: 'tip__title' }, title, totalText ? el('span', {}, totalText) : null),
      ...d.names.map((_, si) => el('div', { class: 'tip__row ' + d.cls(si) }, el('i'), el('span', { class: 'db-tip-name' }, d.label(si)), el('b', {}, fmtNum(d.values[i][si])))));
    tip.hidden = false;
  }
  // placeTip puts the tooltip beside x (px within its box), flipping left
  // near the right edge.
  function placeTip(tip, x, gap, boxWidth) {
    const w = tip.offsetWidth;
    let left = x + gap;
    if (left + w > boxWidth) left = x - gap - w;
    tip.style.left = Math.max(0, left) + 'px';
  }

  // columnChart draws stacked columns, one per time bucket, with a y axis,
  // a few time labels and one tooltip. opts: series, classFor, nameFor,
  // unit [one, many], now (the last bucket ends now), labels (count), label.
  function columnChart(res, opts = {}) {
    const d = seriesData(res, opts);
    const n = d.rows.length;
    const totals = d.values.map((vs) => vs.reduce((a, v) => a + Math.max(0, v), 0));
    const whole = d.values.every((vs) => vs.every(Number.isInteger));
    const step = niceStep(Math.max(0, ...totals), whole);
    const ymax = step * 4;
    const yl = [0, 1, 2, 3, 4].map((k) => fmtCompact(step * k));
    const yw = Math.max(24, Math.max(...yl.map((t) => t.length)) * 7 + 10);
    const tt = timeText(d.times, opts.now);
    const unit = opts.unit || ['', ''];
    const totalText = (v) => (unit[0] ? plural(v, unit[0], unit[1]) : fmtCompact(v));
    const peak = totals.indexOf(Math.max(...totals));
    const summary = `${opts.label || 'Chart'}: ${totalText(totals.reduce((a, v) => a + v, 0))} in total` + (totals[peak] ? `, most at ${tt.tip(peak)} (${fmtCompact(totals[peak])})` : '');

    const cols = el('div', { class: 'cols', role: 'img', 'aria-label': summary, style: `--cmax:${ymax}` },
      ...d.values.map((vs, i) => el('div', { class: 'col', 'data-i': i },
        ...vs.map((v, si) => (v > 0 ? el('i', { class: d.cls(si), style: `--v:${v}` }) : null)).filter(Boolean))));
    const tip = el('div', { class: 'tip', role: 'tooltip', hidden: '' });
    const area = el('div', { class: 'chart__area' }, el('div', { class: 'chart__grid' }), cols, tip);
    let hover = null;
    cols.addEventListener('mouseover', (ev) => {
      const c = ev.target.closest('.col');
      if (!c || c === hover) return;
      if (hover) hover.classList.remove('is-hover');
      hover = c;
      c.classList.add('is-hover');
      const i = Number(c.dataset.i);
      fillTip(tip, tt.tip(i), totalText(totals[i]), d, i);
      const colW = area.clientWidth / n;
      placeTip(tip, (i + 0.5) * colW, colW / 2 + 6, area.clientWidth);
    });
    cols.addEventListener('mouseleave', () => {
      tip.hidden = true;
      if (hover) hover.classList.remove('is-hover');
      hover = null;
    });
    const x = el('div', { class: 'chart__x db-axis', 'aria-hidden': 'true' });
    keepWidth(x, (W) => put(x, ...labelIndexes(n, opts.labels || 7, W).map((i) => el('span', { style: `left:${((i + 0.5) / n * 100).toFixed(2)}%` }, tt.axis(i)))));
    const multi = d.names.length > 1;
    const node = el('div', { class: 'chart db-chart', style: `--yw:${yw}px` },
      el('div', { class: 'chart__plot' },
        el('div', { class: 'chart__y', 'aria-hidden': 'true' }, ...yl.map((t, k) => el('span', { style: `bottom:${k * 25}%` }, t))),
        area),
      x,
      multi ? legendEl(d, opts.legendInHead ? 'show-sm db-legend-below' : 'db-legend-below') : null);
    return { node, legend: multi && opts.legendInHead ? legendEl(d, 'hide-sm') : null, bucket: tt.bucket, totals };
  }

  // lineChart draws one line per series, for panels shown as a line chart.
  function lineChart(res, opts = {}) {
    const d = seriesData(res, opts);
    const n = d.rows.length;
    const flat = d.values.flat();
    const whole = flat.every(Number.isInteger);
    const lo = Math.min(0, ...flat), hi = Math.max(0, ...flat);
    const step = niceStep(hi - lo || (whole ? 4 : 1), whole);
    const ymin = lo < 0 ? Math.floor(lo / step) * step : 0;
    const ymax = Math.max(ymin + step * 4, Math.ceil(hi / step) * step);
    const ticks = Math.round((ymax - ymin) / step);
    const yl = Array.from({ length: ticks + 1 }, (_, k) => ymin + k * step);
    const yw = Math.max(24, Math.max(...yl.map((v) => fmtCompact(v).length)) * 7 + 10);
    const tt = timeText(d.times, opts.now);
    const holder = el('div', { class: 'db-line' });
    const tip = el('div', { class: 'tip', role: 'tooltip', hidden: '' });
    const plot = el('div', { class: 'db-plot' }, holder, tip);
    const summary = `${opts.label || 'Line chart'}: ${d.names.map((_, si) => d.label(si)).join(', ')}`;
    keepWidth(holder, (W) => {
      const H = 200, T = 8, B = 24, R = 6, L = yw;
      const pw = Math.max(10, W - L - R), ph = H - T - B;
      const xAt = (i) => L + (n === 1 ? pw / 2 : i * pw / (n - 1));
      const yAt = (v) => T + ph * (1 - (v - ymin) / (ymax - ymin));
      const s = svg(null, 'svg', { class: 'chart-svg', width: W, height: H, viewBox: `0 0 ${W} ${H}`, role: 'img', 'aria-label': summary });
      yl.forEach((v) => {
        svg(s, 'line', { x1: L, x2: W - R, y1: yAt(v), y2: yAt(v), class: 'grid-line' });
        svg(s, 'text', { x: L - 8, y: yAt(v) + 4, 'text-anchor': 'end' }, fmtCompact(v));
      });
      labelIndexes(n, opts.labels || 7, pw).forEach((i) => {
        const anchor = n > 1 && i === 0 ? 'start' : n > 1 && i === n - 1 ? 'end' : 'middle';
        svg(s, 'text', { x: xAt(i), y: H - 6, 'text-anchor': anchor }, tt.axis(i));
      });
      d.names.forEach((_, si) => {
        const pts = d.values.map((vs, i) => `${xAt(i).toFixed(1)},${yAt(vs[si]).toFixed(1)}`);
        if (n === 1) svg(s, 'circle', { class: 'pt ' + d.cls(si), cx: xAt(0), cy: yAt(d.values[0][si]), r: 3.5 });
        else svg(s, 'polyline', { class: 'ln ' + d.cls(si), points: pts.join(' ') });
      });
      const guide = svg(s, 'line', { class: 'guide', y1: T, y2: T + ph, visibility: 'hidden' });
      const dots = svg(s, 'g', { visibility: 'hidden' });
      const hit = svg(s, 'rect', { x: L, y: T, width: pw, height: ph, fill: 'transparent' });
      let last = -1;
      hit.addEventListener('mousemove', (ev) => {
        const r = s.getBoundingClientRect();
        const i = n === 1 ? 0 : Math.max(0, Math.min(n - 1, Math.round((ev.clientX - r.left - L) / (pw / (n - 1)))));
        if (i === last) return;
        last = i;
        guide.setAttribute('x1', xAt(i));
        guide.setAttribute('x2', xAt(i));
        guide.setAttribute('visibility', 'visible');
        dots.replaceChildren();
        d.names.forEach((_, si) => svg(dots, 'circle', { class: 'pt ' + d.cls(si), cx: xAt(i), cy: yAt(d.values[i][si]), r: 3.5 }));
        dots.setAttribute('visibility', 'visible');
        fillTip(tip, tt.tip(i), d.names.length > 1 ? fmtCompact(d.values[i].reduce((a, v) => a + v, 0)) : '', d, i);
        placeTip(tip, xAt(i), 12, W);
      });
      hit.addEventListener('mouseleave', () => {
        last = -1;
        guide.setAttribute('visibility', 'hidden');
        dots.setAttribute('visibility', 'hidden');
        tip.hidden = true;
      });
      holder.replaceChildren(s);
    });
    const multi = d.names.length > 1;
    return {
      node: el('div', { class: 'chart db-chart' }, plot, multi ? legendEl(d, opts.legendInHead ? 'show-sm db-legend-below' : 'db-legend-below') : null),
      legend: multi && opts.legendInHead ? legendEl(d, 'hide-sm') : null,
    };
  }

  // rankList draws a ranked list: label, a short inline bar, the value.
  // items: [{label, value, title, mono, iconName, type, sev, band, href, onclick}]
  function rankList(items, opts = {}) {
    const max = Math.max(opts.min || 0, ...items.map((it) => it.value)) || 1;
    const glyphs = items.some((it) => it.sev);
    return el('ul', { class: 'rank', role: 'list' }, ...items.map((it) => {
      const text = it.onclick
        ? el('a', { class: 'rank__link' + (it.mono ? ' mono' : ''), href: it.href || '#', onclick: (ev) => { ev.preventDefault(); it.onclick(); } }, it.label)
        : el('span', { class: it.mono ? 'mono' : '' }, it.label);
      let lead = null;
      if (it.sev) lead = el('span', { class: 'sev sev--glyph', 'data-sev': it.sev, role: 'img', 'aria-label': (LEVEL_LABEL[it.sev] || it.sev) + ' severity' });
      else if (glyphs) lead = el('span', { class: 'db-glyph-pad', 'aria-hidden': 'true' });
      else if (it.iconName) lead = icon(it.iconName);
      const pct = it.value > 0 ? Math.max(2, Math.min(100, (it.value / max) * 100)) : 0;
      return el('li', { title: it.title || '' },
        el('span', { class: 'rank__label' }, lead, text, it.type ? el('span', { class: 'rank__type' }, it.type) : null),
        el('span', attrs({ class: 'rank__bar', 'aria-hidden': 'true' }, { 'data-band': it.band }), el('span', { style: `--w:${pct.toFixed(1)}%` })),
        el('span', { class: 'rank__value' }, fmtCompact(it.value)));
    }));
  }

  // ---------- loading ----------
  async function loadDashboardList() {
    let res;
    try {
      res = await api('api/dashboards');
      dash.listError = '';
    } catch (e) {
      res = { dashboards: [{ id: 'posture', title: 'Security posture', builtin: true }] };
      dash.listError = e.message;
    }
    dash.list = res.dashboards || [];
    dash.off = res.error || '';
    dash.problems = res.problems || [];
    if (!dash.list.some((d) => d.id === dash.current)) dash.current = 'posture';
    renderMenu();
    renderProblems();
  }

  function renderProblems() {
    const box = $('db-problems');
    const n = dash.problems.length;
    const items = dash.problems.map((p) => el('p', {}, el('code', {}, p.file), ' ', p.error));
    if (dash.listError) items.unshift(el('p', {}, dash.listError));
    const title = dash.listError ? 'Your dashboards could not be listed.' : `${n} dashboard file${n === 1 ? '' : 's'} could not be loaded.`;
    put(box, icon('triangle-alert'), el('div', {}, el('b', {}, title), ...items));
    box.classList.toggle('hidden', !items.length);
  }

  // The dashboard switcher: every dashboard, then New dashboard.
  function renderMenu() {
    const close = () => $('db-switch').removeAttribute('open');
    const items = dash.list.map((d) => {
      const cur = d.id === dash.current;
      return el('button', attrs({ class: 'menu__item', type: 'button', 'data-id': d.id, onclick: () => { close(); showDashboard(d.id); } }, { 'aria-current': cur ? 'true' : null }),
        icon(d.builtin ? BUILTIN_ICON[d.id] || 'shield' : 'layout-dashboard'), el('span', {}, d.title),
        d.builtin ? el('span', { class: 'badge' }, 'Built-in') : null,
        cur ? icon('check', 'db-check') : null);
    });
    // Viewers can open dashboards but not make them (data-min-role).
    put($('db-menu'), ...items, el('div', { class: 'menu__sep', 'data-min-role': 'analyst' }),
      el('button', { class: 'menu__item', type: 'button', 'data-min-role': 'analyst', onclick: () => { close(); openDashboardEditor(true); } }, icon('plus'), el('span', {}, 'New dashboard')));
  }

  function setHeader(id) {
    const meta = dash.list.find((d) => d.id === id) || {};
    const kind = kindOf(id);
    const custom = id !== 'posture'; // has panels
    const title = (custom && dash.def && dash.def.id === id ? dash.def.title : meta.title) || (custom ? id : 'Security posture');
    $('db-name').textContent = title;
    $('db-switch-icon').replaceChildren(icon(kind === 'custom' ? 'layout-dashboard' : BUILTIN_ICON[id] || 'shield'));
    $('db-builtin').classList.toggle('hidden', kind === 'custom');
    $('db-tools').classList.toggle('hidden', !custom);
    $('db-new').classList.toggle('hidden', custom);
    // Built-in panel dashboards can't be changed, only copied (when this
    // server keeps custom dashboards) and downloaded.
    $('db-edit').classList.toggle('hidden', kind !== 'custom');
    $('db-add').classList.toggle('hidden', kind !== 'custom');
    $('db-copy').classList.toggle('hidden', kind !== 'builtin' || !!dash.off);
    if (custom) $('db-desc').textContent = (dash.def && dash.def.id === id ? dash.def.description : meta.description) || '';
    else $('db-desc').textContent = `Findings, triage speed, risk and data health, each compared with the previous ${rangeWords(dash.range)}.`;
    $('db-desc').classList.toggle('hidden', !$('db-desc').textContent);
  }

  async function showDashboard(id) {
    dash.current = id;
    closeEditor();
    renderMenu();
    const custom = id !== 'posture';
    if (!custom) {
      dash.def = null;
      setHeader(id);
      setAutoRefresh();
      return loadPosture();
    }
    dash.def = null;
    setHeader(id);
    const seq = ++dash.seq;
    const body = $('db-body');
    if (body.dataset.view !== id) {
      forget(body);
      body.dataset.view = 'loading';
      put(body, el('div', { class: 'db-grid' }, ...[0, 1, 2].map(() => el('div', { class: 'card db-panel db-w-third' }, el('div', { class: 'card__head' }, sk('40%')), panelSkeleton('single')))));
    }
    let def;
    try {
      def = await api('api/dashboards/' + encodeURIComponent(id));
    } catch (e) {
      if (seq === dash.seq) {
        // Without its definition there is nothing to edit or add to.
        $('db-tools').classList.add('hidden');
        $('db-new').classList.remove('hidden');
        showBodyError('Couldn’t open this dashboard', e.message);
      }
      return;
    }
    if (seq !== dash.seq) return;
    dash.def = def;
    setHeader(id);
    $('db-yaml').href = 'api/dashboards/' + encodeURIComponent(id) + '/yaml';
    setRange(def.time_range);
    const every = parseEvery(def.refresh);
    if (every) {
      dash.every = every;
      dash.auto = true;
    }
    setAutoRefresh();
    return runDashboard();
  }

  function showBodyError(title, text) {
    const body = $('db-body');
    forget(body);
    body.dataset.view = 'error';
    delete body.dataset.stale;
    body.setAttribute('aria-busy', 'false');
    put(body, el('div', { class: 'card' }, errorState(title, text, retry())));
    dash.updated = 0;
    dash.failed = null;
    renderStamp();
  }

  // refreshFailed keeps the numbers on screen when a refresh fails and says
  // so beside the Refresh button.
  function refreshFailed(e) {
    const body = $('db-body');
    delete body.dataset.stale;
    body.setAttribute('aria-busy', 'false');
    dash.failed = e.message || 'unknown error';
    renderStamp();
  }

  // reloadDashboard reruns the current dashboard. opts.busy dims the old
  // numbers until the new ones arrive (for changes the user asked for).
  function reloadDashboard(opts = {}) {
    if (dash.current === 'posture') return loadPosture(opts);
    return dash.def ? runDashboard({ keep: true, ...opts }) : showDashboard(dash.current);
  }

  function markUpdated() {
    dash.updated = Date.now();
    dash.failed = null;
    const body = $('db-body');
    delete body.dataset.stale;
    body.setAttribute('aria-busy', 'false');
    renderStamp();
  }

  function sinceText(t) {
    const s = Math.max(0, Math.round((Date.now() - t) / 1000));
    if (s < 10) return 'just now';
    if (s < 60) return Math.floor(s / 5) * 5 + 's ago';
    if (s < 3600) return Math.floor(s / 60) + 'm ago';
    return Math.floor(s / 3600) + 'h ago';
  }
  function everyText(sec) {
    const [n, unit] = sec % 3600 === 0 ? [sec / 3600, 'hour'] : sec % 60 === 0 ? [sec / 60, 'minute'] : [sec, 'second'];
    return n === 1 ? 'every ' + unit : `every ${n} ${unit}s`;
  }

  function renderStamp() {
    const live = dash.auto && !dash.failed;
    $('db-live').classList.toggle('hidden', !live || !dash.updated);
    // Nothing loaded yet, or the body shows its own Try again.
    $('db-reload').classList.toggle('hidden', live || (!dash.updated && !dash.failed));
    const t = $('db-updated');
    t.classList.toggle('db-stamp-error', !!dash.failed);
    if (dash.failed) {
      const at = new Date(dash.updated).toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit', hourCycle: 'h23' });
      t.textContent = 'Couldn’t refresh: ' + dash.failed + (dash.updated ? ` · showing data from ${at}` : '');
      t.title = '';
      return;
    }
    if (!dash.updated) { t.textContent = ''; return; }
    $('db-every').classList.toggle('hidden', !live || !dash.updated);
    t.textContent = live ? `· updated ${sinceText(dash.updated)} ·` : `Updated ${sinceText(dash.updated)}`;
    t.title = new Date(dash.updated).toLocaleString();
  }

  // ---------- time range ----------
  const rangeButtons = () => [...$('db-range').querySelectorAll('button[data-range]')];
  function setRange(r) {
    if (!r) return;
    r = String(r).replace(/^-/, '');
    if (!rangeButtons().some((b) => b.dataset.range === r)) {
      $('db-range').append(el('button', { type: 'button', 'data-range': r, title: 'Last ' + rangeWords(r) }, r));
    }
    dash.range = r;
    rangeButtons().forEach((b) => b.setAttribute('aria-pressed', String(b.dataset.range === r)));
  }

  // ---------- security posture ----------
  async function loadSeverities() {
    if (dash.sevsAt && Date.now() - dash.sevsAt < 5 * 60e3) return;
    try {
      const res = await api('api/detections');
      dash.sevs = Object.fromEntries((res.detections || []).map((d) => [d.id, d.severity]));
      dash.sevsAt = Date.now();
    } catch (_) { /* the severity glyphs are optional */ }
  }

  async function loadPosture(opts = {}) {
    const seq = ++dash.seq;
    const range = dash.range;
    const body = $('db-body');
    setHeader('posture');
    if (body.dataset.view !== 'posture') {
      forget(body);
      body.dataset.view = 'posture-loading';
      put(body, ...postureSkeleton());
    } else if (opts.busy) body.dataset.stale = '';
    body.setAttribute('aria-busy', 'true');
    let rep;
    try {
      [rep] = await Promise.all([api('api/posture?range=' + encodeURIComponent(range)), loadSeverities()]);
    } catch (e) {
      if (seq !== dash.seq) return;
      if (body.dataset.view === 'posture') refreshFailed(e);
      else showBodyError('Couldn’t load the security posture', e.message);
      return;
    }
    if (seq !== dash.seq) return;
    renderPosture(rep);
    markUpdated();
  }

  function postureSkeleton() {
    const kpi = () => el('div', { class: 'card kpi', 'aria-hidden': 'true' }, sk('55%'), el('div', { class: 'db-sk-value' }, sk('40%', 28)), sk('70%'));
    return [
      el('div', { class: 'kpis' }, ...Array.from({ length: 6 }, kpi)),
      card({ title: 'New findings by urgency', sub: sk('8em') }, el('div', { class: 'chart' }, skChart())),
      el('div', { class: 'grid-2' },
        card({ title: 'Top detections firing', sub: 'Findings and risk events' }, skRank(5)),
        card({ title: 'Top risk objects', sub: 'Accumulated risk score' }, skRank(5))),
    ];
  }

  function renderPosture(rep) {
    const body = $('db-body');
    forget(body);
    body.dataset.view = 'posture';
    put(body,
      rep.findings_truncated ? el('div', { class: 'alert', 'data-tone': 'info' }, icon('info'), el('p', {}, 'Finding counts are approximate: there are more findings in this period than one request returns.')) : null,
      kpiRow(rep),
      findingsCard(rep),
      el('div', { class: 'grid-2' }, detectionsCard(rep), riskCard(rep)),
      el('div', { class: 'grid-2' }, tacticsCard(rep), healthCard(rep)),
      el('div', { class: 'grid-2' }, datamodelCard(rep), sourcetypeCard(rep)));
  }

  const rowTotals = (res) => (res && res.rows ? res.rows.map((r) => (res.columns || []).filter((c) => c !== '_time').reduce((a, c) => a + num(r[c]), 0)) : []);

  function kpiRow(rep) {
    const sparks = { new_findings: rowTotals(rep.findings_over_time), events_ingested: rowTotals(rep.events_by_datamodel) };
    return el('div', { class: 'kpis' }, ...(rep.indicators || []).map((ind) => kpiTile(ind, rep, sparks[ind.id])));
  }

  function kpiTile(ind, rep, spark) {
    const link = ind.id === 'open_findings' || ind.id === 'new_findings';
    const tile = el(link ? 'a' : 'div', attrs({ class: 'card kpi', title: ind.help || '' }, link ? { href: '#findings', 'data-page': 'findings' } : {}),
      el('div', { class: 'kpi__label' }, icon(KPI_ICON[ind.id] || 'activity'), el('span', {}, ind.label)),
      el('div', { class: 'kpi__value' }, ...(ind.error ? ['–'] : numberParts(ind.value, ind.unit))),
      kpiFoot(ind, rep));
    if (ind.error) return tile;
    if (ind.id === 'open_findings') tile.append(...urgencyBar(rep.open_by_urgency || {}));
    else if (spark && spark.length > 1) tile.append(sparkline(spark));
    return tile;
  }

  function kpiFoot(ind, rep) {
    const foot = (text) => el('div', { class: 'kpi__foot' }, el('span', {}, text));
    if (ind.error) return el('div', { class: 'kpi__foot db-err', title: ind.error }, icon('circle-alert', 'icon--xs'), el('span', {}, 'Couldn’t load'));
    if (ind.value == null) return foot('None in this period');
    if (ind.id === 'open_findings') return foot(ind.value ? 'In the queue now' : 'Queue is clear');
    if (ind.previous == null) return foot(lastRange(rep.range));
    return deltaFoot(ind.value, ind.previous, { better: ind.better, unit: ind.unit, range: rep.range });
  }

  function urgencyBar(by) {
    const parts = LEVELS.filter((u) => by[u] > 0);
    if (!parts.length) return [];
    const words = (u) => `${by[u]} ${LEVEL_LABEL[u].toLowerCase()}`;
    return [
      el('div', { class: 'sevbar', role: 'img', 'aria-label': parts.map(words).join(', ') }, ...parts.map((u) => el('span', { class: levelClass(u), style: `flex:${by[u]}` }))),
      el('div', { class: 'sevbar__legend', 'aria-hidden': 'true' }, ...parts.slice(0, 2).map((u) => el('span', { class: levelClass(u) }, el('i'), words(u)))),
    ];
  }

  // sparkline: a neutral line with one dot for now.
  function sparkline(values) {
    const n = values.length;
    const max = Math.max(...values), min = Math.min(...values);
    const span = max - min || 1;
    const y = (v) => (max === min ? 24 : 24 - (v - min) / span * 20);
    const s = svg(null, 'svg', { viewBox: '0 0 100 28', preserveAspectRatio: 'none' });
    svg(s, 'path', { d: values.map((v, i) => `${i ? 'L' : 'M'}${(i / (n - 1) * 100).toFixed(1)} ${y(v).toFixed(1)}`).join('') });
    return el('div', { class: 'spark', 'aria-hidden': 'true' }, s, el('i', { style: `top:${(y(values[n - 1]) / 28 * 100).toFixed(1)}%` }));
  }

  function findingsCard(rep) {
    const res = rep.findings_over_time;
    const err = sectionError(rep, 'findings');
    const range = lastRange(rep.range);
    const total = rowTotals(res).reduce((a, v) => a + v, 0);
    let content, legend = null, title = 'New findings by urgency';
    if (err) content = errorState('Couldn’t load findings', err, retry());
    else if (!res || !total) content = emptyState('shield-check', 'No new findings', `Nothing was raised in the ${range}. New findings show here as detections fire.`);
    else {
      const ch = columnChart(res, {
        series: (res.columns || []).filter((c) => c !== '_time'), classFor: levelClass, nameFor: (u) => LEVEL_LABEL[u] || u,
        unit: ['finding', 'findings'], now: true, labels: 7, legendInHead: true, label: 'New findings by urgency, ' + range,
      });
      content = ch.node;
      legend = ch.legend;
      if (ch.bucket) title = 'New findings by ' + ch.bucket;
    }
    // the time range is in the header's segment, so card subtitles leave it out
    return card({ title, sub: err ? '' : `${plural(total, 'finding', 'findings')} · by urgency`, legend, actions: [pageLink('Open queue', 'findings')] }, content);
  }

  function detectionsCard(rep) {
    const err = sectionError(rep, 'findings', 'top_detections');
    const list = rep.top_detections || [];
    const items = list.map((d) => ({
      label: d.title, value: d.findings + d.risk_events, sev: dash.sevs && dash.sevs[d.id],
      title: [d.findings ? plural(d.findings, 'finding', 'findings') : '', d.risk_events ? plural(d.risk_events, 'risk event', 'risk events') : ''].filter(Boolean).join(' · '),
      href: '#detections', onclick: () => showDetection(d.id),
    }));
    let content;
    if (items.length) content = rankList(items.slice(0, TOP));
    else if (err) content = errorState('Couldn’t count detections', err, retry());
    else content = emptyState('crosshair', 'No detection fired', `Detections that raise findings or risk in the ${lastRange(rep.range)} show here.`);
    return card({ title: 'Top detections firing', sub: 'Findings and risk events', actions: [pageLink('All detections', 'detections')] },
      items.length && err ? cardAlert('danger', err) : null, content);
  }

  // riskBand comes from risk.js, so a score has the same colour here and on the Risk page.
  function riskCard(rep) {
    const err = sectionError(rep, 'risk_objects');
    const q = rep.queries || {};
    const items = (rep.top_risk_objects || []).map((r) => {
      const score = num(r.risk_score);
      const name = String(r.risk_object);
      return {
        label: name, mono: true, type: r.risk_object_type, value: score, band: riskBand(score),
        iconName: looksLikeIP(name) ? 'globe' : r.risk_object_type === 'user' ? 'user' : 'server',
        title: `Risk ${fmtValue(score)} · ${plural(num(r.events), 'event', 'events')} · ${plural(num(r.detections), 'detection', 'detections')}`,
        href: '#risk', onclick: () => { showPage('risk'); if (typeof showRiskObject === 'function') showRiskObject(r.risk_object, r.risk_object_type); },
      };
    });
    let content;
    if (err) content = errorState('Couldn’t load risk', err, retry());
    else if (!items.length) content = emptyState('gauge', 'No risk in this period', 'Risk builds up when detections with a risk score match a user or system.');
    else content = rankList(items.slice(0, TOP), { min: 100 });
    return card({
      title: 'Top risk objects', sub: 'Accumulated risk score',
      actions: [searchButton(q.risk_objects, '-' + rep.range, 'Open the risk query in Search'), pageLink('Open Risk', 'risk')],
    }, content);
  }

  function tacticsCard(rep) {
    const err = sectionError(rep, 'tactics');
    const items = (rep.tactics || []).map((t) => ({
      label: t.name, value: t.findings + t.risk_events,
      title: [t.findings ? plural(t.findings, 'finding', 'findings') : '', t.risk_events ? plural(t.risk_events, 'risk event', 'risk events') : ''].filter(Boolean).join(' · '),
    })).sort((a, b) => b.value - a.value);
    let content;
    if (items.length) content = rankList(items.slice(0, TOP));
    else if (err) content = errorState('Couldn’t load ATT&CK tactics', err, retry());
    else content = emptyState('grid-3x3', 'No ATT&CK activity', 'Findings and risk events mapped to ATT&CK show here by tactic.');
    const shown = items.length > TOP ? `Top ${TOP} of ${items.length} · ` : '';
    return card({ title: 'ATT&CK tactics seen', sub: shown + 'Findings and risk events', actions: [pageLink('Coverage', 'coverage')] },
      items.length && err ? cardAlert('danger', err) : null, content);
  }

  function healthCard(rep) {
    const h = rep.health;
    const err = sectionError(rep, 'health', 'sources');
    if (!h) return card({ title: 'Detection health' }, errorState('Couldn’t check detection health', err || 'Not available on this server.', retry()));
    const erroring = h.erroring || [], silent = h.silent || [], stale = h.stale_sources || [];
    const stat = (value, small, label, tone, title) => el('div', attrs({ class: 'db-hstat', title: title || '' }, { 'data-tone': tone }),
      el('b', {}, value, small ? el('small', {}, small) : null), el('span', {}, label));
    const detLink = (d) => el('a', { class: 'db-issue__name', href: '#detections', onclick: (ev) => { ev.preventDefault(); showDetection(d.id); } }, d.title || d.id);
    const issues = (title, count, items) => (items.length ? el('div', { class: 'db-issues' },
      el('div', { class: 'section-title' }, title, el('span', { class: 'count' }, String(count))),
      el('ul', { class: 'db-issue-list', role: 'list' }, ...items)) : null);
    // On a server that does not run the detections, their run times and
    // errors are on the one that does.
    const away = !!h.runs_elsewhere;
    const sub = away ? (h.runs_on ? `Run on ${h.runs_on}` : 'Not running') : h.scheduler_on ? 'Scheduler on' : 'Scheduler off';
    const none = el('span', {}, el('span', { 'aria-hidden': 'true' }, '–'), el('span', { class: 'sr-only' }, 'Not known here'));
    let note = null;
    if (away && h.runs_on) note = cardAlert('info', `Detections run on ${h.runs_on}. Their run times and errors are shown there.`);
    else if (away) note = cardAlert('danger', 'No server runs detections right now.' + (can('admin') ? ' The Servers page says why.' : ' An admin needs to look.'));
    else if (!h.scheduler_on) note = cardAlert('warning', 'The scheduler is off on this server, so detections only run when you click Run now.');
    return card({ title: 'Detection health', sub, actions: [pageLink('Detections', 'detections')] },
      el('div', { class: 'db-hstats' },
        stat(String(h.enabled), ` of ${h.total}`, 'detections on', null, h.not_run ? `${h.not_run} enabled detections have not run since the server started` : ''),
        away ? stat(none, '', 'erroring', null, h.runs_on ? `Shown on ${h.runs_on}` : '') : stat(String(erroring.length), '', 'erroring', erroring.length ? 'danger' : null),
        stat(String(silent.length), '', `no match in ${h.silent_window}`, null, 'Enabled detections with no findings and no risk events. They may need tuning, or the data they need may be missing.'),
        stat(String(stale.length), ` of ${h.sources}`, 'sources stopped', stale.length ? 'warning' : null, `Hosts and source types seen in the last ${h.source_lookback} with nothing in the last ${h.stale_after}`)),
      err ? cardAlert('danger', err) : null,
      note,
      issues('Erroring', erroring.length, erroring.map((d) => el('li', {}, detLink(d), el('span', { class: 'db-issue__meta', title: d.error }, d.error)))),
      issues(`Stopped sending for ${h.stale_after}+`, stale.length, stale.map((s) => el('li', {},
        el('span', { class: 'db-issue__name mono' }, s.host), el('span', { class: 'db-issue__meta' }, `${s.sourcetype} · last event ${ago(s.last_seen)}`)))),
      silent.length ? el('details', { class: 'db-more' },
        el('summary', {}, icon('chevron-right', 'db-more__chev'), el('span', {}, `No match in ${h.silent_window}`), el('span', { class: 'count' }, String(silent.length))),
        el('ul', { class: 'db-issue-list', role: 'list' }, ...silent.map((d) => el('li', {}, detLink(d))))) : null);
  }

  function datamodelCard(rep) {
    const res = rep.events_by_datamodel;
    const err = sectionError(rep, 'events_by_datamodel');
    const q = rep.queries || {};
    const total = rowTotals(res).reduce((a, v) => a + v, 0);
    let content;
    if (err) content = errorState('Couldn’t count events', err, retry());
    else if (!res || !total) content = emptyState('database', 'No events in this period', 'Check the Health page to confirm data is arriving.', smallButton('Open Health', null, () => showPage('health')), null, typeof samplePointer === 'function' ? samplePointer() : null);
    else content = columnChart(res, { unit: ['event', 'events'], now: true, labels: 5, label: 'Events by data model, ' + lastRange(rep.range) }).node;
    return card({ title: 'Events by data model', sub: err ? '' : plural(total, 'event', 'events'), actions: [searchButton(q.events_by_datamodel, '-' + rep.range)] }, content);
  }

  function sourcetypeCard(rep) {
    const res = rep.events_by_sourcetype;
    const err = sectionError(rep, 'events_by_sourcetype');
    const q = rep.queries || {};
    const names = res ? (res.columns || []).filter((c) => c !== '_time') : [];
    const items = names.map((nm) => ({
      label: nm, mono: true, value: (res.rows || []).reduce((a, r) => a + num(r[nm]), 0), href: '#search',
      onclick: () => openSearch('sourcetype=' + quoteValue(nm), '-' + rep.range),
    })).filter((it) => it.value > 0).sort((a, b) => b.value - a.value).slice(0, TOP);
    items.forEach((it) => { it.title = `${plural(it.value, 'event', 'events')}. Open these events in Search.`; });
    let content;
    if (err) content = errorState('Couldn’t count events', err, retry());
    else if (!items.length) content = emptyState('database', 'No events in this period', 'Check the Health page to confirm data is arriving.');
    else content = rankList(items);
    return card({ title: 'Events by source type', sub: err ? '' : plural(names.length, 'source type', 'source types'), actions: [searchButton(q.events_by_sourcetype, '-' + rep.range)] }, content);
  }

  // ---------- custom dashboards ----------
  function panelQuery(p, pr) {
    return [p.query, pr && pr.earliest ? pr.earliest : '-' + dash.range];
  }

  function panelSkeleton(viz) {
    if (viz === 'single') return el('div', { class: 'db-single', 'aria-hidden': 'true' }, el('div', { class: 'db-sk-value' }, sk('35%', 28)), sk('55%'));
    if (viz === 'line' || viz === 'area') return el('div', { class: 'chart' }, skChart());
    return skRank(4);
  }

  // panelCard is one panel: title, time range, legend and an actions menu.
  function panelCard(p, i, n, preview, readOnly) {
    const body = el('div', { class: 'db-panel__body' }, panelSkeleton(p.viz));
    const item = (ic, text, onclick, extra) => el('button', attrs({
      class: 'menu__item', type: 'button',
      onclick: (ev) => { ev.currentTarget.closest('details').removeAttribute('open'); onclick(); },
    }, extra), icon(ic), text);
    const edit = { 'data-min-role': 'analyst' };
    const menu = preview ? null : el('details', { class: 'menu db-panel__menu' },
      el('summary', { class: 'btn btn--ghost btn--icon btn--sm', title: 'Panel actions', 'aria-label': 'Actions for ' + p.title }, icon('ellipsis')),
      el('div', { class: 'menu__panel' },
        item('search', 'Open in Search', () => openSearch(...panelQuery(p, body._result))),
        ...(readOnly ? [] : [item('pencil', 'Edit panel', () => openPanelEditor({ index: i, panel: p }), edit),
        el('div', attrs({ class: 'menu__sep' }, edit)),
        item('arrow-up', 'Move earlier', () => movePanel(i, -1), { ...edit, disabled: i === 0 }),
        item('arrow-down', 'Move later', () => movePanel(i, 1), { ...edit, disabled: i === n - 1 }),
        el('div', attrs({ class: 'menu__sep' }, edit)),
        item('trash-2', 'Remove panel', () => removePanel(i), { ...edit, class: 'menu__item menu__item--danger' })])));
    const c = card({ title: p.title || 'Preview', sub: lastRange(dash.range), actions: menu ? [menu] : [], cls: 'db-panel db-w-' + (p.width || 'half') }, body);
    body._sub = c._sub;
    body._legend = c._legend;
    c._body = body;
    c.dataset.index = i;
    return c;
  }

  function renderPanels() {
    const body = $('db-body');
    forget(body);
    body.dataset.view = dash.current;
    const d = dash.def;
    body._empty = null;
    if (!d.panels.length) {
      put(body, el('div', { class: 'card' }, can('analyst')
        ? emptyState('layout-dashboard', 'No panels yet',
          'A panel is a query and a chart. Add one here, or run a search and choose Add to dashboard.',
          smallButton('Add panel', 'plus', () => openPanelEditor({})))
        : emptyState('layout-dashboard', 'No panels yet', 'An analyst or admin can add panels to this dashboard.')));
      body._boxes = [];
      return [];
    }
    const readOnly = isBuiltinPanels();
    const cards = d.panels.map((p, i) => panelCard(p, i, d.panels.length, false, readOnly));
    // A built-in dashboard says how to get data when every panel is empty.
    body._empty = readOnly ? el('div', { class: 'db-empty-slot' }) : null;
    put(body, readOnly ? body._empty : null, el('div', { class: 'db-grid' }, ...cards));
    body._boxes = cards.map((c) => c._body);
    return body._boxes;
  }

  // runDashboard runs every panel. opts.keep updates the panels in place
  // (a refresh or a new time range) instead of drawing them again.
  async function runDashboard(opts = {}) {
    const d = dash.def;
    if (!d) return;
    const seq = ++dash.seq;
    const body = $('db-body');
    let boxes;
    const kept = opts.keep && body.dataset.view === d.id && body._boxes && body._boxes.length === d.panels.length && d.panels.length;
    if (kept) {
      boxes = body._boxes;
      if (opts.busy) body.dataset.stale = '';
    } else boxes = renderPanels();
    if (!boxes.length) { markUpdated(); return; }
    body.setAttribute('aria-busy', 'true');
    let res;
    try {
      res = await api('api/dashboards/' + encodeURIComponent(d.id) + '/run', { range: dash.range });
    } catch (e) {
      if (seq !== dash.seq) return;
      if (kept && boxes.every((b) => b._result)) { refreshFailed(e); return; }
      boxes.forEach((b) => put(b, errorState('Couldn’t run this dashboard', e.message, retry())));
      body.setAttribute('aria-busy', 'false');
      dash.updated = 0;
      renderStamp();
      return;
    }
    if (seq !== dash.seq) return;
    res.panels.forEach((pr, i) => {
      if (boxes[i]) {
        boxes[i]._result = pr;
        renderPanelBody(boxes[i], d.panels[i], pr, res.range);
      }
    });
    if (body._empty) renderNoData(body._empty, d, res.panels);
    markUpdated();
  }

  // panelEmpty: the panel ran and found nothing (a single value of 0
  // counts as nothing).
  const panelEmpty = (p, pr) => !pr.error && (p.viz === 'single' ? !num(pr.value) : !((pr.result || {}).rows || []).length);

  // renderNoData fills the slot above a built-in dashboard's panels when
  // none of them found anything: what data it needs and where to set it up.
  function renderNoData(slot, d, results) {
    const none = results.length && results.every((pr, i) => d.panels[i] && panelEmpty(d.panels[i], pr));
    if (!none || d.id !== 'malware') { put(slot); return; }
    const admin = typeof can === 'function' && can('admin');
    put(slot, el('div', { class: 'card db-nodata' }, emptyState('shield-check', 'No antivirus events yet',
      'Collect Microsoft Defender events with the Windows agent, ClamAV with the Linux agent, or send your antivirus console’s syslog to Signalith.',
      admin ? el('button', { class: 'btn btn--primary btn--sm', type: 'button', onclick: () => openAntivirusSetup() }, icon('shield-check'), 'Set up antivirus logs') : null,
      null, admin ? null : 'An admin can set this up on the Add data page.')));
  }

  // copyDashboard saves a built-in dashboard as a new custom one, titled
  // "<title> (copy)", and opens it.
  async function copyDashboard() {
    const d = dash.def;
    if (!d || !isBuiltinPanels()) return;
    if (dash.off) { offNotice(); return; }
    const btn = $('db-copy');
    btn.disabled = true;
    const copy = { title: d.title + ' (copy)', description: d.description || '', time_range: d.time_range || '', refresh: d.refresh || '', panels: structuredClone(d.panels || []) };
    let saved;
    try {
      saved = await api('api/dashboards', copy);
    } catch (e) {
      sayError('Couldn’t make a copy: ' + e.message);
      return;
    } finally {
      btn.disabled = false;
    }
    await loadDashboardList();
    await showDashboard(saved.id);
    say(`Made “${saved.title}”. Change it as you like; ${d.title} stays as it is.`);
  }

  // columnsOf splits a result's columns into labels and numbers using the
  // first row.
  function columnsOf(res) {
    const row = (res.rows || [])[0] || {};
    const cols = (res.columns || []).filter((c) => c !== '_raw');
    const nums = cols.filter((c) => typeof row[c] === 'number' && c !== 'percent');
    return { labels: cols.filter((c) => !nums.includes(c) && c !== 'percent' && c !== '_time'), nums };
  }

  const LABELS_FOR_WIDTH = { third: 3, half: 5, full: 8 };

  function renderPanelBody(box, p, pr, range) {
    forget(box);
    if (box._legend) put(box._legend);
    const earliest = pr.earliest || '-' + range;
    if (box._sub) box._sub.textContent = earliestWords(earliest);
    if (pr.error) {
      // In the editor's preview the query is fixed right there.
      const inEditor = box.closest('dialog');
      put(box, errorState(inEditor ? 'The query failed' : 'This panel’s query failed', pr.error,
        inEditor ? null : smallButton('Fix it in Search', 'search', () => openSearch(p.query, pr.earliest))));
      return;
    }
    const res = pr.result || { rows: [], columns: [] };
    const rows = res.rows || [];
    const notes = [];
    if (res.truncated) notes.push(`Showing the first ${rows.length} rows.`);
    const noRows = () => emptyState('search', 'No results', 'Nothing matched in this time range.');
    const chartOpts = { labels: LABELS_FOR_WIDTH[p.width] || 5, legendInHead: p.width === 'full' && (res.columns || []).length <= 5, label: p.title };
    switch (p.viz) {
      case 'single': {
        if (box._sub) box._sub.textContent = [pr.field, earliestWords(earliest)].filter(Boolean).join(' · ');
        const delta = pr.previous != null ? deltaFoot(Number(pr.value) || 0, Number(pr.previous) || 0, { range: earliest.replace(/^-/, '') }) : null;
        put(box, el('div', { class: 'db-single' },
          el('div', { class: 'kpi__value' }, ...numberParts(pr.value)),
          delta,
          pr.compare_note ? el('div', { class: 'kpi__foot' }, el('span', { title: pr.compare_note }, pr.compare_note)) : null));
        return;
      }
      case 'line':
      case 'area':
        if (res.kind === 'timechart') {
          if (!rows.length) { put(box, noRows()); return; }
          const ch = p.viz === 'line' ? lineChart(res, chartOpts) : columnChart(res, chartOpts);
          put(box, ch.node, ...notes.map(note));
          if (ch.legend && box._legend) put(box._legend, ch.legend);
          return;
        }
        notes.push('Line charts and stacked columns need a query ending in | timechart, for example | timechart count by action. Showing bars instead.');
      // fall through
      case 'bar': {
        let content;
        if (res.kind === 'timechart') {
          // Total each series over the period.
          const items = (res.columns || []).filter((c) => c !== '_time').map((c) => ({ label: c, value: rows.reduce((a, r) => a + num(r[c]), 0) }));
          content = items.length ? rankList(items) : noRows();
        } else {
          const { labels, nums } = columnsOf(res);
          const vcol = pr.field && nums.includes(pr.field) ? pr.field : p.field && nums.includes(p.field) ? p.field : nums[0];
          if (!rows.length) content = noRows();
          else if (!vcol) {
            notes.push('Bars need a number column; try | stats count by <field>.');
            content = panelTable(res);
          } else {
            content = rankList(rows.slice(0, 20).map((r) => ({
              label: labels.length ? labels.map((c) => fmtValue(r[c])).join(' · ') : vcol, value: num(r[vcol]),
            })));
          }
        }
        put(box, content, ...notes.map(note));
        return;
      }
      default:
        put(box, panelTable(res), ...notes.map(note));
    }
  }

  const shortTime = (v) => {
    const d = new Date(v);
    return isNaN(d) ? fmtValue(v) : d.toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit', second: '2-digit', hourCycle: 'h23' });
  };

  // panelTable shows up to 100 rows and 8 columns; columns that do not fit
  // the panel's width are hidden (Open in Search shows everything).
  function panelTable(res) {
    const rows = res.rows || [];
    if (!rows.length) return emptyState('search', 'No results', 'Nothing matched in this time range.');
    let cols = res.columns || [];
    if (res.kind === 'events') {
      const preferred = ['_time', 'host', 'sourcetype', 'action', 'user', 'src', 'dest', 'process_name', 'signature'];
      cols = preferred.filter((c) => cols.includes(c));
    }
    cols = cols.slice(0, 8);
    return el('div', { class: 'db-table' }, el('table', { class: 'table table--compact' },
      el('thead', {}, el('tr', {}, ...cols.map((c) => el('th', { 'data-col': c, title: c, class: typeof (rows[0] || {})[c] === 'number' ? 'num' : '' }, c)))),
      el('tbody', {}, ...rows.slice(0, 100).map((r) => el('tr', {}, ...cols.map((c) => {
        const v = r[c];
        const text = c === '_time' ? shortTime(v) : fmtValue(v);
        return el('td', { class: typeof v === 'number' ? 'num' : '', title: c === '_time' ? fmtTime(v) : text }, text);
      }))))));
  }

  // ---------- saving ----------
  async function saveDashboard(d) {
    const saved = await api('api/dashboards/' + encodeURIComponent(d.id), d, 'PUT');
    if (saved.id === dash.current) dash.def = saved;
    return saved;
  }
  const say = (msg, action, opts) => { if (typeof toast === 'function') toast(msg, action, opts); };
  const sayError = (msg) => say(msg, null, { tone: 'danger' });

  async function movePanel(i, dir) {
    const d = structuredClone(dash.def);
    const j = i + dir;
    if (j < 0 || j >= d.panels.length) return;
    [d.panels[i], d.panels[j]] = [d.panels[j], d.panels[i]];
    try { await saveDashboard(d); } catch (e) { sayError('Couldn’t move the panel: ' + e.message); return; }
    runDashboard();
  }

  async function removePanel(i) {
    const before = structuredClone(dash.def);
    const title = before.panels[i].title;
    const d = structuredClone(before);
    d.panels.splice(i, 1);
    try { await saveDashboard(d); } catch (e) { sayError('Couldn’t remove the panel: ' + e.message); return; }
    runDashboard();
    say(`Removed “${title}”.`, {
      label: 'Undo',
      run: async () => {
        try { await saveDashboard(before); } catch (e) { sayError('Couldn’t restore the panel: ' + e.message); return; }
        if (dash.current === before.id) runDashboard();
      },
    });
  }

  // ---------- editors (one modal dialog) ----------
  const dialog = () => $('db-editor');
  function openModal(wide) {
    const dlg = dialog();
    dlg.classList.toggle('db-modal--wide', !!wide);
    if (!dlg.open) dlg.showModal();
    return dlg;
  }
  function closeEditor() {
    const dlg = dialog();
    if (dlg.open) dlg.close();
  }
  dialog().addEventListener('close', () => {
    if (dialog().open) return; // reopened before this event arrived
    forget(dialog());
    dialog().replaceChildren();
  });

  function modalHead(title, desc) {
    return el('div', { class: 'modal__head' },
      el('div', {}, el('h2', { class: 'modal__title', id: 'db-editor-title' }, title), desc ? el('p', { class: 'modal__desc' }, desc) : null),
      el('button', { class: 'btn btn--ghost btn--icon btn--sm db-modal__close', type: 'button', 'aria-label': 'Close', onclick: closeEditor }, icon('x')));
  }
  let fieldSeq = 0;
  function field(label, control, hint) {
    if (!control.id) control.id = 'db-f' + (++fieldSeq);
    return el('div', { class: 'field' }, el('label', { class: 'label', for: control.id }, label), control, hint ? el('p', { class: 'hint' }, hint) : null);
  }
  function problemsAlert(e) {
    return el('div', { class: 'alert', 'data-tone': 'danger', role: 'alert' }, icon('circle-alert'),
      el('div', {}, ...(e.problems && e.problems.length
        ? [el('b', {}, 'Fix these and try again.'), el('ul', { class: 'db-problem-list' }, ...e.problems.map((p) => el('li', {}, p)))]
        : [el('p', {}, e.message)])));
  }
  const ghost = (text, onclick, cls) => el('button', { class: 'btn btn--ghost' + (cls ? ' ' + cls : ''), type: 'button', onclick }, text);

  // offNotice explains why a dashboard cannot be created on this server.
  function offNotice() {
    const dlg = openModal(false);
    put(dlg, modalHead('Custom dashboards are off'),
      el('div', { class: 'modal__body' }, el('div', { class: 'alert', 'data-tone': 'info' }, icon('info'),
        el('p', {}, 'This server has no dashboards folder, so new dashboards cannot be saved. Set ', el('code', {}, 'dashboards.dir'), ' in the config file and restart Signalith.'))),
      el('div', { class: 'modal__foot' }, el('button', { class: 'btn btn--secondary', type: 'button', onclick: closeEditor }, 'Close')));
    dlg.querySelector('.modal__foot .btn').focus();
  }

  function rangeSelect(value) {
    const opts = ['15m', '1h', '4h', '24h', '7d', '30d'];
    if (value && !opts.includes(value)) opts.push(value);
    const s = el('select', { class: 'select select--block', name: 'time_range' }, ...opts.map((o) => el('option', { value: o }, 'Last ' + rangeWords(o))));
    s.value = value || '24h';
    return s;
  }

  function refreshSelect(value) {
    const opts = [['', 'Off'], ['1m', 'Every minute'], ['5m', 'Every 5 minutes'], ['15m', 'Every 15 minutes'], ['1h', 'Every hour']];
    if (value && !opts.some((o) => o[0] === value)) opts.push([value, 'Every ' + value]);
    const s = el('select', { class: 'select select--block', name: 'refresh' }, ...opts.map(([v, t]) => el('option', { value: v }, t)));
    s.value = value || '';
    return s;
  }

  function openDashboardEditor(isNew) {
    if (dash.off) { offNotice(); return; }
    if (!isNew && (!dash.def || isBuiltinPanels())) return;
    const d = isNew ? { title: '', description: '', time_range: dash.range, refresh: '', panels: [] } : dash.def;
    const title = el('input', { class: 'input', type: 'text', value: d.title || '', placeholder: 'For example: Authentication overview', maxlength: '200', autocomplete: 'off' });
    const titleErr = el('p', { class: 'field-error', hidden: '' }, icon('circle-alert'), 'Give the dashboard a title.');
    const desc = el('input', { class: 'input', type: 'text', value: d.description || '', placeholder: 'Optional: what this dashboard is for', autocomplete: 'off' });
    const range = rangeSelect(d.time_range);
    const refresh = refreshSelect(d.refresh);
    const msg = el('div', {});
    const saveBtn = el('button', { class: 'btn btn--primary', type: 'submit' }, isNew ? 'Create dashboard' : 'Save');
    title.addEventListener('input', () => { title.removeAttribute('aria-invalid'); titleErr.hidden = true; });
    const save = async (ev) => {
      ev.preventDefault();
      if (!title.value.trim()) {
        title.setAttribute('aria-invalid', 'true');
        titleErr.hidden = false;
        title.focus();
        return;
      }
      saveBtn.disabled = true;
      const body = { ...structuredClone(d), title: title.value.trim(), description: desc.value.trim(), time_range: range.value, refresh: refresh.value };
      try {
        const saved = isNew ? await api('api/dashboards', body) : await saveDashboard(body);
        closeEditor();
        await loadDashboardList();
        await showDashboard(saved.id);
        if (isNew) openPanelEditor({});
        else say('Dashboard saved.');
      } catch (e) {
        put(msg, problemsAlert(e));
        saveBtn.disabled = false;
      }
    };
    const dlg = openModal(false);
    put(dlg, el('form', { class: 'db-modal__form', novalidate: '', onsubmit: save },
      modalHead(isNew ? 'New dashboard' : 'Dashboard settings', isNew ? 'Saved as a YAML file on the server, so you can also keep it in Git.' : null),
      el('div', { class: 'modal__body' },
        msg,
        el('div', { class: 'field' }, el('label', { class: 'label', for: 'db-f-title' }, 'Title'), Object.assign(title, { id: 'db-f-title' }), titleErr),
        field('Description', desc),
        el('div', { class: 'form-grid' }, field('Default time range', range), field('Auto-refresh', refresh))),
      el('div', { class: 'modal__foot' },
        isNew ? null : ghost('Delete dashboard', () => confirmDelete(), 'db-danger'),
        el('span', { class: 'spacer' }),
        ghost('Cancel', closeEditor),
        saveBtn)));
    title.focus();
  }

  function confirmDelete() {
    const d = dash.def;
    const msg = el('div', { class: 'modal__body', hidden: '' });
    const btn = el('button', { class: 'btn btn--danger', type: 'button' }, 'Delete dashboard');
    btn.addEventListener('click', async () => {
      btn.disabled = true;
      try {
        await api('api/dashboards/' + encodeURIComponent(d.id), undefined, 'DELETE');
      } catch (e) {
        put(msg, problemsAlert(e));
        msg.hidden = false;
        btn.disabled = false;
        return;
      }
      closeEditor();
      await loadDashboardList();
      await showDashboard('posture');
      say(`Deleted “${d.title}”.`);
    });
    const dlg = openModal(false);
    put(dlg, modalHead('Delete this dashboard?', `“${d.title}” and its YAML file are removed from the server. This can’t be undone.`),
      msg,
      el('div', { class: 'modal__foot' }, ghost('Cancel', () => openDashboardEditor(false)), btn));
    btn.focus();
  }

  // suggestViz mirrors the server: timechart is a line, stats without "by" a
  // single value, other stats and top bars, anything else a table.
  function suggestViz(q) {
    const cmds = q.split('|').slice(1).map((c) => c.trim());
    let viz = 'table';
    for (const c of cmds) {
      if (/^timechart\b/i.test(c)) return 'line';
      if (/^stats\b/i.test(c)) viz = /\bby\b/i.test(c) ? 'bar' : 'single';
      else if (/^top\b/i.test(c)) viz = 'bar';
      else if (/^table\b/i.test(c)) viz = 'table';
    }
    return viz;
  }

  // defaultTitle names a panel from its query when the user gave no title:
  // "Authentication: timechart count by action".
  function defaultTitle(q) {
    const parts = q.split('|').map((x) => x.trim()).filter(Boolean);
    const dm = (/datamodel\s*=\s*"?([\w-]+)/i.exec(parts[0] || '') || [])[1];
    const last = parts.length > 1 ? parts[parts.length - 1] : parts[0] || 'Panel';
    const t = (dm && parts.length > 1 ? dm.replace('_', ' ') + ': ' : '') + last;
    return t.length > 80 ? t.slice(0, 79) + '…' : t;
  }

  // openPanelEditor edits panel `index` of the current dashboard, or adds a
  // new one. With pickTarget, the user also picks which dashboard to add it
  // to (from the Search page).
  function openPanelEditor({ index, panel, pickTarget }) {
    if (dash.off) { offNotice(); return; }
    // A built-in dashboard takes no panels: add to a custom one instead.
    if (!pickTarget && isBuiltinPanels()) pickTarget = true;
    const p = { title: '', query: '', viz: '', width: '', field: '', compare: false, ...(panel || {}) };
    const isNew = index == null;
    let vizTouched = !!p.viz;
    const custom = dash.list.filter((d) => !d.builtin);

    const target = el('select', { class: 'select select--block' }, ...custom.map((d) => el('option', { value: d.id }, d.title)), el('option', { value: '' }, 'New dashboard…'));
    if (dash.def && custom.some((d) => d.id === dash.def.id)) target.value = dash.def.id;
    else target.value = custom.length ? custom[0].id : '';
    const newTitle = el('input', { class: 'input', type: 'text', placeholder: 'For example: Authentication overview', autocomplete: 'off' });
    const newField = field('New dashboard title', newTitle);
    const syncTarget = () => { newField.hidden = target.value !== ''; };
    target.addEventListener('change', syncTarget);

    const ask = el('input', { class: 'input', type: 'search', placeholder: 'Ask in plain English, for example: failed logins by source ip', autocomplete: 'off', 'aria-label': 'Ask in plain English' });
    const askBtn = el('button', { class: 'btn btn--secondary', type: 'button' }, 'Write query');
    const askMsg = el('p', { class: 'hint db-ask-msg', 'aria-live': 'polite' });
    const title = el('input', { class: 'input', type: 'text', value: p.title, placeholder: 'Optional: named from the query', autocomplete: 'off' });
    const qtext = el('textarea', { class: 'textarea db-query', rows: '4', spellcheck: 'false', placeholder: 'datamodel=Authentication action=failure | stats count by src' });
    qtext.value = p.query;
    const viz = el('select', { class: 'select select--block' }, ...Object.entries(VIZ_LABEL).map(([v, t]) => el('option', { value: v }, t)));
    viz.value = p.viz || suggestViz(p.query);
    const width = el('select', { class: 'select select--block' }, el('option', { value: '' }, 'Automatic'), ...Object.entries(WIDTH_LABEL).map(([v, t]) => el('option', { value: v }, t)));
    width.value = p.width || '';
    const fieldIn = el('input', { class: 'input', type: 'text', value: p.field || '', placeholder: 'The first number', list: 'field-names', autocomplete: 'off' });
    const compare = el('input', { type: 'checkbox' });
    compare.checked = !!p.compare;
    const singleOpts = el('div', { class: 'form-grid db-single-opts' },
      field('Value column', fieldIn),
      el('label', { class: 'check' }, compare, 'Compare with the previous period'));
    const syncViz = () => { singleOpts.hidden = viz.value !== 'single'; };
    viz.addEventListener('change', () => { vizTouched = true; syncViz(); });
    qtext.addEventListener('input', () => { if (!vizTouched) { viz.value = suggestViz(qtext.value); syncViz(); } });
    const preview = el('div', { class: 'db-preview', hidden: '', 'aria-label': 'Preview' });
    const msg = el('div', {});
    const previewBtn = el('button', { class: 'btn btn--secondary', type: 'button' }, icon('play'), 'Preview');
    const saveBtn = el('button', { class: 'btn btn--primary', type: 'submit' }, isNew ? 'Add to dashboard' : 'Save panel');

    const current = () => ({
      title: title.value.trim() || defaultTitle(qtext.value), query: qtext.value.trim(), viz: viz.value, width: width.value,
      field: viz.value === 'single' ? fieldIn.value.trim() : '', compare: viz.value === 'single' && compare.checked,
    });
    const needQuery = () => {
      put(msg, problemsAlert({ message: 'Write a query first, or ask for one above.' }));
      qtext.focus();
    };

    const doAsk = async () => {
      const question = ask.value.trim();
      if (!question) { ask.focus(); return; }
      askBtn.disabled = true;
      askMsg.textContent = 'Writing the query…';
      try {
        const res = await api('api/ask', { question, mode: 'auto' });
        qtext.value = res.query;
        if (!title.value.trim()) title.value = question.charAt(0).toUpperCase() + question.slice(1);
        if (!vizTouched) { viz.value = suggestViz(res.query); syncViz(); }
        const unknown = (res.unknown || []).length ? ' Not understood: ' + res.unknown.join(', ') + '.' : '';
        askMsg.textContent = (res.source === 'ai' ? 'Written by the AI model; check it.' : 'Check the query below.') + unknown + (res.ai_error ? ' (AI model failed: ' + res.ai_error + ')' : '');
        doPreview();
      } catch (e) {
        askMsg.textContent = e.message;
      }
      askBtn.disabled = false;
    };
    askBtn.addEventListener('click', doAsk);
    ask.addEventListener('keydown', (ev) => { if (ev.key === 'Enter') { ev.preventDefault(); doAsk(); } });

    const doPreview = async () => {
      const pn = current();
      if (!pn.query) { needQuery(); return; }
      put(msg);
      forget(preview);
      const c = panelCard({ ...pn, width: pn.width || (pn.viz === 'single' ? 'third' : pn.viz === 'line' || pn.viz === 'area' ? 'full' : 'half') }, 0, 1, true);
      put(preview, el('div', { class: 'db-grid' }, c));
      preview.hidden = false;
      previewBtn.disabled = true;
      try {
        const res = await api('api/panels/run', { range: dash.range, panel: pn });
        c.className = 'card db-panel db-w-' + (res.panel.width || 'full');
        renderPanelBody(c._body, res.panel, res.result, res.range);
      } catch (e) {
        put(c._body, errorState('Couldn’t run the query', e.message));
      }
      previewBtn.disabled = false;
    };
    previewBtn.addEventListener('click', doPreview);
    qtext.addEventListener('keydown', (ev) => { if (ev.key === 'Enter' && (ev.ctrlKey || ev.metaKey)) { ev.preventDefault(); doPreview(); } });

    const doSave = async (ev) => {
      ev.preventDefault();
      const pn = current();
      if (!pn.query) { needQuery(); return; }
      saveBtn.disabled = true;
      try {
        let id = dash.def && !pickTarget ? dash.def.id : target.value;
        if (pickTarget && !id) {
          const created = await api('api/dashboards', { title: newTitle.value.trim() || pn.title || 'My dashboard', time_range: dash.range, panels: [pn] });
          id = created.id;
        } else if (isNew) {
          await api('api/dashboards/' + encodeURIComponent(id) + '/panels', pn);
        } else {
          const d = structuredClone(dash.def);
          d.panels[index] = pn;
          await saveDashboard(d);
        }
        closeEditor();
        await loadDashboardList();
        await showDashboard(id);
        say(isNew ? `Added “${pn.title}”.` : 'Panel saved.');
      } catch (e) {
        put(msg, problemsAlert(e));
        saveBtn.disabled = false;
      }
    };

    const dlg = openModal(true);
    put(dlg, el('form', { class: 'db-modal__form', novalidate: '', onsubmit: doSave },
      modalHead(isNew ? 'Add a panel' : 'Edit panel', 'A panel is a query and how to show its result.'),
      el('div', { class: 'modal__body' },
        msg,
        pickTarget ? el('div', { class: 'form-grid' }, field('Dashboard', target), newField) : null,
        el('div', { class: 'db-ask' }, el('div', { class: 'input-wrap' }, icon('sparkles'), ask), askBtn),
        askMsg,
        field('Query', qtext, 'Ctrl+Enter previews the panel.'),
        el('div', { class: 'form-grid db-form-3' }, field('Title', title), field('Show as', viz), field('Width', width)),
        singleOpts,
        preview),
      el('div', { class: 'modal__foot' },
        el('span', { class: 'db-foot-hint' }, 'Uses the ' + lastRange(dash.range) + '.'),
        ghost('Cancel', closeEditor),
        previewBtn,
        saveBtn)));
    syncTarget();
    syncViz();
    (p.query ? title : ask).focus();
    if (p.query) doPreview();
  }

  // ---------- auto-refresh ----------
  // parseEvery reads a dashboard's refresh setting such as 5m, in seconds.
  function parseEvery(r) {
    const m = /^(\d+)\s*([smhd])$/.exec(r || '');
    return m ? Math.max(30, Number(m[1]) * { s: 1, m: 60, h: 3600, d: 86400 }[m[2]]) : 0;
  }
  const refreshSeconds = () => dash.every;

  // The interval menu beside "Live · updated 10s ago".
  const EVERY = [60, 300, 900, 3600];
  function renderEveryMenu() {
    const opts = EVERY.includes(dash.every) ? EVERY : [...EVERY, dash.every].sort((a, b) => a - b);
    $('db-every-text').textContent = everyText(dash.every);
    put($('db-every-menu'), ...opts.map((sec) => el('button', attrs({
      class: 'menu__item', type: 'button',
      onclick: () => {
        $('db-every').removeAttribute('open');
        dash.every = sec;
        try { localStorage.setItem('signalith.dashRefresh', String(sec)); } catch (_) { /* ignore */ }
        setAutoRefresh();
      },
    }, { 'aria-current': sec === dash.every ? 'true' : null }), el('span', {}, everyText(sec).replace(/^e/, 'E')), sec === dash.every ? icon('check', 'db-check') : null)));
  }

  function setAutoRefresh() {
    clearInterval(dash.timer);
    dash.timer = null;
    $('db-auto').checked = dash.auto;
    renderEveryMenu();
    if (dash.auto) {
      dash.timer = setInterval(() => {
        if (document.hidden || !$('page-dashboards').classList.contains('active')) return;
        reloadDashboard();
      }, refreshSeconds() * 1000);
    }
    renderStamp();
  }
  // Keep "updated 15s ago" current while the page is on screen.
  setInterval(() => {
    if (!document.hidden && $('page-dashboards').classList.contains('active')) renderStamp();
  }, 15000);

  // ---------- wiring ----------
  $('db-range').addEventListener('click', (ev) => {
    const b = ev.target.closest('button[data-range]');
    if (!b || b.dataset.range === dash.range) return;
    setRange(b.dataset.range);
    try { localStorage.setItem('signalith.dashRange', dash.range); } catch (_) { /* ignore */ }
    reloadDashboard({ busy: true });
  });
  $('db-auto').addEventListener('change', () => {
    dash.auto = $('db-auto').checked;
    try { localStorage.setItem('signalith.dashAuto', dash.auto ? '1' : '0'); } catch (_) { /* ignore */ }
    setAutoRefresh();
    if (dash.auto) reloadDashboard();
  });
  $('db-reload').addEventListener('click', () => reloadDashboard({ busy: true }));
  $('db-new').addEventListener('click', () => openDashboardEditor(true));
  $('db-add').addEventListener('click', () => openPanelEditor({}));
  $('db-edit').addEventListener('click', () => openDashboardEditor(false));
  $('db-copy').addEventListener('click', copyDashboard);

  // The switcher: arrow keys move between items; opening it focuses the
  // current dashboard.
  $('db-switch').addEventListener('toggle', () => {
    if (!$('db-switch').open) return;
    const cur = $('db-menu').querySelector('[aria-current]') || $('db-menu').querySelector('.menu__item');
    if (cur) cur.focus();
  });
  $('db-menu').addEventListener('keydown', (ev) => {
    if (ev.key !== 'ArrowDown' && ev.key !== 'ArrowUp') return;
    const items = [...$('db-menu').querySelectorAll('.menu__item')];
    const i = items.indexOf(document.activeElement);
    ev.preventDefault();
    items[(i + (ev.key === 'ArrowDown' ? 1 : -1) + items.length) % items.length].focus();
  });

  // "Add to dashboard" on the Search page.
  const addBtn = $('add-to-dashboard');
  if (addBtn) {
    addBtn.addEventListener('click', async () => {
      const query = $('query').value.trim();
      if (!query) {
        if (typeof showQueryError === 'function') showQueryError(new Error('Write or ask for a query first.'));
        return;
      }
      const asked = typeof lastAsk !== 'undefined' ? lastAsk : null;
      const title = asked && asked.query.trim() === query ? asked.question.charAt(0).toUpperCase() + asked.question.slice(1) : '';
      showPage('dashboards');
      await dashReady;
      openPanelEditor({ panel: { query, title }, pickTarget: true });
    });
  }

  let dashReady = null;
  pageHooks.push((name) => {
    if (name !== 'dashboards') {
      closeEditor();
      return;
    }
    if (!dash.loaded) {
      dash.loaded = true;
      try {
        const r = localStorage.getItem('signalith.dashRange');
        if (r) setRange(r);
        // dashRefresh is the interval in seconds; before the switch, 0 also meant off.
        const a = localStorage.getItem('signalith.dashAuto');
        const every = Number(localStorage.getItem('signalith.dashRefresh'));
        if (every >= 30) dash.every = every;
        dash.auto = a != null ? a === '1' : every > 0;
      } catch (_) { /* ignore */ }
      setAutoRefresh();
      dashReady = loadDashboardList().then(() => showDashboard(dash.current));
    } else {
      dashReady = reloadDashboard();
    }
  });

  // openDashboardAt opens a dashboard on a time range, kept as the choice
  // for next time (the sample-data card shows the week).
  window.openDashboardAt = (id, range) => {
    setRange(range);
    try { localStorage.setItem('signalith.dashRange', dash.range); } catch (_) { /* ignore */ }
    const switching = dash.loaded && dash.current !== id;
    if (!dash.loaded) dash.current = id;
    showPage('dashboards');
    return switching ? Promise.resolve(dashReady).then(() => showDashboard(id)) : dashReady;
  };

  // For scripted checks and links from other pages.
  window.showDashboard = (id) => {
    if (!dash.loaded) showPage('dashboards');
    return Promise.resolve(dashReady).then(() => showDashboard(id));
  };
})();
