// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0
// Risk analysis and the asset and identity lists.
'use strict';

// ---------- shared: priority, context, states, inspectors ----------
// intel.js uses the ri* helpers, so they stay global.
const PRIORITY_LABEL = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low' };

// prioBadge shows an asset or identity priority with the severity meter;
// plain=true leaves out the word "priority" (for a Priority column).
const prioBadge = (p, plain) => (p ? el('span', { class: 'sev sev--plain', 'data-sev': p, title: 'Priority' },
  (PRIORITY_LABEL[p] || p) + (plain ? '' : ' priority')) : null);
const riWatchBadge = () => el('span', { class: 'badge', title: 'On the watchlist' }, icon('eye', 'icon--xs'), 'Watchlist');

function riContextBits(c) {
  const bits = [];
  if (c.name) bits.push(c.name);
  if (c.owner) bits.push((c.kind === 'identity' ? 'manager ' : 'owner ') + c.owner);
  if ((c.category || []).length) bits.push(c.category.join(', '));
  if (c.bunit) bits.push(c.bunit);
  return bits;
}

const riNum = (v) => (typeof v === 'number' ? v.toLocaleString(undefined, { maximumFractionDigits: 1 }) : fmtValue(v));

// riskBand puts a total in a band for colour. 100 in 24 hours raises a
// finding (the risk-threshold-exceeded detection), so high starts there.
const riskBand = (n) => (n >= 200 ? 'critical' : n >= 100 ? 'high' : n >= 50 ? 'medium' : 'low');

// riskScore draws the score with a short meter coloured by band; the
// meter is relative to the largest score shown (at least 100).
function riskScore(score, top) {
  const w = Math.max(4, Math.min(100, (100 * (score || 0)) / Math.max(top || 0, 100)));
  return el('span', { class: 'risk' }, el('b', {}, riNum(score || 0)),
    el('span', { class: 'meter', 'data-band': riskBand(score || 0), 'aria-hidden': 'true' }, el('span', { style: `--w:${w.toFixed(1)}%` })));
}

// riEmpty is the empty and error state inside a card (SPEC section 9).
function riEmpty({ icon: name, title, text, action, tone }) {
  const attrs = { class: 'empty empty--compact' };
  if (tone) attrs['data-tone'] = tone;
  let btn = null;
  if (action) {
    btn = el('button', { class: 'btn btn--secondary btn--sm', type: 'button', onclick: action.run }, action.icon ? icon(action.icon) : null, action.label);
  }
  return el('div', attrs, el('span', { class: 'empty__icon' }, icon(name)), el('div', { class: 'empty__title' }, title),
    text ? el('p', { class: 'empty__text' }, text) : null, btn ? el('div', { class: 'empty__actions' }, btn) : null);
}
const riRetry = (run) => ({ label: 'Try again', icon: 'refresh-cw', run });
const riCap = (s) => String(s).replace(/^./, (c) => c.toUpperCase());

// riIconBtn is a small icon-only ghost button, as in the inspector bar.
function riIconBtn(name, label, run, disabled) {
  const b = el('button', { class: 'btn btn--ghost btn--icon btn--sm', type: 'button', 'aria-label': label, title: label, onclick: run }, icon(name));
  b.disabled = !!disabled;
  return b;
}

// riSkeleton keeps a table's layout while it loads: real headers, bars in
// the cells. cols are [label, className] pairs.
function riSkeleton(cols, rows = 5) {
  const widths = [72, 48, 60, 36, 54, 66];
  return el('table', { class: 'table', 'aria-busy': 'true' },
    el('thead', {}, el('tr', {}, ...cols.map(([h, cls]) => el('th', { class: cls || '' }, h)))),
    el('tbody', {}, ...Array.from({ length: rows }, (_, r) => el('tr', {}, ...cols.map(([, cls], i) => el('td', { class: cls || '' },
      el('span', { class: 'skeleton', style: `width:${i === 0 ? 60 + ((r * 13) % 30) : widths[(i + r) % widths.length]}%` })))))));
}

// riHead is a table header row; cols are [label, className, title] lists.
const riHead = (cols) => el('thead', {}, el('tr', {}, ...cols.map(([h, cls, title]) => el('th', title ? { class: cls || '', title } : { class: cls || '' }, h))));

// Inspectors (the risk and indicator details) sit beside their table from
// 1360px and slide over it with the shell's scrim below that. The scrim
// and Esc clear .app[data-inspect]; the open inspector closes with it.
const riSlideOver = matchMedia('(max-width: 1359px)');
const riInspectors = [];
const riOpenInspector = () => riInspectors.find((i) => i.page === currentPage && !i.panel.classList.contains('hidden'));
function riShowPanel(panel) {
  panel.classList.remove('hidden');
  if (riSlideOver.matches) appEl.setAttribute('data-inspect', '');
}
// riReveal scrolls a just-opened side inspector up to its sticky place when
// its foot (the actions) would start below the window, as on Threat intel
// where the indicators come after the feeds.
function riReveal(panel) {
  if (riSlideOver.matches) return;
  const r = panel.getBoundingClientRect();
  if (r.bottom <= innerHeight) return;
  const bar = document.querySelector('.topbar');
  const top = (bar ? bar.getBoundingClientRect().bottom : 0) + 16;
  const smooth = !matchMedia('(prefers-reduced-motion: reduce)').matches;
  window.scrollBy({ top: r.top - top, behavior: smooth ? 'smooth' : 'auto' });
}
function riHidePanel(panel) {
  if (panel.classList.contains('hidden')) return;
  panel.classList.add('hidden');
  if (riSlideOver.matches) { appEl.removeAttribute('data-inspect'); syncInspectInert(); }
}
new MutationObserver(() => {
  if (appEl.hasAttribute('data-inspect') || !riSlideOver.matches) return;
  const open = riOpenInspector();
  if (open) open.close();
}).observe(appEl, { attributes: true, attributeFilter: ['data-inspect'] });
riSlideOver.addEventListener('change', () => {
  if (!riOpenInspector()) return;
  appEl.toggleAttribute('data-inspect', riSlideOver.matches);
});
// Esc also closes an inspector that sits beside its table.
window.addEventListener('keydown', (ev) => {
  if (ev.key !== 'Escape' || ev.defaultPrevented || isTyping(ev.target)) return;
  if (document.querySelector('dialog[open], details.menu[open]') || appEl.hasAttribute('data-nav-open')) return;
  const open = riOpenInspector();
  if (open) open.close();
}, true);
pageHooks.push((name) => {
  // A slide-over does not follow you to another page.
  for (const i of riInspectors) if (i.page !== name && riSlideOver.matches) i.close();
});

// riRowKeys makes table rows work from the keyboard: Enter or Space opens
// a row, the arrow keys move between rows (and follow in the inspector).
function riRowKeys(tr, open, inspectorOpen) {
  tr.tabIndex = 0;
  tr.addEventListener('keydown', (ev) => {
    if (ev.target !== tr) return;
    if (ev.key === 'Enter' || ev.key === ' ') { ev.preventDefault(); open(); return; }
    if (ev.key !== 'ArrowDown' && ev.key !== 'ArrowUp') return;
    ev.preventDefault();
    const next = ev.key === 'ArrowDown' ? tr.nextElementSibling : tr.previousElementSibling;
    if (!next) return;
    next.focus();
    if (inspectorOpen()) next.click();
  });
}

// ---------- risk ----------
let riskOpen = null;
const riskState = { since: '24h', objs: null, error: null, seq: 0, detailSeq: 0 };
const RISK_TYPE_ICON = { user: 'user', system: 'server', other: 'circle-dot' };
const RISK_SINCE_LABEL = { '24h': 'last 24 hours', '7d': 'last 7 days', '30d': 'last 30 days' };
const RISK_COLS = [['User or system', 'r-c-obj'], ['Risk', 'num r-c-risk', '100 or more in 24 hours raises a finding'],
  ['Detections', 'num hide-sm'], ['Tactics', 'num hide-md hide-sm r-c-tac', 'ATT&CK tactics'], ['Events', 'num hide-md hide-sm r-c-events'],
  ['Last seen', 'hide-sm r-c-seen'], ['Context', 'hide-sm r-c-ctx']];
const riskKey = (o) => o.risk_object_type + ':' + o.risk_object;
// an address gets the globe, as on Dashboards and in finding entities
const riskIcon = (type, name) => (looksLikeIP(String(name)) ? 'globe' : RISK_TYPE_ICON[type] || 'circle-dot');
const isRiskOpen = (o) => !!riskOpen && riskOpen.object === o.risk_object && riskOpen.type === o.risk_object_type;

async function loadRisk() {
  const seq = ++riskState.seq;
  const p = new URLSearchParams({ since: riskState.since });
  if ($('r-type').value) p.set('type', $('r-type').value);
  if (!riskState.objs) $('r-list').replaceChildren(riSkeleton(RISK_COLS));
  else $('r-list').querySelector('table')?.setAttribute('aria-busy', 'true');
  $('r-refresh').disabled = true;
  try {
    const res = await api('api/risk?' + p);
    if (seq !== riskState.seq) return;
    riskState.objs = res.objects || [];
    riskState.error = null;
  } catch (e) {
    if (seq !== riskState.seq) return;
    riskState.objs = null;
    riskState.error = e;
  } finally {
    if (seq === riskState.seq) $('r-refresh').disabled = false;
  }
  renderRisk();
}

function riskMatches(o, q) {
  if (!q) return true;
  const c = o.context || {};
  return [o.risk_object, c.name, c.owner, c.email, c.bunit].some((v) => v && String(v).toLowerCase().includes(q));
}

function renderRisk() {
  const list = $('r-list');
  const foot = $('r-foot');
  if (riskState.error) {
    foot.classList.add('hidden');
    list.replaceChildren(riEmpty({ icon: 'circle-alert', tone: 'danger', title: 'Couldn’t load risk', text: riskState.error.message + '. Your filters are kept.', action: riRetry(loadRisk) }));
    return;
  }
  const all = riskState.objs || [];
  const q = $('r-find').value.trim().toLowerCase();
  const objs = all.filter((o) => riskMatches(o, q));
  const filtered = q || $('r-type').value;
  if (!objs.length) {
    foot.classList.add('hidden');
    list.replaceChildren(filtered && (all.length || $('r-type').value)
      ? riEmpty({ icon: 'search', title: 'No users or systems match', text: 'Nothing in the ' + RISK_SINCE_LABEL[riskState.since] + ' matches these filters.', action: { label: 'Clear filters', run: clearRiskFilters } })
      : riEmpty({ icon: 'gauge', title: 'No risk in the ' + RISK_SINCE_LABEL[riskState.since], text: 'Risk appears when detections with a risk score find something.',
        action: riskState.since !== '30d' ? { label: 'Show the last 30 days', run: () => setRiskSince('30d') } : null }));
    return;
  }
  const top = Math.max(...all.map((o) => o.risk_score || 0));
  const rows = objs.map((o) => {
    const type = o.risk_object_type;
    const open = () => showRiskObject(o.risk_object, type);
    const tr = el('tr', { 'data-key': riskKey(o), onclick: open },
      el('td', { class: 'r-c-obj' }, el('span', { class: 'r-obj', title: o.risk_object },
        el('span', { class: 'r-obj__icon', title: type, role: 'img', 'aria-label': type }, icon(riskIcon(type, o.risk_object))),
        el('span', { class: 'mono' }, o.risk_object))),
      el('td', { class: 'num r-c-risk' }, riskScore(o.risk_score, top)),
      el('td', { class: 'num hide-sm' }, String(o.detections ?? '')),
      el('td', { class: 'num hide-md hide-sm r-c-tac' }, String(o.tactics ?? '')),
      el('td', { class: 'num hide-md hide-sm r-c-events' }, riNum(o.events)),
      el('td', { class: 'hide-sm r-c-seen' }, el('span', { class: 'age', title: o.last_seen ? fmtTime(o.last_seen) : '' }, o.last_seen ? ago(o.last_seen) : '')),
      el('td', { class: 'hide-sm r-c-ctx' }, riskContextCell(o.context)));
    if (isRiskOpen(o)) tr.setAttribute('aria-selected', 'true');
    riRowKeys(tr, open, () => !!riskOpen);
    return tr;
  });
  list.replaceChildren(el('table', { class: 'table r-table' }, riHead(RISK_COLS), el('tbody', {}, ...rows)));
  const n = all.length;
  const what = (k) => `${k.toLocaleString()} ${k === 1 ? 'user or system' : 'users and systems'}`;
  fill(foot, el('span', {}, (objs.length === n ? what(n) : `${objs.length.toLocaleString()} of ${what(n)}`) + ' · ' + RISK_SINCE_LABEL[riskState.since]),
    n >= 200 ? el('span', {}, 'Showing the 200 with the most risk') : null);
  foot.classList.remove('hidden');
}

function riskContextCell(c) {
  if (!c) return el('span', { class: 'subtle' }, 'Not in your lists');
  const bits = riContextBits(c);
  return el('span', { class: 'r-ctx', title: bits.join(' · ') }, prioBadge(c.priority, true), c.watchlist ? riWatchBadge() : null,
    bits.length ? el('span', { class: 'r-ctx__text' }, bits.join(' · ')) : null);
}

function clearRiskFilters() {
  $('r-find').value = '';
  if ($('r-type').value) { $('r-type').value = ''; loadRisk(); } else renderRisk();
}

function setRiskSince(v) {
  riskState.since = v;
  $('r-since').querySelectorAll('button').forEach((b) => b.setAttribute('aria-pressed', String(b.dataset.since === v)));
  loadRisk();
  if (riskOpen) showRiskObject(riskOpen.object, riskOpen.type);
}

// openRiskSince opens the Risk page on a time window (the sample-data card
// links to the whole week); opening the page loads it.
function openRiskSince(v) {
  riskState.since = v;
  $('r-since').querySelectorAll('button').forEach((b) => b.setAttribute('aria-pressed', String(b.dataset.since === v)));
  if ($('page-risk').classList.contains('active')) setRiskSince(v);
  else showPage('risk');
}

function markRiskRow() {
  $('r-list').querySelectorAll('tbody tr').forEach((tr) => {
    if (riskOpen && tr.dataset.key === riskOpen.type + ':' + riskOpen.object) tr.setAttribute('aria-selected', 'true');
    else tr.removeAttribute('aria-selected');
  });
}

function closeRiskObject() {
  if (!riskOpen) return;
  const hadFocus = $('r-detail').contains(document.activeElement);
  const row = $('r-list').querySelector('tr[aria-selected="true"]');
  riskOpen = null;
  riskState.detailSeq++;
  riHidePanel($('r-detail'));
  markRiskRow();
  if (row && (hadFocus || document.activeElement === document.body)) row.focus();
}
riInspectors.push({ page: 'risk', panel: $('r-detail'), close: closeRiskObject });

// tacticName gives the MITRE name of a tactic (credential-access ->
// Credential Access), as Findings, Dashboards and Coverage show it. The
// names come from the ATT&CK data once loaded; until then the slug is
// spelled out the same way (only "and" stays lower case).
function tacticName(t) {
  const s = String(t);
  const known = coverage && (coverage.tactics || []).find((x) => x.short === s || x.name === s);
  if (known) return known.name;
  return s.split(/[-_\s]+/).map((w, i) => (i && w === 'and' ? w : w.charAt(0).toUpperCase() + w.slice(1))).join(' ');
}

// showRiskObject opens one user or system in the inspector. Dashboards
// call it too, right after showPage('risk').
async function showRiskObject(object, type) {
  riskOpen = { object, type };
  const seq = ++riskState.detailSeq;
  const box = $('r-detail');
  markRiskRow();
  const since = riskState.since;
  const shown = (riskState.objs || []).filter((o) => riskMatches(o, $('r-find').value.trim().toLowerCase()));
  const idx = shown.findIndex(isRiskOpen);
  const row = idx >= 0 ? shown[idx] : null;
  const step = (d) => { const o = shown[idx + d]; if (o) showRiskObject(o.risk_object, o.risk_object_type); };
  const bar = el('div', { class: 'inspector__bar' },
    icon(riskIcon(type, object), 'icon--sm'), el('span', {}, type === 'user' ? 'User' : type === 'system' ? 'System' : 'Other'),
    idx >= 0 ? el('span', {}, `· ${idx + 1} of ${shown.length}`) : null,
    el('span', { class: 'spacer' }),
    riIconBtn('chevron-up', 'Previous', () => step(-1), idx <= 0),
    riIconBtn('chevron-down', 'Next', () => step(1), idx < 0 || idx >= shown.length - 1),
    riIconBtn('x', 'Close details', closeRiskObject));
  const title = el('h2', { class: 'inspector__title mono', tabindex: '-1' }, object);
  const head = el('div', { class: 'inspector__head' }, title);
  const body = el('div', { class: 'inspector__body', 'aria-busy': 'true' },
    el('div', { class: 'r-stats' }, ...['Risk', 'Detections', 'Events'].map((l) => el('div', {}, el('span', { class: 'r-stat__label' }, l), el('span', { class: 'skeleton r-stat__skel' })))),
    el('section', { class: 'section' }, el('span', { class: 'skeleton', style: 'width:40%' }), el('span', { class: 'skeleton', style: 'width:90%' }), el('span', { class: 'skeleton', style: 'width:75%' })));
  const findingsBtn = el('button', { class: 'btn btn--secondary', type: 'button', onclick: () => {
    showPage('findings');
    if ($('f-text')) $('f-text').value = object;
    loadFindings();
  } }, icon('shield-alert'), 'Related findings');
  const searchBtn = el('button', { class: 'btn btn--ghost', type: 'button' }, icon('search'), 'Open in Search');
  searchBtn.disabled = true;
  const storyBtn = type === 'other' ? null : storylineButton({ type: type === 'system' && looksLikeIP(object) ? 'ip' : type, object, since: since === '24h' ? '24h' : since },
    { kind: 'secondary', label: 'Storyline', title: 'See what added this risk as one attack story, in ATT&CK order' });
  const foot = el('div', { class: 'inspector__foot' }, findingsBtn, storyBtn, searchBtn);
  box.replaceChildren(bar, head, body, foot);
  const wasOpen = !box.classList.contains('hidden');
  riShowPanel(box);
  if (riSlideOver.matches && !wasOpen) title.focus();
  let res;
  try {
    res = await api('api/risk/object?' + new URLSearchParams({ object, type, since }));
  } catch (e) {
    if (seq !== riskState.detailSeq) return;
    body.removeAttribute('aria-busy');
    body.replaceChildren(riEmpty({ icon: 'circle-alert', tone: 'danger', title: 'Couldn’t load the details', text: e.message, action: riRetry(() => showRiskObject(object, type)) }));
    return;
  }
  if (seq !== riskState.detailSeq) return;
  const evs = res.events || [];
  const tactics = new Set();
  const dets = new Set();
  evs.forEach((e) => { [].concat(e.mitre_tactic || []).forEach((t) => tactics.add(t)); if (e.detection_id) dets.add(e.detection_id); });
  searchBtn.disabled = false;
  // The server's query already names its time range.
  searchBtn.addEventListener('click', () => openSearch(res.query, /\bearliest=/.test(res.query || '') ? undefined : '-' + since));
  head.append(el('div', { class: 'inspector__meta' },
    el('span', {}, 'Risk in the ' + RISK_SINCE_LABEL[since]),
    row && row.last_seen ? el('span', { class: 'dotsep' }) : null,
    row && row.last_seen ? el('span', { title: fmtTime(row.last_seen) }, 'last seen ' + ago(row.last_seen)) : null));
  const stat = (label, value) => el('div', {}, el('span', { class: 'r-stat__label' }, label), value);
  const sections = [el('div', { class: 'r-stats' },
    stat('Risk', el('span', { class: 'r-stat__value' }, riskScore(res.total, Math.max(res.total, ...(riskState.objs || []).map((o) => o.risk_score || 0))))),
    stat('Detections', el('span', { class: 'r-stat__value num' }, String(dets.size))),
    stat('Events', el('span', { class: 'r-stat__value num' }, evs.length >= 500 ? '500+' : String(evs.length))))];
  sections.push(riskContextSection(res.context, type));
  // The tactic chips filter the list of what added risk.
  const evList = el('ol', { class: 'timeline r-timeline' });
  const evCount = el('span', { class: 'count' }, String(evs.length));
  let tacticOn = '';
  const links = riskEventLinks(evs, since, seq);
  const drawEvents = () => {
    const shownEvs = tacticOn ? evs.filter((e) => [].concat(e.mitre_tactic || []).includes(tacticOn)) : evs;
    evCount.textContent = tacticOn ? `${shownEvs.length} of ${evs.length}` : String(evs.length);
    fill(evList, ...shownEvs.map((e) => riskEventItem(e, links)));
  };
  if (tactics.size) {
    const chips = el('div', { class: 'chips r-tactics', role: 'group', 'aria-label': 'Show what added risk for a tactic' });
    const drawTactics = () => fill(chips, ...[...tactics].map((t) => el('button', {
      type: 'button', class: 'tech tech--plain r-tactic', 'aria-pressed': String(tacticOn === t),
      title: tacticOn === t ? 'Show all of what added risk' : 'Show only what added risk for this tactic',
      onclick: () => { tacticOn = tacticOn === t ? '' : t; drawTactics(); drawEvents(); },
    }, tacticName(t))));
    drawTactics();
    if (!coverage && typeof loadAttackIndex === 'function') loadAttackIndex().then(() => { if (chips.isConnected) drawTactics(); });
    sections.push(el('section', { class: 'section', 'aria-label': 'ATT&CK tactics' },
      el('h3', { class: 'section-title' }, 'ATT&CK tactics', el('span', { class: 'count' }, String(tactics.size))), chips));
  }
  if (evs.length) drawEvents();
  sections.push(el('section', { class: 'section', 'aria-label': 'What added risk' },
    el('h3', { class: 'section-title' }, 'What added risk', evCount),
    evs.length ? evList : el('p', { class: 'muted' }, 'No risk events in this period.')));
  body.removeAttribute('aria-busy');
  body.replaceChildren(...sections.filter(Boolean));
}

// riskEventItem draws one risk event: its message opens the detection that
// added the risk, and a link under it opens the finding raised with it, or
// for a risk-only detection the risk event in Search.
function riskEventItem(e, links) {
  const id = e.detection_id || '';
  const msg = e.risk_message || id || 'Risk event';
  let title = el('span', { class: 'r-ev__title' }, msg);
  const actions = el('span', { class: 'r-ev__links' });
  const t = new Date(e._time).getTime();
  const searchLink = () => el('button', {
    type: 'button', class: 'link-btn r-ev__link', title: 'Show this risk event in Search',
    onclick: () => openSearch(`datamodel=Risk detection_id=${quoteValue(id || '*')} risk_object=${quoteValue(e.risk_object || '*')}`,
      new Date(t - 60e3).toISOString(), new Date(t + 60e3).toISOString()),
  }, icon('search', 'icon--xs'), 'Show in Search');
  const draw = (l) => {
    if (l.detections.has(id)) {
      // A link, not a button, so a long message wraps after the score.
      const b = el('a', { href: '#detections', class: 'r-ev__title', title: 'Open this detection', onclick: (ev) => { ev.preventDefault(); focusDetection(id); } }, msg);
      title.replaceWith(b);
      title = b;
    }
    const fid = l.findings.get(e);
    fill(actions,
      fid ? el('button', { type: 'button', class: 'link-btn r-ev__link r-ev__finding', title: 'Open the finding raised with this risk', onclick: () => openFindingFromCase(fid) },
        icon('shield-alert', 'icon--xs'), 'Open finding') : null,
      searchLink(),
      // A behavior baseline's event: admins can mark it as normal.
      /^baseline-/.test(id) && can('admin') && window.blMarkNormal
        ? el('button', { type: 'button', class: 'link-btn r-ev__link r-ev__normal', onclick: () => window.blMarkNormal(e) }, 'Mark as normal') : null,
      // Or forget what it learned, when the value came from misuse.
      /^baseline-/.test(id) && !e.baseline_reason && can('admin') && window.blUnlearn
        ? el('button', { type: 'button', class: 'link-btn r-ev__link r-ev__unlearn', onclick: () => window.blUnlearn(e) }, 'Forget it') : null);
  };
  draw({ detections: new Set(), findings: new Map() });
  links.then((l) => { if (l) draw(l); });
  return el('li', {},
    el('span', { class: 'timeline__dot' }, icon('crosshair')),
    el('span', { class: 'timeline__text' }, el('b', { class: 'num' }, '+' + riNum(e.risk_score)), ' ', title,
      el('span', { class: 'r-ev__meta' }, el('span', { class: 'mono' }, id),
        e.risk_priority ? el('span', {}, `${PRIORITY_LABEL[e.risk_priority] || e.risk_priority} priority, base ${riNum(e.risk_base_score)}`) : null),
      actions),
    el('span', { class: 'timeline__time', title: fmtTime(e._time) }, ago(e._time)));
}

// riskEventLinks looks up, for the risk events on screen, which of their
// detections still exist and which finding each event was raised with: a
// detection that is not risk-only raises its finding in the same run, with
// the same group key. It resolves to null when another object was opened.
async function riskEventLinks(evs, since, seq) {
  const ids = [...new Set(evs.map((e) => e.detection_id).filter(Boolean))].slice(0, 25);
  const detections = new Set();
  const findings = new Map();
  await Promise.all(ids.map(async (id) => {
    let d;
    try { d = await api('api/detections/' + encodeURIComponent(id)); } catch (_) { return; }
    detections.add(id);
    if (d.risk && d.risk.only) return;
    let res;
    try { res = await api('api/findings?' + new URLSearchParams({ detection: id, since, limit: '1000' })); } catch (_) { return; }
    const fs = (res.findings || []).filter((f) => f.group_key);
    evs.forEach((e) => {
      if (e.detection_id !== id || !e.group_key) return;
      const t = new Date(e._time).getTime();
      let best = null;
      let gap = 5 * 60e3; // a finding is raised with its risk, in the same run
      fs.forEach((f) => {
        if (f.group_key !== e.group_key) return;
        const g = Math.abs(new Date(f.slot || f.created).getTime() - t);
        if (g <= gap) { gap = g; best = f; }
      });
      if (best) findings.set(e, best.id);
    });
  }));
  return seq === riskState.detailSeq ? { detections, findings } : null;
}

function riskContextSection(c, type) {
  const head = el('h3', { class: 'section-title' }, type === 'user' ? 'Identity' : 'Asset');
  if (!c) {
    return el('section', { class: 'section' }, head, el('p', { class: 'muted' }, 'Not in your asset or identity lists, so it gets normal priority. ',
      el('a', { href: '#assets', 'data-page': 'assets' }, 'Add it to a list')));
  }
  const rows = [];
  const add = (k, v) => { if (v) rows.push(el('dt', {}, k), el('dd', {}, v)); };
  add('Name', c.name);
  add('Email', c.email);
  add(c.kind === 'identity' ? 'Manager' : 'Owner', c.owner);
  add('Priority', prioBadge(c.priority, true));
  add('Category', (c.category || []).join(', '));
  add('Business unit', c.bunit);
  add('Location', c.location);
  add('Watchlist', c.watchlist ? 'On the watchlist' : null);
  return el('section', { class: 'section' }, head, rows.length ? el('dl', { class: 'kv' }, ...rows) : el('p', { class: 'muted' }, 'In your lists with no details.'));
}

$('r-refresh').addEventListener('click', () => { loadRisk(); if (riskOpen) showRiskObject(riskOpen.object, riskOpen.type); });
$('r-since').querySelectorAll('button').forEach((b) => b.addEventListener('click', () => { if (b.dataset.since !== riskState.since) setRiskSince(b.dataset.since); }));
$('r-type').addEventListener('change', loadRisk);
$('r-find').addEventListener('input', () => { if (riskState.objs) renderRisk(); });

// ---------- assets and identities ----------
const LIST_INFO = {
  assets: {
    noun: 'asset', nouns: 'assets', find: 'Find a host, IP or owner', icon: 'server',
    title: 'Replace the asset list',
    columns: ['host, ip, cidr, owner, priority, category, bunit, location', '. Separate several values with ', '|', '.'],
    example: 'host,ip,cidr,owner,priority,category,bunit,location\nDC01.corp.local|DC01,10.0.0.10,,it-ops,critical,domain_controller|pci,IT,HQ\n,,10.20.0.0/16,,low,workstation,Corp,',
    empty: 'Upload a CSV of hosts, IP addresses and networks with an owner and a priority.',
  },
  identities: {
    noun: 'identity', nouns: 'identities', find: 'Find a user, name or manager', icon: 'user',
    title: 'Replace the identity list',
    columns: ['identity, name, email, manager, priority, category, bunit, watchlist', '. List every username form, like ', 'bob|CORP\\bob', '.'],
    example: 'identity,name,email,manager,priority,category,bunit,watchlist\nbob|CORP\\bob,Bob Smith,bob@corp.com,alice,high,admin,IT,true\nsvc_backup,Backup service,,it-ops,critical,service,IT,',
    empty: 'Upload a CSV of user accounts with a name, manager and priority. Watchlisted users get extra risk.',
  },
};
const LIST_COL_LABEL = {
  host: 'Host', ip: 'IP', cidr: 'Network', owner: 'Owner', priority: 'Priority', category: 'Category', bunit: 'Business unit',
  location: 'Location', identity: 'Identity', name: 'Name', email: 'Email', manager: 'Manager', watchlist: 'Watchlist',
};
const LIST_MONO = new Set(['host', 'ip', 'cidr', 'identity']);
const LIST_KEY = new Set(['host', 'identity']);
const LIST_SHOW = 200;
const listState = { kind: 'assets', res: {}, err: {}, loading: {} };

async function loadLists() {
  const kinds = ['assets', 'identities'];
  for (const k of kinds) listState.loading[k] = true;
  renderList();
  await Promise.all(kinds.map(async (kind) => {
    try {
      listState.res[kind] = await api('api/lookups/' + kind);
      listState.err[kind] = null;
    } catch (e) {
      listState.res[kind] = null;
      listState.err[kind] = e;
    }
    listState.loading[kind] = false;
    const count = document.querySelector(`#page-assets .l-count[data-kind="${kind}"]`);
    const res = listState.res[kind];
    count.textContent = res ? res.count.toLocaleString() : '';
    count.classList.toggle('hidden', !res);
    if (kind === listState.kind) renderList();
  }));
}

// riBreakable lets long names, addresses and categories wrap after their
// punctuation (DC01.corp.<wbr>local) instead of widening the table.
function riBreakable(text) {
  const parts = String(text).split(/(?<=[.,/_@|\\:-])/);
  const out = [];
  parts.forEach((t, i) => { if (i) out.push(el('wbr')); out.push(t); });
  return out;
}

function listCell(col, v) {
  if (col === 'priority') return prioBadge(v, true);
  // A host or identity opens its attack storyline.
  if ((col === 'host' || col === 'identity') && typeof v === 'string' && v && !/[*?]/.test(v)) {
    const b = el('button', { type: 'button', class: 'l-story mono', title: `Attack storyline for ${v}` }, ...riBreakable(v));
    b.addEventListener('click', () => openStoryline({ type: col === 'host' ? 'system' : 'user', object: v, since: '7d' }));
    return b;
  }
  if (col === 'watchlist') return v === true ? riWatchBadge() : null;
  const text = Array.isArray(v) ? v.join(', ') : v == null ? '' : String(v);
  if (!text) return null;
  // Addresses stay whole; names and categories may wrap at punctuation.
  if (col === 'ip' || col === 'cidr') return el('span', { class: 'mono' }, text);
  return el('span', LIST_MONO.has(col) ? { class: 'mono' } : {}, ...riBreakable(text));
}

function listMatches(it, q) {
  if (!q) return true;
  return Object.values(it).some((v) => (Array.isArray(v) ? v.join(' ') : String(v ?? '')).toLowerCase().includes(q));
}

function renderList() {
  const kind = listState.kind;
  const info = LIST_INFO[kind];
  const box = $('l-table');
  const foot = $('l-foot');
  const toolbar = $('l-toolbar');
  const res = listState.res[kind];
  const err = listState.err[kind];
  foot.classList.add('hidden');
  if (listState.loading[kind] && !res) {
    toolbar.classList.remove('hidden');
    const cols = kind === 'assets' ? ['host', 'ip', 'cidr', 'owner', 'priority', 'category', 'bunit', 'location'] : ['identity', 'name', 'email', 'manager', 'priority', 'category', 'bunit', 'watchlist'];
    box.replaceChildren(riSkeleton(cols.map((c) => [LIST_COL_LABEL[c], listColClass(c)])));
    return;
  }
  if (err) {
    toolbar.classList.add('hidden');
    box.replaceChildren(riEmpty({ icon: 'circle-alert', tone: 'danger', title: `Couldn’t load ${info.nouns}`, text: err.message + '.', action: riRetry(loadLists) }));
    return;
  }
  if (!res) return;
  const items = res.items || [];
  if (!items.length) {
    toolbar.classList.add('hidden');
    box.replaceChildren(can('admin') ? riEmpty({ icon: info.icon, title: `No ${info.nouns} yet`, text: info.empty, action: { label: 'Upload CSV', icon: 'upload', run: openListUpload } })
      : riEmpty({ icon: info.icon, title: `No ${info.nouns} yet`, text: `An admin uploads the ${info.noun} list.` }));
    return;
  }
  toolbar.classList.remove('hidden');
  const q = $('l-find').value.trim().toLowerCase();
  const matches = items.filter((it) => listMatches(it, q));
  if (!matches.length) {
    box.replaceChildren(riEmpty({ icon: 'search', title: `No ${info.nouns} match`, text: `Nothing in the ${info.noun} list contains “${$('l-find').value.trim()}”.`, action: { label: 'Clear search', run: () => { $('l-find').value = ''; renderList(); $('l-find').focus(); } } }));
    return;
  }
  const cols = res.columns || [];
  const shown = matches.slice(0, LIST_SHOW);
  box.replaceChildren(el('table', { class: 'table l-grid' },
    riHead(cols.map((c) => [LIST_COL_LABEL[c] || c, listColClass(c)])),
    el('tbody', {}, ...shown.map((it) => el('tr', {}, ...cols.map((c) => {
      const content = listCell(c, it[c]);
      const td = el('td', { class: listColClass(c), 'data-label': LIST_COL_LABEL[c] || c }, content);
      // the full value on hover, since long values end in an ellipsis
      const text = Array.isArray(it[c]) ? it[c].join(', ') : c === 'priority' || c === 'watchlist' || it[c] == null ? '' : String(it[c]);
      if (text) td.title = visibleText(text);
      return td;
    }))))));
  const total = res.count;
  const parts = [];
  if (q) parts.push(`${matches.length.toLocaleString()} of ${items.length.toLocaleString()} match`);
  else parts.push(`${total.toLocaleString()} ${total === 1 ? info.noun : info.nouns}`);
  // Rows the sample data adds while it is loaded: not part of the list.
  if (!q && res.sample) parts.push(`${res.sample.toLocaleString()} from the sample data, which go when it is removed`);
  // Hosts Signalith found itself (osquery, scans, the network sensor)
  // that the list does not have yet.
  if (!q && res.found) parts.push(`${res.found.toLocaleString()} found by Signalith (Endpoints, scans, network sensor)`);
  if (shown.length < matches.length) parts.push(`showing the first ${shown.length}`);
  if (!q && items.length < total) parts.push(`the server returns the first ${items.length.toLocaleString()}`);
  fill(foot, el('span', {}, parts.join(' · ')), el('span', { class: 'spacer' }),
    shown.length < matches.length || items.length < total ? el('a', { href: $('l-download').getAttribute('href'), download: '' }, 'Download all as CSV') : null);
  foot.classList.remove('hidden');
}

const listColClass = (c) => 'l-c-' + c + (LIST_KEY.has(c) ? ' l-key' : '') + (c === 'priority' ? ' l-prio' : '');

function selectListKind(kind, focus) {
  listState.kind = kind;
  document.querySelectorAll('#page-assets [role="tab"]').forEach((t) => {
    const on = t.dataset.kind === kind;
    t.setAttribute('aria-selected', String(on));
    t.tabIndex = on ? 0 : -1;
    if (on && focus) t.focus();
  });
  $('l-panel').setAttribute('aria-labelledby', 'l-tab-' + kind);
  $('l-download').setAttribute('href', `api/lookups/${kind}.csv`);
  $('l-find').placeholder = LIST_INFO[kind].find;
  $('l-find').value = '';
  renderList();
}
document.querySelectorAll('#page-assets [role="tab"]').forEach((t) => {
  t.addEventListener('click', () => selectListKind(t.dataset.kind));
  t.addEventListener('keydown', (ev) => {
    if (ev.key !== 'ArrowLeft' && ev.key !== 'ArrowRight') return;
    ev.preventDefault();
    selectListKind(listState.kind === 'assets' ? 'identities' : 'assets', true);
  });
});
$('l-find').addEventListener('input', renderList);

// ---------- list upload dialog ----------
function openListUpload() {
  const info = LIST_INFO[listState.kind];
  $('l-dialog-title').textContent = info.title;
  const [cols, mid, ex, end] = info.columns;
  $('l-columns').replaceChildren(el('span', {}, el('code', {}, cols), mid, el('code', {}, ex), end));
  $('l-example').textContent = info.example;
  $('l-msg').replaceChildren();
  $('l-file').value = '';
  $('l-file').removeAttribute('aria-invalid');
  $('l-upload').disabled = false;
  $('l-dialog').showModal();
}
$('l-upload-open').addEventListener('click', openListUpload);
$('l-dialog').querySelectorAll('[data-close]').forEach((b) => b.addEventListener('click', () => $('l-dialog').close()));
$('l-file').addEventListener('change', () => { $('l-file').removeAttribute('aria-invalid'); $('l-msg').replaceChildren(); });

// riAlert is a form-level message (SPEC section 9).
const RI_ALERT_ICON = { danger: 'circle-alert', warning: 'triangle-alert', success: 'circle-check', info: 'info' };
function riAlert(tone, title, ...rest) {
  return el('div', { class: 'alert', 'data-tone': tone, role: tone === 'danger' ? 'alert' : 'status' },
    icon(RI_ALERT_ICON[tone] || 'info'), el('div', {}, el('b', {}, title), ...rest));
}

// riLineErrors lists the bad lines the server reported for an upload.
function riLineErrors(lines) {
  if (!lines || !lines.length) return null;
  return el('ul', { class: 'ri-lines' }, ...lines.slice(0, 20).map((l) => el('li', {}, el('span', { class: 'mono' }, `Line ${l.line}`), ' ', l.msg)),
    lines.length > 20 ? el('li', { class: 'subtle' }, `and ${lines.length - 20} more`) : null);
}

$('l-form').addEventListener('submit', async (ev) => {
  ev.preventDefault();
  const kind = listState.kind;
  const info = LIST_INFO[kind];
  const msg = $('l-msg');
  const file = $('l-file').files[0];
  if (!file) {
    $('l-file').setAttribute('aria-invalid', 'true');
    msg.replaceChildren(riAlert('danger', 'Choose a CSV file first.'));
    $('l-file').focus();
    return;
  }
  const btn = $('l-upload');
  btn.disabled = true;
  try {
    const text = await file.text();
    // Shared by the servers of a cluster: the upload replaces the list as
    // it was shown, and a list changed meanwhile is not overwritten
    // unless the admin says so.
    let etag = (listState.res[kind] || {}).etag || '';
    let resp, data;
    for (;;) {
      const headers = { 'Content-Type': 'text/csv' };
      if (etag) headers['If-Match'] = '"' + etag + '"';
      resp = await apiRaw('api/lookups/' + kind, { method: 'PUT', headers, body: text });
      data = await resp.json().catch(() => ({}));
      if (resp.status !== 412) break;
      const choice = await libraryStale({ data }, info.noun + ' list');
      if (choice === 'overwrite') {
        etag = await latestETag('api/lookups/' + kind);
        continue;
      }
      if (choice === 'reload') {
        $('l-dialog').close();
        loadLists();
      }
      return;
    }
    if (!resp.ok) {
      msg.replaceChildren(riAlert('danger', riCap(data.error || resp.statusText) + '.', riLineErrors(data.lines)));
      return;
    }
    $('l-dialog').close();
    toast(`Saved ${data.count.toLocaleString()} ${data.count === 1 ? info.noun : info.nouns}. New findings and risk use them right away.`);
    loadLists();
  } catch (e) {
    msg.replaceChildren(riAlert('danger', 'The upload failed.', el('p', {}, e.message)));
  } finally {
    btn.disabled = false;
  }
});

pageHooks.push((name) => {
  if (name === 'risk') loadRisk();
  if (name === 'assets') loadLists();
});
