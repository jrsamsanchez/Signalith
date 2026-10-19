// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0
// Attack storyline: the findings and risk events about a user, system or
// address, and the entities and activity that tie them together, as one
// story ordered by ATT&CK tactic. Opened from a finding, an investigation,
// the Risk page, the asset and identity lists, or by name.
'use strict';

const sl = {
  params: null, // { type, object, since } | { finding } | { case }
  data: null, // the API response
  error: null,
  seq: 0,
  view: 'tactic', // tactic or time
  phase: null, // tactic short name the timeline is filtered to, or null
  node: null, // selected graph node ID
  act: 'login', // activity tab
};

const SL_TYPE_LABEL = { user: 'User', system: 'System', ip: 'Address', process: 'Process', other: 'Other' };
const SL_TYPE_PLURAL = { user: 'Users', system: 'Systems', ip: 'Addresses', process: 'Processes', other: 'Other' };
const SL_TYPE_ICON = { user: 'user', system: 'server', ip: 'globe', process: 'terminal', other: 'tag' };
const SL_TYPE_ORDER = ['user', 'system', 'ip', 'process', 'other'];
const SL_SINCE = { '24h': 'last 24 hours', '7d': 'last 7 days', '30d': 'last 30 days' };
const SL_EDGE_LABEL = { together: 'In the same finding', login: 'Signed in', started: 'Started', ran: 'Ran on', connected: 'Connected' };
const SL_ACT = {
  login: { label: 'Sign-ins', icon: 'log-in', empty: 'No sign-ins between these users and systems.', cols: [['user', 'User'], ['src', 'From'], ['dest', 'To'], ['action', 'Result']] },
  process: { label: 'Processes', icon: 'terminal', empty: 'No process starts of the processes in these findings.', cols: [['dest', 'System'], ['parent_process_name', 'Parent'], ['process_name', 'Process']] },
  connection: { label: 'Connections', icon: 'network', empty: 'No connections to or from the addresses in these findings.', cols: [['src', 'From'], ['dest', 'To'], ['dest_port', 'Port'], ['action', 'Result']] },
};
const slRank = (s) => (s ? SEVERITIES.length - SEVERITIES.indexOf(s) : 0);
const slNum = (v) => (typeof v === 'number' ? v.toLocaleString(undefined, { maximumFractionDigits: 1 }) : String(v ?? ''));
const slPlural = (n, one, many) => `${n.toLocaleString()} ${n === 1 ? one : many || one + 's'}`;

// openStoryline opens the storyline page on a user, system or address
// ({ type, object, since }), a finding ({ finding }) or a case ({ case }).
function openStoryline(params) {
  sl.params = params;
  sl.phase = null;
  sl.node = null;
  if ($('page-storyline').classList.contains('active')) loadStoryline();
  else showPage('storyline');
}

// storylineButton is the button other pages show to open a storyline.
function storylineButton(params, opts = {}) {
  const b = el('button', { type: 'button', class: `btn btn--${opts.kind || 'secondary'}${opts.sm ? ' btn--sm' : ''}`, title: opts.title || 'See every finding and risk event about this as one attack story, in ATT&CK order' },
    icon('waypoints'), opts.label || 'Attack storyline');
  b.addEventListener('click', () => openStoryline(params));
  return b;
}

// slParamsFrom reads storyline parameters from an address query.
function slParamsFrom(q) {
  const p = new URLSearchParams(q);
  if (p.get('finding')) return { finding: p.get('finding') };
  if (p.get('case')) return { case: p.get('case') };
  if (p.get('object')) return { type: p.get('type') || 'system', object: p.get('object'), since: SL_SINCE[p.get('since')] ? p.get('since') : '7d' };
  return null;
}

pageHooks.push((name) => {
  if (name !== 'storyline') return;
  // An address such as #storyline?type=user&object=bob names the story.
  if (typeof pageQuery !== 'undefined' && pageQuery) {
    const p = slParamsFrom(pageQuery);
    pageQuery = '';
    if (p) { sl.params = p; sl.phase = null; sl.node = null; }
  }
  loadStoryline();
});
window.addEventListener('hashchange', () => {
  if (currentPage !== 'storyline' || typeof pageQuery === 'undefined' || !pageQuery) return;
  const p = slParamsFrom(pageQuery);
  pageQuery = '';
  if (p && JSON.stringify(p) !== JSON.stringify(sl.params)) openStoryline(p);
});

// slSyncAddress keeps the address on the open story, so it can be shared
// and Back returns to it.
function slSyncAddress() {
  if (!sl.params || currentPage !== 'storyline') return;
  const p = new URLSearchParams(Object.entries(sl.params).filter(([, v]) => v));
  const want = '#storyline?' + p;
  if (location.hash !== want) { try { history.replaceState(null, '', want); } catch (_) { /* sandboxed */ } }
}

async function loadStoryline() {
  const seq = ++sl.seq;
  slSyncForm();
  slSyncAddress();
  const box = $('sl-body');
  if (!sl.params) {
    sl.data = null;
    $('sl-case').classList.add('hidden');
    fill(box, el('div', { class: 'card' }, dxEmpty({
      icon: 'waypoints', title: 'Follow an attack from start to finish',
      text: 'Enter a user, host or IP address to see every finding and risk event about it as one story, ordered by ATT&CK tactic, with the accounts, systems and processes that tie them together.',
      hint: 'You can also open a storyline from a finding, an investigation, the Risk page or the asset and identity lists.',
    })));
    return;
  }
  box.setAttribute('aria-busy', 'true');
  if (!sl.data) fill(box, slSkeleton());
  let res;
  try {
    res = await api('api/storyline?' + new URLSearchParams(Object.entries(sl.params).filter(([, v]) => v)));
  } catch (e) {
    if (seq !== sl.seq) return;
    box.removeAttribute('aria-busy');
    sl.data = null;
    $('sl-case').classList.add('hidden');
    fill(box, el('div', { class: 'card' }, dxEmpty({ tone: 'danger', icon: 'circle-alert', title: 'Couldn’t build the storyline', text: sentence(e.message), action: dxRetry(loadStoryline) })));
    return;
  }
  if (seq !== sl.seq) return;
  sl.data = res;
  box.removeAttribute('aria-busy');
  renderStoryline();
}

function slSkeleton() {
  const kpi = () => el('div', { class: 'card kpi' }, dxSkel('50%'), el('span', { class: 'skeleton', style: 'width:40%;height:28px' }), dxSkel('70%'));
  return el('div', { class: 'sl-stack' },
    el('div', { class: 'sl-kpis' }, kpi(), kpi(), kpi(), kpi()),
    el('div', { class: 'card sl-chain-card' }, el('div', { class: 'card__body' }, el('span', { class: 'skeleton', style: 'width:100%;height:56px' }))),
    el('div', { class: 'sl-grid' },
      el('div', { class: 'card' }, el('div', { class: 'card__body sl-skel' }, dxSkel('35%'), dxSkel('90%'), dxSkel('80%'), dxSkel('85%'), dxSkel('60%'))),
      el('div', { class: 'card' }, el('div', { class: 'card__body sl-skel' }, dxSkel('30%'), el('span', { class: 'skeleton', style: 'width:100%;height:220px' })))));
}

// ---------- the form ----------
function slSyncForm() {
  const p = sl.params || {};
  if (p.object) {
    $('sl-object').value = p.object;
    $('sl-type').value = p.type === 'ip' ? 'system' : p.type;
  }
  const since = p.since || '7d';
  $('sl-since').querySelectorAll('button').forEach((b) => b.setAttribute('aria-pressed', String(b.dataset.since === since)));
  // A finding's or case's story covers the days around it.
  $('sl-since').classList.toggle('hidden', !!(p.finding || p.case));
}

$('sl-form').addEventListener('submit', (ev) => {
  ev.preventDefault();
  const object = $('sl-object').value.trim();
  if (!object) { $('sl-object').focus(); return; }
  const type = looksLikeIP(object) ? 'ip' : $('sl-type').value;
  openStoryline({ type, object, since: (sl.params && sl.params.since) || '7d' });
});
$('sl-since').querySelectorAll('button').forEach((b) => b.addEventListener('click', () => {
  const p = sl.params;
  if (!p || !p.object || p.since === b.dataset.since) return;
  openStoryline({ ...p, since: b.dataset.since });
}));
$('sl-refresh').addEventListener('click', loadStoryline);
$('sl-case').addEventListener('click', (ev) => slOpenCase(ev.currentTarget));

// ---------- the page ----------
function renderStoryline() {
  const { storyline: st, anchor } = sl.data;
  const box = $('sl-body');
  const caseBtn = $('sl-case');
  const findingIDs = st.items.filter((i) => i.kind === 'finding').map((i) => i.id);
  const canCase = can('analyst') && (anchor.kind === 'case' || findingIDs.length > 0);
  caseBtn.classList.toggle('hidden', !canCase);
  caseBtn.lastChild.textContent = anchor.kind === 'case' ? 'Open investigation' : 'Open an investigation';
  caseBtn.title = anchor.kind === 'case' ? 'Go back to this investigation' : 'Open an investigation holding every finding in this story';
  document.title = 'Storyline: ' + visibleText(slSeedText(st.seeds)) + ' · Signalith';

  const parts = [slAnchor(st, anchor), slKpis(st), slChain(st, sl.data.tactics || [])];
  for (const w of st.warnings || []) parts.push(el('div', { class: 'alert', 'data-tone': 'warning' }, icon('triangle-alert'), el('div', {}, w)));
  if ((st.truncated || []).length) {
    const what = { findings: `the first ${200} findings`, risk: 'the first 300 risk events', nodes: 'the 60 most involved entities', edges: 'the 120 strongest links', login: 'the 40 busiest sign-ins', process: 'the 40 busiest process starts', connection: 'the 40 busiest connections' };
    parts.push(el('div', { class: 'alert', 'data-tone': 'info' }, icon('info'),
      el('div', {}, el('b', {}, 'This story is large. '), 'It shows ' + st.truncated.map((t) => what[t] || t).join(', ') + '. A shorter time range shows everything.')));
  }
  if (!st.items.length) {
    const p = sl.params;
    parts.push(el('div', { class: 'card' }, dxEmpty({
      icon: 'shield-check', title: 'No findings or risk in this period',
      text: `Nothing was detected about ${slSeedText(st.seeds)} ${p.since ? 'in the ' + SL_SINCE[p.since] : 'in the days around it'}.`,
      action: p.object && p.since !== '30d' ? { label: 'Look at 30 days', icon: 'calendar', run: () => openStoryline({ ...p, since: '30d' }) } : null,
    })));
  } else {
    parts.push(el('div', { class: 'sl-grid' }, slTimelineCard(st), slGraphCard(st)));
  }
  if (st.activity.length || Object.keys(st.searches || {}).some((k) => SL_ACT[k])) parts.push(slActivityCard(st));
  fill(box, el('div', { class: 'sl-stack' }, ...parts.filter(Boolean)));
  // The graph's width follows its card.
  slDrawGraph();
}

function slSeedText(seeds) {
  const names = seeds.map((s) => s.value);
  if (names.length <= 2) return names.join(' and ');
  return `${names.slice(0, 2).join(', ')} and ${slPlural(names.length - 2, 'other')}`;
}

function slAnchor(st, anchor) {
  const seeds = el('div', { class: 'chips sl-seeds' }, ...st.seeds.map((s) => el('span', { class: 'chip', 'data-kind': s.type === 'system' ? 'host' : s.type }, el('span', {}, s.value))));
  const range = `${fmtTime(st.earliest)} to ${fmtTime(st.latest)}`;
  let lead;
  if (anchor.kind === 'finding') {
    const a = el('a', { href: '#findings' }, anchor.title);
    a.addEventListener('click', (ev) => { ev.preventDefault(); openFindingFromCase(anchor.id); });
    lead = ['Built from the finding ', a, ', over the three days before it and the day after.'];
  } else if (anchor.kind === 'case') {
    const a = el('a', { href: '#cases' }, anchor.title);
    a.addEventListener('click', (ev) => { ev.preventDefault(); openCase(anchor.id); });
    lead = ['Built from the investigation ', a, ', around its findings.'];
  } else {
    lead = [`Everything about this ${(SL_TYPE_LABEL[anchor.type] || 'entity').toLowerCase()} in the ${SL_SINCE[anchor.since] || 'chosen period'}.`];
  }
  return el('div', { class: 'sl-anchor' },
    el('div', { class: 'sl-anchor__text' }, el('span', { class: 'sl-anchor__label' }, 'Following'), seeds),
    el('p', { class: 'sl-anchor__lead' }, ...lead, ' ', el('span', { class: 'sl-anchor__range', title: range }, range)));
}

function slKpis(st) {
  const fs = st.items.filter((i) => i.kind === 'finding');
  const open = fs.filter((f) => !['resolved', 'closed'].includes(f.status)).length;
  const top = fs.reduce((a, f) => (slRank(f.severity) > slRank(a) ? f.severity : a), '');
  const mapped = st.phases.filter((p) => p.tactic);
  const furthest = mapped[mapped.length - 1];
  const count = (t) => st.nodes.filter((n) => n.type === t).length;
  const kpi = (name, label, value, foot, attrs = {}) => el('div', { class: 'card kpi', ...attrs },
    el('div', { class: 'kpi__label' }, icon(name), label), el('div', { class: 'kpi__value num' }, ...[].concat(value)), el('div', { class: 'kpi__foot' }, ...[].concat(foot)));
  const riskBandOf = (n) => (n >= 200 ? 'critical' : n >= 100 ? 'high' : n >= 50 ? 'medium' : 'low');
  return el('div', { class: 'sl-kpis' },
    kpi('shield-alert', 'Findings', fs.length.toLocaleString(), fs.length ? [top ? sevBadge(top) : null, el('span', {}, `${open} open`)] : 'none in this period', top ? { 'data-sev': top } : {}),
    kpi('gauge', 'Risk', slNum(st.risk), st.risk ? el('span', {}, `${st.items.filter((i) => i.risk).length} events added risk`) : 'no risk events', st.risk ? { 'data-sev': riskBandOf(st.risk) } : {}),
    kpi('target', 'ATT&CK tactics', [String(mapped.length), el('small', {}, ' of ' + ((sl.data.tactics || []).length || 14))], furthest ? el('span', { class: 'sl-ellipsis' }, 'Furthest: ' + furthest.name) : 'none mapped'),
    kpi('network', 'Entities', st.nodes.length.toLocaleString(),
      el('span', { class: 'sl-ellipsis' }, [slPlural(count('user'), 'user'), slPlural(count('system') + count('ip'), 'system')].join(' · '))));
}

// slChain is the kill chain: every ATT&CK tactic in order, lit where the
// story reached it. Picking a lit tactic filters the timeline to it.
function slChain(st, tactics) {
  const byTac = new Map(st.phases.map((p) => [p.tactic, p]));
  const steps = tactics.map((t) => ({ tactic: t.short, name: t.name, id: t.id, phase: byTac.get(t.short) }));
  const list = el('ol', { class: 'sl-chain', 'aria-label': 'ATT&CK tactics in order' }, ...steps.map((s, i) => {
    const p = s.phase;
    const on = sl.phase === s.tactic;
    const attrs = { class: 'sl-step' + (p ? ' sl-step--hit' : '') + (s.tactic === '' ? ' sl-step--none' : ''), 'data-sev': p ? p.severity || 'informational' : '' };
    const inner = [el('span', { class: 'sl-step__n' }, s.tactic ? String(i + 1) : '–'),
      slStepName(s.name),
      el('span', { class: 'sl-step__count' }, p ? slPlural(p.items, 'item') : '—')];
    if (!p) return el('li', attrs, el('div', { class: 'sl-step__box', title: `${s.name} (${s.id}): not seen` }, ...inner));
    const b = el('button', { type: 'button', class: 'sl-step__box', 'aria-pressed': String(on), title: `${s.name}${s.id ? ' (' + s.id + ')' : ''}: ${slPlural(p.items, 'item')}, first ${fmtTime(p.first)}. Show only these.` }, ...inner);
    b.addEventListener('click', () => { sl.phase = on ? null : s.tactic; renderStoryline(); });
    return el('li', attrs, b);
  }));
  return el('section', { class: 'card sl-chain-card', 'aria-label': 'Kill chain' },
    el('div', { class: 'card__head' }, el('div', {}, el('h3', { class: 'card__title' }, 'Kill chain'),
      el('p', { class: 'card__sub' }, 'The ATT&CK tactics this story reached, in the order attacks usually move through them.'))),
    el('div', { class: 'sl-chain-wrap' }, list));
}

// slStepName lets the long tactic names break inside a word, at a soft
// hyphen, so the whole chain fits in one row. The text is set directly:
// soft hyphens in data are shown as markers elsewhere, but these are ours.
const SL_BREAKS = { Reconnaissance: 'Reconnais-sance', Development: 'Develop-ment', Persistence: 'Persis-tence', Escalation: 'Escala-tion',
  Impairment: 'Impair-ment', Credential: 'Creden-tial', Discovery: 'Discov-ery', Movement: 'Move-ment', Collection: 'Collec-tion', Exfiltration: 'Exfil-tration' };
function slStepName(name) {
  const n = el('span', { class: 'sl-step__name', title: name });
  n.textContent = name.split(' ').map((w) => (SL_BREAKS[w] || w).replace('-', '\u00ad')).join(' ');
  return n;
}

// ---------- timeline ----------
function slTimelineCard(st) {
  const seg = el('div', { class: 'seg seg--sm', role: 'group', 'aria-label': 'Order' }, ...[['tactic', 'By tactic'], ['time', 'By time']].map(([v, label]) => {
    const b = el('button', { type: 'button', 'aria-pressed': String(sl.view === v) }, label);
    b.addEventListener('click', () => { if (sl.view !== v) { sl.view = v; renderStoryline(); } });
    return b;
  }));
  const phaseName = (t) => (st.phases.find((p) => p.tactic === t) || {}).name || t;
  const filter = sl.phase != null ? el('div', { class: 'sl-filter' }, el('span', {}, 'Showing ', el('b', {}, phaseName(sl.phase))),
    dxBtn('ghost', 'Show all', () => { sl.phase = null; renderStoryline(); }, { sm: true, icon: 'x' })) : null;
  const inPhase = (it) => sl.phase == null || (sl.phase === '' ? !(it.tactics || []).length : (it.tactics || []).includes(sl.phase));
  const items = st.items.filter(inPhase);
  let list;
  if (sl.view === 'time') {
    list = el('ol', { class: 'sl-items' }, ...items.map((it) => slItem(it, st)));
  } else {
    const groups = st.phases.filter((p) => sl.phase == null || p.tactic === sl.phase).map((p) => {
      const its = st.items.filter((it) => (p.tactic === '' ? !(it.tactics || []).length : (it.tactics || []).includes(p.tactic)));
      return el('li', { class: 'sl-phase', 'data-sev': p.severity || 'informational' },
        el('div', { class: 'sl-phase__head' },
          el('span', { class: 'sl-phase__bar', 'aria-hidden': 'true' }),
          el('h4', { class: 'sl-phase__name' }, p.name),
          p.id ? el('a', { class: 'badge badge--outline badge--mono', href: 'https://attack.mitre.org/tactics/' + p.id + '/', target: '_blank', rel: 'noopener', title: 'About this tactic on attack.mitre.org' }, p.id) : null,
          el('span', { class: 'count' }, String(its.length)),
          el('span', { class: 'sl-phase__when', title: `${fmtTime(p.first)} to ${fmtTime(p.last)}` }, slSpan(p.first, p.last))),
        el('ol', { class: 'sl-items' }, ...its.map((it) => slItem(it, st))));
    });
    list = el('ol', { class: 'sl-phases' }, ...groups);
  }
  return el('section', { class: 'card sl-timeline', 'aria-label': 'Timeline' },
    el('div', { class: 'card__head' },
      el('div', {}, el('h3', { class: 'card__title' }, 'Timeline'), el('p', { class: 'card__sub' }, `${slPlural(st.items.length, 'finding and risk event', 'findings and risk events')}, ${slSpan(st.items[0].time, st.items[st.items.length - 1].time)}`)),
      el('div', { class: 'card__actions' }, seg)),
    el('div', { class: 'card__body sl-timeline__body' }, slLanes(st), filter, list));
}

// slSpan describes a time range briefly.
function slSpan(a, b) {
  const da = new Date(a);
  const db = new Date(b);
  const ms = db - da;
  const day = (d) => d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
  const hm = (d) => d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' });
  if (ms < 60e3) return `${day(da)}, ${hm(da)}`;
  const dur = ms < 3600e3 ? `${Math.round(ms / 60e3)} min` : ms < 2 * 86400e3 ? `${Math.round(ms / 3600e3)} h` : `${Math.round(ms / 86400e3)} days`;
  return da.toDateString() === db.toDateString() ? `${day(da)}, ${hm(da)} to ${hm(db)} (${dur})` : `${day(da)} to ${day(db)} (${dur})`;
}

function slItem(it, st) {
  const nodes = new Map(st.nodes.map((n) => [n.id, n]));
  // Every item is about the followed entities, so only the others show.
  const ents = (it.entities || []).map((id) => nodes.get(id)).filter((n) => n && !n.seed).slice(0, 3);
  const d = new Date(it.time);
  const right = it.kind === 'finding'
    ? [sevBadge(it.severity), it.risk ? el('span', { class: 'sl-risk', title: 'Risk this added' }, '+' + slNum(it.risk)) : null]
    : [el('span', { class: 'badge badge--accent' }, 'Risk'), el('span', { class: 'sl-risk', title: 'Risk this added' }, '+' + slNum(it.risk))];
  const tactics = sl.view === 'time' && (it.tactics || []).length
    ? (it.tactics || []).map((t) => el('span', { class: 'tech tech--plain' }, (st.phases.find((p) => p.tactic === t) || {}).name || t)) : [];
  const b = el('button', { type: 'button', class: 'sl-item', 'data-item': it.id, 'data-sev': it.severity || '' },
    el('span', { class: 'sl-item__time', title: fmtTime(it.time) },
      el('span', {}, d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' })),
      el('span', { class: 'tabular' }, d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' }))),
    el('span', { class: 'sl-item__main' },
      el('span', { class: 'sl-item__title' }, it.title || it.detection_id || 'Risk event'),
      el('span', { class: 'sl-item__meta' },
        it.kind === 'finding' && it.status ? statusBadge(it.status) : null,
        it.case_id ? el('span', { class: 'badge', title: 'In investigation ' + it.case_id }, icon('briefcase', 'icon--xs'), 'In a case') : null,
        ...tactics,
        ...ents.map((n) => el('span', { class: 'chip', 'data-kind': n.type === 'system' ? 'host' : n.type }, el('span', {}, n.value))))),
    el('span', { class: 'sl-item__side' }, ...right));
  b.title = it.kind === 'finding' ? 'Open this finding' : 'Show this risk event in Search';
  b.addEventListener('click', () => {
    if (it.kind === 'finding') { openFindingFromCase(it.id); return; }
    const t = new Date(it.time).getTime();
    openSearch(`datamodel=Risk detection_id=${quoteValue(it.detection_id || '*')}`, new Date(t - 60e3).toISOString(), new Date(t + 60e3).toISOString());
  });
  return el('li', {}, b);
}

// slLanes draws the swimlanes: one row per tactic, each item a mark at its
// time, and a line through the first item of each tactic showing how the
// attack moved.
function slLanes(st) {
  const phases = st.phases;
  const items = st.items;
  const wrap = el('div', { class: 'sl-lanes' });
  const draw = () => {
    const W = Math.max(280, wrap.clientWidth || 600);
    const small = W < 560;
    const labelW = small ? 104 : 156;
    const rowH = small ? 26 : 28;
    const top = 6;
    const H = top + phases.length * rowH + 26;
    const x0 = labelW + 10;
    const x1 = W - 14;
    let t0 = new Date(items[0].time).getTime();
    let t1 = new Date(items[items.length - 1].time).getTime();
    if (t1 - t0 < 60e3) { t0 -= 1800e3; t1 += 1800e3; }
    const pad = (t1 - t0) * 0.04;
    t0 -= pad; t1 += pad;
    const x = (t) => x0 + ((new Date(t).getTime() - t0) / (t1 - t0)) * (x1 - x0);
    const rowY = (i) => top + i * rowH + rowH / 2;
    const s = slSvg('svg', { class: 'sl-lanes__svg', width: W, height: H, viewBox: `0 0 ${W} ${H}`, role: 'img', 'aria-label': `Timeline of ${items.length} items across ${phases.length} tactics` });
    // ticks
    const ticks = small ? 2 : 4;
    for (let i = 0; i <= ticks; i++) {
      const t = t0 + ((t1 - t0) * i) / ticks;
      const tx = x(t);
      s.append(slSvg('line', { class: 'sl-grid-line', x1: tx, x2: tx, y1: top, y2: top + phases.length * rowH }));
      const d = new Date(t);
      const label = (t1 - t0) > 2 * 86400e3 ? d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' }) : d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' });
      s.append(slSvg('text', { class: 'sl-tick', x: tx, y: H - 8, 'text-anchor': i === 0 ? 'start' : i === ticks ? 'end' : 'middle' }, label));
    }
    phases.forEach((p, i) => {
      if (i % 2 === 0) s.append(slSvg('rect', { class: 'sl-band', x: 0, y: top + i * rowH, width: W, height: rowH, rx: 4 }));
      s.append(slSvg('text', { class: 'sl-lane-label' + (sl.phase === p.tactic ? ' sl-lane-label--on' : ''), x: 8, y: rowY(i) + 4 }, slFit(p.name, labelW - 12, 6.4)));
    });
    // the path through the first item of each tactic
    const firsts = phases.map((p, i) => (p.tactic ? [x(p.first), rowY(i)] : null)).filter(Boolean);
    if (firsts.length > 1) s.append(slSvg('polyline', { class: 'sl-path', points: firsts.map((pt) => pt.join(',')).join(' ') }));
    const row = new Map(phases.map((p, i) => [p.tactic, i]));
    items.forEach((it) => {
      const rows = (it.tactics || []).length ? it.tactics.map((t) => row.get(t)).filter((v) => v != null) : [row.get('')];
      for (const r of rows) {
        if (r == null) continue;
        const cx = x(it.time);
        const cy = rowY(r);
        const g = slSvg('g', { class: 'sl-mark', 'data-sev': it.kind === 'finding' ? it.severity : 'risk', tabindex: '-1' });
        g.append(slSvg('title', {}, `${it.title || it.detection_id} · ${fmtTime(it.time)}`));
        if (it.kind === 'finding') g.append(slSvg('circle', { cx, cy, r: 5.5 }));
        else g.append(slSvg('polygon', { points: `${cx},${cy - 6} ${cx + 6},${cy} ${cx},${cy + 6} ${cx - 6},${cy}` }));
        g.addEventListener('click', () => slFlashItem(it.id));
        s.append(g);
      }
    });
    wrap.replaceChildren(s);
  };
  slAfterLayout(wrap, draw);
  return wrap;
}

function slFlashItem(id) {
  const b = document.querySelector(`#sl-body .sl-item[data-item="${CSS.escape(id)}"]`);
  if (!b) return;
  b.scrollIntoView({ block: 'center', behavior: matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth' });
  b.classList.remove('sl-flash');
  void b.offsetWidth;
  b.classList.add('sl-flash');
  b.focus({ preventScroll: true });
}

// ---------- graph ----------
function slGraphCard(st) {
  const legend = el('ul', { class: 'sl-legend', 'aria-label': 'Links' },
    ...['together', 'login', 'started', 'connected'].filter((k) => st.edges.some((e) => e.kind === k || (k === 'started' && e.kind === 'ran')))
      .map((k) => el('li', { 'data-kind': k }, el('span', { class: 'sl-legend__line', 'aria-hidden': 'true' }), SL_EDGE_LABEL[k])));
  return el('section', { class: 'card sl-graph', 'aria-label': 'Entities' },
    el('div', { class: 'card__head' }, el('div', {}, el('h3', { class: 'card__title' }, 'Who and what'),
      el('p', { class: 'card__sub' }, 'Users, systems, addresses and processes, linked by the findings and activity they share. Pick one for details.'))),
    el('div', { class: 'card__body sl-graph__body' }, el('div', { class: 'sl-graph__canvas', id: 'sl-canvas' }), legend, el('div', { id: 'sl-node', class: 'sl-node-detail', 'aria-live': 'polite' })));
}

function slDrawGraph() {
  const box = $('sl-canvas');
  if (!box || !sl.data) return;
  slAfterLayout(box, () => slGraph(box, sl.data.storyline));
  slNodeDetail();
}

const SL_PER_COL = 10;
function slGraph(box, st) {
  const cols = SL_TYPE_ORDER.filter((t) => st.nodes.some((n) => n.type === t));
  const avail = box.clientWidth || 480;
  const byCol = cols.map((t) => {
    const ns = st.nodes.filter((n) => n.type === t).sort((a, b) => (b.seed - a.seed) || (b.findings - a.findings) || (b.risk - a.risk) || a.value.localeCompare(b.value));
    return { type: t, shown: ns.slice(0, SL_PER_COL), more: Math.max(0, ns.length - SL_PER_COL) };
  });
  const rowH = 70;
  const pos = new Map();
  const labels = [];
  // Wide: a column per type, read left to right. Narrow (a phone): a band
  // per type, read top to bottom, its entities in rows.
  const bands = avail / cols.length < 118;
  let W;
  let H;
  let colW;
  if (!bands) {
    colW = Math.floor(avail / cols.length);
    W = avail;
    const top = 34;
    const rows = Math.max(...byCol.map((c) => c.shown.length + (c.more ? 1 : 0)));
    H = top + rows * rowH;
    byCol.forEach((c, ci) => {
      const cx = colW * ci + colW / 2;
      c.shown.forEach((n, i) => pos.set(n.id, { x: cx, y: top + i * rowH + 20, r: n.seed ? 17 : 14, n }));
      labels.push(slSvg('text', { class: 'sl-col-label', x: cx, y: 14, 'text-anchor': 'middle' }, `${SL_TYPE_PLURAL[c.type]} · ${c.shown.length + c.more}`));
      if (c.more) labels.push(slSvg('text', { class: 'sl-more', x: cx, y: top + c.shown.length * rowH + 22, 'text-anchor': 'middle' }, `+${c.more} more`));
    });
  } else {
    W = avail;
    const per = Math.max(2, Math.floor(W / 112));
    colW = Math.floor(W / per);
    let y = 0;
    byCol.forEach((c) => {
      labels.push(slSvg('text', { class: 'sl-col-label', x: 0, y: y + 14 }, `${SL_TYPE_PLURAL[c.type]} · ${c.shown.length + c.more}`));
      y += 30;
      c.shown.forEach((n, i) => pos.set(n.id, { x: colW * (i % per) + colW / 2, y: y + Math.floor(i / per) * rowH + 20, r: n.seed ? 17 : 14, n }));
      y += Math.ceil(c.shown.length / per) * rowH;
      if (c.more) { labels.push(slSvg('text', { class: 'sl-more', x: W / 2, y: y + 4, 'text-anchor': 'middle' }, `+${c.more} more`)); y += 18; }
      y += 12;
    });
    H = y;
  }
  const s = slSvg('svg', { class: 'sl-graph__svg', width: W, height: H, viewBox: `0 0 ${W} ${H}`, role: 'group', 'aria-label': `${st.nodes.length} entities and ${st.edges.length} links` });
  const defs = slSvg('defs', {});
  for (const k of ['login', 'started', 'connected']) {
    defs.append(slSvg('marker', { id: 'sl-arrow-' + k, viewBox: '0 0 10 10', refX: 9, refY: 5, markerWidth: 8, markerHeight: 8, markerUnits: 'userSpaceOnUse', orient: 'auto-start-reverse', class: 'sl-arrow', 'data-kind': k },
      slSvg('path', { d: 'M 0 1 L 9 5 L 0 9 z' })));
  }
  s.append(defs);
  labels.forEach((l) => s.append(l));
  const edges = slSvg('g', { class: 'sl-edges' });
  for (const e of st.edges) {
    const a = pos.get(e.from);
    const b = pos.get(e.to);
    if (!a || !b) continue;
    const kind = e.kind === 'ran' ? 'started' : e.kind;
    let d;
    if (bands) {
      // vertical curves between bands; across a row, an arc above it
      if (Math.abs(a.y - b.y) < 1) {
        const lift = 22 + Math.abs(a.x - b.x) / 8;
        d = `M ${a.x} ${a.y - a.r} C ${a.x} ${a.y - a.r - lift}, ${b.x} ${b.y - b.r - lift}, ${b.x} ${b.y - b.r - 2}`;
      } else {
        const dir = b.y > a.y ? 1 : -1;
        const sy = a.y + dir * (a.r + (dir > 0 ? 30 : 0));
        const ey = b.y - dir * (b.r + 2 + (dir < 0 ? 30 : 0));
        const mid = (ey - sy) / 2;
        d = `M ${a.x} ${sy} C ${a.x} ${sy + mid}, ${b.x} ${ey - mid}, ${b.x} ${ey}`;
      }
    } else if (Math.abs(a.x - b.x) < 1) {
      // same column: an arc out to the left
      const bend = Math.min(colW / 2 - 8, 26 + Math.abs(a.y - b.y) / 6);
      d = `M ${a.x - a.r} ${a.y} C ${a.x - a.r - bend} ${a.y}, ${b.x - b.r - bend} ${b.y}, ${b.x - b.r - 2} ${b.y}`;
    } else {
      const dir = b.x > a.x ? 1 : -1;
      const sx = a.x + dir * a.r;
      const ex = b.x - dir * (b.r + 2);
      const mid = (ex - sx) / 2;
      d = `M ${sx} ${a.y} C ${sx + mid} ${a.y}, ${ex - mid} ${b.y}, ${ex} ${b.y}`;
    }
    const attrs = { d, class: 'sl-edge', 'data-kind': kind, 'data-from': e.from, 'data-to': e.to, 'stroke-width': Math.min(4, 1.25 + Math.log2(e.count) * 0.6).toFixed(2) };
    if (kind !== 'together') attrs['marker-end'] = `url(#sl-arrow-${kind})`;
    const p = slSvg('path', attrs);
    p.append(slSvg('title', {}, `${SL_EDGE_LABEL[e.kind] || e.kind}${e.label ? ' (' + e.label + ')' : ''}: ${a.n.value} → ${b.n.value}, ${slPlural(e.count, 'time')}`));
    edges.append(p);
  }
  s.append(edges);
  const maxChars = Math.max(8, Math.floor((colW - 14) / 6.6));
  for (const { x, y, r, n } of pos.values()) {
    const sub = n.findings ? slPlural(n.findings, 'finding') : n.risk ? 'risk ' + slNum(n.risk) : n.context && n.context.name ? n.context.name : SL_TYPE_LABEL[n.type];
    const g = slSvg('g', { class: 'sl-gnode' + (n.seed ? ' sl-gnode--seed' : '') + (sl.node === n.id ? ' sl-gnode--on' : ''), 'data-id': n.id, 'data-sev': n.severity || '', tabindex: '0', role: 'button',
      'aria-label': `${SL_TYPE_LABEL[n.type]} ${visibleText(n.value)}${n.seed ? ', followed' : ''}: ${sub}`, 'aria-pressed': String(sl.node === n.id) });
    if (n.seed) g.append(slSvg('circle', { class: 'sl-gnode__ring', cx: x, cy: y, r: r + 4 }));
    g.append(slSvg('circle', { class: 'sl-gnode__dot', cx: x, cy: y, r }));
    const ic = slSvg('use', { href: '#i-' + SL_TYPE_ICON[n.type], x: x - 7, y: y - 7, width: 14, height: 14, class: 'sl-gnode__icon' });
    g.append(ic);
    g.append(slSvg('text', { class: 'sl-gnode__label', x, y: y + r + 15, 'text-anchor': 'middle' }, slFit(n.value, colW - 14, 6.6, maxChars)));
    g.append(slSvg('text', { class: 'sl-gnode__sub', x, y: y + r + 28, 'text-anchor': 'middle' }, slFit(sub, colW - 14, 6)));
    if (n.context && n.context.watchlist) g.append(slSvg('circle', { class: 'sl-gnode__watch', cx: x + r * 0.72, cy: y - r * 0.72, r: 4 }, slSvg('title', {}, 'On the watchlist')));
    const hl = (on) => slHighlight(s, on ? n.id : null);
    g.addEventListener('mouseenter', () => hl(true));
    g.addEventListener('mouseleave', () => hl(false));
    g.addEventListener('focus', () => hl(true));
    g.addEventListener('blur', () => hl(false));
    const pick = () => { sl.node = sl.node === n.id ? null : n.id; s.querySelectorAll('.sl-gnode').forEach((o) => { const on = o.dataset.id === sl.node; o.classList.toggle('sl-gnode--on', on); o.setAttribute('aria-pressed', String(on)); }); slNodeDetail(); };
    g.addEventListener('click', pick);
    g.addEventListener('keydown', (ev) => { if (ev.key === 'Enter' || ev.key === ' ') { ev.preventDefault(); pick(); } });
    s.append(g);
  }
  box.replaceChildren(s);
}

// slHighlight brings out one node's links and dims the rest.
function slHighlight(s, id) {
  s.classList.toggle('sl-graph--focus', !!id);
  const near = new Set(id ? [id] : []);
  s.querySelectorAll('.sl-edge').forEach((p) => {
    const on = !!id && (p.dataset.from === id || p.dataset.to === id);
    p.classList.toggle('sl-edge--on', on);
    if (on) { near.add(p.dataset.from); near.add(p.dataset.to); }
  });
  s.querySelectorAll('.sl-gnode').forEach((g) => g.classList.toggle('sl-gnode--near', near.has(g.dataset.id)));
}

function slNodeDetail() {
  const box = $('sl-node');
  if (!box || !sl.data) return;
  const st = sl.data.storyline;
  const n = st.nodes.find((x) => x.id === sl.node);
  if (!n) { box.replaceChildren(); box.classList.add('hidden'); return; }
  box.classList.remove('hidden');
  const c = n.context;
  const bits = [];
  if (c) {
    if (c.name) bits.push(c.name);
    if (c.priority) bits.push(c.priority + ' priority');
    if (c.owner) bits.push((c.kind === 'identity' ? 'manager ' : 'owner ') + c.owner);
    if (c.bunit) bits.push(c.bunit);
    if (c.watchlist) bits.push('on the watchlist');
  }
  const stats = [n.findings ? slPlural(n.findings, 'finding') : null, n.risk ? 'risk ' + slNum(n.risk) : null,
    n.first ? (n.first === n.last ? 'seen ' + fmtTime(n.first) : `seen ${fmtTime(n.first)} to ${fmtTime(n.last)}`) : null].filter(Boolean);
  const links = st.edges.filter((e) => e.from === n.id || e.to === n.id).length;
  const fields = { user: ['user', 'src_user'], system: ['host', 'dest', 'src', 'dest_host', 'src_host'], ip: ['src', 'dest'], process: ['process_name', 'parent_process_name'], other: ['risk_object'] }[n.type];
  const q = fields.map((f) => `${f}=${quoteValue(n.value)}`).join(' OR ');
  const actions = [dxBtn('secondary', 'Search events', () => openSearch(q, st.earliest, st.latest), { sm: true, icon: 'search', title: 'Search every event with this value in the story’s time range' })];
  const followable = ['user', 'system', 'ip'].includes(n.type) && !st.seeds.some((x) => `${x.type}:${x.value}` === n.id);
  if (followable) actions.unshift(dxBtn('primary', 'Follow this', () => openStoryline({ type: n.type, object: n.value, since: (sl.params && sl.params.since) || '7d' }), { sm: true, icon: 'waypoints', title: 'Build the storyline about this one instead' }));
  fill(box,
    el('span', { class: 'entity__icon' }, icon(SL_TYPE_ICON[n.type])),
    el('div', { class: 'sl-node-detail__main' },
      el('div', { class: 'sl-node-detail__name' }, el('span', { class: 'mono' }, n.value), n.severity ? sevBadge(n.severity) : null, n.seed ? el('span', { class: 'badge badge--accent' }, 'Followed') : null),
      el('p', { class: 'sl-node-detail__meta' }, [SL_TYPE_LABEL[n.type], ...bits, ...stats, slPlural(links, 'link')].join(' · '))),
    el('div', { class: 'sl-node-detail__actions' }, ...actions,
      dxBtn('ghost', '', () => { sl.node = null; slDrawGraph(); }, { sm: true, icon: 'x', title: 'Close' })));
}

// ---------- activity ----------
function slActivityCard(st) {
  const kinds = Object.keys(SL_ACT).filter((k) => st.searches && st.searches[k]);
  if (!kinds.length) return null;
  if (!kinds.includes(sl.act)) sl.act = kinds[0];
  const tabs = el('div', { class: 'tabs sl-tabs', role: 'tablist', 'aria-label': 'Activity' }, ...kinds.map((k) => {
    const n = st.activity.filter((a) => a.kind === k).length;
    const b = el('button', { class: 'tab', type: 'button', role: 'tab', id: 'sl-tab-' + k, 'aria-selected': String(sl.act === k), 'aria-controls': 'sl-act-panel', tabindex: sl.act === k ? '0' : '-1' },
      SL_ACT[k].label, el('span', { class: 'count' }, String(n)));
    b.addEventListener('click', () => { sl.act = k; renderStoryline(); $('sl-tab-' + k).focus(); });
    b.addEventListener('keydown', (ev) => {
      const i = kinds.indexOf(k);
      const to = ev.key === 'ArrowRight' ? kinds[(i + 1) % kinds.length] : ev.key === 'ArrowLeft' ? kinds[(i + kinds.length - 1) % kinds.length] : null;
      if (to) { ev.preventDefault(); sl.act = to; renderStoryline(); $('sl-tab-' + to).focus(); }
    });
    return b;
  }));
  const info = SL_ACT[sl.act];
  const rows = st.activity.filter((a) => a.kind === sl.act);
  const body = rows.length
    ? el('div', { class: 'table-wrap' }, el('table', { class: 'table table--compact sl-act' },
      el('thead', {}, el('tr', {}, ...info.cols.map(([, h]) => el('th', {}, h)), el('th', { class: 'num' }, 'Count'), el('th', {}, 'Last seen'))),
      el('tbody', {}, ...rows.map((a) => el('tr', {},
        ...info.cols.map(([f, h]) => el('td', { 'data-label': h, class: f === 'action' ? '' : 'mono' }, f === 'action' && a.fields[f] ? el('span', { class: 'badge' + (a.fields[f] === 'failure' || a.fields[f] === 'blocked' ? ' badge--danger' : '') }, a.fields[f]) : a.fields[f] || '–')),
        el('td', { class: 'num', 'data-label': 'Count' }, a.count.toLocaleString()),
        el('td', { 'data-label': 'Last seen', title: a.last ? fmtTime(a.last) : '' }, a.last ? ago(a.last) : '–'))))))
    : el('p', { class: 'muted sl-act-empty' }, info.empty);
  return el('section', { class: 'card sl-activity', 'aria-label': 'Activity' },
    el('div', { class: 'card__head' }, el('div', {}, el('h3', { class: 'card__title' }, 'Activity that links them'),
      el('p', { class: 'card__sub' }, 'Sign-ins, process starts and connections between the entities in this story, busiest first.')),
    el('div', { class: 'card__actions' }, dxBtn('ghost', 'Open in Search', () => openSearch(st.searches[sl.act]), { sm: true, icon: 'search', title: 'Run this in Search' }))),
    tabs, el('div', { class: 'card__body', id: 'sl-act-panel', role: 'tabpanel', 'aria-labelledby': 'sl-tab-' + sl.act }, body));
}

// ---------- open an investigation ----------
async function slOpenCase(btn) {
  const d = sl.data;
  if (!d) return;
  const { storyline: st, anchor } = d;
  if (anchor.kind === 'case') { openCase(anchor.id); return; }
  const ids = [...new Set(st.items.filter((i) => i.kind === 'finding').map((i) => i.id))];
  if (!ids.length) return;
  const top = st.items.reduce((a, i) => (slRank(i.severity) > slRank(a) ? i.severity : a), '') || 'medium';
  const path = st.phases.filter((p) => p.tactic).map((p) => p.name).join(' → ');
  const description = `Attack storyline for ${slSeedText(st.seeds)}, ${fmtTime(st.earliest)} to ${fmtTime(st.latest)}.` + (path ? ` ATT&CK tactics reached: ${path}.` : '');
  const done = busy(btn, 'Opening…');
  try {
    const res = await api('api/cases', { title: 'Storyline: ' + slSeedText(st.seeds), severity: top === 'informational' ? 'low' : top, description, findings: ids }, 'POST');
    const id = res.case.id;
    for (const s of st.seeds) {
      try { await api('api/cases/' + encodeURIComponent(id) + '/entities', { field: s.type === 'user' ? 'user' : 'dest', value: s.value }, 'POST'); } catch (_) { /* the case is still useful */ }
    }
    const failed = Object.keys(res.failed || {}).length;
    if (typeof refreshCaseCount === 'function') refreshCaseCount();
    toast(`Investigation opened with ${slPlural(ids.length - failed, 'finding')}.` + (failed ? ` ${failed} could not be added.` : ''), { label: 'Open', run: () => openCase(id) });
    loadStoryline();
  } catch (e) {
    toastError('Couldn’t open an investigation', e);
  } finally { done(); }
}

// ---------- small helpers ----------
function slSvg(tag, attrs = {}, ...kids) {
  const n = document.createElementNS('http://www.w3.org/2000/svg', tag);
  for (const [k, v] of Object.entries(attrs)) n.setAttribute(k, v);
  for (const k of kids) n.append(k instanceof Node ? k : visibleText(String(k)));
  return n;
}

// slFit shortens text to about the width given, at an average character
// width, with an ellipsis.
function slFit(text, width, charW, cap) {
  const s = visibleText(String(text));
  const max = Math.max(4, Math.min(cap || Infinity, Math.floor(width / charW)));
  return s.length > max ? s.slice(0, max - 1) + '…' : s;
}

// slAfterLayout draws once the box has its width, and again when the
// width changes.
function slAfterLayout(box, draw) {
  if (typeof ResizeObserver !== 'function') {
    requestAnimationFrame(() => { if (box.isConnected) draw(); });
    return;
  }
  let w = -1;
  const ro = new ResizeObserver(() => {
    if (!box.isConnected) { ro.disconnect(); return; }
    if (Math.abs(box.clientWidth - w) < 2) return;
    w = box.clientWidth;
    draw();
  });
  ro.observe(box);
}
