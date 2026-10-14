// Findings queue, detection management and ATT&CK coverage.
'use strict';

const SEVERITIES = ['critical', 'high', 'medium', 'low', 'informational'];
const STATUS_LABEL = { new: 'New', in_progress: 'In progress', pending: 'Pending', resolved: 'Resolved', closed: 'Closed' };
const DISPOSITION_LABEL = {
  '': 'None', true_positive: 'True positive', benign_true_positive: 'Benign true positive',
  false_positive: 'False positive', undetermined: 'Undetermined',
};

// Other scripts add page hooks here.
const pageHooks = [];
function onPageShown(name) {
  // A page switch closes any slide-over inspector; the page that owns one
  // opens it again.
  appEl.removeAttribute('data-inspect');
  if (name === 'findings') loadFindings();
  if (name === 'detections') loadDetections();
  if (name === 'coverage') loadCoverage();
  pageHooks.forEach((h) => h(name));
  syncInspectors();
}

// fill replaces a node's children, skipping null placeholders.
const fill = (n, ...kids) => n.replaceChildren(...kids.filter((k) => k != null));
const SEVERITY_LABEL = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', informational: 'Info' };
// sevBadge and statusBadge draw the .sev and .status components keyed by the API value.
const sevBadge = (s) => el('span', { class: 'sev', 'data-sev': s }, SEVERITY_LABEL[s] || s);
const statusBadge = (s) => el('span', { class: 'status', 'data-status': s }, STATUS_LABEL[s] || s);
// techLink links an ATT&CK technique ID to attack.mitre.org, with its name
// once the coverage data has loaded.
const techLink = (id) => {
  const info = attackInfo(id);
  const attrs = {
    class: 'tech' + (info ? '' : ' tech--bare'), target: '_blank', rel: 'noopener',
    href: 'https://attack.mitre.org/techniques/' + id.replace('.', '/') + '/',
  };
  if (info) attrs.title = info.sub ? `${id}: a sub-technique of ${info.parent} ${info.name}` : `${id} ${info.name}`;
  return el('a', attrs, el('code', {}, id), info ? info.name : null);
};

// Opens the Search page on a query and time window.
function openSearch(query, earliest, latest) {
  let q = query || '*';
  const [search, rest] = splitPipes(q);
  const times = [];
  if (earliest) times.push('earliest=' + quoteValue(earliest));
  if (latest) times.push('latest=' + quoteValue(latest));
  if (times.length) q = search.trim() + ' ' + times.join(' ') + (rest ? '\n' + rest.trim() : '');
  setQuery(q);
  showPage('search');
  runSearch();
}

// select builds a <select> from [value, label] pairs.
function select(id, options, value) {
  const s = el('select', { id });
  for (const [v, label] of options) {
    const o = el('option', { value: v }, label);
    if (v === value) o.selected = true;
    s.append(o);
  }
  return s;
}

// ---------- small UI helpers (dx = this script) ----------
const SEVERITY_FULL = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', informational: 'Informational' };
// Below 1360px the inspectors are slide-overs (.app[data-inspect]).
const dxSlideOver = matchMedia('(max-width: 1359px)');

// Redrawing an inspector replaces its controls, which would drop keyboard
// focus to the page. dxRedraw draws, then puts focus back on the new copy of
// the control that had it (by data-action or id), or else on the title.
// dxKeep marks a button before its handler disables it, because a disabled
// button loses focus before the redraw can see it.
const dxFocusKey = (n) => (n && (n.dataset.action || (n.id ? '#' + n.id : ''))) || '';
function dxKeep(btn) {
  const box = btn.closest('.inspector');
  if (box && document.activeElement === btn) box.dataset.refocus = dxFocusKey(btn);
}
function dxRedraw(box, titleId, draw) {
  const a = document.activeElement;
  const lost = !a || a === document.body;
  const inBox = !lost && box.contains(a);
  const pending = box.dataset.refocus;
  delete box.dataset.refocus;
  const key = pending && (lost || a.id === titleId || inBox) ? pending : inBox ? dxFocusKey(a) : '';
  draw();
  if (!key) return;
  const again = key[0] === '#' ? document.getElementById(key.slice(1)) : box.querySelector(`[data-action="${CSS.escape(key)}"]`);
  if (again && box.contains(again) && !again.disabled) { again.focus({ preventScroll: true }); return; }
  // still loading, or busy (Run now while it runs): come back to it on the next draw
  if (!again || (again.disabled && key !== 'prev' && key !== 'next')) box.dataset.refocus = key;
  const t = document.getElementById(titleId);
  if (t && box.contains(t)) t.focus({ preventScroll: true });
}

function dxBtn(kind, label, onclick, opts = {}) {
  const attrs = { class: `btn btn--${kind}${opts.sm ? ' btn--sm' : ''}${label ? '' : ' btn--icon'}${opts.cls ? ' ' + opts.cls : ''}`, type: opts.type || 'button' };
  if (opts.title) attrs.title = opts.title;
  if (!label && opts.title) attrs['aria-label'] = opts.title;
  if (opts.id) attrs.id = opts.id;
  if (opts.action) attrs['data-action'] = opts.action;
  const b = el('button', attrs, opts.icon ? icon(opts.icon) : null, label || null);
  if (onclick) b.addEventListener('click', onclick);
  if (opts.disabled) b.disabled = true;
  return b;
}

// dxEmpty draws the empty, error (tone: 'danger') state inside a card.
function dxEmpty(o) {
  const attrs = { class: 'empty' + (o.compact ? ' empty--compact' : '') };
  if (o.tone) { attrs['data-tone'] = o.tone; attrs.role = 'alert'; }
  return el('div', attrs,
    el('span', { class: 'empty__icon' }, icon(o.icon || 'inbox')),
    el('div', { class: 'empty__title' }, o.title),
    o.text ? el('p', { class: 'empty__text' }, o.text) : null,
    o.action ? el('div', { class: 'empty__actions' },
      dxBtn('secondary', o.action.label, o.action.run, { sm: true, icon: o.action.icon })) : null,
    o.hint ? el('p', { class: 'empty__hint' }, o.hint) : null);
}
const dxRetry = (run) => ({ label: 'Try again', icon: 'refresh-cw', run });
const dxSkel = (w) => el('span', { class: 'skeleton', style: `width:${w}` });

function dxField(label, control, hint) {
  const hid = hint ? control.id + '-hint' : null;
  if (hid) control.setAttribute('aria-describedby', hid);
  return el('div', { class: 'field' }, el('label', { class: 'label', for: control.id }, label), control,
    hint ? el('div', { class: 'hint', id: hid }, hint) : null);
}

function dxAlert(tone, title, text, extra) {
  const ic = { danger: 'circle-alert', warning: 'triangle-alert', success: 'circle-check', info: 'info' }[tone];
  return el('div', { class: 'alert', 'data-tone': tone, role: tone === 'danger' ? 'alert' : 'status' }, icon(ic),
    el('div', { class: 'dx-alert__body' }, el('b', {}, title), text ? el('p', {}, text) : null, extra || null));
}

// dxMenu is a ⋯ menu (details.menu); app.js closes it on Esc and outside clicks.
function dxMenu(label, items) {
  const panel = el('div', { class: 'menu__panel', role: 'menu' });
  const d = el('details', { class: 'menu dx-menu' },
    el('summary', { class: 'btn btn--ghost btn--icon', 'aria-label': label, title: label }, icon('ellipsis')), panel);
  for (const it of items) {
    if (!it) continue;
    if (it === 'sep') { panel.append(el('div', { class: 'menu__sep' })); continue; }
    const attrs = { class: 'menu__item' + (it.danger ? ' menu__item--danger' : ''), role: 'menuitem' };
    let n;
    if (it.href) {
      attrs.href = it.href;
      if (it.download) attrs.download = '';
      n = el('a', attrs, icon(it.icon), it.label);
    } else {
      attrs.type = 'button';
      n = el('button', attrs, icon(it.icon), it.label);
    }
    n.addEventListener('click', () => { d.removeAttribute('open'); if (it.run) it.run(); });
    panel.append(n);
  }
  return d;
}

// dxTabs draws a tab bar over panels; keys: [id, label, count].
function dxTabs(prefix, tabs, current, onchange) {
  const bar = el('div', { class: 'tabs', role: 'tablist' });
  const btns = tabs.map(([id, label, count]) => {
    const b = el('button', {
      class: 'tab', type: 'button', role: 'tab', id: `${prefix}-tab-${id}`, 'aria-controls': `${prefix}-panel-${id}`,
      'aria-selected': String(id === current), tabindex: id === current ? '0' : '-1',
    }, label, count ? el('span', { class: 'count' }, String(count)) : null);
    b.addEventListener('click', () => onchange(id));
    return b;
  });
  bar.addEventListener('keydown', (ev) => {
    if (ev.key !== 'ArrowRight' && ev.key !== 'ArrowLeft') return;
    const i = btns.indexOf(document.activeElement);
    if (i < 0) return;
    const next = btns[(i + (ev.key === 'ArrowRight' ? 1 : btns.length - 1)) % btns.length];
    next.focus();
    next.click();
  });
  bar.append(...btns);
  return bar;
}
const dxPanel = (prefix, id, current, ...kids) => {
  const p = el('div', { class: 'dx-panel', role: 'tabpanel', id: `${prefix}-panel-${id}`, 'aria-labelledby': `${prefix}-tab-${id}` }, ...kids.filter((k) => k != null));
  p.hidden = id !== current;
  return p;
};

function dxInspectorBar(o) {
  return el('div', { class: 'inspector__bar' },
    el('span', { class: 'mono dx-insp-id', title: o.id }, o.id),
    o.index >= 0 ? el('span', { class: 'dx-insp-pos' }, `${o.index + 1} of ${o.count}`) : null,
    el('span', { class: 'spacer' }),
    dxBtn('ghost', '', () => o.step(-1), { sm: true, icon: 'chevron-up', title: `Previous ${o.noun} (K)`, disabled: !(o.index > 0), action: 'prev' }),
    dxBtn('ghost', '', () => o.step(1), { sm: true, icon: 'chevron-down', title: `Next ${o.noun} (J)`, disabled: !(o.count > 0 && o.index < o.count - 1), action: 'next' }),
    dxBtn('ghost', '', o.close, { sm: true, icon: 'x', title: 'Close details' }));
}

function dxSection(title, ...kids) {
  return el('section', { class: 'section' }, el('h3', { class: 'section-title' }, title), ...kids.filter((k) => k != null));
}
const dxDots = (...items) => {
  const out = [];
  items.filter(Boolean).forEach((n, i) => { if (i) out.push(el('span', { class: 'dotsep', 'aria-hidden': 'true' })); out.push(n); });
  return out;
};
const dxKv = (pairs) => el('dl', { class: 'kv dx-kv' }, ...pairs.filter(Boolean).flatMap(([k, v]) => [el('dt', {}, k), el('dd', {}, v)]));
const dxPlural = (n, word) => `${typeof n === 'number' ? n.toLocaleString() : n} ${word}${n === 1 ? '' : 's'}`;
const dxClock = (t) => new Date(t).toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
// dxAge is a short age for table columns: now, 4m, 3h, 2d.
function dxAge(t) {
  const s = (Date.now() - new Date(t).getTime()) / 1000;
  if (!isFinite(s)) return '';
  if (s < 60) return 'now';
  if (s < 3600) return Math.floor(s / 60) + 'm';
  if (s < 86400) return Math.floor(s / 3600) + 'h';
  return Math.floor(s / 86400) + 'd';
}
// dxUntil says how soon a future time is: in 4m, in 2h.
function dxUntil(t) {
  const s = (new Date(t).getTime() - Date.now()) / 1000;
  if (!isFinite(s)) return '';
  if (s < 60) return 'due now';
  if (s < 3600) return 'in ' + Math.ceil(s / 60) + 'm';
  if (s < 86400) return 'in ' + Math.round(s / 3600) + 'h';
  return 'in ' + Math.round(s / 86400) + 'd';
}
// dxNotify shows a toast; failures pass { tone: 'danger' } so they get the
// alert icon instead of the tick.
function dxNotify(msg, action, opts) {
  if (typeof toast === 'function') toast(msg, action, opts);
}
function dxOwner(name) {
  if (!name) {
    return el('span', { class: 'owner', title: 'Unassigned' },
      el('span', { class: 'avatar avatar--none avatar--sm', 'aria-hidden': 'true' }), el('span', { class: 'sr-only' }, 'Unassigned'));
  }
  let h = 0;
  for (const ch of name) h = (h * 31 + ch.charCodeAt(0)) >>> 0;
  const initial = (name.replace(/^[^a-z0-9]+/i, '').charAt(0) || '?').toUpperCase();
  return el('span', { class: 'owner', title: name },
    el('span', { class: 'avatar avatar--sm', 'data-hue': String(h % 5), 'aria-hidden': 'true' }, initial),
    el('span', { class: 'owner__name' }, name));
}

// Slide-over inspectors are off screen when closed, so they must not take focus.
function syncInspectors() {
  const shown = appEl.hasAttribute('data-inspect');
  for (const id of ['f-detail', 'd-detail']) $(id).inert = dxSlideOver.matches && !shown;
}
dxSlideOver.addEventListener('change', () => { appEl.removeAttribute('data-inspect'); syncInspectors(); });
// When app.js closes a slide-over (Esc, scrim), focus goes back to the row.
new MutationObserver(() => {
  syncInspectors();
  if (appEl.hasAttribute('data-inspect')) return;
  const a = document.activeElement;
  if (a && a.closest && a.closest('#f-detail, #d-detail')) {
    const row = document.querySelector('.page.active tbody tr[aria-selected="true"] .dx-rowlink');
    if (row) row.focus();
  }
}).observe(appEl, { attributes: true, attributeFilter: ['data-inspect'] });

// ---------- ATT&CK names (from the coverage data) ----------
let attackIndex = null;
let attackLoading = null;
function indexAttack(c) {
  const m = new Map();
  for (const t of c.tactics) {
    for (const x of t.techniques) {
      if (!m.has(x.id)) m.set(x.id, { name: x.name, tactics: [] });
      m.get(x.id).tactics.push(t.name);
    }
  }
  attackIndex = m;
}
function loadAttackIndex() {
  if (attackIndex) return Promise.resolve();
  if (!attackLoading) {
    attackLoading = api('api/coverage').then((c) => { if (!coverage) coverage = c; indexAttack(c); })
      .catch(() => { attackLoading = null; });
  }
  return attackLoading;
}
function attackInfo(id) {
  if (!attackIndex || !id) return null;
  if (attackIndex.has(id)) return attackIndex.get(id);
  const parent = id.split('.')[0];
  const p = attackIndex.get(parent);
  return p ? { name: p.name, tactics: p.tactics, sub: true, parent } : null;
}
// techRow shows the techniques and their tactics; it fills in names when
// the ATT&CK data arrives.
function techRow(ids) {
  const row = el('div', { class: 'row dx-techs' });
  const draw = () => {
    const tactics = new Set();
    ids.forEach((id) => { const i = attackInfo(id); if (i) i.tactics.forEach((t) => tactics.add(t)); });
    fill(row, ...ids.map(techLink), ...[...tactics].map((t) => el('span', { class: 'tech tech--plain' }, t)));
  };
  draw();
  if (!attackIndex) loadAttackIndex().then(draw);
  return row;
}

// ---------- findings ----------
let currentUser = '';
meReady.then((m) => { if (m) currentUser = m.username; });
let findingsList = []; // the rows on screen, in display order
const selected = new Set();
let openFinding = null;

const FND_LIMIT = 1000;
const URG_RANK = { critical: 4, high: 3, medium: 2, low: 1, informational: 0 };
const urgencyOf = (f) => f.urgency || f.severity;
const fnd = {
  urgency: new Set(), since: '7d', detection: '', sort: { key: 'urgency', dir: 'desc' },
  counts: {}, all: 0, total: 0, loaded: false, loadedAt: 0, stale: null, sig: '',
  closed: false, tab: 'overview', owners: new Set(), seq: 0, detailSeq: 0,
};
const FND_DEFAULT_STATUS = 'new,in_progress,pending';

async function refreshOpenCount() {
  try {
    const s = await api('api/findings/summary');
    const b = $('open-count');
    const crit = s.by_urgency.critical || 0;
    b.textContent = s.open;
    b.classList.toggle('hidden', !s.open);
    // A small dot marks open critical findings; the count stays neutral.
    b.toggleAttribute('data-critical', crit > 0);
    b.title = crit ? `${s.open} open, ${crit} critical` : `${s.open} open`;
    return s;
  } catch (_) { return null; }
}

// loadFindings reads the toolbar and pills, then redraws the queue.
// opts.quiet refreshes in the background (no skeleton; no redraw if
// nothing changed).
async function loadFindings(opts = {}) {
  const seq = ++fnd.seq;
  refreshOpenCount();
  syncFindingFilters();
  const owner = $('f-owner').value;
  const p = new URLSearchParams();
  if ($('f-status').value) p.set('status', $('f-status').value);
  if (owner === '__me') { if (currentUser) p.set('owner', currentUser); } else if (owner && owner !== '__none') p.set('owner', owner);
  const q = $('f-text').value.trim();
  if (q) p.set('q', q);
  if (fnd.since) p.set('since', fnd.since);
  if (fnd.detection) p.set('detection', fnd.detection);
  p.set('limit', String(FND_LIMIT));
  let skel = null;
  if (!opts.quiet) {
    if (!fnd.loaded) renderFindingsSkeleton();
    else skel = setTimeout(() => { if (seq === fnd.seq) renderFindingsSkeleton(); }, 250);
  }
  try {
    const res = await api('api/findings?' + p);
    const unassigned = owner === '__none';
    let base = res.findings;
    if (unassigned) base = base.filter((f) => !f.owner);
    const truncated = res.total > res.findings.length;
    let rows = fnd.urgency.size ? base.filter((f) => fnd.urgency.has(urgencyOf(f))) : base;
    let total = unassigned ? base.length : res.total;
    if (truncated && fnd.urgency.size) {
      // The newest page does not hold them all: ask the server for this urgency.
      p.set('urgency', [...fnd.urgency].join(','));
      const r2 = await api('api/findings?' + p);
      rows = unassigned ? r2.findings.filter((f) => !f.owner) : r2.findings;
      total = unassigned ? rows.length : r2.total;
    } else if (fnd.urgency.size) total = rows.length;
    if (seq !== fnd.seq) return;
    clearTimeout(skel);
    const counts = {};
    base.forEach((f) => { const u = urgencyOf(f); counts[u] = (counts[u] || 0) + 1; });
    base.forEach((f) => { if (f.owner) fnd.owners.add(f.owner); });
    rows = sortFindings(rows);
    const sig = JSON.stringify([counts, total, rows.map((f) => [f.id, f.updated, f.status, f.owner, urgencyOf(f), f.case_id])]);
    fnd.loadedAt = Date.now();
    fnd.stale = null;
    fnd.counts = counts;
    fnd.all = unassigned ? base.length : res.total;
    fnd.total = total;
    syncOwnerOptions();
    if (opts.quiet && fnd.loaded && sig === fnd.sig) { renderFindingsFoot(); return; }
    fnd.sig = sig;
    fnd.loaded = true;
    findingsList = rows;
    renderFindings();
    if (!openFinding && !fnd.closed && !dxSlideOver.matches && rows.length && currentPage === 'findings') showFinding(rows[0].id, { focus: false });
    else if (openFinding) syncFindingBar();
  } catch (e) {
    if (seq !== fnd.seq) return;
    clearTimeout(skel);
    if (opts.quiet && fnd.loaded) { fnd.stale = e; renderFindingsFoot(); return; }
    fnd.loaded = false;
    fnd.sig = '';
    findingsList = [];
    updateBulk();
    $('f-foot').classList.add('hidden');
    $('f-list').replaceChildren(dxEmpty({
      tone: 'danger', icon: 'circle-alert', title: 'Couldn’t load findings',
      text: e.message + '. Your filters are kept.', action: dxRetry(() => loadFindings()),
    }));
    closeFindingInspector({ keepState: true });
  }
}
function filterSeverity(sv) { fnd.urgency = new Set(sv ? [sv] : []); loadFindings(); }

function sortFindings(rows) {
  const { key, dir } = fnd.sort;
  const sign = dir === 'desc' ? -1 : 1;
  const t = (f) => new Date(f.created).getTime();
  return [...rows].sort((a, b) => {
    if (key === 'urgency') {
      const d = URG_RANK[urgencyOf(a)] - URG_RANK[urgencyOf(b)];
      if (d) return sign * d;
      return t(b) - t(a);
    }
    return sign * (t(a) - t(b));
  });
}

function syncOwnerOptions() {
  const sel = $('f-owner');
  const cur = sel.value;
  const names = [...fnd.owners].filter((n) => n !== currentUser).sort((a, b) => a.localeCompare(b));
  const keep = [...sel.options].slice(0, 3);
  sel.replaceChildren(...keep, ...names.map((n) => el('option', { value: n }, n)));
  if (cur && ![...sel.options].some((o) => o.value === cur)) sel.append(el('option', { value: cur }, cur));
  sel.value = cur;
  const names2 = [...new Set([currentUser, ...fnd.owners].filter(Boolean))];
  $('f-owner-list').replaceChildren(...names2.map((n) => el('option', { value: n })));
}

function findingFiltersActive() {
  return $('f-status').value !== FND_DEFAULT_STATUS || $('f-owner').value !== '' || $('f-text').value.trim() !== ''
    || fnd.since !== '7d' || fnd.urgency.size > 0 || fnd.detection !== '';
}
function syncFindingFilters() {
  $('f-since').querySelectorAll('button').forEach((b) => b.setAttribute('aria-pressed', String(b.dataset.since === fnd.since)));
  $('f-clear').classList.toggle('hidden', !findingFiltersActive());
  const chip = $('f-detection');
  chip.classList.toggle('hidden', !fnd.detection);
  if (fnd.detection) {
    fill(chip, el('span', { class: 'fnd-filter__label' }, 'Detection'), el('code', {}, fnd.detection),
      dxBtn('ghost', '', () => { fnd.detection = ''; loadFindings(); }, { sm: true, icon: 'x', title: 'Show every detection' }));
  }
}
function clearFindingFilters() {
  $('f-status').value = FND_DEFAULT_STATUS;
  $('f-owner').value = '';
  $('f-text').value = '';
  fnd.since = '7d';
  fnd.urgency.clear();
  fnd.detection = '';
  loadFindings();
}

function renderFindingPills() {
  const open = $('f-status').value === FND_DEFAULT_STATUS;
  const pills = [el('button', {
    class: 'pill', type: 'button', 'aria-pressed': String(!fnd.urgency.size), title: 'Show every urgency',
  }, icon('inbox'), open ? 'All open' : 'All', el('span', { class: 'num' }, String(fnd.all)))];
  pills[0].addEventListener('click', () => { fnd.urgency.clear(); loadFindings(); });
  for (const s of SEVERITIES) {
    const n = fnd.counts[s] || 0;
    const on = fnd.urgency.has(s);
    if (!n && !on) continue;
    const b = el('button', {
      class: 'pill', type: 'button', 'aria-pressed': String(on),
      title: on ? 'Show every urgency' : `Show ${SEVERITY_LABEL[s].toLowerCase()} urgency only. Shift-click to add it to the filter.`,
    }, el('span', { class: 'sev', 'data-sev': s }, SEVERITY_LABEL[s]), el('span', { class: 'num' }, String(n)));
    b.addEventListener('click', (ev) => {
      if (ev.shiftKey || ev.ctrlKey || ev.metaKey) { if (on) fnd.urgency.delete(s); else fnd.urgency.add(s); } else fnd.urgency = new Set(on && fnd.urgency.size === 1 ? [] : [s]);
      loadFindings();
    });
    pills.push(b);
  }
  $('f-summary').replaceChildren(...pills);
}

const FND_COLS = [['sev', 'Urgency', 'urgency'], ['title', 'Finding'], ['status', 'Status · detection'], ['owner', 'Owner'], ['age', 'Age', 'age']];
function findingsHead(all) {
  return el('thead', {}, el('tr', {},
    el('th', { class: 'col-check', 'data-min-role': 'analyst' }, all ? el('label', { class: 'check' }, all) : null),
    ...FND_COLS.map(([col, label, key]) => {
      const th = el('th', { 'data-col': col, class: col === 'age' ? 'num' : '' });
      if (!key) { th.textContent = label; return th; }
      const on = fnd.sort.key === key;
      if (on) th.setAttribute('aria-sort', fnd.sort.dir === 'desc' ? 'descending' : 'ascending');
      const b = el('button', { class: 'dx-sort', type: 'button', title: `Sort by ${label.toLowerCase()}` }, label,
        on ? icon(fnd.sort.dir === 'desc' ? 'arrow-down' : 'arrow-up') : null);
      b.addEventListener('click', () => {
        fnd.sort = on ? { key, dir: fnd.sort.dir === 'desc' ? 'asc' : 'desc' } : { key, dir: 'desc' };
        findingsList = sortFindings(findingsList);
        renderFindings();
        syncFindingBar();
      });
      th.append(b);
      return th;
    })));
}

function renderFindingsSkeleton() {
  const rows = Array.from({ length: 6 }, () => el('tr', {},
    el('td', { class: 'col-check', 'data-min-role': 'analyst' }),
    el('td', { 'data-col': 'sev' }, dxSkel('64px')),
    el('td', { 'data-col': 'title' }, dxSkel('80%'), el('div', { class: 'dx-skel-gap' }), dxSkel('45%')),
    el('td', { 'data-col': 'status' }, dxSkel('70px'), el('div', { class: 'dx-skel-gap' }), dxSkel('120px')),
    el('td', { 'data-col': 'owner' }, dxSkel('20px')),
    el('td', { 'data-col': 'age', class: 'num' }, dxSkel('24px'))));
  $('f-list').replaceChildren(el('table', { class: 'table table--stack findings', 'aria-busy': 'true' }, findingsHead(null), el('tbody', {}, ...rows)));
}

const ENTITY_LABEL = {
  user: 'User', src_user: 'Source user', src: 'Source', src_host: 'Source host', dest: 'Destination', dest_host: 'Destination host',
  host: 'Host', process_name: 'Process', object: 'Object', member: 'Member', risk_object: 'Risk object',
};
const FINDING_KIND_ICON = { user: 'user', host: 'server', ip: 'globe', process: 'terminal', file: 'file-text', domain: 'link', hash: 'hash', group: 'users' };
function findingEntityKind(k, v, ents) {
  if (['user', 'src_user', 'member'].includes(k)) return 'user';
  if (['src_host', 'dest_host', 'host'].includes(k)) return 'host';
  if (k === 'process_name') return 'process';
  if (k === 'src' || k === 'dest') return /^\d{1,3}(\.\d{1,3}){3}$/.test(v) || (/:/.test(v) && /^[0-9a-f:]+$/i.test(v)) ? 'ip' : 'host';
  if (k === 'risk_object') return ents.risk_object_type === 'user' ? 'user' : ents.risk_object_type === 'system' ? 'host' : '';
  return '';
}
function findingChips(f) {
  const ents = f.entities || {};
  const seen = new Set();
  const chips = [];
  if (f.case_id) chips.push(el('span', { class: 'badge', title: 'Part of case ' + f.case_id }, icon('briefcase', 'icon--xs'), 'In case'));
  for (const [k, raw] of Object.entries(ents)) {
    if (k === 'risk_object_type' || raw == null) continue;
    const v = String(raw);
    if (!v || seen.has(v)) continue;
    seen.add(v);
    const kind = findingEntityKind(k, v, ents);
    const attrs = { class: 'chip', title: `${ENTITY_LABEL[k] || k}: ${v}` };
    if (kind) attrs['data-kind'] = kind;
    chips.push(el('span', attrs, el('span', {}, v)));
    if (chips.length >= 4) break;
  }
  return chips;
}

function findingRow(f) {
  const u = urgencyOf(f);
  const cb = el('input', { type: 'checkbox', 'aria-label': 'Select: ' + f.title });
  cb.checked = selected.has(f.id);
  cb.addEventListener('click', (ev) => ev.stopPropagation());
  cb.addEventListener('change', () => { if (cb.checked) selected.add(f.id); else selected.delete(f.id); updateBulk(); });
  const sev = sevBadge(u);
  if (u !== f.severity) sev.title = `Severity ${SEVERITY_FULL[f.severity] || f.severity}, adjusted for asset and user priority`;
  const open = el('button', { class: 'dx-rowlink', type: 'button' }, f.title);
  const check = el('td', { class: 'col-check', 'data-min-role': 'analyst' }, el('label', { class: 'check' }, cb));
  // The whole cell toggles the box, so a near miss does not open the finding.
  check.addEventListener('click', (ev) => { ev.stopPropagation(); if (ev.target === check) cb.click(); });
  const tr = el('tr', { 'data-id': f.id, 'aria-selected': String(openFinding === f.id) },
    check,
    el('td', { 'data-col': 'sev' }, sev),
    el('td', { 'data-col': 'title' }, el('div', { class: 'cell-title', title: f.title }, open), el('div', { class: 'cell-sub' }, ...findingChips(f))),
    el('td', { 'data-col': 'status' }, statusBadge(f.status), el('span', { class: 'cell-det', title: 'Detection: ' + f.detection_id }, f.detection_id)),
    el('td', { 'data-col': 'owner' }, dxOwner(f.owner)),
    el('td', { 'data-col': 'age', class: 'num age', title: fmtTime(f.created) }, dxAge(f.created)));
  tr.addEventListener('click', () => showFinding(f.id));
  return tr;
}

function renderFindings() {
  for (const id of [...selected]) if (!findingsList.some((f) => f.id === id)) selected.delete(id);
  renderFindingPills();
  updateBulk();
  const box = $('f-list');
  if (!findingsList.length) {
    const filtered = findingFiltersActive();
    const span = { '24h': 'the last 24 hours', '7d': 'the last 7 days', '30d': 'the last 30 days', '': 'any time' }[fnd.since];
    box.replaceChildren(filtered
      ? dxEmpty({ icon: 'filter-x', title: 'No findings match these filters', text: `Nothing in ${span} matches. Widen the time range or clear the filters.`, action: { label: 'Clear filters', run: clearFindingFilters } })
      : dxEmpty({ icon: 'shield-check', title: 'No open findings', text: 'Nothing has fired in the last 7 days. New findings appear here as detections fire.', action: { label: 'Review detections', run: () => showPage('detections') }, hint: typeof samplePointer === 'function' ? samplePointer() : null }));
    renderFindingsFoot();
    if (openFinding && !findingsList.some((f) => f.id === openFinding) && !dxSlideOver.matches) syncFindingBar();
    if (!openFinding) closeFindingInspector({ keepState: true });
    return;
  }
  const all = el('input', { type: 'checkbox', id: 'f-all', 'aria-label': 'Select every finding shown' });
  all.addEventListener('change', () => {
    findingsList.forEach((f) => (all.checked ? selected.add(f.id) : selected.delete(f.id)));
    box.querySelectorAll('tbody input[type=checkbox]').forEach((c) => { c.checked = all.checked; });
    updateBulk();
  });
  box.replaceChildren(el('table', { class: 'table table--stack findings' }, findingsHead(all), el('tbody', {}, ...findingsList.map(findingRow))));
  updateBulk();
  renderFindingsFoot();
}

function renderFindingsFoot() {
  const foot = $('f-foot');
  if (!fnd.loaded) { foot.classList.add('hidden'); return; }
  foot.classList.remove('hidden');
  const live = fnd.stale
    ? el('span', { class: 'live', title: fnd.stale.message }, el('span', { class: 'pulse', 'data-state': 'warn' }), 'Couldn’t refresh · updated ' + ago(fnd.loadedAt))
    : el('span', { class: 'live' }, el('span', { class: 'pulse' }), 'Live · updated ' + ago(fnd.loadedAt));
  const more = fnd.total > findingsList.length
    ? el('span', {}, `Showing the newest ${findingsList.length} of ${fnd.total}. Narrow the filters to see the rest.`) : null;
  fill(foot, live, more, el('span', { class: 'spacer' }),
    findingsList.length ? el('span', { class: 'shortcuts hide-sm', 'aria-hidden': 'true' }, el('kbd', {}, 'J'), el('kbd', {}, 'K'), el('span', {}, 'move'), ...(can('analyst') ? [el('kbd', {}, 'X'), el('span', {}, 'select')] : [])) : null);
}

function updateBulk() {
  const n = selected.size;
  $('f-bulk').classList.toggle('hidden', n === 0);
  $('f-toolbar').classList.toggle('hidden', n > 0);
  $('f-bulk-count').textContent = `${n} selected`;
  const all = $('f-all');
  if (all) {
    const k = findingsList.filter((f) => selected.has(f.id)).length;
    all.checked = k > 0 && k === findingsList.length;
    all.indeterminate = k > 0 && k < findingsList.length;
  }
}

// bulkUpdate applies one update to the selected findings and offers Undo
// for the fields it changed (notes cannot be undone).
async function bulkUpdate(update, done) {
  const ids = [...selected];
  if (!ids.length) return false;
  const fields = ['status', 'owner', 'disposition'].filter((k) => k in update);
  const before = new Map(ids.map((id) => [id, findingsList.find((f) => f.id === id)]));
  const res = await api('api/findings/bulk', { ids, update });
  const failed = Object.keys(res.failed || {});
  const changed = ids.filter((id) => !failed.includes(id));
  selected.clear();
  let undo = null;
  if (fields.length && changed.length) {
    undo = { label: 'Undo', run: async () => {
      const groups = new Map();
      for (const id of changed) {
        const f = before.get(id);
        if (!f) continue;
        const prev = {};
        fields.forEach((k) => { prev[k] = f[k] || ''; });
        const key = JSON.stringify(prev);
        if (!groups.has(key)) groups.set(key, { prev, ids: [] });
        groups.get(key).ids.push(id);
      }
      try {
        for (const g of groups.values()) await api('api/findings/bulk', { ids: g.ids, update: g.prev });
        dxNotify('Change undone.');
      } catch (e) { dxNotify('Couldn’t undo: ' + e.message, null, { tone: 'danger' }); }
      await loadFindings();
      if (openFinding) showFinding(openFinding, { focus: false });
    } };
  }
  dxNotify(`${done} ${dxPlural(changed.length, 'finding')}.` + (failed.length ? ` ${failed.length} could not be updated.` : ''), undo);
  await loadFindings();
  if (openFinding) showFinding(openFinding, { focus: false });
  return true;
}
async function bulkButton(btn, update, done) {
  btn.disabled = true;
  try { await bulkUpdate(update, done); } catch (e) { dxNotify('Nothing was changed: ' + e.message, null, { tone: 'danger' }); } finally { btn.disabled = false; }
}
$('f-bulk-clear').addEventListener('click', () => {
  selected.clear();
  $('f-list').querySelectorAll('tbody input[type=checkbox]').forEach((c) => { c.checked = false; });
  updateBulk();
  $('f-text').focus();
});
$('f-bulk-mine').addEventListener('click', () => {
  if (!currentUser) return;
  bulkButton($('f-bulk-mine'), { owner: currentUser }, 'Assigned to you:');
});
$('f-bulk-resolve').addEventListener('click', () => bulkButton($('f-bulk-resolve'), { status: 'resolved' }, 'Resolved'));
$('f-bulk-edit').addEventListener('click', () => {
  for (const id of ['f-bulk-status', 'f-bulk-disposition', 'f-bulk-owner', 'f-bulk-comment']) $(id).value = '';
  $('f-bulk-error').classList.add('hidden');
  $('f-bulk-title').textContent = `Update ${dxPlural(selected.size, 'finding')}`;
  $('f-bulk-dialog').showModal();
  $('f-bulk-status').focus();
});
for (const id of ['f-bulk-cancel']) $(id).addEventListener('click', () => $('f-bulk-dialog').close());
$('f-bulk-dialog').querySelector('.dx-close').addEventListener('click', () => $('f-bulk-dialog').close());
$('f-bulk-form').addEventListener('submit', async (ev) => {
  ev.preventDefault();
  const update = {};
  if ($('f-bulk-status').value) update.status = $('f-bulk-status').value;
  if ($('f-bulk-disposition').value) update.disposition = $('f-bulk-disposition').value;
  if ($('f-bulk-owner').value.trim()) update.owner = $('f-bulk-owner').value.trim();
  if ($('f-bulk-comment').value.trim()) update.comment = $('f-bulk-comment').value.trim();
  const err = (msg) => { $('f-bulk-error-text').textContent = msg; $('f-bulk-error').classList.remove('hidden'); };
  if (!Object.keys(update).length) { err('Choose a status, disposition or owner, or write a note.'); return; }
  const btn = $('f-bulk-apply');
  btn.disabled = true;
  try {
    await bulkUpdate(update, 'Updated');
    $('f-bulk-dialog').close();
  } catch (e) { err(e.message); } finally { btn.disabled = false; }
});

// toolbar
$('f-status').addEventListener('change', () => loadFindings());
$('f-owner').addEventListener('change', () => loadFindings());
$('f-since').addEventListener('click', (ev) => {
  const b = ev.target.closest('button[data-since]');
  if (!b) return;
  fnd.since = b.dataset.since;
  loadFindings();
});
let fndTextTimer = null;
$('f-text').addEventListener('input', () => { clearTimeout(fndTextTimer); fndTextTimer = setTimeout(() => loadFindings(), 300); });
$('f-text').addEventListener('keydown', (e) => { if (e.key === 'Enter') { clearTimeout(fndTextTimer); loadFindings(); } });
$('f-clear').addEventListener('click', clearFindingFilters);
$('f-export').addEventListener('click', exportFindings);

// exportFindings saves the findings on screen as CSV. Cells that a
// spreadsheet would run as a formula get a leading quote.
function exportFindings() {
  const cols = ['id', 'created', 'urgency', 'severity', 'status', 'owner', 'disposition', 'title', 'detection_id', 'case_id', 'entities'];
  const cell = (v) => {
    let s = v == null ? '' : String(v);
    if (/^[=+\-@\t\r]/.test(s)) s = "'" + s;
    return /[",\n\r]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
  };
  const lines = [cols.join(',')];
  for (const f of findingsList) {
    const row = { ...f, urgency: urgencyOf(f), entities: Object.entries(f.entities || {}).map(([k, v]) => `${k}=${v}`).join('; ') };
    lines.push(cols.map((c) => cell(row[c])).join(','));
  }
  const url = URL.createObjectURL(new Blob([lines.join('\r\n') + '\r\n'], { type: 'text/csv' }));
  const a = el('a', { href: url, download: `signalith-findings-${new Date().toISOString().slice(0, 10)}.csv` });
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
  dxNotify(`Exported ${dxPlural(findingsList.length, 'finding')}.`);
}

// ---- finding inspector ----
function markRows(listId, openId) {
  $(listId).querySelectorAll('tbody tr[data-id]').forEach((tr) => tr.setAttribute('aria-selected', String(tr.dataset.id === openId)));
}
function stepFinding(d) {
  if (!findingsList.length) return;
  let i = findingsList.findIndex((f) => f.id === openFinding);
  i = i < 0 ? 0 : Math.min(findingsList.length - 1, Math.max(0, i + d));
  const f = findingsList[i];
  showFinding(f.id, { focus: false });
  const tr = $('f-list').querySelector(`tr[data-id="${CSS.escape(f.id)}"]`);
  if (tr) tr.scrollIntoView({ block: 'nearest' });
}
function syncFindingBar() {
  const bar = $('f-detail').querySelector('.inspector__bar');
  if (!bar || !openFinding) return;
  bar.replaceWith(dxInspectorBar({
    id: openFinding, index: findingsList.findIndex((f) => f.id === openFinding), count: findingsList.length,
    noun: 'finding', step: stepFinding, close: () => closeFindingInspector(),
  }));
}
function closeFindingInspector(opts = {}) {
  const was = openFinding;
  openFinding = null;
  fnd.detailSeq++;
  if (!opts.keepState) fnd.closed = true;
  appEl.removeAttribute('data-inspect');
  syncInspectInert();   // now, so the row can take focus back below
  $('f-detail').hidden = true;
  $('f-split').classList.add('split--solo');
  markRows('f-list', null);
  if (was && !opts.keepState) {
    const b = $('f-list').querySelector(`tr[data-id="${CSS.escape(was)}"] .dx-rowlink`);
    if (b) b.focus();
  }
  syncInspectors();
}

async function showFinding(id, opts = {}) {
  openFinding = id;
  fnd.closed = false;
  markRows('f-list', id);
  const box = $('f-detail');
  box.hidden = false;
  $('f-split').classList.remove('split--solo');
  if (dxSlideOver.matches) appEl.setAttribute('data-inspect', '');
  syncInspectors();
  const seq = ++fnd.detailSeq;
  const known = findingsList.find((f) => f.id === id);
  const bar = () => dxInspectorBar({
    id, index: findingsList.findIndex((f) => f.id === id), count: findingsList.length,
    noun: 'finding', step: stepFinding, close: () => closeFindingInspector(),
  });
  dxRedraw(box, 'fd-title', () => fill(box, bar(),
    el('div', { class: 'inspector__head', 'aria-busy': 'true' },
      known ? el('h2', { class: 'inspector__title', id: 'fd-title', tabindex: '-1' }, known.title) : dxSkel('85%'),
      known ? el('div', { class: 'row dx-tags' }, sevBadge(urgencyOf(known)), statusBadge(known.status)) : dxSkel('40%')),
    el('div', { class: 'inspector__body', 'aria-busy': 'true' }, dxSkel('92%'), dxSkel('80%'), dxSkel('60%'), dxSkel('100%'), dxSkel('70%'))));
  let data;
  try {
    data = await api('api/findings/' + encodeURIComponent(id));
  } catch (e) {
    if (seq !== fnd.detailSeq) return;
    fill(box, bar(), dxEmpty({ tone: 'danger', icon: 'circle-alert', compact: true, title: 'Couldn’t load this finding', text: e.message, action: dxRetry(() => showFinding(id)) }));
    return;
  }
  if (seq !== fnd.detailSeq) return;
  dxRedraw(box, 'fd-title', () => renderFindingDetail(box, data, opts));
  if (dxSlideOver.matches && opts.focus !== false) { const t = $('fd-title'); if (t) t.focus(); }
}

function historyText(h) {
  const label = (field, v) => (field === 'status' ? STATUS_LABEL[v] : field === 'severity' || field === 'urgency' ? SEVERITY_FULL[v] : field === 'disposition' ? DISPOSITION_LABEL[v] : v) || v;
  const b = (t) => el('b', {}, t);
  switch (h.field) {
    case 'created': return h.to === 'manual' ? [b(h.author), ' raised it by hand'] : ['Raised by detection ', b(h.to || 'unknown')];
    case 'status': return [b(h.author), ' set status to ', b(label('status', h.to))];
    case 'owner': return h.to ? [b(h.author), h.to === h.author ? ' took it' : [' assigned it to ', b(h.to)]].flat() : [b(h.author), ' unassigned it'];
    case 'severity': return [b(h.author), ' set severity to ', b(label('severity', h.to))];
    case 'disposition': return [b(h.author), ' marked it ', b(label('disposition', h.to))];
    default: return [b(h.author), ` changed ${h.field} from ${h.from || 'empty'} to ${h.to || 'empty'}`];
  }
}
const FINDING_HISTORY_ICON = { created: 'crosshair', status: 'circle-dot', owner: 'user', severity: 'gauge', disposition: 'flag' };
function findingActivity(f) {
  const time = (t) => el('span', { class: 'timeline__time', title: fmtTime(t) }, dxAge(t));
  const dot = (name) => el('span', { class: 'timeline__dot' }, icon(name));
  return [
    ...(f.comments || []).map((c) => ({ t: c.time, node: el('li', {}, dot('message-square-text'),
      el('div', { class: 'timeline__text' }, el('b', {}, c.author), ' added a note', el('p', { class: 'dx-note' }, c.text)), time(c.time)) })),
    ...(f.history || []).filter((h) => h.field !== 'urgency').map((h) => ({ t: h.time, node: el('li', {}, dot(FINDING_HISTORY_ICON[h.field] || 'history'),
      el('div', { class: 'timeline__text' }, ...historyText(h)), time(h.time)) })),
  ].sort((a, b) => new Date(b.t) - new Date(a.t)).map((x) => x.node);
}

function contextBits(c) {
  if (!c) return [];
  const bits = [];
  if (c.name) bits.push(c.name);
  if (c.priority) bits.push(c.priority + ' priority');
  if (c.bunit) bits.push(c.bunit);
  if ((c.category || []).length) bits.push(c.category.join(', '));
  if (c.owner) bits.push((c.kind === 'identity' ? 'manager ' : 'owner ') + c.owner);
  return bits;
}
function findingEntity(k, v, f) {
  const val = String(v);
  const kind = findingEntityKind(k, val, f.entities || {});
  const ctx = f.context && f.context[k];
  const q = (k === 'risk_object' ? 'datamodel=Risk ' : '') + k + '=' + quoteValue(val);
  const b = el('button', { class: 'entity dx-entity', type: 'button', title: `Search the last 7 days for ${k}=${val}` },
    el('span', { class: 'entity__icon' }, icon(FINDING_KIND_ICON[kind] || 'tag')),
    el('span', { class: 'entity__main' }, el('span', { class: 'entity__name' }, val),
      el('span', { class: 'entity__desc' }, [ENTITY_LABEL[k] || k, ...contextBits(ctx)].join(' · '))),
    ctx && ctx.watchlist ? el('span', { class: 'badge badge--warning' }, 'Watchlist') : null,
    icon('search', 'dx-entity__go'));
  b.addEventListener('click', () => openSearch(q, '-7d'));
  return b;
}

function renderFindingDetail(box, data, opts = {}) {
  const f = data.finding;
  const d = data.detection;
  const u = urgencyOf(f);
  const idx = findingsList.findIndex((x) => x.id === f.id);
  const status = select('fd-status', Object.entries(STATUS_LABEL), f.status);
  const severity = select('fd-severity', SEVERITIES.map((s) => [s, SEVERITY_FULL[s]]), f.severity);
  const disposition = select('fd-disposition', Object.entries(DISPOSITION_LABEL), f.disposition || '');
  for (const s of [status, severity, disposition]) s.className = 'select select--block';
  const owner = el('input', { class: 'input', id: 'fd-owner', type: 'text', value: f.owner || '', placeholder: 'Unassigned', list: 'f-owner-list', autocomplete: 'off' });
  const comment = el('textarea', { class: 'textarea', id: 'fd-comment', rows: 3, placeholder: 'Add a note: what you checked, what you found', 'aria-label': 'Note' });
  if (opts.keepNote) comment.value = opts.keepNote;
  const errText = el('p', {});
  const err = el('div', { class: 'alert hidden', 'data-tone': 'danger', role: 'alert' }, icon('circle-alert'), el('div', {}, el('b', {}, 'Couldn’t save.'), errText));
  const fail = (e) => { errText.textContent = e.message; err.classList.remove('hidden'); err.scrollIntoView({ block: 'nearest' }); };

  const save = dxBtn('primary', 'Save', null, { title: 'Save (Ctrl+Enter)', action: 'save' });
  save.addEventListener('click', async () => {
    dxKeep(save);
    err.classList.add('hidden');
    const prev = { status: f.status, severity: f.severity, disposition: f.disposition || '', owner: f.owner || '' };
    const next = { status: status.value, severity: severity.value, disposition: disposition.value, owner: owner.value.trim() };
    const changed = Object.keys(next).some((k) => next[k] !== prev[k]);
    if (!changed && !comment.value.trim()) { dxNotify('Nothing to save.'); return; }
    save.disabled = true;
    try {
      await api('api/findings/' + encodeURIComponent(f.id), { ...next, comment: comment.value }, 'PATCH');
      dxNotify('Finding saved.', changed ? { label: 'Undo', run: () => undoFinding(f.id, prev) } : null);
      await loadFindings({ quiet: true });
      if (openFinding === f.id) showFinding(f.id, { focus: false });
    } catch (e) { fail(e); save.disabled = false; }
  });
  comment.addEventListener('keydown', (ev) => { if (ev.key === 'Enter' && (ev.ctrlKey || ev.metaKey)) { ev.preventDefault(); save.click(); } });

  const mine = currentUser && f.owner !== currentUser ? dxBtn('secondary', 'Assign to me', null, { icon: 'user-plus', title: 'Assign to you and start work on it', action: 'assign' }) : null;
  if (mine) {
    mine.addEventListener('click', async () => {
      dxKeep(mine);
      const prev = { owner: f.owner || '', status: f.status };
      mine.disabled = true;
      try {
        await api('api/findings/' + encodeURIComponent(f.id), { owner: currentUser, status: f.status === 'new' ? 'in_progress' : f.status }, 'PATCH');
        dxNotify(f.status === 'new' ? 'Assigned to you and moved to In progress.' : 'Assigned to you.', { label: 'Undo', run: () => undoFinding(f.id, prev) });
        const note = comment.value;
        await loadFindings({ quiet: true });
        if (openFinding === f.id) showFinding(f.id, { focus: false, keepNote: note });
      } catch (e) { fail(e); mine.disabled = false; }
    });
  }
  const caseBtn = f.case_id
    ? dxBtn('ghost', 'Open case', () => openCase(f.case_id), { title: 'This finding is part of case ' + f.case_id })
    : dxBtn('ghost', 'Add to case', () => addFindingsToCase([f.id], f.title), { title: 'Group this finding into an investigation' });
  const more = dxMenu('More actions', [
    { icon: 'search', label: 'Open events in Search', run: () => openSearch(f.query, f.earliest, f.latest) },
    d ? { icon: 'crosshair', label: 'Open the detection', run: () => focusDetection(f.detection_id) } : null,
    d ? { icon: 'list-filter', label: 'Findings from this detection', run: () => { fnd.detection = f.detection_id; fnd.urgency.clear(); loadFindings(); } } : null,
    can('analyst') ? { icon: 'zap', label: 'Respond…', run: () => { const b = box.querySelector('[data-action="respond"]'); if (b) b.click(); } } : null,
    can('analyst') ? { icon: 'sparkles', label: 'Investigate with AI…', run: () => openInvestigate(f) } : null,
    d && can('admin') ? 'sep' : null,
    d && can('admin') ? { icon: 'bell-off', label: 'Don’t alert on this again…', run: () => suppressFinding(f, d) } : null,
  ]);

  const sev = sevBadge(u);
  let sevNote = null;
  if (u !== f.severity) {
    const up = URG_RANK[u] > URG_RANK[f.severity];
    sev.title = `Urgency: severity ${SEVERITY_FULL[f.severity]}, ${up ? 'raised' : 'lowered'} for asset and user priority`;
    sevNote = `Shown as ${SEVERITY_FULL[u]}: ${up ? 'raised' : 'lowered'} for asset and user priority.`;
  }
  const detBadge = d
    ? el('button', { class: 'badge badge--outline badge--mono dx-linkbadge', type: 'button', title: 'Open detection ' + f.detection_id }, f.detection_id)
    : el('span', { class: 'badge badge--outline badge--mono', title: f.detection_id === 'manual' ? 'Raised by hand' : 'Detection' }, f.detection_id);
  if (d) detBadge.addEventListener('click', () => focusDetection(f.detection_id));
  const caseLink = f.case_id ? el('a', { href: '#cases', title: 'Open case ' + f.case_id }, 'In a case') : null;
  if (caseLink) caseLink.addEventListener('click', (ev) => { ev.preventDefault(); openCase(f.case_id); });

  const ents = Object.entries(f.entities || {}).filter(([k, v]) => k !== 'risk_object_type' && v != null && String(v) !== '');
  const result = Object.entries(f.result || {}).filter(([k]) => k !== '_raw');
  const activity = findingActivity(f);
  const prefix = 'fd';
  const tabs = [['overview', 'Overview'], ['evidence', 'Evidence', result.length], ['activity', 'Activity', activity.length]];
  if (!tabs.some(([t]) => t === fnd.tab)) fnd.tab = 'overview';
  const setTab = (t) => {
    fnd.tab = t;
    box.querySelectorAll('[role=tab]').forEach((b) => { const on = b.id === `${prefix}-tab-${t}`; b.setAttribute('aria-selected', String(on)); b.tabIndex = on ? 0 : -1; });
    box.querySelectorAll('[role=tabpanel]').forEach((p) => { p.hidden = p.id !== `${prefix}-panel-${t}`; });
  };
  const win = f.earliest || f.latest ? `${f.earliest ? fmtTime(f.earliest) : 'start'} to ${f.latest ? fmtTime(f.latest) : 'now'}` : null;

  fill(box,
    dxInspectorBar({ id: f.id, index: idx, count: findingsList.length, noun: 'finding', step: stepFinding, close: () => closeFindingInspector() }),
    el('div', { class: 'inspector__head' },
      el('h2', { class: 'inspector__title', id: 'fd-title', tabindex: '-1' }, f.title),
      el('div', { class: 'row dx-tags' }, sev, statusBadge(f.status), detBadge),
      el('div', { class: 'inspector__meta' }, ...dxDots(
        el('span', { title: fmtTime(f.created) }, 'Detected ' + ago(f.created)),
        el('span', { class: 'tabular' }, dxClock(f.created)), raisedLater(f), caseLink))),
    dxTabs(prefix, tabs, fnd.tab, setTab),
    el('div', { class: 'inspector__body' },
      dxPanel(prefix, 'overview', fnd.tab,
        typeof pbFindingBanner === 'function' ? pbFindingBanner(f.id) : null,
        f.description ? el('p', { class: 'dx-lede' }, f.description) : null,
        f.credit ? el('p', { class: 'dx-credit' }, f.credit) : null,
        d && d.guidance ? el('div', { class: 'callout' }, icon('lightbulb'), el('div', {}, el('b', {}, 'How to triage. '), d.guidance)) : null,
        (f.mitre || []).length ? techRow(f.mitre) : null,
        can('analyst') && typeof findingInvestigate === 'function' ? findingInvestigate(f) : null,
        err,
        // Viewers see the triage state; analysts and admins change it.
        can('analyst') ? dxSection('Triage',
          el('div', { class: 'form-grid' },
            dxField('Status', status), dxField('Owner', owner), dxField('Severity', severity, sevNote), dxField('Disposition', disposition)),
          comment)
          : dxSection('Triage', dxKv([['Status', STATUS_LABEL[f.status] || f.status], ['Owner', f.owner || 'Unassigned'],
            ['Severity', SEVERITY_FULL[f.severity] || f.severity], ['Disposition', DISPOSITION_LABEL[f.disposition || ''] || f.disposition]])),
        ents.length ? el('section', { class: 'section' },
          el('h3', { class: 'section-title' }, 'Entities', el('span', { class: 'count' }, String(ents.length))),
          ...ents.map(([k, v]) => findingEntity(k, v, f))) : null,
        can('analyst') ? findingRespond(f) : null),
      dxPanel(prefix, 'evidence', fnd.tab,
        el('section', { class: 'section' },
          el('div', { class: 'dx-sec-head' }, el('h3', { class: 'section-title' }, 'Query'),
            dxBtn('ghost', 'Open in Search', () => openSearch(f.query, f.earliest, f.latest), { sm: true, icon: 'search', title: 'Show the events behind this finding' })),
          el('pre', { class: 'dx-code' }, f.query || '*'),
          win ? el('p', { class: 'dx-hint' }, win) : null),
        dxSection('What the detection found',
          result.length ? dxKv(result.map(([k, v]) => [k, el('span', { class: 'mono' }, k === '_time' ? fmtTime(v) : fmtValue(v))]))
            : el('p', { class: 'muted' }, 'No fields were recorded.')),
        f.result && f.result._raw ? dxSection('Raw event', el('pre', { class: 'dx-code dx-raw' }, f.result._raw)) : null),
      dxPanel(prefix, 'activity', fnd.tab,
        activity.length ? el('ol', { class: 'timeline' }, ...activity) : el('p', { class: 'muted' }, 'No activity yet. Notes and changes appear here.'))),
    el('div', { class: 'inspector__foot' }, ...(can('analyst') ? [save, mine, caseBtn] : [f.case_id ? caseBtn : null]), el('span', { class: 'spacer' }), more));
}

// findingRespond is the Response section: Respond runs an action (block
// an IP, disable an account) on one of the finding's entities; past runs
// list below it (respond.js).
function findingRespond(f) {
  const ents = f.entities || {};
  const entities = Object.entries(ents).filter(([k, v]) => k !== 'risk_object_type' && v != null && String(v) !== '')
    .flatMap(([k, v]) => [].concat(v).map((x) => ({ field: k, value: String(x),
      kind: k === 'risk_object' ? (ents.risk_object_type === 'user' ? 'user' : 'host') : undefined })));
  const go = () => openRespond({ findingId: f.id, title: f.title, entities, onDone: () => {
    if (openFinding !== f.id) return;
    const note = $('fd-comment');
    showFinding(f.id, { focus: false, keepNote: note ? note.value : '' });
  } });
  return el('section', { class: 'section' },
    el('div', { class: 'dx-sec-head' }, el('h3', { class: 'section-title' }, 'Response'),
      dxBtn('secondary', 'Respond', go, { sm: true, icon: 'zap', action: 'respond', title: 'Run a response action, such as blocking an IP or disabling an account' })),
    rpRunsSection({ findingId: f.id }));
}

async function undoFinding(id, prev) {
  try {
    await api('api/findings/' + encodeURIComponent(id), prev, 'PATCH');
    dxNotify('Change undone.');
  } catch (e) { dxNotify('Couldn’t undo: ' + e.message, null, { tone: 'danger' }); }
  await loadFindings({ quiet: true });
  if (openFinding === id) showFinding(id, { focus: false });
}

// The queue refreshes itself while it is on screen.
setInterval(() => {
  if (currentPage !== 'findings' || document.hidden || !fnd.loaded) return;
  const busy = document.querySelector('dialog[open]') || (document.activeElement && document.activeElement.closest && document.activeElement.closest('#f-list'));
  if (Date.now() - fnd.loadedAt >= 29000 && !busy) loadFindings({ quiet: true });
  else renderFindingsFoot();
}, 15000);

// ---------- detections ----------
let detections = [];
let schedulerOn = true;
// runsOn names the server that runs the detections when this one does
// not; '' when none does; null when this server runs them, or when it is
// on its own (no other servers share its OpenSearch) with its scheduler
// off. schedulerHere is this server's own scheduler setting.
let runsOn = null;
let schedulerHere = true;
const det = { show: '', open: null, closed: false, list: [], counts24: null, loaded: false, seq: 0, msg: null, test: null, running: null,
  // source: '' shows Signalith's and your own detections plus pack rules
  // that are on; 'pack:<name>' browses one content pack; 'all' is every one.
  source: '', packs: [], limit: 0 };
// The list draws this many rows at first; Show more adds as many again.
const DET_PAGE = 150;
// d-show is a group of pills; other pages set it like a select ($('d-show').value = '').
Object.defineProperty($('d-show'), 'value', { configurable: true, get: () => det.show, set: (v) => { det.show = v || ''; } });
const DET_SHOW = [['', 'All'], ['enabled', 'On'], ['disabled', 'Off'], ['custom', 'Custom or edited'], ['errors', 'Failing']];
const detShows = (d, show) => (show === 'enabled' ? d.enabled : show === 'disabled' ? !d.enabled
  : show === 'custom' ? d.source === 'custom' || d.source === 'override' : show === 'errors' ? !!(d.state && d.state.last_error) : true);
const plainTitle = (t) => t.replace(/\$([^$]+)\$/g, '$1');
// detTitle shows $field$ tokens as quiet code.
function detTitle(t) {
  const out = [];
  t.split(/(\$[A-Za-z_][A-Za-z0-9_.()]*\$)/).forEach((part, i) => { if (part) out.push(i % 2 ? el('span', { class: 'dx-tok' }, part) : part); });
  return out;
}
const SOURCE_LABEL = { builtin: 'Built-in', custom: 'Custom', override: 'Edited', pack: 'Content pack' };
const sourceLabel = (d) => (d.source === 'pack' && d.origin ? packShort(d.origin.pack) : SOURCE_LABEL[d.source] || d.source);
const packShort = (name) => ({ sigmahq: 'SigmaHQ', splunk: 'Splunk' }[name] || name);
// PACK_INFO is how each pack's card reads: who wrote the rules, under
// which licence, and which of its rules the one-click button turns on
// (Splunk's TTP rules raise findings; its anomalies only add risk).
const PACK_INFO = {
  sigmahq: { icon: 'sigma', by: 'By the SigmaHQ authors named on each rule, under the ', license: 'Detection Rule License 1.1', home: 'SigmaHQ on GitHub',
    desc: 'Windows rules for Sysmon and the Security, PowerShell, System, Application, Defender and Code Integrity logs, and Linux rules for Sysmon for Linux and the audit log, each tested before it ships. Off until you turn them on.',
    strong: (d) => d.severity === 'high' || d.severity === 'critical', strongName: 'high and critical rule' },
  splunk: { icon: 'layers', by: 'By Splunk’s Threat Research Team and the authors named on each rule, under the ', license: 'Apache License 2.0', home: 'security_content on GitHub',
    desc: 'Splunk’s Windows and Linux process, file, registry and PowerShell detections, each tested before it ships. TTP rules raise findings; anomalies add risk. Off until you turn them on.',
    strong: (d) => (d.tags || []).includes('ttp'), strongName: 'TTP rule' },
};
const packInfo = (p) => PACK_INFO[p.name] || { icon: 'layers', by: 'Under the ', license: p.license, home: 'Source', desc: p.description, strong: () => false, strongName: 'rule' };
const inSource = (d, src) => (src === 'all' ? true : src.startsWith('pack:') ? !!d.origin && d.origin.pack === src.slice(5) : !d.origin || d.enabled);

async function loadDetections() {
  const seq = ++det.seq;
  if (!det.loaded) renderDetectionsSkeleton();
  try {
    const [res, f24, packs, contentInfo] = await Promise.all([
      api('api/detections'),
      api('api/findings?since=24h&limit=1000').catch(() => null),
      api('api/detections/packs').catch(() => null),
      api('api/detections/content').catch(() => null),
    ]);
    if (seq !== det.seq) return;
    detections = res.detections;
    det.packs = packs ? packs.packs : [];
    det.content = contentInfo;
    schedulerOn = res.scheduler;
    runsOn = typeof res.runs_on === 'string' ? res.runs_on : null;
    schedulerHere = res.scheduler_here !== false;
    det.stateError = res.state_error || '';
    det.counts24 = null;
    if (f24) {
      det.counts24 = {};
      f24.findings.forEach((f) => { det.counts24[f.detection_id] = (det.counts24[f.detection_id] || 0) + 1; });
      det.counts24Partial = f24.total > f24.findings.length;
    }
    det.loaded = true;
    schedulerNote();
    renderDetections();
  } catch (e) {
    if (seq !== det.seq) return;
    det.loaded = false;
    $('d-show').replaceChildren();
    $('d-foot').classList.add('hidden');
    $('d-list').replaceChildren(dxEmpty({ tone: 'danger', icon: 'circle-alert', title: 'Couldn’t load detections', text: e.message + '.', action: dxRetry(loadDetections) }));
    closeDetectionInspector({ keepState: true });
  }
}

function renderDetectionsSkeleton() {
  const rows = Array.from({ length: 6 }, () => el('tr', {},
    el('td', { 'data-col': 'sev' }, dxSkel('64px')),
    el('td', { 'data-col': 'title' }, dxSkel('75%'), el('div', { class: 'dx-skel-gap' }), dxSkel('40%')),
    el('td', { 'data-col': 'sched' }, dxSkel('60px')), el('td', { 'data-col': 'last' }, dxSkel('50px')),
    el('td', { 'data-col': 'n24', class: 'num' }, dxSkel('20px')), el('td', { 'data-col': 'on' }, dxSkel('28px'))));
  $('d-list').replaceChildren(el('table', { class: 'table table--stack dx-detections', 'aria-busy': 'true' }, detectionsHead(), el('tbody', {}, ...rows)));
}
function detectionsHead() {
  return el('thead', {}, el('tr', {},
    el('th', { 'data-col': 'sev' }, 'Severity'), el('th', { 'data-col': 'title' }, 'Detection'),
    el('th', { 'data-col': 'sched' }, 'Schedule'), el('th', { 'data-col': 'last' }, 'Last run'),
    el('th', { 'data-col': 'n24', class: 'num', title: 'Findings raised in the last 24 hours' }, '24h'),
    el('th', { 'data-col': 'on' }, el('span', { class: 'sr-only' }, 'On'))));
}

// schedulerNote says when detections do not run on this server: its
// scheduler is off, another server runs them, or none does right now.
function schedulerNote() {
  const note = $('d-scheduler-note');
  const offHere = schedulerHere ? '' : 'This server’s scheduler is off. ';
  let tone = 'info', ic = 'info', title = 'The scheduler is off on this server.', text = ['Detections only run when you choose Run now.'];
  if (runsOn) {
    title = `Detections run on ${runsOn}.`;
    text = [offHere + 'Their runs, errors and missed runs show here just as they do there. Run now runs one on this server.'];
  } else if (runsOn === '') {
    tone = 'danger'; ic = 'circle-alert';
    title = 'No server runs detections right now.';
    text = can('admin') ? [offHere + 'The ', el('a', { href: '#servers', 'data-page': 'servers' }, 'Servers page'), ' says why.']
      : [offHere + 'An admin needs to look.'];
  }
  note.dataset.tone = tone;
  note.querySelector('use').setAttribute('href', '#i-' + ic);
  $('d-scheduler-title').textContent = title;
  $('d-scheduler-text').replaceChildren(...text);
  note.classList.toggle('hidden', schedulerOn);
}

function lastRunCell(st, d) {
  if (st.running) return [el('div', { class: 'dx-line' }, 'Running…')];
  // The run state is shared, so the next run shows on every server while
  // any server runs the detections.
  const next = d && d.enabled && (schedulerOn !== false || runsOn) && st.next_run ? 'next ' + dxUntil(st.next_run) : '';
  const skip = dxSkipped(st) ? el('span', { class: 'badge badge--warning dx-skipchip', title: skippedText(st) }, 'Skipped') : null;
  if (!st.last_run) return [el('div', { class: 'dx-line muted' }, 'Not yet'), next || skip ? el('span', { class: 'dx-meta' }, skip, next) : null];
  const second = st.last_error ? el('span', { class: 'dx-meta dx-fail', title: st.last_error }, errorKindLabel(st))
    : el('span', { class: 'dx-meta', title: next }, skip, st.last_findings ? dxPlural(st.last_findings, 'new finding') : st.last_results ? dxPlural(st.last_results, 'result') : 'No results');
  return [el('div', { class: 'dx-line', title: fmtTime(st.last_run) }, ago(st.last_run)), second];
}

// errorKindLabel names what went wrong in the last scheduled run, short.
function errorKindLabel(st) {
  return st.timed_out || st.error_kind === 'timeout' ? 'Timed out' : st.error_kind === 'transient' ? 'Retrying' : st.error_kind === 'query' ? 'Query error' : 'Failed';
}

// errorKindText says, in a sentence, what a failed run means and what
// happens next.
function errorKindText(st) {
  switch (st.error_kind) {
    case 'query': return 'The query has an error; fix it and the next run uses it.';
    case 'transient': return 'OpenSearch did not answer; this run is retried.';
    case 'timeout': return 'The run took longer than its time limit. It is tried up to three times, then the next run goes on.';
  }
  return '';
}

// dxSkipped is true when missed runs of a detection were skipped in the
// last 24 hours, because they were older than detections.catch_up (Make
// up missed runs on the Settings page).
function dxSkipped(st) {
  const sk = st.skipped;
  return !!(sk && sk.count > 0 && Date.now() - new Date(sk.at).getTime() < 864e5);
}

// dxSpan is "from 02:10 to 09:40" in the viewer's time zone, with dates
// when the times are not both today.
function dxSpan(from, to) {
  const f = new Date(from), t = new Date(to);
  const hm = { hour: '2-digit', minute: '2-digit' };
  const today = new Date().toDateString();
  const one = f.toDateString() === today && t.toDateString() === today;
  const fmt = (x) => (one ? x.toLocaleTimeString(undefined, hm) : x.toLocaleString(undefined, { month: 'short', day: 'numeric', ...hm }));
  return `from ${fmt(f)} to ${fmt(t)}`;
}

// skippedText is the sentence about skipped runs; '' when there were none.
function skippedText(st) {
  if (!st.skipped || !st.skipped.count) return '';
  const sk = st.skipped;
  return `Signalith was not running detections ${dxSpan(sk.from, sk.to)}; ${sk.count.toLocaleString()} ${sk.count === 1 ? 'run' : 'runs'} of this detection ${sk.count === 1 ? 'was' : 'were'} skipped, because ${sk.count === 1 ? 'it was' : 'they were'} older than the Make up missed runs limit on the Settings page. Search that time by hand if it matters.`;
}

// lagText says how far the detection fell behind: runs that started
// more than one schedule interval after their time. '' when none.
function lagText(st) {
  return st.late_runs ? `${dxPlural(st.late_runs, 'late run')}, last ${ago(st.last_late)}. Missed runs are made up in order, so findings arrived late but nothing was left out.` : '';
}

// raisedLater says when a finding was actually raised, for one raised
// well after its scheduled time (a missed run made up later). Its
// Detected time is the scheduled time, so findings sort by when the
// activity was searched for.
function raisedLater(f) {
  if (!f.raised_at || !f.created) return null;
  const s = (new Date(f.raised_at).getTime() - new Date(f.created).getTime()) / 1000;
  if (!isFinite(s) || s < 300) return null;
  const late = s < 3600 ? Math.round(s / 60) + ' min' : s < 86400 ? Math.round(s / 3600) + ' h' : Math.round(s / 86400) + ' d';
  return el('span', { title: 'Raised ' + fmtTime(f.raised_at) }, `raised ${late} after its scheduled time (the run was made up later)`);
}

// manualText is the last "Run now", on any server.
function manualText(m) {
  const who = [m.by ? 'by ' + m.by : '', m.node ? 'on ' + m.node : ''].filter(Boolean).join(' ');
  const what = m.error ? 'it failed: ' + m.error : `${dxPlural(m.results, 'result')}, ${dxPlural(m.findings, 'new finding')}${m.throttled ? `, ${m.throttled} held back as repeats` : ''}${m.risk ? `, ${dxPlural(m.risk, 'risk event')}` : ''}`;
  return el('span', { title: fmtTime(m.at) }, `Run now${who ? ' ' + who : ''}, ${ago(m.at)}: ${what}`);
}

function detectionRow(d) {
  const st = d.state || {};
  const sw = el('input', { type: 'checkbox', role: 'switch', 'aria-label': 'On: ' + plainTitle(d.title) });
  sw.checked = d.enabled;
  sw.addEventListener('click', (ev) => ev.stopPropagation());
  sw.addEventListener('change', () => setDetectionEnabled(d, sw.checked, sw));
  const n24 = det.counts24 ? (det.counts24[d.id] || 0) : null;
  const sub = [el('span', { class: 'dx-id' }, d.id), ...(d.mitre || []).slice(0, 3).map((t) => el('span', { class: 'chip' }, t))];
  // While a pack is browsed every row is from it, so its badge would only
  // repeat the card above.
  if (d.source !== 'builtin' && !(d.source === 'pack' && det.source.startsWith('pack:'))) sub.splice(1, 0, el('span', { class: 'badge' }, sourceLabel(d)));
  if (d.risk && d.risk.only) sub.push(el('span', { class: 'badge', title: 'Records risk without raising findings' }, 'Risk only'));
  const tr = el('tr', { 'data-id': d.id, 'aria-selected': String(det.open === d.id), class: d.enabled ? '' : 'dx-off' },
    el('td', { 'data-col': 'sev' }, sevBadge(d.severity)),
    el('td', { 'data-col': 'title' },
      el('div', { class: 'cell-title', title: plainTitle(d.title) }, el('button', { class: 'dx-rowlink', type: 'button' }, ...detTitle(d.title))),
      el('div', { class: 'cell-sub' }, ...sub)),
    el('td', { 'data-col': 'sched' }, el('div', { class: 'dx-line' }, 'Every ' + d.schedule), el('span', { class: 'dx-meta' }, 'looks back ' + d.lookback)),
    el('td', { 'data-col': 'last' }, ...lastRunCell(st, d)),
    el('td', { 'data-col': 'n24', class: 'num', title: n24 == null ? 'Couldn’t count findings' : `${dxPlural(n24, 'finding')} in the last 24 hours` }, n24 == null ? '–' : String(n24)),
    // Only admins turn detections on and off; others see On or Off.
    can('admin') ? el('td', { 'data-col': 'on' }, el('label', { class: 'switch', title: d.enabled ? 'On: runs on schedule' : 'Off' }, sw))
      : el('td', { 'data-col': 'on' }, el('span', { class: 'muted' }, d.enabled ? 'On' : 'Off')));
  if (can('admin')) tr.lastChild.addEventListener('click', (ev) => { ev.stopPropagation(); if (ev.target === tr.lastChild) sw.click(); });
  tr.addEventListener('click', () => openDetection(d.id));
  return tr;
}

// renderPacks draws a card per content pack: what it is, how many of its
// rules are on, and (for admins) one click to turn on its strongest rules.
// While a pack is browsed, the card turns into the bar for that view.
function renderPacks(list) {
  const box = $('d-packs');
  const admin = can('admin');
  const browsing = det.source.startsWith('pack:') ? det.packs.find((p) => 'pack:' + p.name === det.source) : null;
  const cards = det.packs.map((p) => {
    if (browsing && browsing !== p) return null;
    const rules = detections.filter((d) => d.origin && d.origin.pack === p.name);
    const on = rules.filter((d) => d.enabled).length;
    const info = packInfo(p);
    const strong = rules.filter((d) => !d.enabled && info.strong(d));
    const credit = el('p', { class: 'dx-pack__credit' }, info.by,
      el('a', { href: p.license_url, target: '_blank', rel: 'noopener' }, info.license), ' · ',
      el('a', { href: p.source, target: '_blank', rel: 'noopener' }, info.home));
    const actions = [];
    if (browsing) {
      actions.push(dxBtn('ghost', 'Back to your detections', () => { det.source = ''; det.limit = DET_PAGE; renderDetections(); }, { sm: true, icon: 'arrow-left' }));
      if (admin && list.length) {
        const off = list.filter((d) => !d.enabled), onNow = list.filter((d) => d.enabled);
        if (off.length) actions.push(dxBtn('secondary', `Turn on ${off.length === list.length ? 'all ' : ''}${dxPlural(off.length, 'shown rule')}`, (ev) => bulkEnable(off, true, ev.currentTarget), { sm: true, icon: 'power' }));
        if (onNow.length) actions.push(dxBtn('ghost', `Turn off ${dxPlural(onNow.length, 'shown rule')}`, (ev) => bulkEnable(onNow, false, ev.currentTarget), { sm: true }));
      }
    } else {
      actions.push(dxBtn('secondary', 'Browse rules', () => { det.source = 'pack:' + p.name; det.show = ''; det.limit = DET_PAGE; renderDetections(); }, { sm: true, icon: 'list-filter' }));
      if (admin && strong.length) actions.push(dxBtn('ghost', `Turn on ${dxPlural(strong.length, info.strongName)}`, (ev) => bulkEnable(strong, true, ev.currentTarget), { sm: true, icon: 'power' }));
    }
    return el('div', { class: 'card dx-pack' },
      el('div', { class: 'dx-pack__mark', 'aria-hidden': 'true' }, icon(info.icon)),
      el('div', { class: 'dx-pack__body' },
        el('div', { class: 'dx-pack__head' }, el('b', {}, p.title),
          el('span', { class: 'dx-meta' }, `${p.rules.toLocaleString()} rules · ${on ? on.toLocaleString() + ' on' : 'all off'}`)),
        el('p', { class: 'dx-pack__desc' }, browsing ? 'Filter by name, ATT&CK ID or tag, then turn on what fits your systems.'
          : info.desc),
        credit),
      el('div', { class: 'dx-pack__actions' }, ...actions));
  });
  fill(box, ...cards, browsing ? null : contentBar());
  box.classList.toggle('hidden', !det.packs.length);
}

// contentVersion turns a content version (20261013140000) into a date.
function contentDate(v) {
  if (!v || v.length < 8) return '';
  const d = new Date(Date.UTC(+v.slice(0, 4), +v.slice(4, 6) - 1, +v.slice(6, 8)));
  return d.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric', timeZone: 'UTC' });
}

// contentBar says how new the pack rules are and, for admins, checks for
// signed updates or takes one uploaded (for servers without internet).
function contentBar() {
  const c = det.content;
  if (!c) return null;
  const st = c.status;
  const admin = can('admin');
  const parts = [st.updated ? `Rules updated ${contentDate(st.version)}` : `Rules from ${contentDate(st.version)}, built into Signalith`];
  if (c.mode === 'daily') parts.push('checked daily');
  if (st.last_check) parts.push(`last checked ${dxClock(st.last_check)}${st.last_result === 'up to date' ? ', up to date' : ''}`);
  const lines = [el('span', {}, parts.join(' · '))];
  if (st.skipped) lines.push(el('span', { class: 'dx-content__warn', title: (st.skipped_reasons || []).join('\n') }, `${dxPlural(st.skipped, 'new rule')} need a newer Signalith.`));
  if (st.last_error) lines.push(el('span', { class: 'dx-content__err' }, sentence(st.last_error)));
  const actions = [];
  if (admin && st.ready) {
    actions.push(dxBtn('ghost', 'Check for updates', (ev) => contentAction(ev.currentTarget, () => api('api/detections/content/check', {})), { sm: true, icon: 'refresh-cw' }));
    const pick = el('input', { type: 'file', multiple: '', accept: '.gz,.sig', class: 'hidden', 'aria-label': 'Content update and its signature' });
    pick.addEventListener('change', () => uploadContent(pick, upBtn));
    const upBtn = dxBtn('ghost', 'Upload update…', () => pick.click(), { sm: true, icon: 'upload' });
    upBtn.title = 'For a server without internet access: choose signalith-content.tar.gz and signalith-content.tar.gz.sig together';
    actions.push(pick, upBtn);
    if (st.updated) actions.push(dxBtn('ghost', 'Use built-in rules', (ev) => contentAction(ev.currentTarget, () => api('api/detections/content', undefined, 'DELETE')), { sm: true }));
  } else if (admin) {
    lines.push(el('span', { class: 'dx-meta' }, 'This build of Signalith cannot take content updates.'));
  }
  return el('div', { class: 'dx-content' }, el('span', { class: 'dx-content__icon', 'aria-hidden': 'true' }, icon('cloud-download')),
    el('div', { class: 'dx-content__text' }, ...lines), actions.length ? el('div', { class: 'dx-content__actions' }, ...actions) : null);
}

async function contentAction(btn, call) {
  btn.disabled = true;
  try {
    det.content = await call();
    const st = det.content.status;
    toast(st.last_result === 'installed' ? `Rules updated to ${contentDate(st.version)}.` : st.updated ? 'Rules are up to date.' : 'Using the rules built into Signalith.');
    loadDetections();
  } catch (e) {
    toastError('Content update failed', e);
    if (det.content) det.content = await api('api/detections/content').catch(() => det.content);
    renderDetections();
  } finally {
    btn.disabled = false;
  }
}

async function uploadContent(pick, btn) {
  const files = [...pick.files];
  pick.value = '';
  const sig = files.find((f) => f.name.endsWith('.sig'));
  const bundle = files.find((f) => !f.name.endsWith('.sig'));
  if (!sig || !bundle) {
    toast('Choose both files: the update (.tar.gz) and its signature (.sig).', null, { tone: 'danger', title: 'Two files needed' });
    return;
  }
  const form = new FormData();
  form.append('bundle', bundle);
  form.append('signature', sig);
  await contentAction(btn, async () => {
    const resp = await apiRaw('api/detections/content/upload', { method: 'POST', body: form });
    const data = await resp.json().catch(() => ({}));
    if (!resp.ok) throw new Error(data.error || resp.statusText);
    return data;
  });
}

// bulkEnable turns many detections on or off at once, after a check when
// it is more than a handful.
async function bulkEnable(ds, on, btn) {
  if (!ds.length) return;
  if (on && ds.length > 20) {
    const ok = await dxConfirm({
      title: `Turn on ${dxPlural(ds.length, 'rule')}?`,
      text: `They start running on their schedules and raise findings for what they match. You can turn any of them off again here.`,
      confirm: 'Turn on',
    });
    if (!ok) return;
  }
  if (btn) { dxKeep(btn); btn.disabled = true; }
  const ids = ds.map((d) => d.id);
  try {
    await api('api/detections/enable', { ids, enabled: on });
    await loadDetections();
    dxNotify(`${dxPlural(ids.length, 'rule')} turned ${on ? 'on' : 'off'}.`, {
      label: 'Undo',
      run: async () => {
        try { await api('api/detections/enable', { ids, enabled: !on }); await loadDetections(); dxNotify('Change undone.'); }
        catch (e) { dxNotify('Couldn’t undo: ' + e.message, null, { tone: 'danger' }); }
      },
    });
  } catch (e) {
    dxNotify(`Couldn’t turn ${on ? 'on' : 'off'} the rules: ${e.message}`, null, { tone: 'danger' });
    if (btn) btn.disabled = false;
  }
}

function renderDetections() {
  const term = $('d-filter').value.trim().toLowerCase();
  if (!det.limit) det.limit = DET_PAGE;
  const scoped = detections.filter((d) => inSource(d, det.source));
  const list = scoped.filter((d) => detShows(d, det.show)
    && (!term || [d.id, d.title, d.description, ...(d.mitre || []), ...(d.tags || [])].join(' ').toLowerCase().includes(term)));
  det.list = list;
  renderPacks(list);
  const pills = DET_SHOW.map(([v, label]) => {
    const n = scoped.filter((d) => detShows(d, v)).length;
    if (v && !n && det.show !== v) return null;
    const b = el('button', { class: 'pill', type: 'button', 'aria-pressed': String(det.show === v) }, v ? null : icon('crosshair'), label, el('span', { class: 'num' }, n.toLocaleString()));
    b.addEventListener('click', () => { det.show = det.show === v ? '' : v; renderDetections(); });
    return b;
  });
  fill($('d-show'), ...pills);
  const enabled = detections.filter((d) => d.enabled).length;
  const box = $('d-list');
  if (!list.length) {
    box.replaceChildren(detections.length
      ? dxEmpty({ icon: 'filter-x', title: 'No detections match', text: 'Try another name or ATT&CK ID, or show every detection.', action: { label: 'Clear filters', run: () => { $('d-filter').value = ''; det.show = ''; renderDetections(); } } })
      : dxEmpty({ icon: 'crosshair', title: 'No detections yet', text: can('admin') ? 'Write one with New detection, import a Sigma rule, or use Save as detection on the Search page.' : 'Detections an admin adds appear here.' }));
  } else {
    // Long lists (a whole content pack) draw in pages, keeping the open
    // detection's row in view.
    const openAt = det.open ? list.findIndex((d) => d.id === det.open) : -1;
    if (openAt >= det.limit) det.limit = Math.ceil((openAt + 1) / DET_PAGE) * DET_PAGE;
    const shown = list.slice(0, det.limit);
    const more = list.length > shown.length
      ? el('div', { class: 'dx-more' }, dxBtn('ghost', `Show ${Math.min(DET_PAGE, list.length - shown.length)} more of ${list.length.toLocaleString()}`, () => { det.limit += DET_PAGE; renderDetections(); }, { sm: true }))
      : null;
    box.replaceChildren(el('table', { class: 'table table--stack dx-detections' }, detectionsHead(), el('tbody', {}, ...shown.map(detectionRow))), ...(more ? [more] : []));
  }
  const foot = $('d-foot');
  foot.classList.toggle('hidden', !detections.length);
  fill(foot,
    el('span', {}, `${enabled.toLocaleString()} of ${dxPlural(detections.length, 'detection')} on`),
    det.counts24 ? el('span', {}, det.counts24Partial ? '24h counts the newest 1000 findings' : '24h is findings raised in the last 24 hours') : null,
    el('span', { class: 'spacer' }),
    list.length ? el('span', { class: 'shortcuts hide-sm', 'aria-hidden': 'true' }, el('kbd', {}, 'J'), el('kbd', {}, 'K'), el('span', {}, 'move')) : null);
  // Keep the open detection; on wide screens open the first one.
  if (det.open && list.some((d) => d.id === det.open)) {
    openDetection(det.open, { focus: false, slide: det.slide });
    det.slide = false;
  } else if (!det.closed && !dxSlideOver.matches && list.length && currentPage === 'detections') openDetection(list[0].id, { focus: false });
  else closeDetectionInspector({ keepState: true });
}
$('d-filter').addEventListener('input', () => { det.limit = DET_PAGE; renderDetections(); });

async function setDetectionEnabled(d, on, input) {
  // the list and inspector are redrawn, so note where focus was to put it back
  const inList = document.activeElement === input && !!input.closest('#d-list');
  dxKeep(input);
  input.disabled = true;
  try {
    const { state, ...body } = d;
    await api('api/detections/' + encodeURIComponent(d.id), { ...body, enabled: on }, 'PUT');
    await loadDetections();
    if (inList) {
      const again = $('d-list').querySelector(`tr[data-id="${CSS.escape(d.id)}"] input[role="switch"]`);
      if (again) again.focus({ preventScroll: true });
    }
    // Undo puts back exactly what was there by saving it as it was (for a
    // built-in or pack rule that only records on or off again).
    const undo = async () => {
      try {
        await api('api/detections/' + encodeURIComponent(d.id), body, 'PUT');
        await loadDetections();
        dxNotify('Change undone.');
      } catch (e) { dxNotify('Couldn’t undo: ' + e.message, null, { tone: 'danger' }); }
    };
    dxNotify(`${plainTitle(d.title)} is ${on ? 'on' : 'off'}.`, { label: 'Undo', run: undo });
  } catch (e) {
    input.checked = !on;
    dxNotify(`Couldn’t turn ${on ? 'on' : 'off'} ${plainTitle(d.title)}: ${e.message}`, null, { tone: 'danger' });
  } finally { input.disabled = false; }
}

// ---- detection inspector ----
function stepDetection(dir) {
  if (!det.list.length) return;
  let i = det.list.findIndex((d) => d.id === det.open);
  i = i < 0 ? 0 : Math.min(det.list.length - 1, Math.max(0, i + dir));
  openDetection(det.list[i].id, { focus: false });
  const tr = $('d-list').querySelector(`tr[data-id="${CSS.escape(det.list[i].id)}"]`);
  if (tr) tr.scrollIntoView({ block: 'nearest' });
}
function openDetection(id, opts = {}) {
  if (det.open !== id) { det.msg = null; det.test = null; }
  det.open = id;
  det.closed = false;
  markRows('d-list', id);
  $('d-detail').hidden = false;
  $('d-split').classList.remove('split--solo');
  if (dxSlideOver.matches && opts.slide !== false) appEl.setAttribute('data-inspect', '');
  syncInspectors();
  renderDetectionInspector();
  if (dxSlideOver.matches && opts.focus !== false) { const t = $('dd-title'); if (t) t.focus(); }
}
function closeDetectionInspector(opts = {}) {
  const was = det.open;
  if (!opts.keepState) { det.closed = true; det.open = null; }
  appEl.removeAttribute('data-inspect');
  syncInspectInert();   // now, so the row can take focus back below
  $('d-detail').hidden = true;
  $('d-split').classList.add('split--solo');
  markRows('d-list', opts.keepState ? det.open : null);
  if (was && !opts.keepState) {
    const b = $('d-list').querySelector(`tr[data-id="${CSS.escape(was)}"] .dx-rowlink`);
    if (b) b.focus();
  }
  syncInspectors();
}
// focusDetection opens the Detections page on one detection.
function focusDetection(id) {
  det.open = id;
  det.closed = false;
  det.slide = true;
  det.msg = null;
  det.test = null;
  det.show = '';
  $('d-filter').value = '';
  showPage('detections');
}
function viewDetectionFindings(id) {
  fnd.detection = id;
  fnd.urgency.clear();
  showPage('findings');
}
const detBody = (d) => { const { state, ...body } = d; return body; };

function testResult(res, lookback) {
  const r = res.result;
  const n = (r.rows || []).length;
  return el('div', { class: 'callout dx-test' }, icon('scan-search'),
    el('div', {},
      el('b', {}, n ? `${dxPlural(n, 'finding')} would be raised.` : 'No results, so no findings would be raised.'),
      ` Searched the last ${lookback} in ${r.took_ms} ms, before throttling.`,
      n ? el('ul', { class: 'dx-test__list' }, ...res.titles.map((t) => el('li', {}, t))) : null,
      n > res.titles.length ? el('p', { class: 'dx-hint' }, `And ${n - res.titles.length} more.`) : null));
}

function renderDetectionInspector() {
  const d = detections.find((x) => x.id === det.open);
  const box = $('d-detail');
  if (!d) { closeDetectionInspector({ keepState: true }); return; }
  const st = d.state || {};
  const idx = det.list.findIndex((x) => x.id === d.id);
  const sw = el('input', { type: 'checkbox', role: 'switch', id: 'dd-enabled' });
  sw.checked = d.enabled;
  sw.addEventListener('change', () => setDetectionEnabled(d, sw.checked, sw));
  const risk = d.risk;
  const thr = d.throttle || {};
  const n24 = det.counts24 ? (det.counts24[d.id] || 0) : null;

  const edit = dxBtn('secondary', 'Edit', () => editDetection(d), { icon: 'pencil', action: 'edit' });
  const run = dxBtn('ghost', 'Run now', null, { icon: 'play', title: 'Run once now and raise findings', disabled: det.running === d.id, action: 'run' });
  run.addEventListener('click', async () => {
    dxKeep(run);
    det.running = d.id;
    det.msg = { id: d.id, tone: 'info', title: 'Running…', text: `Searching the last ${d.lookback}.` };
    renderDetectionInspector();
    try {
      const res = await api('api/detections/' + encodeURIComponent(d.id) + '/run', {});
      const n = res.findings.length;
      det.msg = {
        id: d.id, tone: 'success', title: n ? `${dxPlural(n, 'new finding')} raised.` : 'Run finished. No new findings.',
        text: `${dxPlural(res.results, 'result')}, ${res.throttled} held back as repeats${res.duplicates ? `, ${res.duplicates} already raised` : ''}${res.suppressed ? `, ${res.suppressed} matched an exception` : ''}${res.risk_events ? `, ${dxPlural(res.risk_events, 'risk event')}` : ''}. The schedule is not changed.`,
        action: n ? { label: 'View findings', run: () => viewDetectionFindings(d.id) } : null,
      };
    } catch (e) {
      det.msg = { id: d.id, tone: 'danger', title: 'The run failed.', text: e.message };
    }
    det.running = null;
    await loadDetections();
  });
  const test = dxBtn('ghost', 'Test', null, { icon: 'scan-search', title: 'Search the lookback window without raising findings', action: 'test' });
  test.addEventListener('click', async () => {
    dxKeep(test);
    test.disabled = true;
    det.test = { id: d.id, busy: true };
    renderDetectionInspector();
    let t;
    try {
      t = { id: d.id, res: await api('api/detections/test', detBody(d)) };
    } catch (e) { t = { id: d.id, error: e.message }; }
    if (det.open === d.id) { det.test = t; renderDetectionInspector(); }
  });
  const del = d.source === 'override' ? { icon: 'rotate-ccw', label: 'Revert to built-in', danger: true, run: () => deleteDetection(d) }
    : d.source === 'custom' ? { icon: 'trash-2', label: 'Delete detection', danger: true, run: () => deleteDetection(d) } : null;
  const admin = can('admin');
  const more = dxMenu('More actions', [
    { icon: 'search', label: 'Open in Search', run: () => openSearch(d.query, '-' + (d.lookback || '24h')) },
    { icon: 'list-filter', label: 'View its findings', run: () => viewDetectionFindings(d.id) },
    { icon: 'download', label: 'Download YAML', href: 'api/detections/' + encodeURIComponent(d.id) + '/yaml', download: true },
    del && admin ? 'sep' : null, admin ? del : null,
  ]);

  let msg = null;
  if (det.msg && det.msg.id === d.id) {
    const m = det.msg;
    msg = dxAlert(m.tone, m.title, m.text, m.action ? dxBtn('ghost', m.action.label, m.action.run, { sm: true, cls: 'dx-alert__action', icon: 'arrow-right' }) : null);
  }
  let testOut = null;
  if (det.test && det.test.id === d.id) {
    testOut = det.test.busy ? el('div', { class: 'callout dx-test' }, icon('scan-search'), el('div', {}, `Searching the last ${d.lookback}…`))
      : det.test.error ? dxAlert('danger', 'The test failed.', det.test.error) : testResult(det.test.res, d.lookback);
  }
  const next = d.enabled && (schedulerOn || runsOn) && st.next_run ? dxUntil(st.next_run) : null;

  dxRedraw(box, 'dd-title', () => fill(box,
    dxInspectorBar({ id: d.id, index: idx, count: det.list.length, noun: 'detection', step: stepDetection, close: () => closeDetectionInspector() }),
    el('div', { class: 'inspector__head' },
      el('h2', { class: 'inspector__title', id: 'dd-title', tabindex: '-1' }, ...detTitle(d.title)),
      el('div', { class: 'row dx-tags' }, sevBadge(d.severity),
        admin ? el('label', { class: 'switch', for: 'dd-enabled' }, sw, d.enabled ? 'On' : 'Off') : el('span', { class: 'badge' }, d.enabled ? 'On' : 'Off'),
        el('span', { class: 'badge' }, sourceLabel(d))),
      el('div', { class: 'inspector__meta' }, ...dxDots(
        el('span', {}, 'Every ' + d.schedule), el('span', {}, 'looks back ' + d.lookback),
        next ? el('span', {}, 'next run ' + next) : null))),
    el('div', { class: 'inspector__body dx-detbody' },
      msg,
      det.stateError ? dxAlert('warning', 'The run state could not be read just now.', 'What is shown may be out of date. It is read again when the page reloads.') : null,
      st.last_error ? dxAlert(st.error_kind === 'transient' ? 'warning' : 'danger', st.timed_out || st.error_kind === 'timeout' ? 'The last run timed out.' : st.error_kind === 'transient' ? 'The last run could not finish.' : 'The last run failed.',
        [errorKindText(st), st.last_error].filter(Boolean).join(' ')) : null,
      d.description ? el('p', { class: 'dx-lede' }, d.description) : null,
      d.guidance ? el('div', { class: 'callout' }, icon('lightbulb'), el('div', {}, el('b', {}, 'How to triage. '), d.guidance)) : null,
      (d.mitre || []).length ? techRow(d.mitre) : null,
      testOut,
      el('section', { class: 'section' },
        el('div', { class: 'dx-sec-head' }, el('h3', { class: 'section-title' }, 'Query'),
          dxBtn('ghost', 'Open in Search', () => openSearch(d.query, '-' + (d.lookback || '24h')), { sm: true, icon: 'search' })),
        el('pre', { class: 'dx-code' }, d.query)),
      dxSection('Last run', dxKv([
        ['When', st.last_run ? el('span', { title: fmtTime(st.last_run) }, ago(st.last_run) + (st.last_duration_ms ? ` · took ${st.last_duration_ms} ms` : '') + (st.node ? ` · on ${st.node}` : '')) : 'Not run on schedule yet'],
        st.last_slot ? ['Searched up to', el('span', {}, fmtTime(st.last_slot))] : null,
        st.last_run ? ['Results', [
          dxPlural(st.last_results, 'result'), dxPlural(st.last_findings, 'new finding'),
          st.last_duplicates ? `${st.last_duplicates} already raised` : '',
          st.last_throttled ? `${st.last_throttled} held back as repeats` : '',
          st.last_risk ? dxPlural(st.last_risk, 'risk event') : '',
          st.last_suppressed ? `${st.last_suppressed} matched an exception` : '',
        ].filter(Boolean).join(', ') + (st.capped ? '. Stopped at the most findings one run may raise.' : '')] : null,
        st.last_error ? ['Problem', errorKindLabel(st)] : null,
        lagText(st) || dxSkipped(st) ? ['Behind schedule', [lagText(st), dxSkipped(st) ? skippedText(st) : ''].filter(Boolean).join(' ')] : null,
        st.manual ? ['Last run now', manualText(st.manual)] : null,
        n24 != null ? ['Last 24 hours', n24 ? el('button', { class: 'link-btn', type: 'button' }, dxPlural(n24, 'finding')) : 'No findings'] : null,
        schedulerOn && d.enabled ? null : ['Schedule', schedulerOn || runsOn != null && !d.enabled ? 'Off, so it does not run'
          : runsOn ? `Runs on ${runsOn}` : runsOn === '' ? 'No server runs detections right now' : 'Scheduler off; runs only with Run now'],
      ])),
      d.origin ? dxSection('Source', dxKv([
        ['From', d.origin.pack_title],
        d.origin.author ? ['Author', d.origin.author] : null,
        ['Licence', el('a', { href: d.origin.license_url, target: '_blank', rel: 'noopener' }, d.origin.license === 'DRL-1.1' ? 'Detection Rule License 1.1' : d.origin.license)],
        ['Rule', el('a', { href: d.origin.url, target: '_blank', rel: 'noopener' }, 'View the original rule')],
        d.origin.status ? ['Maturity', d.origin.status === 'stable' ? 'Stable' : d.origin.status === 'test' ? 'Tested by its authors' : d.origin.status] : null,
        (d.origin.references || []).length ? ['References', el('div', { class: 'dx-refs' }, ...d.origin.references.slice(0, 5).map((u) => /^https?:\/\//.test(u) ? el('a', { href: u, target: '_blank', rel: 'noopener noreferrer' }, u.replace(/^https?:\/\//, '')) : el('span', {}, u)))] : null,
      ])) : null,
      exceptionsSection(d, admin),
      dxSection('Settings', dxKv([
        ['Repeats', (thr.fields || []).length ? `One finding per ${thr.fields.join(', ')}${thr.window ? ' for ' + thr.window : ''}` : thr.window ? `Held back for ${thr.window}` : 'Every result raises a finding'],
        ['Risk', risk ? `+${risk.score} to ${(risk.objects || []).map((o) => o.field).join(', ') || 'nothing'}${risk.only ? ', no findings' : ''}` : 'None'],
        (d.tags || []).length ? ['Tags', d.tags.join(', ')] : null,
      ]))),
    el('div', { class: 'inspector__foot' }, ...(admin ? [edit, run, test] : []), el('span', { class: 'spacer' }), more)));
  const link = box.querySelector('.dx-kv .link-btn');
  if (link) link.addEventListener('click', () => viewDetectionFindings(d.id));
}

async function deleteDetection(d) {
  const revert = d.source === 'override';
  const ok = await dxConfirm({
    title: revert ? 'Revert to the built-in version?' : 'Delete this detection?',
    text: revert ? `Your changes to “${plainTitle(d.title)}” are discarded and the built-in version comes back.`
      : `“${plainTitle(d.title)}” stops running. Findings it already raised stay.`,
    confirm: revert ? 'Revert' : 'Delete',
  });
  if (!ok) return;
  try {
    const res = await api('api/detections/' + encodeURIComponent(d.id), undefined, 'DELETE');
    if (res.deleted) { det.open = null; det.closed = false; }
    det.msg = null;
    dxNotify(revert ? 'Reverted to the built-in version.' : 'Detection deleted.');
    loadDetections();
  } catch (e) { dxNotify('Couldn’t ' + (revert ? 'revert' : 'delete') + ': ' + e.message, null, { tone: 'danger' }); }
}

function dxConfirm(o) {
  const dlg = $('d-confirm');
  return new Promise((resolve) => {
    let result = false;
    const cancel = dxBtn('ghost', 'Cancel', () => dlg.close());
    const ok = el('button', { class: 'btn btn--danger', type: 'button' }, o.confirm);
    ok.addEventListener('click', () => { result = true; dlg.close(); });
    dlg.onclose = () => resolve(result);
    fill(dlg,
      el('div', { class: 'modal__head' }, el('div', {}, el('h2', { class: 'modal__title', id: 'd-confirm-title' }, o.title), el('p', { class: 'modal__desc' }, o.text))),
      el('div', { class: 'modal__foot' }, cancel, ok));
    dlg.showModal();
    cancel.focus();
  });
}

// ---- tuning: exceptions ----
// tuneDialog is the dialog for exceptions. It sits on the body, not in a
// page, because "Don't alert on this again" opens from the Findings page.
function tuneDialog() {
  let dlg = $('d-tune');
  if (!dlg) {
    dlg = el('dialog', { class: 'modal', id: 'd-tune', 'aria-labelledby': 'd-tune-title' });
    document.body.append(dlg);
  }
  return dlg;
}
const SUPPRESS_FOR = [['24h', 'For 24 hours'], ['7d', 'For 7 days'], ['30d', 'For 30 days'], ['', 'Until removed']];
// Result fields that are counts, times or the raw event make poor exceptions.
const SUPPRESS_SKIP = new Set(['_time', '_raw', 'count', 'risk_object', 'risk_object_type', 'earliest', 'latest', 'first_seen', 'last_seen']);

// suppressFields lists the fields of a finding an exception can match on:
// its entities first, then other single values of its result.
function suppressFields(f) {
  const out = [];
  const seen = new Set();
  const add = (k, v, entity) => {
    if (seen.has(k) || SUPPRESS_SKIP.has(k) || k.startsWith('_')) return;
    if (Array.isArray(v)) { if (v.length !== 1) return; v = v[0]; }
    if (v == null || typeof v === 'object' || String(v).trim() === '' || String(v).length > 1024) return;
    seen.add(k);
    out.push({ field: k, value: String(v), entity });
  };
  for (const [k, v] of Object.entries(f.entities || {})) add(k, f.result && f.result[k] != null ? f.result[k] : v, true);
  for (const [k, v] of Object.entries(f.result || {})) if (typeof v !== 'number') add(k, v, false);
  return out;
}

// suppressFinding is "Don't alert on this again": an exception on the
// finding's detection for the values picked, closing the finding too.
function suppressFinding(f, d) {
  const dlg = tuneDialog();
  const fields = suppressFields(f);
  const boxes = fields.map((x, i) => {
    const cb = el('input', { type: 'checkbox', id: 'sf-field-' + i });
    cb.checked = x.entity && !fields.slice(0, i).some((y) => y.entity);
    return cb;
  });
  const more = el('details', { class: 'dx-sf-more' }, el('summary', {}, 'More fields from the result'));
  const row = (x, i) => el('label', { class: 'check dx-sf-field' }, boxes[i], el('span', { class: 'mono' }, x.field), el('span', { class: 'mono dx-sf-value', title: x.value }, x.value));
  const entityRows = fields.map((x, i) => (x.entity ? row(x, i) : null)).filter(Boolean);
  const otherRows = fields.map((x, i) => (x.entity ? null : row(x, i))).filter(Boolean);
  more.append(...otherRows);
  const dur = select('sf-for', SUPPRESS_FOR, '7d');
  dur.className = 'select select--block';
  const note = el('textarea', { class: 'textarea', id: 'sf-comment', rows: 2, placeholder: 'Why: a scanner, a known admin script, a test host…' });
  const close = el('input', { type: 'checkbox', id: 'sf-close' });
  close.checked = f.status !== 'closed';
  const disp = select('sf-disposition', Object.entries(DISPOSITION_LABEL).filter(([k]) => k), f.disposition || 'false_positive');
  disp.className = 'select select--block';
  const errBox = el('div', {});
  const cancel = dxBtn('ghost', 'Cancel', () => dlg.close());
  const ok = dxBtn('primary', 'Stop alerting', null, { icon: 'bell-off' });
  const preview = el('p', { class: 'dx-hint', 'aria-live': 'polite' });
  const picked = () => fields.filter((_, i) => boxes[i].checked);
  const update = () => {
    const p = picked();
    ok.disabled = !p.length;
    preview.textContent = p.length
      ? `This detection raises no findings where ${p.map((x) => `${x.field} is ${x.value}`).join(' and ')}${dur.value ? ', ' + dur.selectedOptions[0].textContent.toLowerCase() : ''}.`
      : 'Pick at least one field.';
  };
  for (const b of boxes) b.addEventListener('change', update);
  dur.addEventListener('change', update);
  ok.addEventListener('click', async () => {
    ok.disabled = true;
    fill(errBox);
    try {
      const body = { fields: picked().map((x) => x.field), for: dur.value, comment: note.value.trim() };
      if (close.checked) body.update = { status: 'closed', disposition: disp.value };
      const res = await api('api/findings/' + encodeURIComponent(f.id) + '/suppress', body);
      dlg.close();
      dxNotify(res.warning ? 'Exception saved, but the finding was not updated.' : close.checked ? 'Exception saved and the finding closed.' : 'Exception saved.',
        { label: 'Undo', run: () => removeException(f.detection_id, res.exception.id) });
      await loadFindings({ quiet: true });
      if (openFinding === f.id) showFinding(f.id, { focus: false });
      if (typeof loadDetections === 'function' && detections.length) loadDetections();
    } catch (e) {
      fill(errBox, dxAlert('danger', 'Couldn’t save the exception.', e.message));
      ok.disabled = false;
    }
  });
  fill(dlg,
    el('div', { class: 'modal__head' }, el('div', {},
      el('h2', { class: 'modal__title', id: 'd-tune-title' }, 'Don’t alert on this again'),
      el('p', { class: 'modal__desc' }, 'Adds an exception to the detection. Matching results raise no finding and add no risk; other results still alert.'))),
    el('div', { class: 'modal__body' },
      errBox,
      fields.length ? el('fieldset', { class: 'dx-sf-fields' }, el('legend', { class: 'label' }, 'Match these values'),
        ...entityRows, otherRows.length ? (entityRows.length ? more : el('div', {}, ...otherRows)) : null)
        : dxAlert('warning', 'This finding has no values to match on.', 'Turn the detection off, or edit its query, instead.'),
      el('div', { class: 'form-grid' }, dxField('How long', dur), dxField('Close as', disp)),
      el('label', { class: 'check' }, close, 'Close this finding'),
      dxField('Comment', note),
      preview),
    el('div', { class: 'modal__foot' }, cancel, ok));
  close.addEventListener('change', () => { disp.disabled = !close.checked; });
  update();
  dlg.onclose = null;
  dlg.showModal();
  (boxes.find((b) => b.checked) || cancel).focus();
}

async function removeException(detID, exID) {
  try {
    await api('api/detections/' + encodeURIComponent(detID) + '/exceptions/' + encodeURIComponent(exID), undefined, 'DELETE');
    dxNotify('Exception removed.');
    if (typeof loadDetections === 'function') await loadDetections();
  } catch (e) { dxNotify('Couldn’t remove the exception: ' + e.message, null, { tone: 'danger' }); }
}

function exceptionWhen(e) {
  const now = Date.now();
  if (e.from && new Date(e.from).getTime() > now) return `From ${dxClock(e.from)}${e.until ? ' to ' + dxClock(e.until) : ''}`;
  if (e.until) return new Date(e.until).getTime() <= now ? 'Ended ' + ago(e.until) : 'Until ' + dxClock(e.until);
  return 'Until removed';
}

// exceptionsSection lists a detection's exceptions; admins add a
// maintenance window or remove one.
function exceptionsSection(d, admin) {
  const es = d.exceptions || [];
  const items = es.map((e) => {
    const ended = e.until && new Date(e.until).getTime() <= Date.now();
    const what = e.match && Object.keys(e.match).length
      ? Object.entries(e.match).sort(([a], [b]) => a.localeCompare(b)).map(([k, v]) => el('span', { class: 'badge badge--outline badge--mono', title: `${k} = ${v}` }, `${k}=${v}`))
      : [el('span', { class: 'badge' }, 'Every result')];
    return el('li', { class: 'dx-ex' + (ended ? ' dx-ex--ended' : '') },
      el('div', { class: 'dx-ex__what' }, ...what),
      el('div', { class: 'dx-ex__meta' }, ...dxDots(el('span', {}, exceptionWhen(e)), e.by ? el('span', {}, 'by ' + e.by) : null,
        e.added ? el('span', { title: fmtTime(e.added) }, 'added ' + ago(e.added)) : null)),
      e.comment ? el('p', { class: 'dx-ex__note' }, e.comment) : null,
      admin ? dxBtn('ghost', '', () => removeException(d.id, e.id), { sm: true, icon: 'trash-2', title: 'Remove this exception', cls: 'dx-ex__del' }) : null);
  });
  const add = admin ? dxBtn('ghost', 'Add', () => addException(d), { sm: true, icon: 'plus', title: 'Add an exception or a maintenance window' }) : null;
  return el('section', { class: 'section' },
    el('div', { class: 'dx-sec-head' }, el('h3', { class: 'section-title' }, 'Exceptions', es.length ? el('span', { class: 'count' }, String(es.length)) : null), add),
    es.length ? el('ul', { class: 'dx-exlist' }, ...items)
      : el('p', { class: 'muted' }, admin ? 'None. Use Don’t alert on this again on a finding, or Add, to stop alerts for a host, user or time window.' : 'None.'));
}

// addException adds an exception by hand: field values to match, or none
// for a maintenance window that silences every result.
function addException(d) {
  const dlg = tuneDialog();
  const match = el('textarea', { class: 'textarea mono', id: 'ae-match', rows: 3, spellcheck: 'false', placeholder: 'host=web*\nuser=svc-backup' });
  const fromIn = el('input', { class: 'input', id: 'ae-from', type: 'datetime-local' });
  const dur = select('ae-for', [['1h', '1 hour'], ['4h', '4 hours'], ...SUPPRESS_FOR], '7d');
  dur.className = 'select select--block';
  const note = el('textarea', { class: 'textarea', id: 'ae-comment', rows: 2, placeholder: 'Why' });
  const errBox = el('div', {});
  const cancel = dxBtn('ghost', 'Cancel', () => dlg.close());
  const ok = dxBtn('primary', 'Add exception', null, { icon: 'plus' });
  ok.addEventListener('click', async () => {
    fill(errBox);
    const m = {};
    for (const line of match.value.split('\n').map((s) => s.trim()).filter(Boolean)) {
      const i = line.indexOf('=');
      if (i < 1) { fill(errBox, dxAlert('danger', 'Write each value as field=value.', line)); return; }
      m[line.slice(0, i).trim()] = line.slice(i + 1).trim();
    }
    const body = { match: m, for: dur.value, comment: note.value.trim() };
    if (fromIn.value) body.from = new Date(fromIn.value).toISOString();
    ok.disabled = true;
    try {
      await api('api/detections/' + encodeURIComponent(d.id) + '/exceptions', body);
      dlg.close();
      dxNotify('Exception added.');
      await loadDetections();
    } catch (e) {
      fill(errBox, dxAlert('danger', 'Couldn’t add the exception.', e.problems ? e.problems.join(' ') : e.message));
      ok.disabled = false;
    }
  });
  fill(dlg,
    el('div', { class: 'modal__head' }, el('div', {},
      el('h2', { class: 'modal__title', id: 'd-tune-title' }, 'Add an exception'),
      el('p', { class: 'modal__desc' }, 'Results of this detection that match raise no finding and add no risk.'))),
    el('div', { class: 'modal__body' },
      errBox,
      dxField('Match', match, 'One field=value per line; * and ? are wildcards and case is ignored. Leave it empty to silence every result for a maintenance window.'),
      el('div', { class: 'form-grid' }, dxField('Starting', fromIn, 'Empty starts now.'), dxField('How long', dur)),
      dxField('Comment', note)),
    el('div', { class: 'modal__foot' }, cancel, ok));
  dlg.onclose = null;
  dlg.showModal();
  match.focus();
}

// ---- detection editor ----
const blankDetection = () => ({
  id: '', title: '', description: '', query: '', schedule: '5m', lookback: '15m', severity: 'medium',
  mitre: [], throttle: { fields: [], window: '1h' }, enabled: true, guidance: '', tags: [], source: 'new',
});

function editDetection(d, opts = {}) {
  if (currentPage !== 'detections') showPage('detections');
  const isNew = d.source === 'new';
  const dlg = $('d-editor');
  const inp = (id, value, attrs = {}) => el('input', { class: 'input', id, type: 'text', value: value == null ? '' : String(value), autocomplete: 'off', ...attrs });
  const area = (id, value, rows, cls) => { const t = el('textarea', { class: 'textarea' + (cls ? ' ' + cls : ''), id, rows: String(rows) }); t.value = value || ''; return t; };
  const id = inp('de-id', d.id, isNew ? { placeholder: 'lowercase-with-dashes', spellcheck: 'false' } : { readonly: '' });
  const title = inp('de-title', d.title, { placeholder: 'Brute force from $src$' });
  const query = area('de-query', d.query, 5, 'mono det-code');
  query.spellcheck = false;
  const schedule = inp('de-schedule', d.schedule, { placeholder: '5m', spellcheck: 'false' });
  const lookback = inp('de-lookback', d.lookback, { placeholder: '15m', spellcheck: 'false' });
  const severity = select('de-severity', SEVERITIES.map((s) => [s, SEVERITY_FULL[s]]), d.severity);
  severity.className = 'select select--block';
  const mitre = inp('de-mitre', (d.mitre || []).join(', '), { placeholder: 'T1110.003, T1078', spellcheck: 'false' });
  const tfields = inp('de-tfields', ((d.throttle || {}).fields || []).join(', '), { placeholder: 'src, user', spellcheck: 'false' });
  const twindow = inp('de-twindow', (d.throttle || {}).window || '', { placeholder: '1h', spellcheck: 'false' });
  const desc = area('de-desc', d.description, 2);
  const guidance = area('de-guidance', d.guidance, 3);
  const risk = d.risk || null;
  const riskScore = inp('de-risk-score', risk ? risk.score : '', { placeholder: 'None', type: 'number', min: '1', max: '1000', inputmode: 'numeric' });
  const riskObjs = inp('de-risk-objs', risk ? risk.objects.map((o) => o.field + ':' + o.type).join(', ') : '', { placeholder: 'user:user, dest:system', spellcheck: 'false' });
  const riskOnly = el('input', { type: 'checkbox', id: 'de-risk-only' });
  riskOnly.checked = !!(risk && risk.only);
  const enabled = el('input', { type: 'checkbox', id: 'de-enabled', role: 'switch' });
  enabled.checked = !!d.enabled;
  const errBox = el('div', { class: 'hidden' });
  const out = el('div', { class: 'dx-test-out', 'aria-live': 'polite' });
  const list = (s) => s.split(',').map((x) => x.trim()).filter(Boolean);
  const read = () => ({
    id: id.value.trim(), title: title.value.trim(), description: desc.value.trim(), query: query.value.trim(),
    // The name (the title without $field$ tokens) was written for this title;
    // a new title goes without one, and the server derives it.
    name: d.name && title.value.trim() === d.title ? d.name : undefined,
    schedule: schedule.value.trim(), lookback: lookback.value.trim(), severity: severity.value,
    mitre: list(mitre.value), throttle: { fields: list(tfields.value), window: twindow.value.trim() },
    enabled: enabled.checked, guidance: guidance.value.trim(), tags: d.tags || [], exceptions: d.exceptions || undefined,
    risk: riskScore.value.trim() ? {
      score: parseInt(riskScore.value, 10),
      objects: list(riskObjs.value).map((x) => { const [field, type] = x.split(':').map((s) => s.trim()); return { field, type: type || 'other' }; }),
      only: riskOnly.checked,
    } : undefined,
  });
  const body = el('div', { class: 'modal__body' });
  const fail = (e) => {
    fill(errBox, dxAlert('danger', e.problems ? 'Please fix these first:' : 'That didn’t work.', e.problems ? null : e.message,
      e.problems ? el('ul', { class: 'dx-problems' }, ...e.problems.map((p) => el('li', {}, p))) : null));
    errBox.classList.remove('hidden');
    body.scrollTop = 0;
  };
  const ok = () => errBox.classList.add('hidden');

  const testBtn = dxBtn('ghost', 'Test', null, { icon: 'scan-search', title: 'Search the lookback window without raising findings' });
  testBtn.addEventListener('click', async () => {
    ok();
    testBtn.disabled = true;
    fill(out, el('div', { class: 'callout dx-test' }, icon('scan-search'), el('div', {}, `Searching the last ${lookback.value || '?'}…`)));
    try {
      const res = await api('api/detections/test', read());
      fill(out, testResult(res, lookback.value));
    } catch (e) { out.replaceChildren(); fail(e); }
    testBtn.disabled = false;
    out.scrollIntoView({ block: 'nearest' });
  });
  const searchBtn = dxBtn('ghost', 'Open in Search', () => { dlg.close(); openSearch(query.value, '-' + (lookback.value || '24h')); }, { icon: 'search' });
  const saveBtn = el('button', { class: 'btn btn--primary', type: 'submit' }, isNew ? 'Create detection' : 'Save');
  const form = el('form', { method: 'dialog', class: 'dx-form', novalidate: '' });
  form.addEventListener('submit', async (ev) => {
    ev.preventDefault();
    ok();
    saveBtn.disabled = true;
    try {
      const b = read();
      const saved = isNew ? await api('api/detections', b) : await api('api/detections/' + encodeURIComponent(b.id), b, 'PUT');
      dlg.close();
      det.open = saved.id;
      det.closed = false;
      det.msg = null;
      det.test = null;
      if (!detections.some((x) => x.id === saved.id) || !detShows(saved, det.show)) det.show = '';
      dxNotify(isNew ? (saved.enabled ? 'Detection created.' : 'Detection created. It is off until you turn it on.') : 'Detection saved.');
      await loadDetections();
      openDetection(saved.id, { focus: false });
      const tr = $('d-list').querySelector(`tr[data-id="${CSS.escape(saved.id)}"]`);
      if (tr) tr.scrollIntoView({ block: 'nearest' });
    } catch (e) { fail(e); } finally { saveBtn.disabled = false; }
  });
  const close = dxBtn('ghost', '', () => dlg.close(), { sm: true, icon: 'x', title: 'Close', cls: 'dx-close' });
  const note = opts.warnings && opts.warnings.length
    ? dxAlert('warning', 'Review before turning it on.', null, el('ul', { class: 'dx-problems' }, ...opts.warnings.map((w) => el('li', {}, w)))) : null;
  fill(body, note, errBox,
    dxField('Title', title, 'Use $field$ to insert a value from the result, like $src$.'),
    el('div', { class: 'form-grid' }, dxField('ID', id, isNew ? 'Lowercase letters, digits and dashes.' : 'IDs cannot change.'), dxField('Severity', severity)),
    dxField('Query', query, 'Each result row becomes a finding. Leave out earliest= and latest=; Search back sets the window.'),
    out,
    el('div', { class: 'form-grid' }, dxField('Run every', schedule, 'For example 5m, 1h or 1d.'), dxField('Search back', lookback, 'How far back each run looks.')),
    el('div', { class: 'form-grid' }, dxField('Group repeats by', tfields, 'One finding per value of these fields.'), dxField('For', twindow, 'How long to hold back repeats.')),
    dxField('ATT&CK techniques', mitre, 'Comma-separated IDs.'),
    dxField('Description', desc),
    dxField('Triage guidance', guidance, 'Shown to analysts on each finding.'),
    el('div', { class: 'form-grid' }, dxField('Risk score', riskScore, 'Added to each risk object per result.'), dxField('Risk objects', riskObjs, 'field:type pairs; type is user, system or other.')),
    el('label', { class: 'check' }, riskOnly, 'Risk only: record risk without raising findings'),
    el('label', { class: 'switch dx-enable' }, enabled, 'On: run it on its schedule'));
  fill(form,
    el('div', { class: 'modal__head' },
      el('div', {}, el('h2', { class: 'modal__title', id: 'de-heading' }, isNew ? 'New detection' : 'Edit detection'),
        el('p', { class: 'modal__desc' }, d.source === 'builtin' ? 'A built-in detection. Saving keeps your version, and you can revert to the built-in later.'
          : isNew ? 'A search that runs on a schedule and raises a finding for each result.' : plainTitle(d.title))),
      close),
    body,
    el('div', { class: 'modal__foot' }, testBtn, searchBtn, el('span', { class: 'spacer' }), dxBtn('ghost', 'Cancel', () => dlg.close()), saveBtn));
  dlg.replaceChildren(form);
  dlg.showModal();
  (isNew && !title.value ? title : isNew && !query.value ? query : title).focus();
}

$('d-new').addEventListener('click', () => editDetection(blankDetection()));
$('d-sigma').addEventListener('click', () => {
  $('d-sigma-error').classList.add('hidden');
  $('d-sigma-box').showModal();
  $('d-sigma-text').focus();
});
for (const id of ['d-sigma-cancel', 'd-sigma-x']) $(id).addEventListener('click', () => $('d-sigma-box').close());
$('d-sigma-form').addEventListener('submit', async (ev) => {
  ev.preventDefault();
  $('d-sigma-error').classList.add('hidden');
  const btn = $('d-sigma-convert');
  if (!$('d-sigma-text').value.trim()) {
    $('d-sigma-error-text').textContent = 'Paste a Sigma rule first.';
    $('d-sigma-error').classList.remove('hidden');
    return;
  }
  btn.disabled = true;
  try {
    const res = await api('api/detections/sigma', { rule: $('d-sigma-text').value });
    $('d-sigma-box').close();
    $('d-sigma-text').value = '';
    editDetection({ ...res.detection, source: 'new' }, { warnings: res.warnings });
  } catch (e) {
    $('d-sigma-error-text').textContent = e.problems ? e.problems.join('\n') : e.message;
    $('d-sigma-error').classList.remove('hidden');
  } finally { btn.disabled = false; }
});

// "Save as detection" on the Search page.
$('save-detection').addEventListener('click', () => {
  const text = $('query').value.trim();
  const d = blankDetection();
  // The time picker becomes the lookback; earliest/latest in the text are dropped.
  const [search, rest] = splitPipes(text);
  const cleaned = search.replace(/\b(earliest|latest)=("[^"]*"|\S+)/g, '').replace(/\s+/g, ' ').trim();
  d.query = cleaned + (rest ? '\n' + rest.trim() : '');
  const t = $('time').value;
  if (t && t !== '0') d.lookback = t.replace(/^-/, '');
  d.enabled = false;
  showPage('detections');
  editDetection(d);
});

// ---------- coverage ----------
let coverage = null;
const cov = { seq: 0, shown: false };

async function loadCoverage() {
  const seq = ++cov.seq;
  if (!cov.shown) renderCoverageSkeleton();
  try {
    const c = await api('api/coverage');
    if (seq !== cov.seq) return;
    coverage = c;
    indexAttack(c);
    cov.shown = true;
    renderCoverage();
  } catch (e) {
    if (seq !== cov.seq) return;
    cov.shown = false;
    $('c-summary').replaceChildren();
    $('c-matrix').replaceChildren(el('div', { class: 'card cov-error' },
      dxEmpty({ tone: 'danger', icon: 'circle-alert', title: 'Couldn’t load coverage', text: e.message + '.', action: dxRetry(loadCoverage) })));
  }
}

function renderCoverageSkeleton() {
  $('c-summary').replaceChildren(...Array.from({ length: 3 }, () => el('div', { class: 'card kpi', 'aria-busy': 'true' },
    dxSkel('60%'), el('div', { class: 'dx-skel-gap' }), dxSkel('40px'), el('div', { class: 'dx-skel-gap' }), dxSkel('50%'))));
  $('c-matrix').replaceChildren(...Array.from({ length: 7 }, () => el('div', { class: 'card cov-col', 'aria-busy': 'true' },
    el('div', { class: 'cov-col__head' }, dxSkel('70%'), el('div', { class: 'dx-skel-gap' }), dxSkel('40%')),
    el('div', { class: 'cov-list' }, ...Array.from({ length: 8 }, () => el('div', { class: 'cov-skel' }, dxSkel('85%')))))));
}

function covKpi(label, value, of, foot) {
  return el('div', { class: 'card kpi' },
    el('div', { class: 'kpi__label' }, label),
    el('div', { class: 'kpi__value num' }, String(value), of ? el('small', {}, of) : null),
    el('div', { class: 'kpi__foot' }, foot));
}

function covCell(x) {
  const on = x.enabled || [];
  const off = x.disabled || [];
  const level = on.length >= 3 ? '3' : on.length ? String(on.length) : off.length ? 'off' : '0';
  const ids = [...on, ...off];
  const tip = `${x.id} ${x.name}`
    + (on.length ? `\nOn: ${on.join(', ')}` : '') + (off.length ? `\nOff: ${off.join(', ')}` : '')
    + ((x.subs || []).length ? `\nSub-techniques: ${x.subs.join(', ')}` : '')
    + (ids.length ? '\nOpen its detections' : '\nNo detection yet: open it on attack.mitre.org');
  const b = el('button', { class: 'cov-cell', type: 'button', 'data-level': level, title: tip },
    el('span', { class: 'cov-cell__id' }, x.id), el('span', { class: 'cov-cell__name' }, x.name),
    on.length > 1 ? el('span', { class: 'cov-cell__n', title: `${on.length} detections on` }, String(on.length)) : null);
  b.addEventListener('click', () => {
    if (ids.length) {
      $('d-filter').value = x.id;
      det.show = '';
      det.open = null;
      det.closed = false;
      showPage('detections');
    } else window.open('https://attack.mitre.org/techniques/' + x.id + '/', '_blank', 'noopener');
  });
  return el('li', {}, b);
}

function renderCoverage() {
  const c = coverage;
  const s = c.summary;
  const pct = s.techniques ? Math.round(100 * s.enabled / s.techniques) : 0;
  const covered = c.tactics.filter((t) => t.covered > 0).length;
  const none = c.tactics.length - covered;
  const review = s.available ? el('button', { class: 'link-btn', type: 'button' }, 'Review turned-off detections', icon('arrow-right', 'icon--sm')) : null;
  if (review) review.addEventListener('click', () => { $('d-filter').value = ''; det.show = 'disabled'; det.open = null; det.closed = false; showPage('detections'); });
  fill($('c-summary'),
    covKpi('Covered techniques', s.enabled, ` of ${s.techniques}`, `${pct}% of ATT&CK v${c.version}`),
    covKpi('Tactics with coverage', covered, ` of ${c.tactics.length}`, none ? `${none} with no detection yet` : 'Every tactic has a detection'),
    covKpi('Ready to turn on', s.available, null, review || 'No turned-off detection would add coverage'));
  const unknown = Object.entries(c.unknown || {});
  $('cov-unknown').classList.toggle('hidden', !unknown.length);
  $('cov-unknown-text').textContent = unknown.map(([t, dId]) => `${t} (used by ${dId})`).join(', ');

  const term = $('cov-filter').value.trim().toLowerCase();
  const only = $('c-only').checked;
  const cols = c.tactics.map((t) => {
    const techs = t.techniques.filter((x) => (!only || (x.enabled || x.disabled)) && (!term || `${x.id} ${x.name}`.toLowerCase().includes(term)));
    if (term && !techs.length) return null;
    const share = t.techniques.length ? Math.round(100 * t.covered / t.techniques.length) : 0;
    return el('section', { class: 'card cov-col', 'aria-label': t.name },
      el('header', { class: 'cov-col__head' },
        el('h3', { class: 'cov-col__title' }, t.name),
        el('div', { class: 'cov-col__sub' }, el('span', { class: 'num' }, `${t.covered} of ${t.techniques.length}`),
          el('span', { class: 'cov-meter', title: `${share}% covered` }, el('span', { style: `--w:${share}%` })))),
      techs.length ? el('ul', { class: 'cov-list', role: 'list' }, ...techs.map(covCell))
        : el('p', { class: 'cov-none' }, 'No detections yet'));
  }).filter(Boolean);
  if (!cols.length) {
    $('c-matrix').replaceChildren(el('div', { class: 'card cov-error' }, dxEmpty({
      icon: 'search', title: 'No technique matches', text: `Nothing matches “${$('cov-filter').value.trim()}”. Try an ID like T1078 or part of a name.`,
      action: { label: 'Clear search', run: () => { $('cov-filter').value = ''; renderCoverage(); } },
    })));
    return;
  }
  $('c-matrix').replaceChildren(...cols);
}
$('c-only').addEventListener('change', () => coverage && cov.shown && renderCoverage());
$('cov-filter').addEventListener('input', () => coverage && cov.shown && renderCoverage());

// ---------- keys ----------
// "/" focuses the page's own search box (the shell uses it for the page
// jumper elsewhere); J and K move through the open list; X selects.
window.addEventListener('keydown', (ev) => {
  if (ev.key !== '/' || ev.ctrlKey || ev.metaKey || ev.altKey || isTyping(ev.target) || document.querySelector('dialog[open]')) return;
  const box = { findings: 'f-text', detections: 'd-filter', coverage: 'cov-filter' }[currentPage];
  const input = box && $(box);
  if (!input || !input.offsetParent) return;
  ev.preventDefault();
  ev.stopPropagation();
  input.focus();
  input.select();
}, true);
document.addEventListener('keydown', (ev) => {
  if (ev.ctrlKey || ev.metaKey || ev.altKey || ev.defaultPrevented) return;
  if (isTyping(ev.target) || document.querySelector('dialog[open]') || appEl.hasAttribute('data-nav-open')) return;
  const k = ev.key.toLowerCase();
  if (currentPage === 'findings') {
    if (k === 'j' || k === 'k') { ev.preventDefault(); stepFinding(k === 'j' ? 1 : -1); }
    if (k === 'x' && can('analyst') && openFinding && findingsList.some((f) => f.id === openFinding)) {
      ev.preventDefault();
      if (selected.has(openFinding)) selected.delete(openFinding); else selected.add(openFinding);
      const cb = $('f-list').querySelector(`tr[data-id="${CSS.escape(openFinding)}"] input[type=checkbox]`);
      if (cb) cb.checked = selected.has(openFinding);
      updateBulk();
    }
  } else if (currentPage === 'detections' && (k === 'j' || k === 'k')) {
    ev.preventDefault();
    stepDetection(k === 'j' ? 1 : -1);
  }
});

syncInspectors();
refreshOpenCount();
setInterval(refreshOpenCount, 60000);
