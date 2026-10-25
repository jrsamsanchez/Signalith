// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0
// Investigations: cases that group findings with the analyst's notes, the
// searches they ran and the events they pinned.
'use strict';

const caseState = {
  list: [], total: 0, loadedAt: 0, req: 0, // the list view
  open: null, data: null, // the open case
  drafts: {}, // unsent composer text, by case ID
};
const CASE_OPEN = ['new', 'in_progress', 'pending'];
const caseIsOpen = (s) => CASE_OPEN.includes(s);

async function refreshCaseCount() {
  try {
    const s = await api('api/cases/summary');
    const b = $('case-count');
    b.textContent = s.open;
    b.title = `${s.open} open`;
    b.classList.toggle('hidden', !s.open);
  } catch (_) { /* cases may be off on this server */ }
}
refreshCaseCount();

// ---------- small helpers ----------
const plural = (n, one, many) => `${n.toLocaleString()} ${n === 1 ? one : (many || one + 's')}`;
const fullTime = (t) => new Date(t).toLocaleString();
const shortDate = (t) => new Date(t).toLocaleDateString();
const sizeText = (n) => (n >= 1 << 20 ? (n / (1 << 20)).toFixed(1) + ' MB' : n >= 1024 ? Math.round(n / 1024) + ' KB' : plural(n, 'byte'));
// shortAgo drops the "ago" for table cells: 48m, 3h, 2d.
const shortAgo = (t) => { const a = ago(t); return a === 'just now' ? 'now' : a.replace(/ ago$/, ''); };
// when gives a timeline time: relative for a week, then the date.
function when(t) {
  const d = new Date(t);
  if (Date.now() - d.getTime() < 7 * 86400e3) return ago(t);
  return d.toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: d.getFullYear() === new Date().getFullYear() ? undefined : 'numeric' });
}
const dotsep = () => el('span', { class: 'dotsep', 'aria-hidden': 'true' });

function caseSelect(id, options, value, label) {
  const s = el('select', { id, class: 'select select--block' });
  if (label) s.setAttribute('aria-label', label);
  for (const [v, text] of options) {
    const o = el('option', { value: v }, text);
    if (v === value) o.selected = true;
    s.append(o);
  }
  return s;
}

// avatar draws an owner's initial; the signed-in user keeps the top bar's colour.
function caseAvatar(name) {
  if (!name) return el('span', { class: 'avatar avatar--sm avatar--none', 'aria-hidden': 'true' });
  let h = 0;
  for (const ch of name) h = (h * 31 + ch.charCodeAt(0)) >>> 0;
  const initial = (name.replace(/^[^a-z0-9]+/i, '').charAt(0) || '?').toUpperCase();
  return el('span', { class: 'avatar avatar--sm', 'data-hue': name === currentUser ? '0' : String(1 + (h % 4)), 'aria-hidden': 'true' }, initial);
}

// Entities: which icon and chip kind a field's values get.
const CASE_IP_RE = /^(\d{1,3}\.){3}\d{1,3}$|^[0-9a-f]*:[0-9a-f:.]+$/i;
function caseEntityKind(field, value) {
  if (['user', 'src_user', 'member'].includes(field)) return 'user';
  if (field === 'object') return 'group';
  if (['src', 'dest', 'host', 'src_host', 'dest_host', 'dvc'].includes(field)) return CASE_IP_RE.test(value) ? 'ip' : 'host';
  if (field === 'process_name') return 'process';
  if (/sha256|sha1|md5|hash/.test(field)) return 'hash';
  if (['url', 'query', 'domain'].includes(field)) return 'domain';
  return '';
}
const CASE_KIND_ICON = { user: 'user', group: 'users', host: 'server', ip: 'globe', process: 'terminal', hash: 'hash', domain: 'link' };
const CASE_ENTITY_FIELDS = ['user', 'src_user', 'src', 'src_host', 'dest', 'dest_host', 'host', 'process_name', 'process_sha256', 'process_md5', 'object', 'member', 'query', 'url', 'risk_object'];

// busy disables a button while its request runs, optionally relabelled;
// it returns a function that puts the button back.
function busy(btn, label) {
  const last = btn.lastChild;
  const text = last ? last.textContent : '';
  btn.disabled = true;
  if (label && last) last.textContent = label;
  return () => { btn.disabled = false; if (last) last.textContent = text; };
}

// ---------- toast ----------
// toast shows one message bottom right for 5 seconds (longer while the
// pointer or keyboard focus is on it). action is {label, run}; opts.tone is
// success or danger. If the toast hides while it holds focus, focus goes back
// to where it came from.
let toastTimer = null;
let toastNow = null; // { from, arm } of the toast on screen
function toast(msg, action, opts = {}) {
  const t = $('toast');
  const tone = opts.tone || 'success';
  const a = document.activeElement;
  const inside = !t.classList.contains('hidden') && t.contains(a);
  const now = { from: inside ? toastNow.from : a && a !== document.body && !t.contains(a) ? a : null, arm: null };
  toastNow = now;
  t.dataset.tone = tone;
  t.setAttribute('role', tone === 'danger' ? 'alert' : 'status');
  const hide = () => {
    clearTimeout(toastTimer);
    const hadFocus = t.contains(document.activeElement);
    t.classList.add('hidden');
    if (hadFocus) toastReturn(now.from);
  };
  fill(t, icon(tone === 'danger' ? 'circle-alert' : 'circle-check'),
    el('div', { class: 'toast__body' },
      opts.title ? el('div', { class: 'toast__title' }, opts.title) : null,
      el('div', { class: opts.title ? 'toast__text' : 'toast__title' }, msg)),
    action ? el('button', { type: 'button', onclick: () => { hide(); action.run(); } }, action.label) : null);
  t.classList.remove('hidden');
  // a toast that replaces a focused one keeps the focus on its button
  if (inside) { const b = t.querySelector('button'); if (b) b.focus({ preventScroll: true }); else toastReturn(now.from); }
  now.arm = () => { clearTimeout(toastTimer); toastTimer = setTimeout(hide, tone === 'danger' ? 8000 : 5000); };
  if (!toast.wired) {
    toast.wired = true;
    const held = () => t.matches(':hover') || t.contains(document.activeElement);
    t.addEventListener('mouseenter', () => clearTimeout(toastTimer));
    t.addEventListener('mouseleave', () => { if (!held() && !t.classList.contains('hidden')) toastNow.arm(); });
    t.addEventListener('focusin', (ev) => {
      clearTimeout(toastTimer);
      if (ev.relatedTarget && !t.contains(ev.relatedTarget)) toastNow.from = ev.relatedTarget;
    });
    t.addEventListener('focusout', (ev) => {
      if (!t.contains(ev.relatedTarget) && !t.matches(':hover') && !t.classList.contains('hidden')) toastNow.arm();
    });
  }
  now.arm();
}
// toastReturn puts focus back after a focused toast hides. The control may
// have been redrawn meanwhile: then its new copy (same id, or same action in
// the open inspector) takes focus, else the open inspector's title, else the
// page name.
function toastReturn(from) {
  const live = (n) => n && n.isConnected && !n.disabled && n.getClientRects().length ? n : null;
  const box = document.querySelector('.page.active .inspector:not([hidden]):not(.hidden)');
  const act = from && from.dataset && from.dataset.action;
  const back = live(from)
    || live(from && from.id ? document.getElementById(from.id) : null)
    || live(box && act ? box.querySelector(`[data-action="${CSS.escape(act)}"]`) : null)
    || live(box && box.querySelector('h2[tabindex="-1"]'))
    || $('crumb-page');
  back.focus({ preventScroll: true });
}
// sentence makes a server message read as a sentence: capital first, full stop last.
const sentence = (m) => { m = String(m || 'Something went wrong').trim(); m = m.charAt(0).toUpperCase() + m.slice(1); return /[.!?]$/.test(m) ? m : m + '.'; };
const toastError = (title, e) => toast(sentence(e.message), null, { tone: 'danger', title });

// ---------- dialogs ----------
// modalDialog makes (once) a <dialog class="modal"> of ours at the end of the body.
function modalDialog(id) {
  let d = $(id);
  if (!d) {
    d = el('dialog', { id, class: 'modal', 'aria-labelledby': id + '-title' });
    document.body.append(d);
  }
  // A click on the backdrop (the dialog box itself, outside its content) cancels.
  d.onclick = (ev) => { if (ev.target === d) d.close(); };
  return d;
}
function modalHead(id, title, desc, onClose) {
  return el('div', { class: 'modal__head' },
    el('div', {}, el('h2', { class: 'modal__title', id: id + '-title' }, title), desc ? el('p', { class: 'modal__desc' }, desc) : null),
    el('button', { type: 'button', class: 'btn btn--ghost btn--icon btn--sm modal__close', 'aria-label': 'Close', onclick: onClose }, icon('x')));
}
const formAlert = () => el('div', { class: 'alert hidden', 'data-tone': 'danger', role: 'alert' });
function showAlert(box, title, text) {
  fill(box, icon('circle-alert'), el('div', {}, el('b', {}, title), text ? el('p', {}, text) : null));
  box.classList.remove('hidden');
}

// caseConfirm asks before something is removed. It resolves to true or false.
function caseConfirm({ title, text, confirm }) {
  const d = modalDialog('c-confirm');
  return new Promise((resolve) => {
    let answer = false;
    const ok = el('button', { type: 'button', class: 'btn btn--danger', onclick: () => { answer = true; d.close(); } }, confirm);
    fill(d, modalHead('c-confirm', title, text, () => d.close()),
      el('div', { class: 'modal__foot' }, el('button', { type: 'button', class: 'btn btn--ghost', onclick: () => d.close() }, 'Cancel'), ok));
    d.onclose = () => resolve(answer);
    d.showModal();
    ok.focus();
  });
}

// ---------- case list ----------
pageHooks.push((name) => {
  if (name !== 'cases') return;
  // A link to a case (#cases?id=…, which tickets in Jira and ServiceNow
  // carry) opens it.
  if (hashCase) { caseState.open = hashCase; caseState.data = null; hashCase = ''; }
  if (caseState.open) showCase(caseState.open);
  else loadCases();
});

async function showCaseList() {
  const was = caseState.open;
  caseState.open = null;
  caseState.data = null;
  $('c-view').classList.add('hidden');
  $('c-list-view').classList.remove('hidden');
  document.title = 'Investigations · Signalith';
  window.scrollTo(0, 0);
  await loadCases();
  // Back to the list: keyboard focus goes to the case you came from.
  const a = document.activeElement;
  if (caseState.open || (a && a !== document.body && !$('c-view').contains(a))) return;
  const rows = $('c-list').querySelectorAll('tr.case-row');
  const tr = [...rows].find((r) => r.dataset.id === was) || rows[0];
  if (tr) tr.focus();
}

function openCase(id) {
  caseState.open = id;
  if ($('page-cases').classList.contains('active')) showCase(id);
  else showPage('cases');
}

const filtersSet = () => $('c-status').value !== 'new,in_progress,pending' || $('c-owner').value || $('c-text').value.trim();

// loadCases fetches the list. A quiet load (the 30-second refresh) keeps the
// table as it is while it waits and redraws only when something changed.
async function loadCases({ quiet = false } = {}) {
  refreshCaseCount();
  const p = new URLSearchParams({ limit: '500' });
  if ($('c-status').value) p.set('status', $('c-status').value);
  if ($('c-owner').value === 'me' && currentUser) p.set('owner', currentUser);
  if ($('c-text').value.trim()) p.set('q', $('c-text').value.trim());
  const req = ++caseState.req;
  if (!quiet) renderCasesLoading();
  let res;
  try {
    res = await api('api/cases?' + p);
  } catch (e) {
    if (req === caseState.req && !quiet) renderCasesError(e);
    return;
  }
  if (req !== caseState.req) return;
  const changed = !quiet || JSON.stringify(res.cases) !== JSON.stringify(caseState.list) || res.total !== caseState.total;
  caseState.list = res.cases;
  caseState.total = res.total;
  caseState.loadedAt = Date.now();
  if (changed) renderCases(); else updateCasesFoot();
}

const CASE_COLS = [
  ['sev', 'Severity'], ['title', 'Case'], ['status', 'Status'], ['owner', 'Owner'], ['findings', 'Findings', 'num hide-md hide-sm'], ['age', 'Updated', 'num'],
];
function casesTable(rows, busyState) {
  return el('div', { class: 'table-wrap' }, el('table', { class: 'table table--stack c-table', 'aria-busy': busyState ? 'true' : 'false' },
    el('thead', {}, el('tr', {}, ...CASE_COLS.map(([k, label, cls]) => el('th', { 'data-col': k, class: cls || '', scope: 'col' }, label)))),
    el('tbody', {}, ...rows)));
}

function renderCasesLoading() {
  const sk = (w) => el('span', { class: 'skeleton', style: `width:${w}` });
  const rows = [0, 1, 2].map(() => el('tr', {},
    el('td', { 'data-col': 'sev' }, sk('64px')),
    el('td', { 'data-col': 'title' }, sk('70%'), el('div', { class: 'c-sk-gap' }), sk('40%')),
    el('td', { 'data-col': 'status' }, sk('96px')),
    el('td', { 'data-col': 'owner' }, sk('64px')),
    el('td', { 'data-col': 'findings', class: 'num hide-md hide-sm' }, sk('16px')),
    el('td', { 'data-col': 'age', class: 'num' }, sk('28px'))));
  fill($('c-list'), casesTable(rows, true));
}

function renderCasesError(e) {
  fill($('c-list'), el('div', { class: 'empty', 'data-tone': 'danger' },
    el('span', { class: 'empty__icon' }, icon('circle-alert')),
    el('div', { class: 'empty__title' }, 'Couldn’t load investigations'),
    el('p', { class: 'empty__text' }, sentence(e.message) + ' Your filters are kept.'),
    el('div', { class: 'empty__actions' }, el('button', { type: 'button', class: 'btn btn--secondary btn--sm', onclick: () => loadCases() }, icon('refresh-cw'), 'Try again'))));
}

function caseRow(c) {
  const ents = (c.entities || []).slice(0, 8);
  const open = () => openCase(c.id);
  const n = (c.findings || []).length;
  return el('tr', {
    class: 'case-row', tabindex: '0', 'data-id': c.id, 'aria-label': `${c.title}, ${STATUS_LABEL[c.status] || c.status}`,
    onclick: open,
    onkeydown: (ev) => { if (ev.key === 'Enter' || ev.key === ' ') { ev.preventDefault(); open(); } },
  },
  el('td', { 'data-col': 'sev' }, sevBadge(c.severity)),
  el('td', { 'data-col': 'title' },
    el('div', { class: 'cell-title', title: c.title }, c.title),
    ents.length ? el('div', { class: 'cell-sub' }, ...ents.map((e) => {
      const kind = caseEntityKind(e.field, e.value);
      return el('span', Object.assign({ class: 'chip', title: `${e.field}: ${e.value}` }, kind ? { 'data-kind': kind } : {}), el('span', {}, e.value));
    })) : el('div', { class: 'cell-sub c-sub-empty' }, c.description || 'No entities yet')),
  el('td', { 'data-col': 'status' }, statusBadge(c.status), el('span', { class: 'cell-det', title: 'Case ' + c.id }, c.id)),
  el('td', { 'data-col': 'owner' }, el('span', { class: 'owner', title: c.owner || 'Unassigned' }, caseAvatar(c.owner),
    el('span', { class: c.owner ? 'owner__name' : 'owner__name c-unassigned' }, c.owner || 'Unassigned'))),
  el('td', { 'data-col': 'findings', class: 'num hide-md hide-sm', title: plural(n, 'finding') }, String(n)),
  el('td', { 'data-col': 'age', class: 'num age', title: `Updated ${fullTime(c.updated)}\nOpened ${fullTime(c.created)}` }, shortAgo(c.updated)));
}

function renderCases() {
  const list = caseState.list;
  if (!list.length) {
    const filtered = filtersSet();
    fill($('c-list'), el('div', { class: 'empty' },
      el('span', { class: 'empty__icon' }, icon(filtered ? 'filter-x' : 'briefcase')),
      el('div', { class: 'empty__title' }, filtered ? 'No cases match these filters' : 'No open investigations'),
      el('p', { class: 'empty__text' }, filtered ? 'Try another status or owner, or clear the search.'
        : can('analyst') ? 'Start one with New case, or select findings on the Findings page and choose Add to case.'
          : 'Cases that analysts open appear here.'),
      filtered ? el('div', { class: 'empty__actions' }, el('button', { type: 'button', class: 'btn btn--secondary btn--sm', onclick: clearCaseFilters }, 'Clear filters')) : null));
    return;
  }
  fill($('c-list'), casesTable(list.map(caseRow)), el('div', { class: 'table-foot' },
    el('span', { id: 'c-count' }), el('span', { class: 'spacer' }),
    el('span', { class: 'live' }, el('span', { class: 'pulse', 'aria-hidden': 'true' }), el('span', { id: 'c-updated' }))));
  updateCasesFoot();
}

function updateCasesFoot() {
  const count = $('c-count');
  if (!count) return;
  const n = caseState.list.length;
  count.textContent = caseState.total > n ? `Showing ${n.toLocaleString()} of ${caseState.total.toLocaleString()}; narrow the filters to see the rest`
    : plural(n, 'case');
  const s = Math.round((Date.now() - caseState.loadedAt) / 1000);
  $('c-updated').textContent = 'Live · updated ' + (s < 10 ? 'just now' : s < 60 ? s + 's ago' : ago(caseState.loadedAt));
}

function clearCaseFilters() {
  $('c-status').value = 'new,in_progress,pending';
  $('c-owner').value = '';
  $('c-text').value = '';
  loadCases();
}

for (const id of ['c-status', 'c-owner']) $(id).addEventListener('change', () => loadCases());
let caseTextTimer = null;
$('c-text').addEventListener('input', () => { clearTimeout(caseTextTimer); caseTextTimer = setTimeout(() => loadCases(), 300); });
$('c-text').addEventListener('keydown', (e) => {
  if (e.key === 'Enter') { clearTimeout(caseTextTimer); loadCases(); }
  if (e.key === 'Escape' && $('c-text').value) { e.preventDefault(); $('c-text').value = ''; loadCases(); }
});
$('c-new').addEventListener('click', async () => {
  const id = await pickCase({ only: 'new', heading: 'New case' });
  if (id) openCase(id);
});
// "/" searches the list (Ctrl+K still opens the page jumper).
window.addEventListener('keydown', (ev) => {
  if (ev.key !== '/' || ev.ctrlKey || ev.metaKey || ev.altKey || isTyping(ev.target) || document.querySelector('dialog[open]')) return;
  if (!$('page-cases').classList.contains('active') || $('c-list-view').classList.contains('hidden')) return;
  ev.preventDefault();
  ev.stopPropagation();
  $('c-text').focus();
  $('c-text').select();
}, true);
// The list stays current: it reloads every 30 seconds while it is on screen.
setInterval(() => {
  if (document.hidden || caseState.open || !$('page-cases').classList.contains('active')) return;
  if (Date.now() - caseState.loadedAt >= 30000) loadCases({ quiet: true });
  else updateCasesFoot();
}, 10000);

// ---------- one case ----------
async function showCase(id) {
  caseState.open = id;
  const box = $('c-view');
  const first = !caseState.data || caseState.data.case.id !== id;
  // Opening a case (Enter on a row, Open case elsewhere) takes keyboard focus
  // to its title once it is drawn; a refresh of the open case leaves focus be.
  const takeFocus = first && !box.contains(document.activeElement);
  $('c-list-view').classList.add('hidden');
  box.classList.remove('hidden');
  if (first) {
    window.scrollTo(0, 0);
    renderCaseLoading();
  }
  let data;
  try {
    data = await api('api/cases/' + encodeURIComponent(id));
  } catch (e) {
    if (caseState.open !== id) return;
    if (!first) { toastError('Couldn’t refresh the case', e); return; }
    fill(box, backButton(), el('div', { class: 'card' }, el('div', { class: 'empty', 'data-tone': 'danger' },
      el('span', { class: 'empty__icon' }, icon('circle-alert')),
      el('div', { class: 'empty__title' }, 'Couldn’t open this case'),
      el('p', { class: 'empty__text' }, sentence(e.message)),
      el('div', { class: 'empty__actions' }, el('button', { type: 'button', class: 'btn btn--secondary btn--sm', onclick: () => showCase(id) }, icon('refresh-cw'), 'Try again')))));
    return;
  }
  if (caseState.open !== id) return;
  caseState.data = data;
  renderCase();
  if (takeFocus && $('page-cases').classList.contains('active')) {
    const a = document.activeElement;
    // unless you have moved on to something still on screen
    if (!a || a === document.body || box.contains(a) || !a.getClientRects().length) box.querySelector('.c-title')?.focus({ preventScroll: true });
  }
}

const backButton = () => el('button', { type: 'button', class: 'btn btn--ghost btn--sm c-back', onclick: showCaseList }, icon('arrow-left'), 'Investigations');

function renderCaseLoading() {
  const sk = (w, h) => el('span', { class: 'skeleton', style: `width:${w}` + (h ? `;height:${h}` : '') });
  const card = (lines) => el('div', { class: 'card' }, el('div', { class: 'card__body c-sk' }, ...lines));
  fill($('c-view'), backButton(),
    el('div', { class: 'c-head', 'aria-busy': 'true' }, el('div', { class: 'c-head__main' }, sk('320px', '20px'), sk('260px'))),
    el('div', { class: 'c-layout' },
      el('div', { class: 'c-main' }, card([sk('30%'), sk('100%', '72px'), sk('80%'), sk('60%'), sk('70%')])),
      el('div', { class: 'c-side' }, card([sk('40%'), sk('100%', '32px'), sk('100%', '32px'), sk('100%', '72px')]))));
}

// caseCall sends a change to case id and, if that case is on screen,
// redraws it with the server's answer. It returns null after an error.
async function caseCall(id, path, body, method, errTitle = 'Couldn’t update the case') {
  try {
    const res = await api('api/cases/' + encodeURIComponent(id) + path, body, method);
    refreshCaseCount();
    if (caseState.open === id && $('page-cases').classList.contains('active')) await showCase(id);
    return res;
  } catch (e) {
    toastError(errTitle, e);
    return null;
  }
}

function draftFor(id) {
  if (!caseState.drafts[id]) caseState.drafts[id] = { mode: 'note', note: '', query: null, earliest: '-24h', reason: '' };
  return caseState.drafts[id];
}

function renderCase() {
  const { case: c, findings: linked = [], missing_findings: missing, entity_context: ectx } = caseState.data;
  document.title = visibleText(c.title) + ' · Investigations · Signalith';
  // Unsaved edits in the details form survive a redraw of the same case,
  // such as the one after adding a note.
  const edits = caseState.detailsEdits ? caseState.detailsEdits(c.id) : null;
  fill($('c-view'), backButton(), caseHead(c, linked),
    el('div', { class: 'c-layout' },
      el('div', { class: 'c-main' }, tasksCard(c), timelineCard(c, linked)),
      el('div', { class: 'c-side' }, detailsCard(c, linked, edits), ticketsCard(c), findingsCard(c, linked, missing || []), entitiesCard(c, ectx || []))));
}

// ----- tasks: the case's checklist -----
function tasksCard(c) {
  const tasks = c.tasks || [];
  const analyst = can('analyst');
  if (!tasks.length && !analyst) return null;
  const done = tasks.filter((t) => t.done).length;
  const path = (t) => '/tasks/' + encodeURIComponent(t.id);
  const row = (t) => {
    const box = el('input', { type: 'checkbox', 'aria-label': (t.done ? 'Reopen: ' : 'Done: ') + t.title });
    box.checked = !!t.done;
    box.disabled = !analyst;
    box.addEventListener('change', async () => {
      box.disabled = true;
      if (!await caseCall(c.id, path(t), { done: box.checked }, 'PATCH', 'Couldn’t update the task')) { box.checked = !box.checked; box.disabled = false; }
    });
    const meta = t.done && t.done_by ? el('span', { class: 'c-task__meta', title: fmtTime(t.done_at) }, `${t.done_by} · ${when(t.done_at)}`)
      : t.owner ? el('span', { class: 'owner c-task__owner', title: 'Owner: ' + t.owner }, caseAvatar(t.owner), el('span', { class: 'owner__name' }, t.owner)) : null;
    const mine = analyst && !t.done && currentUser && t.owner !== currentUser
      ? el('button', { type: 'button', class: 'btn btn--ghost btn--icon btn--sm', title: 'Take this task', 'aria-label': 'Take: ' + t.title,
        onclick: () => caseCall(c.id, path(t), { owner: currentUser }, 'PATCH', 'Couldn’t update the task') }, icon('user-plus')) : null;
    const del = analyst ? el('button', { type: 'button', class: 'btn btn--ghost btn--icon btn--sm', title: 'Remove this task', 'aria-label': 'Remove: ' + t.title,
      onclick: () => caseCall(c.id, path(t), undefined, 'DELETE', 'Couldn’t remove the task') }, icon('x')) : null;
    return el('li', { class: 'c-task' + (t.done ? ' is-done' : '') },
      el('label', { class: 'c-task__check' }, box, el('span', { class: 'c-task__title' }, t.title)), meta, mine, del);
  };
  let add = null;
  if (analyst) {
    const input = el('input', { class: 'input', type: 'text', maxlength: '200', placeholder: 'Add a task', 'aria-label': 'New task', autocomplete: 'off' });
    const addBtn = el('button', { type: 'submit', class: 'btn btn--secondary' }, 'Add');
    const tmpl = el('details', { class: 'menu c-task-tmpl' }, el('summary', { class: 'btn btn--ghost', title: 'Add the tasks of a template' }, icon('list-checks'), el('span', { class: 'hide-sm' }, 'From template')));
    const menu = el('div', { class: 'menu__panel', role: 'menu' });
    tmpl.append(menu);
    tmpl.addEventListener('toggle', async () => {
      if (!tmpl.open || menu.childElementCount) return;
      try {
        const ts = await caseTemplates();
        fill(menu, ...ts.map((t) => el('button', { type: 'button', class: 'menu__item', role: 'menuitem', onclick: async () => {
          tmpl.open = false;
          if (await caseCall(c.id, '/tasks', { template: t.id }, 'POST', 'Couldn’t add the tasks')) toast(`Added ${plural((t.tasks || []).length, 'task')} from ${t.name}.`);
        } }, t.name, el('span', { class: 'menu__hint' }, plural((t.tasks || []).length, 'task')))));
      } catch (e) { fill(menu, el('p', { class: 'menu__row' }, 'Templates could not be loaded.')); }
    });
    add = el('form', { class: 'c-task-add', onsubmit: async (ev) => {
      ev.preventDefault();
      const title = input.value.trim();
      if (!title) { input.focus(); return; }
      const restore = busy(addBtn, 'Adding…');
      if (await caseCall(c.id, '/tasks', { titles: [title] }, 'POST', 'Couldn’t add the task')) {
        const again = $('c-view').querySelector('.c-task-add input');
        if (again) again.focus();
      } else restore();
    } }, input, addBtn, tmpl);
  }
  const pct = tasks.length ? Math.round((done / tasks.length) * 100) : 0;
  return el('section', { class: 'card c-tasks', 'aria-labelledby': 'ct-head' },
    el('div', { class: 'card__head' }, el('div', {},
      el('h3', { class: 'card__title', id: 'ct-head' }, 'Tasks'),
      el('p', { class: 'card__sub' }, tasks.length ? `${done} of ${tasks.length} done` : 'A checklist for this investigation')),
      tasks.length ? el('div', { class: 'c-task-bar', role: 'progressbar', 'aria-valuemin': '0', 'aria-valuemax': '100', 'aria-valuenow': String(pct), 'aria-label': 'Tasks done' },
        el('span', { style: `--w:${pct}%` })) : null),
    tasks.length ? el('ul', { class: 'c-task-list' }, ...tasks.map(row)) : null,
    add ? el('div', { class: 'card__foot' }, add) : null);
}

// ----- header: editable title, status line, resolve or reopen -----
function caseHead(c, linked) {
  // A title made from a finding carries text from events, so characters
  // that hide or reorder text are shown as markers here too.
  const shown = visibleText(c.title);
  const title = el('input', { class: 'c-title', type: 'text', value: shown, 'aria-label': 'Case title', spellcheck: 'false', title: 'Click to rename; Enter saves' });
  let saving = false;
  const saveTitle = async () => {
    const t = title.value.trim();
    if (saving || t === shown || t === c.title) return;
    if (!t) { title.value = shown; return; }
    saving = true;
    if (await caseCall(c.id, '', { title: t }, 'PATCH', 'Couldn’t rename the case')) toast('Case renamed.');
    else title.value = shown;
    saving = false;
  };
  title.addEventListener('keydown', (ev) => {
    if (ev.key === 'Enter') { ev.preventDefault(); title.blur(); }
    if (ev.key === 'Escape') { ev.preventDefault(); title.value = shown; title.blur(); }
  });
  title.addEventListener('blur', saveTitle);

  const action = caseIsOpen(c.status)
    ? el('button', { type: 'button', class: 'btn btn--secondary', onclick: () => resolveCase(c, linked, 'resolved', caseState.detailsValues && caseState.detailsValues()) }, icon('circle-check'), 'Resolve case')
    : el('button', { type: 'button', class: 'btn btn--secondary', onclick: async (ev) => {
      const done = busy(ev.currentTarget);
      if (await caseCall(c.id, '', { status: 'in_progress' }, 'PATCH')) toast('Case reopened.');
      else done();
    } }, icon('rotate-ccw'), 'Reopen case');

  // Viewers read the case; analysts and admins work it.
  const editable = can('analyst');
  return el('div', { class: 'c-head' },
    el('div', { class: 'c-head__main' },
      el('h2', { class: editable ? 'c-head__title' : 'c-head__title c-head__title--ro' }, editable ? title : c.title),
      el('div', { class: 'c-head__meta' }, sevBadge(c.severity), statusBadge(c.status),
        el('span', { class: 'mono c-id' }, c.id)),
      el('p', { class: 'c-head__when' },
        el('span', { title: fullTime(c.created) }, `Opened ${ago(c.created)}` + (c.created_by ? ` by ${c.created_by}` : '')),
        dotsep(),
        el('span', { title: fullTime(c.updated) }, `Updated ${ago(c.updated)}`))),
    el('div', { class: 'c-head__actions' },
      storylineButton({ case: c.id }, { label: 'Storyline', title: 'See this case’s findings with every other finding and risk event about its entities, in ATT&CK order' }),
      editable ? caseExportMenu(c) : null,
      editable ? el('button', { type: 'button', class: 'btn btn--secondary', title: 'Run a response action, such as blocking an IP or disabling an account', onclick: () => caseRespond(c) }, icon('zap'), 'Respond') : null,
      editable ? action : null));
}

// caseExportMenu downloads the case's report: a page to read, print or
// attach, or its JSON, both with the SHA-256 of the report and of each
// piece of evidence (docs/cases.md#exporting-a-report).
function caseExportMenu(c) {
  const url = (format) => `api/cases/${encodeURIComponent(c.id)}/report?format=${format}`;
  const m = el('details', { class: 'menu c-export' },
    el('summary', { class: 'btn btn--secondary', title: 'Download the case as a report with SHA-256 fingerprints' }, icon('download'), el('span', { class: 'hide-sm' }, 'Export')));
  const item = (format, label, hint) => el('a', { class: 'menu__item', role: 'menuitem', href: url(format), download: '', onclick: () => { m.open = false; } },
    label, el('span', { class: 'menu__hint' }, hint));
  m.append(el('div', { class: 'menu__panel', role: 'menu' },
    item('html', 'Report page', 'HTML'),
    item('json', 'Report data', 'JSON')));
  return m;
}

// caseRespond opens the Respond dialog (respond.js) with the case's
// entities as targets; the run lands on the timeline.
function caseRespond(c) {
  openRespond({ caseId: c.id, title: c.title, entities: (c.entities || []).map((e) => ({ field: e.field, value: e.value })), onDone: () => {
    if (caseState.open === c.id && $('page-cases').classList.contains('active')) showCase(c.id);
  } });
}

// ----- details: status, severity, owner, description -----
const DETAIL_EDITS = ['severity', 'owner', 'description', 'resolution'];
function detailsCard(c, linked, edits) {
  if (!can('analyst')) return detailsView(c);
  const open = caseIsOpen(c.status);
  const status = caseSelect('cd-status', Object.entries(STATUS_LABEL), c.status);
  const severity = caseSelect('cd-severity', SEVERITIES.map((s) => [s, SEVERITY_LABEL[s] || s]), c.severity);
  const owner = el('input', { id: 'cd-owner', class: 'input', type: 'text', value: c.owner || '', placeholder: 'Unassigned', autocomplete: 'off' });
  const desc = el('textarea', { id: 'cd-desc', class: 'textarea', rows: '3', placeholder: 'What is this investigation about?' });
  desc.value = c.description || '';
  const resolution = open ? null : el('textarea', { id: 'cd-resolution', class: 'textarea', rows: '3', placeholder: 'What happened and what was done about it' });
  if (resolution) resolution.value = c.resolution || '';

  const values = () => {
    const v = { status: status.value, severity: severity.value, owner: owner.value.trim(), description: desc.value.trim() };
    if (resolution) v.resolution = resolution.value.trim();
    return v;
  };
  caseState.detailsValues = values;
  caseState.detailsEdits = (id) => {
    if (id !== c.id) return null;
    const v = values();
    const out = {};
    for (const k of DETAIL_EDITS) if (k in v && v[k] !== (c[k] || '')) out[k] = v[k];
    return out;
  };
  if (edits) {
    const inputs = { severity, owner, description: desc, resolution };
    for (const [k, v] of Object.entries(edits)) if (inputs[k]) inputs[k].value = v;
  }
  const save = el('button', { type: 'button', class: 'btn btn--secondary', disabled: '' }, 'Save changes');
  const dirty = () => {
    const v = values();
    return v.status !== c.status || v.severity !== c.severity || v.owner !== (c.owner || '') || v.description !== (c.description || '')
      || (resolution && v.resolution !== (c.resolution || ''));
  };
  const sync = () => { save.disabled = !dirty(); };
  sync();
  [owner, desc, resolution].forEach((n) => n && n.addEventListener('input', sync));
  severity.addEventListener('change', sync);
  status.addEventListener('change', async () => {
    sync();
    // Closing an open case goes through the resolve dialog, which also
    // asks what happened and whether to close the findings.
    if (open && !caseIsOpen(status.value)) {
      const done = await resolveCase(c, linked, status.value, values());
      if (!done) { status.value = c.status; sync(); }
    }
  });
  save.addEventListener('click', async () => {
    const done = busy(save, 'Saving…');
    if (await caseCall(c.id, '', values(), 'PATCH', 'Couldn’t save the case')) toast('Case saved.');
    else done();
  });

  const mine = currentUser && c.owner !== currentUser ? el('button', { type: 'button', class: 'btn btn--ghost', onclick: async (ev) => {
    const prev = { owner: c.owner || '', status: c.status };
    const body = Object.assign(values(), { owner: currentUser });
    if (body.status === 'new') body.status = 'in_progress';
    const done = busy(ev.currentTarget);
    if (await caseCall(c.id, '', body, 'PATCH')) {
      toast('Assigned to you.', { label: 'Undo', run: () => caseCall(c.id, '', prev, 'PATCH') });
    } else done();
  } }, icon('user-plus'), 'Assign to me') : null;

  const field = (label, input, extra) => el('div', { class: 'field' }, el('label', { class: 'label', for: input.id }, label), input, extra || null);
  return el('section', { class: 'card c-details', 'aria-labelledby': 'cd-head' },
    el('div', { class: 'card__head' }, el('h3', { class: 'card__title', id: 'cd-head' }, 'Details')),
    el('div', { class: 'card__body c-details__body' },
      el('div', { class: 'form-grid' }, field('Status', status), field('Severity', severity)),
      field('Owner', owner),
      field('Description', desc),
      resolution ? field('Resolution', resolution) : null),
    el('div', { class: 'card__foot c-details__foot' }, save, mine));
}

// detailsView shows the details to viewers, who cannot change them.
function detailsView(c) {
  caseState.detailsValues = null;
  caseState.detailsEdits = null;
  const pairs = [['Status', STATUS_LABEL[c.status] || c.status], ['Severity', SEVERITY_LABEL[c.severity] || c.severity],
    ['Owner', c.owner || 'Unassigned'], c.description ? ['Description', c.description] : null,
    c.resolution ? ['Resolution', c.resolution] : null].filter(Boolean);
  return el('section', { class: 'card c-details', 'aria-labelledby': 'cd-head' },
    el('div', { class: 'card__head' }, el('h3', { class: 'card__title', id: 'cd-head' }, 'Details')),
    el('div', { class: 'card__body c-details__body' },
      el('dl', { class: 'kv' }, ...pairs.flatMap(([k, v]) => [el('dt', {}, k), el('dd', {}, v)]))));
}

// ----- resolving: outcome, what happened, and the case's open findings -----
function resolveCase(c, linked, status, details) {
  const d = modalDialog('c-resolve');
  const openLinked = linked.filter((f) => caseIsOpen(f.status));
  return new Promise((resolve) => {
    let done = false;
    let outcome = status === 'closed' ? 'closed' : 'resolved';
    let alsoText = null;
    const err = formAlert();
    const seg = el('div', { class: 'seg', role: 'group', 'aria-label': 'Outcome' });
    const go = el('button', { type: 'submit', class: 'btn btn--primary' });
    const syncOutcome = () => {
      seg.querySelectorAll('button').forEach((b) => b.setAttribute('aria-pressed', String(b.dataset.v === outcome)));
      go.textContent = outcome === 'closed' ? 'Close case' : 'Resolve case';
      if (alsoText) alsoText.textContent = `Also set its ${plural(openLinked.length, 'open finding')} to ${STATUS_LABEL[outcome]}`;
    };
    for (const [v, label] of [['resolved', 'Resolved'], ['closed', 'Closed']]) {
      seg.append(el('button', { type: 'button', 'data-v': v, onclick: () => { outcome = v; syncOutcome(); } }, label));
    }
    const text = el('textarea', { id: 'cr-text', class: 'textarea', rows: '4', placeholder: 'What happened and what was done about it' });
    text.value = (details && details.resolution) || c.resolution || '';
    const also = el('input', { type: 'checkbox', id: 'cr-also' });
    const disp = caseSelect('cr-disposition', Object.entries(DISPOSITION_LABEL).filter(([v]) => v), 'true_positive', 'Disposition');
    let findingsBox = null;
    if (openLinked.length) {
      also.checked = true;
      alsoText = el('span', {});
      also.addEventListener('change', () => { disp.disabled = !also.checked; });
      findingsBox = el('div', { class: 'field' }, el('label', { class: 'check' }, also, alsoText),
        el('div', { class: 'c-indent' }, el('label', { class: 'label', for: 'cr-disposition' }, 'Disposition'), disp));
    }
    const close = () => d.close();
    const form = el('form', { method: 'dialog' },
      modalHead('c-resolve', 'Resolve case', 'Record the outcome. The case leaves the open list and can be reopened later.', close),
      el('div', { class: 'modal__body' }, err,
        el('div', { class: 'field' }, el('span', { class: 'label', id: 'cr-outcome' }, 'Outcome'), seg),
        el('div', { class: 'field' }, el('label', { class: 'label', for: 'cr-text' }, 'Resolution'), text),
        findingsBox),
      el('div', { class: 'modal__foot' }, el('button', { type: 'button', class: 'btn btn--ghost', onclick: close }, 'Cancel'), go));
    seg.setAttribute('aria-labelledby', 'cr-outcome');
    syncOutcome();
    form.addEventListener('submit', async (ev) => {
      ev.preventDefault();
      err.classList.add('hidden');
      const body = Object.assign({}, details || {}, { status: outcome, resolution: text.value.trim() });
      if (openLinked.length && also.checked) {
        body.close_findings = true;
        body.disposition = disp.value;
      }
      const restore = busy(go, outcome === 'closed' ? 'Closing…' : 'Resolving…');
      let res;
      try {
        res = await api('api/cases/' + encodeURIComponent(c.id), body, 'PATCH');
      } catch (e) {
        restore();
        showAlert(err, 'The case was not changed.', sentence(e.message));
        return;
      }
      done = true;
      d.close();
      refreshCaseCount();
      const failed = Object.keys(res.failed || {}).length;
      toast(res.findings_closed ? `${plural(res.findings_closed, 'finding')} set to ${STATUS_LABEL[outcome]}.` + (failed ? ` ${failed} could not be changed.` : '') : 'It no longer shows in the open list.',
        null, { title: outcome === 'closed' ? 'Case closed' : 'Case resolved' });
      if (caseState.open === c.id) showCase(c.id);
    });
    fill(d, form);
    d.onclose = () => resolve(done);
    d.showModal();
    text.focus();
  });
}

// ----- timeline: the composer, then entries newest first -----
function timelineCard(c, linked) {
  const draft = draftFor(c.id);
  const ents = c.entities || [];
  if (draft.query === null) draft.query = ents.slice(0, 3).map((e) => e.field + '=' + quoteValue(e.value)).join(' OR ');

  // Note composer
  const note = el('textarea', { id: 'cn-text', class: 'textarea', rows: '3', placeholder: 'Add a note: what you checked, what you found, what is next', 'aria-label': 'Note' });
  note.value = draft.note;
  note.addEventListener('input', () => { draft.note = note.value; noteBtn.disabled = !note.value.trim(); });
  const noteBtn = el('button', { type: 'submit', class: 'btn btn--primary' }, 'Add note');
  noteBtn.disabled = !draft.note.trim();
  const noteForm = el('form', { class: 'c-compose__form' }, note,
    el('div', { class: 'c-compose__bar' }, el('span', { class: 'hint hide-sm' }, el('kbd', {}, /Mac|iPhone|iPad/.test(navigator.platform) ? '⌘' : 'Ctrl'), el('kbd', {}, 'Enter'), 'to add'),
      el('span', { class: 'spacer' }), noteBtn));
  note.addEventListener('keydown', (ev) => { if (ev.key === 'Enter' && (ev.ctrlKey || ev.metaKey)) { ev.preventDefault(); noteForm.requestSubmit(); } });
  noteForm.addEventListener('submit', async (ev) => {
    ev.preventDefault();
    if (!note.value.trim()) return;
    const text = note.value;
    const done = busy(noteBtn, 'Adding…');
    draft.note = '';
    if (await caseCall(c.id, '/entries', { kind: 'note', text }, 'POST', 'Couldn’t add the note')) {
      const n = $('cn-text');
      if (n) n.focus();
    } else {
      draft.note = text;
      done();
    }
  });

  // Search composer: runs now and keeps its first 50 rows on the timeline.
  const sq = el('textarea', { id: 'cs-query', class: 'textarea mono c-query-input', rows: '2', spellcheck: 'false', placeholder: 'datamodel=Authentication user=bob | stats count by src', 'aria-label': 'Query' });
  sq.value = draft.query;
  const stime = caseSelect('cs-time', [['-1h', 'Last hour'], ['-24h', 'Last 24 hours'], ['-7d', 'Last 7 days'], ['-30d', 'Last 30 days'], ['0', 'All time']], draft.earliest, 'Time range');
  stime.classList.remove('select--block');
  const reason = el('input', { id: 'cs-reason', class: 'input', type: 'text', placeholder: 'Why you ran it (optional)', 'aria-label': 'Why you ran it', value: draft.reason });
  const searchBtn = el('button', { type: 'submit', class: 'btn btn--primary' }, icon('play'), 'Run and add');
  const searchErr = el('div', { class: 'field-error hidden', role: 'alert' });
  sq.addEventListener('input', () => { draft.query = sq.value; searchBtn.disabled = !sq.value.trim(); });
  stime.addEventListener('change', () => { draft.earliest = stime.value; });
  reason.addEventListener('input', () => { draft.reason = reason.value; });
  searchBtn.disabled = !sq.value.trim();
  const searchForm = el('form', { class: 'c-compose__form' }, sq, searchErr,
    el('div', { class: 'c-compose__bar' }, stime, reason, searchBtn));
  sq.addEventListener('keydown', (ev) => { if (ev.key === 'Enter' && (ev.ctrlKey || ev.metaKey)) { ev.preventDefault(); searchForm.requestSubmit(); } });
  searchForm.addEventListener('submit', async (ev) => {
    ev.preventDefault();
    if (!sq.value.trim()) return;
    searchErr.classList.add('hidden');
    const done = busy(searchBtn, 'Running…');
    try {
      await api('api/cases/' + encodeURIComponent(c.id) + '/entries', { kind: 'search', query: sq.value.trim(), earliest: stime.value, text: reason.value });
    } catch (e) {
      done();
      fill(searchErr, icon('circle-alert'), sentence(e.message));
      searchErr.classList.remove('hidden');
      return;
    }
    draft.reason = '';
    draft.mode = 'note';
    if (caseState.open === c.id) showCase(c.id);
  });

  // File composer: one file at a time, with an optional note.
  const MAX_FILE = 10 * 1024 * 1024;
  const fileIn = el('input', { id: 'cf-file', class: 'input', type: 'file', 'aria-label': 'File' });
  const fileNote = el('input', { id: 'cf-text', class: 'input', type: 'text', maxlength: '2000', placeholder: 'What it is (optional)', 'aria-label': 'What the file is' });
  const fileBtn = el('button', { type: 'submit', class: 'btn btn--primary', disabled: '' }, icon('paperclip'), 'Attach');
  const fileErr = el('div', { class: 'field-error hidden', role: 'alert' });
  const showFileErr = (m) => { fill(fileErr, icon('circle-alert'), sentence(m)); fileErr.classList.remove('hidden'); };
  fileIn.addEventListener('change', () => {
    fileErr.classList.add('hidden');
    const f = fileIn.files[0];
    fileBtn.disabled = !f;
    if (f && f.size > MAX_FILE) { fileBtn.disabled = true; showFileErr(`${f.name} is ${sizeText(f.size)}; a file is at most 10 MB`); }
  });
  const fileForm = el('form', { class: 'c-compose__form' }, fileIn, fileErr,
    el('div', { class: 'c-compose__bar' }, fileNote, el('span', { class: 'hint hide-sm' }, 'Up to 10 MB. Its SHA-256 is kept with it.'), el('span', { class: 'spacer' }), fileBtn));
  fileForm.addEventListener('submit', async (ev) => {
    ev.preventDefault();
    const f = fileIn.files[0];
    if (!f) return;
    fileErr.classList.add('hidden');
    const fd = new FormData();
    fd.append('text', fileNote.value);
    fd.append('file', f, f.name);
    const done = busy(fileBtn, 'Attaching…');
    try {
      const resp = await apiRaw('api/cases/' + encodeURIComponent(c.id) + '/files', { method: 'POST', body: fd });
      const r = await resp.json().catch(() => ({}));
      if (!resp.ok) throw new Error(r.error || resp.statusText);
    } catch (e) {
      done();
      showFileErr(e.message);
      return;
    }
    draft.mode = 'note';
    refreshCaseCount();
    if (caseState.open === c.id) showCase(c.id);
  });

  // Note, Search or File
  const seg = el('div', { class: 'seg seg--sm', role: 'group', 'aria-label': 'Add to the timeline' });
  const setMode = (m, focus) => {
    draft.mode = m;
    seg.querySelectorAll('button').forEach((b) => b.setAttribute('aria-pressed', String(b.dataset.mode === m)));
    noteForm.classList.toggle('hidden', m !== 'note');
    searchForm.classList.toggle('hidden', m !== 'search');
    fileForm.classList.toggle('hidden', m !== 'file');
    if (focus) (m === 'note' ? note : m === 'search' ? sq : fileIn).focus();
  };
  seg.append(
    el('button', { type: 'button', 'data-mode': 'note', onclick: () => setMode('note', true) }, icon('message-square-text'), 'Note'),
    el('button', { type: 'button', 'data-mode': 'search', onclick: () => setMode('search', true) }, icon('search'), 'Search'),
    el('button', { type: 'button', 'data-mode': 'file', onclick: () => setMode('file', true) }, icon('paperclip'), 'File'));
  setMode(draft.mode);

  const entries = c.entries || [];
  const sorted = [
    ...entries.map((e) => ({ t: e.time, node: entryNode(c, e, linked) })),
    ...(c.history || []).filter((h) => h.field !== 'created').map((h) => ({ t: h.time, h, node: historyNode(h) })),
  ].sort((a, b) => new Date(b.t) - new Date(a.t));
  // Three or more field changes in a row fold into one line.
  const items = [];
  for (let i = 0; i < sorted.length;) {
    let j = i;
    while (j < sorted.length && sorted[j].h) j++;
    if (j - i >= 3) items.push(changeRun(sorted.slice(i, j)));
    else sorted.slice(i, Math.max(j, i + 1)).forEach((x) => items.push(x.node));
    i = Math.max(j, i + 1);
  }
  items.push(tlItem({ kind: 'created', icon: 'briefcase', time: c.created, text: [el('b', {}, c.created_by || 'Someone'), ' opened the case'] }));

  return el('section', { class: 'card c-timeline', 'aria-labelledby': 'ct-head' },
    el('div', { class: 'card__head' },
      el('div', {}, el('h3', { class: 'card__title', id: 'ct-head' }, 'Timeline ', el('span', { class: 'count' }, String(entries.length)))),
      can('analyst') ? el('div', { class: 'card__actions' }, seg) : null),
    can('analyst') ? el('div', { class: 'c-compose' }, noteForm, searchForm, fileForm) : null,
    el('ol', { class: 'timeline c-entries' }, ...items));
}

// tlItem draws one timeline row: a dot, what happened, when, and an
// optional body (a note, a query and its rows, an event).
// The body sits on its own row under the text and the time, so it can use
// the full width of the card.
function tlItem({ kind, icon: ic, time, timeTitle, text, body, remove, change }) {
  return el('li', { class: 'c-entry' + (change ? ' c-entry--change' : ''), 'data-kind': kind },
    el('span', { class: 'timeline__dot' }, icon(ic)),
    el('div', { class: 'c-entry__head' }, el('div', { class: 'timeline__text' }, ...text), remove || null),
    el('time', { class: 'timeline__time', datetime: new Date(time).toISOString(), title: timeTitle || fullTime(time) }, when(time)),
    body ? el('div', { class: 'c-entry__body' }, ...[].concat(body)) : null);
}

function removeEntryButton(c, e, what) {
  // Notes, events and searches are evidence: analysts remove only their
  // own, admins anyone's (the server checks too).
  const mine = me && String(e.author || '').toLowerCase() === String(me.username || '').toLowerCase();
  if (!can('admin') && !(can('analyst') && mine)) return null;
  return el('button', { type: 'button', class: 'btn btn--ghost btn--icon btn--sm c-entry__remove', 'aria-label': `Remove this ${what} from the timeline`, title: 'Remove', onclick: async () => {
    if (await caseConfirm({ title: `Remove this ${what}?`, text: 'It comes off the timeline for everyone. The case history keeps a record that it was removed.', confirm: 'Remove' })) {
      if (await caseCall(c.id, '/entries/' + encodeURIComponent(e.id), undefined, 'DELETE', `Couldn’t remove the ${what}`)) toast(`The ${what} was removed.`);
    }
  } }, icon('trash-2'));
}

function entryNode(c, e, linked) {
  const who = el('b', {}, e.author || 'Someone');
  switch (e.kind) {
    case 'note': {
      // A comment taken from a ticket: by jira:<name> or servicenow:<user>.
      const from = /^(jira|servicenow):(.+)$/.exec(e.author || '');
      if (from) {
        const sys = from[1] === 'jira' ? 'Jira' : 'ServiceNow';
        return tlItem({ kind: 'note', icon: 'message-square-text', time: e.time,
          text: [el('b', {}, from[2]), el('span', { class: 'badge badge--outline c-from', title: 'A comment on the case’s ticket in ' + sys }, sys), ' commented on the ticket'],
          body: el('p', { class: 'c-note' }, e.text), remove: removeEntryButton(c, e, 'note') });
      }
      return tlItem({ kind: 'note', icon: 'message-square-text', time: e.time, text: [who, ' added a note'],
        body: el('p', { class: 'c-note' }, e.text), remove: removeEntryButton(c, e, 'note') });
    }
    case 'finding': {
      const f = linked.find((x) => x.id === e.finding_id);
      return tlItem({ kind: 'finding', icon: 'shield-alert', time: e.time, text: [who, ' added a finding'],
        body: el('div', { class: 'c-finding-ref' }, f ? sevBadge(f.urgency || f.severity) : null,
          el('button', { type: 'button', class: 'link-btn c-link', title: 'Open this finding', onclick: () => openFindingFromCase(e.finding_id) }, e.text || e.finding_id)) });
    }
    case 'event':
      return tlItem({ kind: 'event', icon: 'pin', time: e.time, text: [who, ' pinned an event'],
        body: [e.text ? el('p', { class: 'c-note' }, e.text) : null, eventBody(e.event || {}), evidenceLine(e)],
        remove: removeEntryButton(c, e, 'event') });
    case 'search':
      return tlItem({ kind: 'search', icon: 'search', time: e.time, text: [who, ' ran a search'],
        body: [
          e.text ? el('p', { class: 'c-note' }, e.text) : null,
          el('pre', { class: 'c-query' }, e.query),
          el('div', { class: 'c-search-meta' }, el('span', {}, searchSummary(e)),
            el('button', { type: 'button', class: 'link-btn', onclick: () => openSearch(e.query, e.earliest, e.latest) }, 'Run again in Search', icon('arrow-up-right', 'icon--xs'))),
          snapshotTable(e), evidenceLine(e)],
        remove: removeEntryButton(c, e, 'search') });
    case 'file': {
      // Always a download: the server never shows a file in the browser.
      const href = 'api/cases/' + encodeURIComponent(c.id) + '/files/' + encodeURIComponent(e.file_id);
      return tlItem({ kind: 'file', icon: 'paperclip', time: e.time, text: [who, ' attached a file'],
        body: [e.text ? el('p', { class: 'c-note' }, e.text) : null,
          el('div', { class: 'c-file' },
            el('span', { class: 'c-file__icon' }, icon('file-text')),
            el('div', { class: 'c-file__main' },
              el('a', { class: 'c-file__name', href, download: e.file_name, rel: 'noopener' }, e.file_name),
              el('span', { class: 'hint' }, `${sizeText(e.file_size || 0)} · ${(e.file_type || '').split(';')[0]}`)),
            el('a', { class: 'btn btn--ghost btn--sm', href, download: e.file_name, 'aria-label': 'Download ' + e.file_name }, icon('download'), el('span', { class: 'hide-sm' }, 'Download'))),
          // The file's own SHA-256, which whoever has a copy can check;
          // the warning when the entry was changed outside Signalith.
          ((caseState.data && caseState.data.evidence_changed) || []).includes(e.id) ? evidenceLine(e)
            : e.file_sha256 ? el('p', { class: 'c-evidence', title: 'SHA-256 of the file when attached: ' + e.file_sha256 }, icon('fingerprint', 'icon--xs'),
              'SHA-256 ', el('span', { class: 'mono' }, e.file_sha256.slice(0, 16) + '…')) : null].filter(Boolean),
        remove: removeEntryButton(c, e, 'file') });
    }
    case 'notebook':
      // A hunting notebook linked to this case; unlinking happens from the
      // notebook, so the entry has no remove button here.
      return tlItem({ kind: 'notebook', icon: 'notebook-pen', time: e.time, text: [who, ' linked a hunting notebook'],
        body: el('div', { class: 'c-finding-ref' },
          typeof openNotebook === 'function'
            ? el('button', { type: 'button', class: 'link-btn c-link', title: 'Open this notebook', onclick: () => openNotebook(e.notebook_id) }, e.text || e.notebook_id)
            : el('span', {}, e.text || e.notebook_id)) });
    case 'action':
      // A response action run from this case: the record of what was
      // done, so it cannot be removed. Details come from the audit log.
      return tlItem({ kind: 'action', icon: 'zap', time: e.time, text: [who, ' ran a response action ', e.status ? rpStatusBadge(e.status) : null],
        body: [el('p', { class: 'c-note' }, e.text),
          e.run_id ? el('div', { class: 'c-search-meta' }, el('span', { class: 'mono' }, e.run_id),
            el('button', { type: 'button', class: 'link-btn', onclick: () => rpShowRun(e.run_id, { caseId: c.id }) }, 'Details and output', icon('arrow-up-right', 'icon--xs'))) : null] });
    default:
      return tlItem({ kind: e.kind, icon: 'circle-dot', time: e.time, text: [who, ' added ' + e.kind] });
  }
}

const CASE_HISTORY_ICON = { status: 'circle-dot', owner: 'user', severity: 'gauge', title: 'pencil', description: 'pencil', resolution: 'pencil', finding: 'unlink', entity: 'tag', timeline: 'trash-2', ticket: 'ticket', tasks: 'list-checks', task: 'list-checks' };
// evidenceLine shows the hash taken when evidence was added, and warns
// when the evidence no longer matches it.
function evidenceLine(e) {
  if (!e.sha256) return null;
  const changed = ((caseState.data && caseState.data.evidence_changed) || []).includes(e.id);
  if (changed) {
    return el('p', { class: 'c-evidence is-changed', role: 'note' }, icon('triangle-alert', 'icon--xs'),
      'This no longer matches the SHA-256 taken when it was added: it was changed outside Signalith.');
  }
  return el('p', { class: 'c-evidence', title: 'SHA-256 when added: ' + e.sha256 }, icon('fingerprint', 'icon--xs'),
    'SHA-256 ', el('span', { class: 'mono' }, e.sha256.slice(0, 16) + '…'));
}

function historyNode(h) {
  const who = el('b', {}, h.author || 'Someone');
  const label = (field, v) => {
    if (!v) return field === 'owner' ? 'unassigned' : 'empty';
    if (field === 'status') return STATUS_LABEL[v] || v;
    if (field === 'severity') return SEVERITY_LABEL[v] || v;
    return v;
  };
  let text;
  switch (h.field) {
    case 'finding':
      text = h.to === 'removed' ? [who, ' removed finding ', el('span', { class: 'mono' }, h.from)]
        : [who, ' moved finding ', el('span', { class: 'mono' }, h.from), ' ' + String(h.to).replace(/^moved /, '')];
      break;
    case 'entity': text = [who, ' added entity ', el('span', { class: 'mono' }, h.to)]; break;
    case 'timeline': text = [who, ` removed a ${h.from} from the timeline`]; break;
    case 'description': case 'resolution': text = [who, ` edited the ${h.field}`]; break;
    case 'title': text = [who, ' renamed the case to ', el('b', {}, h.to)]; break;
    case 'tasks': text = [who, ` added ${h.to === '1 added' ? 'a task' : String(h.to).replace(/ added$/, ' tasks')}`]; break;
    case 'task': text = h.to === 'done' ? [who, ' finished ', el('b', {}, h.from)] : h.to === 'reopened' ? [who, ' reopened ', el('b', {}, h.from)] : [who, ' removed the task ', el('b', {}, h.from)]; break;
    case 'ticket': text = h.from ? [who, ' replaced the deleted ticket ', el('b', {}, h.from), ' with ', el('b', {}, h.to)] : [who, ' opened ticket ', el('b', {}, h.to)]; break;
    default: text = [who, ` changed ${h.field} from `, el('b', {}, label(h.field, h.from)), ' to ', el('b', {}, label(h.field, h.to))];
  }
  return tlItem({ kind: 'change', icon: CASE_HISTORY_ICON[h.field] || 'history', time: h.time, text, change: true });
}

// changeRun folds consecutive field changes into "5 changes by sam · Show".
function changeRun(run) {
  const who = [...new Set(run.map((x) => x.h.author || 'someone'))];
  const show = el('button', { type: 'button', class: 'link-btn', 'aria-label': `Show ${run.length} changes` }, 'Show');
  const li = tlItem({ kind: 'changes', icon: 'history', time: run[0].t, change: true, timeTitle: `${fullTime(run[run.length - 1].t)} to ${fullTime(run[0].t)}`,
    text: [el('b', {}, `${run.length} changes`), ` by ${who.slice(0, 3).join(', ')}${who.length > 3 ? ' and others' : ''} · `, show] });
  show.addEventListener('click', () => {
    li.replaceWith(...run.map((x) => x.node));
    const first = run[0].node.querySelector('.timeline__text');
    if (first) { first.setAttribute('tabindex', '-1'); first.focus(); }
  });
  return li;
}

function searchSummary(e) {
  const n = (e.rows || []).length;
  const range = { '-1h': 'Last hour', '-24h': 'Last 24 hours', '-7d': 'Last 7 days', '-30d': 'Last 30 days' };
  const bits = [!e.earliest || e.earliest === '0' ? 'All time' : !e.latest && range[e.earliest] ? range[e.earliest] : `From ${e.earliest}${e.latest ? ' to ' + e.latest : ''}`];
  if (e.result_kind === 'events') bits.push(plural(e.matched || 0, 'matching event'));
  else bits.push(plural(n, 'row'));
  if (e.truncated) bits.push(`first ${n} kept`);
  if (e.sampled) bits.push(`sampled: worked out from the newest ${e.sampled.toLocaleString()} events`);
  return bits.join(' · ');
}

function snapshotTable(e) {
  const rows = e.rows || [];
  if (!rows.length) return el('p', { class: 'c-muted' }, 'No results when it ran.');
  let cols = e.columns || [];
  if (e.result_kind === 'events') {
    const pref = ['_time', 'host', 'action', 'user', 'src', 'dest', 'process_name', 'signature'];
    cols = pref.filter((col) => cols.includes(col));
    if (!cols.length) cols = (e.columns || []).filter((col) => col !== '_raw').slice(0, 6);
  }
  const shown = 8;
  const body = (list) => list.map((r) => el('tr', {}, ...cols.map((col) => {
    const v = col === '_time' ? fmtTime(r[col]) : fmtValue(r[col]);
    return el('td', { class: typeof r[col] === 'number' ? 'num' : '', title: v }, v);
  })));
  const tbody = el('tbody', {}, ...body(rows.slice(0, shown)));
  const more = rows.length > shown ? el('button', { type: 'button', class: 'link-btn c-more', onclick: (ev) => { tbody.replaceChildren(...body(rows)); ev.currentTarget.remove(); } }, `Show all ${rows.length} rows`) : null;
  return el('div', { class: 'c-snap' },
    el('div', { class: 'c-snap__wrap' }, el('table', { class: 'table table--compact c-snap__table' },
      el('thead', {}, el('tr', {}, ...cols.map((col) => el('th', { scope: 'col', title: col }, col)))), tbody)),
    more);
}

function eventBody(ev) {
  const keys = Object.keys(ev).filter((k) => k !== '_raw');
  const shown = 8;
  const pairs = (list) => list.flatMap((k) => [el('dt', {}, k), el('dd', { class: 'mono' }, k === '_time' ? fmtTime(ev[k]) : fmtValue(ev[k]))]);
  const dl = el('dl', { class: 'kv c-kv' }, ...pairs(keys.slice(0, shown)));
  const more = keys.length > shown ? el('button', { type: 'button', class: 'link-btn c-more', onclick: (e) => { dl.replaceChildren(...pairs(keys)); e.currentTarget.remove(); } }, `Show all ${keys.length} fields`) : null;
  return el('div', { class: 'c-event' }, dl, more,
    ev._raw ? el('details', { class: 'c-raw' }, el('summary', {}, icon('chevron-right', 'icon--sm'), 'Raw event'), el('pre', {}, ev._raw)) : null);
}

// ----- findings in the case -----
function findingsCard(c, linked, missing) {
  const rows = linked.map((f) => el('li', { class: 'c-finding' },
    el('div', { class: 'c-finding__main' },
      el('button', { type: 'button', class: 'c-finding__title', title: f.title, onclick: () => openFindingFromCase(f.id) }, f.title),
      el('div', { class: 'c-finding__meta' }, sevBadge(f.urgency || f.severity), statusBadge(f.status),
        el('span', { class: 'c-finding__det mono', title: 'Detection ' + f.detection_id }, f.detection_id))),
    !can('analyst') ? null : el('button', { type: 'button', class: 'btn btn--ghost btn--icon btn--sm c-finding__remove', 'aria-label': 'Remove from the case: ' + f.title, title: 'Remove from the case', onclick: async () => {
      if (await caseConfirm({ title: 'Remove this finding from the case?', text: `“${f.title}” stays in the Findings queue with its status.`, confirm: 'Remove finding' })) {
        if (await caseCall(c.id, '/findings/' + encodeURIComponent(f.id), undefined, 'DELETE', 'Couldn’t remove the finding')) toast('Finding removed from the case.');
      }
    } }, icon('unlink'))));
  missing.forEach((id) => rows.push(el('li', { class: 'c-finding c-finding--gone' }, icon('circle-x', 'icon--sm'), el('span', {}, 'Finding ', el('span', { class: 'mono' }, id), ' no longer exists.'))));
  return el('section', { class: 'card c-findings', 'aria-labelledby': 'cf-head' },
    el('div', { class: 'card__head' }, el('h3', { class: 'card__title', id: 'cf-head' }, 'Findings ', el('span', { class: 'count' }, String(linked.length)))),
    rows.length ? el('ul', { class: 'c-list-plain', role: 'list' }, ...rows)
      : el('div', { class: 'empty empty--compact' },
        el('span', { class: 'empty__icon' }, icon('shield-alert')),
        el('div', { class: 'empty__title' }, 'No findings yet'),
        el('p', { class: 'empty__text' }, can('analyst') ? 'On the Findings page, select findings and choose Add to case.' : 'Findings added to this case appear here.'),
        el('div', { class: 'empty__actions' }, el('a', { class: 'btn btn--secondary btn--sm', href: '#findings', 'data-page': 'findings' }, 'Open Findings'))));
}

// ----- tickets in Jira or ServiceNow -----
// The card draws at once from what was last loaded for the case, then
// loads how each ticket is kept in step. It stays hidden on a server
// without ticketing, unless the case already has a ticket.
const TICKET_SYSTEM = { jira: 'Jira', servicenow: 'ServiceNow' };
const ticketCache = new Map(); // case ID -> api/cases/{id}/tickets
function ticketsCard(c) {
  const body = el('div', {});
  const count = el('span', { class: 'count' });
  const card = el('section', { class: 'card c-tickets', 'aria-labelledby': 'ct-head' },
    el('div', { class: 'card__head' }, el('h3', { class: 'card__title', id: 'ct-head' }, 'Tickets ', count)), body);
  const draw = (d) => {
    const list = d ? d.tickets : (c.tickets || []).map((t) => ({ ...t, state: 'linked' }));
    card.hidden = !list.length && !(d && d.available && d.connections.length);
    count.textContent = String(list.length);
    const rows = list.map((t) => ticketRow(c, t, d));
    const taken = new Set(list.filter((t) => t.state !== 'failed' && t.state !== 'gone').map((t) => t.connection));
    const free = d && d.available && can('analyst') ? d.connections.filter((x) => !taken.has(x.id)) : [];
    let open = null;
    if (free.length) {
      const pick = free.length > 1 ? caseSelect('ct-conn', free.map((x) => [x.id, x.label]), free[0].id, 'Connection') : null;
      const btn = el('button', { type: 'button', class: 'btn btn--secondary btn--sm' }, icon('ticket'), free.length > 1 ? 'Open ticket' : `Open ticket in ${free[0].label}`);
      btn.addEventListener('click', () => openTicket(c, pick ? pick.value : free[0].id, btn));
      open = el('div', { class: 'c-tickets__open' }, pick, btn);
    }
    fill(body,
      rows.length ? el('ul', { class: 'c-list-plain', role: 'list' }, ...rows)
        : el('div', { class: 'empty empty--compact' }, el('div', { class: 'empty__title' }, 'No ticket yet'),
          el('p', { class: 'empty__text' }, can('analyst') ? 'Open one in Jira or ServiceNow; it stays in step with this case.' : 'Tickets opened for this case appear here.')),
      open,
      d && d.links_error ? el('p', { class: 'c-tickets__note' }, d.links_error) : null,
      d && d.available && d.connections.length && !d.public_url_set && can('admin') && free.length
        ? el('p', { class: 'c-tickets__note' }, 'New tickets won’t link back here until server.public_url is set on the Settings page.') : null);
  };
  draw(ticketCache.get(c.id));
  api('api/cases/' + encodeURIComponent(c.id) + '/tickets').then((d) => {
    ticketCache.set(c.id, d);
    if (card.isConnected) draw(d);
  }).catch(() => { /* the case still lists its tickets */ });
  return card;
}

function ticketRow(c, t, d) {
  const sys = TICKET_SYSTEM[t.system] || t.system;
  const key = t.key && /^https?:\/\//i.test(t.url || '')
    ? el('a', { class: 'c-ticket__key', href: t.url, target: '_blank', rel: 'noopener noreferrer', title: `Open ${t.key} in ${sys}` }, t.key, el('span', { class: 'sr-only' }, ' (opens in a new tab)'), icon('arrow-up-right'))
    : el('span', { class: 'c-ticket__key' }, t.key || 'New ticket');
  const meta = [];
  let err = t.error || '';
  let retry = null;
  switch (t.state) {
    case 'pending': case 'creating':
      meta.push(t.state === 'pending' && d && d.runs_on ? `Being opened by ${d.runs_on}` : 'Being opened…');
      break;
    case 'failed':
      meta.push('Couldn’t be opened');
      if (can('analyst')) retry = 'Try again';
      break;
    case 'gone':
      meta.push(`Deleted in ${sys}`);
      err = '';
      if (can('analyst')) retry = 'Open a new one';
      break;
    default:
      if (t.remote_status) meta.push(t.remote_status);
      if (t.synced_at) meta.push(`synced ${ago(t.synced_at)}`);
  }
  if (t.auto) meta.push('opened by itself');
  else if (t.created_by && t.state === 'linked') meta.push(`by ${t.created_by}`);
  const btn = retry ? el('button', { type: 'button', class: 'link-btn' }, retry) : null;
  if (btn) btn.addEventListener('click', () => openTicket(c, t.connection, btn));
  return el('li', { class: 'c-ticket', 'data-state': t.state },
    el('div', { class: 'c-ticket__head' }, key, el('span', { class: 'c-ticket__sys' }, t.connection_name ? `${sys} · ${t.connection_name}` : sys)),
    meta.length ? el('div', { class: 'c-ticket__meta' }, meta.join(' · ')) : null,
    err ? el('p', { class: 'c-ticket__err' }, icon(t.state === 'failed' ? 'circle-alert' : 'triangle-alert'), el('span', {}, err)) : null,
    btn);
}

async function openTicket(c, connection, btn) {
  const restore = busy(btn, 'Opening…');
  let res;
  try {
    res = await api('api/cases/' + encodeURIComponent(c.id) + '/tickets', { connection });
  } catch (e) {
    restore();
    toastError('Couldn’t open the ticket', e);
    ticketCache.delete(c.id);
    if (caseState.open === c.id) showCase(c.id);
    return;
  }
  restore();
  const t = res.ticket || {};
  const sys = TICKET_SYSTEM[t.system] || t.system;
  toast(res.queued ? `Asked for a ticket in ${sys}. The server that talks to ${sys} opens it within a minute.` : `Opened ${t.key} in ${sys}. It stays in step with this case.`);
  ticketCache.delete(c.id);
  if (caseState.open === c.id && $('page-cases').classList.contains('active')) await showCase(c.id);
}

// ----- entities: users, hosts and IPs the case is about -----
function entitiesCard(c, ectx) {
  const ents = c.entities || [];
  const list = ents.map((e, i) => {
    const kind = caseEntityKind(e.field, e.value);
    const ctx = ectx[i];
    const bits = [e.field];
    if (ctx) {
      if (ctx.name && ctx.name !== e.value) bits.push(ctx.name);
      if (ctx.priority) bits.push(ctx.priority.charAt(0).toUpperCase() + ctx.priority.slice(1) + ' priority');
      if (ctx.owner) bits.push((ctx.kind === 'identity' ? 'manager ' : 'owner ') + ctx.owner);
      if ((ctx.category || []).length) bits.push(ctx.category.join(', '));
      if (ctx.bunit) bits.push(ctx.bunit);
    }
    const q = e.field + '=' + quoteValue(e.value);
    return el('li', {}, el('button', { type: 'button', class: 'entity c-entity', title: `Search the last 7 days for ${q}`, onclick: () => openSearch(q, '-7d') },
      el('span', { class: 'entity__icon' }, icon(CASE_KIND_ICON[kind] || 'tag')),
      el('span', { class: 'entity__main' }, el('span', { class: 'entity__name' }, e.value), el('span', { class: 'entity__desc', title: bits.join(' · ') }, bits.join(' · '))),
      ctx && ctx.watchlist ? el('span', { class: 'badge badge--warning' }, 'Watchlist') : null));
  });

  // Adding one by hand
  const fieldIn = el('input', { id: 'ce-field', class: 'input', type: 'text', placeholder: 'Field, e.g. user', list: 'ce-fields', autocomplete: 'off', 'aria-label': 'Field' });
  const valueIn = el('input', { id: 'ce-value', class: 'input', type: 'text', placeholder: 'Value', autocomplete: 'off', 'aria-label': 'Value' });
  const addBtn = el('button', { type: 'submit', class: 'btn btn--secondary btn--sm' }, 'Add');
  const form = el('form', { class: 'c-entity-form hidden' },
    el('datalist', { id: 'ce-fields' }, ...CASE_ENTITY_FIELDS.map((f) => el('option', { value: f }))),
    fieldIn, valueIn,
    el('div', { class: 'c-entity-form__bar' }, el('button', { type: 'button', class: 'btn btn--ghost btn--sm', onclick: () => toggle(false) }, 'Cancel'), addBtn));
  const toggleBtn = el('button', { type: 'button', class: 'btn btn--ghost btn--sm', 'aria-expanded': 'false', onclick: () => toggle(form.classList.contains('hidden')) }, icon('plus'), 'Add');
  const toggle = (show) => {
    form.classList.toggle('hidden', !show);
    toggleBtn.setAttribute('aria-expanded', String(show));
    if (show) fieldIn.focus(); else toggleBtn.focus();
  };
  form.addEventListener('submit', async (ev) => {
    ev.preventDefault();
    const f = fieldIn.value.trim(), v = valueIn.value.trim();
    if (!f) { fieldIn.setAttribute('aria-invalid', 'true'); fieldIn.focus(); return; }
    if (!v) { valueIn.setAttribute('aria-invalid', 'true'); valueIn.focus(); return; }
    const done = busy(addBtn);
    if (await caseCall(c.id, '/entities', { field: f, value: v }, 'POST', 'Couldn’t add the entity')) toast(`Added ${f}=${v}.`);
    else done();
  });
  [fieldIn, valueIn].forEach((n) => n.addEventListener('input', () => n.removeAttribute('aria-invalid')));

  return el('section', { class: 'card c-entities', 'aria-labelledby': 'ce-head' },
    el('div', { class: 'card__head' }, el('h3', { class: 'card__title', id: 'ce-head' }, 'Entities ', el('span', { class: 'count' }, String(ents.length))),
      can('analyst') ? el('div', { class: 'card__actions' }, toggleBtn) : null),
    el('div', { class: 'card__body c-entities__body' }, can('analyst') ? form : null,
      list.length ? el('ul', { class: 'c-list-plain c-entity-list', role: 'list' }, ...list)
        : el('p', { class: 'c-muted' }, 'Users, hosts and IPs from findings and pinned events appear here.')));
}

function openFindingFromCase(id) {
  showPage('findings');
  if (typeof showFinding === 'function') showFinding(id);
}

// ---------- picking a case ----------
// pickCase asks which case to use and returns its ID, creating a new case
// if the analyst chooses that. It resolves to null when cancelled.
function pickCase({ title = '', heading = 'Add to case', only = '' } = {}) {
  const dlg = $('case-picker');
  const newOnly = only === 'new';
  return new Promise((resolve) => {
    let result = null;
    let choice = newOnly ? 'new' : '';
    const err = formAlert();
    const list = el('div', { class: 'cp-list', role: 'radiogroup', 'aria-label': 'Open cases', 'aria-busy': 'true' },
      ...[0, 1].map(() => el('div', { class: 'cp-option cp-option--loading' }, el('span', { class: 'skeleton', style: 'width:60%' }))));
    const newTitle = el('input', { id: 'cp-new-title', class: 'input', type: 'text', value: visibleText(title), placeholder: 'What is this investigation about?', autocomplete: 'off' });
    const titleErr = el('div', { class: 'field-error hidden', id: 'cp-title-err' }, icon('circle-alert'), 'Give the new case a title.');
    const newSev = caseSelect('cp-sev', SEVERITIES.map((s) => [s, SEVERITY_LABEL[s] || s]), 'medium');
    // A template sets the severity and adds its tasks to the new case.
    const newTmpl = caseSelect('cp-template', [['', 'None']], '');
    const tmplHint = el('p', { class: 'hint', id: 'cp-template-hint' });
    newTmpl.setAttribute('aria-describedby', 'cp-template-hint');
    caseTemplates().then((ts) => {
      newTmpl.append(...ts.map((t) => el('option', { value: t.id }, t.name)));
    }).catch(() => {});
    newTmpl.addEventListener('change', async () => {
      const t = (await caseTemplates().catch(() => [])).find((x) => x.id === newTmpl.value);
      if (t && t.severity) newSev.value = t.severity;
      tmplHint.textContent = t ? `Adds ${plural((t.tasks || []).length, 'task', 'tasks')}${t.description ? ': ' + t.description : '.'}` : '';
    });
    const newFields = el('div', { class: 'cp-new' + (newOnly ? '' : ' cp-new--nested') },
      el('div', { class: 'field' }, el('label', { class: 'label', for: 'cp-new-title' }, 'Title'), newTitle, titleErr),
      el('div', { class: 'cp-row' },
        el('div', { class: 'field cp-template' }, el('label', { class: 'label', for: 'cp-template' }, 'Template'), newTmpl),
        el('div', { class: 'field cp-sev' }, el('label', { class: 'label', for: 'cp-sev' }, 'Severity'), newSev)),
      tmplHint);
    const newRadio = el('input', { type: 'radio', name: 'cp-case', value: 'new' });
    const go = el('button', { type: 'submit', class: 'btn btn--primary' }, newOnly ? 'Create case' : 'Add to case');
    const setChoice = (v) => {
      choice = v;
      newFields.classList.toggle('hidden', !newOnly && v !== 'new');
      err.classList.add('hidden');
    };
    newRadio.addEventListener('change', () => setChoice('new'));
    newTitle.addEventListener('input', () => { titleErr.classList.add('hidden'); newTitle.removeAttribute('aria-invalid'); });
    const newOption = newOnly ? null : el('label', { class: 'cp-option cp-option--new' }, newRadio,
      el('span', { class: 'cp-option__icon' }, icon('plus')), el('span', { class: 'cp-option__title' }, 'New case'));
    const cancel = () => dlg.close();
    const form = el('form', { method: 'dialog' },
      modalHead('cp', heading, newOnly ? 'Name the investigation. Add findings, notes and searches to it afterwards.' : 'Choose an open case or start a new one.', cancel),
      el('div', { class: 'modal__body' }, err, newOnly ? null : list, newOption, newFields),
      el('div', { class: 'modal__foot' }, el('button', { type: 'button', class: 'btn btn--ghost', onclick: cancel }, 'Cancel'), go));
    setChoice(choice);
    form.addEventListener('submit', async (ev) => {
      ev.preventDefault();
      err.classList.add('hidden');
      if (choice !== 'new') {
        if (!choice) { showAlert(err, 'Choose a case or start a new one.'); return; }
        result = choice;
        dlg.close();
        return;
      }
      if (!newTitle.value.trim()) {
        titleErr.classList.remove('hidden');
        newTitle.setAttribute('aria-invalid', 'true');
        newTitle.setAttribute('aria-describedby', 'cp-title-err');
        newTitle.focus();
        return;
      }
      const done = busy(go, 'Creating…');
      try {
        const body = { title: newTitle.value.trim(), severity: newSev.value, owner: currentUser };
        if (newTmpl.value) body.template = newTmpl.value;
        const res = await api('api/cases', body);
        refreshCaseCount();
        result = res.case.id;
        dlg.close();
      } catch (e) {
        done();
        showAlert(err, 'The case was not created.', sentence(e.message));
      }
    });
    fill(dlg, form);
    dlg.onclick = (ev) => { if (ev.target === dlg) dlg.close(); };
    dlg.onclose = () => resolve(result);
    dlg.showModal();
    if (newOnly) { newTitle.focus(); newTitle.select(); return; }
    go.focus();
    api('api/cases?' + new URLSearchParams({ status: CASE_OPEN.join(','), limit: '50' })).then((res) => {
      list.setAttribute('aria-busy', 'false');
      if (!res.cases.length) {
        fill(list, el('p', { class: 'cp-none' }, 'There are no open cases yet.'));
        newRadio.checked = true;
        setChoice('new');
        newTitle.focus();
        return;
      }
      fill(list, ...res.cases.map((c) => {
        const r = el('input', { type: 'radio', name: 'cp-case', value: c.id });
        r.addEventListener('change', () => setChoice(c.id));
        if (caseState.open === c.id) { r.checked = true; setChoice(c.id); }
        return el('label', { class: 'cp-option' }, r, sevBadge(c.severity),
          el('span', { class: 'cp-option__title', title: c.title }, c.title),
          el('span', { class: 'owner cp-option__owner', title: c.owner || 'Unassigned' }, caseAvatar(c.owner), el('span', { class: 'owner__name' }, c.owner || 'Unassigned')));
      }));
    }).catch((e) => {
      list.setAttribute('aria-busy', 'false');
      fill(list, el('p', { class: 'cp-none' }, 'Open cases could not be loaded. ' + sentence(e.message)));
    });
  });
}

// ---------- case templates (admins) ----------
// The built-in templates are shown for reference; admins add, change
// and remove their own, saved together.
async function editCaseTemplates() {
  const dlg = $('case-templates');
  let all;
  try { all = await caseTemplates(true); } catch (e) { toastError('Couldn’t load the templates', e); return; }
  const builtin = all.filter((t) => t.builtin);
  const mine = all.filter((t) => !t.builtin).map((t) => ({ ...t, tasks: [...(t.tasks || [])] }));
  const err = formAlert();
  const list = el('div', { class: 'ctm-list' });
  const slug = (name) => name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 40) || 'template';
  const draw = () => {
    fill(list,
      el('p', { class: 'label' }, 'Your templates'),
      mine.length ? null : el('p', { class: 'hint' }, 'None yet. Add one for the incidents your team sees, such as an OT safety event.'),
      ...mine.map((t, i) => {
        const name = el('input', { class: 'input', type: 'text', maxlength: '80', value: t.name, 'aria-label': 'Template name', placeholder: 'Name' });
        name.addEventListener('input', () => { t.name = name.value; });
        const sev = caseSelect('ctm-sev-' + i, [['', 'Any'], ...SEVERITIES.map((v) => [v, SEVERITY_LABEL[v] || v])], t.severity || '', 'Severity');
        sev.addEventListener('change', () => { t.severity = sev.value; });
        const desc = el('textarea', { class: 'textarea', rows: '2', maxlength: '4000', placeholder: 'Description the new case starts with', 'aria-label': 'Description' });
        desc.value = t.description || '';
        desc.addEventListener('input', () => { t.description = desc.value; });
        const tasks = el('textarea', { class: 'textarea', rows: '4', placeholder: 'One task per line', 'aria-label': 'Tasks, one per line' });
        tasks.value = t.tasks.join('\n');
        tasks.addEventListener('input', () => { t.tasks = tasks.value.split('\n').map((x) => x.trim()).filter(Boolean); });
        const del = el('button', { type: 'button', class: 'btn btn--ghost btn--icon', title: 'Remove this template', 'aria-label': 'Remove ' + (t.name || 'template'),
          onclick: () => { mine.splice(i, 1); draw(); } }, icon('trash-2'));
        return el('div', { class: 'ctm-item' },
          el('div', { class: 'ctm-item__row' }, name, sev, del), desc, tasks);
      }),
      el('button', { type: 'button', class: 'btn btn--secondary ctm-add', onclick: () => {
        mine.push({ id: '', name: '', severity: '', description: '', tasks: [] });
        draw();
        const inputs = list.querySelectorAll('.ctm-item input[type=text]');
        if (inputs.length) inputs[inputs.length - 1].focus();
      } }, icon('plus'), 'Add template'),
      el('details', { class: 'ctm-builtin' }, el('summary', {}, `Built-in templates (${builtin.length})`),
        el('ul', {}, ...builtin.map((t) => el('li', {}, el('b', {}, t.name), ` · ${plural((t.tasks || []).length, 'task')}`)))));
  };
  const save = el('button', { type: 'submit', class: 'btn btn--primary' }, 'Save templates');
  const close = () => dlg.close();
  const form = el('form', { method: 'dialog', onsubmit: async (ev) => {
    ev.preventDefault();
    err.classList.add('hidden');
    const used = new Set(builtin.map((t) => t.id));
    const body = mine.map((t) => {
      let id = t.id || slug(t.name);
      for (let n = 2; !t.id && used.has(id); n++) id = slug(t.name).slice(0, 36) + '-' + n;
      used.add(id);
      return { id, name: t.name.trim(), severity: t.severity || '', description: (t.description || '').trim(), tasks: t.tasks };
    });
    const done = busy(save, 'Saving…');
    try {
      await api('api/case-templates', { templates: body }, 'PUT');
      caseTemplates(true).catch(() => {});
      dlg.close();
      toast('Templates saved.');
    } catch (e) {
      done();
      showAlert(err, 'The templates were not saved.', sentence(e.message));
    }
  } },
    modalHead('ctm', 'Case templates', 'A new case can start from a template: its severity, description and tasks.', close),
    el('div', { class: 'modal__body' }, err, list),
    el('div', { class: 'modal__foot' }, el('button', { type: 'button', class: 'btn btn--ghost', onclick: close }, 'Cancel'), save));
  draw();
  fill(dlg, form);
  dlg.showModal();
}
$('c-templates').addEventListener('click', editCaseTemplates);

// ----- checking reports, and the keys that sign them (docs/cases.md#checking-a-report) -----
const KEY_STATUS = { current: ['In use', 'badge--success'], retired: ['Retired', ''], revoked: ['Revoked', 'badge--danger'] };

async function openReportCheck() {
  const dlg = $('case-reports');
  const close = () => dlg.close();
  const result = el('div', { class: 'crk-result', 'aria-live': 'polite' });
  const file = el('input', { class: 'input', type: 'file', accept: '.html,.htm,.json,text/html,application/json', id: 'crk-file', 'aria-label': 'Report file' });
  const check = el('button', { type: 'submit', class: 'btn btn--primary', disabled: '' }, icon('shield-check'), 'Check');
  file.addEventListener('change', () => { check.disabled = !file.files.length; fill(result); });
  const keys = el('div', { class: 'crk-keys' });
  // Revoking a key is the provider's: every tenant shares it.
  const admin = can('admin') && !inTenant();

  const showResult = (r) => {
    const ok = r.verified;
    const lines = [];
    if (r.case) lines.push(el('p', {}, el('b', {}, r.title || r.case), ` · ${r.case}`));
    if (r.generated) lines.push(el('p', { class: 'hint' }, `Made ${fullTime(r.generated)} by ${r.generated_by}`));
    // Only a verified report is "signed with" its key; otherwise the key
    // is only what the file claims.
    if (ok && r.key_id) lines.push(el('p', { class: 'hint' }, `Signed with report key ${r.key_id}` + (r.key_status ? ` (${(KEY_STATUS[r.key_status] || [r.key_status])[0].toLowerCase()})` : '')));
    else if (r.key_id) lines.push(el('p', { class: 'hint' }, `Claims report key ${r.key_id}`));
    if (!ok && r.error) lines.push(el('p', {}, sentence(String(r.error).replace(/^the report did not verify: /, ''))));
    const head = ok ? 'Verified: this server signed it, and nothing changed since.'
      : r.status === 'revoked' ? 'Signed with a revoked key: this report cannot be trusted.' : 'This report did not verify.';
    fill(result, el('div', { class: 'alert', 'data-tone': ok ? 'success' : 'danger', role: 'status' },
      icon(ok ? 'shield-check' : 'shield-x'), el('div', {}, el('b', {}, head), ...lines)));
  };

  const drawKeys = (ks) => {
    if (!ks.length) { fill(keys, el('p', { class: 'hint' }, 'No report has been signed yet. The first export makes the key.')); return; }
    fill(keys, el('ul', { class: 'crk-list' }, ...ks.map((k) => {
      const [label, tone] = KEY_STATUS[k.status || (k.revoked ? 'revoked' : k.retired ? 'retired' : 'current')] || ['', ''];
      const st = k.revoked ? 'revoked' : k.retired ? 'retired' : 'current';
      const revoke = admin && st !== 'revoked' ? el('button', { type: 'button', class: 'btn btn--ghost btn--sm', onclick: () => revokeKey(k) }, 'Revoke…') : null;
      return el('li', { class: 'crk-key' },
        el('div', { class: 'crk-key__main' },
          el('span', { class: 'mono' }, k.id),
          el('span', { class: 'badge ' + (KEY_STATUS[st] || ['', ''])[1] }, (KEY_STATUS[st] || [st])[0]),
          el('span', { class: 'hint' }, `${k.source === 'cluster' ? 'Cluster key' : 'Master key'} · since ${shortDate(k.first_used)}`)),
        k.revoked ? el('p', { class: 'hint' }, `Revoked ${shortDate(k.revoked)}${k.revoked_by ? ' by ' + k.revoked_by : ''}${k.reason ? ': ' + k.reason : ''}`) : null,
        revoke);
    })));
  };
  const loadKeys = async () => {
    try { drawKeys((await api('api/cases/reports/keys')).keys || []); } catch (e) { fill(keys, el('p', { class: 'hint' }, 'The report keys could not be loaded.')); }
  };
  const revokeKey = async (k) => {
    const reason = el('textarea', { class: 'textarea', rows: '2', maxlength: '500', placeholder: 'Why, such as "the master key was in a leaked backup"', 'aria-label': 'Reason' });
    const d = modalDialog('crk-revoke');
    const ok = el('button', { type: 'button', class: 'btn btn--danger' }, 'Revoke key');
    ok.onclick = async () => {
      const done = busy(ok, 'Revoking…');
      try {
        drawKeys((await api(`api/cases/reports/keys/${encodeURIComponent(k.id)}/revoke`, { reason: reason.value }, 'POST')).keys || []);
        d.close();
        toast('Key revoked. Reports it signed no longer verify.');
      } catch (e) { done(); toastError('Couldn’t revoke the key', e); }
    };
    fill(d, modalHead('crk-revoke', `Revoke report key ${k.id}?`, 'Do this when the cluster key or master key it comes from may have leaked: someone with it could sign a report. Reports it signed no longer verify, and it signs no more; reports are exported unsigned until you change that key, so new reports get a new one.', () => d.close()),
      el('div', { class: 'modal__body' }, reason),
      el('div', { class: 'modal__foot' }, el('button', { type: 'button', class: 'btn btn--ghost', onclick: () => d.close() }, 'Cancel'), ok));
    d.showModal();
    reason.focus();
  };

  const form = el('form', { method: 'dialog', onsubmit: async (ev) => {
    ev.preventDefault();
    const f = file.files[0];
    if (!f) return;
    if (f.size > 16 * 1024 * 1024) { showResult({ verified: false, error: 'the file is larger than 16 MiB, more than any case report' }); return; }
    const done = busy(check, 'Checking…');
    try {
      const resp = await apiRaw('api/cases/reports/verify', { method: 'POST', body: f, headers: { 'Content-Type': 'application/octet-stream' } });
      const r = await resp.json().catch(() => ({}));
      if (!resp.ok) throw new Error(r.error || resp.statusText);
      showResult(r);
    } catch (e) { showResult({ verified: false, error: e.message }); }
    done();
  } },
    modalHead('crk', 'Check a report', 'Check a case report someone sent you: that this server signed it, and that nothing in it changed since.', close),
    el('div', { class: 'modal__body crk-body' },
      el('div', { class: 'crk-pick' }, el('label', { class: 'label', for: 'crk-file' }, 'Report file (.html or .json)'), el('div', { class: 'crk-pick__row' }, file, check)),
      result,
      el('div', { class: 'crk-keys-head' },
        el('p', { class: 'label' }, 'Report keys'),
        el('a', { class: 'btn btn--ghost btn--sm', href: 'api/cases/reports/keys', download: 'signalith-report-keys.json', title: 'For checking reports on another computer: signalith report verify -keys signalith-report-keys.json report.html' }, icon('download'), 'Download')),
      keys),
    el('div', { class: 'modal__foot' }, el('button', { type: 'button', class: 'btn btn--ghost', onclick: close }, 'Close')));
  fill(dlg, form);
  dlg.showModal();
  loadKeys();
}
$('c-reports').addEventListener('click', openReportCheck);

// caseTemplates loads the case templates once a page view.
let caseTemplatesP = null;
function caseTemplates(fresh) {
  if (!caseTemplatesP || fresh) caseTemplatesP = api('api/case-templates').then((r) => r.templates || []).catch((e) => { caseTemplatesP = null; throw e; });
  return caseTemplatesP;
}

// ---------- adding from other pages ----------
async function addFindingsToCase(ids, title) {
  const id = await pickCase({ title });
  if (!id) return;
  try {
    const res = await api('api/cases/' + encodeURIComponent(id) + '/findings', { ids });
    const failed = Object.keys(res.failed || {}).length;
    refreshCaseCount();
    toast(`${plural(ids.length - failed, 'finding')} added to ${res.case.title}.` + (failed ? ` ${failed} could not be added.` : ''),
      { label: 'Open case', run: () => openCase(id) });
    if ($('page-findings').classList.contains('active') && typeof loadFindings === 'function') {
      if (typeof selected !== 'undefined') selected.clear();
      loadFindings();
      if (typeof openFinding !== 'undefined' && openFinding && typeof showFinding === 'function') showFinding(openFinding);
    }
  } catch (e) { toastError('Couldn’t add to the case', e); }
}

if ($('f-bulk-case')) {
  $('f-bulk-case').addEventListener('click', () => {
    const ids = [...selected];
    if (!ids.length) return;
    const first = findingsList.find((f) => f.id === ids[0]);
    addFindingsToCase(ids, first ? first.title : '');
  });
}

if ($('search-to-case')) {
  $('search-to-case').addEventListener('click', async () => {
    const query = $('query').value.trim();
    if (!query) { showQueryError(new Error('Write or ask for a query first.')); return; }
    const id = await pickCase({ title: lastAsk && lastAsk.query.trim() === query ? lastAsk.question : '' });
    if (!id) return;
    const earliest = timeEarliest();
    try {
      const res = await api('api/cases/' + encodeURIComponent(id) + '/entries', { kind: 'search', query, earliest });
      toast(`Search saved to ${res.case.title}.`, { label: 'Open case', run: () => openCase(id) });
    } catch (e) { toastError('Couldn’t save the search to the case', e); }
  });
}

// pinEventToCase is called from the search results cell menu.
async function pinEventToCase(row) {
  const id = await pickCase();
  if (!id) return;
  try {
    const res = await api('api/cases/' + encodeURIComponent(id) + '/entries', { kind: 'event', event: row });
    toast(`Event pinned to ${res.case.title}.`, { label: 'Open case', run: () => openCase(id) });
  } catch (e) { toastError('Couldn’t pin the event', e); }
}
