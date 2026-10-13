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
      el('div', { class: 'c-main' }, timelineCard(c, linked)),
      el('div', { class: 'c-side' }, detailsCard(c, linked, edits), findingsCard(c, linked, missing || []), entitiesCard(c, ectx || []))));
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
    editable ? el('div', { class: 'c-head__actions' },
      el('button', { type: 'button', class: 'btn btn--secondary', title: 'Run a response action, such as blocking an IP or disabling an account', onclick: () => caseRespond(c) }, icon('zap'), 'Respond'),
      action) : null);
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

  // Note or Search
  const seg = el('div', { class: 'seg seg--sm', role: 'group', 'aria-label': 'Add to the timeline' });
  const setMode = (m, focus) => {
    draft.mode = m;
    seg.querySelectorAll('button').forEach((b) => b.setAttribute('aria-pressed', String(b.dataset.mode === m)));
    noteForm.classList.toggle('hidden', m !== 'note');
    searchForm.classList.toggle('hidden', m !== 'search');
    if (focus) (m === 'note' ? note : sq).focus();
  };
  seg.append(
    el('button', { type: 'button', 'data-mode': 'note', onclick: () => setMode('note', true) }, icon('message-square-text'), 'Note'),
    el('button', { type: 'button', 'data-mode': 'search', onclick: () => setMode('search', true) }, icon('search'), 'Search'));
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
    can('analyst') ? el('div', { class: 'c-compose' }, noteForm, searchForm) : null,
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
    case 'note':
      return tlItem({ kind: 'note', icon: 'message-square-text', time: e.time, text: [who, ' added a note'],
        body: el('p', { class: 'c-note' }, e.text), remove: removeEntryButton(c, e, 'note') });
    case 'finding': {
      const f = linked.find((x) => x.id === e.finding_id);
      return tlItem({ kind: 'finding', icon: 'shield-alert', time: e.time, text: [who, ' added a finding'],
        body: el('div', { class: 'c-finding-ref' }, f ? sevBadge(f.urgency || f.severity) : null,
          el('button', { type: 'button', class: 'link-btn c-link', title: 'Open this finding', onclick: () => openFindingFromCase(e.finding_id) }, e.text || e.finding_id)) });
    }
    case 'event':
      return tlItem({ kind: 'event', icon: 'pin', time: e.time, text: [who, ' pinned an event'],
        body: [e.text ? el('p', { class: 'c-note' }, e.text) : null, eventBody(e.event || {})],
        remove: removeEntryButton(c, e, 'event') });
    case 'search':
      return tlItem({ kind: 'search', icon: 'search', time: e.time, text: [who, ' ran a search'],
        body: [
          e.text ? el('p', { class: 'c-note' }, e.text) : null,
          el('pre', { class: 'c-query' }, e.query),
          el('div', { class: 'c-search-meta' }, el('span', {}, searchSummary(e)),
            el('button', { type: 'button', class: 'link-btn', onclick: () => openSearch(e.query, e.earliest, e.latest) }, 'Run again in Search', icon('arrow-up-right', 'icon--xs'))),
          snapshotTable(e)],
        remove: removeEntryButton(c, e, 'search') });
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

const CASE_HISTORY_ICON = { status: 'circle-dot', owner: 'user', severity: 'gauge', title: 'pencil', description: 'pencil', resolution: 'pencil', finding: 'unlink', entity: 'tag', timeline: 'trash-2' };
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
    const newFields = el('div', { class: 'cp-new' + (newOnly ? '' : ' cp-new--nested') },
      el('div', { class: 'field' }, el('label', { class: 'label', for: 'cp-new-title' }, 'Title'), newTitle, titleErr),
      el('div', { class: 'field cp-sev' }, el('label', { class: 'label', for: 'cp-sev' }, 'Severity'), newSev));
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
        const res = await api('api/cases', { title: newTitle.value.trim(), severity: newSev.value, owner: currentUser });
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
