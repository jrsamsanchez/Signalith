// Hunting notebooks: saved hunts made of notes and searches in order, each
// search with what it found when it last ran, tagged with the ATT&CK
// techniques the hunt looks for. Starter hunts are built in.
'use strict';

const nbState = {
  list: [], starters: [], loaded: false, error: '', req: 0, // the list view
  open: null, nb: null, version: '', can: {}, // the open notebook
  editing: null, // id of the cell being edited, or 'new-markdown' / 'new-search'
  drafts: {}, // unsaved cell edits, by cell id
  running: new Set(), // ids of cells running now
  range: '', // the time range this page runs with, when it is not the notebook's
};
const NB_RANGES = [['24h', 'Last 24 hours'], ['7d', 'Last 7 days'], ['30d', 'Last 30 days'], ['90d', 'Last 90 days']];
const NB_SHARING = {
  private: { icon: 'lock', label: 'Private', text: 'Only you and admins can see it.' },
  read: { icon: 'eye', label: 'Team can view', text: 'Everyone who can sign in can see and run it. Only you and admins change it.' },
  edit: { icon: 'users', label: 'Team can edit', text: 'Every analyst can change it. Only you and admins share or delete it.' },
};

pageHooks.push((name) => {
  if (name !== 'notebooks') return;
  if (hashNotebook) { nbState.open = hashNotebook; hashNotebook = null; }
  if (nbState.open) showNotebook(nbState.open);
  else loadNotebooks();
});

const nbIsMine = (n) => !!me && String(n.owner || '').toLowerCase() === String(me.username || '').toLowerCase();
const nbPath = (id) => 'api/notebooks/' + encodeURIComponent(id);
function nbSetHash(id) {
  try { history.replaceState(null, '', id ? '#notebooks?id=' + encodeURIComponent(id) : '#notebooks'); } catch (_) { /* sandboxed */ }
}

// ---------- markdown ----------
// mdRender turns a note's Markdown into DOM nodes. Only text nodes are
// made from the note, never HTML, so a note cannot run script or inject
// markup; links work only for http(s), mailto and pages of this app.
// Supported: headings, paragraphs, lists, quotes, code, bold, italic,
// inline code, links and rules.
function mdRender(text) {
  const out = [];
  const lines = String(text || '').replace(/\r\n?/g, '\n').split('\n');
  let para = [];
  const flush = () => {
    if (para.length) out.push(el('p', {}, ...mdInline(para.join(' '))));
    para = [];
  };
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const fence = line.match(/^\s*(`{3,}|~{3,})/);
    if (fence) {
      flush();
      const body = [];
      for (i++; i < lines.length && !lines[i].trim().startsWith(fence[1]); i++) body.push(lines[i]);
      out.push(el('pre', { class: 'nb-md__code' }, el('code', {}, body.join('\n'))));
      continue;
    }
    const h = line.match(/^(#{1,6})\s+(.*?)\s*#*\s*$/);
    if (h) {
      flush();
      out.push(el('h' + Math.min(6, h[1].length + 2), { class: 'nb-md__h' + Math.min(3, h[1].length) }, ...mdInline(h[2])));
      continue;
    }
    if (/^\s*([-*_])(\s*\1){2,}\s*$/.test(line)) { flush(); out.push(el('hr', {})); continue; }
    if (/^\s*>/.test(line)) {
      flush();
      const body = [];
      for (; i < lines.length && /^\s*>/.test(lines[i]); i++) body.push(lines[i].replace(/^\s*>\s?/, ''));
      i--;
      out.push(el('blockquote', {}, ...mdRender(body.join('\n'))));
      continue;
    }
    const li = line.match(/^\s*([-*+]|\d{1,9}[.)])\s+(.*)$/);
    if (li) {
      flush();
      const ordered = /\d/.test(li[1]);
      const items = [];
      for (; i < lines.length; i++) {
        const m = lines[i].match(/^\s*([-*+]|\d{1,9}[.)])\s+(.*)$/);
        if (m && /\d/.test(m[1]) === ordered) items.push(m[2]);
        else if (m || !lines[i].trim()) break;
        else if (items.length && /^\s+\S/.test(lines[i])) items[items.length - 1] += ' ' + lines[i].trim();
        else break;
      }
      i--;
      const attrs = {};
      if (ordered) { const start = parseInt(li[1], 10); if (start > 1) attrs.start = String(start); }
      out.push(el(ordered ? 'ol' : 'ul', attrs, ...items.map((t) => el('li', {}, ...mdInline(t)))));
      continue;
    }
    if (!line.trim()) { flush(); continue; }
    para.push(line.trim());
  }
  flush();
  return out;
}

// mdSafeHref returns a link target a note may use, or null.
function mdSafeHref(url) {
  const u = String(url || '').trim();
  if (/^#[a-z][\w?=&.-]*$/i.test(u)) return u;
  if (/^mailto:[^\s<>"]+$/i.test(u)) return u;
  try {
    const p = new URL(u);
    if (p.protocol === 'https:' || p.protocol === 'http:') return p.href;
  } catch (_) { /* not a URL */ }
  return null;
}

// mdInline renders one line's code spans, links, bold and italic.
function mdInline(text) {
  const out = [];
  const re = /`([^`]+)`|\[([^\]]+)\]\(([^)\s]+)\)|\*\*(.+?)\*\*|__(.+?)__|\*([^*\s][^*]*?)\*|(?<![\w])_([^_\s][^_]*?)_(?![\w])/;
  let rest = text;
  while (rest) {
    const m = rest.match(re);
    if (!m) { out.push(rest); break; }
    if (m.index) out.push(rest.slice(0, m.index));
    if (m[1] != null) out.push(el('code', {}, m[1]));
    else if (m[2] != null) {
      const href = mdSafeHref(m[3]);
      if (!href) out.push(m[0]);
      else if (href.startsWith('#')) out.push(el('a', { href }, ...mdInline(m[2])));
      else out.push(el('a', { href, target: '_blank', rel: 'noopener noreferrer nofollow' }, ...mdInline(m[2])));
    } else if (m[4] != null || m[5] != null) out.push(el('strong', {}, ...mdInline(m[4] ?? m[5])));
    else out.push(el('em', {}, ...mdInline(m[6] ?? m[7])));
    rest = rest.slice(m.index + m[0].length);
  }
  return out;
}

// ---------- the list ----------
async function loadNotebooks() {
  nbState.open = null;
  nbState.nb = null;
  $('nb-view').classList.add('hidden');
  $('nb-list-view').classList.remove('hidden');
  document.title = 'Hunting notebooks · Signalith';
  const p = new URLSearchParams();
  const q = $('nb-q').value.trim();
  if (q) p.set('q', q);
  const req = ++nbState.req;
  if (!nbState.loaded) renderNotebooksLoading();
  let res;
  try {
    res = await api('api/notebooks' + (p.toString() ? '?' + p : ''));
  } catch (e) {
    if (req !== nbState.req) return;
    fill($('nb-list'), el('div', { class: 'card' }, el('div', { class: 'empty', 'data-tone': 'danger' },
      el('span', { class: 'empty__icon' }, icon('circle-alert')),
      el('div', { class: 'empty__title' }, 'Couldn’t load notebooks'),
      el('p', { class: 'empty__text' }, sentence(e.message)),
      el('div', { class: 'empty__actions' }, el('button', { type: 'button', class: 'btn btn--secondary btn--sm', onclick: () => loadNotebooks() }, icon('refresh-cw'), 'Try again')))));
    return;
  }
  if (req !== nbState.req) return;
  nbState.list = res.notebooks || [];
  nbState.starters = res.starters || [];
  nbState.error = res.error || '';
  nbState.loaded = true;
  renderNotebooks();
}

function renderNotebooksLoading() {
  const sk = (w, h) => el('span', { class: 'skeleton', style: `width:${w}` + (h ? `;height:${h}` : '') });
  fill($('nb-list'), el('div', { class: 'nb-grid', 'aria-busy': 'true' }, ...[0, 1, 2].map(() => el('div', { class: 'card nb-card nb-card--sk' },
    sk('40%'), sk('80%', '18px'), sk('100%'), sk('60%')))));
}

function nbSection(title, sub, cards, empty) {
  return el('section', { class: 'nb-section' },
    el('div', { class: 'nb-section__head' }, el('h3', { class: 'nb-section__title' }, title, cards.length ? el('span', { class: 'count' }, String(cards.length)) : null),
      sub ? el('p', { class: 'nb-section__sub' }, sub) : null),
    cards.length ? el('div', { class: 'nb-grid' }, ...cards) : empty);
}

function renderNotebooks() {
  const q = $('nb-q').value.trim();
  const mine = nbState.list.filter(nbIsMine);
  const shared = nbState.list.filter((n) => !nbIsMine(n));
  const parts = [];
  if (nbState.error) {
    parts.push(el('div', { class: 'alert', 'data-tone': 'warning', role: 'status' }, icon('triangle-alert'),
      el('div', {}, el('b', {}, 'Notebooks can’t be saved on this server. '), sentence(nbState.error) + ' The starter hunts still run.')));
  }
  const emptyMine = el('div', { class: 'card nb-empty' }, el('div', { class: 'empty empty--compact' },
    el('span', { class: 'empty__icon' }, icon('notebook-pen')),
    el('div', { class: 'empty__title' }, q ? 'None of your notebooks match' : 'No notebooks yet'),
    el('p', { class: 'empty__text' }, q ? 'Try other words, or clear the search.'
      : can('analyst') ? 'Open a starter hunt below and make a copy, or start a blank notebook.' : 'Notebooks analysts share with the team appear here.'),
    !q && can('analyst') ? el('div', { class: 'empty__actions' }, el('button', { type: 'button', class: 'btn btn--secondary btn--sm', onclick: newNotebook }, icon('plus'), 'New notebook')) : null));
  if (can('analyst')) parts.push(nbSection('Your notebooks', null, mine.map(nbCard), emptyMine));
  if (shared.length || !can('analyst')) {
    parts.push(nbSection(can('analyst') ? 'Shared with the team' : 'Shared notebooks', null, shared.map(nbCard),
      can('analyst') ? null : emptyMine));
  }
  parts.push(nbSection('Starter hunts', 'Built-in hunts to run against your data. Make a copy to change one and keep its results.',
    nbState.starters.map(nbCard), el('p', { class: 'nb-section__none' }, 'No starter hunt matches.')));
  fill($('nb-list'), ...parts);
}

function nbSharingBadge(n) {
  if (n.starter) return el('span', { class: 'badge badge--accent nb-badge' }, icon('sparkles', 'icon--xs'), 'Starter');
  const s = NB_SHARING[n.sharing] || NB_SHARING.private;
  return el('span', { class: 'badge nb-badge', 'data-sharing': n.sharing, title: s.text }, icon(s.icon, 'icon--xs'), s.label);
}

function nbCard(n) {
  const open = () => openNotebook(n.id);
  const techs = n.techniques || [];
  const meta = [plural(n.searches || 0, 'search', 'searches')];
  if (n.last_run) meta.push('ran ' + ago(n.last_run));
  if (!n.starter && n.owner && !nbIsMine(n)) meta.push(n.owner);
  return el('article', {
    class: 'card nb-card', tabindex: '0', role: 'link', 'data-id': n.id, 'aria-label': n.title,
    onclick: open, onkeydown: (ev) => { if (ev.key === 'Enter' || ev.key === ' ') { ev.preventDefault(); open(); } },
  },
  el('div', { class: 'nb-card__top' }, el('span', { class: 'nb-card__icon', 'aria-hidden': 'true' }, icon(n.starter ? 'target' : 'notebook-pen')), nbSharingBadge(n)),
  el('h4', { class: 'nb-card__title' }, n.title),
  n.description ? el('p', { class: 'nb-card__desc' }, n.description) : null,
  techs.length ? el('div', { class: 'nb-card__techs' }, ...techs.slice(0, 3).map((t) => el('code', { class: 'nb-tech' }, t)),
    techs.length > 3 ? el('span', { class: 'nb-more' }, '+' + (techs.length - 3)) : null) : null,
  el('div', { class: 'nb-card__meta' }, meta.join(' · ')));
}

let nbQTimer = null;
$('nb-q').addEventListener('input', () => { clearTimeout(nbQTimer); nbQTimer = setTimeout(() => loadNotebooks(), 250); });
$('nb-q').addEventListener('keydown', (e) => {
  if (e.key === 'Escape' && $('nb-q').value) { e.preventDefault(); $('nb-q').value = ''; loadNotebooks(); }
});
$('nb-new').addEventListener('click', () => newNotebook());

async function newNotebook() {
  const title = await nbAsk({ title: 'New notebook', label: 'Name', placeholder: 'What are you hunting for?', confirm: 'Create notebook' });
  if (!title) return;
  try {
    const res = await api('api/notebooks', { title, cells: [{ kind: 'markdown', text: '## Hypothesis\nWhat you expect to find, and why.' }] });
    openNotebook(res.notebook.id, { editFirst: true });
  } catch (e) { toastError('Couldn’t create the notebook', e); }
}

// nbAsk asks for one line of text in a small dialog; it resolves to the
// trimmed text, or '' when cancelled.
function nbAsk({ title, label, placeholder = '', value = '', confirm, desc }) {
  const d = modalDialog('nb-ask');
  return new Promise((resolve) => {
    let answer = '';
    const input = el('input', { id: 'nb-ask-input', class: 'input', type: 'text', value, placeholder, autocomplete: 'off', maxlength: '200' });
    const err = el('div', { class: 'field-error hidden', id: 'nb-ask-err' }, icon('circle-alert'), 'This can’t be empty.');
    const form = el('form', { method: 'dialog' },
      modalHead('nb-ask', title, desc, () => d.close()),
      el('div', { class: 'modal__body' }, el('div', { class: 'field' }, el('label', { class: 'label', for: 'nb-ask-input' }, label), input, err)),
      el('div', { class: 'modal__foot' }, el('button', { type: 'button', class: 'btn btn--ghost', onclick: () => d.close() }, 'Cancel'),
        el('button', { type: 'submit', class: 'btn btn--primary' }, confirm)));
    form.addEventListener('submit', (ev) => {
      ev.preventDefault();
      if (!input.value.trim()) { err.classList.remove('hidden'); input.setAttribute('aria-invalid', 'true'); input.focus(); return; }
      answer = input.value.trim();
      d.close();
    });
    fill(d, form);
    d.onclose = () => resolve(answer);
    d.showModal();
    input.focus();
    input.select();
  });
}

// ---------- one notebook ----------
function openNotebook(id, opts = {}) {
  nbState.open = id;
  nbState.openOpts = opts;
  if ($('page-notebooks').classList.contains('active')) showNotebook(id);
  else showPage('notebooks');
}

async function showNotebook(id) {
  const box = $('nb-view');
  const first = !nbState.nb || nbState.nb.id !== id;
  $('nb-list-view').classList.add('hidden');
  box.classList.remove('hidden');
  if (first) {
    nbState.editing = null;
    nbState.drafts = {};
    nbState.range = '';
    window.scrollTo(0, 0);
    renderNotebookLoading();
  }
  let res;
  try {
    res = await api(nbPath(id));
  } catch (e) {
    if (nbState.open !== id) return;
    fill(box, nbBack(), el('div', { class: 'card' }, el('div', { class: 'empty', 'data-tone': 'danger' },
      el('span', { class: 'empty__icon' }, icon('circle-alert')),
      el('div', { class: 'empty__title' }, e.status === 404 ? 'This notebook isn’t there' : 'Couldn’t open this notebook'),
      el('p', { class: 'empty__text' }, e.status === 404 ? 'It may have been deleted, or it is private to someone else.' : sentence(e.message)),
      el('div', { class: 'empty__actions' }, el('button', { type: 'button', class: 'btn btn--secondary btn--sm', onclick: nbBackToList }, icon('arrow-left'), 'All notebooks')))));
    return;
  }
  if (nbState.open !== id) return;
  nbTake(res);
  nbSetHash(id);
  const opts = nbState.openOpts || {};
  nbState.openOpts = null;
  if (opts.editFirst && res.can.edit && res.notebook.cells.length) nbState.editing = res.notebook.cells[0].id;
  renderNotebook();
  if (first) $('nb-view').querySelector('.nb-title')?.focus({ preventScroll: true });
}

// nbTake keeps a notebook as the server answered with it.
function nbTake(res) {
  nbState.nb = res.notebook;
  nbState.version = res.version || '';
  nbState.can = res.can || {};
}

function nbBackToList() {
  nbState.open = null;
  nbState.nb = null;
  nbSetHash('');
  loadNotebooks();
}
const nbBack = () => el('button', { type: 'button', class: 'btn btn--ghost btn--sm nb-back', onclick: nbBackToList }, icon('arrow-left'), 'Notebooks');

function renderNotebookLoading() {
  const sk = (w, h) => el('span', { class: 'skeleton', style: `width:${w}` + (h ? `;height:${h}` : '') });
  fill($('nb-view'), nbBack(), el('div', { class: 'nb-head', 'aria-busy': 'true' }, sk('320px', '22px'), sk('220px')),
    ...[0, 1].map(() => el('div', { class: 'card nb-cell' }, el('div', { class: 'card__body nb-sk' }, sk('30%'), sk('100%', '64px'), sk('70%')))));
}

// nbSave sends the notebook as change leaves a copy of it. Saves wait for
// each other, and each names the version it was made on, so a change
// someone else made meanwhile is never overwritten.
let nbSaving = Promise.resolve();
function nbSave(change, errTitle = 'Couldn’t save the notebook') {
  const run = async () => {
    const n = structuredClone(nbState.nb);
    change(n);
    const body = {
      title: n.title, description: n.description || '', techniques: n.techniques || [], time_range: n.time_range, sharing: n.sharing,
      cells: n.cells.map((c) => ({ id: c.id, kind: c.kind, title: c.title || '', text: c.text || '', query: c.query || '' })),
    };
    try {
      const res = await api(nbPath(n.id), body, 'PUT', nbState.version ? { 'If-Match': '"' + nbState.version + '"' } : undefined);
      if (nbState.open === n.id) nbTake(res);
      return res;
    } catch (e) {
      if (e.status === 412) {
        toast(sentence(e.message), { label: 'Reload', run: () => { nbState.drafts = {}; nbState.editing = null; showNotebook(n.id); } }, { tone: 'danger', title: 'Not saved' });
      } else toastError(errTitle, e);
      return null;
    }
  };
  nbSaving = nbSaving.then(run, run);
  return nbSaving;
}

function renderNotebook() {
  const n = nbState.nb;
  if (!n) return;
  document.title = visibleText(n.title) + ' · Notebooks · Signalith';
  const cells = el('ol', { class: 'nb-cells', 'aria-label': 'Cells' }, ...n.cells.map((c, i) => el('li', { class: 'nb-cells__item', 'data-id': c.id }, nbCell(c, i))));
  fill($('nb-view'), nbBack(), nbHead(n),
    n.starter ? el('div', { class: 'callout nb-starter' }, icon('sparkles'), el('div', {},
      el('b', {}, 'A starter hunt. '), 'Run it to see what it finds in your data. ',
      can('analyst') ? 'Make a copy to change it, keep its results and share it.' : 'Results shown here are not saved.'),
    can('analyst') ? el('button', { type: 'button', class: 'btn btn--secondary btn--sm', onclick: () => nbCopy(n) }, icon('copy'), 'Make a copy') : null) : null,
    n.cells.length ? cells : el('div', { class: 'card' }, el('div', { class: 'empty empty--compact' },
      el('span', { class: 'empty__icon' }, icon('notebook-pen')),
      el('div', { class: 'empty__title' }, 'This notebook is empty'),
      el('p', { class: 'empty__text' }, nbState.can.edit ? 'Add a note with your hypothesis, then the searches that test it.' : 'Nothing has been added yet.'))),
    nbState.can.edit ? nbAddBar() : null);
  // A cell being edited keeps its focus.
  if (nbState.editing) {
    const f = $('nb-view').querySelector('.nb-cell--editing textarea, .nb-cell--editing input');
    if (f && !$('nb-view').contains(document.activeElement)) f.focus({ preventScroll: true });
  }
}

function nbHead(n) {
  const rights = nbState.can;
  const rangeSel = el('select', { class: 'select select--sm nb-range', 'aria-label': 'Time range' },
    ...NB_RANGES.concat(NB_RANGES.some(([v]) => v === n.time_range) ? [] : [[n.time_range, 'Last ' + n.time_range]])
      .map(([v, label]) => el('option', { value: v, selected: (nbState.range || n.time_range) === v }, label)));
  rangeSel.addEventListener('change', async () => {
    if (rights.edit) {
      nbState.range = '';
      if (await nbSave((m) => { m.time_range = rangeSel.value; })) renderNotebook();
    } else nbState.range = rangeSel.value === n.time_range ? '' : rangeSel.value;
  });
  const runAll = el('button', { type: 'button', class: 'btn btn--primary', onclick: () => nbRun() }, icon('play'), 'Run all');
  if (!n.cells.some((c) => c.kind === 'search') || nbState.running.size) runAll.disabled = true;
  const sharingBtn = rights.manage ? el('button', { type: 'button', class: 'btn btn--secondary', onclick: () => nbShare(n) }, icon(NB_SHARING[n.sharing].icon), 'Share') : null;
  const caseBtn = rights.edit && typeof pickCase === 'function' ? el('button', { type: 'button', class: 'btn btn--secondary', title: 'Link this hunt to an investigation and add its results to the timeline', onclick: () => nbLinkCase(n) }, icon('briefcase'), el('span', { class: 'hide-sm' }, 'Link to case')) : null;
  const more = dxMenu('More actions', [
    rights.edit ? { icon: 'pencil', label: 'Edit details', run: () => nbEditDetails(n) } : null,
    rights.copy ? { icon: 'copy', label: 'Make a copy', run: () => nbCopy(n) } : null,
    { icon: 'link', label: 'Copy link', run: () => nbCopyLink(n) },
    { icon: 'download', label: 'Download as Markdown', href: nbPath(n.id) + '/markdown', download: true },
    rights.manage ? 'sep' : null,
    rights.manage ? { icon: 'trash-2', label: 'Delete notebook', danger: true, run: () => nbDelete(n) } : null,
  ]);
  more.classList.add('nb-more-menu');

  const meta = [nbSharingBadge(n)];
  if (!n.starter) {
    meta.push(el('span', { class: 'nb-head__who' }, el('span', { title: 'Owner' }, icon('user', 'icon--xs'), n.owner)));
    meta.push(el('span', { class: 'nb-head__when', title: fullTime(n.updated) }, `Updated ${ago(n.updated)}` + (n.updated_by ? ` by ${n.updated_by}` : '')));
  }
  if ((n.cases || []).length) {
    meta.push(el('span', { class: 'nb-head__cases' }, icon('briefcase', 'icon--xs'),
      ...n.cases.flatMap((id, i) => [i ? ', ' : '', el('button', { type: 'button', class: 'link-btn', title: 'Open this investigation', onclick: () => openCase(id) }, id)]),
      rights.edit ? el('button', { type: 'button', class: 'link-btn nb-unlink', onclick: () => nbUnlinkCase(n) }, 'Unlink') : null));
  }
  const techs = n.techniques || [];
  return el('header', { class: 'nb-head' },
    el('div', { class: 'nb-head__main' },
      el('h2', { class: 'nb-title', tabindex: '-1' }, n.title),
      n.description ? el('p', { class: 'nb-head__desc' }, n.description) : null,
      el('div', { class: 'nb-head__meta' }, ...meta),
      techs.length || rights.edit ? el('div', { class: 'nb-head__techs' }, ...nbTechLinks(techs),
        rights.edit ? el('button', { type: 'button', class: 'btn btn--ghost btn--sm nb-tech-add', onclick: () => nbEditDetails(n, true) }, icon(techs.length ? 'pencil' : 'plus'), techs.length ? 'Techniques' : 'Add ATT&CK techniques') : null) : null),
    el('div', { class: 'nb-head__actions' }, rangeSel, sharingBtn, caseBtn, more, runAll));
}

// nbTechLinks shows each technique with its name, without the tactic chips
// techRow adds, which crowd a notebook's header.
function nbTechLinks(ids) {
  const row = el('span', { class: 'nb-head__techlist' });
  const draw = () => fill(row, ...ids.map(techLink));
  draw();
  if (ids.length && !attackIndex) loadAttackIndex().then(draw);
  return ids.length ? [row] : [];
}

function nbAddBar() {
  const add = (kind) => {
    nbState.editing = 'new-' + kind;
    nbState.drafts['new-' + kind] = kind === 'search' ? { title: '', query: '' } : { text: '' };
    renderNotebook();
    $('nb-view').querySelector('.nb-cell--editing')?.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
  };
  const editingNew = nbState.editing && nbState.editing.startsWith('new-');
  return el('div', { class: 'nb-add' },
    editingNew ? el('div', { class: 'nb-cells__item' }, nbEditor(null, nbState.editing.slice(4))) : null,
    el('div', { class: 'nb-add__bar' },
      el('button', { type: 'button', class: 'btn btn--secondary btn--sm', onclick: () => add('markdown') }, icon('message-square-text'), 'Add note'),
      el('button', { type: 'button', class: 'btn btn--secondary btn--sm', onclick: () => add('search') }, icon('search'), 'Add search')));
}

// ---------- cells ----------
function nbCell(c, i) {
  if (nbState.editing === c.id) return nbEditor(c, c.kind);
  const n = nbState.nb;
  const rights = nbState.can;
  const count = n.cells.length;
  const move = (d) => nbSave((m) => { const [x] = m.cells.splice(i, 1); m.cells.splice(i + d, 0, x); }).then((r) => r && renderNotebook());
  const editItems = rights.edit ? ['sep',
    { icon: 'pencil', label: 'Edit', run: () => nbEdit(c) },
    i > 0 ? { icon: 'arrow-up', label: 'Move up', run: () => move(-1) } : null,
    i < count - 1 ? { icon: 'arrow-down', label: 'Move down', run: () => move(1) } : null,
    'sep',
    { icon: 'trash-2', label: c.kind === 'search' ? 'Delete search' : 'Delete note', danger: true, run: () => nbRemoveCell(c) }] : [];
  if (c.kind === 'markdown') {
    const items = editItems.filter((x) => x && x !== 'sep' || x === 'sep').slice(1);
    const body = el('div', { class: 'nb-md' }, ...mdRender(c.text));
    if (rights.edit) body.addEventListener('dblclick', () => nbEdit(c));
    return el('div', { class: 'nb-cell nb-cell--note' }, body,
      items.length ? el('div', { class: 'nb-cell__corner' }, dxMenu('Note actions', items)) : null);
  }
  const running = nbState.running.has(c.id);
  const menu = dxMenu('Search actions', [
    { icon: 'search', label: 'Open in Search', run: () => openSearch(c.query, c.result && c.result.earliest ? c.result.earliest : '-' + (nbState.range || n.time_range)) },
    can('admin') ? { icon: 'crosshair', label: 'Turn into detection', run: () => nbToDetection(c) } : null,
    ...editItems,
  ]);
  const runBtn = el('button', { type: 'button', class: 'btn btn--secondary btn--sm', disabled: running || nbState.running.size > 0, onclick: () => nbRun(c.id) },
    icon(running ? 'refresh-cw' : 'play', running ? 'spin' : ''), running ? 'Running…' : c.result ? 'Run again' : 'Run');
  const q = el('pre', { class: 'nb-query', 'aria-label': 'Query' });
  renderQuery(q, c.query);
  if (rights.edit) q.addEventListener('dblclick', () => nbEdit(c));
  const searchNo = n.cells.slice(0, i + 1).filter((x) => x.kind === 'search').length;
  return el('div', { class: 'nb-cell nb-cell--search card' + (running ? ' is-running' : '') },
    el('div', { class: 'nb-cell__head' },
      el('span', { class: 'nb-cell__no', 'aria-hidden': 'true' }, String(searchNo)),
      el('h3', { class: 'nb-cell__title' }, c.title || 'Search ' + searchNo),
      el('div', { class: 'nb-cell__actions' }, runBtn, menu)),
    q,
    nbResult(c, running));
}

function nbResultMeta(r) {
  const bits = [];
  bits.push(el('span', { title: fullTime(r.ran_at) }, `Ran ${ago(r.ran_at)}` + (r.ran_by ? ` by ${r.ran_by}` : '')));
  const range = r.earliest ? r.earliest.replace(/^-/, '') : '';
  if (range) bits.push(el('span', {}, 'last ' + range));
  if (!r.error) {
    const rows = (r.rows || []).length;
    bits.push(el('span', {}, r.kind === 'events' ? plural(r.matched || rows, 'matching event') : plural(rows, 'row')));
    if (r.truncated) bits.push(el('span', {}, `first ${rows} kept`));
  }
  return el('div', { class: 'nb-result__meta' }, ...bits.flatMap((b, k) => (k ? [el('span', { class: 'dotsep', 'aria-hidden': 'true' }), b] : [b])));
}

function nbResult(c, running) {
  const r = c.result;
  if (running) {
    return el('div', { class: 'nb-result', 'aria-busy': 'true' }, ...[0, 1, 2].map(() => el('span', { class: 'skeleton', style: 'width:100%;height:14px' })));
  }
  if (!r) {
    return el('div', { class: 'nb-result nb-result--none' }, icon('circle-dashed', 'icon--sm'),
      el('span', {}, nbState.can.edit || nbState.nb.starter || !can('analyst') ? 'Not run yet. Run it to see what it finds.' : 'Not run yet.'));
  }
  if (r.error) {
    return el('div', { class: 'nb-result' }, nbResultMeta(r),
      el('div', { class: 'alert', 'data-tone': 'danger', role: 'status' }, icon('circle-alert'), el('div', {}, sentence(r.error))));
  }
  const rows = r.rows || [];
  if (!rows.length) {
    return el('div', { class: 'nb-result' }, nbResultMeta(r),
      el('div', { class: 'nb-result__empty' }, icon('circle-check', 'icon--sm'), 'Nothing found. That is a result too: note it and move on.'));
  }
  const body = el('div', { class: 'nb-result__body' });
  if (r.kind === 'timechart' && typeof drawTimeChart === 'function') {
    const chart = el('div', { class: 'nb-chart' });
    body.append(chart);
    requestAnimationFrame(() => drawTimeChart(chart, { rows, columns: r.columns }, { height: 180, label: c.title, legend: true }));
  } else body.append(nbTable(r));
  return el('div', { class: 'nb-result' }, nbResultMeta(r), body);
}

const NB_EVENT_COLS = ['_time', 'host', 'dest', 'user', 'src', 'action', 'process_name', 'process', 'signature', 'query'];
function nbTable(r) {
  const rows = r.rows || [];
  let cols = r.columns && r.columns.length ? r.columns : Object.keys(rows[0] || {});
  if (r.kind === 'events') {
    const pref = NB_EVENT_COLS.filter((k) => cols.includes(k));
    cols = pref.length ? pref.slice(0, 6) : cols.filter((k) => k !== '_raw').slice(0, 6);
  }
  const isNum = (k) => rows.every((x) => x[k] == null || typeof x[k] === 'number') && rows.some((x) => typeof x[k] === 'number');
  const nums = new Set(cols.filter(isNum));
  const shown = 10;
  const body = (list) => list.map((row) => el('tr', {}, ...cols.map((k) => {
    const v = row[k];
    const text = v == null ? '' : k === '_time' || k === 'first_seen' || k === 'last_seen' ? fmtTime(v) : fmtValue(v);
    return el('td', { class: nums.has(k) ? 'num' : '', title: text, 'data-label': k }, text);
  })));
  const tbody = el('tbody', {}, ...body(rows.slice(0, shown)));
  const more = rows.length > shown ? el('button', { type: 'button', class: 'link-btn nb-more-rows', onclick: (ev) => { tbody.replaceChildren(...body(rows)); ev.currentTarget.remove(); } }, `Show all ${rows.length} rows`) : null;
  return el('div', { class: 'nb-table' },
    el('div', { class: 'nb-table__wrap' }, el('table', { class: 'table table--compact' },
      el('thead', {}, el('tr', {}, ...cols.map((k) => el('th', { scope: 'col', class: nums.has(k) ? 'num' : '', title: k }, k)))), tbody)),
    more);
}

function nbEdit(c) {
  nbState.editing = c.id;
  nbState.drafts[c.id] = c.kind === 'search' ? { title: c.title || '', query: c.query || '' } : { text: c.text || '' };
  renderNotebook();
}

// nbEditor edits one cell, or a new one (c is null) of kind.
function nbEditor(c, kind) {
  const key = c ? c.id : 'new-' + kind;
  const draft = nbState.drafts[key] || (nbState.drafts[key] = kind === 'search' ? { title: '', query: '' } : { text: '' });
  const err = el('div', { class: 'alert hidden', 'data-tone': 'danger', role: 'alert' });
  const cancel = () => { delete nbState.drafts[key]; nbState.editing = null; renderNotebook(); };
  const save = async (andRun) => {
    err.classList.add('hidden');
    let cellId = c ? c.id : null;
    const res = await nbSave((m) => {
      const v = kind === 'search' ? { title: draft.title.trim(), query: draft.query.trim() } : { text: draft.text };
      if (c) Object.assign(m.cells.find((x) => x.id === c.id) || {}, v);
      else m.cells.push({ kind, ...v });
    }, kind === 'search' ? 'Couldn’t save the search' : 'Couldn’t save the note');
    if (!res) return;
    if (!cellId) cellId = res.notebook.cells[res.notebook.cells.length - 1].id;
    delete nbState.drafts[key];
    nbState.editing = null;
    renderNotebook();
    if (andRun) nbRun(cellId);
  };
  const keys = (ev) => {
    if (ev.key === 'Enter' && (ev.ctrlKey || ev.metaKey)) { ev.preventDefault(); save(kind === 'search'); }
    if (ev.key === 'Escape') { ev.preventDefault(); cancel(); }
  };
  const actions = el('div', { class: 'nb-editor__bar' },
    el('span', { class: 'hint hide-sm' }, el('kbd', {}, isMac ? '⌘' : 'Ctrl'), el('kbd', {}, 'Enter'), kind === 'search' ? 'to save and run' : 'to save'),
    el('span', { class: 'spacer' }),
    el('button', { type: 'button', class: 'btn btn--ghost btn--sm', onclick: cancel }, 'Cancel'),
    kind === 'search' ? el('button', { type: 'button', class: 'btn btn--secondary btn--sm', onclick: () => save(false) }, 'Save') : null,
    el('button', { type: 'button', class: 'btn btn--primary btn--sm', onclick: () => save(kind === 'search') }, kind === 'search' ? [icon('play'), 'Save and run'] : 'Save note'));
  if (kind === 'search') {
    const title = el('input', { class: 'input', type: 'text', value: draft.title, placeholder: 'What this search looks for', 'aria-label': 'Search title', maxlength: '200' });
    title.addEventListener('input', () => { draft.title = title.value; });
    const q = el('textarea', { class: 'textarea mono nb-editor__query', rows: '4', spellcheck: 'false', autocapitalize: 'off', 'aria-label': 'Query', placeholder: 'datamodel=Authentication action=failure | stats dc(user) as accounts by src' });
    q.value = draft.query;
    q.addEventListener('input', () => { draft.query = q.value; });
    for (const x of [title, q]) x.addEventListener('keydown', keys);
    return el('div', { class: 'nb-cell nb-cell--search nb-cell--editing card' },
      el('div', { class: 'nb-editor' }, el('div', { class: 'nb-editor__label' }, icon('search', 'icon--sm'), c ? 'Edit search' : 'New search'),
        title, q, err, actions));
  }
  const ta = el('textarea', { class: 'textarea nb-editor__text', rows: '6', 'aria-label': 'Note', placeholder: '## Hypothesis\nWhat you expect to find, and why. **Bold**, _italic_, `code`, lists and [links](https://attack.mitre.org) work.' });
  ta.value = draft.text;
  const preview = el('div', { class: 'nb-md nb-editor__preview hidden', 'aria-live': 'polite' });
  ta.addEventListener('input', () => { draft.text = ta.value; });
  ta.addEventListener('keydown', keys);
  const seg = el('div', { class: 'seg seg--sm', role: 'group', 'aria-label': 'Write or preview' });
  const setMode = (m) => {
    seg.querySelectorAll('button').forEach((b) => b.setAttribute('aria-pressed', String(b.dataset.mode === m)));
    ta.classList.toggle('hidden', m !== 'write');
    preview.classList.toggle('hidden', m !== 'preview');
    if (m === 'preview') fill(preview, ...(draft.text.trim() ? mdRender(draft.text) : [el('p', { class: 'muted' }, 'Nothing to preview yet.')]));
  };
  seg.append(el('button', { type: 'button', 'data-mode': 'write', onclick: () => { setMode('write'); ta.focus(); } }, 'Write'),
    el('button', { type: 'button', 'data-mode': 'preview', onclick: () => setMode('preview') }, 'Preview'));
  setMode('write');
  return el('div', { class: 'nb-cell nb-cell--note nb-cell--editing card' },
    el('div', { class: 'nb-editor' }, el('div', { class: 'nb-editor__label' }, icon('message-square-text', 'icon--sm'), c ? 'Edit note' : 'New note', el('span', { class: 'spacer' }), seg),
      ta, preview, err, actions));
}

async function nbRemoveCell(c) {
  const what = c.kind === 'search' ? 'search' : 'note';
  if (!await caseConfirm({ title: `Delete this ${what}?`, text: c.kind === 'search' ? 'The search and its last results come out of the notebook.' : 'The note comes out of the notebook.', confirm: 'Delete' })) return;
  if (await nbSave((m) => { m.cells = m.cells.filter((x) => x.id !== c.id); })) { renderNotebook(); toast(`The ${what} was deleted.`); }
}

// ---------- running ----------
// nbRun runs one search, or every search, and shows what they found. For
// someone who may change the notebook the results are kept with it.
async function nbRun(cellId) {
  const n = nbState.nb;
  if (!n || nbState.running.size) return;
  const ids = n.cells.filter((c) => c.kind === 'search' && (!cellId || c.id === cellId)).map((c) => c.id);
  if (!ids.length) return;
  await nbSaving;
  ids.forEach((id) => nbState.running.add(id));
  renderNotebook();
  const body = {};
  if (cellId) body.cell = cellId;
  if (nbState.range) body.range = nbState.range;
  try {
    const res = await api(nbPath(n.id) + '/run', body);
    if (nbState.open !== n.id) return;
    nbTake(res);
    if (!res.saved && !n.starter && can('analyst')) toast('Results are shown here but not saved, since you can’t change this notebook.', null, { title: 'Not saved' });
    const failed = res.notebook.cells.filter((c) => ids.includes(c.id) && c.result && c.result.error).length;
    if (failed) toast(`${plural(failed, 'search')} failed. The reason is under each.`, null, { tone: 'danger' });
  } catch (e) {
    toastError('Couldn’t run the notebook', e);
  } finally {
    ids.forEach((id) => nbState.running.delete(id));
    if (nbState.open === n.id) renderNotebook();
  }
}

// ---------- notebook actions ----------
async function nbCopy(n) {
  try {
    const res = await api('api/notebooks', { from: n.id });
    toast(`${res.notebook.title} is yours now. It is private until you share it.`, null, { title: 'Copy made' });
    openNotebook(res.notebook.id);
  } catch (e) { toastError('Couldn’t copy the notebook', e); }
}

function nbCopyLink(n) {
  const url = location.href.split('#')[0] + '#notebooks?id=' + encodeURIComponent(n.id);
  const done = () => toast(n.sharing === 'private' && !n.starter ? 'Link copied. Share the notebook too, or only you and admins can open it.' : 'Link copied.');
  if (navigator.clipboard && window.isSecureContext) navigator.clipboard.writeText(url).then(done, () => nbAsk({ title: 'Link to this notebook', label: 'Link', value: url, confirm: 'Done' }));
  else nbAsk({ title: 'Link to this notebook', label: 'Link', value: url, confirm: 'Done' });
}

async function nbDelete(n) {
  if (!await caseConfirm({ title: 'Delete this notebook?', text: `${n.title} and the results it keeps are deleted for everyone. Investigations it is linked to keep the searches copied to them.`, confirm: 'Delete notebook' })) return;
  try {
    await api(nbPath(n.id), undefined, 'DELETE');
    toast('Notebook deleted.');
    nbBackToList();
  } catch (e) { toastError('Couldn’t delete the notebook', e); }
}

function nbShare(n) {
  const d = modalDialog('nb-share');
  let choice = n.sharing;
  const opts = Object.entries(NB_SHARING).map(([v, s]) => {
    const r = el('input', { type: 'radio', name: 'nb-sharing', value: v, checked: v === n.sharing });
    r.addEventListener('change', () => { choice = v; });
    return el('label', { class: 'nb-share__opt' }, r, el('span', { class: 'nb-share__icon' }, icon(s.icon)),
      el('span', {}, el('b', {}, s.label), el('span', { class: 'nb-share__text' }, s.text)));
  });
  const go = el('button', { type: 'submit', class: 'btn btn--primary' }, 'Save');
  const form = el('form', { method: 'dialog' },
    modalHead('nb-share', 'Share this notebook', 'Viewers can see shared notebooks and run them; their runs are not saved.', () => d.close()),
    el('div', { class: 'modal__body nb-share' }, ...opts),
    el('div', { class: 'modal__foot' }, el('button', { type: 'button', class: 'btn btn--ghost', onclick: () => d.close() }, 'Cancel'), go));
  form.addEventListener('submit', async (ev) => {
    ev.preventDefault();
    if (choice === n.sharing) { d.close(); return; }
    const done = busy(go, 'Saving…');
    const res = await nbSave((m) => { m.sharing = choice; }, 'Couldn’t change the sharing');
    done();
    if (!res) return;
    d.close();
    renderNotebook();
    toast(`${NB_SHARING[choice].label}. ${NB_SHARING[choice].text}`);
  });
  fill(d, form);
  d.showModal();
  d.querySelector('input:checked')?.focus();
}

// nbEditDetails edits the title, description and ATT&CK techniques.
function nbEditDetails(n, focusTechs) {
  const d = modalDialog('nb-details');
  const title = el('input', { id: 'nbd-title', class: 'input', type: 'text', value: n.title, maxlength: '200', autocomplete: 'off' });
  const desc = el('textarea', { id: 'nbd-desc', class: 'textarea', rows: '3', placeholder: 'What this hunt is for' });
  desc.value = n.description || '';
  const techs = el('input', { id: 'nbd-techs', class: 'input mono', type: 'text', value: (n.techniques || []).join(', '), placeholder: 'T1059.001, T1110.003', autocomplete: 'off', spellcheck: 'false', list: 'nbd-techs-list' });
  const list = el('datalist', { id: 'nbd-techs-list' });
  const names = el('div', { class: 'nb-tech-names', 'aria-live': 'polite' });
  const showNames = () => {
    const ids = techs.value.split(/[\s,]+/).map((x) => x.trim().toUpperCase()).filter(Boolean);
    fill(names, ...ids.map((id) => { const i = attackInfo(id); return el('span', { class: i ? 'tech tech--plain' : 'tech tech--bad' }, el('code', {}, id), i ? i.name : 'not an ATT&CK technique'); }));
  };
  loadAttackIndex().then(() => {
    if (!attackIndex) return;
    fill(list, ...[...attackIndex.entries()].slice(0, 2000).map(([id, i]) => el('option', { value: id }, i.name)));
    showNames();
  });
  techs.addEventListener('input', showNames);
  const err = formAlert();
  const go = el('button', { type: 'submit', class: 'btn btn--primary' }, 'Save');
  const form = el('form', { method: 'dialog' },
    modalHead('nb-details', 'Notebook details', null, () => d.close()),
    el('div', { class: 'modal__body' }, err,
      el('div', { class: 'field' }, el('label', { class: 'label', for: 'nbd-title' }, 'Title'), title),
      el('div', { class: 'field' }, el('label', { class: 'label', for: 'nbd-desc' }, 'Description'), desc),
      el('div', { class: 'field' }, el('label', { class: 'label', for: 'nbd-techs' }, 'ATT&CK techniques'), techs, list,
        el('p', { class: 'hint' }, 'Technique IDs, separated by commas. The ATT&CK coverage of detections uses the same IDs.'), names)),
    el('div', { class: 'modal__foot' }, el('button', { type: 'button', class: 'btn btn--ghost', onclick: () => d.close() }, 'Cancel'), go));
  form.addEventListener('submit', async (ev) => {
    ev.preventDefault();
    err.classList.add('hidden');
    if (!title.value.trim()) { showAlert(err, 'Give the notebook a title.'); title.focus(); return; }
    const done = busy(go, 'Saving…');
    const ids = techs.value.split(/[\s,]+/).map((x) => x.trim().toUpperCase()).filter(Boolean);
    let failed = null;
    const n2 = structuredClone(nbState.nb);
    n2.title = title.value.trim();
    n2.description = desc.value.trim();
    n2.techniques = ids;
    try {
      const res = await api(nbPath(n.id), {
        title: n2.title, description: n2.description, techniques: ids, time_range: n2.time_range, sharing: n2.sharing,
        cells: n2.cells.map((c) => ({ id: c.id, kind: c.kind, title: c.title || '', text: c.text || '', query: c.query || '' })),
      }, 'PUT', nbState.version ? { 'If-Match': '"' + nbState.version + '"' } : undefined);
      nbTake(res);
    } catch (e) { failed = e; }
    done();
    if (failed) { showAlert(err, 'Not saved.', failed.problems ? failed.problems.join(' ') : sentence(failed.message)); return; }
    d.close();
    renderNotebook();
  });
  fill(d, form);
  d.showModal();
  (focusTechs ? techs : title).focus();
  showNames();
}

async function nbLinkCase(n) {
  const id = await pickCase({ title: n.title, heading: 'Link to case' });
  if (!id) return;
  const runs = n.cells.filter((c) => c.kind === 'search' && c.result && !c.result.error).length;
  try {
    const res = await api(nbPath(n.id) + '/cases', { case_id: id, with_results: true });
    nbTake(res);
    renderNotebook();
    refreshCaseCount();
    toast(`Linked to ${res.case.title}.` + (runs ? ` ${plural(runs, 'search result')} went to its timeline.` : ' Run the searches and link again to add their results.'),
      { label: 'Open case', run: () => openCase(id) });
  } catch (e) { toastError('Couldn’t link the case', e); }
}

async function nbUnlinkCase(n) {
  const ids = n.cases || [];
  if (!ids.length) return;
  let id = ids[0];
  if (ids.length > 1) {
    id = await nbAsk({ title: 'Unlink a case', label: 'Case ID', value: ids[ids.length - 1], confirm: 'Unlink', desc: 'Linked: ' + ids.join(', ') });
    if (!id) return;
  } else if (!await caseConfirm({ title: 'Unlink this case?', text: `The notebook comes off the timeline of ${id}. Searches already copied there stay.`, confirm: 'Unlink' })) return;
  try {
    const res = await api(nbPath(n.id) + '/cases/' + encodeURIComponent(id), undefined, 'DELETE');
    nbTake(res);
    renderNotebook();
    toast('Case unlinked.');
  } catch (e) { toastError('Couldn’t unlink the case', e); }
}

// nbToDetection opens the detection editor with a search's query and the
// notebook's techniques, turned off until an admin checks and enables it.
function nbToDetection(c) {
  const n = nbState.nb;
  const d = blankDetection();
  const [search, rest] = splitPipes(c.query);
  const cleaned = search.replace(/\b(earliest|latest)=("[^"]*"|\S+)/g, '').replace(/\s+/g, ' ').trim();
  d.query = cleaned + (rest ? '\n' + rest.trim() : '');
  d.title = c.title || n.title;
  d.description = `From the hunting notebook "${n.title}".` + (n.description ? ' ' + n.description : '');
  d.mitre = (n.techniques || []).slice();
  d.enabled = false;
  editDetection(d);
}

// ---------- adding from the Search page ----------
// pickNotebook lets an analyst choose a notebook they can change, or name
// a new one. It resolves to a notebook ID, or null.
function pickNotebook(suggested) {
  const d = modalDialog('nb-pick');
  return new Promise((resolve) => {
    let result = null;
    let choice = '';
    const err = formAlert();
    const list = el('div', { class: 'cp-list', role: 'radiogroup', 'aria-label': 'Notebooks', 'aria-busy': 'true' },
      el('div', { class: 'cp-option cp-option--loading' }, el('span', { class: 'skeleton', style: 'width:60%' })));
    const newTitle = el('input', { id: 'nbp-title', class: 'input', type: 'text', value: suggested || '', placeholder: 'What are you hunting for?', autocomplete: 'off', maxlength: '200' });
    const newFields = el('div', { class: 'cp-new cp-new--nested hidden' }, el('div', { class: 'field' }, el('label', { class: 'label', for: 'nbp-title' }, 'Title'), newTitle));
    const setChoice = (v) => { choice = v; newFields.classList.toggle('hidden', v !== 'new'); err.classList.add('hidden'); };
    const newRadio = el('input', { type: 'radio', name: 'nbp', value: 'new' });
    newRadio.addEventListener('change', () => setChoice('new'));
    const go = el('button', { type: 'submit', class: 'btn btn--primary' }, 'Add to notebook');
    const form = el('form', { method: 'dialog' },
      modalHead('nb-pick', 'Add to notebook', 'The search goes at the end of the notebook. Run it there to keep its results.', () => d.close()),
      el('div', { class: 'modal__body' }, err, list,
        el('label', { class: 'cp-option cp-option--new' }, newRadio, el('span', { class: 'cp-option__icon' }, icon('plus')), el('span', { class: 'cp-option__title' }, 'New notebook')),
        newFields),
      el('div', { class: 'modal__foot' }, el('button', { type: 'button', class: 'btn btn--ghost', onclick: () => d.close() }, 'Cancel'), go));
    form.addEventListener('submit', async (ev) => {
      ev.preventDefault();
      if (!choice) { showAlert(err, 'Choose a notebook or start a new one.'); return; }
      if (choice !== 'new') { result = choice; d.close(); return; }
      if (!newTitle.value.trim()) { showAlert(err, 'Give the new notebook a title.'); newTitle.focus(); return; }
      const done = busy(go, 'Creating…');
      try {
        const res = await api('api/notebooks', { title: newTitle.value.trim() });
        result = res.notebook.id;
        d.close();
      } catch (e) { done(); showAlert(err, 'The notebook was not created.', sentence(e.message)); }
    });
    fill(d, form);
    d.onclose = () => resolve(result);
    d.showModal();
    go.focus();
    api('api/notebooks').then((res) => {
      list.setAttribute('aria-busy', 'false');
      const mine = (res.notebooks || []).filter((n) => can('admin') || nbIsMine(n) || n.sharing === 'edit');
      if (!mine.length) {
        fill(list, el('p', { class: 'cp-none' }, 'You have no notebooks yet.'));
        newRadio.checked = true;
        setChoice('new');
        newTitle.focus();
        return;
      }
      fill(list, ...mine.map((n) => {
        const r = el('input', { type: 'radio', name: 'nbp', value: n.id });
        r.addEventListener('change', () => setChoice(n.id));
        if (nbState.open === n.id) { r.checked = true; setChoice(n.id); }
        return el('label', { class: 'cp-option' }, r, el('span', { class: 'cp-option__icon' }, icon('notebook-pen')),
          el('span', { class: 'cp-option__title', title: n.title }, n.title), nbSharingBadge(n));
      }));
    }).catch((e) => {
      list.setAttribute('aria-busy', 'false');
      fill(list, el('p', { class: 'cp-none' }, 'Notebooks could not be loaded. ' + sentence(e.message)));
    });
  });
}

if ($('search-to-notebook')) {
  $('search-to-notebook').addEventListener('click', async () => {
    const query = $('query').value.trim();
    if (!query) { showQueryError(new Error('Write or ask for a query first.')); return; }
    const asked = typeof lastAsk !== 'undefined' && lastAsk && lastAsk.query.trim() === query ? lastAsk.question : '';
    const id = await pickNotebook(asked);
    if (!id) return;
    try {
      const res = await api(nbPath(id) + '/cells', { kind: 'search', title: asked, query });
      toast(`Search added to ${res.notebook.title}.`, { label: 'Open notebook', run: () => openNotebook(id) });
    } catch (e) { toastError('Couldn’t add the search to the notebook', e); }
  });
}
