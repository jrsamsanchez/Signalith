// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0
// Sample data: a clean card on the Add data page that loads a week of
// made-up activity with a few attacks hidden in it, so Signalith can be
// tried on real-looking data, and removes it in one click. Admins only;
// others see a short read-only note. It also offers a one-line pointer to
// admins when there is no data: on empty states, and near the top of
// Dashboards and Search when nothing at all arrived in the last 7 days.

let sampleInfo = null; // last api/sample reply (admins only), or null
let samplePoll = null; // interval id while a load or remove runs
let sampleConfirm = false; // true while Remove is in its confirm step
let sampleRun = null; // the running view's live parts, updated in place
let sampleErr = ''; // why the last api/sample read failed

// fetchSample reads the sample-data status for admins and caches it.
async function fetchSample() {
  if (!can('admin')) { sampleInfo = null; return null; }
  try { sampleInfo = await api('api/sample'); sampleErr = ''; } catch (e) { sampleInfo = null; sampleErr = (e && e.message) || ''; }
  return sampleInfo;
}

// samplePointer returns a one-line admin pointer for an empty state, or null
// when it does not apply: not an admin, the feature is off, or sample data
// is already loaded (or part loaded) or a job is running.
function samplePointer() {
  if (!can('admin') || !sampleInfo || !sampleInfo.available || sampleInfo.loaded || sampleInfo.partial || sampleInfo.running) return null;
  return el('span', { class: 'sample-hint' },
    icon('wand-sparkles', 'icon--sm'), ' New here? ',
    el('a', { href: '#data', 'data-page': 'data' }, 'Load sample data'),
    ' to try Signalith on a week of activity.');
}

// syncSampleNotes shows the pointer near the top of Dashboards and Search
// when no events at all arrived in the last 7 days (admins only).
function syncSampleNotes() {
  const show = !!(sampleInfo && sampleInfo.no_data && samplePointer());
  for (const id of ['db-sample-note', 'search-sample-note']) {
    const box = $(id);
    if (!box) continue;
    if (show) fill(box, samplePointer());
    box.hidden = !show;
  }
}

function stopSamplePoll() {
  if (samplePoll) { clearInterval(samplePoll); samplePoll = null; }
}

// loadSampleCard draws the card when the Add data page opens.
function loadSampleCard() {
  const card = $('sample-card');
  if (!card) return;
  stopSamplePoll();
  sampleConfirm = false;
  if (!can('admin')) {
    card.hidden = false;
    fill(card, el('div', { class: 'card__head sample-card__head' },
      el('span', { class: 'sample-card__icon' }, icon('wand-sparkles')),
      el('div', {},
        el('h3', { class: 'card__title' }, 'Sample data'),
        el('p', { class: 'card__sub' }, 'An admin can load a week of made-up activity here to try Signalith.'))));
    return;
  }
  card.hidden = false;
  renderSampleCard({ checking: true });
  fetchSample().then(() => renderSampleCard());
}

function sampleHead() {
  return el('div', { class: 'card__head sample-card__head' },
    el('span', { class: 'sample-card__icon' }, icon('wand-sparkles')),
    el('div', {},
      el('h3', { class: 'card__title' }, 'Try it with sample data'),
      el('p', { class: 'card__sub' },
        'Load a week of made-up activity, with a few attacks hidden in it, to see detections, findings, risk and the dashboards come to life. Everything is fictional, and you remove it in one click.')));
}

// renderSampleCard draws the card from the current status. focus names the
// element to move keyboard focus to (its data-focus value), or the card's
// first such element when the new card has no element by that name; it
// moves only when focus was in the card, or was lost with the content it
// replaces.
function renderSampleCard({ checking = false, focus = null } = {}) {
  const card = $('sample-card');
  if (!card || !can('admin')) return;
  const hadFocus = card.contains(document.activeElement) || document.activeElement === document.body;
  sampleRun = null;
  let body;
  if (checking) body = sampleBody(el('p', { class: 'muted' }, 'Checking…'));
  else if (sampleInfo === null) {
    // OB-6: say why, not only Try again.
    body = sampleBody(
      el('p', { class: 'muted', role: 'status' }, 'Couldn’t check the sample data' + (sampleErr ? ': ' + sampleErr : '.')),
      el('div', { class: 'sample-actions' },
        el('button', { type: 'button', class: 'btn btn--secondary btn--sm', onclick: loadSampleCard }, icon('refresh-cw'), 'Try again')));
  } else if (!sampleInfo.available) body = sampleBody(el('p', { class: 'muted' }, 'Sample data is not available on this server.'));
  else if (sampleInfo.running) body = sampleRunningBody();
  else if (sampleInfo.partial) body = samplePartialBody();
  else if (sampleInfo.loaded) body = sampleLoadedBody();
  else body = sampleIdleBody();
  fill(card, sampleHead(), body);
  if (focus && hadFocus) {
    const target = card.querySelector('[data-focus="' + focus + '"]') || card.querySelector('[data-focus]');
    if (target) target.focus();
  }
  syncSampleNotes();
}

const sampleBody = (...kids) => el('div', { class: 'card__body sample-card__body' }, ...kids);

// sampleError shows the last job's error in plain English, with the
// technical text behind a Details disclosure.
function sampleError() {
  if (!sampleInfo.error) return null;
  return el('div', { class: 'alert sample-alert', 'data-tone': 'danger', role: 'alert' },
    icon('circle-alert'),
    el('div', {},
      el('p', {}, sampleInfo.error),
      sampleInfo.error_detail ? el('details', { class: 'sample-detail' },
        el('summary', {}, icon('chevron-right', 'icon--sm chev'), 'Details'),
        el('pre', {}, sampleInfo.error_detail)) : null));
}

// sampleIdleBody: nothing loaded. Pick a size and load.
function sampleIdleBody() {
  const size = el('select', { id: 'sample-size', class: 'select select--sm', 'aria-describedby': 'sample-size-hint' },
    el('option', { value: 'standard' }, 'Standard: a full week'),
    el('option', { value: 'small' }, 'Small: same attacks, less noise'));
  const loadBtn = el('button', { type: 'button', class: 'btn btn--primary', 'data-focus': 'load', onclick: () => sampleLoad(size.value) },
    icon('wand-sparkles'), 'Load sample data');
  return sampleBody(
    sampleError(),
    el('div', { class: 'sample-load' },
      el('label', { class: 'sample-load__size' }, el('span', { class: 'label' }, 'How much'), size),
      loadBtn),
    el('p', { id: 'sample-size-hint', class: 'muted sample-size-hint' }, SAMPLE_SIZE_HINT));
}
const SAMPLE_SIZE_HINT = 'Both have every attack. Standard adds a full week of everyday activity, about 27,000 events; Small keeps it to a few hundred. Either takes about a minute.';

// sampleRunningBody: a load or remove is going. Show the step and poll;
// the poll moves the step and the bar on in place.
function sampleRunningBody() {
  const verb = sampleInfo.op === 'remove' ? 'Removing sample data' : 'Loading sample data';
  const fillBar = el('div', { class: 'sample-bar__fill' });
  const bar = el('div', { class: 'sample-bar', role: 'progressbar', 'aria-label': verb, 'aria-valuemin': '0', 'aria-valuemax': '100' }, fillBar);
  const phase = el('span', {});
  const num = el('span', { class: 'sample-phase__pct', 'aria-hidden': 'true' });
  sampleRun = { op: sampleInfo.op, phase, num, bar, fill: fillBar };
  updateSampleRun();
  if (!samplePoll) samplePoll = setInterval(sampleTick, 1000);
  return sampleBody(
    el('div', { class: 'sample-phase' },
      el('p', { role: 'status', tabindex: '-1', 'data-focus': 'progress' }, verb + ': ', phase),
      num),
    bar,
    // A job another server (or the command line) runs: say where.
    sampleInfo.where ? el('p', { class: 'muted sample-where' }, sampleInfo.where + ' It carries on there; this page follows it.') : null);
}

// updateSampleRun moves the running view on without redrawing it, so the
// status line is announced only when the step changes. It reports false
// when there is no running view of the same job to update.
function updateSampleRun() {
  if (!sampleRun || sampleRun.op !== sampleInfo.op) return false;
  const pct = Math.max(0, Math.min(100, sampleInfo.percent || 0));
  const phase = sampleInfo.phase || 'Starting';
  if (sampleRun.phase.textContent !== phase) sampleRun.phase.textContent = phase;
  sampleRun.num.textContent = pct + '%';
  sampleRun.fill.style.width = pct + '%';
  sampleRun.bar.setAttribute('aria-valuenow', String(pct));
  return true;
}

// samplePartialBody: a load or removal stopped part way. Offer to remove
// what is left.
function samplePartialBody() {
  const removing = !!(sampleInfo.state && sampleInfo.state.removing);
  const text = removing
    ? 'The last removal did not finish. Part of the sample data is still in place: finish removing it.'
    : 'The last load did not finish. Part of the sample data is in place: remove it, then load it again.';
  return sampleBody(
    sampleError() || el('div', { class: 'alert', 'data-tone': 'warning', role: 'status' }, icon('triangle-alert'),
      el('p', {}, text)),
    el('div', { class: 'sample-actions' },
      el('button', { type: 'button', class: 'btn btn--secondary btn--sm', 'data-focus': 'remove', onclick: sampleRemove },
        icon('x'), removing ? 'Finish removing' : 'Remove what was loaded')));
}

// sampleUnfinishedText is the toast for a job elsewhere that stopped part
// way.
function sampleUnfinishedText() {
  return sampleInfo.state && sampleInfo.state.removing
    ? 'The sample-data removal did not finish. Use Finish removing to take out the rest.'
    : 'The sample-data load did not finish. Remove what was loaded, then load it again.';
}

// sampleFocusFor names where focus goes for the card as it is now.
function sampleFocusFor() {
  if (!sampleInfo) return 'load';
  if (sampleInfo.running) return 'progress';
  if (sampleInfo.partial || sampleInfo.loaded) return 'remove';
  return 'load';
}

// sampleTries are the loaded card's shortcuts, each to a view that covers
// the sample's week (several pages open on the last 24 hours).
function sampleTries(st) {
  const go = (fn) => (ev) => {
    if (ev.button !== 0 || ev.ctrlKey || ev.metaKey || ev.shiftKey || ev.altKey) return;
    ev.preventDefault();
    fn();
  };
  const caseID = (st.cases || [])[0];
  return [
    ['See the findings that fired', 'findings', 'shield-alert', () => showPage('findings')],
    ['Watch risk build up over the week', 'risk', 'trending-up', () => openRiskSince('7d')],
    ['Walk through the sample investigation', 'cases', 'briefcase', () => (caseID ? openCase(caseID) : showPage('cases'))],
    ['See the week on the dashboard', 'dashboards', 'layout-dashboard', () => window.openDashboardAt('posture', '7d')],
    ['Search the week for threat intel matches', 'search', 'search', sampleHunt],
  ].map(([label, page, ic, fn]) => el('li', {},
    el('a', { href: '#' + page, onclick: go(fn) }, icon(ic, 'icon--sm'), label)));
}

// sampleHunt opens Search on the threat intel matches over the last 7 days,
// with the time picker on that range (not saved as the viewer's choice).
function sampleHunt() {
  setQuery('* | threatmatch\n| table _time, threat_match_field, threat_match_value, threat_source, host, user');
  $('time').value = '-7d';
  showPage('search');
  runSearch();
}

// sampleLoadedBody: a set is loaded. Offer things to try and Remove.
function sampleLoadedBody() {
  const st = sampleInfo.state || {};
  const counts = el('div', { class: 'sample-counts' },
    sampleCount(st.events, 'events'),
    sampleCount(st.findings, 'findings'),
    sampleCount(st.risk_events, 'risk events'),
    sampleCount(st.indicators, 'threat intel indicators'));
  const stories = (st.stories || []).map((s) => s.title).filter(Boolean);

  let actions;
  if (sampleConfirm) {
    actions = el('div', { class: 'sample-confirm', role: 'group', 'aria-labelledby': 'sample-confirm-q' },
      el('span', { id: 'sample-confirm-q' }, 'Remove all sample data? Nothing of yours is touched.'),
      el('button', { type: 'button', class: 'btn btn--danger btn--sm', 'data-focus': 'confirm', onclick: sampleRemove }, 'Yes, remove it'),
      el('button', { type: 'button', class: 'btn btn--ghost btn--sm', onclick: () => { sampleConfirm = false; renderSampleCard({ focus: 'remove' }); } }, 'Cancel'));
  } else {
    actions = el('button', { type: 'button', class: 'btn btn--secondary btn--sm', 'data-focus': 'remove',
      onclick: () => { sampleConfirm = true; renderSampleCard({ focus: 'confirm' }); } },
    icon('x'), 'Remove sample data');
  }

  return sampleBody(
    el('div', { class: 'sample-loaded-head' },
      el('span', { class: 'sample-badge', tabindex: '-1', 'data-focus': 'loaded' }, icon('circle-check', 'icon--sm'), 'Loaded'),
      el('span', { class: 'muted' }, st.loaded_at ? ago(st.loaded_at) : '')),
    counts,
    el('div', { class: 'sample-try-wrap' },
      el('p', { class: 'label' }, 'Things to try'),
      el('ul', { class: 'sample-try', role: 'list' }, ...sampleTries(st))),
    stories.length ? el('p', { class: 'muted sample-stories' }, 'Hidden in it: ' + stories.join(', ') + '.') : null,
    el('div', { class: 'sample-actions' }, actions));
}

function sampleCount(n, label) {
  return el('div', { class: 'sample-count' },
    el('span', { class: 'sample-count__n' }, Number(n || 0).toLocaleString()),
    el('span', { class: 'sample-count__l' }, label));
}

// sampleTick polls the status while a job runs and redraws when it ends.
async function sampleTick() {
  const op = sampleRun ? sampleRun.op : sampleInfo && sampleInfo.op;
  await fetchSample();
  if (sampleInfo && sampleInfo.running) {
    if (!updateSampleRun()) renderSampleCard();
    return;
  }
  stopSamplePoll();
  if (!sampleInfo) { renderSampleCard(); return; }
  if (sampleInfo.error) {
    renderSampleCard({ focus: sampleInfo.partial ? 'remove' : 'load' });
    toast(sampleInfo.error, null, { tone: 'danger' });
  } else if (sampleInfo.partial) {
    // A job on another server, or the command line, stopped part way.
    renderSampleCard({ focus: 'remove' });
    toast(sampleUnfinishedText(), null, { tone: 'danger' });
  } else if (sampleInfo.loaded) {
    renderSampleCard({ focus: 'loaded' });
    toast('Sample data loaded. Have a look around.');
  } else {
    renderSampleCard({ focus: 'load' });
    if (op === 'remove') toast('Sample data removed.');
  }
}

async function sampleStart(path, body, failText) {
  sampleConfirm = false;
  try {
    await api(path, body);
  } catch (e) {
    toast(e.message || failText, null, { tone: 'danger' });
    await fetchSample();
    renderSampleCard({ focus: sampleFocusFor() });
    return;
  }
  await fetchSample();
  renderSampleCard({ focus: 'progress' });
  if (!samplePoll) samplePoll = setInterval(sampleTick, 1000);
}

const sampleLoad = (size) => sampleStart('api/sample/load', { size }, 'Could not start loading the sample data.');
const sampleRemove = () => sampleStart('api/sample/remove', {}, 'Could not start removing the sample data.');

// Prefetch the status once the role is known, so the pointers can appear on
// the first render of Dashboards, Search and Findings for admins.
if (typeof meReady !== 'undefined') meReady.then(() => { if (can('admin')) fetchSample().then(syncSampleNotes); });

// The pointer goes once data arrives: check again when those pages open.
if (typeof pageHooks !== 'undefined') {
  pageHooks.push((name) => {
    if ((name === 'dashboards' || name === 'search') && sampleInfo && sampleInfo.no_data) fetchSample().then(syncSampleNotes);
  });
}
