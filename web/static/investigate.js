// Investigate with AI (analysts): from a finding, gather its evidence,
// show exactly what will be sent to the AI model, let the model run a few
// read-only searches, and show its verdict with a timeline, the evidence
// and suggested response actions, which a person still reviews and runs.
// The write-up stays in this tab until it is saved to a case. See
// docs/investigate.md.

const inv = { info: null, infoAt: 0, seq: 0, results: new Map(), abort: null };
const INV_VERDICT = {
  real: { label: 'Likely real', tone: 'danger', icon: 'shield-alert', badge: 'badge--danger' },
  benign: { label: 'Likely benign', tone: 'success', icon: 'shield-check', badge: 'badge--success' },
  unsure: { label: 'Unsure', tone: 'warning', icon: 'circle-help', badge: 'badge--warning' },
};
const INV_STEP_ICON = { search: 'search', intel: 'shield-alert', findings: 'crosshair' };
const INV_SKIP_PREVIEW = 'signalith.investigate.skipPreview';

async function invInfo(fresh) {
  if (!fresh && inv.info && Date.now() - inv.infoAt < 60000) return inv.info;
  inv.info = await api('api/investigate');
  inv.infoAt = Date.now();
  return inv.info;
}

function invSkipPreview(v) {
  try {
    if (v === undefined) return localStorage.getItem(INV_SKIP_PREVIEW) === '1';
    if (v) localStorage.setItem(INV_SKIP_PREVIEW, '1'); else localStorage.removeItem(INV_SKIP_PREVIEW);
  } catch (_) { /* storage blocked: always preview */ }
  return false;
}

// findingInvestigate is the AI investigation section on a finding's
// Overview: the last verdict when there is one, else the button.
function findingInvestigate(f) {
  const res = inv.results.get(f.id);
  const open = () => openInvestigate(f);
  if (res) {
    const v = INV_VERDICT[res.verdict] || INV_VERDICT.unsure;
    return el('section', { class: 'section inv-sec' },
      el('div', { class: 'dx-sec-head' }, el('h3', { class: 'section-title' }, 'AI investigation'),
        dxBtn('ghost', 'Show write-up', () => openInvestigate(f, { show: true }), { sm: true, icon: 'sparkles' })),
      el('button', { type: 'button', class: 'inv-last', onclick: () => openInvestigate(f, { show: true }) },
        el('span', { class: 'badge ' + v.badge }, v.label),
        el('span', { class: 'inv-last__text' }, res.summary || 'No summary.')));
  }
  return el('section', { class: 'section inv-sec' },
    el('div', { class: 'dx-sec-head' }, el('h3', { class: 'section-title' }, 'AI investigation'),
      dxBtn('secondary', 'Investigate with AI', open, { sm: true, icon: 'sparkles', action: 'investigate', title: 'Have the AI model look into this finding and write a verdict' })),
    el('p', { class: 'dx-hint' }, 'Gathers the events, user and host history and threat intel, runs a few read-only searches, and writes a verdict. Nothing is changed.'));
}

// openInvestigate opens the dialog: why it cannot run, the preview, the
// progress, or the write-up. opts.show shows the last write-up.
async function openInvestigate(f, opts = {}) {
  const d = modalDialog('inv-dialog');
  d.classList.add('rp-dialog', 'inv-dialog');
  const seq = ++inv.seq;
  const alive = () => seq === inv.seq && d.open;
  const close = () => d.close();
  const show = (title, body, foot) => {
    fill(d, modalHead('inv-dialog', title, f.title, close), el('div', { class: 'modal__body inv-body' }, ...[].concat(body)),
      foot ? el('div', { class: 'modal__foot' }, ...foot) : null);
  };
  const cancelBtn = (label = 'Cancel') => el('button', { type: 'button', class: 'btn btn--ghost', onclick: close }, label);
  d.onclose = () => { inv.seq++; if (inv.abort) { inv.abort.abort(); inv.abort = null; } };
  if (!d.open) d.showModal();

  if (opts.show && inv.results.has(f.id)) { invShowResult(f, inv.results.get(f.id), { show, close, alive }); return; }

  show('Investigate with AI', invSkeleton('Checking the AI model'), [cancelBtn()]);
  let info;
  try { info = await invInfo(true); } catch (e) {
    if (!alive()) return;
    show('Investigate with AI', invProblem('Couldn’t check the AI model', sentence(e.message)), [cancelBtn('Close')]);
    return;
  }
  if (!alive()) return;
  if (!info.enabled) { invOff(info, { show, close }); return; }
  if (invSkipPreview()) { invRun(f, info, { show, close, alive }); return; }
  invPreview(f, info, { show, close, alive });
}

function invSkeleton(text) {
  return el('div', { class: 'inv-wait', role: 'status' }, el('span', { class: 'rp-spinner', 'aria-hidden': 'true' }), el('b', {}, text));
}
function invProblem(title, text) {
  return el('div', { class: 'alert', 'data-tone': 'danger', role: 'alert' }, icon('circle-alert'), el('div', {}, el('b', {}, title), el('p', {}, text)));
}

// invOff explains why it cannot run, and takes an admin to the setting.
function invOff(info, { show, close }) {
  const admin = can('admin');
  const body = el('div', { class: 'empty empty--compact' },
    el('span', { class: 'empty__icon' }, icon('sparkles')),
    el('div', { class: 'empty__title' }, info.code === 'no_model' ? 'No AI model is set up' : 'Investigate with AI is off'),
    el('p', { class: 'empty__text' }, admin
      ? (info.code === 'no_model'
        ? 'Set up a model in Settings, under AI assistant, then turn on Investigate with AI. A model on your own hardware, such as Ollama, keeps event data on your network.'
        : 'It sends a finding’s events to ' + (info.model || 'the AI model') + ', so it stays off until you turn it on in Settings, under AI assistant.')
      : info.reason));
  show('Investigate with AI', body, [
    el('button', { type: 'button', class: 'btn ' + (admin ? 'btn--ghost' : 'btn--secondary'), onclick: close }, 'Close'),
    admin ? el('button', { type: 'button', class: 'btn btn--primary', onclick: () => { close(); showPage('settings'); } }, icon('settings'), 'Open Settings') : null]);
}

// invWhere says where the data goes, and whether it leaves the network.
function invWhere(info) {
  const host = (info.sent_to || '').replace(/^https?:\/\//, '').replace(/:(443|80)$/, '');
  return info.local
    ? el('div', { class: 'alert', 'data-tone': 'success' }, icon('lock'), el('div', {}, el('b', {}, 'Stays on your network.'),
      el('p', {}, `Sent to ${info.model} at ${host}.`)))
    : el('div', { class: 'alert', 'data-tone': 'warning' }, icon('globe'), el('div', {}, el('b', {}, 'Leaves your network.'),
      el('p', {}, `Sent to ${info.model} at ${host}. For data that must stay in-house, an admin can switch to a model on your own hardware.`)));
}

function invMaskChips(list) {
  const always = new Set(['*password*', '*passwd*', '*secret*', '*token*', '*api_key*', '*apikey*', '*cookie*', '*authorization*', '*session_id*', '*private_key*']);
  const own = (list || []).filter((m) => !always.has(m));
  return el('div', { class: 'inv-mask' },
    ...own.map((m) => el('span', { class: 'badge badge--outline badge--mono' }, m === '_raw' ? '_raw (event text)' : m)),
    el('span', { class: 'hint' }, (own.length ? 'and ' : '') + 'passwords, tokens, keys and cookies, always.'));
}

// invPreview gathers the evidence and shows what will be sent.
async function invPreview(f, info, { show, close, alive }) {
  show('Investigate with AI', invSkeleton('Gathering the finding’s events and history'), [el('button', { type: 'button', class: 'btn btn--ghost', onclick: close }, 'Cancel')]);
  let p;
  try { p = (await api('api/findings/' + encodeURIComponent(f.id) + '/investigate/preview', {}, 'POST')).preview; } catch (e) {
    if (!alive()) return;
    if (e.status === 409) { inv.info = null; invOff({ code: e.code, reason: sentence(e.message), model: info.model }, { show, close }); return; }
    show('Investigate with AI', invProblem('Couldn’t gather the evidence', sentence(e.message)), [el('button', { type: 'button', class: 'btn btn--secondary', onclick: close }, 'Close')]);
    return;
  }
  if (!alive()) return;
  const skip = el('input', { type: 'checkbox', id: 'inv-skip' });
  const go = el('button', { type: 'button', class: 'btn btn--primary', 'data-action': 'send' }, icon('sparkles'), 'Send and investigate');
  go.addEventListener('click', () => { invSkipPreview(skip.checked); invRun(f, info, { show, close, alive }); });
  const kb = Math.max(1, Math.round(p.message.length / 1024));
  show('Investigate with AI', [
    invWhere(info),
    el('section', { class: 'inv-part' },
      el('h3', { class: 'section-title' }, 'What is sent'),
      el('ul', { class: 'inv-list' },
        el('li', {}, icon('crosshair'), el('span', {}, 'This finding: its title, severity, entities, context, notes and the result that fired.')),
        ...p.steps.map((s) => el('li', {}, icon(INV_STEP_ICON[s.kind] || 'search'),
          el('span', {}, s.title, el('span', { class: 'muted' }, ' · ' + (s.error ? 'failed' : s.rows && s.rows.length ? plural(s.matched || s.rows.length, s.kind === 'search' ? 'event' : 'match', s.kind === 'search' ? 'events' : 'matches') : 'nothing found'))))),
        el('li', {}, icon('sparkles'), el('span', {}, `Up to ${info.limits.searches} more read-only searches the model asks for, sent the same way: the first ${info.limits.rows} rows of each.`))),
      el('p', { class: 'hint' }, `About ${kb} KB to start, plus the query language reference.`)),
    el('section', { class: 'inv-part' },
      el('h3', { class: 'section-title' }, 'Never sent'),
      invMaskChips(p.masked),
      el('p', { class: 'hint' }, 'Masked values are replaced with stand-ins such as masked-user-1. ' + (can('admin') ? 'Change the list in Settings, under AI assistant.' : 'An admin sets the list in Settings.'))),
    el('details', { class: 'inv-exact' },
      el('summary', {}, icon('chevron-right', 'inv-exact__chev'), 'Show the exact text'),
      el('pre', { class: 'dx-code inv-pre', tabindex: '0' }, p.message)),
    el('label', { class: 'check inv-skip', for: 'inv-skip' }, skip, el('span', {}, 'Don’t show this preview again in this browser')),
  ], [el('button', { type: 'button', class: 'btn btn--ghost', onclick: close }, 'Cancel'), go]);
  go.focus();
}

// invStream posts and reads one JSON object per line as it arrives.
async function invStream(path, onEvent, signal) {
  const resp = await apiRaw(path, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}', signal });
  if (!resp.ok) {
    const data = await resp.json().catch(() => ({}));
    if (resp.status === 401) toSignIn();
    const e = new Error(data.error || resp.statusText);
    e.status = resp.status;
    e.code = data.code;
    throw e;
  }
  const reader = resp.body.getReader();
  const dec = new TextDecoder();
  let buf = '';
  const flush = () => {
    let i;
    while ((i = buf.indexOf('\n')) >= 0) {
      const line = buf.slice(0, i).trim();
      buf = buf.slice(i + 1);
      if (line) onEvent(JSON.parse(line));
    }
  };
  for (;;) {
    const { value, done } = await reader.read();
    if (done) break;
    buf += dec.decode(value, { stream: true });
    flush();
  }
  buf += '\n';
  flush();
}

// invStepItem draws one piece of evidence: what it was, its query, what
// it found, and a button to run it again in Search.
function invStepItem(s, opts = {}) {
  const found = s.error ? el('span', { class: 'inv-step__err' }, 'Failed: ' + s.error)
    : el('span', { class: 'muted' }, s.matched ? plural(s.matched, s.kind === 'search' ? 'result' : 'match', s.kind === 'search' ? 'results' : 'matches') : 'Nothing found');
  const rerun = s.query ? dxBtn('ghost', 'Open in Search', () => { const d = $('inv-dialog'); if (d) d.close(); openSearch(s.query, s.earliest, s.latest); },
    { sm: true, icon: 'search', title: 'Run this search again on the Search page' }) : null;
  return el('li', { class: 'inv-step', id: opts.anchor ? 'inv-step-' + s.n : null, tabindex: opts.anchor ? '-1' : null },
    el('span', { class: 'inv-step__n tabular' }, String(s.n)),
    el('div', { class: 'inv-step__main' },
      el('div', { class: 'inv-step__head' },
        el('span', { class: 'inv-step__title' }, s.title),
        s.by === 'ai' ? el('span', { class: 'badge badge--accent' }, 'Asked by AI') : null),
      s.query ? el('pre', { class: 'dx-code inv-step__q' }, s.query) : null,
      el('div', { class: 'inv-step__foot' }, found, rerun)));
}

// invRun runs the investigation, showing each step as it arrives.
async function invRun(f, info, { show, close, alive }) {
  const status = el('b', {}, 'Gathering the finding’s events and history');
  const steps = el('ol', { class: 'inv-steps', 'aria-live': 'polite' });
  const stop = el('button', { type: 'button', class: 'btn btn--ghost', onclick: close }, 'Stop');
  show('Investigating', [
    el('div', { class: 'inv-wait', role: 'status' }, el('span', { class: 'rp-spinner', 'aria-hidden': 'true' }),
      el('div', {}, status, el('p', { class: 'muted' }, `${info.model} is looking into it. This can take a minute or two; it changes nothing.`))),
    steps,
  ], [stop]);
  const ctl = new AbortController();
  inv.abort = ctl;
  let result = null;
  let failed = null;
  try {
    await invStream('api/findings/' + encodeURIComponent(f.id) + '/investigate', (ev) => {
      if (!alive()) return;
      if (ev.type === 'status') status.textContent = ev.text;
      else if (ev.type === 'step') { steps.append(invStepItem(ev.step)); steps.lastChild.scrollIntoView({ block: 'nearest' }); }
      else if (ev.type === 'result') result = ev.result;
      else if (ev.type === 'error') failed = new Error(ev.text);
    }, ctl.signal);
  } catch (e) {
    if (e.name === 'AbortError' || !alive()) return;
    failed = e;
  } finally { if (inv.abort === ctl) inv.abort = null; }
  if (!alive()) {
    if (result) { inv.results.set(f.id, result); invRefreshFinding(f.id); toast('The AI investigation is done.', { label: 'Show', run: () => openInvestigate(f, { show: true }) }, { title: 'Investigate with AI' }); }
    return;
  }
  if (!result) {
    const err = failed || new Error('The answer stopped before the investigation finished.');
    if (err.status === 409) { inv.info = null; invOff({ code: err.code, reason: sentence(err.message), model: info.model }, { show, close }); return; }
    const again = el('button', { type: 'button', class: 'btn btn--secondary', onclick: () => invRun(f, info, { show, close, alive }) }, icon('refresh-cw'), 'Try again');
    show('Investigate with AI', [invProblem(err.status === 429 ? 'Too many investigations at once' : 'The investigation did not finish', sentence(err.message)), steps.childElementCount ? steps : null],
      [el('button', { type: 'button', class: 'btn btn--ghost', onclick: close }, 'Close'), again]);
    again.focus();
    return;
  }
  inv.results.set(f.id, result);
  invRefreshFinding(f.id);
  invShowResult(f, result, { show, close, alive });
}

function invRefreshFinding(id) {
  if (typeof openFinding !== 'undefined' && openFinding === id && typeof showFinding === 'function') {
    const note = $('fd-comment');
    showFinding(id, { focus: false, keepNote: note ? note.value : '' });
  }
}

const invTimeFmt = new Intl.DateTimeFormat(undefined, { month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit' });
function invTime(t) {
  const d = new Date(t);
  return isNaN(d) ? t : invTimeFmt.format(d);
}

// invShowResult draws the write-up.
function invShowResult(f, r, { show, close, alive }) {
  const v = INV_VERDICT[r.verdict] || INV_VERDICT.unsure;
  const goStep = (n) => {
    const det = $('inv-searches');
    if (det) det.open = true;
    const node = $('inv-step-' + n);
    if (node) { node.scrollIntoView({ block: 'center', behavior: 'smooth' }); node.focus({ preventScroll: true }); }
  };
  const stepRefs = (ns) => (ns || []).map((n) => el('button', { type: 'button', class: 'inv-ref tabular', title: 'Show step ' + n, onclick: () => goStep(n) }, String(n)));
  const ents = Object.entries(f.entities || {}).filter(([k, val]) => k !== 'risk_object_type' && val != null && String(val) !== '')
    .flatMap(([k, val]) => [].concat(val).map((x) => ({ field: k, value: String(x),
      kind: k === 'risk_object' ? ((f.entities || {}).risk_object_type === 'user' ? 'user' : 'host') : undefined })));
  const actions = (r.actions || []).map((a) => el('li', { class: 'inv-action' },
    el('span', { class: 'inv-action__icon' }, icon('zap')),
    el('div', { class: 'inv-action__main' },
      el('div', { class: 'inv-action__title' }, a.label || a.action, ' ', el('span', { class: 'mono inv-action__target' }, a.target)),
      a.reason ? el('p', { class: 'muted' }, a.reason) : null),
    dxBtn('secondary', 'Review…', () => {
      close();
      openRespond({ findingId: f.id, title: f.title, entities: ents, action: a.action, target: a.target,
        reason: a.reason ? 'Suggested by Investigate with AI: ' + a.reason : '', onDone: () => invRefreshFinding(f.id) });
    }, { sm: true, title: 'Check and run it on the Respond dialog; nothing runs until you confirm' })));
  const save = el('button', { type: 'button', class: 'btn btn--primary', 'data-action': 'save-case' }, icon('briefcase'), f.case_id ? 'Save to case' : 'Save to a case…');
  save.addEventListener('click', () => invSaveToCase(f, r, save));
  const copy = el('button', { type: 'button', class: 'btn btn--ghost', title: 'Copy the write-up as text' }, icon('copy'), el('span', {}, 'Copy'));
  copy.addEventListener('click', () => agentSetupCopy(invText(f, r), copy));
  const again = el('button', { type: 'button', class: 'btn btn--ghost', onclick: () => { inv.results.delete(f.id); openInvestigate(f); } }, icon('refresh-cw'), 'Investigate again');
  show('AI investigation', [
    el('div', { class: 'inv-verdict', 'data-tone': v.tone },
      el('span', { class: 'inv-verdict__icon' }, icon(v.icon)),
      el('div', {},
        el('div', { class: 'inv-verdict__label' }, v.label, el('span', { class: 'inv-verdict__conf' }, `${r.confidence} confidence`)),
        el('p', { class: 'inv-verdict__summary' }, r.summary || 'The model gave no summary.'))),
    (r.actions || []).length ? el('section', { class: 'inv-part' },
      el('h3', { class: 'section-title' }, 'Suggested response', el('span', { class: 'count' }, String(r.actions.length))),
      el('ul', { class: 'inv-actions' }, ...actions),
      el('p', { class: 'hint' }, icon('info', 'icon--xs'), ' Nothing runs by itself. Review opens the Respond dialog, where you check the target and confirm.')) : null,
    (r.timeline || []).length ? el('section', { class: 'inv-part' },
      el('h3', { class: 'section-title' }, 'Timeline'),
      el('ol', { class: 'inv-timeline' }, ...r.timeline.map((t) => el('li', {},
        el('time', { class: 'inv-timeline__time tabular' }, invTime(t.time)), el('span', {}, t.text))))) : null,
    (r.evidence || []).length ? el('section', { class: 'inv-part' },
      el('h3', { class: 'section-title' }, 'Evidence'),
      el('ul', { class: 'inv-evidence' }, ...r.evidence.map((e) => el('li', {}, el('span', {}, e.text), e.steps && e.steps.length ? el('span', { class: 'inv-refs' }, ...stepRefs(e.steps)) : null)))) : null,
    (r.next_steps || []).length ? el('section', { class: 'inv-part' },
      el('h3', { class: 'section-title' }, 'Check next'),
      el('ul', { class: 'inv-next' }, ...r.next_steps.map((s) => el('li', {}, icon('arrow-right', 'icon--xs'), el('span', {}, s))))) : null,
    el('details', { class: 'inv-part inv-searches', id: 'inv-searches' },
      el('summary', {}, icon('chevron-right', 'inv-exact__chev'), el('span', { class: 'section-title' }, 'Searches and evidence', el('span', { class: 'count' }, String((r.steps || []).length)))),
      el('ol', { class: 'inv-steps' }, ...(r.steps || []).map((s) => invStepItem(s, { anchor: true })))),
    el('p', { class: 'hint inv-credit' }, icon('sparkles', 'icon--xs'),
      ` Written by ${r.model} ${ago(r.finished)}. It can be wrong: check the evidence before acting.`),
  ], [again, el('span', { class: 'spacer' }), copy, save]);
  save.focus();
}

// invText is the write-up as plain text, for a case note or the clipboard.
function invText(f, r) {
  const v = INV_VERDICT[r.verdict] || INV_VERDICT.unsure;
  const lines = [`Investigate with AI: ${v.label} (${r.confidence} confidence)`, `Finding: ${f.title} (${f.id})`, `Model: ${r.model}, ${fmtTime(r.finished)}`, '', r.summary || ''];
  const list = (title, items) => { if (items.length) lines.push('', title, ...items); };
  list('Timeline:', (r.timeline || []).map((t) => `- ${invTime(t.time)}: ${t.text}`));
  list('Evidence:', (r.evidence || []).map((e) => `- ${e.text}` + (e.steps && e.steps.length ? ` (step ${e.steps.join(', ')})` : '')));
  list('Suggested response (not run):', (r.actions || []).map((a) => `- ${a.label || a.action} on ${a.target}` + (a.reason ? `: ${a.reason}` : '')));
  list('Check next:', (r.next_steps || []).map((s) => `- ${s}`));
  list('Searches:', (r.steps || []).filter((s) => s.query).map((s) => `${s.n}. ${s.title}${s.by === 'ai' ? ' (asked by AI)' : ''}: ${s.query.replace(/\n/g, ' ')} [${s.earliest} to ${s.latest}] ${s.error ? 'failed' : (s.matched || 0) + ' results'}`));
  lines.push('', 'Written by an AI model; it can be wrong.');
  return lines.join('\n').slice(0, 19000);
}

// invSaveToCase adds the write-up to the finding's case as a note, or to
// a case the analyst picks, adding the finding to it too.
async function invSaveToCase(f, r, btn) {
  let id = f.case_id;
  if (!id) {
    id = await pickCase({ title: f.title, heading: 'Save to case' });
    if (!id) return;
  }
  btn.disabled = true;
  try {
    if (!f.case_id) await api('api/cases/' + encodeURIComponent(id) + '/findings', { ids: [f.id] });
    const res = await api('api/cases/' + encodeURIComponent(id) + '/entries', { kind: 'note', text: invText(f, r) });
    f.case_id = id;
    refreshCaseCount();
    toast(`Write-up saved to ${res.case.title}.`, { label: 'Open case', run: () => { const d = $('inv-dialog'); if (d) d.close(); openCase(id); } });
    fill(btn, icon('check'), 'Saved to case');
    if (typeof loadFindings === 'function' && $('page-findings').classList.contains('active')) loadFindings({ quiet: true });
  } catch (e) {
    btn.disabled = false;
    toastError('Couldn’t save to the case', e);
  }
}
