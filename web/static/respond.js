// Response actions: the Respond dialog analysts open on a finding or a
// case, the past runs shown there, and the Response actions page where
// admins set the actions up. The server checks everything again; see
// docs/response-actions.md.
'use strict';

const RP_KIND = { http: ['HTTP request', 'send'], script: ['Script', 'terminal'], disable_user: ['Directory account', 'user-x'] };
const RP_TARGET = { ip: ['IP address', 'globe'], domain: ['Domain', 'link'], user: ['User', 'user'], host: ['Host', 'server'], any: ['Any target', 'target'] };
const RP_STATUS = { running: ['Running', 'accent', 'refresh-cw'], succeeded: ['Succeeded', 'success', 'circle-check'], failed: ['Failed', 'danger', 'circle-alert'], interrupted: ['Interrupted', 'warning', 'triangle-alert'] };
const RP_SAMPLE = { ip: '203.0.113.7', domain: 'bad.example.com', user: 'jdoe', host: 'ws-0042' };
const RP_IP = /^(\d{1,3}\.){3}\d{1,3}$|^[0-9a-f]*:[0-9a-f:.]+$/i;

const rpStatusBadge = (s) => {
  const [label, tone] = RP_STATUS[s] || [s, ''];
  return el('span', { class: 'badge' + (tone ? ' badge--' + tone : '') }, label);
};
const rpNoun = (k) => (RP_TARGET[k] ? RP_TARGET[k][0] : 'Target').replace(/^(IP|[A-Z])/, (m) => (m === 'IP' ? m : m.toLowerCase()));
// rpDocs links to the guide of this version: its release tag, else main.
function rpDocs(anchor) {
  const v = ($('user-menu-version') || {}).textContent || '';
  const ref = /^v\d+\.\d+\.\d+$/.test(v) ? v : 'main';
  return `https://github.com/jrsamsanchez/signalith/blob/${ref}/docs/response-actions.md` + (anchor ? '#' + anchor : '');
}
const rpDocLink = (anchor, label) => el('a', { class: 'rp-doc', href: rpDocs(anchor), target: '_blank', rel: 'noopener noreferrer' },
  label, icon('arrow-up-right', 'icon--xs'), el('span', { class: 'sr-only' }, ' (opens in a new tab)'));
// rpWhat fills an action's "what" sentence with the target, in bold.
function rpWhat(what, target) {
  const parts = String(what || '').split('{target}');
  const out = [];
  parts.forEach((p, i) => { if (i) out.push(el('b', { class: 'rp-target' }, target)); if (p) out.push(p); });
  return out;
}
const rpWhatPlain = (what, kind) => String(what || '').replace(/\{target\}/g, 'the ' + rpNoun(kind));

// ---------- targets from a finding or a case ----------
// rpGuessKind mirrors the server's guess for an action that takes any target.
function rpGuessKind(v) {
  v = String(v || '').trim();
  if (RP_IP.test(v)) return 'ip';
  if (/[@\\ ]/.test(v)) return 'user';
  if (v.replace(/\.$/, '').includes('.')) return 'domain';
  return 'host';
}
// rpEntityKind says what kind of target an entity field holds, or '' when
// it is not one an action can take (a hash, a process).
function rpEntityKind(field, value, hint) {
  const f = String(field || '').toLowerCase();
  if (hint) return hint;
  if (RP_IP.test(value)) return 'ip';
  if (/(^|_)user$|^member$|^user_name$|^account$|^identity$/.test(f)) return 'user';
  if (/(^|_)host$|^dvc$|^src$|^dest$|^computer$|hostname/.test(f)) return 'host';
  if (/domain|^query$|^url$|fqdn/.test(f)) return 'domain';
  return '';
}
// rpCandidates turns entities ([{field, value, kind?}]) into targets an
// action can be run on, each kind and value once.
function rpCandidates(entities) {
  const out = [];
  const seen = new Set();
  for (const e of entities || []) {
    let v = String(e.value == null ? '' : e.value).trim();
    if (!v || v.length > 256) continue;
    if (String(e.field).toLowerCase() === 'url') {
      try { v = new URL(v.includes('://') ? v : 'http://' + v).hostname; } catch (_) { continue; }
    }
    const kind = rpEntityKind(e.field, v, e.kind);
    if (!kind || seen.has(kind + '\0' + v.toLowerCase())) continue;
    seen.add(kind + '\0' + v.toLowerCase());
    out.push({ kind, value: v, field: e.field });
  }
  return out;
}
const rpFits = (actionKind, c) => actionKind === 'any' || c.kind === actionKind || (actionKind === 'host' && c.kind === 'ip');

// ---------- a run, as it is shown ----------
function rpRunDetail(r) {
  const [, tone, ic] = RP_STATUS[r.status] || ['', 'info', 'info'];
  const alertTone = tone === 'accent' ? 'info' : tone;
  const head = r.status === 'running' ? 'Still running' : r.status === 'succeeded' ? 'Done' : r.status === 'interrupted' ? 'Interrupted' : 'It failed';
  const who = r.automatic ? `playbook ${r.actor}` + (r.approved_by ? `, approved by ${r.approved_by}` : '') : r.actor;
  const dur = r.duration_ms ? (r.duration_ms < 1000 ? `${r.duration_ms} ms` : `${(r.duration_ms / 1000).toFixed(1)} s`) : '';
  return el('div', { class: 'rp-result' },
    el('div', { class: 'alert', 'data-tone': alertTone, role: tone === 'danger' ? 'alert' : 'status' }, icon(ic),
      el('div', {}, el('b', {}, head), r.summary ? el('p', {}, r.summary) : null, r.error ? el('p', {}, r.error) : null)),
    (r.record_errors || []).length ? el('div', { class: 'alert', 'data-tone': 'warning' }, icon('triangle-alert'),
      el('div', {}, el('b', {}, 'It ran, but was not noted everywhere'), ...r.record_errors.map((x) => el('p', {}, sentence(x))))) : null,
    el('dl', { class: 'kv rp-kv' },
      el('dt', {}, 'Action'), el('dd', {}, r.action_label || r.action),
      el('dt', {}, 'Target'), el('dd', {}, el('span', { class: 'mono' }, r.target), ' ', el('span', { class: 'muted' }, rpNoun(r.target_kind))),
      el('dt', {}, 'Run by'), el('dd', {}, who),
      r.reason ? el('dt', {}, 'Reason') : null, r.reason ? el('dd', { class: 'rp-reason' }, r.reason) : null,
      el('dt', {}, 'When'), el('dd', {}, el('span', { title: new Date(r.started).toLocaleString() }, new Date(r.started).toLocaleString()), dur ? ` · ${dur}` : ''),
      r.server ? el('dt', {}, 'Server') : null, r.server ? el('dd', { class: 'mono' }, r.server) : null,
      el('dt', {}, 'Run ID'), el('dd', { class: 'mono' }, r.id)),
    r.output ? el('div', { class: 'rp-output' }, el('div', { class: 'section-title' }, 'Output'), el('pre', { class: 'rp-pre', tabindex: '0' }, r.output)) : null);
}

// rpShowRun opens one past run.
async function rpShowRun(id, filter) {
  const d = modalDialog('rp-show');
  d.classList.add('rp-dialog');
  const body = el('div', { class: 'modal__body' }, el('span', { class: 'skeleton', style: 'width:60%' }), el('span', { class: 'skeleton', style: 'width:90%' }));
  fill(d, modalHead('rp-show', 'Response action', id, () => d.close()), body,
    el('div', { class: 'modal__foot' }, el('button', { type: 'button', class: 'btn btn--secondary', onclick: () => d.close() }, 'Close')));
  d.showModal();
  try {
    const p = new URLSearchParams({ limit: '200' });
    if (filter.caseId) p.set('case_id', filter.caseId);
    if (filter.findingId) p.set('finding_id', filter.findingId);
    const res = await api('api/respond/runs?' + p);
    const r = (res.runs || []).find((x) => x.id === id);
    fill(body, r ? rpRunDetail(r) : el('p', { class: 'muted' }, 'This run is no longer in the audit log.'));
  } catch (e) {
    fill(body, el('div', { class: 'alert', 'data-tone': 'danger', role: 'alert' }, icon('circle-alert'), el('div', {}, el('b', {}, 'Couldn’t load the run'), el('p', {}, sentence(e.message)))));
  }
}

// rpRunsSection lists the runs made from a finding. It stays empty until
// there are some, and for viewers (runs are analyst data).
function rpRunsSection({ findingId, caseId }) {
  const box = el('div', { class: 'rp-runs hidden' });
  if (!can('analyst')) return box;
  const p = new URLSearchParams({ limit: '50' });
  if (findingId) p.set('finding_id', findingId);
  if (caseId) p.set('case_id', caseId);
  api('api/respond/runs?' + p).then((res) => {
    const runs = res.runs || [];
    if (!runs.length) return;
    fill(box, el('p', { class: 'rp-runs__label' }, 'Past runs ', el('span', { class: 'count' }, String(runs.length))),
      rpRunList(runs, { findingId, caseId }));
    box.classList.remove('hidden');
  }, () => { /* response actions may be off on this server */ });
  return box;
}
function rpRunList(runs, filter) {
  return el('ul', { class: 'rp-runlist', role: 'list' }, ...runs.map((r) => el('li', {},
    el('button', { type: 'button', class: 'rp-runrow', onclick: () => rpShowRun(r.id, filter) },
      el('span', { class: 'rp-runrow__dot', 'data-status': r.status }, icon((RP_STATUS[r.status] || [])[2] || 'zap')),
      el('span', { class: 'rp-runrow__main' },
        el('span', { class: 'rp-runrow__title' }, r.action_label || r.action, ' ', el('span', { class: 'mono' }, r.target)),
        el('span', { class: 'rp-runrow__meta' }, [(RP_STATUS[r.status] || [r.status])[0], r.automatic ? 'playbook ' + r.actor : r.actor, ago(r.started),
          filter.findingId || filter.caseId ? '' : r.case_id || r.finding_id || ''].filter(Boolean).join(' · '))),
      icon('chevron-right', 'rp-runrow__go')))));
}

// ---------- the Respond dialog ----------
// openRespond runs an action on a target from a finding or a case:
// pick the action, check the target and give a reason, confirm a sentence
// that says exactly what will happen, then see the result and output.
// ctx: { findingId, caseId, entities: [{field, value, kind?}], title, onDone(run) }.
const rp = { seq: 0 };
async function openRespond(ctx) {
  const d = modalDialog('rp-run');
  d.classList.add('rp-dialog');
  const seq = ++rp.seq;
  const alive = () => seq === rp.seq && d.open;
  const where = ctx.caseId ? `case ${ctx.caseId}` : `finding ${ctx.findingId}`;
  const close = () => d.close();
  const show = (title, desc, body, foot) => {
    fill(d, modalHead('rp-run', title, desc, close), el('div', { class: 'modal__body rp-body' }, ...[].concat(body)), foot ? el('div', { class: 'modal__foot' }, ...foot) : null);
  };
  const cancel = () => el('button', { type: 'button', class: 'btn btn--ghost', onclick: close }, 'Cancel');
  show('Respond', ctx.title || where, [el('span', { class: 'skeleton', style: 'width:70%' }), el('span', { class: 'skeleton', style: 'width:90%;height:48px' }), el('span', { class: 'skeleton', style: 'width:90%;height:48px' })], [cancel()]);
  d.onclose = () => { rp.seq++; };
  d.showModal();

  let actions, listError;
  const load = async () => {
    try {
      const r = await api('api/respond/actions');
      actions = r.actions || [];
      listError = r.error || '';
    } catch (e) {
      if (!alive()) return;
      show('Respond', ctx.title || where, el('div', { class: 'empty empty--compact', 'data-tone': 'danger' },
        el('span', { class: 'empty__icon' }, icon('circle-alert')), el('div', { class: 'empty__title' }, 'Couldn’t load the response actions'),
        el('p', { class: 'empty__text' }, sentence(e.message)),
        el('div', { class: 'empty__actions' }, el('button', { type: 'button', class: 'btn btn--secondary btn--sm', onclick: load }, icon('refresh-cw'), 'Try again'))), [cancel()]);
      return;
    }
    if (!alive()) return;
    if (!actions.length) {
      show('Respond', ctx.title || where, el('div', { class: 'empty empty--compact' },
        el('span', { class: 'empty__icon' }, icon('zap')),
        el('div', { class: 'empty__title' }, listError ? 'The response actions can’t be read' : 'No response actions yet'),
        el('p', { class: 'empty__text' }, listError || (can('admin') ? 'Set up actions such as Block IP on the firewall or Disable AD user, and they appear here.' : 'An admin sets them up on the Response actions page.')),
        can('admin') ? el('div', { class: 'empty__actions' }, el('button', { type: 'button', class: 'btn btn--secondary btn--sm', onclick: () => { close(); showPage('respond'); } }, icon('settings'), 'Set up response actions')) : null),
      [el('button', { type: 'button', class: 'btn btn--secondary', onclick: close }, 'Close')]);
      return;
    }
    choose();
  };

  const cands = rpCandidates(ctx.entities);
  const st = { action: null, target: '', kind: '', typed: false, reason: '' };
  const firstUsable = (list) => list.find((a) => !a.problem);

  // Step 1: what, on what, and why.
  const choose = (err) => {
    if (!st.action) st.action = firstUsable(actions) || null;
    const errBox = el('div', { class: 'alert hidden', 'data-tone': 'danger', role: 'alert' });
    const options = el('div', { class: 'rp-pick', role: 'radiogroup', 'aria-label': 'Action' }, ...actions.map((a, i) => {
      const id = 'rp-a-' + i;
      const r = el('input', { type: 'radio', name: 'rp-action', id, value: a.name });
      r.checked = st.action && st.action.name === a.name;
      if (a.problem) r.disabled = true;
      r.addEventListener('change', () => { st.action = a; if (!st.typed) st.target = ''; syncTarget(); syncReason(); });
      return el('label', { class: 'rp-opt' + (a.problem ? ' is-off' : ''), for: id }, r,
        el('span', { class: 'rp-opt__icon' }, icon((RP_KIND[a.kind] || ['', 'zap'])[1])),
        el('span', { class: 'rp-opt__main' },
          el('span', { class: 'rp-opt__title' }, a.label || a.name,
            a.disruptive ? el('span', { class: 'badge badge--warning' }, 'Disruptive') : null),
          el('span', { class: 'rp-opt__desc' }, a.problem ? a.problem : a.description || rpWhatPlain(a.what, a.target))));
    }));
    const target = el('input', { id: 'rp-target', class: 'input mono', type: 'text', autocomplete: 'off', spellcheck: 'false', 'aria-describedby': 'rp-target-hint' });
    const targetLabel = el('label', { class: 'label', for: 'rp-target' }, 'Target');
    const chips = el('div', { class: 'rp-chips', id: 'rp-target-hint' });
    const reason = el('textarea', { id: 'rp-reason', class: 'textarea', rows: '2', maxlength: '2000', placeholder: 'Why: what you saw, what this stops' });
    reason.value = st.reason;
    const reasonLabel = el('label', { class: 'label', for: 'rp-reason' });
    target.addEventListener('input', () => { st.target = target.value; st.typed = true; st.kind = ''; target.removeAttribute('aria-invalid'); syncChips(); });
    reason.addEventListener('input', () => { st.reason = reason.value; reason.removeAttribute('aria-invalid'); });
    const syncChips = () => {
      const a = st.action;
      const fit = a ? cands.filter((c) => rpFits(a.target, c)) : [];
      fill(chips, ...(fit.length ? [el('span', { class: 'hint' }, 'From this ' + (ctx.caseId ? 'case' : 'finding') + ':'), ...fit.slice(0, 8).map((c) =>
        el('button', { type: 'button', class: 'rp-chip' + (c.value === st.target.trim() ? ' is-on' : ''), title: c.field, 'aria-pressed': String(c.value === st.target.trim()),
          onclick: () => { st.target = c.value; st.kind = c.kind; st.typed = false; target.value = c.value; target.removeAttribute('aria-invalid'); syncChips(); } },
        icon(RP_TARGET[c.kind][1], 'icon--xs'), c.value))]
        : [el('span', { class: 'hint' }, a ? `Enter the ${rpNoun(a.target === 'any' ? '' : a.target)} to act on.` : '')]));
    };
    const syncTarget = () => {
      const a = st.action;
      if (a && !st.target) {
        const c = cands.find((x) => rpFits(a.target, x));
        if (c) { st.target = c.value; st.kind = c.kind; }
      }
      target.value = st.target;
      targetLabel.textContent = a ? (a.target === 'any' ? 'Target' : RP_TARGET[a.target][0]) : 'Target';
      target.placeholder = a && a.target !== 'any' ? RP_SAMPLE[a.target] : 'IP address, domain, user or host';
      syncChips();
    };
    const syncReason = () => {
      const req = !!(st.action && st.action.disruptive);
      fill(reasonLabel, 'Reason', el('span', { class: 'rp-req' }, req ? ' (required)' : ' (optional)'));
      reason.required = req;
    };
    syncTarget();
    syncReason();
    // A hidden submit button lets Enter in the target field go on.
    const next = el('button', { type: 'submit', class: 'sr-only', tabindex: '-1', 'aria-hidden': 'true' }, 'Review');
    const form = el('form', { class: 'rp-form', novalidate: '' }, errBox,
      el('fieldset', { class: 'rp-fieldset' }, el('legend', { class: 'label' }, 'Action'), options),
      el('div', { class: 'field' }, targetLabel, target, chips),
      el('div', { class: 'field' }, reasonLabel, reason,
        el('p', { class: 'hint' }, 'Saved with the run in the audit log and on the ' + (ctx.caseId ? 'case timeline' : 'finding') + '.')));
    const fail = (field, msg) => {
      fill(errBox, icon('circle-alert'), el('div', {}, el('b', {}, msg)));
      errBox.classList.remove('hidden');
      const n = { target, reason }[field];
      if (n) { n.setAttribute('aria-invalid', 'true'); n.focus(); }
    };
    form.addEventListener('submit', (ev) => {
      ev.preventDefault();
      errBox.classList.add('hidden');
      if (!st.action) { fail('', 'Choose an action.'); return; }
      st.target = target.value.trim();
      if (!st.target) { fail('target', `Enter the ${rpNoun(st.action.target)} to act on.`); return; }
      if (st.action.disruptive && !reason.value.trim()) { fail('reason', 'Say why: this action changes something, so it needs a reason.'); return; }
      st.reason = reason.value.trim();
      confirmStep();
    });
    show('Respond', ctx.title || where, form, [cancel(), el('button', { type: 'button', class: 'btn btn--primary', onclick: () => form.requestSubmit() }, 'Review', icon('arrow-right'))]);
    form.append(next);
    if (err) fail(err.field, sentence(err.message));
    else (st.action ? target : options.querySelector('input:not(:disabled)') || target).focus();
  };

  // Step 2: the sentence of what will happen, and nothing else to read.
  const confirmStep = () => {
    const a = st.action;
    const kind = a.target === 'any' ? (st.kind || rpGuessKind(st.target)) : a.target;
    const run = el('button', { type: 'button', class: 'btn ' + (a.disruptive ? 'btn--danger' : 'btn--primary') }, icon('zap'), a.disruptive ? 'Yes, run it' : 'Run it');
    run.addEventListener('click', () => runStep(kind));
    show('Confirm', a.label, [
      el('div', { class: 'rp-confirm' + (a.disruptive ? ' is-disruptive' : '') },
        el('span', { class: 'rp-confirm__icon' }, icon(a.disruptive ? 'triangle-alert' : 'zap')),
        el('p', { class: 'rp-confirm__what' }, ...rpWhat(a.what, st.target))),
      el('dl', { class: 'kv rp-kv' },
        el('dt', {}, 'Target'), el('dd', {}, el('span', { class: 'mono' }, st.target), ' ', el('span', { class: 'muted' }, rpNoun(kind))),
        el('dt', {}, 'Reason'), el('dd', { class: 'rp-reason' }, st.reason || el('span', { class: 'muted' }, 'None given')),
        el('dt', {}, 'Recorded'), el('dd', {}, `In the audit log as ${me ? me.username : 'you'}, and on ${where}.`)),
      a.disruptive ? el('p', { class: 'hint rp-warn' }, icon('info'), 'It takes effect at once, outside Signalith. To reverse it, run the matching undo action if there is one.') : null,
    ], [el('button', { type: 'button', class: 'btn btn--ghost', onclick: () => choose() }, icon('arrow-left'), 'Back'), run]);
    run.focus();
  };

  // Step 3: run it, then show what came back.
  const runStep = async (kind) => {
    const a = st.action;
    show('Running', a.label, el('div', { class: 'rp-running', role: 'status' }, el('span', { class: 'rp-spinner', 'aria-hidden': 'true' }),
      el('div', {}, el('b', {}, ...rpWhat(a.what, st.target)), el('p', { class: 'muted' }, 'This can take up to a few minutes for a script. You can close this; the result is saved either way.'))),
    [el('button', { type: 'button', class: 'btn btn--secondary', onclick: close }, 'Close')]);
    let r;
    try {
      r = await api('api/respond/run', { action: a.name, target: st.target, target_kind: a.target === 'any' ? kind : '', finding_id: ctx.findingId || '', case_id: ctx.caseId || '', reason: st.reason }, 'POST');
    } catch (e) {
      if (!alive()) { if (!e.status) toast('The response action may still be running. Its result appears in past runs.', null, { tone: 'danger', title: 'Lost the connection' }); return; }
      if (e.status === 400) { choose(e); return; }
      const lost = !e.status || e.status >= 502;
      show(lost && !e.status ? 'Connection lost' : 'Not run', a.label, el('div', { class: 'alert', 'data-tone': 'danger', role: 'alert' }, icon('circle-alert'),
        el('div', {}, el('b', {}, !e.status ? 'The answer did not arrive' : e.status === 429 ? 'Too many runs' : 'The action did not run'),
          el('p', {}, !e.status ? 'The action may still have run. Its result appears in past runs on this ' + (ctx.caseId ? 'case' : 'finding') + ' when it is done.' : sentence(e.message)))),
      [el('button', { type: 'button', class: 'btn btn--ghost', onclick: () => choose() }, icon('arrow-left'), 'Back'), el('button', { type: 'button', class: 'btn btn--secondary', onclick: close }, 'Close')]);
      if (!e.status && ctx.onDone) ctx.onDone(null);
      return;
    }
    if (ctx.onDone) ctx.onDone(r);
    if (!alive()) {
      toast(`${a.label}: ${(RP_STATUS[r.status] || [r.status])[0].toLowerCase()}.`, null, { tone: r.status === 'succeeded' ? 'success' : 'danger', title: 'Response action' });
      return;
    }
    const done = el('button', { type: 'button', class: 'btn btn--primary', onclick: close }, 'Done');
    show('Result', a.label, rpRunDetail(r), [done]);
    done.focus();
  };

  await load();
}

// ---------- the Response actions page (admins) ----------
const rpPage = { cfg: null, loading: null, runs: null };

pageHooks.push((name) => { if (name === 'respond') rpLoad(); });
$('rp-refresh').addEventListener('click', () => rpLoad());
$('rp-add').addEventListener('click', () => rpAddDialog());

async function rpLoad() {
  const body = $('rp-body');
  if (!rpPage.cfg) {
    fill(body, el('div', { class: 'card' }, el('div', { class: 'card__body rp-sk' }, ...[0, 1, 2].map(() => el('div', { class: 'rp-sk__row' },
      el('span', { class: 'skeleton', style: 'width:32px;height:32px' }), el('div', {}, el('span', { class: 'skeleton', style: 'width:40%' }), el('span', { class: 'skeleton', style: 'width:70%' })))))));
  }
  try {
    const [cfg, runs] = await Promise.all([api('api/respond/config'), api('api/respond/runs?limit=20').catch(() => ({ runs: null }))]);
    rpPage.cfg = cfg;
    rpPage.runs = runs.runs;
  } catch (e) {
    fill(body, el('div', { class: 'card' }, el('div', { class: 'empty', 'data-tone': 'danger' },
      el('span', { class: 'empty__icon' }, icon('circle-alert')), el('div', { class: 'empty__title' }, 'Couldn’t load the response actions'),
      el('p', { class: 'empty__text' }, sentence(e.message)),
      el('div', { class: 'empty__actions' }, el('button', { type: 'button', class: 'btn btn--secondary btn--sm', onclick: () => rpLoad() }, icon('refresh-cw'), 'Try again')))));
    return;
  }
  rpRender();
}

function rpRender() {
  const cfg = rpPage.cfg;
  const acts = cfg.actions || [];
  const list = acts.length ? el('ul', { class: 'rp-actions', role: 'list' }, ...acts.map((v, i) => rpActionRow(v, i)))
    : el('div', { class: 'rp-start' },
      el('div', { class: 'empty empty--compact' }, el('span', { class: 'empty__icon' }, icon('zap')),
        el('div', { class: 'empty__title' }, 'No response actions yet'),
        el('p', { class: 'empty__text' }, 'Start from a template. Analysts then see the action under Respond on a finding or a case.')),
      rpTemplateGrid(cfg));
  fill($('rp-body'),
    cfg.file_error ? el('div', { class: 'alert rp-gap', 'data-tone': 'danger', role: 'alert' }, icon('circle-alert'),
      el('div', {}, el('b', {}, 'The response actions file can’t be read'), el('p', {}, sentence(cfg.file_error)), el('p', {}, 'Nothing can run, and saving is refused until the file is fixed: ', el('span', { class: 'mono' }, cfg.file)))) : null,
    el('section', { class: 'card rp-gap', 'aria-labelledby': 'rp-list-head' },
      el('div', { class: 'card__head' }, el('div', {}, el('h3', { class: 'card__title', id: 'rp-list-head' }, 'Actions ', el('span', { class: 'count' }, String(acts.length))),
        el('p', { class: 'card__sub' }, 'Analysts run them from a finding or a case. Each run is confirmed, checked and written to the audit log.')),
      el('div', { class: 'card__actions' }, rpDocLink('', 'Guide'))),
      el('div', { class: 'card__body' }, list)),
    el('div', { class: 'rp-info' }, rpScriptsCard(cfg), rpDirectoryCard(cfg), rpRecentCard()));
}

function rpActionRow(v, i) {
  const [kindLabel, kindIcon] = RP_KIND[v.kind] || [v.kind, 'zap'];
  const locked = (v.locked || []).length ? `The ${v.locked.join(' and ')} could not be decrypted on this server; enter ${v.locked.length > 1 ? 'them' : 'it'} again.` : '';
  const problem = locked || v.problem;
  const more = dxMenu('More for ' + (v.label || v.name), [
    { icon: 'play', label: 'Test', run: () => rpEditDialog(i, null, { test: true }) },
    { icon: v.enabled ? 'power' : 'play', label: v.enabled ? 'Turn off' : 'Turn on', run: () => rpToggle(i) },
    'sep',
    { icon: 'trash-2', label: 'Delete', danger: true, run: () => rpDelete(i) },
  ]);
  return el('li', { class: 'rp-action' + (v.enabled ? '' : ' is-off'), 'data-name': v.name },
    el('span', { class: 'rp-action__icon', 'data-kind': v.kind }, icon(kindIcon)),
    el('div', { class: 'rp-action__main' },
      el('div', { class: 'rp-action__title' }, el('span', {}, v.label || v.name),
        v.enabled ? null : el('span', { class: 'badge' }, 'Off'),
        v.disruptive ? el('span', { class: 'badge badge--warning' }, 'Disruptive') : null),
      el('p', { class: 'rp-action__what' }, rpWhatPlain(v.what, v.target)),
      el('p', { class: 'rp-action__meta' }, el('span', { class: 'mono' }, v.name), dotsep(), kindLabel, dotsep(), 'acts on ' + (v.target === 'any' ? 'any target' : rpNoun(v.target))),
      problem ? el('p', { class: 'field-error rp-action__problem' }, icon('circle-alert'), problem) : null),
    el('div', { class: 'rp-action__acts' },
      el('button', { type: 'button', class: 'btn btn--secondary btn--sm', onclick: () => rpEditDialog(i), 'aria-label': 'Edit ' + (v.label || v.name) }, icon('pencil'), el('span', { class: 'hide-sm' }, 'Edit')),
      more));
}

function rpScriptsCard(cfg) {
  const scripts = cfg.scripts || [];
  return el('section', { class: 'card', 'aria-labelledby': 'rp-scripts-head' },
    el('div', { class: 'card__head' }, el('h3', { class: 'card__title', id: 'rp-scripts-head' }, 'Scripts folder')),
    el('div', { class: 'card__body rp-card-body' },
      el('p', { class: 'mono rp-path' }, cfg.scripts_dir),
      el('p', { class: 'muted' }, 'Script actions run only programs in this folder, so whoever can change actions here still can’t run anything else on the server. Put scripts there with an administrator account; change the folder in signalith.yaml (response.scripts_dir).'),
      scripts.length ? el('ul', { class: 'rp-scripts', role: 'list' }, ...scripts.map((s) => el('li', { class: 'mono' }, icon('file-code', 'icon--xs'), s)))
        : el('p', { class: 'hint' }, icon('info'), 'No scripts in it yet.'),
      rpDocLink('run-a-script', 'Example isolate scripts')));
}

function rpDirectoryCard(cfg) {
  const d = cfg.directory || {};
  return el('section', { class: 'card', 'aria-labelledby': 'rp-dir-head' },
    el('div', { class: 'card__head' }, el('h3', { class: 'card__title', id: 'rp-dir-head' }, 'Directory')),
    el('div', { class: 'card__body rp-card-body' },
      d.configured ? el('dl', { class: 'kv rp-kv' },
        el('dt', {}, 'Server'), el('dd', { class: 'mono' }, d.url),
        d.domain ? el('dt', {}, 'Domain') : null, d.domain ? el('dd', {}, d.domain) : null,
        el('dt', {}, 'Type'), el('dd', {}, d.type === 'ad' ? 'Active Directory' : 'LDAP'),
        d.service_account ? el('dt', {}, 'Account') : null, d.service_account ? el('dd', { class: 'mono rp-break' }, d.service_account) : null)
        : el('p', { class: 'muted' }, 'Disable-account actions use the directory set up under Users › Directory sign-in. None is set up yet.'),
      d.problem ? el('p', { class: 'field-error' }, icon('circle-alert'), d.problem) : d.configured ? el('p', { class: 'hint' }, icon('circle-check'), 'Encrypted, so accounts can be changed.') : null,
      rpDocLink('disable-a-directory-account', 'Delegate “Read/Write userAccountControl”')));
}

function rpRecentCard() {
  const runs = rpPage.runs;
  if (!runs) return null;
  return el('section', { class: 'card rp-recent', 'aria-labelledby': 'rp-recent-head' },
    el('div', { class: 'card__head' }, el('h3', { class: 'card__title', id: 'rp-recent-head' }, 'Recent runs')),
    el('div', { class: 'card__body rp-card-body' }, runs.length ? rpRunList(runs, {})
      : el('p', { class: 'muted' }, 'Runs appear here, newest first. Every run is kept in the audit log.')));
}

// ----- saving the list -----
// rpInputOf is a saved action as the page sends it back: every setting,
// and each secret it has kept as it is.
function rpInputOf(v) {
  const { headers, password_set: pw, bind_password_set: bpw, locked, problem, what, ...conn } = v;
  return { ...conn, headers: (headers || []).filter((h) => h.set).map((h) => ({ name: h.name, keep: true })), password: { keep: !!pw }, bind_password: { keep: !!bpw } };
}
async function rpSaveList(list) {
  const cfg = await api('api/respond/config', { actions: list }, 'PUT');
  rpPage.cfg = cfg;
  rpRender();
  return cfg;
}
async function rpToggle(i) {
  const list = rpPage.cfg.actions.map(rpInputOf);
  list[i].enabled = !list[i].enabled;
  try {
    await rpSaveList(list);
    toast(`${list[i].label || list[i].name} is ${list[i].enabled ? 'on' : 'off'}.`);
  } catch (e) { toastError('Couldn’t change the action', e); }
}
async function rpDelete(i) {
  const v = rpPage.cfg.actions[i];
  if (!(await caseConfirm({ title: `Delete ${v.label || v.name}?`, text: 'Analysts can no longer run it. Past runs stay in the audit log.', confirm: 'Delete action' }))) return;
  const list = rpPage.cfg.actions.map(rpInputOf);
  list.splice(i, 1);
  try {
    await rpSaveList(list);
    toast(`Deleted ${v.label || v.name}.`);
  } catch (e) { toastError('Couldn’t delete the action', e); }
}

// ----- adding: templates -----
const RP_BLANK = [
  { id: 'blank-http', title: 'HTTP request', icon: 'send', description: 'Call any API or webhook with the target in the URL or body.', connector: { kind: 'http', target: 'ip', method: 'POST', body_format: 'json', body: '{"ip": "{{.ip}}"}' }, help: '', docs: 'send-a-webhook' },
  { id: 'blank-script', title: 'Script', icon: 'terminal', description: 'Run a program from the scripts folder with the target.', connector: { kind: 'script', target: 'host', timeout_seconds: 60 }, help: '', docs: 'run-a-script' },
  { id: 'blank-ldap', title: 'Directory account', icon: 'user-x', description: 'Disable or enable an account in the directory.', connector: { kind: 'disable_user', target: 'user', operation: 'disable' }, help: '', docs: 'disable-a-directory-account' },
];
function rpTemplateGrid(cfg, after) {
  const card = (t) => el('button', { type: 'button', class: 'rp-tpl', onclick: () => { if (after) after(); rpEditDialog(-1, t); } },
    el('span', { class: 'rp-tpl__icon' }, icon(t.icon || 'zap')),
    el('span', { class: 'rp-tpl__main' }, el('span', { class: 'rp-tpl__title' }, t.title), el('span', { class: 'rp-tpl__desc' }, t.description)));
  return el('div', { class: 'rp-tpls' },
    el('h4', { class: 'section-title' }, 'Templates'),
    el('div', { class: 'rp-tpl-grid' }, ...(cfg.templates || []).map(card)),
    el('h4', { class: 'section-title' }, 'From scratch'),
    el('div', { class: 'rp-tpl-grid' }, ...RP_BLANK.map(card)));
}
function rpAddDialog() {
  if (!rpPage.cfg) return;
  const d = modalDialog('rp-add-dialog');
  d.classList.add('rp-dialog', 'rp-dialog--wide');
  fill(d, modalHead('rp-add-dialog', 'Add a response action', 'Start from a template; you can change everything before saving.', () => d.close()),
    el('div', { class: 'modal__body' }, rpTemplateGrid(rpPage.cfg, () => d.close())),
    el('div', { class: 'modal__foot' }, el('button', { type: 'button', class: 'btn btn--ghost', onclick: () => d.close() }, 'Cancel')));
  d.showModal();
  const first = d.querySelector('.rp-tpl');
  if (first) first.focus();
}

// ----- the edit form -----
const rpSlug = (s) => String(s || '').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 63);
function rpUniqueName(base) {
  const names = new Set((rpPage.cfg.actions || []).map((a) => a.name));
  let n = base || 'action';
  for (let i = 2; names.has(n); i++) n = (base || 'action').slice(0, 60) + '-' + i;
  return n;
}

// rpEditDialog edits action i, or adds one from template tpl (i < 0).
function rpEditDialog(i, tpl, opts = {}) {
  const cfg = rpPage.cfg;
  const saved = i >= 0 ? cfg.actions[i] : null;
  const src = saved || { ...tpl.connector };
  const edit = !!saved;
  const d = modalDialog('rp-edit');
  d.classList.add('rp-dialog', 'rp-dialog--wide');
  const p = 'rp-e';
  const input = (name, attrs = {}) => el('input', { id: `${p}-${name}`, class: 'input', type: 'text', autocomplete: 'off', spellcheck: 'false', ...attrs });
  const field = (label, ctl, hint, extra) => el('div', { class: 'field', 'data-field': extra || '' }, el('label', { class: 'label', for: ctl.id }, label), ctl, hint ? el('p', { class: 'hint' }, hint) : null);
  const sel = (name, options, value) => {
    const s = el('select', { id: `${p}-${name}`, class: 'select select--block' }, ...options.map(([v, l]) => el('option', { value: v }, l)));
    s.value = value;
    return s;
  };
  const kind = src.kind;

  // common
  const label = input('label', { placeholder: 'Block IP on the firewall', maxlength: '100' });
  label.value = src.label || '';
  const name = input('name', { class: 'input mono', placeholder: 'block-ip', maxlength: '63' });
  name.value = edit ? src.name : rpUniqueName(src.name || rpSlug(src.label) || '');
  let nameTouched = edit || !!src.name;
  name.addEventListener('input', () => { nameTouched = true; });
  label.addEventListener('input', () => { if (!nameTouched) name.value = rpUniqueName(rpSlug(label.value)); });
  const desc = input('desc', { placeholder: 'Shown to analysts under the label', maxlength: '500' });
  desc.value = src.description || '';
  const target = sel('target', [['ip', 'IP address'], ['domain', 'Domain'], ['user', 'User'], ['host', 'Host'], ['any', 'Any of these']], src.target || 'ip');
  if (kind === 'disable_user') { target.value = 'user'; target.disabled = true; }
  const disruptive = el('input', { id: `${p}-disruptive`, type: 'checkbox' });
  disruptive.checked = src.disruptive == null ? !(kind === 'disable_user' && src.operation === 'enable') : !!src.disruptive;
  const enabled = el('input', { id: `${p}-enabled`, type: 'checkbox' });
  enabled.checked = src.enabled == null ? true : !!src.enabled;

  // secrets: saved ones are kept, replaced or removed, never shown
  const secret = (key, labelText, isSet, placeholder) => {
    const s = { key, saved: !!isSet, state: 'keep', input: el('input', { id: `${p}-${key}`, class: 'input mono', type: 'password', autocomplete: 'new-password', spellcheck: 'false', placeholder: placeholder || '' }) };
    s.box = el('div', { class: 'field', 'data-field': key });
    s.draw = () => {
      if (!s.saved) { fill(s.box, el('label', { class: 'label', for: s.input.id }, s.labelText), s.input); return; }
      const btn = (text, st) => el('button', { type: 'button', class: 'btn btn--ghost btn--sm', onclick: () => { s.state = st; s.draw(); (s.box.querySelector('input') || s.box.querySelector('button')).focus(); } }, text);
      fill(s.box, el('span', { class: 'label' }, s.labelText),
        s.state === 'replace' ? el('div', { class: 'rp-secret' }, s.input, btn('Cancel', 'keep'))
          : s.state === 'remove' ? el('div', { class: 'rp-secret' }, el('span', { class: 'rp-secret__state' }, 'Removed when you save'), btn('Undo', 'keep'))
            : el('div', { class: 'rp-secret' }, el('span', { class: 'rp-secret__state' }, icon('lock', 'icon--xs'), 'Saved, hidden'), btn('Replace', 'replace'), btn('Remove', 'remove')));
    };
    s.labelText = labelText;
    s.value = () => {
      if (s.saved && s.state === 'keep') return { keep: true };
      if (s.saved && s.state === 'remove') return {};
      if (s.input.value) return { value: s.input.value };
      // Replace, left empty, keeps the saved one.
      return s.saved ? { keep: true } : {};
    };
    s.draw();
    return s;
  };

  // HTTP
  const method = sel('method', ['POST', 'PUT', 'PATCH', 'DELETE', 'GET'].map((m) => [m, m]), src.method || 'POST');
  const url = input('url', { class: 'input mono', type: 'url', inputmode: 'url', placeholder: 'https://firewall.example.lan/api/…/{{.ip}}' });
  url.value = src.url || '';
  let bodyFormat = src.body_format || 'json';
  const bodyFmt = el('div', { class: 'seg seg--sm', role: 'group', 'aria-label': 'Body format' });
  const drawFmt = () => fill(bodyFmt, ...[['json', 'JSON'], ['form', 'Form'], ['text', 'Text']].map(([v, l]) =>
    el('button', { type: 'button', 'aria-pressed': String(bodyFormat === v), onclick: () => { bodyFormat = v; drawFmt(); } }, l)));
  drawFmt();
  const body = el('textarea', { id: `${p}-body`, class: 'textarea mono rp-code', rows: '4', spellcheck: 'false' });
  body.value = src.body || '';
  let lastText = body;
  [url, body].forEach((n) => n.addEventListener('focus', () => { lastText = n; }));
  const chips = el('div', { class: 'rp-chips rp-ph' }, el('span', { class: 'hint' }, 'Insert:'), ...(cfg.placeholders || []).map((ph) =>
    el('button', { type: 'button', class: 'rp-chip mono', title: `Insert {{.${ph}}}`, onclick: () => {
      const n = lastText;
      const t = `{{.${ph}}}`;
      const a = n.selectionStart == null ? n.value.length : n.selectionStart;
      const b = n.selectionEnd == null ? a : n.selectionEnd;
      n.value = n.value.slice(0, a) + t + n.value.slice(b);
      n.focus();
      n.setSelectionRange(a + t.length, a + t.length);
    } }, ph)));
  const savedHeaders = edit ? (saved.headers || []).map((h) => secret('h-' + h.name, h.name, h.set)) : [];
  savedHeaders.forEach((s, j) => { s.name = saved.headers[j].name; s.input.setAttribute('aria-label', `New value for ${s.name}`); s.labelText = s.name; s.draw(); });
  const newHeaders = [];
  const headersBox = el('div', { class: 'rp-headers', 'data-field': 'headers' });
  const addHeader = (n = '', hint = '') => {
    const j = newHeaders.length;
    const h = { name: input('hn-' + j, { class: 'input mono', placeholder: 'X-Api-Key', 'aria-label': 'Header name' }), value: input('hv-' + j, { class: 'input mono', type: 'password', autocomplete: 'new-password', placeholder: hint || 'Value', 'aria-label': 'Header value' }) };
    h.name.value = n;
    newHeaders.push(h);
    drawHeaders();
    return h;
  };
  const drawHeaders = () => fill(headersBox, el('span', { class: 'label' }, 'Headers'),
    ...savedHeaders.map((s) => s.box),
    ...newHeaders.filter((h) => !h.gone).map((h) => el('div', { class: 'rp-header' }, h.name, h.value,
      el('button', { type: 'button', class: 'btn btn--ghost btn--icon btn--sm', 'aria-label': 'Remove this header', title: 'Remove', onclick: () => { h.gone = true; drawHeaders(); url.focus(); } }, icon('x')))),
    el('button', { type: 'button', class: 'link-btn', onclick: () => addHeader().name.focus() }, icon('plus', 'icon--sm'), 'Add a header'),
    el('p', { class: 'hint' }, 'Sent with each request and saved encrypted. For a token, use Authorization with Bearer and the token.'));
  if (!edit) for (const h of tpl.headers || []) addHeader(h.name, h.hint);
  drawHeaders();
  const user = input('user', { placeholder: tpl && tpl.username_label ? tpl.username_label : 'Only for Basic sign-in' });
  user.value = src.username || '';
  const pass = secret('password', tpl && tpl.password_label ? tpl.password_label : 'Password', saved && saved.password_set);
  const ca = el('textarea', { id: `${p}-ca`, class: 'textarea mono rp-code', rows: '3', spellcheck: 'false', placeholder: '-----BEGIN CERTIFICATE-----' });
  ca.value = src.ca_cert || '';
  const loop = el('input', { id: `${p}-loop`, type: 'checkbox' });
  loop.checked = !!src.allow_loopback;

  // script
  const program = input('program', { class: 'input mono', list: `${p}-scripts`, placeholder: 'isolate-host.sh' });
  program.value = src.program || '';
  const timeout = input('timeout', { type: 'number', min: '1', max: String(cfg.max_timeout || 600), inputmode: 'numeric' });
  timeout.value = String(src.timeout_seconds || 60);

  // directory
  let operation = src.operation || 'disable';
  const opSeg = el('div', { class: 'seg', role: 'group', 'aria-label': 'What it does' });
  const drawOp = () => fill(opSeg, ...[['disable', 'Disable the account'], ['enable', 'Enable it again']].map(([v, l]) =>
    el('button', { type: 'button', 'aria-pressed': String(operation === v), onclick: () => { operation = v; drawOp(); } }, icon(v === 'disable' ? 'user-x' : 'user-check'), l)));
  drawOp();
  const dir = cfg.directory || {};
  const bindDN = input('bind-dn', { class: 'input mono', placeholder: dir.service_account || 'CN=svc-signalith,OU=Service,DC=corp,DC=example,DC=com' });
  bindDN.value = src.bind_dn || '';
  const bindPw = secret('bind_password', 'Password of that account', saved && saved.bind_password_set);
  const attr = input('attr', { class: 'input mono', placeholder: 'nsAccountLock' });
  attr.value = src.disable_attribute || '';
  const attrVal = input('attr-val', { class: 'input mono', placeholder: 'TRUE' });
  attrVal.value = src.disable_value || '';

  // the kind's own settings
  let kindPart;
  if (kind === 'http') {
    kindPart = [
      el('div', { class: 'rp-row rp-row--url' }, field('Method', method), field('URL', url, 'Placeholders go in the path or query, never in the server name.', 'url')),
      el('div', { class: 'field', 'data-field': 'body' }, el('div', { class: 'label-row' }, el('label', { class: 'label', for: body.id }, 'Body'), bodyFmt), body,
        el('p', { class: 'hint' }, 'Values are escaped for JSON, form or text, so a target can’t change the request. In JSON, put placeholders inside quotes.')),
      chips, headersBox,
      el('div', { class: 'form-grid' }, field(tpl && tpl.username_label ? tpl.username_label : 'User name', user, null, 'username'), pass.box),
      el('details', { class: 'rp-adv' }, el('summary', {}, icon('chevron-right', 'rp-chev'), 'Advanced'),
        el('div', { class: 'rp-adv__body' },
          field('Trust this CA certificate', ca, 'Paste the PEM of a private CA. The system’s CAs are always trusted; checking certificates can’t be turned off.', 'ca_cert'),
          el('label', { class: 'check' }, loop, 'Allow this server’s own addresses (localhost). Cloud metadata addresses stay blocked.'))),
    ];
  } else if (kind === 'script') {
    kindPart = [
      el('datalist', { id: `${p}-scripts` }, ...(cfg.scripts || []).map((s) => el('option', { value: s }))),
      field('Program', program, el('span', {}, 'A file in ', el('span', { class: 'mono' }, cfg.scripts_dir), '. It gets the target as its only argument and in SIGNALITH_TARGET; no shell is used.'), 'program'),
      (cfg.scripts || []).length ? null : el('div', { class: 'alert', 'data-tone': 'warning' }, icon('triangle-alert'), el('div', {}, el('b', {}, 'The scripts folder is empty'), el('p', {}, 'Copy the script there first, with an administrator account. ', rpDocLink('run-a-script', 'Examples')))),
      el('div', { class: 'form-grid' }, field('Stop it after (seconds)', timeout, `Up to ${cfg.max_timeout || 600}. Output past 16 KB is cut.`, 'timeout_seconds')),
    ];
  } else {
    const isAD = !dir.type || dir.type === 'ad';
    kindPart = [
      el('div', { class: 'field', 'data-field': 'operation' }, el('span', { class: 'label' }, 'What it does'), opSeg),
      dir.configured ? (dir.problem ? el('div', { class: 'alert', 'data-tone': 'warning' }, icon('triangle-alert'), el('div', {}, el('b', {}, 'The directory can’t be changed yet'), el('p', {}, dir.problem)))
        : el('p', { class: 'hint' }, icon('circle-check'), `Uses the directory at ${dir.url}` + (dir.domain ? ` (${dir.domain})` : '') + '.'))
        : el('div', { class: 'alert', 'data-tone': 'warning' }, icon('triangle-alert'), el('div', {}, el('b', {}, 'No directory is set up'), el('p', {}, 'Set it up under Users › Directory sign-in first.'))),
      field('Account that changes accounts (bind DN)', bindDN, dir.service_account ? 'Leave empty to use the directory sign-in account. Either way it must be delegated “Read/Write userAccountControl” on the users’ OU.' : 'An account delegated “Read/Write userAccountControl” on the users’ OU.', 'bind_dn'),
      bindPw.box,
      isAD ? null : el('div', { class: 'form-grid' },
        field('Attribute that locks an account', attr, 'Such as nsAccountLock (389 DS) or pwdAccountLockedTime.', 'disable_attribute'),
        field('Value that locks it', attrVal, 'Enabling removes the attribute.', 'disable_value')),
      el('p', { class: 'hint' }, icon('info'), 'It refuses to change its own account. Writes need LDAPS or StartTLS.'),
    ];
  }

  // test
  const testTarget = input('test-target', { class: 'input mono', placeholder: RP_SAMPLE[target.value] || 'jdoe' });
  const testBtn = el('button', { type: 'button', class: 'btn btn--secondary' }, icon('play'), 'Test');
  const sendBtn = kind === 'http' ? el('button', { type: 'button', class: 'btn btn--ghost' }, icon('send'), 'Send test request') : null;
  const testOut = el('div', { class: 'rp-test-out', 'aria-live': 'polite' });
  const testHint = { http: 'Test fills in the request and checks the address, without sending it. Send test request really sends it, and it is recorded.', script: 'Test checks the program can run. It does not run it.', disable_user: 'Test signs in and looks the user up. Nothing is changed.' }[kind];
  const testPart = el('section', { class: 'rp-test' },
    el('h4', { class: 'section-title' }, 'Test'),
    el('div', { class: 'rp-test__row' }, el('label', { class: 'sr-only', for: testTarget.id }, 'Test target'), testTarget, testBtn, sendBtn),
    el('p', { class: 'hint' }, testHint), testOut);

  // the request
  const errBox = el('div', { class: 'alert hidden', 'data-tone': 'danger', role: 'alert' });
  const value = () => {
    const c = {
      name: name.value.trim(), label: label.value.trim(), description: desc.value.trim(), kind,
      target: kind === 'disable_user' ? 'user' : target.value, disruptive: disruptive.checked, enabled: enabled.checked,
      headers: [], password: {}, bind_password: {},
    };
    if (kind === 'http') {
      Object.assign(c, { method: method.value, url: url.value.trim(), body: method.value === 'GET' ? '' : body.value, body_format: bodyFormat, username: user.value.trim(), ca_cert: ca.value.trim(), allow_loopback: loop.checked, password: pass.value() });
      for (const s of savedHeaders) {
        const v = s.value();
        if (v.keep || v.value) c.headers.push({ name: s.name, ...v });
      }
      for (const h of newHeaders) if (!h.gone && (h.name.value.trim() || h.value.value)) c.headers.push({ name: h.name.value.trim(), value: h.value.value });
    } else if (kind === 'script') {
      Object.assign(c, { program: program.value.trim(), timeout_seconds: parseInt(timeout.value, 10) || 0 });
    } else {
      Object.assign(c, { operation, bind_dn: bindDN.value.trim(), bind_password: bindPw.value(), disable_attribute: attr.value.trim(), disable_value: attrVal.value.trim() });
    }
    return c;
  };
  const clearErrors = () => {
    errBox.classList.add('hidden');
    d.querySelectorAll('.rp-ferr').forEach((n) => n.remove());
    d.querySelectorAll('[aria-invalid]').forEach((n) => n.removeAttribute('aria-invalid'));
  };
  const showErrors = (title, e) => {
    const probs = e.problems || [];
    fill(errBox, icon('circle-alert'), el('div', {}, el('b', {}, title),
      probs.length ? el('ul', { class: 'rp-probs' }, ...probs.map((x) => el('li', {}, sentence(x.message)))) : el('p', {}, sentence(e.message))));
    errBox.classList.remove('hidden');
    let first = null;
    for (const x of probs) {
      const f = d.querySelector(`[data-field="${CSS.escape(x.field)}"]`) || ({ name, label, description: desc, target }[x.field] || {}).parentNode;
      if (!f || !f.append) continue;
      const ctl = f.querySelector('input, select, textarea');
      if (ctl) { ctl.setAttribute('aria-invalid', 'true'); first = first || ctl; }
      f.append(el('p', { class: 'field-error rp-ferr' }, icon('circle-alert'), sentence(x.message)));
    }
    errBox.scrollIntoView({ block: 'nearest' });
    if (first) first.focus();
  };
  const doTest = async (send) => {
    clearErrors();
    const btn = send ? sendBtn : testBtn;
    if (send && !(await caseConfirm({ title: 'Send a real request?', text: `This sends the request to ${url.value.trim() || 'the server'} for ${testTarget.value.trim() || 'the sample target'} now. It is recorded in the audit log like any run.`, confirm: 'Send it' }))) return;
    const done = busy(btn, send ? 'Sending…' : 'Testing…');
    fill(testOut);
    let rep;
    try {
      rep = await api('api/respond/test', { action: value(), target: testTarget.value.trim(), send }, 'POST');
    } catch (e) {
      done();
      if (e.problems) showErrors('Fix these first', e);
      else fill(testOut, el('p', { class: 'field-error' }, icon('circle-alert'), sentence(e.message)));
      return;
    }
    done();
    fill(testOut,
      el('ol', { class: 'rp-steps' }, ...(rep.steps || []).map((s) => el('li', { class: s.ok ? 'is-ok' : 'is-bad' }, icon(s.ok ? 'circle-check' : 'circle-x'), el('span', {}, s.message)))),
      rep.request ? el('pre', { class: 'rp-pre rp-req', tabindex: '0' }, `${rep.request.method} ${rep.request.url}\n${(rep.request.headers || []).join('\n')}${rep.request.body ? '\n\n' + rep.request.body : ''}`) : null,
      rep.run && rep.run.output ? el('div', { class: 'rp-output' }, el('div', { class: 'section-title' }, 'Response'), el('pre', { class: 'rp-pre', tabindex: '0' }, rep.run.output)) : null,
      el('div', { class: 'alert', 'data-tone': rep.ok ? 'success' : 'danger', role: rep.ok ? 'status' : 'alert' }, icon(rep.ok ? 'circle-check' : 'circle-alert'), el('div', {}, el('b', {}, rep.ok ? 'Looks good' : 'It failed'), el('p', {}, rep.message))));
  };
  testBtn.addEventListener('click', () => doTest(false));
  if (sendBtn) sendBtn.addEventListener('click', () => doTest(true));

  const saveBtn = el('button', { type: 'submit', class: 'btn btn--primary', form: `${p}-form` }, edit ? 'Save changes' : 'Add action');
  const form = el('form', { id: `${p}-form`, class: 'rp-edit', novalidate: '' }, errBox,
    tpl && tpl.help ? el('div', { class: 'callout' }, icon('lightbulb'), el('div', {}, tpl.help, ' ', tpl.docs ? rpDocLink(tpl.docs, 'Step by step') : null)) : null,
    el('div', { class: 'form-grid' }, field('Label', label, 'What analysts see in the Respond menu.', 'label'),
      edit ? el('div', { class: 'field' }, el('span', { class: 'label' }, 'Name'), el('p', { class: 'mono rp-name' }, src.name)) : field('Name', name, 'Used in the audit log; can’t change later.', 'name')),
    field('Description', desc, null, 'description'),
    el('div', { class: 'form-grid' }, field('Acts on', target, kind === 'disable_user' ? 'A directory account.' : 'Analysts’ input is checked strictly as this kind.', 'target'),
      el('div', { class: 'field rp-switches' },
        el('label', { class: 'switch' }, disruptive, 'Disruptive: needs a reason and a firm confirm'),
        el('label', { class: 'switch' }, enabled, 'On: analysts can run it'))),
    el('div', { class: 'rp-kind' }, el('h4', { class: 'section-title' }, icon((RP_KIND[kind] || ['', 'zap'])[1], 'icon--xs'), (RP_KIND[kind] || [kind])[0]), ...kindPart.filter(Boolean)),
    testPart);
  form.addEventListener('submit', async (ev) => {
    ev.preventDefault();
    clearErrors();
    const c = value();
    if (!c.label) { showErrors('Fix these first', { problems: [{ field: 'label', message: 'enter a label' }] }); return; }
    const list = cfg.actions.map(rpInputOf);
    if (edit) list[i] = c; else list.push(c);
    const done = busy(saveBtn, 'Saving…');
    try {
      await rpSaveList(list);
    } catch (e) {
      done();
      showErrors(edit ? 'Couldn’t save the action' : 'Couldn’t add the action', e);
      return;
    }
    d.close();
    toast(edit ? `Saved ${c.label}.` : `Added ${c.label}. Analysts see it under Respond.`);
  });
  fill(d, modalHead('rp-edit', edit ? 'Edit response action' : 'New response action', edit ? (saved.label || saved.name) : (tpl.title || ''), () => d.close()),
    el('div', { class: 'modal__body' }, form),
    el('div', { class: 'modal__foot' }, el('button', { type: 'button', class: 'btn btn--ghost', onclick: () => d.close() }, 'Cancel'), saveBtn));
  target.addEventListener('change', () => { testTarget.placeholder = RP_SAMPLE[target.value] || 'target'; });
  d.showModal();
  if (opts.test) { testTarget.focus(); testTarget.scrollIntoView({ block: 'center' }); } else label.focus();
}
