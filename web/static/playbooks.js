// Playbooks (admins) and Approvals (analysts). A playbook runs steps in
// order when a detection raises a finding: notify a channel, run a
// response action (after an analyst approves it, for disruptive ones),
// open a case, set the finding. The server keeps the playbooks in one
// file and takes them whole (PUT api/playbooks); the server that runs the
// background jobs runs them. Steps that wait for approval are listed on
// the Approvals page, with the same sentence the Respond dialog shows;
// the navigation counts them, and a finding that has one says so. See
// docs/playbooks.md.
'use strict';

(function () {
  const PB = { data: null, runs: null, runsErr: '', seq: 0, detections: null, deferred: false };
  const AP = { waiting: null, recent: null, err: '', seq: 0, notes: new Map(), busy: new Set() };

  const STEP = {
    notify: { icon: 'bell', label: 'Notify a channel', short: 'Notify' },
    action: { icon: 'zap', label: 'Run a response action', short: 'Action' },
    open_case: { icon: 'briefcase', label: 'Open a case', short: 'Open case' },
    set_finding: { icon: 'flag', label: 'Set the finding', short: 'Set finding' },
  };
  const STEP_ORDER = ['notify', 'action', 'open_case', 'set_finding'];
  const TARGETS = [['src', 'Source (src)'], ['dest', 'Destination (dest)'], ['user', 'User (user)'], ['host', 'Host (host)'],
    ['entity', 'First entity that fits'], ['fixed', 'A fixed value']];
  const LEAST = [['critical', 'Critical'], ['high', 'High'], ['medium', 'Medium'], ['low', 'Low'], ['informational', 'Any']];
  const STATUS = {
    running: ['Running', 'accent'], waiting_approval: ['Waiting for approval', 'warning'], approved: ['Approved', 'accent'],
    queued: ['Queued', 'accent'], succeeded: ['Done', 'success'], failed: ['Failed', 'danger'], rejected: ['Rejected', ''],
    expired: ['Expired', ''], interrupted: ['Interrupted', 'warning'],
  };
  const FINDING_STATUS = { new: 'New', in_progress: 'In progress', pending: 'Pending', resolved: 'Resolved', closed: 'Closed' };

  const plural = (n, one, many) => `${n.toLocaleString()} ${n === 1 ? one : many || one + 's'}`;
  const joinAnd = (l) => (l.length <= 1 ? l.join('') : l.slice(0, -1).join(', ') + ' and ' + l[l.length - 1]);
  const manage = () => !!(PB.data && PB.data.manage);
  const statusBadge = (s) => { const [l, tone] = STATUS[s] || [s, '']; return el('span', { class: 'badge' + (tone ? ' badge--' + tone : '') }, l); };
  const newID = () => [...crypto.getRandomValues(new Uint8Array(6))].map((x) => x.toString(16).padStart(2, '0')).join('');
  const channel = (id) => ((PB.data && PB.data.channels) || []).find((c) => c.id === id);
  const action = (name) => ((PB.data && PB.data.actions) || []).find((a) => a.name === name);
  const lowerFirst = (s) => (s && !/^.[A-Z]/.test(s) ? s[0].toLowerCase() + s.slice(1) : s);
  const until = (t) => {
    const s = (new Date(t).getTime() - Date.now()) / 1000;
    if (!isFinite(s) || s <= 0) return 'expired';
    if (s < 3600) return `${Math.max(1, Math.round(s / 60))}m left`;
    return `${Math.round(s / 3600)}h left`;
  };
  const openFinding = (id) => {
    showPage('findings');
    if (typeof showFinding === 'function') showFinding(id);
  };

  pageHooks.push((name) => {
    if (name === 'playbooks') loadPlaybooks();
    if (name === 'approvals') loadApprovals();
  });
  $('pb-add').addEventListener('click', () => openEditor(null));

  // ================= the Playbooks page =================
  const box = () => $('pb-page');

  async function loadPlaybooks(quiet) {
    const seq = ++PB.seq;
    if (!PB.data && !quiet) {
      box().setAttribute('aria-busy', 'true');
      fill(box(), el('div', { class: 'card pb-skel' }, dxSkel('40%'), dxSkel('75%'), dxSkel('60%')));
    }
    try {
      const [d, r] = await Promise.all([
        api('api/playbooks'),
        api('api/playbooks/runs?limit=25').catch((e) => ({ error: e.message })),
      ]);
      if (seq !== PB.seq) return;
      PB.data = d;
      PB.runs = r.runs || null;
      PB.runsErr = r.error || '';
      renderPlaybooks();
    } catch (e) {
      if (seq !== PB.seq) return;
      box().removeAttribute('aria-busy');
      fill(box(), el('div', { class: 'card' }, dxEmpty({ tone: 'danger', icon: 'circle-alert', title: 'Couldn’t load playbooks', text: e.message, action: dxRetry(() => loadPlaybooks()) })));
    }
  }

  function renderPlaybooks() {
    const d = PB.data;
    box().removeAttribute('aria-busy');
    if (box().querySelector('details.menu[open]')) { PB.deferred = true; return; }
    PB.deferred = false;
    $('pb-add').classList.toggle('hidden', !manage() || !d.playbooks.length);
    fill(box(), pageNotes(), d.playbooks.length ? listCard() : emptyCard(), d.playbooks.length || (PB.runs || []).length ? runsCard() : null);
  }

  function pageNotes() {
    const d = PB.data;
    const list = [];
    if (d.file_error) list.push(dxAlert('danger', 'No playbook starts until the playbooks file is fixed.', d.file_error));
    if (!d.manage && !d.file_error) {
      list.push(dxAlert('info', d.runs_on ? `Playbooks are set up on ${d.runs_on}.` : 'Playbooks are set up on another server.',
        d.runs_on ? `Only the server that runs the background jobs runs playbooks, with its own. Change them on ${d.runs_on}.` : d.manage_why || ''));
    }
    if (d.manage && !d.respond && !d.notify) list.push(dxAlert('info', 'Nothing to run yet.', 'Set up a notification channel or a response action first; playbooks use them.'));
    return list.length ? el('div', { class: 'pb-notes' }, ...list) : null;
  }

  // The empty page offers three ways to start, filled in as far as this
  // server's channels and actions allow.
  function emptyCard() {
    const d = PB.data;
    const ch = d.channels[0];
    const act = d.actions.find((a) => a.target === 'ip' || a.target === 'any') || d.actions[0];
    const starts = [
      ch ? { icon: 'bell', title: 'Tell the team', text: `Notify ${ch.label} and open a case for high and critical findings.`,
        steps: [{ kind: 'notify', channel: ch.id }, { kind: 'open_case', title: '{title}' }] } : null,
      act ? { icon: 'zap', title: 'Contain after approval', text: `${act.label} on the source once an analyst approves, then open a case.`,
        steps: [...(ch ? [{ kind: 'notify', channel: ch.id }] : []), { kind: 'action', action: act.name, target: act.target === 'user' ? 'user' : 'src', needs_approval: true }, { kind: 'open_case', title: '{title}' }] } : null,
      { icon: 'plus', title: 'Start from scratch', text: 'Pick the detections and add the steps yourself.', steps: [] },
    ].filter(Boolean);
    return el('div', { class: 'card' }, el('div', { class: 'empty pb-empty' },
      el('span', { class: 'empty__icon' }, icon('list-checks')),
      el('div', { class: 'empty__title' }, 'No playbooks yet'),
      el('p', { class: 'empty__text' }, manage()
        ? 'A playbook does the first steps for you when a detection fires: tell the team, block an address once an analyst approves, open a case.'
        : 'Playbooks are set up on the server that runs the background jobs.'),
      manage() ? el('div', { class: 'pb-starts' }, ...starts.map((s) => el('button', { class: 'pb-start', type: 'button',
        onclick: () => openEditor(null, { steps: s.steps, name: s.steps.length ? s.title : '' }) },
      el('span', { class: 'pb-start__icon' }, icon(s.icon)),
      el('span', { class: 'pb-start__text' }, el('b', {}, s.title), el('span', {}, s.text))))) : null));
  }

  function listCard() {
    const d = PB.data;
    const on = d.playbooks.filter((p) => p.enabled).length;
    return el('section', { class: 'card', 'aria-labelledby': 'pb-list-title' },
      el('div', { class: 'card__head' }, el('div', {},
        el('h3', { class: 'card__title', id: 'pb-list-title' }, 'Playbooks'),
        el('p', { class: 'card__sub' }, `${on} of ${d.playbooks.length} on · each runs once per finding, in order`))),
      el('ul', { class: 'pb-list' }, ...d.playbooks.map(playbookRow)));
  }

  function runStats(p) {
    const runs = (PB.runs || []).filter((r) => r.playbook_id === p.id);
    const bits = [];
    const waiting = runs.filter((r) => r.status === 'waiting_approval').length;
    if (waiting) bits.push(el('a', { href: '#approvals', 'data-page': 'approvals', class: 'pb-wait-link' }, `${waiting} waiting for approval`));
    if (runs.length) bits.push(el('span', {}, `last ran ${ago(runs[0].created)}`));
    return bits;
  }

  function playbookRow(p) {
    const sw = el('input', { type: 'checkbox', role: 'switch', 'aria-label': `${p.name}: on` });
    sw.checked = p.enabled;
    sw.disabled = !manage();
    sw.addEventListener('change', async () => {
      sw.disabled = true;
      const ok = await save((list) => { list.find((x) => x.id === p.id).enabled = sw.checked; },
        sw.checked ? `${p.name} is on. Findings raised from now on start it.` : `${p.name} is off.`);
      if (ok !== true) { sw.checked = !sw.checked; sw.disabled = false; }
    });
    const menu = manage() ? dxMenu('Actions for ' + p.name, [
      { icon: 'pencil', label: 'Edit', run: () => openEditor(p) },
      { icon: 'copy', label: 'Duplicate', run: () => openEditor(null, { ...strip(p), name: p.name + ' copy', enabled: false }) },
      'sep', { icon: 'trash-2', label: 'Delete', danger: true, run: () => remove(p) }]) : null;
    if (menu) {
      menu.querySelector('summary').classList.add('btn--sm');
      menu.addEventListener('toggle', () => { if (!menu.open && PB.deferred) setTimeout(renderPlaybooks); });
    }
    const stats = runStats(p);
    return el('li', { class: 'pb-row' + (p.enabled ? '' : ' is-off') },
      el('label', { class: 'switch pb-row__switch' }, sw),
      el('div', { class: 'pb-row__main' },
        el('div', { class: 'pb-row__name' }, manage() ? el('button', { type: 'button', class: 'pb-row__open', onclick: () => openEditor(p) }, p.name) : p.name,
          p.enabled ? null : el('span', { class: 'badge badge--outline' }, 'Off')),
        el('p', { class: 'pb-row__sum' }, p.summary),
        chain(p.steps),
        stats.length ? el('div', { class: 'pb-row__meta' }, ...stats.flatMap((b, i) => (i ? [el('span', { class: 'dotsep', 'aria-hidden': 'true' }), b] : [b]))) : null),
      menu);
  }

  // chain draws the steps as a row of numbered chips.
  function chain(steps) {
    if (!steps.length) return null;
    return el('ol', { class: 'pb-chain', 'aria-label': 'Steps' }, ...steps.map((s, i) => el('li', { class: 'pb-chip', 'data-kind': s.kind },
      el('span', { class: 'pb-chip__n' }, String(i + 1)), icon(STEP[s.kind] ? STEP[s.kind].icon : 'circle-dot'),
      el('span', { class: 'pb-chip__text' }, chipText(s)),
      s.kind === 'action' && s.needs_approval ? el('span', { class: 'pb-chip__gate', title: 'Waits for an analyst to approve it' }, icon('user-check'), el('span', { class: 'sr-only' }, ' after approval')) : null)));
  }

  function chipText(s) {
    switch (s.kind) {
      case 'notify': { const c = channel(s.channel); return c ? c.label : 'Deleted channel'; }
      case 'action': { const a = action(s.action); return a ? a.label : s.action; }
      case 'open_case': return s.reuse ? 'Open or add to case' : 'Open a case';
      case 'set_finding': return [s.status ? FINDING_STATUS[s.status] : '', s.owner ? '→ ' + s.owner : ''].filter(Boolean).join(' ') || 'Set finding';
    }
    return s.kind;
  }

  function runsCard() {
    const list = PB.runs || [];
    const head = el('div', { class: 'card__head' }, el('div', {},
      el('h3', { class: 'card__title', id: 'pb-runs-title' }, 'Recent runs'),
      el('p', { class: 'card__sub' }, 'What playbooks did, newest first · kept for 90 days')),
    el('div', { class: 'card__actions' }, el('button', { class: 'btn btn--ghost btn--sm btn--icon', type: 'button', title: 'Refresh', 'aria-label': 'Refresh runs', onclick: () => loadPlaybooks(true) }, icon('refresh-cw'))));
    let body;
    if (PB.runsErr) body = dxEmpty({ compact: true, tone: 'danger', icon: 'circle-alert', title: 'Couldn’t load runs', text: PB.runsErr, action: dxRetry(() => loadPlaybooks(true)) });
    else if (!list.length) {
      body = el('div', { class: 'empty empty--compact' }, el('div', { class: 'empty__title' }, 'No runs yet'),
        el('p', { class: 'empty__text' }, 'Runs show up here when a new finding matches a playbook that is on.'));
    } else {
      body = el('ul', { class: 'pb-runs' }, ...list.map(runRow));
    }
    return el('section', { class: 'card', 'aria-labelledby': 'pb-runs-title' }, head, body);
  }

  function runRow(r) {
    const steps = (r.playbook && r.playbook.steps) || [];
    const done = new Set((r.steps || []).filter((s) => s.status === 'succeeded').map((s) => s.step)).size;
    const last = (r.steps || [])[r.steps.length - 1];
    const detail = r.status === 'waiting_approval' && r.approval ? r.approval.what
      : r.error || (last && r.status !== 'succeeded' ? last.text : `${done} of ${plural(steps.length, 'step')} done`);
    return el('li', { class: 'pb-run' },
      el('div', { class: 'pb-run__main' },
        el('div', { class: 'pb-run__title' }, r.urgency ? sevBadge(r.urgency) : null,
          el('button', { type: 'button', class: 'pb-run__finding', title: 'Open the finding', onclick: () => openFinding(r.finding_id) }, r.finding_title || r.finding_id)),
        el('div', { class: 'pb-run__sub' }, el('span', {}, r.playbook_name), el('span', { class: 'dotsep', 'aria-hidden': 'true' }),
          el('span', { title: fmtTime(r.created) }, ago(r.created)), r.case_id ? el('span', { class: 'dotsep', 'aria-hidden': 'true' }) : null,
          r.case_id ? el('a', { href: '#cases', onclick: (ev) => { ev.preventDefault(); openCase(r.case_id); } }, r.case_id) : null)),
      el('div', { class: 'pb-run__state' }, statusBadge(r.status), el('p', { class: 'pb-run__detail', title: detail }, detail)));
  }

  // ---------- saving ----------
  // strip is a playbook as the server takes it back.
  function strip(p) {
    return {
      id: p.id, name: p.name, enabled: p.enabled, approval_channel: p.approval_channel || '',
      trigger: { detections: [...(p.trigger.detections || [])], min_urgency: p.trigger.min_urgency || 'high', include_sample: !!p.trigger.include_sample },
      steps: (p.steps || []).map((s) => ({ ...s })),
    };
  }

  async function save(change, done, opts = {}) {
    const list = PB.data.playbooks.map(strip);
    change(list);
    try {
      PB.data = await api('api/playbooks', { revision: PB.data.revision, playbooks: list }, 'PUT');
    } catch (e) {
      if (opts.quiet) return e;
      toastError(e.status === 409 ? 'The playbooks changed elsewhere' : 'Couldn’t save', e);
      if (e.status === 409) loadPlaybooks(true);
      return false;
    }
    renderPlaybooks();
    if (done) toast(done);
    return true;
  }

  async function remove(p) {
    const ok = await confirm({ title: `Delete ${p.name}?`, text: 'It stops starting for new findings. Runs already waiting for approval can still be approved or rejected.', confirm: 'Delete playbook' });
    if (ok) await save((list) => list.splice(list.findIndex((x) => x.id === p.id), 1), `Deleted ${p.name}.`);
  }

  function confirm(o) {
    const dlg = $('pb-confirm');
    return new Promise((resolve) => {
      let result = false;
      const cancel = el('button', { class: 'btn btn--ghost', type: 'button', onclick: () => dlg.close() }, 'Cancel');
      const ok = el('button', { class: 'btn btn--danger', type: 'button', onclick: () => { result = true; dlg.close(); } }, o.confirm);
      dlg.onclose = () => resolve(result);
      fill(dlg, el('div', { class: 'modal__head' }, el('div', {}, el('h2', { class: 'modal__title', id: 'pb-confirm-title' }, o.title), el('p', { class: 'modal__desc', id: 'pb-confirm-desc' }, o.text))),
        el('div', { class: 'modal__foot' }, cancel, ok));
      dlg.showModal();
      cancel.focus();
    });
  }

  async function loadDetections() {
    if (PB.detections) return PB.detections;
    try {
      const r = await api('api/detections');
      // A title such as "Brute force against $dest$ from $src$" reads as
      // "Brute force": it stops before the first value it would fill in.
      const plain = (d) => (d.title || '').split(/\s+(?:against|from|to|on|of|by|for|in|at|via|with)?\s*\$/i)[0].trim() || d.id;
      PB.detections = (r.detections || []).map((d) => ({ id: d.id, title: plain(d) }));
    } catch (_) { PB.detections = []; }
    return PB.detections;
  }

  // summary says what a playbook does while it is edited, in the words
  // the server uses once it is saved, with detection titles.
  function summary(st) {
    const dets = st.trigger.detections.map((id) => { const d = (PB.detections || []).find((x) => x.id === id); return d ? d.title : id; });
    const when = dets.length === 0 ? 'any detection' : dets.length <= 3 ? joinAnd(dets) : `any of ${dets.length} detections`;
    const u = st.trigger.min_urgency;
    let head = 'When ' + when + ' fires' + (u === 'informational' ? '' : u === 'critical' ? ' at critical' : ` at ${u} or above`);
    if (st.trigger.include_sample) head += ' (sample data too)';
    if (!st.steps.length) return head + ': nothing yet. Add a step.';
    return head + ': ' + st.steps.map(phrase).join(', then ') + '.';
  }

  function phrase(s) {
    switch (s.kind) {
      case 'notify': { const c = channel(s.channel); return c ? 'notify ' + c.label : 'notify a channel'; }
      case 'action': {
        const a = action(s.action);
        if (!a) return 'run an action';
        const ip = a.target === 'ip';
        const where = { src: ip ? 'the source IP' : 'the source', dest: ip ? 'the destination IP' : 'the destination', user: 'the user', host: 'the host', fixed: s.value || 'a fixed value' }[s.target]
          || ({ ip: 'the finding’s IP', domain: 'the finding’s domain', user: 'the finding’s user', host: 'the finding’s host' }[a.target] || 'the finding’s first entity');
        return lowerFirst(a.label) + ' for ' + where + (s.needs_approval || a.disruptive ? ' after approval' : '');
      }
      case 'open_case': return (s.reuse ? 'open a case (or add to the one it opened)' : 'open a case') + (s.owner ? ' for ' + s.owner : '');
      case 'set_finding': {
        const bits = [];
        if (s.status) bits.push('set the finding to ' + FINDING_STATUS[s.status]);
        if (s.owner) bits.push((bits.length ? 'assign it to ' : 'assign the finding to ') + s.owner);
        return bits.join(' and ') || 'set the finding';
      }
    }
    return s.kind;
  }

  // ---------- the editor ----------
  let fieldSeq = 0;
  const fid = (p) => `pb-f${++fieldSeq}-${p}`;
  const input = (p, attrs = {}) => el('input', { class: 'input', id: fid(p), type: 'text', autocomplete: 'off', spellcheck: 'false', ...attrs });
  function field(label, control, hint, name) {
    const hid = hint ? control.id + '-hint' : null;
    if (hid) control.setAttribute('aria-describedby', hid);
    return el('div', { class: 'field', 'data-field': name || '' }, el('label', { class: 'label', for: control.id }, label), control, hint ? el('p', { class: 'hint', id: hid }, hint) : null);
  }
  function selectEl(p, options, value) {
    const s = el('select', { class: 'select select--block', id: fid(p) });
    for (const [v, l] of options) {
      const o = el('option', { value: v }, l);
      if (v === value) o.selected = true;
      s.append(o);
    }
    return s;
  }

  async function openEditor(p, preset) {
    const dlg = $('pb-dialog');
    const edit = !!p;
    const st = edit ? strip(p) : {
      id: newID(), name: '', enabled: true, approval_channel: '', trigger: { detections: [], min_urgency: 'high', include_sample: false }, steps: [],
      ...(preset ? strip({ trigger: {}, ...preset, id: newID() }) : {}),
    };
    if (!edit && preset) { st.enabled = preset.enabled !== false; st.name = preset.name || ''; }
    const dets = await loadDetections();
    const msg = el('div', { class: 'pb-msg', 'aria-live': 'polite' });
    const preview = el('p', { class: 'pb-preview__text' });
    const sync = () => { preview.textContent = summary(st); drawApproval(); };

    const name = input('name', { maxlength: '80', placeholder: 'Brute force response' });
    name.value = st.name;
    name.addEventListener('input', () => { st.name = name.value; });

    // --- when ---
    const urg = el('div', { class: 'seg pb-urg', role: 'group', 'aria-label': 'Least urgency' });
    const drawUrg = () => fill(urg, ...LEAST.map(([v, l]) => el('button', { type: 'button', 'aria-pressed': String(st.trigger.min_urgency === v),
      onclick: () => { st.trigger.min_urgency = v; drawUrg(); sync(); } }, v === 'informational' ? null : el('span', { class: 'pb-sevdot', 'data-sev': v }), l)));
    drawUrg();
    let some = st.trigger.detections.length > 0;
    const detSeg = el('div', { class: 'seg', role: 'group', 'aria-label': 'Detections' });
    const detFind = el('input', { class: 'input input--sm', type: 'search', placeholder: 'Find a detection', 'aria-label': 'Find a detection', autocomplete: 'off', spellcheck: 'false' });
    const detList = el('div', { class: 'pb-detlist' });
    const detBox = el('div', { class: 'pb-dets' }, detFind, detList);
    const drawDetList = () => {
      const q = detFind.value.trim().toLowerCase();
      const known = new Set(dets.map((d) => d.id));
      const all = [...dets, ...st.trigger.detections.filter((x) => !known.has(x)).map((x) => ({ id: x, title: x }))];
      const shown = all.filter((d) => !q || d.id.toLowerCase().includes(q) || d.title.toLowerCase().includes(q));
      fill(detList, ...shown.slice(0, 200).map((d) => {
        const cb = el('input', { type: 'checkbox' });
        cb.checked = st.trigger.detections.includes(d.id);
        cb.addEventListener('change', () => {
          st.trigger.detections = cb.checked ? [...st.trigger.detections, d.id] : st.trigger.detections.filter((x) => x !== d.id);
          sync();
        });
        return el('label', { class: 'check pb-det' }, cb, el('span', { class: 'pb-det__text' }, el('span', { class: 'pb-det__title' }, d.title), el('span', { class: 'pb-det__id mono' }, d.id)));
      }), shown.length ? null : el('p', { class: 'hint pb-det__none' }, q ? 'No detection matches.' : 'No detections yet.'));
    };
    detFind.addEventListener('input', drawDetList);
    const drawDetSeg = () => {
      fill(detSeg, ...[[false, 'Any detection'], [true, 'Only some']].map(([v, l]) => el('button', { type: 'button', 'aria-pressed': String(some === v),
        onclick: () => { some = v; if (!v) st.trigger.detections = []; drawDetSeg(); drawDetList(); sync(); if (v) detFind.focus(); } }, l)));
      detBox.hidden = !some;
    };
    drawDetSeg();
    drawDetList();
    const sample = el('input', { type: 'checkbox' });
    sample.checked = st.trigger.include_sample;
    sample.addEventListener('change', () => { st.trigger.include_sample = sample.checked; sync(); });

    // --- then: the steps ---
    const stepsBox = el('ol', { class: 'pb-steps' });
    const addMenu = dxMenu('Add a step', STEP_ORDER.map((k) => ({ icon: STEP[k].icon, label: STEP[k].label, run: () => addStep(k) })));
    const addSummary = addMenu.querySelector('summary');
    addSummary.className = 'btn btn--secondary btn--sm';
    fill(addSummary, icon('plus'), 'Add step');
    addMenu.classList.add('pb-add');
    const addStep = (kind) => {
      const s = { kind };
      if (kind === 'notify') s.channel = (PB.data.channels[0] || {}).id || '';
      if (kind === 'action') {
        const a = PB.data.actions[0];
        s.action = a ? a.name : '';
        s.target = a && a.target === 'user' ? 'user' : 'src';
        s.needs_approval = true;
      }
      if (kind === 'open_case') s.title = '{title}';
      if (kind === 'set_finding') s.status = 'in_progress';
      st.steps.push(s);
      drawSteps(st.steps.length - 1);
      sync();
    };
    const drawSteps = (focusIndex) => {
      fill(stepsBox, ...st.steps.map((s, i) => stepCard(s, i)));
      stepsBox.hidden = !st.steps.length;
      emptySteps.hidden = st.steps.length > 0;
      if (focusIndex != null) {
        const card = stepsBox.children[focusIndex];
        const ctl = card && card.querySelector('select, input');
        if (ctl) ctl.focus();
      }
    };
    const emptySteps = el('p', { class: 'pb-steps__empty' }, 'No steps yet. Add what should happen, in order.');
    const move = (i, by) => {
      const j = i + by;
      if (j < 0 || j >= st.steps.length) return;
      [st.steps[i], st.steps[j]] = [st.steps[j], st.steps[i]];
      drawSteps();
      sync();
      const btn = stepsBox.children[j].querySelector(by < 0 ? '[data-move="up"]' : '[data-move="down"]');
      (btn && !btn.disabled ? btn : stepsBox.children[j].querySelector('select, input')).focus();
    };

    function stepCard(s, i) {
      const k = STEP[s.kind] || { icon: 'circle-dot', label: s.kind };
      const body = el('div', { class: 'pb-step__body' });
      const f = (n) => `steps[${i}].${n}`;
      const changed = () => sync();
      if (s.kind === 'notify') {
        const chans = PB.data.channels;
        const sel = selectEl('ch', [...(chans.some((c) => c.id === s.channel) || !s.channel ? [] : [[s.channel, 'Deleted channel']]), ...chans.map((c) => [c.id, c.label])], s.channel);
        sel.addEventListener('change', () => { s.channel = sel.value; changed(); });
        body.append(chans.length || s.channel ? field('Channel', sel, null, f('channel'))
          : el('p', { class: 'hint' }, 'There are no notification channels yet. Add one on the ', el('a', { href: '#notify', 'data-page': 'notify' }, 'Notifications page'), '.'));
      } else if (s.kind === 'action') {
        const acts = PB.data.actions;
        const sel = selectEl('act', [...(acts.some((a) => a.name === s.action) || !s.action ? [] : [[s.action, s.action + ' (deleted)']]), ...acts.map((a) => [a.name, a.label])], s.action);
        const tgt = selectEl('tgt', TARGETS, s.target || 'src');
        const val = input('val', { placeholder: '203.0.113.7', value: s.value || '' });
        const valField = field('Value', val, null, f('value'));
        const appr = el('input', { type: 'checkbox' });
        const apprWrap = el('label', { class: 'check' }, appr, el('span', {}, 'Wait for an analyst to approve'));
        const what = el('p', { class: 'pb-what' });
        const drawAct = () => {
          const a = action(s.action);
          valField.hidden = s.target !== 'fixed';
          const forced = !!(a && a.disruptive);
          if (forced) s.needs_approval = true;
          appr.checked = !!s.needs_approval;
          appr.disabled = forced;
          apprWrap.title = forced ? 'Disruptive actions always wait for approval' : '';
          const sample = s.target === 'fixed' ? (s.value || 'the value') : { src: 'the source', dest: 'the destination', user: 'the user', host: 'the host', entity: 'the first entity that fits' }[s.target] || 'the target';
          fill(what, a ? el('span', {}, ...rpWhatSafe(a.what, sample)) : null,
            a && a.problem ? el('span', { class: 'pb-what__warn' }, ' ' + a.problem) : null,
            forced ? el('span', { class: 'pb-what__note' }, ' Disruptive: an analyst always approves it first.') : null);
        };
        sel.addEventListener('change', () => {
          s.action = sel.value;
          const a = action(s.action);
          if (a && a.target === 'user' && s.target !== 'fixed' && s.target !== 'entity') { s.target = 'user'; tgt.value = 'user'; }
          if (a && a.target !== 'user' && a.target !== 'any' && s.target === 'user') { s.target = 'src'; tgt.value = 'src'; }
          drawAct(); changed();
        });
        tgt.addEventListener('change', () => { s.target = tgt.value; drawAct(); changed(); if (s.target === 'fixed') val.focus(); });
        val.addEventListener('input', () => { s.value = val.value.trim(); drawAct(); changed(); });
        appr.addEventListener('change', () => { s.needs_approval = appr.checked; changed(); });
        if (!acts.length && !s.action) {
          body.append(el('p', { class: 'hint' }, 'There are no response actions yet. Add one on the ', el('a', { href: '#respond', 'data-page': 'respond' }, 'Response actions page'), '.'));
        } else {
          body.append(el('div', { class: 'pb-grid' }, field('Action', sel, null, f('action')), field('Target', tgt, null, f('target'))), valField, what,
            el('div', { class: 'field', 'data-field': f('needs_approval') }, apprWrap));
          drawAct();
        }
      } else if (s.kind === 'open_case') {
        const title = input('title', { maxlength: '200', placeholder: '{title}', value: s.title || '' });
        const owner = input('owner', { maxlength: '100', placeholder: 'Unassigned', value: s.owner || '' });
        const reuse = el('input', { type: 'checkbox' });
        reuse.checked = !!s.reuse;
        title.addEventListener('input', () => { s.title = title.value; changed(); });
        owner.addEventListener('input', () => { s.owner = owner.value.trim(); changed(); });
        reuse.addEventListener('change', () => { s.reuse = reuse.checked; changed(); });
        body.append(el('div', { class: 'pb-grid' }, field('Case title', title, null, f('title')), field('Owner', owner, null, f('owner'))),
          el('p', { class: 'hint' }, 'The title may use ', ...PB.data.placeholders.flatMap((ph, n) => [n ? ' ' : '', el('code', {}, ph)]), '.'),
          el('div', { class: 'field' }, el('label', { class: 'check' }, reuse, el('span', {}, 'Add later findings to the case this playbook opened, while it is open'))));
      } else if (s.kind === 'set_finding') {
        const status = selectEl('status', [['', 'Leave as it is'], ...PB.data.statuses.map((x) => [x, FINDING_STATUS[x] || x])], s.status || '');
        const owner = input('owner', { maxlength: '100', placeholder: 'Leave as it is', value: s.owner || '' });
        status.addEventListener('change', () => { s.status = status.value; changed(); });
        owner.addEventListener('input', () => { s.owner = owner.value.trim(); changed(); });
        body.append(el('div', { class: 'pb-grid' }, field('Status', status, null, f('status')), field('Owner', owner, null, f('owner'))));
      }
      const up = dxBtn('ghost', '', () => move(i, -1), { sm: true, icon: 'chevron-up', title: 'Move up', disabled: i === 0 });
      const down = dxBtn('ghost', '', () => move(i, 1), { sm: true, icon: 'chevron-down', title: 'Move down', disabled: i === st.steps.length - 1 });
      up.dataset.move = 'up';
      down.dataset.move = 'down';
      const del = dxBtn('ghost', '', () => {
        st.steps.splice(i, 1);
        drawSteps();
        sync();
        const next = stepsBox.children[Math.min(i, st.steps.length - 1)];
        (next ? next.querySelector('select, input') : addSummary).focus();
      }, { sm: true, icon: 'trash-2', title: 'Remove this step' });
      return el('li', { class: 'pb-step', 'data-kind': s.kind, 'data-field': `steps[${i}].kind` },
        el('div', { class: 'pb-step__head' },
          el('span', { class: 'pb-step__n', 'aria-hidden': 'true' }, String(i + 1)),
          el('span', { class: 'pb-step__icon' }, icon(k.icon)),
          el('span', { class: 'pb-step__title' }, k.label),
          el('span', { class: 'spacer' }), up, down, del),
        body);
    }

    // --- approvals channel ---
    const apprSel = selectEl('apch', [['', 'Don’t send a message'], ...PB.data.channels.map((c) => [c.id, c.label]),
      ...(st.approval_channel && !channel(st.approval_channel) ? [[st.approval_channel, 'Deleted channel']] : [])], st.approval_channel);
    apprSel.addEventListener('change', () => { st.approval_channel = apprSel.value; });
    const apprField = field('Ask for approval in', apprSel, `Steps that wait show on the Approvals page for ${PB.data.approval_hours} hours. Pick a channel to tell people too.`, 'approval_channel');
    const drawApproval = () => {
      apprField.hidden = !st.steps.some((s) => s.kind === 'action' && (s.needs_approval || (action(s.action) || {}).disruptive));
    };

    const on = el('input', { type: 'checkbox', role: 'switch' });
    on.checked = st.enabled;
    on.addEventListener('change', () => { st.enabled = on.checked; });
    const form = el('form', { class: 'pb-form', novalidate: '', autocomplete: 'off' });
    const saveBtn = el('button', { class: 'btn btn--primary', type: 'submit' }, edit ? 'Save changes' : 'Add playbook');
    form.addEventListener('submit', async (ev) => {
      ev.preventDefault();
      clearErrors(form);
      fill(msg);
      st.name = name.value.trim();
      saveBtn.disabled = true;
      const res = await save((list) => {
        const i = list.findIndex((x) => x.id === st.id);
        if (i >= 0) list[i] = st; else list.push(st);
      }, null, { quiet: true });
      saveBtn.disabled = false;
      if (res !== true) { showProblems(form, msg, res, 'playbook:' + st.id, edit ? 'Couldn’t save the playbook.' : 'Couldn’t add the playbook.'); return; }
      dlg.close();
      toast(edit ? `Saved ${st.name}.` : st.enabled ? `Added ${st.name}. Findings raised from now on start it.` : `Added ${st.name}. It’s off for now.`);
      loadPlaybooks(true);
    });

    const more = el('details', { class: 'pb-more' }, el('summary', {}, icon('chevron-right', 'pb-chev'), 'More options'),
      el('div', { class: 'pb-more__body' }, el('label', { class: 'check' }, sample, el('span', {}, 'Include sample data')),
        el('p', { class: 'hint' }, 'Findings from the one-click sample data are skipped unless this is on. Turn it on to try a playbook out; it still really runs its steps.')));
    if (st.trigger.include_sample) more.open = true;

    fill(form,
      el('div', { class: 'modal__body' }, msg,
        field('Name', name, null, 'name'),
        el('section', { class: 'pb-sec' }, el('h3', { class: 'pb-sec__title' }, 'When'),
          el('div', { class: 'field', 'data-field': 'trigger.detections' }, el('span', { class: 'label' }, 'A finding from'), detSeg, detBox),
          el('div', { class: 'field', 'data-field': 'trigger.min_urgency' }, el('span', { class: 'label' }, 'At least this urgent'), urg),
          more),
        el('section', { class: 'pb-sec', 'data-field': 'steps' }, el('div', { class: 'pb-sec__head' }, el('h3', { class: 'pb-sec__title' }, 'Then'), addMenu),
          stepsBox, emptySteps, apprField),
        el('div', { class: 'pb-preview' }, icon('list-checks'), el('div', {}, el('b', {}, 'This playbook'), preview))),
      el('div', { class: 'modal__foot pb-foot' }, el('label', { class: 'switch' }, on, el('span', {}, 'On')), el('span', { class: 'spacer' }),
        el('button', { class: 'btn btn--ghost', type: 'button', onclick: () => dlg.close() }, 'Cancel'), saveBtn));
    fill(dlg,
      el('div', { class: 'modal__head' }, el('div', {},
        el('h2', { class: 'modal__title', id: 'pb-dialog-title' }, edit ? `Edit ${p.name}` : 'Add a playbook'),
        el('p', { class: 'modal__desc' }, 'What to do, step by step, when a new finding matches. It runs once per finding; a step that fails stops it.')),
      el('button', { class: 'btn btn--ghost btn--icon btn--sm', type: 'button', 'aria-label': 'Close', onclick: () => dlg.close() }, icon('x'))),
      form);
    drawSteps();
    sync();
    dlg.showModal();
    name.focus();
  }

  // rpWhatSafe fills an action's sentence with the target, in bold, as
  // the Respond dialog does (respond.js), or plainly without it.
  function rpWhatSafe(what, target) {
    if (typeof rpWhat === 'function') return rpWhat(what, target);
    return [String(what || '').replace(/\{target\}/g, target)];
  }

  function clearErrors(form) {
    form.querySelectorAll('[data-error]').forEach((n) => n.remove());
    form.querySelectorAll('[aria-invalid]').forEach((n) => n.removeAttribute('aria-invalid'));
  }
  function showProblems(form, msgBox, e, where, fallback) {
    const others = [];
    let first = null;
    for (const p of e.problems || []) {
      const msg = p.message.replace(/^[^:]*: /, '').replace(/^step \d+: /, '');
      const f = p.where === where ? form.querySelector(`[data-field="${CSS.escape(p.field)}"]`) : null;
      if (f) {
        const ctl = f.querySelector('input, select, textarea');
        if (ctl) ctl.setAttribute('aria-invalid', 'true');
        f.append(el('p', { class: 'field-error', 'data-error': '' }, icon('circle-alert'), sentence(msg)));
        first = first || ctl;
      } else {
        others.push(sentence(p.message));
      }
    }
    if (!(e.problems || []).length) others.push(e.message);
    fill(msgBox, others.length ? dxAlert('danger', fallback, others.join(' ')) : null);
    if (first) first.focus();
    else msgBox.scrollIntoView({ block: 'nearest' });
  }

  // ================= the Approvals page =================
  const abox = () => $('ap-page');

  async function loadApprovals(quiet) {
    const seq = ++AP.seq;
    if (!AP.waiting && !quiet) {
      abox().setAttribute('aria-busy', 'true');
      fill(abox(), el('div', { class: 'card pb-skel' }, dxSkel('50%'), dxSkel('80%'), dxSkel('30%')));
    }
    try {
      const [w, r] = await Promise.all([
        api('api/playbooks/runs?status=waiting_approval&limit=100'),
        api('api/playbooks/runs?status=approved,queued,running,succeeded,failed,rejected,expired,interrupted&limit=100').catch(() => ({ runs: [] })),
      ]);
      if (seq !== AP.seq) return;
      // Oldest first: the one that expires soonest is on top.
      AP.waiting = (w.runs || []).slice().reverse();
      // Runs whose approval step was decided or expired, whatever came after.
      AP.recent = (r.runs || []).filter((x) => x.approval && (x.approval.decided_by || x.status === 'expired')).slice(0, 20);
      AP.err = '';
      setCount(w.waiting);
    } catch (e) {
      if (seq !== AP.seq) return;
      AP.err = e.status === 503 ? 'Playbooks are not available on this server.' : e.message;
    }
    renderApprovals();
  }

  function renderApprovals() {
    abox().removeAttribute('aria-busy');
    if (AP.err && !AP.waiting) {
      fill(abox(), el('div', { class: 'card' }, dxEmpty({ tone: 'danger', icon: 'circle-alert', title: 'Couldn’t load approvals', text: AP.err, action: dxRetry(() => loadApprovals()) })));
      return;
    }
    const live = AP.waiting.filter((r) => new Date(r.approval.expires).getTime() > Date.now());
    const a = document.activeElement;
    const key = a && abox().contains(a) && a.dataset ? a.dataset.key : '';
    fill(abox(),
      live.length ? el('ul', { class: 'ap-list', 'aria-label': 'Waiting for approval' }, ...live.map(approvalCard))
        : el('div', { class: 'card' }, el('div', { class: 'empty ap-empty' },
          el('span', { class: 'empty__icon ap-empty__icon' }, icon('circle-check')),
          el('div', { class: 'empty__title' }, 'Nothing waits for approval'),
          el('p', { class: 'empty__text' }, 'When a playbook reaches a step that needs a person’s say, it waits here. Nothing runs until someone approves it.'))),
      AP.recent && AP.recent.length ? recentCard() : null);
    if (key) { const again = abox().querySelector(`[data-key="${CSS.escape(key)}"]`); if (again) again.focus({ preventScroll: true }); }
  }

  function approvalCard(r) {
    const a = r.approval;
    const busy = AP.busy.has(r.id);
    const note = el('textarea', { class: 'textarea ap-note', rows: '2', maxlength: '1000', placeholder: 'Add a note (optional): why, a ticket number', 'aria-label': 'Note', 'data-key': 'n:' + r.id });
    note.value = AP.notes.get(r.id) || '';
    note.addEventListener('input', () => AP.notes.set(r.id, note.value));
    const approve = el('button', { class: 'btn btn--primary', type: 'button', 'data-key': 'a:' + r.id, onclick: () => decide(r, true) }, icon('check'), busy ? 'Working…' : 'Approve');
    const reject = el('button', { class: 'btn btn--secondary', type: 'button', 'data-key': 'r:' + r.id, onclick: () => decide(r, false) }, 'Reject');
    approve.disabled = reject.disabled = busy;
    const steps = (r.playbook && r.playbook.steps) || [];
    const left = until(a.expires);
    const soon = new Date(a.expires).getTime() - Date.now() < 2 * 3600 * 1000;
    return el('li', { class: 'card ap-card' },
      el('div', { class: 'ap-card__top' },
        r.urgency ? sevBadge(r.urgency) : null,
        el('button', { type: 'button', class: 'ap-card__finding', title: 'Open the finding', onclick: () => openFinding(r.finding_id) }, r.finding_title || r.finding_id),
        el('span', { class: 'spacer' }),
        el('span', { class: 'ap-card__left' + (soon ? ' is-soon' : ''), title: 'Expires ' + fmtTime(a.expires) }, icon('clock'), left)),
      el('div', { class: 'ap-card__ask' },
        el('span', { class: 'ap-card__icon' }, icon('zap')),
        el('div', { class: 'ap-card__what' },
          el('p', { class: 'ap-card__label' }, `Playbook ${r.playbook_name} wants to`),
          el('p', { class: 'ap-card__sentence' }, ...whatWithTarget(a.what, a.target)),
          el('p', { class: 'ap-card__meta' }, `Step ${a.step + 1} of ${steps.length}`, el('span', { class: 'dotsep', 'aria-hidden': 'true' }),
            `asked ${ago(a.requested)}`, steps.length > a.step + 1 ? el('span', { class: 'dotsep', 'aria-hidden': 'true' }) : null,
            steps.length > a.step + 1 ? `then ${steps.slice(a.step + 1).map(phrase).join(', then ')}` : null))),
      el('div', { class: 'ap-card__foot' }, note, el('div', { class: 'ap-card__btns' }, reject, approve)));
  }

  // whatWithTarget shows the sentence with its target in bold.
  function whatWithTarget(what, target) {
    const i = target ? what.indexOf(target) : -1;
    if (i < 0) return [what];
    return [what.slice(0, i), el('b', { class: 'rp-target' }, target), what.slice(i + target.length)];
  }

  async function decide(r, approve) {
    if (AP.busy.has(r.id)) return;
    AP.busy.add(r.id);
    renderApprovals();
    try {
      await api(`api/playbooks/runs/${encodeURIComponent(r.id)}/${approve ? 'approve' : 'reject'}`, { note: AP.notes.get(r.id) || '' }, 'POST');
      AP.notes.delete(r.id);
      toast(approve ? `Approved. The server running the jobs does it within a few seconds.` : 'Rejected. The playbook stopped for this finding.', null,
        { title: approve ? 'Approved' : 'Rejected' });
    } catch (e) {
      toastError(e.status === 409 ? 'Already decided' : approve ? 'Couldn’t approve' : 'Couldn’t reject', e);
    }
    AP.busy.delete(r.id);
    await loadApprovals(true);
  }

  function recentCard() {
    return el('section', { class: 'card', 'aria-labelledby': 'ap-recent-title' },
      el('div', { class: 'card__head' }, el('div', {}, el('h3', { class: 'card__title', id: 'ap-recent-title' }, 'Decided recently'),
        el('p', { class: 'card__sub' }, 'Approved, rejected and expired steps'))),
      el('ul', { class: 'pb-runs' }, ...AP.recent.map((r) => {
        const a = r.approval || {};
        const decision = r.status === 'expired' || r.status === 'rejected' ? r.status : 'approved';
        const who = decision === 'expired' ? 'Nobody approved it in time' : `${decision === 'approved' ? 'Approved' : 'Rejected'} by ${a.decided_by}` + (a.note ? `: ${a.note}` : '');
        return el('li', { class: 'pb-run' },
          el('div', { class: 'pb-run__main' },
            el('div', { class: 'pb-run__title' }, el('span', { class: 'pb-run__what' }, a.what || r.playbook_name)),
            el('div', { class: 'pb-run__sub' }, el('button', { type: 'button', class: 'pb-run__finding pb-run__finding--sub', onclick: () => openFinding(r.finding_id) }, r.finding_title || r.finding_id),
              el('span', { class: 'dotsep', 'aria-hidden': 'true' }), el('span', { title: fmtTime(a.decided || r.updated) }, ago(a.decided || r.updated)))),
          el('div', { class: 'pb-run__state' }, statusBadge(decision), el('p', { class: 'pb-run__detail', title: who }, who)));
      })));
  }

  // ================= the count in the navigation =================
  function setCount(n) {
    const b = $('approval-count');
    if (!b) return;
    b.textContent = n || '';
    b.classList.toggle('hidden', !n);
    b.title = n ? `${plural(n, 'step')} waiting for approval` : '';
  }
  async function refreshApprovalCount() {
    if (!can('analyst') || document.hidden) return;
    try {
      const r = await api('api/playbooks/runs?status=waiting_approval&limit=1');
      setCount(r.waiting);
    } catch (_) { setCount(0); }
  }
  meReady.then(() => { refreshApprovalCount(); setInterval(refreshApprovalCount, 60000); });
  // The page stays current while it is open.
  setInterval(() => {
    if (!document.hidden && currentPage === 'approvals' && !AP.busy.size && !abox().contains(document.activeElement)) loadApprovals(true);
  }, 30000);

  // ================= the banner on a finding =================
  // pbFindingBanner says, on a finding, that a playbook waits for
  // approval to act on it, with a link to the Approvals page.
  window.pbFindingBanner = function (findingId) {
    const holder = el('div', { class: 'pb-banner hidden' });
    if (!can('analyst')) return holder;
    api('api/playbooks/runs?status=waiting_approval&finding_id=' + encodeURIComponent(findingId)).then((r) => {
      const live = (r.runs || []).filter((x) => x.approval && new Date(x.approval.expires).getTime() > Date.now());
      if (!live.length) return;
      const x = live[0];
      fill(holder, el('div', { class: 'alert pb-banner__alert', 'data-tone': 'warning', role: 'status' }, icon('user-check'),
        el('div', { class: 'pb-banner__body' },
          el('b', {}, live.length === 1 ? `Playbook ${x.playbook_name} waits for approval` : `${live.length} playbook steps wait for approval`),
          el('p', {}, ...whatWithTarget(x.approval.what, x.approval.target))),
        el('a', { class: 'btn btn--secondary btn--sm', href: '#approvals', 'data-page': 'approvals' }, 'Review')));
      holder.classList.remove('hidden');
    }, () => { /* playbooks may be off on this server */ });
    return holder;
  };
  window.refreshApprovalCount = refreshApprovalCount;
})();
