// Settings > Behavior baselines (admins): what each check has learned of
// your users and hosts, its risk score and switch, the exceptions that
// hold its risk back, and how long it learns and remembers. The server
// that runs the background jobs learns every hour and adds risk events
// for what is new or rare, so they count in risk-based alerting with the
// detections' own. See docs/baselines.md.
'use strict';

(function () {
  // B.view is the last api/baselines reply; B.patch the unsaved changes:
  // top-level settings by key, and checks[id] = { off, score }.
  const B = { view: null, seq: 0, patch: { top: {}, checks: {} }, problems: [], saving: false };
  const page = $('bl-page');
  const DOCS = 'https://github.com/jrsamsanchez/signalith/blob/main/docs/baselines.md';
  const ENTITY = { user: ['user', 'users'], system: ['host', 'hosts'] };
  const VALUE_HINT = {
    'new-country': 'A country code, such as BR',
    'new-network': 'A network, such as AS15169',
    'unusual-hour': 'An hour, such as 03:00 UTC',
    'rare-process': 'A program, such as teamviewer.exe',
    'new-change': 'A change, such as CreateAccessKey',
    'data-volume': 'Leave empty: a host’s volume has no value',
  };

  pageHooks.push((name) => {
    if (name === 'baselines' && can('admin')) load();
  });

  leaveGuards.push((from, to, opts) => {
    if (from !== 'baselines' || !B.view || !dirty()) return true;
    caseConfirm({ title: 'Discard your changes?', text: 'Some behavior baseline settings were changed but not saved. Leave this page without saving?', confirm: 'Discard changes' })
      .then((ok) => {
        if (!ok) { const b = $('bl-save'); if (b) b.focus(); return; }
        discard();
        showPage(to, Object.assign({}, opts, { force: true }));
      });
    return false;
  });
  window.addEventListener('beforeunload', (ev) => {
    if (B.view && dirty()) { ev.preventDefault(); ev.returnValue = ''; }
  });

  async function load() {
    if (!B.view) skeleton();
    const seq = ++B.seq;
    try {
      const v = await api('api/baselines');
      if (seq !== B.seq) return;
      B.view = v;
      render();
    } catch (e) {
      if (seq !== B.seq) return;
      page.setAttribute('aria-busy', 'false');
      fill(page, el('div', { class: 'card' }, dxEmpty({ tone: 'danger', icon: 'circle-alert', compact: true, title: 'Couldn’t load the behavior baselines', text: sentence(e.message), action: dxRetry(() => load()) })));
    }
  }

  function skeleton() {
    page.setAttribute('aria-busy', 'true');
    fill(page, ...[1, 2].map(() => el('section', { class: 'card st-card st-skel' },
      el('div', { class: 'st-card__head' }, el('div', { class: 'st-card__heading' }, dxSkel('180px'))),
      el('div', { class: 'st-card__body' }, ...[1, 2, 3].map(() => el('div', { class: 'st-field' },
        el('div', { class: 'st-field__text' }, dxSkel('140px'), dxSkel('80%')), el('div', { class: 'st-field__control' }, dxSkel('100%'))))))));
  }

  // ---------- values ----------
  const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);
  const saved = () => B.view.settings;
  const savedTop = (k) => { const v = saved()[k]; return v == null ? (k === 'off' ? false : k === 'ip_database' ? '' : 0) : v; };
  const savedCheck = (id) => Object.assign({ off: false, score: 0 }, (saved().checks || {})[id] || {});
  const top = (k) => (k in B.patch.top ? B.patch.top[k] : savedTop(k));
  const checkOf = (id) => Object.assign(savedCheck(id), B.patch.checks[id] || {});
  const dirty = () => Object.keys(B.patch.top).length + Object.keys(B.patch.checks).length;

  function setTop(k, v) {
    if (same(v, savedTop(k))) delete B.patch.top[k]; else B.patch.top[k] = v;
    B.problems = [];
  }
  function setCheck(id, k, v) {
    const next = Object.assign({}, B.patch.checks[id] || {}, { [k]: v });
    const was = savedCheck(id);
    for (const key of Object.keys(next)) if (same(next[key], was[key])) delete next[key];
    if (Object.keys(next).length) B.patch.checks[id] = next; else delete B.patch.checks[id];
    B.problems = [];
  }
  function discard() { B.patch = { top: {}, checks: {} }; B.problems = []; }

  // settings returns the saved settings with the unsaved changes on top.
  function settings(extra) {
    const s = JSON.parse(JSON.stringify(saved()));
    Object.assign(s, B.patch.top);
    s.checks = s.checks || {};
    for (const [id, c] of Object.entries(B.patch.checks)) s.checks[id] = Object.assign({}, s.checks[id] || {}, c);
    return Object.assign(s, extra || {});
  }

  const plural = (n, one, many) => (n === 1 ? '1 ' + one : riNumText(n) + ' ' + many);
  const riNumText = (n) => Number(n || 0).toLocaleString();
  const day = (t) => new Date(t).toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
  const hourOf = (t) => new Date(t).toLocaleString(undefined, { month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit' });

  // ---------- drawing ----------
  function render() {
    page.setAttribute('aria-busy', 'false');
    const focusId = document.activeElement && page.contains(document.activeElement) ? document.activeElement.id : '';
    const parts = [statusCard(), checksCard(), exceptionsCard(), settingsCard()];
    if (B.problems.length) {
      parts.push(dxAlert('danger', 'Nothing was saved', '', el('ul', { class: 'st-problems' }, ...B.problems.map((p) => el('li', {}, sentence(p))))));
    }
    parts.push(saveBar());
    fill(page, ...parts);
    if (focusId && $(focusId)) $(focusId).focus();
  }

  // statusCard says whether the baselines learn, and how far they are.
  function statusCard() {
    const v = B.view;
    const off = !!saved().off;
    const behind = v.behind_s || 0;
    let state = 'on';
    let title = 'Watching your users and hosts';
    let text = 'Every hour, the server that runs the background jobs learns what each user and host usually does, and adds risk to the ones doing something new or rare. That risk shows on the Risk page and adds up with the detections’ own.';
    if (off) {
      state = 'off';
      title = 'Behavior baselines are off';
      text = 'Nothing is learned and no risk is added. Turn them on under Learning, below.';
    } else if (!v.through) {
      state = 'wait';
      title = 'Starting';
      text = 'The first round reads up to 30 days of the data you already have, so users and hosts with a history are judged from the start. It runs on the server that runs the background jobs.';
    } else if (behind > 3 * 3600) {
      state = 'wait';
      title = 'Catching up';
      text = 'Learned up to ' + hourOf(v.through) + '. Older hours are learned first, a day of data at a time.';
    } else {
      text = 'Learned up to ' + hourOf(v.through) + '. ' + text;
    }
    const kids = [el('div', { class: 'bl-status__row' },
      el('span', { class: 'bl-status__icon', 'data-state': state }, icon(state === 'off' ? 'circle-dashed' : state === 'wait' ? 'hourglass' : 'trending-up')),
      el('div', { class: 'bl-status__text' }, el('b', {}, title), el('p', {}, text)),
      el('a', { class: 'btn btn--ghost btn--sm bl-status__docs', href: DOCS, target: '_blank', rel: 'noopener noreferrer' },
        icon('book-open'), 'How it works', el('span', { class: 'sr-only' }, ' (opens in a new tab)')))];
    if (v.last_error && !off) {
      kids.push(dxAlert('danger', 'The last round failed' + (v.last_run ? ' (' + ago(v.last_run) + ')' : ''), sentence(v.last_error)));
    }
    return el('div', { class: 'card bl-status' }, ...kids);
  }

  function checksCard() {
    const rows = B.view.checks.map(checkRow);
    return el('section', { class: 'card st-card', 'aria-labelledby': 'bl-checks-title' },
      el('div', { class: 'st-card__head' }, el('div', { class: 'st-card__heading' },
        el('h3', { class: 'st-card__title', id: 'bl-checks-title' }, 'Checks'),
        el('p', { class: 'st-card__desc' }, 'Each check adds its risk score to the user or host, raised by its priority in your asset and identity lists. A user or host is only learned from for the learning period before it adds risk.'))),
      el('div', { class: 'st-card__body' }, ...rows));
  }

  function checkRow(c) {
    const cur = checkOf(c.id);
    const on = !top('off') && !cur.off;
    const [one, many] = ENTITY[c.entity] || ['', ''];
    const id = 'bl-' + c.id;
    const changed = !!B.patch.checks[c.id];
    const meta = [];
    if (c.profiles) meta.push(plural(c.profiles, one + ' learned', many + ' learned'));
    else if (on) meta.push('Nothing learned yet');
    if (c.raised) meta.push(plural(c.raised, 'risk event', 'risk events') + (c.last_raised ? ', last ' + ago(c.last_raised) : ''));
    if (c.excepted) meta.push(plural(c.excepted, 'held back by an exception', 'held back by exceptions'));
    if (c.learning_until && new Date(c.learning_until) > new Date()) meta.push('Learning until ' + day(c.learning_until));
    meta.push('From ' + c.data.replace('_', ' ') + ' data');
    const notes = [];
    if (c.waiting) notes.push(el('p', { class: 'st-warn' }, icon('triangle-alert'), el('span', {}, c.waiting)));
    if (c.capped) notes.push(el('p', { class: 'st-warn' }, icon('triangle-alert'), el('span', {}, `Some hours had more than ${B.view.defaults.max_raised_per_hour} new or rare ${many}, so only the first ${B.view.defaults.max_raised_per_hour} added risk (${riNumText(c.capped)} held back). A software rollout or a network change can do this.`)));
    if (c.full) notes.push(el('p', { class: 'st-warn' }, icon('triangle-alert'), el('span', {}, `It has learned the most ${many} it keeps (${riNumText(B.view.defaults.max_profiles)}); new ones are learned once old ones are forgotten.`)));
    if (c.truncated) notes.push(el('p', { class: 'st-warn' }, icon('triangle-alert'), el('span', {}, 'An hour had more combinations than one search returns, so some of it was not learned.')));

    const box = el('input', { type: 'checkbox', id: id + '-on', role: 'switch', 'aria-label': c.title });
    box.checked = !cur.off;
    if (top('off') || B.saving) box.disabled = true;
    box.addEventListener('change', () => { setCheck(c.id, 'off', !box.checked); render(); });
    const score = el('input', { type: 'number', id: id + '-score', class: 'input bl-score', min: '1', max: '1000', step: '1', inputmode: 'numeric',
      'aria-label': 'Risk score of ' + c.title, value: String(cur.score || c.default_score) });
    if (B.saving) score.disabled = true;
    score.addEventListener('input', () => {
      const n = parseInt(score.value, 10);
      setCheck(c.id, 'score', !n || n === c.default_score ? 0 : n);
      syncBar();
    });
    const menu = dxMenu('More for ' + c.title, [
      { icon: 'search', label: 'Show its risk in Search', run: () => openSearch('datamodel=Risk detection_id=baseline-' + c.id, '-7d') },
      'sep',
      { icon: 'rotate-ccw', label: 'Forget what it learned…', danger: true, run: () => reset(c) },
    ]);
    return el('div', { class: 'st-field bl-check' + (changed ? ' is-changed' : ''), 'data-on': on ? 'true' : 'false', id },
      el('div', { class: 'st-field__text' },
        el('div', { class: 'bl-check__head' }, el('span', { class: 'st-field__label' }, c.title), on ? null : el('span', { class: 'badge' }, 'Off')),
        el('p', { class: 'st-field__help' }, c.description),
        el('p', { class: 'bl-check__meta' }, ...meta.flatMap((m, i) => (i ? [el('span', { class: 'st-dot', 'aria-hidden': 'true' }), m] : [m]))),
        ...notes),
      el('div', { class: 'st-field__control bl-check__control' },
        el('label', { class: 'bl-score__wrap', for: id + '-score' }, el('span', { class: 'bl-score__label' }, 'Risk'), score),
        el('label', { class: 'switch st-switch' }, box, el('span', { class: 'st-switch__state', 'aria-hidden': 'true' }, cur.off ? 'Off' : 'On')),
        menu));
  }

  async function reset(c) {
    const [, many] = ENTITY[c.entity] || ['', ''];
    const ok = await caseConfirm({ title: 'Forget what “' + c.title + '” learned?',
      text: `It forgets the ${riNumText(c.profiles)} ${many} it learned and starts learning again from the next hour, so for the learning period it adds no risk. Risk it already added stays.`,
      confirm: 'Forget and relearn' });
    if (!ok) return;
    try {
      B.view = await api('api/baselines/' + encodeURIComponent(c.id) + '/reset', {});
      render();
      toast('It forgets at the next round, within the hour, then learns again.');
    } catch (e) { toastError('Couldn’t reset it', e); }
  }

  // ---------- exceptions ----------
  function exceptionsCard() {
    const list = saved().exceptions || [];
    const add = el('button', { type: 'button', class: 'btn btn--secondary btn--sm', id: 'bl-ex-add' }, icon('plus'), 'Add an exception');
    add.addEventListener('click', () => exceptionDialog({}));
    let body;
    if (!list.length) {
      body = el('p', { class: 'bl-empty' }, 'None yet. Add one for behavior that is new but expected, such as a team that travels, a VPN provider or a backup host. ' +
        'You can also add one from a baseline’s risk event on the Risk page with Mark as normal.');
    } else {
      body = el('ul', { class: 'bl-ex' }, ...list.map(exceptionRow));
    }
    return el('section', { class: 'card st-card', 'aria-labelledby': 'bl-ex-title' },
      el('div', { class: 'st-card__head' }, el('div', { class: 'st-card__heading' },
        el('h3', { class: 'st-card__title', id: 'bl-ex-title' }, 'Exceptions'),
        el('p', { class: 'st-card__desc' }, 'What matches an exception adds no risk. It is still learned, so it stays normal once the exception ends. Use * as a wildcard.')), add),
      body);
  }

  function exceptionRow(e) {
    const m = e.match || {};
    const check = m.baseline ? ((B.view.checks.find((c) => c.id === m.baseline) || {}).title || m.baseline) : 'Any check';
    const expired = e.until && new Date(e.until) <= new Date();
    const extra = Object.entries(m).filter(([k]) => !['baseline', 'risk_object', 'baseline_value'].includes(k));
    const chip = (label, v) => el('span', { class: 'bl-ex__chip' }, el('span', { class: 'bl-ex__k' }, label), v ? el('span', { class: 'mono' }, v) : el('span', { class: 'muted' }, 'any'));
    const meta = [(e.by ? 'Added by ' + e.by + ', ' : 'Added ') + day(e.added)];
    meta.push(e.until ? (expired ? 'ended ' : 'until ') + day(e.until) : 'no end');
    return el('li', { class: 'bl-ex__item', 'data-expired': expired ? 'true' : 'false' },
      el('div', { class: 'bl-ex__main' },
        el('div', { class: 'bl-ex__head' }, el('b', {}, check), expired ? el('span', { class: 'badge' }, 'Ended') : null),
        el('div', { class: 'bl-ex__chips' }, chip('User or host', m.risk_object), chip('Value', m.baseline_value),
          ...extra.map(([k, v]) => chip(k, v))),
        e.comment ? el('p', { class: 'bl-ex__why' }, e.comment) : null,
        el('p', { class: 'bl-ex__by' }, meta.join(', '))),
      dxMenu('More for this exception', [
        { icon: 'pencil', label: 'Edit…', run: () => exceptionDialog(e) },
        { icon: 'trash-2', label: 'Remove', danger: true, run: () => removeException(e) },
      ]));
  }

  // saveExceptions saves a new list of exceptions at once, with the
  // settings as saved; unsaved changes above stay unsaved.
  async function saveExceptions(list) {
    const body = { settings: Object.assign(JSON.parse(JSON.stringify(saved())), { exceptions: list }), version: B.view.version };
    B.view = await api('api/baselines', body, 'PUT');
    render();
  }

  async function removeException(e) {
    const ok = await caseConfirm({ title: 'Remove this exception?', text: 'What it matched adds risk again from the next hour.', confirm: 'Remove' });
    if (!ok) return;
    try {
      await saveExceptions((saved().exceptions || []).filter((x) => x.id !== e.id));
      toast('Exception removed.');
    } catch (err) { toastError('Couldn’t remove it', err); }
  }

  // exceptionDialog adds an exception, or edits e when it has an ID.
  function exceptionDialog(e) {
    const d = modalDialog('bl-ex-dialog');
    const m = e.match || {};
    const checkSel = el('select', { id: 'bl-ex-check', class: 'select select--block' },
      el('option', { value: '' }, 'Any check'), ...B.view.checks.map((c) => el('option', { value: c.id }, c.title)));
    checkSel.value = m.baseline || '';
    const who = el('input', { id: 'bl-ex-who', class: 'input mono', type: 'text', autocomplete: 'off', spellcheck: 'false', autocapitalize: 'none', placeholder: 'e.g. alice or svc-* (empty for anyone)', value: m.risk_object || '' });
    const what = el('input', { id: 'bl-ex-what', class: 'input mono', type: 'text', autocomplete: 'off', spellcheck: 'false', autocapitalize: 'none', value: m.baseline_value || '' });
    const why = el('textarea', { id: 'bl-ex-why', class: 'textarea', rows: '2', maxlength: '1000', placeholder: 'e.g. Sales team travels to Brazil every quarter' });
    why.value = e.comment || '';
    const until = el('input', { id: 'bl-ex-until', class: 'input', type: 'date', value: e.until ? new Date(e.until).toISOString().slice(0, 10) : '' });
    const whatHint = el('span', {});
    const syncHint = () => { what.placeholder = VALUE_HINT[checkSel.value] ? VALUE_HINT[checkSel.value] + (checkSel.value === 'data-volume' ? '' : ' (empty for anything)') : 'Empty for anything'; fill(whatHint, 'The value the check saw: ' + (VALUE_HINT[checkSel.value] || 'a country, network, hour, program or change') + '.'); };
    checkSel.addEventListener('change', syncHint);
    syncHint();
    const alert = formAlert();
    const save = el('button', { type: 'button', class: 'btn btn--primary' }, e.id ? 'Save' : 'Add exception');
    const form = el('form', { class: 'modal__body bl-ex-form', novalidate: '' },
      alert,
      dxField('Check', checkSel),
      dxField('User or host', who, 'As the risk event names it. The Risk page lists them.'),
      dxField('Value', what, whatHint),
      dxField('Why', why, 'Helps whoever reviews it later.'),
      dxField('Until', until, 'Optional. It stops matching at the start of this day (UTC).'));
    form.addEventListener('submit', async (ev) => {
      ev.preventDefault();
      const match = {};
      if (checkSel.value) match.baseline = checkSel.value;
      if (who.value.trim()) match.risk_object = who.value.trim();
      if (what.value.trim()) match.baseline_value = what.value.trim();
      for (const [k, v] of Object.entries(m)) if (!['baseline', 'risk_object', 'baseline_value'].includes(k)) match[k] = v;
      if (!Object.keys(match).length) {
        showAlert(alert, 'Say what it matches', 'Pick a check, or fill in a user or host or a value. An exception for everything would turn the baselines off.');
        return;
      }
      const next = Object.assign({}, e, { match, comment: why.value.trim() });
      if (until.value) next.until = new Date(until.value + 'T00:00:00Z').toISOString(); else delete next.until;
      const list = (saved().exceptions || []).slice();
      const i = list.findIndex((x) => e.id && x.id === e.id);
      if (i >= 0) list[i] = next; else list.push(next);
      const restore = busy(save, 'Saving…');
      try {
        await saveExceptions(list);
        d.close();
        toast(e.id ? 'Exception saved.' : 'Exception added. It applies from the next hour learned.');
      } catch (err) {
        restore();
        showAlert(alert, 'Nothing was saved', sentence(err.message));
      }
    });
    fill(d, modalHead('bl-ex-dialog', e.id ? 'Edit the exception' : 'Add an exception', 'What matches adds no risk, but is still learned.', () => d.close()),
      form, el('div', { class: 'modal__foot' }, el('button', { type: 'button', class: 'btn btn--ghost', onclick: () => d.close() }, 'Cancel'), save));
    save.addEventListener('click', () => form.requestSubmit());
    d.showModal();
    (e.id ? why : checkSel).focus();
  }

  // blMarkNormal adds an exception for one baseline risk event, from the
  // Risk page: that check, that user or host, that value.
  window.blMarkNormal = async function (ev) {
    try {
      if (!B.view) B.view = await api('api/baselines');
    } catch (e) { toastError('Couldn’t load the behavior baselines', e); return; }
    const check = String(ev.baseline || ev.detection_id || '').replace(/^baseline-/, '');
    const match = { baseline: check };
    if (ev.risk_object) match.risk_object = ev.risk_object;
    if (ev.baseline_value != null && ev.baseline_value !== '') match.baseline_value = String(ev.baseline_value);
    exceptionDialog({ match });
  };

  // ---------- learning settings ----------
  function settingsCard() {
    const v = B.view;
    const d = v.defaults;
    const rows = [
      switchRow(),
      numRow('learning_days', 'Learning period', 'Days a new user or host is only learned from before its new behavior adds risk.', d.learning_days, 1, 90, 'days'),
      numRow('forget_days', 'Forget after', 'Days a country, program or other value not seen again is remembered. A user or host not seen for this long is forgotten too.', d.forget_days, 7, 365, 'days'),
      numRow('rare_hosts', 'Rare program', 'A program is rare when at most this many hosts ever ran it.', d.rare_hosts, 1, 10, 'hosts'),
      numRow('min_mb', 'Least unusual volume', 'An hour must send at least this much to count as an unusual data volume.', d.min_mb, 1, 1000000, 'MB'),
      ipRow(),
    ];
    return el('section', { class: 'card st-card', 'aria-labelledby': 'bl-set-title' },
      el('div', { class: 'st-card__head' }, el('div', { class: 'st-card__heading' },
        el('h3', { class: 'st-card__title', id: 'bl-set-title' }, 'Learning'),
        el('p', { class: 'st-card__desc' }, 'Every server shares these. Each check keeps at most ' + d.max_values + ' values per user or host, and at most ' + riNumText(d.max_profiles) + ' users or hosts.'))),
      el('div', { class: 'st-card__body' }, ...rows));
  }

  const rowClass = (k) => 'st-field' + (k in B.patch.top ? ' is-changed' : '');

  function switchRow() {
    const box = el('input', { type: 'checkbox', id: 'bl-on', role: 'switch', 'aria-describedby': 'bl-on-help' });
    box.checked = !top('off');
    if (B.saving) box.disabled = true;
    box.addEventListener('change', () => { setTop('off', !box.checked); render(); });
    return el('div', { class: rowClass('off') },
      el('div', { class: 'st-field__text' }, el('label', { class: 'st-field__label', for: 'bl-on' }, 'Behavior baselines'),
        el('p', { class: 'st-field__help', id: 'bl-on-help' }, 'Off stops all learning and risk from these checks. What was learned is kept.')),
      el('div', { class: 'st-field__control' }, el('label', { class: 'switch st-switch' }, box, el('span', { class: 'st-switch__state', 'aria-hidden': 'true' }, box.checked ? 'On' : 'Off'))));
  }

  function numRow(k, label, help, def, min, max, unit) {
    const id = 'bl-' + k.replace(/_/g, '-');
    const v = top(k);
    const n = el('input', { type: 'number', id, class: 'input st-input--short', min: String(min), max: String(max), step: '1', inputmode: 'numeric',
      placeholder: String(def), value: v ? String(v) : '', 'aria-describedby': id + '-help' });
    if (B.saving) n.disabled = true;
    n.addEventListener('input', () => {
      const x = parseInt(n.value, 10);
      setTop(k, !x || x === def ? 0 : x);
      syncBar();
    });
    return el('div', { class: rowClass(k) },
      el('div', { class: 'st-field__text' }, el('label', { class: 'st-field__label', for: id }, label),
        el('p', { class: 'st-field__help', id: id + '-help' }, help + ' Empty is ' + def + ' ' + unit + '.')),
      el('div', { class: 'st-field__control' }, el('div', { class: 'bl-unit' }, n, el('span', { class: 'bl-unit__text' }, unit))));
  }

  function ipRow() {
    const ip = B.view.ip_database || {};
    const n = el('input', { type: 'text', id: 'bl-ipdb', class: 'input mono', autocomplete: 'off', spellcheck: 'false', autocapitalize: 'none', inputmode: 'url',
      placeholder: B.view.defaults.ip_database, value: top('ip_database'), 'aria-describedby': 'bl-ipdb-help bl-ipdb-notes' });
    if (B.saving) n.disabled = true;
    n.addEventListener('input', () => { setTop('ip_database', n.value.trim()); syncBar(); });
    const notes = [];
    const off = String(top('ip_database')).toLowerCase() === 'off';
    const custom = ip.source && ip.source !== B.view.defaults.ip_database;
    if (off) {
      notes.push(el('p', { class: 'st-source' }, icon('circle-dashed', 'icon--xs'), el('span', {}, 'Off: the country and network checks wait.')));
    } else if (ip.rows) {
      notes.push(el('p', { class: 'st-source' }, icon('circle-check', 'icon--xs'),
        el('span', {}, riNumText(ip.rows) + ' address ranges, downloaded ' + ago(ip.fetched_at) + (custom ? ' from ' : '.')), custom ? el('span', { class: 'mono' }, ip.source) : null));
    } else if (!ip.error) {
      notes.push(el('p', { class: 'st-source' }, icon('hourglass', 'icon--xs'), el('span', {}, 'Not downloaded yet: the server that runs the background jobs downloads it at its next round.')));
    }
    if (ip.error && !off) notes.push(el('p', { class: 'st-warn' }, icon('triangle-alert'), el('span', {}, 'The last download failed' + (ip.tried_at ? ' (' + ago(ip.tried_at) + ')' : '') + ': ' + sentence(ip.error) + (ip.rows ? ' The copy downloaded before is still used.' : ''))));
    return el('div', { class: rowClass('ip_database') },
      el('div', { class: 'st-field__text' }, el('label', { class: 'st-field__label', for: 'bl-ipdb' }, 'IP database'),
        el('p', { class: 'st-field__help', id: 'bl-ipdb-help' }, 'Tells the country and network checks which network an address belongs to. Empty downloads the free iptoasn.com database weekly. Enter a mirror’s https address; for servers without internet access, file: and the name of a file in the ipdb folder of the lookups folder, such as file:ip2asn-combined.tsv.gz; or off.')),
      el('div', { class: 'st-field__control' }, n, el('div', { class: 'st-field__notes', id: 'bl-ipdb-notes' }, ...notes)));
  }

  // ---------- saving ----------
  function saveBar() {
    const n = dirty();
    const save = el('button', { type: 'button', class: 'btn btn--primary btn--sm', id: 'bl-save' }, icon('check'), 'Save');
    save.addEventListener('click', saveAll);
    const disc = el('button', { type: 'button', class: 'btn btn--ghost btn--sm', id: 'bl-discard' }, 'Discard');
    disc.addEventListener('click', () => { discard(); render(); });
    return el('div', { class: 'st-savebar', id: 'bl-savebar', hidden: n ? null : '' },
      el('div', { class: 'st-savebar__row' },
        el('span', { class: 'st-savebar__text', id: 'bl-savebar-text' }, el('span', { class: 'st-savebar__dot', 'aria-hidden': 'true' }), n === 1 ? '1 unsaved change' : n + ' unsaved changes'),
        el('span', { class: 'bl-grow' }), disc, save));
  }

  function syncBar() {
    const bar = $('bl-savebar');
    if (!bar) return;
    const n = dirty();
    bar.hidden = !n;
    fill($('bl-savebar-text'), el('span', { class: 'st-savebar__dot', 'aria-hidden': 'true' }), n === 1 ? '1 unsaved change' : n + ' unsaved changes');
  }

  async function saveAll() {
    if (B.saving || !dirty()) return;
    B.saving = true;
    const restore = busy($('bl-save'), 'Saving…');
    try {
      B.view = await api('api/baselines', { settings: settings(), version: B.view.version }, 'PUT');
      B.saving = false;
      discard();
      render();
      toast('Saved. It applies from the next hour learned.');
    } catch (e) {
      B.saving = false;
      restore();
      B.problems = e.status === 409 ? ['Someone else changed these settings since you opened this page. Reload it to see their changes, then make yours again.'] : [e.message];
      render();
    }
  }
}());
