// Setup guide: a short walkthrough each user is offered on first use. It
// lists the few steps that take a new install from running to watching
// (two-step sign-in, data, notifications, the team, the security check,
// an optional AI model, a first search), says why each matters, opens the
// page that does it, and checks a step off once the server sees it done
// (api/me/setup). Nothing here changes a setting by itself.
//
// Every choice is the user's own and kept on the server, so it follows
// them to any browser:
//   - Skip this step: moves on; the step shows as skipped.
//   - Skip for now (or closing the guide): it opens again next sign-in.
//   - Ask me later: it opens again in a day.
//   - Don't ask again: it never opens by itself; the account menu still
//     has it.
// Once a step's page is opened from the guide, the guide counts as
// started: it no longer opens by itself, and a Setup button at the top
// of the page shows the steps left and opens it again.
'use strict';

(function () {
  const box = $('setup-guide');
  if (!box) return;
  // Closing without an answer skips the guide until the next sign-in;
  // signing out clears sessionStorage.
  const SKIP_KEY = 'signalith.setupSkipped';
  const S = { view: null, open: '', busy: false, error: '', loadedAt: 0, seq: 0 };

  // ---------- the steps ----------
  // go opens the step's page (or dialog). manual steps are ones the
  // server cannot check: opening their page from here counts as done.
  const STEPS = {
    mfa: {
      icon: 'shield-check', title: 'Turn on two-step sign-in',
      why: 'A stolen password alone should never open your SIEM. Add an authenticator app or a passkey to your own account.',
      done: 'Two-step sign-in is on for your account.',
      action: 'Set up two-step sign-in',
      go: () => { const b = $('mfa-open'); if (b) b.click(); },
    },
    data: {
      icon: 'database', title: 'Bring in your logs',
      why: 'Install an agent on Windows or Linux, point syslog at Signalith or connect a cloud service. Not ready yet? Load a week of sample data from the same page to try things first.',
      done: 'Events are arriving.',
      unknown: 'Signalith could not check for events just now.',
      action: 'Open Add data', page: 'data',
    },
    notify: {
      icon: 'bell', title: 'Get told when something fires',
      why: 'Send new findings to e-mail, Slack, Teams or a webhook, so nobody has to watch the queue all day.',
      done: 'A notification channel is set up.',
      action: 'Open Notifications', page: 'notify',
    },
    team: {
      icon: 'users', title: 'Add your team',
      why: 'Give each person their own account with the least role they need, or connect your directory or single sign-on. Nobody should share the admin account.',
      done: 'Others can sign in.',
      action: 'Open Users', page: 'users',
    },
    security: {
      icon: 'shield', title: 'Fix what the security check finds',
      why: 'Signalith checks its own setup every hour: HTTPS, encryption at rest, OpenSearch, accounts and more. Start with anything marked at risk.',
      done: 'Nothing is at risk.',
      unknown: 'The first check runs shortly after Signalith starts.',
      action: 'Open Security', page: 'security',
    },
    ai: {
      icon: 'sparkles', title: 'Connect an AI model',
      why: 'Ask questions in plain English and get the query written for you, with Claude, OpenAI or a model on your own hardware. Off until you turn it on; only the question and field names are sent.',
      done: 'An AI model is connected, or you looked at the settings.',
      action: 'Open AI settings', manual: true,
      go: () => { if (typeof window.openSetting === 'function') window.openSetting('assistant.provider'); else showPage('settings'); },
    },
    findings: {
      icon: 'inbox', title: 'Meet the findings queue',
      why: 'Detections put what they find here, ranked by severity and risk. Triage starts here.',
      done: 'You opened the findings queue.',
      action: 'Open Findings', page: 'findings', manual: true,
    },
    search: {
      icon: 'search', title: 'Run your first search',
      why: 'The Query guide shows the search language with examples you can run, and the Ask box writes a query from a plain-English question.',
      done: 'You opened the Query guide.',
      action: 'Open the Query guide', page: 'help', manual: true,
    },
  };

  const steps = () => ((S.view && S.view.steps) || []).filter((s) => STEPS[s.id]);
  const skipped = (id) => !!S.view && (S.view.skipped || []).includes(id);
  const settled = (s) => s.done || skipped(s.id);
  const left = () => steps().filter((s) => !settled(s));
  const doneCount = () => steps().filter((s) => s.done).length;
  const firstOpen = () => { const l = left(); return l.length ? l[0].id : ''; };
  const answered = () => !!S.view && ['started', 'never', 'done'].includes(S.view.state);

  // ---------- talking to the server ----------
  async function load() {
    const seq = ++S.seq;
    try {
      const v = await api('api/me/setup');
      if (seq !== S.seq) return S.view;
      S.view = v;
      S.error = '';
      S.loadedAt = Date.now();
    } catch (e) {
      if (seq === S.seq) S.error = e.message;
    }
    syncChip();
    return S.view;
  }

  // save sends a choice: a new state and the step lists, keeping what is
  // not given. It answers with the guide as the server now sees it.
  async function save(change) {
    const v = S.view || {};
    const body = {
      state: change.state !== undefined ? change.state : (v.state || ''),
      skipped: change.skipped || v.skipped || [],
      opened: change.opened || v.opened || [],
    };
    S.busy = true;
    try {
      S.view = await api('api/me/setup', body, 'PUT');
      S.error = '';
      return true;
    } catch (e) {
      S.error = e.message;
      return false;
    } finally {
      S.busy = false;
      syncChip();
    }
  }

  // ---------- the Setup button and the account menu ----------
  function syncChip() {
    const chip = $('setup-chip');
    const item = $('setup-open');
    if (item) item.classList.toggle('hidden', !S.view);
    const all = steps().length;
    const n = left().length;
    const hint = $('setup-hint');
    if (hint) hint.textContent = S.view && all ? `${all - n}/${all}` : '';
    if (!chip) return;
    const show = !!S.view && S.view.state === 'started' && n > 0;
    chip.classList.toggle('hidden', !show);
    if (!show) return;
    $('setup-chip-count').textContent = `${all - n}/${all}`;
    chip.title = `Setup: ${n} ${n === 1 ? 'step' : 'steps'} left`;
    chip.setAttribute('aria-label', `Setup guide, ${all - n} of ${all} steps settled`);
  }

  // ---------- the dialog ----------
  // render draws the dialog and moves focus to the element whose
  // data-focus is focusId.
  function render(focusId) {
    const all = steps();
    const done = doneCount();
    const settledN = all.filter(settled).length;
    const finished = all.length > 0 && settledN === all.length;
    if (!S.open || (!all.find((s) => s.id === S.open))) S.open = firstOpen() || (all[0] && all[0].id) || '';
    const pct = all.length ? Math.round((settledN / all.length) * 100) : 0;

    const head = el('div', { class: 'setup__head' },
      el('span', { class: 'setup__mark' }, icon('list-checks')),
      el('div', { class: 'setup__heading' },
        el('h2', { class: 'modal__title', id: 'setup-title' }, finished ? 'You’re set up' : 'Set up Signalith'),
        el('p', { class: 'modal__desc', id: 'setup-desc' }, finished
          ? 'Everything here is done or skipped. You can open this guide again from the account menu.'
          : 'A few steps take a new install from running to watching. Each opens the page that does it and checks itself off once it’s done.')),
      el('button', { type: 'button', class: 'btn btn--ghost btn--icon btn--sm setup__close', 'aria-label': 'Close', onclick: () => box.close() }, icon('x')));

    const progress = el('div', { class: 'setup__progress' },
      el('div', { class: 'setup__bar', role: 'progressbar', 'aria-label': 'Setup progress', 'aria-valuemin': '0', 'aria-valuemax': String(all.length), 'aria-valuenow': String(settledN) },
        el('span', { class: 'setup__fill' })),
      el('span', { class: 'setup__count' }, `${done} of ${all.length} done` + (settledN > done ? `, ${settledN - done} skipped` : '')));
    progress.querySelector('.setup__fill').style.width = pct + '%';

    const list = el('ol', { class: 'setup__steps' }, ...all.map((s, i) => stepRow(s, i)));
    const alert = S.error ? el('div', { class: 'alert', 'data-tone': 'danger', role: 'alert' }, icon('circle-alert'), el('div', {}, el('b', {}, 'That didn’t save'), el('p', {}, S.error))) : null;

    fill(box, head, el('div', { class: 'setup__body' }, progress, alert, list), foot(finished));
    if (focusId) {
      const t = box.querySelector(`[data-focus="${focusId}"]`);
      if (t) t.focus();
    }
  }

  function stepRow(s, i) {
    const def = STEPS[s.id];
    const isSkipped = skipped(s.id) && !s.done;
    const state = s.done ? 'done' : isSkipped ? 'skipped' : 'todo';
    const open = S.open === s.id;
    const bodyId = 'setup-step-' + s.id;
    const marker = el('span', { class: 'setup__marker', 'data-state': state, 'aria-hidden': 'true' },
      s.done ? icon('check') : isSkipped ? icon('minus') : String(i + 1));
    const tag = s.done ? el('span', { class: 'badge badge--success setup__tag' }, 'Done')
      : isSkipped ? el('span', { class: 'badge setup__tag' }, 'Skipped')
        : s.optional ? el('span', { class: 'badge setup__tag' }, 'Optional') : null;
    const toggle = el('button', {
      type: 'button', class: 'setup__toggle', 'aria-expanded': String(open), 'aria-controls': bodyId, 'data-focus': 'toggle-' + s.id,
      onclick: () => { S.open = open ? '' : s.id; render('toggle-' + s.id); },
    }, marker,
    el('span', { class: 'setup__icon' }, icon(def.icon)),
    el('span', { class: 'setup__title' }, def.title, el('span', { class: 'sr-only' }, s.done ? ' (done)' : isSkipped ? ' (skipped)' : '')),
    tag, icon('chevron-down', 'setup__chev'));

    let status = null;
    if (s.done) status = el('p', { class: 'setup__status', 'data-state': 'done' }, icon('circle-check'), def.done);
    else if (s.id === 'security' && s.count > 0) status = el('p', { class: 'setup__status', 'data-state': 'risk' }, icon('circle-alert'), `${s.count} ${s.count === 1 ? 'check is' : 'checks are'} at risk.`);
    else if (s.unknown && def.unknown) status = el('p', { class: 'setup__status' }, icon('info'), def.unknown);

    const actions = el('div', { class: 'setup__actions' },
      el('button', { type: 'button', class: 'btn ' + (s.done ? 'btn--secondary' : 'btn--primary') + ' btn--sm', 'data-focus': 'go-' + s.id, disabled: S.busy, onclick: () => go(s) },
        def.action, icon('arrow-right')),
      s.done ? null : isSkipped
        ? el('button', { type: 'button', class: 'btn btn--ghost btn--sm', 'data-focus': 'skip-' + s.id, disabled: S.busy, onclick: () => skip(s, false) }, icon('undo-2'), 'Undo skip')
        : el('button', { type: 'button', class: 'btn btn--ghost btn--sm', 'data-focus': 'skip-' + s.id, disabled: S.busy, onclick: () => skip(s, true) }, 'Skip this step'));

    return el('li', { class: 'setup__step', 'data-state': state, 'data-open': String(open) },
      toggle,
      el('div', { class: 'setup__detail', id: bodyId, hidden: !open },
        el('p', { class: 'setup__why' }, def.why), status, actions));
  }

  function foot(finished) {
    if (finished) {
      return el('div', { class: 'modal__foot setup__foot' },
        el('button', { type: 'button', class: 'btn btn--primary', 'data-focus': 'finish', disabled: S.busy, onclick: () => finish() }, icon('check'), 'Done'));
    }
    // Once answered (started, or after Don't ask again or Done), the
    // guide was opened on purpose: closing it is all that is left.
    const v = S.view || {};
    if (v.state === 'never' || v.state === 'done') {
      return el('div', { class: 'modal__foot setup__foot' },
        el('button', { type: 'button', class: 'btn btn--secondary', onclick: () => box.close() }, 'Close'));
    }
    return el('div', { class: 'modal__foot setup__foot' },
      el('button', { type: 'button', class: 'btn btn--ghost setup__never', disabled: S.busy, onclick: () => never() }, 'Don’t ask again'),
      el('span', { class: 'setup__spacer' }),
      v.state === 'started'
        ? el('button', { type: 'button', class: 'btn btn--secondary', onclick: () => box.close() }, 'Close')
        : el('button', { type: 'button', class: 'btn btn--secondary', disabled: S.busy, title: 'Closes the guide until your next sign-in', onclick: () => skipForNow() }, 'Skip for now'),
      v.state === 'started' ? null
        : el('button', { type: 'button', class: 'btn btn--secondary', disabled: S.busy, title: 'Opens the guide again tomorrow', onclick: () => later() }, icon('clock'), 'Ask me later'));
  }

  // ---------- answers ----------
  async function go(s) {
    const def = STEPS[s.id];
    const v = S.view || {};
    const change = {};
    if (!answered() || v.state === 'later') change.state = 'started';
    if (def.manual && !(v.opened || []).includes(s.id)) change.opened = [...(v.opened || []), s.id];
    if (Object.keys(change).length) await save(change);
    box.close();
    if (def.go) def.go();
    else showPage(def.page);
  }

  async function skip(s, on) {
    const v = S.view || {};
    const list = (v.skipped || []).filter((id) => id !== s.id);
    if (on) list.push(s.id);
    const change = { skipped: list };
    if (!answered() || v.state === 'later') change.state = 'started';
    if (!(await save(change))) { render('skip-' + s.id); return; }
    // Move on to the next step still to do, after this one first.
    if (on) {
      const all = steps();
      const i = all.findIndex((x) => x.id === s.id);
      const next = [...all.slice(i + 1), ...all.slice(0, i)].find((x) => !settled(x));
      S.open = next ? next.id : s.id;
    }
    render(on ? (S.open !== s.id ? 'go-' + S.open : 'toggle-' + s.id) : 'skip-' + s.id);
  }

  function skipForNow() {
    try { sessionStorage.setItem(SKIP_KEY, '1'); } catch (_) { /* storage may be blocked */ }
    box.close();
  }

  async function later() {
    if (!(await save({ state: 'later' }))) { render(); return; }
    box.close();
    if (typeof toast === 'function') toast('The setup guide will ask again tomorrow. It’s also in the account menu.', null, { title: 'Setup guide put away' });
  }

  async function never() {
    if (!(await save({ state: 'never' }))) { render(); return; }
    box.close();
    if (typeof toast === 'function') toast('It won’t open by itself again. Open it any time from the account menu.', null, { title: 'Setup guide turned off' });
  }

  async function finish() {
    if (S.view && S.view.state !== 'done' && !(await save({ state: 'done' }))) { render('finish'); return; }
    box.close();
  }

  // ---------- opening ----------
  // openGuide opens the dialog with fresh step states. auto is the guide
  // opening by itself, which never covers another dialog.
  async function openGuide(auto) {
    if (auto && document.querySelector('dialog[open]')) return;
    if (!box.open) {
      if (S.view) render();
      else fill(box, el('div', { class: 'setup__head' }, el('h2', { class: 'modal__title', id: 'setup-title' }, 'Set up Signalith'),
        el('p', { class: 'modal__desc', id: 'setup-desc' }, 'Checking what’s done…')));
      box.showModal();
    }
    await load();
    if (!box.open) return;
    if (!S.view) {
      fill(box, el('div', { class: 'setup__head' },
        el('div', { class: 'setup__heading' }, el('h2', { class: 'modal__title', id: 'setup-title' }, 'Set up Signalith'),
          el('p', { class: 'modal__desc', id: 'setup-desc' }, 'The setup guide could not be loaded: ' + (S.error || 'no answer') + '.')),
        el('button', { type: 'button', class: 'btn btn--ghost btn--icon btn--sm setup__close', 'aria-label': 'Close', onclick: () => box.close() }, icon('x'))));
      return;
    }
    S.open = firstOpen();
    render();
    // Focus starts on the dialog itself, so it opens without a focus ring
    // on a button; Tab goes on to the first step.
    box.tabIndex = -1;
    box.focus();
    // A started guide whose steps are all settled is done.
    if (S.view.state === 'started' && !left().length) save({ state: 'done' });
  }

  box.addEventListener('click', (ev) => { if (ev.target === box) box.close(); });
  box.addEventListener('close', () => {
    // Closed before answering: skipped until the next sign-in.
    if (S.view && (S.view.state === '' || S.view.state === 'later') && S.view.ask) {
      try { sessionStorage.setItem(SKIP_KEY, '1'); } catch (_) { /* storage may be blocked */ }
    }
  });
  $('setup-chip').addEventListener('click', () => openGuide(false));
  $('setup-open').addEventListener('click', () => {
    $('user-menu').removeAttribute('open');
    openGuide(false);
  });

  // Coming back to the tab, or moving to another page, refreshes the
  // Setup button's count (at most every 20 seconds).
  const refresh = () => {
    if (!S.view || document.hidden || box.open || S.view.state !== 'started') return;
    if (Date.now() - S.loadedAt > 20000) load();
  };
  document.addEventListener('visibilitychange', refresh);
  window.addEventListener('hashchange', refresh);
  // Two-step sign-in is set up in its own dialog: when it closes, the
  // guide's count catches up at once.
  document.addEventListener('close', (ev) => {
    if (ev.target && ev.target.id === 'u-mfa-dialog' && S.view) load();
  }, true);

  meReady.then(async (m) => {
    if (!m || m.must_change_password || m.must_setup_mfa || m.auth === 'token') return;
    await load();
    let skippedNow = false;
    try { skippedNow = sessionStorage.getItem(SKIP_KEY) === '1'; } catch (_) { /* ignore */ }
    if (!S.view || !S.view.ask || skippedNow) return;
    // Let the first page draw before the guide opens over it.
    setTimeout(() => openGuide(true), 700);
  });
})();
