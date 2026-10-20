// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0
// Settings > API tokens (admins): named tokens a program reads through
// the API with, such as the AI tools server (signalith mcp). A token is
// shown once, in the dialog that creates it; Signalith keeps only a
// fingerprint, in the shared settings, so every server accepts it and a
// revocation reaches all of them within seconds. Whatever its role, a
// token can only read. A token expires after the days picked when it is
// made, 90 unless the admin picks another; Never is offered but not
// recommended. See docs/ai-tools.md.
'use strict';

(function () {
  const SHOW_REVOKED_KEY = 'signalith.apiTokensShowRevoked';
  const A = { data: null, seq: 0, showRevoked: false };
  try { A.showRevoked = localStorage.getItem(SHOW_REVOKED_KEY) === '1'; } catch (_) { /* storage may be blocked */ }

  const body = $('at-body');
  const newBtn = $('at-new');
  newBtn.dataset.feature = 'api_tokens';
  newBtn.addEventListener('click', () => openCreate());

  pageHooks.push((name) => {
    if (name === 'apitokens' && can('admin')) load();
  });

  async function load(quiet) {
    if (!A.data && !quiet) skeleton();
    const seq = ++A.seq;
    try {
      const d = await api('api/api-tokens');
      if (seq !== A.seq) return;
      A.data = d;
      render();
    } catch (e) {
      if (seq !== A.seq) return;
      if (!A.data || !quiet) failed(e);
    }
  }

  // ---------- small parts ----------
  const sameYear = (d) => d.getFullYear() === new Date().getFullYear();
  function day(t) {
    const d = new Date(t);
    if (!isFinite(d)) return '';
    return d.toLocaleDateString(undefined, sameYear(d) ? { day: 'numeric', month: 'short' } : { day: 'numeric', month: 'short', year: 'numeric' });
  }
  const full = (t) => new Date(t).toLocaleString();
  const status = (state, label) => el('span', { class: 'tk-status', 'data-state': state }, label);
  // EXPIRY are the lifetimes the create dialog offers; 0 is never.
  const EXPIRY = [[30, '30 days'], [90, '90 days'], [180, '180 days'], [365, '1 year'], [0, 'Never (not recommended)']];
  const EXPIRY_HINT = 'When the token expires, programs that read with it are refused. Make a new one then.';
  const NEVER_HINT = 'Not recommended: a token that never expires keeps working until someone revokes it, even if it leaks or the tool is forgotten.';
  // SOON is how close to its expiry a token is marked Expires soon.
  const SOON = 7 * 24 * 3600 * 1000;
  const ROLE_HINT = {
    viewer: 'Reads searches, findings, cases, detections, assets and risk. Enough for every AI tool.',
    analyst: 'Also reads what only analysts may see. Pick it only if a tool needs it.',
  };
  // docs links to the AI tools guide.
  const docs = (anchor) => 'https://github.com/jrsamsanchez/signalith/blob/main/docs/ai-tools.md' + (anchor ? '#' + anchor : '');
  const docLink = (anchor, label) => el('a', { href: docs(anchor), target: '_blank', rel: 'noopener noreferrer' },
    label, icon('arrow-up-right', 'icon--xs'), el('span', { class: 'sr-only' }, ' (opens in a new tab)'));

  function skeleton() {
    body.setAttribute('aria-busy', 'true');
    const rows = Array.from({ length: 2 }, () => el('tr', {},
      el('td', { 'data-col': 'name' }, dxSkel('140px'), el('div', { class: 'tk-skel-gap' }), dxSkel('80px')),
      el('td', { 'data-col': 'role' }, dxSkel('56px')),
      el('td', { 'data-col': 'created' }, dxSkel('80px')),
      el('td', { 'data-col': 'expires' }, dxSkel('64px')),
      el('td', { 'data-col': 'used' }, dxSkel('56px')),
      el('td', { 'data-col': 'status' }, dxSkel('56px')),
      el('td', { 'data-col': 'act' })));
    fill(body, table(rows));
  }

  function failed(e) {
    body.setAttribute('aria-busy', 'false');
    fill(body, dxEmpty({ tone: 'danger', icon: 'circle-alert', compact: true, title: 'Couldn’t load the API tokens', text: sentence(e.message), action: dxRetry(() => load()) }));
  }

  const COLS = [['name', 'Name'], ['role', 'Role'], ['created', 'Created'], ['expires', 'Expires'], ['used', 'Last used'], ['status', 'Status'], ['act', '']];
  function table(rows) {
    return el('div', { class: 'table-wrap' }, el('table', { class: 'table tk-table' },
      el('thead', {}, el('tr', {}, ...COLS.map(([k, label]) => el('th', { 'data-col': k, scope: 'col' },
        label || el('span', { class: 'sr-only' }, 'Actions'))))),
      el('tbody', {}, ...rows)));
  }

  // ---------- the list ----------
  function render() {
    const d = A.data;
    body.setAttribute('aria-busy', 'false');
    newBtn.disabled = !d.on;
    const tokens = d.tokens || [];
    const active = tokens.filter((t) => t.active);
    // Expired tokens are kept with the revoked ones: neither is accepted.
    const revoked = tokens.filter((t) => !t.active);
    const offLabel = revoked.some((t) => t.expired && !t.revoked) ? 'expired and revoked' : 'revoked';
    const parts = [];
    if (!d.on) {
      parts.push(el('div', { class: 'alert tk-alert', 'data-tone': 'warning', role: 'status' }, icon('triangle-alert'),
        el('div', { class: 'tk-alert__body' }, el('b', {}, 'New API tokens can’t be made now.'), el('p', {}, sentence(d.off)))));
    }
    const shown = A.showRevoked ? [...active, ...revoked] : active;
    if (shown.length) {
      parts.push(table(shown.map(row)));
    } else if (d.on) {
      parts.push(el('div', { class: 'empty empty--compact tk-empty' },
        el('span', { class: 'empty__icon' }, icon('key-round')),
        el('div', { class: 'empty__title' }, revoked.length ? 'No active API tokens' : 'No API tokens yet'),
        el('p', { class: 'empty__text' }, 'Make one for each AI tool or program that reads from Signalith, so you can see what it does and cut it off on its own.'),
        el('div', { class: 'empty__actions' }, dxBtn('secondary', 'New token', () => openCreate(), { sm: true, icon: 'plus' }))));
    }
    if (revoked.length) {
      parts.push(el('div', { class: 'tk-foot' },
        el('button', { type: 'button', class: 'link-btn tk-toggle', 'aria-expanded': String(A.showRevoked), onclick: toggleRevoked },
          icon('chevron-right', 'icon--sm chev'), A.showRevoked ? `Hide ${offLabel} (${revoked.length})` : `Show ${offLabel} (${revoked.length})`)));
    }
    fill(body, ...parts);
  }

  function toggleRevoked() {
    A.showRevoked = !A.showRevoked;
    try { localStorage.setItem(SHOW_REVOKED_KEY, A.showRevoked ? '1' : '0'); } catch (_) { /* storage may be blocked */ }
    render();
    const b = body.querySelector('.tk-toggle');
    if (b) b.focus();
  }

  function expires(t) {
    if (!t.expires) {
      const s = status('warn', 'Never');
      s.title = 'This token never expires. That is not recommended: make one that expires and revoke this one.';
      return s;
    }
    return el('span', { title: full(t.expires) }, day(t.expires));
  }

  function lastUsed(t) {
    if (!t.last_used) return el('span', { class: 'tk-muted' }, 'Never');
    const a = ago(t.last_used);
    // Capital first, like Never in the same column.
    return el('span', { class: 'age', title: full(t.last_used) }, a.charAt(0).toUpperCase() + a.slice(1));
  }

  function row(t) {
    const off = !t.active;
    const by = t.created_by ? ' by ' + t.created_by : '';
    let state = status('ok', 'Active');
    if (t.revoked) {
      state = status('off', 'Revoked');
      state.title = 'Revoked ' + full(t.revoked) + (t.revoked_by ? ' by ' + t.revoked_by : '');
    } else if (t.expired) {
      state = status('off', 'Expired');
      state.title = 'Expired ' + full(t.expires);
    } else if (off) {
      state = status('off', 'Not accepted');
    } else if (t.expires && new Date(t.expires) - Date.now() < SOON) {
      state = status('warn', 'Expires soon');
      state.title = 'Expires ' + full(t.expires) + '. Make a new token for this tool before then.';
    }
    return el('tr', { 'data-token': t.id, class: off ? 'tk-off' : '' },
      el('td', { 'data-col': 'name' },
        el('div', { class: 'tk-name' }, t.name),
        el('div', { class: 'tk-hint mono', title: 'The end of the token, to match it with a program’s settings' }, 'sgl_api_…' + (t.hint || ''))),
      el('td', { 'data-col': 'role' }, t.role_label || t.role),
      el('td', { 'data-col': 'created' }, el('span', { title: full(t.created) + by }, day(t.created) + by)),
      el('td', { 'data-col': 'expires' }, expires(t)),
      el('td', { 'data-col': 'used' }, lastUsed(t)),
      el('td', { 'data-col': 'status' }, state),
      el('td', { 'data-col': 'act' }, off ? null : (() => {
        const m = dxMenu('Actions for ' + t.name, [{ icon: 'ban', label: 'Revoke', danger: true, run: () => revoke(t) }]);
        m.classList.add('tk-menu');
        return m;
      })()));
  }

  function focusRow(id) {
    const r = id ? body.querySelector(`[data-token="${CSS.escape(id)}"] summary`) : null;
    (r || newBtn).focus();
  }

  // ---------- dialogs ----------
  function setFieldError(input, err, msg) {
    if (msg) {
      input.setAttribute('aria-invalid', 'true');
      err.replaceChildren(icon('circle-alert'), sentence(msg));
    } else {
      input.removeAttribute('aria-invalid');
      err.replaceChildren();
    }
    err.classList.toggle('hidden', !msg);
  }
  const busyBtn = (b, on, label) => { b.disabled = on; b.setAttribute('aria-busy', String(on)); if (label) b.lastChild.textContent = label; };

  function openCreate() {
    const d = modalDialog('at-dialog');
    d.classList.add('tk-dialog');
    let made = null;
    d.onclose = () => {
      // The token leaves the page with the dialog.
      d.querySelectorAll('input, textarea').forEach((i) => { i.value = ''; });
      fill(d);
      focusRow(made);
    };
    const close = () => d.close();
    const name = el('input', { class: 'input', id: 'at-f-name', type: 'text', maxlength: '64', autocomplete: 'off', spellcheck: 'false', required: '',
      placeholder: 'For example Claude Desktop on Ana’s laptop', 'aria-describedby': 'at-f-name-hint at-f-name-error' });
    const nameErr = el('p', { class: 'field-error hidden', id: 'at-f-name-error', role: 'alert' });
    name.addEventListener('input', () => setFieldError(name, nameErr, ''));
    const roles = (A.data && A.data.roles) || ['viewer', 'analyst'];
    const role = el('select', { class: 'select select--block', id: 'at-f-role', 'aria-describedby': 'at-f-role-hint' },
      ...roles.map((r) => el('option', { value: r }, r.charAt(0).toUpperCase() + r.slice(1))));
    const roleHint = el('p', { class: 'hint', id: 'at-f-role-hint' }, ROLE_HINT[role.value] || '');
    role.addEventListener('change', () => { roleHint.textContent = ROLE_HINT[role.value] || ''; });
    const def = (A.data && A.data.default_days) || 90;
    const expiry = el('select', { class: 'select select--block', id: 'at-f-expiry', 'aria-describedby': 'at-f-expiry-hint' },
      ...EXPIRY.map(([n, label]) => el('option', { value: String(n) }, label)));
    expiry.value = String(def);
    const expiryHint = el('p', { class: 'hint', id: 'at-f-expiry-hint' }, EXPIRY_HINT);
    expiry.addEventListener('change', () => { expiryHint.textContent = expiry.value === '0' ? NEVER_HINT : EXPIRY_HINT; });
    const alertBox = formAlert();
    const submit = el('button', { type: 'submit', class: 'btn btn--primary' }, el('span', {}, 'Create token'));
    const form = el('form', { novalidate: '' },
      modalHead('at-dialog', 'New API token', 'For one AI tool or program. It can only read, whatever its role.', close),
      el('div', { class: 'modal__body' }, alertBox,
        el('div', { class: 'field' }, el('label', { class: 'label', for: 'at-f-name' }, 'Name'), name,
          el('p', { class: 'hint', id: 'at-f-name-hint' }, 'Name the tool and where it runs. The audit log shows what it does as api-token:<name>.'), nameErr),
        el('div', { class: 'field' }, el('label', { class: 'label', for: 'at-f-role' }, 'Role'), role, roleHint),
        el('div', { class: 'field' }, el('label', { class: 'label', for: 'at-f-expiry' }, 'Expires after'), expiry, expiryHint)),
      el('div', { class: 'modal__foot' }, el('button', { type: 'button', class: 'btn btn--ghost', onclick: close }, 'Cancel'), submit));
    form.addEventListener('submit', async (ev) => {
      ev.preventDefault();
      alertBox.classList.add('hidden');
      const n = name.value.trim().replace(/\s+/g, ' ');
      if (!n) {
        setFieldError(name, nameErr, 'Enter a name, such as Claude Desktop.');
        return name.focus();
      }
      busyBtn(submit, true, 'Creating…');
      try {
        const days = Number(expiry.value);
        const r = await api('api/api-tokens', days ? { name: n, role: role.value, expires_in_days: days } : { name: n, role: role.value, never: true });
        made = r.id;
        showSecret(d, r);
        load(true);
      } catch (e) {
        busyBtn(submit, false, 'Create token');
        if (e.status === 400 || e.status === 409) {
          setFieldError(name, nameErr, e.message);
          name.focus();
        } else {
          showAlert(alertBox, 'Couldn’t create the token', sentence(e.message));
        }
      }
    });
    fill(d, form);
    d.showModal();
    name.focus();
  }

  // copyBox is a read-only text area with a Copy button.
  function copyBox(id, label, text, rows) {
    // A text area, so the whole value shows, wrapped, at any width.
    const out = el('textarea', { class: 'input mono tk-secret__value', id, rows: String(rows), readonly: '', autocomplete: 'off', spellcheck: 'false', 'aria-label': label });
    out.value = text;
    out.addEventListener('focus', () => out.select());
    const copy = el('button', { type: 'button', class: 'btn btn--secondary tk-secret__copy' }, icon('copy'), el('span', {}, 'Copy'));
    copy.addEventListener('click', () => agentSetupCopy(text, copy));
    return { box: el('div', { class: 'tk-secret' }, out, copy), copy };
  }

  // showSecret is the dialog's second step: the token, once, and the
  // command that adds the AI tools server to Claude Code with it.
  function showSecret(d, t) {
    const close = () => d.close();
    const origin = location.origin;
    const cmd = `claude mcp add signalith -e SIGNALITH_URL=${origin} -e SIGNALITH_TOKEN=${t.token} -- signalith mcp`;
    const tok = copyBox('at-secret', 'The new token', t.token, 2);
    const ex = copyBox('at-command', 'Command for Claude Code', cmd, 3);
    fill(d,
      modalHead('at-dialog', 'Copy your new token', `For “${t.name}”, as ${(t.role_label || t.role || '').toLowerCase()}` +
        (t.expires ? `, until ${new Date(t.expires).toLocaleDateString(undefined, { day: 'numeric', month: 'short', year: 'numeric' })}.` : ', with no expiry.'), close),
      el('div', { class: 'modal__body' },
        tok.box,
        el('div', { class: 'alert', 'data-tone': 'warning', role: 'status' }, icon('triangle-alert'),
          el('div', {}, el('b', {}, 'You won’t see this token again.'),
            el('p', {}, 'Signalith keeps only a fingerprint of it. Put it in the AI tool’s settings as SIGNALITH_TOKEN now; if you lose it, create a new one.'))),
        el('div', { class: 'field' }, el('span', { class: 'label' }, 'Add it to Claude Code'), ex.box,
          el('p', { class: 'hint' }, 'Claude Desktop, VS Code, Cursor and Docker: see ', docLink('5-add-it-to-your-ai-tool', 'the AI tools guide')))),
      el('div', { class: 'modal__foot' }, el('button', { type: 'button', class: 'btn btn--primary', onclick: close }, 'Done')));
    // Each box grows to show all of its text.
    d.querySelectorAll('textarea').forEach((t) => { t.style.height = t.scrollHeight + 2 + 'px'; });
    tok.copy.focus();
  }

  async function revoke(t) {
    const ok = await caseConfirm({
      title: `Revoke “${t.name}”?`,
      text: 'Programs that read with this token are refused within a few seconds on every server. This can’t be undone; to bring the tool back, make a new token.',
      confirm: 'Revoke token',
    });
    if (!ok) return focusRow(t.id);
    try {
      await api(`api/api-tokens/${encodeURIComponent(t.id)}/revoke`, {});
      toast(`Revoked “${t.name}”.`);
    } catch (e) {
      toastError('Couldn’t revoke the token', e);
    }
    await load(true);
    focusRow(null);
  }
}());
