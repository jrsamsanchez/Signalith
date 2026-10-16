// Add data > Agent tokens (admins): the tokens agents send with, one per
// agent or group. A new token is shown once, in the dialog that creates it
// (or in the config Add data hands out; see app.js); Signalith keeps only a
// fingerprint. Revoking one turns its agents away within seconds on every
// server. Shared tokens from signalith.yaml or the environment, kept from
// older setups, are listed under the table with the way to retire them.
'use strict';

(function () {
  const REFRESH_MS = 60000;
  const SHOW_REVOKED_KEY = 'signalith.tokensShowRevoked';
  const T = { data: null, seq: 0, busy: false, failed: null, at: 0, ticker: null, showRevoked: false };
  try { T.showRevoked = localStorage.getItem(SHOW_REVOKED_KEY) === '1'; } catch (_) { /* storage may be blocked */ }

  const body = $('tokens-body');
  $('tokens-new').addEventListener('click', () => openCreate());

  pageHooks.push((name) => {
    if (name !== 'data' || !can('admin')) return;
    load();
    if (!T.ticker) T.ticker = setInterval(tick, 5000);
  });

  // tick reloads now and then while Add data is open, so Last used and the
  // event counts move; it stops when another page is open.
  function tick() {
    if (currentPage !== 'data') {
      clearInterval(T.ticker);
      T.ticker = null;
      return;
    }
    if (!document.hidden && !T.busy && Date.now() - T.at >= REFRESH_MS) load(true);
  }

  async function load(quiet) {
    if (!T.data && !quiet) skeleton();
    T.busy = true;
    T.at = Date.now();
    const seq = ++T.seq;
    try {
      const d = await api('api/agent-tokens');
      if (seq !== T.seq) return;
      T.data = d;
      T.failed = null;
      render();
      if (typeof agentTokenNames === 'function' && d.loaded !== false) {
        agentTokenNames((d.tokens || []).filter((t) => t.status === 'active').map((t) => t.name));
      }
    } catch (e) {
      if (seq !== T.seq) return;
      T.failed = e;
      if (!T.data || !quiet) failed(e);
    } finally {
      if (seq === T.seq) T.busy = false;
    }
  }
  // tokensReload is how app.js says a token was just made on this page.
  window.tokensReload = () => load(true);

  // ---------- small parts ----------
  const plural = (n, one, many) => `${Number(n).toLocaleString()} ${n === 1 ? one : many || one + 's'}`;
  const sameYear = (d) => d.getFullYear() === new Date().getFullYear();
  function day(t) {
    const d = new Date(t);
    if (!isFinite(d)) return '';
    return d.toLocaleDateString(undefined, sameYear(d) ? { day: 'numeric', month: 'short' } : { day: 'numeric', month: 'short', year: 'numeric' });
  }
  const full = (t) => new Date(t).toLocaleString();

  function lastUsed(x) {
    if (!x.last_used_at) return el('span', { class: 'tk-muted' }, 'Never');
    const title = full(x.last_used_at) + (x.last_used_from ? ' from ' + x.last_used_from : '');
    const a = ago(x.last_used_at);
    // Capital first, like Never in the same column.
    return el('span', { class: 'age', title }, a.charAt(0).toUpperCase() + a.slice(1));
  }
  const events = (x) => el('span', { class: 'tk-num' }, Number(x.events_1h || 0).toLocaleString());

  function status(state, label) {
    return el('span', { class: 'tk-status', 'data-state': state }, label);
  }

  function skeleton() {
    body.setAttribute('aria-busy', 'true');
    const rows = Array.from({ length: 3 }, () => el('tr', {},
      el('td', { 'data-col': 'name' }, dxSkel('140px'), el('div', { class: 'tk-skel-gap' }), dxSkel('80px')),
      el('td', { 'data-col': 'created' }, dxSkel('80px')),
      el('td', { 'data-col': 'used' }, dxSkel('56px')),
      el('td', { 'data-col': 'events' }, dxSkel('32px')),
      el('td', { 'data-col': 'status' }, dxSkel('56px')),
      el('td', { 'data-col': 'act' })));
    fill(body, table(rows));
  }

  function failed(e) {
    body.setAttribute('aria-busy', 'false');
    fill(body, dxEmpty({ tone: 'danger', icon: 'circle-alert', compact: true, title: 'Couldn’t load the agent tokens', text: sentence(e.message), action: dxRetry(() => load()) }));
  }

  const COLS = [['name', 'Name'], ['created', 'Created'], ['used', 'Last used'], ['events', 'Events, last hour'], ['status', 'Status'], ['act', '']];
  function table(rows) {
    return el('div', { class: 'table-wrap' }, el('table', { class: 'table tk-table' },
      el('thead', {}, el('tr', {}, ...COLS.map(([k, label]) => el('th', { 'data-col': k, scope: 'col', class: k === 'events' ? 'num' : '' },
        label || el('span', { class: 'sr-only' }, 'Actions'))))),
      el('tbody', {}, ...rows)));
  }

  // ---------- the list ----------
  function render() {
    const d = T.data;
    body.setAttribute('aria-busy', 'false');
    const had = document.activeElement && body.contains(document.activeElement) ? document.activeElement.closest('[data-token]') : null;
    const tokens = d.tokens || [];
    const active = tokens.filter((t) => t.status !== 'revoked');
    const revoked = tokens.filter((t) => t.status === 'revoked');
    const parts = [];
    if (d.loaded === false) {
      parts.push(el('div', { class: 'alert tk-alert', 'data-tone': 'warning', role: 'status' }, icon('triangle-alert'),
        el('div', { class: 'tk-alert__body' },
          el('b', {}, 'Agent tokens couldn’t be read from OpenSearch.'),
          el('p', {}, 'New agents can’t be set up until it’s reachable. Agents keep their events and send them again once the list is read.')),
        dxBtn('secondary', 'Try again', () => load(), { sm: true, icon: 'refresh-cw' })));
    }
    const shown = T.showRevoked ? [...active, ...revoked] : active;
    if (shown.length) {
      parts.push(table(shown.map(row)));
    } else if (d.loaded !== false) {
      parts.push(el('div', { class: 'empty empty--compact tk-empty' },
        el('span', { class: 'empty__icon' }, icon('key-round')),
        el('div', { class: 'empty__title' }, revoked.length ? 'No active agent tokens' : 'No agent tokens yet'),
        el('p', { class: 'empty__text' }, 'Copy or download an agent configuration above and Signalith makes one, or create one now.'),
        el('div', { class: 'empty__actions' }, dxBtn('secondary', 'New token', () => openCreate(), { sm: true, icon: 'plus' }))));
    }
    if (revoked.length) {
      parts.push(el('div', { class: 'tk-foot' },
        el('button', { type: 'button', class: 'link-btn tk-toggle', 'aria-expanded': String(T.showRevoked), onclick: toggleRevoked },
          icon('chevron-right', 'icon--sm chev'), T.showRevoked ? `Hide revoked (${revoked.length})` : `Show revoked (${revoked.length})`)));
    }
    // Shared tokens get their IDs from the list, so they are shown once it is read.
    if (d.loaded !== false && (d.legacy || []).length) parts.push(legacyBlock(d.legacy));
    fill(body, ...parts);
    if (had) {
      const again = body.querySelector(`[data-token="${CSS.escape(had.dataset.token)}"] summary, [data-token="${CSS.escape(had.dataset.token)}"] button`);
      if (again) again.focus();
    }
  }

  function toggleRevoked() {
    T.showRevoked = !T.showRevoked;
    try { localStorage.setItem(SHOW_REVOKED_KEY, T.showRevoked ? '1' : '0'); } catch (_) { /* storage may be blocked */ }
    render();
    const b = body.querySelector('.tk-toggle');
    if (b) b.focus();
  }

  function row(t) {
    const off = t.status === 'revoked';
    const created = day(t.created_at) + (t.created_by ? ' by ' + t.created_by : '');
    const createdTitle = full(t.created_at) + (t.created_by ? ' by ' + t.created_by : '');
    let state = status('ok', 'Active');
    if (off) {
      state = status('off', 'Revoked');
      if (t.revoked_at) state.title = 'Revoked ' + full(t.revoked_at) + (t.revoked_by ? ' by ' + t.revoked_by : '');
    }
    return el('tr', { 'data-token': t.id, class: off ? 'tk-off' : '' },
      el('td', { 'data-col': 'name' },
        el('div', { class: 'tk-name' }, t.name),
        el('div', { class: 'tk-hint mono', title: 'The end of the token, to match it with an agent’s configuration' }, 'sgl_…' + (t.hint || ''))),
      el('td', { 'data-col': 'created' }, el('span', { title: createdTitle }, created)),
      el('td', { 'data-col': 'used' }, lastUsed(t)),
      el('td', { 'data-col': 'events', class: 'num' }, events(t)),
      el('td', { 'data-col': 'status' }, state),
      el('td', { 'data-col': 'act' }, off ? null : (() => {
        const m = dxMenu('Actions for ' + t.name, [
          { icon: 'pencil', label: 'Rename', run: () => openRename(t) },
          'sep',
          { icon: 'ban', label: 'Revoke', danger: true, run: () => revoke(t) },
        ]);
        m.classList.add('tk-menu');
        return m;
      })()));
  }

  // ---------- shared (legacy) tokens ----------
  const SOURCE = {
    'signalith.yaml': 'from signalith.yaml',
    SIGNALITH_INGEST_TOKEN: 'from SIGNALITH_INGEST_TOKEN',
    SIGNALITH_INGEST_TOKEN_FILE: 'from SIGNALITH_INGEST_TOKEN_FILE',
  };
  const sourceWhere = (src) => (src === 'signalith.yaml' ? 'signalith.yaml (ingest.tokens)' : src || 'the configuration');

  function legacyBlock(list) {
    const accepted = list.filter((l) => l.status !== 'refused').length;
    return el('section', { class: 'tk-legacy', 'aria-labelledby': 'tk-legacy-title' },
      el('div', { class: 'alert', 'data-tone': accepted ? 'warning' : 'info', role: 'status' }, icon(accepted ? 'triangle-alert' : 'info'),
        el('div', {},
          el('b', { id: 'tk-legacy-title' }, 'Shared tokens'),
          el('p', {}, accepted
            ? 'Every agent set up with a shared token uses the same secret, so a copy taken from any one of them works for all of them. Give those agents a configuration with their own token above, then stop accepting the shared token.'
            : 'No shared token is accepted any more, so none can be used. There’s nothing else to do; on the Docker quick start, leave docker-compose.yml as it is.'))),
      el('ul', { class: 'tk-legacy__list', role: 'list' }, ...list.map(legacyRow)));
  }

  function legacyRow(l) {
    const refused = l.status === 'refused';
    const btn = refused
      ? dxBtn('secondary', 'Accept again', () => acceptLegacy(l), { sm: true, icon: 'check' })
      : dxBtn('secondary', 'Stop accepting', () => refuseLegacy(l), { sm: true, icon: 'ban', cls: 'tk-stop' });
    const st = refused ? status('off', 'No longer accepted') : status('warn', 'Accepted');
    if (refused && l.refused_at) st.title = 'Since ' + full(l.refused_at) + (l.refused_by ? ' (' + l.refused_by + ')' : '');
    return el('li', { class: 'tk-legacy__row' + (refused ? ' tk-off' : ''), 'data-token': 'legacy-' + l.id },
      el('div', { class: 'tk-legacy__main' },
        el('div', { class: 'tk-name' }, l.name),
        el('div', { class: 'tk-legacy__src' }, SOURCE[l.source] || (l.source ? 'from ' + l.source : '')),
        l.public ? el('p', { class: 'tk-legacy__public' }, icon('circle-alert', 'icon--sm'), 'This is the example token from an older docker-compose.yml. Anyone can look it up.') : null),
      el('dl', { class: 'tk-legacy__facts' },
        el('div', {}, el('dt', {}, 'Last used'), el('dd', {}, lastUsed(l))),
        el('div', {}, el('dt', {}, 'Events, last hour'), el('dd', {}, events(l)))),
      el('div', { class: 'tk-legacy__state' }, st),
      el('div', { class: 'tk-legacy__act' }, btn));
  }

  async function refuseLegacy(l) {
    const ok = await caseConfirm({
      title: `Stop accepting “${l.name}”?`,
      text: `Agents still sending it are refused within a few seconds on every server. Fluent Bit and the Collector drop the batches refused this way, so update those agents first. You can accept it again here. It can stay in ${sourceWhere(l.source)}: once it is no longer accepted, it can’t be used.`,
      confirm: 'Stop accepting',
    });
    if (!ok) return focusLegacy(l);
    try {
      const r = await api(`api/agent-tokens/legacy/${encodeURIComponent(l.id)}/refuse`, {});
      const n = r.hosts_removed || 0;
      toast(`Stopped accepting “${l.name}”.` + (n ? ` ${plural(n, 'osquery host was', 'osquery hosts were')} removed.` : ''));
    } catch (e) {
      toastError('Couldn’t stop accepting the token', e);
    }
    await load(true);
    focusLegacy(l);
  }

  async function acceptLegacy(l) {
    try {
      await api(`api/agent-tokens/legacy/${encodeURIComponent(l.id)}/accept`, {});
      toast(`“${l.name}” is accepted again.`);
    } catch (e) {
      toastError('Couldn’t accept the token again', e);
    }
    await load(true);
    focusLegacy(l);
  }

  function focusLegacy(l) {
    const b = body.querySelector(`[data-token="legacy-${CSS.escape(l.id)}"] button`);
    if (b) b.focus();
  }

  function focusRow(id) {
    const r = id ? body.querySelector(`[data-token="${CSS.escape(id)}"] summary`) : null;
    (r || $('tokens-new')).focus();
  }

  // ---------- dialogs ----------
  // nameField is the Name field with its hint and a place for its error.
  function nameField(id, value, hint, placeholder) {
    const input = el('input', { class: 'input', id, type: 'text', maxlength: '64', autocomplete: 'off', spellcheck: 'false', required: '' });
    if (placeholder) input.placeholder = placeholder;
    input.value = value || '';
    const err = el('p', { class: 'field-error hidden', id: id + '-error', role: 'alert' });
    input.setAttribute('aria-describedby', id + '-hint ' + id + '-error');
    input.addEventListener('input', () => setFieldError(input, err, ''));
    const field = el('div', { class: 'field' }, el('label', { class: 'label', for: id }, 'Name'), input,
      hint ? el('p', { class: 'hint', id: id + '-hint' }, hint) : null, err);
    return { field, input, err };
  }
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
    const d = modalDialog('tk-dialog');
    d.classList.add('tk-dialog');
    let made = null;
    d.onclose = () => {
      // The token leaves the page with the dialog.
      d.querySelectorAll('input').forEach((i) => { i.value = ''; });
      fill(d);
      focusRow(made);
    };
    const close = () => d.close();
    const f = nameField('tk-f-name', '', 'Name the agent or group that will use it. The name is recorded on every event they send.', 'For example Linux web servers');
    const alertBox = formAlert();
    const submit = el('button', { type: 'submit', class: 'btn btn--primary' }, el('span', {}, 'Create token'));
    const form = el('form', { novalidate: '' },
      modalHead('tk-dialog', 'New agent token', 'Use it in the configuration of the agents in one group.', close),
      el('div', { class: 'modal__body' }, alertBox, f.field),
      el('div', { class: 'modal__foot' }, el('button', { type: 'button', class: 'btn btn--ghost', onclick: close }, 'Cancel'), submit));
    form.addEventListener('submit', async (ev) => {
      ev.preventDefault();
      alertBox.classList.add('hidden');
      const name = f.input.value.trim().replace(/\s+/g, ' ');
      if (!name) {
        setFieldError(f.input, f.err, 'Enter a name, such as Linux web servers.');
        return f.input.focus();
      }
      busyBtn(submit, true, 'Creating…');
      try {
        const r = await api('api/agent-tokens', { name, purpose: '' });
        made = r.token && r.token.id;
        showSecret(d, r.token || { name }, r.secret);
        load(true);
      } catch (e) {
        busyBtn(submit, false, 'Create token');
        if (e.field === 'name' || e.code === 'name_invalid' || e.code === 'name_taken') {
          setFieldError(f.input, f.err, e.message);
          f.input.focus();
        } else {
          showAlert(alertBox, 'Couldn’t create the token', sentence(e.message));
        }
      }
    });
    fill(d, form);
    d.showModal();
    f.input.focus();
  }

  // showSecret is the dialog's second step: the token, once.
  function showSecret(d, t, secret) {
    const close = () => d.close();
    // A text area, so the whole token shows, wrapped, at any width.
    const out = el('textarea', { class: 'input mono tk-secret__value', id: 'tk-secret', rows: '2', readonly: '', autocomplete: 'off', spellcheck: 'false', 'aria-label': 'The new token' });
    out.value = secret;
    out.addEventListener('focus', () => out.select());
    const copy = el('button', { type: 'button', class: 'btn btn--secondary tk-secret__copy' }, icon('copy'), el('span', {}, 'Copy'));
    copy.addEventListener('click', () => agentSetupCopy(secret, copy));
    const done = el('button', { type: 'button', class: 'btn btn--primary', onclick: close }, 'Done');
    fill(d,
      modalHead('tk-dialog', 'Copy your new token', `For “${t.name}”.`, close),
      el('div', { class: 'modal__body' },
        el('div', { class: 'tk-secret' }, out, copy),
        el('div', { class: 'alert', 'data-tone': 'warning', role: 'status' }, icon('triangle-alert'),
          el('div', {}, el('b', {}, 'You won’t see this token again.'),
            el('p', {}, 'Signalith keeps only a fingerprint of it. Paste it into the agent’s configuration now; if you lose it, create a new one.')))),
      el('div', { class: 'modal__foot' }, done));
    copy.focus();
  }

  function openRename(t) {
    const d = modalDialog('tk-dialog');
    d.classList.add('tk-dialog');
    d.onclose = () => { fill(d); focusRow(t.id); };
    const close = () => d.close();
    const f = nameField('tk-f-rename', t.name, 'Events already stored keep the old name.');
    const alertBox = formAlert();
    const submit = el('button', { type: 'submit', class: 'btn btn--primary' }, el('span', {}, 'Save'));
    const form = el('form', { novalidate: '' },
      modalHead('tk-dialog', 'Rename token', null, close),
      el('div', { class: 'modal__body' }, alertBox, f.field),
      el('div', { class: 'modal__foot' }, el('button', { type: 'button', class: 'btn btn--ghost', onclick: close }, 'Cancel'), submit));
    form.addEventListener('submit', async (ev) => {
      ev.preventDefault();
      alertBox.classList.add('hidden');
      const name = f.input.value.trim().replace(/\s+/g, ' ');
      if (!name) {
        setFieldError(f.input, f.err, 'Enter a name.');
        return f.input.focus();
      }
      if (name === t.name) return close();
      busyBtn(submit, true, 'Saving…');
      try {
        await api(`api/agent-tokens/${encodeURIComponent(t.id)}`, { name }, 'PATCH');
        close();
        toast(`Renamed to “${name}”.`);
        load(true);
      } catch (e) {
        busyBtn(submit, false, 'Save');
        if (e.field === 'name' || e.code === 'name_invalid' || e.code === 'name_taken') {
          setFieldError(f.input, f.err, e.message);
          f.input.focus();
        } else {
          showAlert(alertBox, 'Couldn’t rename the token', sentence(e.message));
          if (e.code === 'revoked' || e.code === 'not_found') load(true);
        }
      }
    });
    fill(d, form);
    d.showModal();
    f.input.select();
  }

  async function revoke(t) {
    const ok = await caseConfirm({
      title: `Revoke “${t.name}”?`,
      text: 'Agents that send with this token are refused within a few seconds on every server, and osquery hosts enrolled with it are removed. Events already stored stay. This can’t be undone; to bring those agents back, give them a new configuration.',
      confirm: 'Revoke token',
    });
    if (!ok) return focusRow(t.id);
    try {
      const r = await api(`api/agent-tokens/${encodeURIComponent(t.id)}/revoke`, {});
      const n = r.hosts_removed || 0;
      toast(`Revoked “${t.name}”.` + (n ? ` ${plural(n, 'osquery host was', 'osquery hosts were')} removed.` : ''));
    } catch (e) {
      toastError('Couldn’t revoke the token', e);
    }
    await load(true);
    focusRow(null);
  }
}());
