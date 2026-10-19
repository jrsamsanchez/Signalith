// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0
// Tenants (multi-tenant mode): the customers one install serves, each
// with its own data and users. Settings > Tenants lets the provider's
// admins add, rename and turn off tenants; the picker in the top bar lets
// the provider's analysts and admins switch the tenant their session
// works in. Tenant users see neither: their session only ever works in
// their own tenant. See docs/multi-tenant.md.
'use strict';

(function () {
  const T = { data: null, seq: 0 };
  // docs links to the multi-tenant guide.
  const DOCS = 'https://github.com/jrsamsanchez/signalith/blob/main/docs/multi-tenant.md';
  const docLink = (label) => el('a', { href: DOCS, target: '_blank', rel: 'noopener noreferrer' },
    label, icon('arrow-up-right', 'icon--xs'), el('span', { class: 'sr-only' }, ' (opens in a new tab)'));

  // ---------- rules of IDs and names (as internal/tenants checks them) ----------
  const ID_MAX = 24;
  const NAME_MAX = 100;
  // Control and text-direction characters could make one tenant's name
  // read as another's.
  const BAD_NAME = /[\0-\x1f\x7f-\x9f‪-‮⁦-⁩]/;
  function idProblem(id) {
    if (!id) return 'Enter an ID, such as acme.';
    if (id === 'default') return '“default” is the default tenant’s ID.';
    if (!/^[a-z]/.test(id)) return 'The ID must start with a lower-case letter.';
    if (/[^a-z0-9]/.test(id)) return 'The ID may only have lower-case letters and digits.';
    if (id.length < 2 || id.length > ID_MAX) return `The ID must be 2 to ${ID_MAX} characters.`;
    return '';
  }
  function nameProblem(name) {
    if (!name) return 'Enter a name, such as Acme Corp.';
    if ([...name].length > NAME_MAX) return `The name must be at most ${NAME_MAX} characters.`;
    if (BAD_NAME.test(name)) return 'The name can’t have control or text-direction characters.';
    return '';
  }
  // idFrom suggests an ID for a name: its letters and digits, lower case,
  // without accents, starting with a letter.
  function idFrom(name) {
    const id = name.normalize('NFKD').toLowerCase().replace(/[^a-z0-9]/g, '').replace(/^[0-9]+/, '').slice(0, ID_MAX);
    return id === 'default' ? '' : id;
  }
  const cleanName = (s) => s.trim().replace(/\s+/g, ' ');

  // ---------- the picker in the top bar ----------
  const pick = $('tenant-pick');
  const pickMenu = $('tenant-menu');
  const P = { list: [], active: 'default' };

  meReady.then((m) => {
    if (m && m.tenant === '' && can('analyst')) loadPicker();
  });

  async function loadPicker() {
    let d;
    try { d = await api('api/tenants'); } catch (_) { return; }
    renderPicker(d);
  }

  function renderPicker(d) {
    P.list = d.tenants || [];
    P.active = d.active || 'default';
    pick.classList.toggle('hidden', !d.enabled && P.active === 'default');
    const cur = P.list.find((t) => t.id === P.active) || { id: P.active, name: P.active };
    const inCustomer = P.active !== 'default';
    if (inCustomer) pick.dataset.active = 'tenant';
    else delete pick.dataset.active;
    $('tenant-name').textContent = cur.name;
    const btn = $('tenant-btn');
    btn.setAttribute('aria-label', `Tenant: ${cur.name}${inCustomer ? ' (' + cur.id + ')' : ''}. Switch tenant`);
    btn.title = inCustomer ? `Working in ${cur.name} (${cur.id})` : 'Switch tenant';
    const close = () => pick.removeAttribute('open');
    const items = P.list.map((t) => {
      const here = t.id === P.active;
      const b = el('button', { class: 'menu__item', type: 'button', role: 'menuitemradio', 'aria-checked': String(here), 'data-id': t.id, disabled: !!t.disabled && !here },
        icon('layers'), el('span', {}, t.name),
        el('span', { class: 'menu__hint' }, t.disabled ? 'Off' : t.id),
        here ? icon('check', 'tenant-menu__check') : null);
      if (t.disabled) b.title = `${t.name} is turned off`;
      b.addEventListener('click', () => { close(); if (!here) switchTo(t); });
      return b;
    });
    fill(pickMenu, el('div', { class: 'tenant-menu__label', 'aria-hidden': 'true' }, 'Work in'), ...items,
      el('div', { class: 'menu__sep', 'data-min-role': 'admin' }),
      el('a', { class: 'menu__item', role: 'menuitem', href: '#tenants', 'data-page': 'tenants', 'data-min-role': 'admin', onclick: close },
        icon('settings'), el('span', {}, 'Manage tenants')));
  }

  // Opening the picker focuses the tenant in use; arrow keys move
  // between its items, Esc closes it (app.js).
  pick.addEventListener('toggle', () => {
    if (!pick.open) return;
    const cur = pickMenu.querySelector('[aria-checked="true"]') || pickMenu.querySelector('.menu__item:not(:disabled)');
    if (cur) cur.focus();
  });
  pickMenu.addEventListener('keydown', (ev) => {
    if (ev.key !== 'ArrowDown' && ev.key !== 'ArrowUp' && ev.key !== 'Home' && ev.key !== 'End') return;
    const items = [...pickMenu.querySelectorAll('.menu__item')].filter((n) => !n.disabled && n.getClientRects().length);
    if (!items.length) return;
    ev.preventDefault();
    const i = items.indexOf(document.activeElement);
    let next = ev.key === 'Home' ? 0 : ev.key === 'End' ? items.length - 1 : i + (ev.key === 'ArrowDown' ? 1 : -1);
    next = (next + items.length) % items.length;
    items[next].focus();
  });

  // switchTo moves the session to tenant t and reloads the page, so every
  // page, count and menu shows that tenant's data; the toast after the
  // reload says where you are.
  const SWITCH_NOTE_KEY = 'signalith.tenantSwitched';
  async function switchTo(t) {
    $('tenant-btn').setAttribute('aria-busy', 'true');
    try {
      await api('api/tenants/switch', { tenant: t.id });
    } catch (e) {
      $('tenant-btn').removeAttribute('aria-busy');
      toastError(`Couldn’t switch to ${t.name}`, e);
      loadPicker();
      return;
    }
    try { sessionStorage.setItem(SWITCH_NOTE_KEY, t.default ? 'the default tenant' : t.name); } catch (_) { /* storage may be blocked */ }
    location.reload();
  }
  meReady.then(() => {
    let where = null;
    try { where = sessionStorage.getItem(SWITCH_NOTE_KEY); sessionStorage.removeItem(SWITCH_NOTE_KEY); } catch (_) { /* storage may be blocked */ }
    if (where) toast(`You’re now working in ${where}.`);
  });

  // ---------- Settings > Tenants ----------
  const body = $('tn-body');
  const newBtn = $('tn-new');
  newBtn.addEventListener('click', () => openCreate());

  pageHooks.push((name) => {
    if (name === 'tenants' && can('admin') && !inTenant()) load();
  });

  async function load(quiet) {
    if (!T.data && !quiet) skeleton();
    const seq = ++T.seq;
    try {
      const d = await api('api/tenants');
      if (seq !== T.seq) return;
      T.data = d;
      render();
      renderPicker(d);
    } catch (e) {
      if (seq !== T.seq) return;
      if (!T.data || !quiet) failed(e);
    }
  }

  const sameYear = (d) => d.getFullYear() === new Date().getFullYear();
  function day(t) {
    const d = new Date(t);
    if (!t || !isFinite(d)) return '';
    return d.toLocaleDateString(undefined, sameYear(d) ? { day: 'numeric', month: 'short' } : { day: 'numeric', month: 'short', year: 'numeric' });
  }
  const status = (state, label) => el('span', { class: 'tk-status', 'data-state': state }, label);

  function skeleton() {
    body.setAttribute('aria-busy', 'true');
    const rows = Array.from({ length: 2 }, () => el('tr', {},
      el('td', { 'data-col': 'name' }, dxSkel('140px'), el('div', { class: 'tk-skel-gap' }), dxSkel('60px')),
      el('td', { 'data-col': 'created' }, dxSkel('80px')),
      el('td', { 'data-col': 'status' }, dxSkel('40px')),
      el('td', { 'data-col': 'act' })));
    fill(body, table(rows));
  }

  function failed(e) {
    body.setAttribute('aria-busy', 'false');
    fill(body, dxEmpty({ tone: 'danger', icon: 'circle-alert', compact: true, title: 'Couldn’t load the tenants', text: sentence(e.message), action: dxRetry(() => load()) }));
  }

  const COLS = [['name', 'Tenant'], ['created', 'Created'], ['status', 'Status'], ['act', '']];
  function table(rows) {
    return el('div', { class: 'table-wrap' }, el('table', { class: 'table tk-table' },
      el('thead', {}, el('tr', {}, ...COLS.map(([k, label]) => el('th', { 'data-col': k, scope: 'col' },
        label || el('span', { class: 'sr-only' }, 'Actions'))))),
      el('tbody', {}, ...rows)));
  }

  function render() {
    const d = T.data;
    body.setAttribute('aria-busy', 'false');
    newBtn.disabled = !!d.off;
    const list = d.tenants || [];
    const parts = [];
    if (d.off) {
      parts.push(el('div', { class: 'alert tk-alert', 'data-tone': 'warning', role: 'status' }, icon('triangle-alert'),
        el('div', { class: 'tk-alert__body' }, el('b', {}, 'Tenants can’t be added or changed now.'), el('p', {}, sentence(d.off)))));
    }
    if (list.some((t) => !t.default)) {
      parts.push(table(list.map(row)));
    } else {
      parts.push(el('div', { class: 'empty empty--compact tk-empty' },
        el('span', { class: 'empty__icon' }, icon('layers')),
        el('div', { class: 'empty__title' }, 'No tenants yet'),
        el('p', { class: 'empty__text' }, 'A tenant keeps one customer’s events, findings and users apart from everyone else’s, in this one install. Your own data stays in the default tenant. ',
          docLink('How tenants work')),
        d.off ? null : el('div', { class: 'empty__actions' }, dxBtn('secondary', 'New tenant', () => openCreate(), { sm: true, icon: 'plus' }))));
    }
    fill(body, ...parts);
  }

  function row(t) {
    const here = t.id === (T.data && T.data.active);
    const by = t.created_by ? ' by ' + t.created_by : '';
    let menu = null;
    if (!t.default) {
      menu = dxMenu('Actions for ' + t.name, [
        { icon: 'pencil', label: 'Rename', run: () => openRename(t) },
        t.disabled ? { icon: 'power', label: 'Turn on', run: () => setOff(t, false) }
          : { icon: 'power', label: 'Turn off', danger: true, run: () => setOff(t, true) },
      ]);
      menu.classList.add('tk-menu');
    }
    return el('tr', { 'data-tenant': t.id, class: t.disabled ? 'tk-off' : '' },
      el('td', { 'data-col': 'name' },
        el('div', { class: 'tk-name' }, el('span', {}, t.name),
          here ? el('span', { class: 'badge badge--accent', title: 'Your session works in this tenant now' }, 'You’re here') : null),
        el('div', { class: 'tk-hint mono' }, t.id)),
      el('td', { 'data-col': 'created' }, t.created ? el('span', { title: new Date(t.created).toLocaleString() + by }, day(t.created) + by) : null),
      el('td', { 'data-col': 'status' }, t.disabled ? status('off', 'Off') : status('ok', 'On')),
      el('td', { 'data-col': 'act' }, menu));
  }

  function focusRow(id) {
    const r = id ? body.querySelector(`[data-tenant="${CSS.escape(id)}"] summary`) : null;
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

  function nameField(value) {
    const input = el('input', { class: 'input', id: 'tn-f-name', type: 'text', maxlength: String(NAME_MAX), autocomplete: 'off', spellcheck: 'false', required: '',
      placeholder: 'For example Acme Corp', 'aria-describedby': 'tn-f-name-hint tn-f-name-error' });
    input.value = value || '';
    const err = el('p', { class: 'field-error hidden', id: 'tn-f-name-error', role: 'alert' });
    return { input, err };
  }

  // openCreate adds a tenant: a name, and an ID made from it until the
  // ID is edited by hand.
  function openCreate() {
    const d = modalDialog('tn-dialog');
    d.classList.add('tk-dialog', 'tn-dialog');
    let made = null;
    d.onclose = () => { fill(d); focusRow(made); };
    const close = () => d.close();
    const name = nameField('');
    const id = el('input', { class: 'input tn-id', id: 'tn-f-id', type: 'text', maxlength: String(ID_MAX), autocomplete: 'off', autocapitalize: 'off', spellcheck: 'false', required: '',
      placeholder: 'acme', 'aria-describedby': 'tn-f-id-hint tn-f-id-error' });
    const idErr = el('p', { class: 'field-error hidden', id: 'tn-f-id-error', role: 'alert' });
    let idEdited = false;
    name.input.addEventListener('input', () => {
      setFieldError(name.input, name.err, '');
      if (idEdited) return;
      id.value = idFrom(name.input.value);
      setFieldError(id, idErr, '');
    });
    id.addEventListener('input', () => {
      idEdited = id.value !== '';
      // Mark what is wrong while typing, except that the ID is still short.
      const p = idProblem(id.value);
      setFieldError(id, idErr, id.value.length < 2 && /^[a-z]?$/.test(id.value) ? '' : p);
    });
    id.addEventListener('blur', () => { if (id.value) setFieldError(id, idErr, idProblem(id.value)); });
    const alertBox = formAlert();
    const submit = el('button', { type: 'submit', class: 'btn btn--primary' }, el('span', {}, 'Add tenant'));
    const form = el('form', { novalidate: '' },
      modalHead('tn-dialog', 'New tenant', 'A customer with its own data, detections and users. It starts empty.', close),
      el('div', { class: 'modal__body' }, alertBox,
        el('div', { class: 'field' }, el('label', { class: 'label', for: 'tn-f-name' }, 'Name'), name.input,
          el('p', { class: 'hint', id: 'tn-f-name-hint' }, 'Shown in the tenant picker. You can rename it later.'), name.err),
        el('div', { class: 'field' }, el('label', { class: 'label', for: 'tn-f-id' }, 'ID'), id,
          el('p', { class: 'hint', id: 'tn-f-id-hint' }, `2 to ${ID_MAX} lower-case letters and digits, starting with a letter. Its index names start with it, so it can’t be changed later.`), idErr)),
      el('div', { class: 'modal__foot' }, el('button', { type: 'button', class: 'btn btn--ghost', onclick: close }, 'Cancel'), submit));
    form.addEventListener('submit', async (ev) => {
      ev.preventDefault();
      alertBox.classList.add('hidden');
      const n = cleanName(name.input.value);
      const i = id.value.trim();
      const np = nameProblem(n);
      const ip = idProblem(i);
      setFieldError(name.input, name.err, np);
      setFieldError(id, idErr, ip);
      if (np) return name.input.focus();
      if (ip) return id.focus();
      busyBtn(submit, true, 'Adding…');
      let r;
      try {
        r = await api('api/tenants', { id: i, name: n });
      } catch (e) {
        busyBtn(submit, false, 'Add tenant');
        if (e.status === 400 && /name/i.test(e.message) && !/\bID\b/.test(e.message)) {
          setFieldError(name.input, name.err, e.message);
          name.input.focus();
        } else if (e.status === 400 || (e.status === 409 && /already exists/.test(e.message))) {
          setFieldError(id, idErr, e.message);
          id.focus();
        } else {
          showAlert(alertBox, 'Couldn’t add the tenant', sentence(e.message));
        }
        return;
      }
      made = r.tenant && r.tenant.id;
      close();
      if (r.warning) toast(sentence(r.warning), null, { tone: 'danger', title: `${n} was added` });
      else toast(`${n} was added. Switch to it with the tenant picker in the top bar.`);
      load(true);
    });
    fill(d, form);
    d.showModal();
    name.input.focus();
  }

  function openRename(t) {
    const d = modalDialog('tn-dialog');
    d.classList.add('tk-dialog', 'tn-dialog');
    d.onclose = () => { fill(d); focusRow(t.id); };
    const close = () => d.close();
    const name = nameField(t.name);
    name.input.addEventListener('input', () => setFieldError(name.input, name.err, ''));
    const alertBox = formAlert();
    const submit = el('button', { type: 'submit', class: 'btn btn--primary' }, el('span', {}, 'Rename'));
    const form = el('form', { novalidate: '' },
      modalHead('tn-dialog', `Rename “${t.name}”`, `Its ID stays ${t.id}.`, close),
      el('div', { class: 'modal__body' }, alertBox,
        el('div', { class: 'field' }, el('label', { class: 'label', for: 'tn-f-name' }, 'Name'), name.input,
          el('p', { class: 'hint', id: 'tn-f-name-hint' }, 'Shown in the tenant picker and on this page.'), name.err)),
      el('div', { class: 'modal__foot' }, el('button', { type: 'button', class: 'btn btn--ghost', onclick: close }, 'Cancel'), submit));
    form.addEventListener('submit', async (ev) => {
      ev.preventDefault();
      alertBox.classList.add('hidden');
      const n = cleanName(name.input.value);
      const np = nameProblem(n);
      setFieldError(name.input, name.err, np);
      if (np) return name.input.focus();
      if (n === t.name) return close();
      busyBtn(submit, true, 'Renaming…');
      try {
        await api('api/tenants/' + encodeURIComponent(t.id), { name: n }, 'PATCH');
      } catch (e) {
        busyBtn(submit, false, 'Rename');
        if (e.status === 400) {
          setFieldError(name.input, name.err, e.message);
          name.input.focus();
        } else {
          showAlert(alertBox, 'Couldn’t rename the tenant', sentence(e.message));
        }
        return;
      }
      close();
      toast(`Renamed to ${n}.`);
      load(true);
    });
    fill(d, form);
    d.showModal();
    name.input.select();
  }

  async function setOff(t, off) {
    if (off) {
      const ok = await caseConfirm({
        title: `Turn off “${t.name}”?`,
        text: 'Its users can’t sign in and its agents are refused at once, and its background jobs stop. Its data stays: turn it on again to bring everything back.',
        confirm: 'Turn off',
      });
      if (!ok) return focusRow(t.id);
    }
    try {
      await api('api/tenants/' + encodeURIComponent(t.id), { disabled: off }, 'PATCH');
      toast(off ? `${t.name} is turned off.` : `${t.name} is turned on.`);
    } catch (e) {
      toastError(off ? 'Couldn’t turn the tenant off' : 'Couldn’t turn the tenant on', e);
    }
    await load(true);
    focusRow(t.id);
  }
}());
