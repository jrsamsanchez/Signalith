// Users page (admins): the people who can sign in and their roles, and
// directory (LDAP or Active Directory) sign-in. Also the account menu's
// Change password, which every local user has.
'use strict';

(function () {
  const ROLE_ORDER = ['admin', 'analyst', 'viewer'];
  const ROLE_LABEL = { viewer: 'Viewer', analyst: 'Analyst', admin: 'Admin' };
  // Used until api/users has answered with the server's own words.
  const ROLE_INFO = [
    { id: 'viewer', label: 'Viewer', description: 'Searches and looks at everything, but changes nothing.' },
    { id: 'analyst', label: 'Analyst', description: 'Also triages findings, works investigations and builds dashboards.' },
    { id: 'admin', label: 'Admin', description: 'Also manages detections, threat intel, data collection and users.' },
  ];
  const SOURCE_LABEL = { local: 'Local', directory: 'Directory', builtin: 'Built-in' };

  const U = { data: null, seq: 0, tab: 'users', loadedAt: 0 };

  // ---------- small helpers ----------
  const roles = () => (U.data && U.data.roles) || ROLE_INFO;
  const roleLabel = (r) => ROLE_LABEL[r] || r || 'None';
  const displayName = (u) => u.name || u.username;

  // field wraps a control with its label and an optional hint.
  function field(label, control, hint, opts = {}) {
    const hid = hint ? control.id + '-hint' : null;
    if (hid) control.setAttribute('aria-describedby', hid);
    return el('div', { class: 'field' + (opts.cls ? ' ' + opts.cls : '') },
      el('label', { class: 'label', for: control.id }, label, opts.optional ? el('span', { class: 'u-optional' }, 'optional') : null),
      control, hint ? el('div', { class: 'hint', id: hid }, hint) : null);
  }
  function input(id, attrs = {}) {
    return el('input', Object.assign({ id, class: 'input', type: 'text', autocomplete: 'off', spellcheck: 'false' }, attrs));
  }

  // markField shows a problem under one control; clearFields removes them.
  function markField(control, msg) {
    const box = control.closest('.field, .u-roles, .u-groups') || control.parentElement;
    control.setAttribute('aria-invalid', 'true');
    let e = box.querySelector(':scope > .field-error');
    if (!e) {
      e = el('div', { class: 'field-error', id: (control.id || box.id || 'u') + '-error', role: 'alert' });
      box.append(e);
    }
    fill(e, icon('circle-alert'), el('span', {}, sentence(msg)));
    const ids = (control.getAttribute('aria-describedby') || '').split(' ').filter((x) => x && x !== e.id);
    control.setAttribute('aria-describedby', [...ids, e.id].join(' '));
  }
  function clearField(control) {
    if (!control || !control.hasAttribute('aria-invalid')) return;
    control.removeAttribute('aria-invalid');
    const box = control.closest('.field, .u-roles, .u-groups') || control.parentElement;
    const e = box && box.querySelector(':scope > .field-error');
    if (e) {
      control.setAttribute('aria-describedby', (control.getAttribute('aria-describedby') || '').split(' ').filter((x) => x && x !== e.id).join(' '));
      e.remove();
    }
  }
  function clearFields(root) {
    root.querySelectorAll('[aria-invalid]').forEach(clearField);
  }

  // copyText copies to the clipboard. navigator.clipboard needs HTTPS or
  // localhost, so plain-HTTP servers select the text and copy that.
  async function copyText(text, from) {
    try {
      await navigator.clipboard.writeText(text);
      return true;
    } catch (_) {
      if (!from) return false;
      from.focus();
      from.select();
      try { return document.execCommand('copy'); } catch (_) { return false; }
    }
  }

  // ifMatch makes a change apply only to the user (or the directory
  // settings) as the page shows them, on servers that share their users:
  // the server answers 412 when someone changed them meanwhile, on this
  // server or another. A server that keeps its users in its own files
  // works as it always did.
  const ifMatch = (v, shared) => (shared && v && v.etag ? { 'If-Match': v.etag } : undefined);
  const usersShared = () => !!(U.data && U.data.shared);
  // changedBy says who changed something meanwhile, where and when, from
  // a 412 answer.
  function changedBy(e) {
    const d = e.data || {};
    let t = 'Changed';
    if (d.changed_on) t += ` on ${d.changed_on}`;
    if (d.changed_by) t += ` by ${d.changed_by}`;
    if (d.changed_at) t += ` ${ago(d.changed_at)}`;
    return t === 'Changed' ? 'Someone else changed it since the page read it.' : t + '.';
  }
  // reread loads the list again and gives u the version now listed, so
  // saving again applies on top of the other change.
  async function reread(u) {
    await loadUsers({ quiet: true });
    const now = U.data && U.data.users.find((x) => x.username === u.username);
    if (now) u.etag = now.etag;
  }
  // changeFailed shows why a change of u was not made in a dialog's alert
  // box: someone changed u meanwhile (412), the shared settings can't be
  // changed now (503), or anything else, under title.
  function changeFailed(box, u, e, title) {
    if (e.status === 412) {
      showAlert(box, `Someone else changed ${u.username} meanwhile.`, `${changedBy(e)} The list now shows their change. Save again to apply yours on top of it.`);
      reread(u);
    } else if (e.status === 503) {
      showAlert(box, 'Users can’t be changed right now.', sentence(e.message));
    } else {
      showAlert(box, title, sentence(e.message));
    }
  }
  // toastChangeFailed is changeFailed for a change made from the row menu.
  function toastChangeFailed(u, e, title) {
    if (e.status === 412) {
      toast(`${changedBy(e)} Check ${u.username} in the list, then try again.`, null, { tone: 'warning', title: `Someone else changed ${u.username}` });
      reread(u);
    } else if (e.code !== 'forbidden') {
      toastError(e.status === 503 ? 'Users can’t be changed right now' : title, e);
    }
  }

  // roleCards is the role picker: one card per role, each with a line on
  // what the role can do.
  function roleCards(name, current) {
    const fs = el('fieldset', { class: 'u-roles', id: name },
      el('legend', { class: 'label' }, 'Role'));
    for (const r of roles()) {
      const radio = el('input', { type: 'radio', name, value: r.id, id: `${name}-${r.id}` });
      if (r.id === current) radio.checked = true;
      fs.append(el('label', { class: 'u-role-card', for: radio.id }, radio,
        el('span', { class: 'u-role-card__text' }, el('b', {}, r.label), el('span', {}, r.description))));
    }
    fs.addEventListener('change', () => clearField(fs));
    fs.value = () => { const c = fs.querySelector('input:checked'); return c ? c.value : ''; };
    return fs;
  }

  // passwordChoice is "Generate one" or "Set one" for a new or reset
  // password. withMustChange adds the "choose their own" box (new users).
  function passwordChoice(prefix, withMustChange) {
    let mode = 'generate';
    const pass = el('input', { id: prefix + '-password', class: 'input', type: 'password', autocomplete: 'new-password', spellcheck: 'false' });
    const must = el('input', { type: 'checkbox', id: prefix + '-must' });
    must.checked = true;
    const seg = el('div', { class: 'seg', role: 'group', 'aria-label': 'Password' });
    const gen = el('p', { class: 'hint u-pw-note' }, icon('info'), 'Signalith makes one up and shows it to you once.');
    const set = el('div', { class: 'u-pw-set hidden' },
      field('Password', pass, 'At least 8 characters.'),
      withMustChange ? el('label', { class: 'check' }, must, 'Ask them to choose their own at first sign-in') : null);
    const sync = () => {
      seg.querySelectorAll('button').forEach((b) => b.setAttribute('aria-pressed', String(b.dataset.mode === mode)));
      gen.classList.toggle('hidden', mode !== 'generate');
      set.classList.toggle('hidden', mode !== 'set');
    };
    for (const [m, label] of [['generate', 'Generate one'], ['set', 'Set one']]) {
      seg.append(el('button', { type: 'button', 'data-mode': m, onclick: () => { mode = m; sync(); if (m === 'set') pass.focus(); } }, label));
    }
    pass.addEventListener('input', () => clearField(pass));
    sync();
    return {
      node: el('div', { class: 'field u-pw' }, el('span', { class: 'label', id: prefix + '-pw-label' }, 'Password'), seg, gen, set),
      input: pass,
      value: () => (mode === 'set' ? pass.value : ''),
      mustChange: () => mode === 'generate' || must.checked,
      check() {
        if (mode === 'set' && pass.value.length < 8) { markField(pass, 'enter at least 8 characters'); pass.focus(); return false; }
        return true;
      },
      init() { seg.setAttribute('aria-labelledby', prefix + '-pw-label'); },
    };
  }

  // userDialog is the one dialog for adding, editing and resetting.
  function userDialog() {
    const d = modalDialog('u-dialog');
    d.classList.add('u-dialog');
    return d;
  }
  const footer = (...kids) => el('div', { class: 'modal__foot' }, ...kids);
  const cancelButton = (d, label = 'Cancel') => el('button', { type: 'button', class: 'btn btn--ghost', onclick: () => d.close() }, label);

  // showSecret replaces a dialog's content with a password shown once.
  function showSecret(d, { title, who, password, note }) {
    const box = el('input', { id: 'u-secret', class: 'input mono u-secret__value', type: 'text', readonly: '', spellcheck: 'false', 'aria-label': `Temporary password for ${who}` });
    box.value = password;
    const said = el('span', { class: 'sr-only', role: 'status' });
    const label = el('span', {}, 'Copy');
    const copy = el('button', { type: 'button', class: 'btn btn--secondary u-secret__copy' }, icon('copy'), label);
    copy.addEventListener('click', async () => {
      const ok = await copyText(password, box);
      copy.querySelector('use').setAttribute('href', ok ? '#i-check' : '#i-circle-alert');
      label.textContent = ok ? 'Copied' : 'Select and copy';
      said.textContent = ok ? 'Copied to the clipboard.' : 'Couldn’t copy. Select the password and press Ctrl+C.';
      copy.focus();
      clearTimeout(copy.timer);
      copy.timer = setTimeout(() => { copy.querySelector('use').setAttribute('href', '#i-copy'); label.textContent = 'Copy'; }, 2000);
    });
    box.addEventListener('focus', () => box.select());
    const done = el('button', { type: 'button', class: 'btn btn--primary', onclick: () => d.close() }, 'Done');
    // A stray click outside must not lose a password shown only once.
    d.onclick = null;
    fill(d,
      modalHead('u-dialog', title, `Give it to ${who}. They choose their own password when they first sign in.`, () => d.close()),
      el('div', { class: 'modal__body' },
        el('div', { class: 'u-secret' }, box, copy),
        el('p', { class: 'hint' }, icon('eye-off'), note || 'This is the only time it is shown.'), said),
      footer(done));
    copy.focus();
  }

  // ---------- the list ----------
  pageHooks.push((name) => {
    if (name !== 'users') return;
    selectTab(U.tab, false);
    loadUsers({ quiet: !!U.data });
    if (U.tab === 'directory') loadDirectory();
  });

  async function loadUsers({ quiet = false } = {}) {
    const seq = ++U.seq;
    if (!quiet || !U.data) renderUsersLoading();
    let data;
    try {
      data = await api('api/users');
    } catch (e) {
      if (seq === U.seq) renderUsersError(e);
      return;
    }
    if (seq !== U.seq) return;
    U.data = data;
    U.loadedAt = Date.now();
    renderUsers();
  }

  const COLS = [['user', 'User'], ['role', 'Role'], ['source', 'Source'], ['status', 'Status'], ['last', 'Last sign-in'], ['act', '']];
  function usersTable(rows, busyNow) {
    return el('table', { class: 'table u-table', 'aria-busy': String(!!busyNow) },
      el('thead', {}, el('tr', {}, ...COLS.map(([k, label]) => el('th', { 'data-col': k, scope: 'col' }, label ? label : el('span', { class: 'sr-only' }, 'Actions'))))),
      el('tbody', {}, ...rows));
  }
  function renderUsersLoading() {
    $('u-list').setAttribute('aria-busy', 'true');
    const rows = Array.from({ length: 4 }, () => el('tr', {},
      el('td', { 'data-col': 'user' }, el('div', { class: 'u-user' }, el('span', { class: 'avatar avatar--none u-avatar' }), el('div', { class: 'u-user__text' }, dxSkel('120px'), el('div', { class: 'u-skel-gap' }), dxSkel('180px')))),
      el('td', { 'data-col': 'role' }, dxSkel('56px')),
      el('td', { 'data-col': 'source' }, dxSkel('48px')),
      el('td', { 'data-col': 'status' }, dxSkel('60px')),
      el('td', { 'data-col': 'last' }, dxSkel('48px')),
      el('td', { 'data-col': 'act' })));
    fill($('u-list'), usersTable(rows, true));
    $('u-foot').classList.add('hidden');
  }
  function renderUsersError(e) {
    $('u-list').setAttribute('aria-busy', 'false');
    fill($('u-list'), dxEmpty({ tone: 'danger', icon: 'circle-alert', title: 'Couldn’t load the users', text: sentence(e.message), action: dxRetry(() => loadUsers()) }));
    $('u-foot').classList.add('hidden');
  }

  function statusOf(u) {
    if (u.disabled) return ['off', 'Disabled', 'Cannot sign in until an admin enables them.'];
    if (u.refused) return ['off', 'No access', `Refused by the directory: ${u.refused}. Access comes back if a later sign-in is accepted.`];
    if (u.must_change_password) return ['temp', 'Temporary password', 'Must choose a new password at their next sign-in.'];
    return ['ok', 'Active', ''];
  }

  function userRow(u) {
    const [state, stateLabel, stateTitle] = statusOf(u);
    const sub = u.source === 'builtin' ? [U.data && U.data.shared ? 'The same on every server' : 'Set on the server (signalith passwd)']
      : [u.name ? u.username : '', u.email].filter(Boolean);
    const roleBadge = el('span', { class: 'badge u-role', 'data-role': u.role }, roleLabel(u.role));
    if (u.source === 'directory') roleBadge.title = 'From their directory groups at their last sign-in';
    const nameAttrs = { class: 'u-user__name' };
    if (u.dn) nameAttrs.title = u.dn;
    return el('tr', { 'data-user': u.username, class: u.disabled ? 'u-off' : '' },
      el('td', { 'data-col': 'user' }, el('div', { class: 'u-user' },
        Object.assign(caseAvatar(u.username), { className: 'avatar u-avatar' + (u.disabled ? ' avatar--none' : '') }),
        el('div', { class: 'u-user__text' },
          el('div', nameAttrs, el('span', {}, displayName(u)), u.you ? el('span', { class: 'badge badge--outline' }, 'You') : null),
          el('div', { class: 'u-user__sub' + (sub.length ? '' : ' u-user__sub--src') }, sub.join(' · '),
            // The Source column is hidden on phones; say it here instead.
            el('span', { class: 'u-user__src' }, (sub.length ? ' · ' : '') + (SOURCE_LABEL[u.source] || u.source)))))),
      el('td', { 'data-col': 'role' }, roleBadge),
      el('td', { 'data-col': 'source' }, el('span', { class: 'u-source' }, SOURCE_LABEL[u.source] || u.source)),
      el('td', { 'data-col': 'status' }, el('span', { class: 'u-status', 'data-state': state, title: stateTitle }, stateLabel)),
      el('td', { 'data-col': 'last' }, u.last_sign_in
        // With shared users, the server they signed in on last, too.
        ? el('div', {}, el('span', { class: 'age', title: new Date(u.last_sign_in).toLocaleString() + (u.last_sign_in_server ? ` on ${u.last_sign_in_server}` : '') }, ago(u.last_sign_in)),
          u.last_sign_in_server ? el('div', { class: 'u-last__on' }, 'on ' + u.last_sign_in_server) : null)
        : el('span', { class: 'u-never' }, 'Never')),
      el('td', { 'data-col': 'act' }, rowMenu(u)));
  }

  function rowMenu(u) {
    const has = (a) => (u.actions || []).includes(a);
    const items = [];
    if (has('edit')) items.push({ icon: 'pencil', label: 'Edit', run: () => openEditUser(u) });
    // The built-in admin's own row, once every server shares its password.
    if (has('change_password')) items.push({ icon: 'key-round', label: 'Change password', run: () => openChangePassword() });
    if (has('reset_password')) items.push({ icon: 'key-round', label: 'Reset password', run: () => openResetPassword(u) });
    if (has('disable')) items.push({ icon: 'user-x', label: 'Disable', run: () => setDisabled(u, true) });
    if (has('enable')) items.push({ icon: 'user-check', label: 'Enable', run: () => setDisabled(u, false) });
    if (has('delete')) items.push('sep', { icon: 'trash-2', label: 'Delete', danger: true, run: () => deleteUser(u) });
    if (!items.length) return null;
    if (items[0] === 'sep') items.shift();
    const m = dxMenu('Actions for ' + u.username, items);
    m.classList.add('u-menu');
    return m;
  }

  // focusRow puts keyboard focus back on a user's actions button after a
  // dialog closes or the list is redrawn, or on Add user if the row is gone.
  function focusRow(name) {
    const row = name ? document.querySelector(`#u-list tr[data-user="${CSS.escape(name)}"]`) : null;
    const target = (row && row.querySelector('[data-col=act] summary')) || $('u-add');
    if (target && !target.closest('.hidden')) target.focus();
  }

  function renderUsers() {
    const { users, directory } = U.data;
    // Redrawing replaces the rows, so note which row had focus.
    const had = document.activeElement && $('u-list').contains(document.activeElement) ? document.activeElement.closest('tr[data-user]') : null;
    const term = $('u-find').value.trim().toLowerCase();
    $('u-list').setAttribute('aria-busy', 'false');
    $('u-count').textContent = String(users.length);
    $('u-count').classList.remove('hidden');
    $('u-dir-on').classList.toggle('hidden', !directory.enabled);
    $('u-toolbar').classList.toggle('hidden', users.length <= 8 && !term);
    const shown = users.filter((u) => !term || [u.username, u.name, u.email, roleLabel(u.role), SOURCE_LABEL[u.source]].join(' ').toLowerCase().includes(term));
    if (!shown.length) {
      fill($('u-list'), dxEmpty({ icon: 'filter-x', title: 'No users match', text: 'Try part of a name, username or email address.', action: { label: 'Clear', icon: 'x', run: () => { $('u-find').value = ''; renderUsers(); $('u-find').focus(); } } }));
    } else {
      fill($('u-list'), usersTable(shown.map(userRow)));
    }
    if (had) focusRow(had.dataset.user);
    const local = users.filter((u) => u.source === 'local').length;
    const dirUsers = users.filter((u) => u.source === 'directory').length;
    const foot = $('u-foot');
    const bits = [plural(users.length, 'user')];
    if (local) bits.push(`${local} local`);
    if (dirUsers) bits.push(`${dirUsers} from the directory`);
    let note = null;
    if (users.length === 1 && !directory.enabled) {
      note = el('span', {}, 'Only the built-in admin can sign in. Add a user for each person, or ',
        el('button', { type: 'button', class: 'link-btn', onclick: () => selectTab('directory', true) }, 'set up directory sign-in'), '.');
    } else if (directory.enabled) {
      note = el('span', {}, 'Directory users appear after their first sign-in.');
    }
    if (U.data.shared) bits.push('the same on every server');
    fill(foot, el('span', {}, bits.join(' · ')), el('span', { class: 'spacer' }), note);
    foot.classList.remove('hidden');
    renderPending(U.data.shared_pending);
  }

  // renderPending says, on a server of a cluster that does not share the
  // users yet, why: a server whose version can't, or the users not
  // brought in yet.
  function renderPending(p) {
    const box = $('u-note');
    if (!p) { box.classList.add('hidden'); fill(box); return; }
    const old = (p.servers || []).map((s) => (s.version ? `${s.name} (${s.version})` : s.name));
    fill(box, dxAlert('info', 'Each server keeps its own users for now.', old.length
      ? `Users and sign-in become shared by every server once every server runs ${p.version || 'this version'} or later. Still on an older version: ${old.join(', ')}. Until then, a user added here signs in on this server only.`
      : 'Users and sign-in become shared by every server once the server that founded the cluster brings its users in. Until then, a user added here signs in on this server only.'));
    box.classList.remove('hidden');
  }
  $('u-find').addEventListener('input', () => { if (U.data) renderUsers(); });

  // The Audit page, with the records about users: who added, changed or
  // removed them, and sign-ins.
  {
    const btn = el('button', { class: 'btn btn--ghost', type: 'button', id: 'u-audit' }, icon('scroll-text'), 'Audit');
    btn.addEventListener('click', () => window.openAudit && window.openAudit({ q: 'user' }));
    $('u-add').before(btn);
  }

  // ---------- adding a user ----------
  $('u-add').addEventListener('click', openAddUser);

  function openAddUser() {
    const d = userDialog();
    const close = () => d.close();
    let added = '';
    d.onclose = () => focusRow(added);
    const err = formAlert();
    const username = input('u-f-username', { autocapitalize: 'none', required: '' });
    const name = input('u-f-name', { spellcheck: 'true' });
    const email = input('u-f-email', { type: 'email', inputmode: 'email' });
    const role = roleCards('u-f-role', 'viewer');
    const pw = passwordChoice('u-f', true);
    const submit = el('button', { type: 'submit', class: 'btn btn--primary' }, 'Add user');
    const fields = { username, name, email, role, password: pw.input };
    [username, name, email].forEach((n) => n.addEventListener('input', () => clearField(n)));
    const form = el('form', { novalidate: '' },
      modalHead('u-dialog', 'Add a user', 'They sign in with this username and a password you give them.', close),
      el('div', { class: 'modal__body' }, err,
        field('Username', username, 'Used to sign in. Letters, digits, dots, dashes, underscores or @.'),
        el('div', { class: 'form-grid' }, field('Name', name, null, { optional: true }), field('Email', email, null, { optional: true })),
        role, pw.node),
      footer(cancelButton(d), submit));
    form.addEventListener('submit', async (ev) => {
      ev.preventDefault();
      err.classList.add('hidden');
      clearFields(form);
      if (!username.value.trim()) { markField(username, 'enter a username'); username.focus(); return; }
      if (!pw.check()) return;
      const body = { username: username.value.trim(), name: name.value.trim(), email: email.value.trim(), role: role.value(), password: pw.value(), must_change_password: pw.mustChange() };
      const restore = busy(submit, 'Adding…');
      let res;
      try {
        res = await api('api/users', body);
      } catch (e) {
        restore();
        if (e.field && fields[e.field]) {
          markField(fields[e.field], e.message);
          (fields[e.field].querySelector ? fields[e.field].querySelector('input') || fields[e.field] : fields[e.field]).focus();
        } else {
          showAlert(err, 'The user was not added.', sentence(e.message));
        }
        return;
      }
      const who = res.user.username;
      added = who;
      loadUsers({ quiet: true }).then(() => { if (!d.open) focusRow(who); });
      if (res.temporary_password) {
        showSecret(d, { title: `${who} is added`, who, password: res.temporary_password });
      } else {
        close();
        toast(`${who} can sign in now, as ${roleLabel(res.user.role)}.`, null, { title: 'User added' });
      }
    });
    fill(d, form);
    pw.init();
    d.showModal();
    username.focus();
  }

  // ---------- changing a user ----------
  function openEditUser(u) {
    const d = userDialog();
    const close = () => d.close();
    const err = formAlert();
    const name = input('u-e-name', { spellcheck: 'true' });
    name.value = u.name || '';
    const email = input('u-e-email', { type: 'email', inputmode: 'email' });
    email.value = u.email || '';
    const canRole = (u.actions || []).includes('role');
    const role = canRole ? roleCards('u-e-role', u.role) : null;
    const fields = { name, email, role };
    [name, email].forEach((n) => n.addEventListener('input', () => clearField(n)));
    const submit = el('button', { type: 'submit', class: 'btn btn--primary' }, 'Save');
    d.onclose = () => focusRow(u.username);
    const form = el('form', { novalidate: '' },
      modalHead('u-dialog', 'Edit ' + displayName(u), `Signs in as ${u.username}.`, close),
      el('div', { class: 'modal__body' }, err,
        el('div', { class: 'form-grid' }, field('Name', name, null, { optional: true }), field('Email', email, null, { optional: true })),
        role || el('p', { class: 'hint u-pw-note' }, icon('info'), u.you ? `Your role is ${roleLabel(u.role)}. Another admin can change it.` : `Role: ${roleLabel(u.role)}.`)),
      footer(cancelButton(d), submit));
    form.addEventListener('submit', async (ev) => {
      ev.preventDefault();
      err.classList.add('hidden');
      clearFields(form);
      const body = {};
      if (name.value.trim() !== (u.name || '')) body.name = name.value.trim();
      if (email.value.trim() !== (u.email || '')) body.email = email.value.trim();
      if (role && role.value() !== u.role) body.role = role.value();
      if (!Object.keys(body).length) { close(); return; }
      const restore = busy(submit, 'Saving…');
      let res;
      try {
        res = await api('api/users/' + encodeURIComponent(u.username), body, 'PUT', ifMatch(u, usersShared()));
      } catch (e) {
        restore();
        if (e.field && fields[e.field]) markField(fields[e.field], e.message);
        else changeFailed(err, u, e, 'Nothing was changed.');
        return;
      }
      close();
      loadUsers({ quiet: true }).then(() => focusRow(u.username));
      if (body.role) toast(`${displayName(res.user)} is now ${roleLabel(res.user.role)}. It applies right away.`, null, { title: 'Role changed' });
      else toast('Saved.');
      if (u.you) meReady.then(() => api('api/me').then(showUser).catch(() => {}));
    });
    fill(d, form);
    d.showModal();
    name.focus();
  }

  function openResetPassword(u) {
    const d = userDialog();
    const close = () => d.close();
    const err = formAlert();
    const pw = passwordChoice('u-r', false);
    const submit = el('button', { type: 'submit', class: 'btn btn--primary' }, 'Reset password');
    d.onclose = () => focusRow(u.username);
    const form = el('form', { novalidate: '' },
      modalHead('u-dialog', `Reset ${u.username}’s password`, 'They are signed out everywhere and must choose a new password at their next sign-in.', close),
      el('div', { class: 'modal__body' }, err, pw.node),
      footer(cancelButton(d), submit));
    form.addEventListener('submit', async (ev) => {
      ev.preventDefault();
      err.classList.add('hidden');
      clearFields(form);
      if (!pw.check()) return;
      const restore = busy(submit, 'Resetting…');
      let res;
      try {
        res = await api('api/users/' + encodeURIComponent(u.username) + '/password', pw.value() ? { password: pw.value() } : {}, 'POST', ifMatch(u, usersShared()));
      } catch (e) {
        restore();
        if (e.field === 'password') markField(pw.input, e.message);
        else changeFailed(err, u, e, 'The password was not changed.');
        return;
      }
      loadUsers({ quiet: true }).then(() => { if (!d.open) focusRow(u.username); });
      if (res.temporary_password) {
        showSecret(d, { title: `New password for ${u.username}`, who: u.username, password: res.temporary_password });
      } else {
        close();
        toast(`${u.username} must choose a new password at their next sign-in.`, null, { title: 'Password reset' });
      }
    });
    fill(d, form);
    pw.init();
    d.showModal();
    form.querySelector('.seg button').focus();
  }

  async function setDisabled(u, off) {
    if (off) {
      const ok = await caseConfirm({
        title: `Disable ${u.username}?`,
        text: u.source === 'directory'
          ? 'They are signed out now and stay out, even if the directory accepts their password, until you enable them.'
          : 'They are signed out now and cannot sign in until you enable them.',
        confirm: 'Disable',
      });
      if (!ok) { focusRow(u.username); return; }
    }
    try {
      await api('api/users/' + encodeURIComponent(u.username), { disabled: off }, 'PUT', ifMatch(u, usersShared()));
    } catch (e) {
      toastChangeFailed(u, e, off ? 'Couldn’t disable ' + u.username : 'Couldn’t enable ' + u.username);
      focusRow(u.username);
      return;
    }
    toast(off ? `${u.username} is signed out and cannot sign in.` : `${u.username} can sign in again.`, null, { title: off ? 'User disabled' : 'User enabled' });
    focusRow(u.username);
    loadUsers({ quiet: true }).then(() => focusRow(u.username));
  }

  async function deleteUser(u) {
    const ok = await caseConfirm({
      title: `Delete ${u.username}?`,
      text: u.source === 'directory'
        ? 'They are signed out and removed from this list. If the directory still lets them in, they come back at their next sign-in; disable them instead to keep them out.'
        : 'They are signed out and can no longer sign in. Findings and notes keep their name. This cannot be undone.',
      confirm: 'Delete user',
    });
    if (!ok) { focusRow(u.username); return; }
    try {
      await api('api/users/' + encodeURIComponent(u.username), undefined, 'DELETE', ifMatch(u, usersShared()));
    } catch (e) {
      toastChangeFailed(u, e, 'Couldn’t delete ' + u.username);
      focusRow(u.username);
      return;
    }
    toast(`${u.username} was deleted.`);
    loadUsers({ quiet: true }).then(() => focusRow(''));
  }

  // ---------- tabs ----------
  const TABS = ['users', 'directory'];
  try { if (TABS.includes(localStorage.getItem('signalith.usersTab'))) U.tab = localStorage.getItem('signalith.usersTab'); } catch (_) { /* storage may be blocked */ }
  function selectTab(tab, load) {
    U.tab = tab;
    for (const t of TABS) {
      const b = $('u-tab-' + t);
      b.setAttribute('aria-selected', String(t === tab));
      b.tabIndex = t === tab ? 0 : -1;
      $('u-panel-' + t).hidden = t !== tab;
    }
    // Add user is the primary action of the Users tab only.
    $('u-add').classList.toggle('hidden', tab !== 'users');
    try { localStorage.setItem('signalith.usersTab', tab); } catch (_) { /* ignore */ }
    if (load && tab === 'directory') loadDirectory();
    if (load && tab === 'users') loadUsers({ quiet: true });
  }
  for (const t of TABS) $('u-tab-' + t).addEventListener('click', () => selectTab(t, true));
  // showUsersTab opens the Users page on a tab, for links from other pages
  // (the Security page's "Open Directory sign-in").
  window.showUsersTab = (tab) => {
    if (!TABS.includes(tab)) tab = 'users';
    if (currentPage === 'users') selectTab(tab, true);
    else { U.tab = tab; showPage('users'); }
    const b = $('u-tab-' + tab);
    if (b && currentPage === 'users') b.focus();
  };
  document.querySelector('.u-tabs').addEventListener('keydown', (ev) => {
    if (ev.key !== 'ArrowRight' && ev.key !== 'ArrowLeft') return;
    const next = TABS[(TABS.indexOf(U.tab) + 1) % TABS.length];
    selectTab(next, true);
    $('u-tab-' + next).focus();
  });

  // ---------- directory sign-in ----------
  // D.view is the last api/auth/directory reply; D.form the settings being
  // edited (with bind_password, empty to keep the saved one); D.base the
  // form as saved, to tell when there are unsaved changes.
  const D = { view: null, form: null, base: '', setup: false, seq: 0, inputs: {}, conn: null, user: null, problems: null, connSnap: '', userSnap: '' };
  const PRESET_KEYS = ['type', 'user_filter', 'username_attribute', 'name_attribute', 'email_attribute', 'group_search', 'nested_groups', 'group_filter'];
  // Examples shown in empty fields while setting up; never in the
  // read-only view, where an empty field shows "Not set".
  const EXAMPLE = {
    ad: {
      url: 'e.g. ldaps://dc1.example.com', failover: 'e.g. ldaps://dc2.example.com', bind: 'e.g. CN=svc-signalith,OU=Service Accounts,DC=…',
      base: 'e.g. DC=example,DC=com', group: 'e.g. CN=SOC Analysts,OU=Groups,DC=…', groupBase: 'e.g. OU=Groups,DC=example,DC=com',
    },
    openldap: {
      url: 'e.g. ldaps://ldap.example.com', failover: 'e.g. ldaps://ldap2.example.com', bind: 'e.g. cn=signalith,ou=services,dc=…',
      base: 'e.g. ou=people,dc=example,dc=com', group: 'e.g. cn=soc,ou=groups,dc=…', groupBase: 'e.g. ou=groups,dc=example,dc=com',
    },
  };
  // The saved bind password is only used with the saved servers, bind DN
  // and TLS settings (the server enforces this too).
  const CONN_KEYS = ['url', 'failover_url', 'bind_dn', 'start_tls', 'tls_skip_verify', 'ca_cert'];
  // Test connection reads only these settings, so only they make its
  // result out of date.
  const CONN_TEST_KEYS = CONN_KEYS.concat(['bind_password', 'user_base_dn', 'group_base_dn', 'connect_timeout_seconds', 'timeout_seconds']);
  const connSnapshot = () => JSON.stringify(CONN_TEST_KEYS.map((k) => D.form[k]));
  const ROLE_GROUP_HINT = {
    admin: 'Everything, including detections, intel feeds, data collection and users.',
    analyst: 'Triage, investigations and dashboards.',
    viewer: 'Look and search only.',
  };
  // Which setting a failed test points at, so "Show the setting" can go there.
  const CODE_FIELD = {
    connect: 'url', tls_untrusted: 'ca_cert', tls_hostname: 'url', tls_handshake: 'url', starttls_refused: 'start_tls', ca_cert: 'ca_cert',
    encryption_required: 'start_tls', bind_refused: 'bind_dn', bind_failed: 'bind_dn', bind_required: 'bind_dn', base_not_found: 'user_base_dn',
    search_refused: 'bind_dn', user_not_found: 'user_base_dn', multiple_matches: 'user_filter', no_role: 'admin_groups',
  };

  const dirty = () => !!D.form && JSON.stringify(D.form) !== D.base;
  const readOnly = () => !!(D.view && D.view.from_config);
  // connChanged reports whether the form talks to other servers, as
  // another account or with other TLS settings than the saved ones; then
  // the saved bind password must be typed again.
  const connValue = (k, v) => (k === 'start_tls' || k === 'tls_skip_verify' ? !!v : k === 'bind_dn' ? normDN(v) : String(v || '').trim().toLowerCase());
  const connChanged = () => !!D.view && CONN_KEYS.some((k) => connValue(k, D.form[k]) !== connValue(k, D.view.settings[k]));
  const reuseSaved = () => !readOnly() && D.view.settings.bind_password_set && !connChanged();

  function formFromView(v) {
    const s = Object.assign({}, v.settings);
    delete s.bind_password_set;
    s.enabled = !!s.enabled;
    s.nested_groups = !!s.nested_groups;
    for (const k of ['admin_groups', 'analyst_groups', 'viewer_groups']) s[k] = (s[k] || []).slice();
    s.bind_password = '';
    return s;
  }

  async function loadDirectory() {
    const seq = ++D.seq;
    if (!D.view) renderDirectoryLoading();
    let v;
    try {
      v = await api('api/auth/directory');
    } catch (e) {
      if (seq === D.seq) fill($('u-panel-directory'), el('div', { class: 'card' }, dxEmpty({ tone: 'danger', icon: 'circle-alert', title: 'Couldn’t load the directory settings', text: sentence(e.message), action: dxRetry(loadDirectory) })));
      return;
    }
    if (seq !== D.seq) return;
    D.view = v;
    $('u-dir-on').classList.toggle('hidden', !v.settings.enabled);
    // Keep unsaved edits when coming back to the tab.
    if (!dirty()) {
      D.form = formFromView(v);
      D.base = JSON.stringify(D.form);
    }
    renderDirectory();
  }

  function renderDirectoryLoading() {
    fill($('u-panel-directory'), el('div', { class: 'card u-dir-skel', 'aria-busy': 'true' },
      ...[0, 1, 2].map(() => el('div', { class: 'u-sec' }, el('div', { class: 'u-sec__head' }, dxSkel('90px')), el('div', { class: 'u-sec__body' }, dxSkel('70%'), dxSkel('45%'))))));
  }

  function renderDirectory() {
    const v = D.view;
    const box = $('u-panel-directory');
    D.inputs = {};
    if (!readOnly() && !D.form.enabled && !v.settings.url && !D.setup && !dirty()) {
      fill(box, el('div', { class: 'card' }, el('div', { class: 'empty u-dir-empty' },
        el('span', { class: 'empty__icon' }, icon('building-2')),
        el('div', { class: 'empty__title' }, 'Directory sign-in is off'),
        el('p', { class: 'empty__text' }, 'Let people sign in with their Active Directory or LDAP account. Their groups decide their role.'),
        el('div', { class: 'empty__actions' }, el('button', { type: 'button', class: 'btn btn--primary', onclick: () => {
          D.setup = true;
          renderDirectory();
          const first = D.inputs.url;
          if (first) first.focus();
        } }, 'Set up directory sign-in')))));
      return;
    }
    const scrollY = window.scrollY;
    const focusId = document.activeElement && box.contains(document.activeElement) ? document.activeElement.id : '';
    const side = el('aside', { class: 'u-dir__side', 'aria-label': 'Test the settings' }, testCard());
    fill(box, el('div', { class: 'u-dir' },
      el('div', { class: 'u-dir__main' }, ...directoryForm()), side));
    keepSideInView(side);
    syncBindPassword();
    syncDirty();
    window.scrollTo(0, scrollY);
    if (focusId && $(focusId)) $(focusId).focus({ preventScroll: true });
  }

  // The test card stays in view while the form scrolls, unless it is
  // taller than the window (then its end could never be reached).
  const sideFit = typeof ResizeObserver === 'function' ? new ResizeObserver((entries) => {
    for (const e of entries) e.target.classList.toggle('is-tall', e.target.offsetHeight > window.innerHeight - 100);
  }) : null;
  function keepSideInView(side) {
    if (sideFit) { sideFit.disconnect(); sideFit.observe(side); }
  }

  // ---- the form ----
  function bind(key, control) {
    D.inputs[key] = control;
    const ro = readOnly();
    if (control.type === 'checkbox') {
      control.checked = !!D.form[key];
      control.addEventListener('change', () => { D.form[key] = control.checked; changed(key); });
    } else if (control.type === 'number') {
      control.value = D.form[key] || '';
      control.addEventListener('input', () => { D.form[key] = Number(control.value) || 0; changed(key); });
    } else {
      control.value = D.form[key] == null ? '' : D.form[key];
      control.addEventListener('input', () => { D.form[key] = control.value; changed(key); });
      if (control.tagName === 'SELECT') control.addEventListener('change', () => { D.form[key] = control.value; changed(key); });
    }
    if (ro) control.disabled = true;
    return control;
  }
  function changed(key) {
    clearField(D.inputs[key]);
    if (CONN_KEYS.includes(key)) syncBindPassword();
    syncDirty();
  }

  // syncBindPassword says whether the saved bind password still applies.
  function syncBindPassword() {
    const pw = D.inputs.bind_password;
    if (!pw) return;
    const hintEl = $('ud-bind_password-hint');
    const set = D.view.settings.bind_password_set;
    if (readOnly()) {
      pw.placeholder = set ? 'Saved' : 'Not set';
      return;
    }
    const keep = reuseSaved();
    pw.placeholder = keep ? 'Saved. Type a new one to replace it.' : '';
    if (hintEl) {
      hintEl.textContent = keep ? 'Leave empty to keep the saved password.'
        : set && D.form.bind_dn ? 'Enter it again. The saved password is only sent to the saved server, with the saved bind DN and TLS settings.' : '';
      hintEl.classList.toggle('hidden', !hintEl.textContent);
      hintEl.classList.toggle('u-hint-warn', !keep && !!hintEl.textContent);
    }
  }
  const text = (id, attrs) => input('ud-' + id, Object.assign({ class: 'input mono' }, attrs || {}));
  const area = (id, rows, attrs) => el('textarea', Object.assign({ id: 'ud-' + id, class: 'textarea mono', rows: String(rows), spellcheck: 'false' }, attrs || {}));

  function section(title, desc, ...body) {
    return el('section', { class: 'u-sec' },
      el('div', { class: 'u-sec__head' }, el('h3', { class: 'u-sec__title' }, title), desc ? el('p', { class: 'u-sec__desc' }, desc) : null),
      el('div', { class: 'u-sec__body' }, ...body.filter((b) => b != null)));
  }

  function directoryForm() {
    const v = D.view;
    const f = D.form;
    const ex = EXAMPLE[f.type] || EXAMPLE.ad;
    const ro = readOnly();
    const out = [];

    if (ro) {
      out.push(dxAlert('info', 'From signalith.yaml', null, el('p', {}, 'These settings are in auth.ldap in ', el('code', {}, v.config_file || 'signalith.yaml'),
        '. Change them there, run ', el('code', {}, 'signalith validate'), ' and restart Signalith. The tests use these settings.')));
    }
    if (v.shared) out.push(provenance(v));
    for (const w of v.warnings || []) out.push(dxAlert('warning', w));

    // On or off, and the directory type.
    const on = bind('enabled', el('input', { type: 'checkbox', id: 'ud-enabled', role: 'switch' }));
    const onText = el('span', { class: 'u-dir-switch__state' });
    const syncOn = () => { onText.textContent = on.checked ? 'On' : 'Off'; };
    on.addEventListener('change', syncOn);
    syncOn();
    const typeSeg = el('div', { class: 'seg', role: 'group', 'aria-label': 'Directory type' });
    for (const [t, label] of [['ad', 'Active Directory'], ['openldap', 'OpenLDAP']]) {
      const b = el('button', { type: 'button', 'data-type': t, 'aria-pressed': String(f.type === t), onclick: () => setType(t) }, label);
      if (ro) b.disabled = true;
      typeSeg.append(b);
    }
    const users = v.directory_users || 0;
    const head = el('div', { class: 'u-dir-head' },
      el('div', { class: 'u-dir-head__main' },
        el('label', { class: 'switch u-dir-switch', for: 'ud-enabled' }, on, el('b', {}, 'Directory sign-in'), onText),
        el('p', { class: 'u-dir-head__note' }, f.enabled
          ? (users ? `${plural(users, 'directory user')} signed in so far.` : 'People in a mapped group can sign in with their directory account.')
          : ro ? 'Turned off in signalith.yaml.' : 'Fill in the settings and test them, then turn this on and save.')),
      el('div', { class: 'u-dir-head__type' }, typeSeg,
        ro ? null : el('p', { class: 'u-dir-head__note' }, 'Fills in the usual filters and attributes.')));

    // Read-only: no examples or editing hints, just the values.
    const ph = (example) => (ro ? 'Not set' : example);
    const hint = (h) => (ro ? null : h);
    const url = bind('url', text('url', { placeholder: ph(ex.url), inputmode: 'url' }));
    const failover = bind('failover_url', text('failover_url', { placeholder: ph(ex.failover), inputmode: 'url' }));
    const startTLS = bind('start_tls', el('input', { type: 'checkbox', id: 'ud-start_tls' }));
    const ca = bind('ca_cert', area('ca_cert', 3, { placeholder: ph('-----BEGIN CERTIFICATE-----') }));
    const bindDN = bind('bind_dn', text('bind_dn', { placeholder: ph(ex.bind) }));
    const bindPw = bind('bind_password', input('ud-bind_password', { type: 'password', autocomplete: 'new-password' }));
    const base = bind('user_base_dn', text('user_base_dn', { placeholder: ph(ex.base) }));
    const groupBase = bind('group_base_dn', text('group_base_dn', { placeholder: ph(ex.groupBase) }));

    const server = section('Server', 'Where your directory is.',
      field('Server address', url, hint('ldaps:// uses port 636. For ldap:// on port 389, also turn on StartTLS.')),
      field('Second server', failover, hint('Used only when the first cannot be reached.'), { optional: !ro }),
      el('div', { class: 'field' }, el('label', { class: 'check' }, startTLS, 'Use StartTLS'),
        el('div', { class: 'hint u-indent', id: 'ud-start_tls-hint' }, 'Encrypts an ldap:// connection before the password is sent.')),
      field('CA certificate', ca, hint('Paste it (PEM) if your own CA signed the directory’s certificate.'), { optional: !ro }));
    startTLS.setAttribute('aria-describedby', 'ud-start_tls-hint');

    const account = section('Service account', 'Searches for users when they sign in. Read access is enough.',
      field('Bind DN', bindDN, hint('Leave the bind DN and password empty to search anonymously.')),
      field('Password', bindPw, ro ? null : ' '));

    const usersSec = section('Users', 'Where to look for people.',
      field('User base DN', base, hint('Signalith searches here and everything under it.')));

    const noGroup = el('fieldset', { class: 'u-radio-row', id: 'ud-default_role' }, el('legend', { class: 'label' }, 'People in none of these groups'));
    for (const [val, label] of [['none', 'Can’t sign in'], ['viewer', 'Sign in as Viewer']]) {
      const r = el('input', { type: 'radio', name: 'ud-default-role', value: val });
      r.checked = (f.default_role || 'none') === val;
      if (ro) r.disabled = true;
      r.addEventListener('change', () => { D.form.default_role = val; changed('default_role'); });
      noGroup.append(el('label', { class: 'check' }, r, label));
    }
    D.inputs.default_role = noGroup;
    const searchesGroups = f.group_search === 'search' || !!f.nested_groups;
    const groupsSec = section('Groups and roles', 'People get the highest role of any group they are in, nested groups included.',
      searchesGroups ? field('Group base DN', groupBase, hint('Where to look for groups. Empty searches the whole domain.'), { optional: !ro }) : null,
      ...ROLE_ORDER.map((r) => groupBlock(r, ex.group)),
      noGroup);
    if (f.group_search === 'search' || !f.nested_groups) groupsSec.querySelector('.u-sec__desc').textContent = 'People get the highest role of any group they are in.';

    out.push(el('div', { class: 'card u-dir-form' }, head, server, account, usersSec, groupsSec, moreSettings(), ro ? null : saveBar()));
    return out;
  }

  // provenance says, when every server shares the settings, where the
  // ones in use came from.
  function provenance(v) {
    const f = v.from || {};
    const on = f.node ? ` on ${f.node}` : '';
    const when = f.at ? `, ${new Date(f.at).toLocaleString()}` : '';
    const from = {
      yaml: `Applied from signalith.yaml${on}${when}.`,
      page: `Saved on this page${on}${when}.`,
      import: `Brought in from ${f.node ? f.node + '’s' : 'the first server’s'} settings when the servers began sharing users${when}.`,
      env: `Service account password last set from SIGNALITH_LDAP_BIND_PASSWORD${on}${when}.`,
    }[f.source];
    return dxAlert('info', 'These settings apply on every server.', (from ? from + ' ' : '') +
      'A change saved here applies on every server at once. A later change to auth.ldap in a server’s signalith.yaml applies too, when that server starts.');
  }

  function groupBlock(role, example) {
    const key = role + '_groups';
    const ro = readOnly();
    const list = el('div', { class: 'u-groups__list' });
    const block = el('div', { class: 'u-groups', id: 'ud-' + key, 'data-role': role });
    const sync = () => {
      D.form[key] = [...list.querySelectorAll('input')].map((i) => i.value);
      changed(key);
    };
    const addRow = (value, focus) => {
      const inp = el('input', { class: 'input mono', type: 'text', spellcheck: 'false', autocomplete: 'off', placeholder: ro ? '' : example, 'aria-label': `${ROLE_LABEL[role]} group DN` });
      inp.value = value;
      if (ro) inp.disabled = true;
      inp.addEventListener('input', sync);
      const rm = ro ? null : el('button', { type: 'button', class: 'btn btn--ghost btn--icon btn--sm', title: 'Remove', 'aria-label': `Remove this ${ROLE_LABEL[role]} group` }, icon('x'));
      const row = el('div', { class: 'u-group-row' }, inp, rm);
      if (rm) {
        rm.addEventListener('click', () => {
          const next = row.nextElementSibling || row.previousElementSibling;
          row.remove();
          sync();
          (next ? next.querySelector('input') : add).focus();
        });
      }
      list.append(row);
      if (focus) inp.focus();
    };
    const add = el('button', { type: 'button', class: 'btn btn--ghost btn--sm u-groups__add' }, icon('plus'), 'Add group');
    add.addEventListener('click', () => { addRow('', true); sync(); });
    (D.form[key] || []).forEach((g) => addRow(g));
    const none = !(D.form[key] || []).length;
    block.append(...[
      el('div', { class: 'u-groups__head' }, el('span', { class: 'badge u-role', 'data-role': role }, ROLE_LABEL[role]), el('span', { class: 'u-groups__desc' }, ROLE_GROUP_HINT[role])),
      list,
      ro ? (none ? el('p', { class: 'u-groups__none' }, 'No groups.') : null) : add,
    ].filter(Boolean));
    D.inputs[key] = block;
    return block;
  }

  function moreSettings() {
    const f = D.form;
    const filter = bind('user_filter', area('user_filter', 3));
    const userAttr = bind('username_attribute', text('username_attribute'));
    const nameAttr = bind('name_attribute', text('name_attribute'));
    const mailAttr = bind('email_attribute', text('email_attribute'));
    const how = bind('group_search', el('select', { id: 'ud-group_search', class: 'select select--block' },
      el('option', { value: 'memberof' }, 'The user’s memberOf attribute'),
      el('option', { value: 'search' }, 'A search for groups that list the user')));
    how.addEventListener('change', () => renderDirectory());
    const nested = bind('nested_groups', el('input', { type: 'checkbox', id: 'ud-nested_groups' }));
    nested.addEventListener('change', () => renderDirectory());
    const gfilter = bind('group_filter', area('group_filter', 3));
    const connect = bind('connect_timeout_seconds', input('ud-connect_timeout_seconds', { type: 'number', min: '1', max: '120', inputmode: 'numeric' }));
    const timeout = bind('timeout_seconds', input('ud-timeout_seconds', { type: 'number', min: '1', max: '300', inputmode: 'numeric' }));
    const skip = bind('tls_skip_verify', el('input', { type: 'checkbox', id: 'ud-tls_skip_verify' }));
    const search = f.group_search === 'search';
    const det = el('details', { class: 'u-more', id: 'ud-more' },
      el('summary', {}, icon('sliders-horizontal'), 'More settings', el('span', { class: 'u-more__sub hide-sm' }, 'Filters, attributes, group lookup, timeouts'), icon('chevron-down', 'chev')),
      el('div', { class: 'u-more__body' },
        field('User filter', filter, '{username} is replaced by the name typed at sign-in, safely escaped.'),
        el('div', { class: 'form-grid u-grid-3' },
          field('Username attribute', userAttr), field('Name attribute', nameAttr), field('Email attribute', mailAttr)),
        field('How to find a user’s groups', how),
        search ? null : el('div', { class: 'field' }, el('label', { class: 'check' }, nested, 'Count nested groups'),
          el('div', { class: 'hint u-indent' }, 'Active Directory only: a member of a group inside a mapped group gets its role.')),
        search ? field('Group filter', gfilter, '{dn} is the user’s DN and {username} their username.') : null,
        el('div', { class: 'form-grid' },
          field('Connect timeout (seconds)', connect), field('Search timeout (seconds)', timeout)),
        el('div', { class: 'u-danger' + (f.tls_skip_verify ? ' is-on' : '') },
          el('label', { class: 'check' }, skip, el('b', {}, 'Don’t check the server’s certificate')),
          el('p', {}, 'Unsafe: anyone who can intercept the connection can read passwords. Only for a quick test; paste the CA certificate instead.'))));
    skip.addEventListener('change', () => skip.closest('.u-danger').classList.toggle('is-on', skip.checked));
    if (D.openMore) det.open = true;
    det.addEventListener('toggle', () => { D.openMore = det.open; });
    return det;
  }

  function saveBar() {
    const status = el('span', { class: 'u-savebar__status', id: 'ud-status', role: 'status' });
    const discard = el('button', { type: 'button', class: 'btn btn--ghost', id: 'ud-discard' }, 'Discard changes');
    const save = el('button', { type: 'button', class: 'btn btn--primary', id: 'ud-save' }, 'Save');
    discard.addEventListener('click', () => {
      D.form = formFromView(D.view);
      D.base = JSON.stringify(D.form);
      D.problems = null;
      D.setup = false;
      // Results of tests on the discarded settings no longer apply.
      D.conn = D.user = null;
      D.connSnap = D.userSnap = '';
      renderDirectory();
      toast('Changes discarded.');
    });
    save.addEventListener('click', saveDirectory);
    return el('div', { class: 'u-savebar' }, D.problems ? problemsAlert(D.problems) : null,
      el('div', { class: 'u-savebar__row' }, status, el('span', { class: 'spacer' }), discard, save));
  }
  function problemsAlert(list) {
    return dxAlert('danger', 'Some settings need fixing.', null, el('ul', { class: 'u-problems' }, ...list.map((p) => el('li', {}, sentence(p)))));
  }
  function syncDirty() {
    const d = dirty();
    const save = $('ud-save');
    if (save) save.disabled = !d;
    const discard = $('ud-discard');
    if (discard) discard.classList.toggle('hidden', !d);
    const status = $('ud-status');
    if (status) {
      status.textContent = d ? 'Unsaved changes' : D.view.saved ? 'Saved' : 'Not saved yet';
      status.closest('.u-savebar').classList.toggle('is-dirty', d || !!D.problems);
    }
    syncStale();
  }
  // A test result says when the settings changed since the test.
  function syncStale() {
    for (const [id, snap, now] of [['ud-test-out', D.connSnap, connSnapshot()], ['ud-test-user-out', D.userSnap, JSON.stringify(D.form)]]) {
      const out = $(id);
      if (out) out.classList.toggle('is-stale', !!snap && snap !== now && !readOnly());
    }
  }
  window.addEventListener('beforeunload', (ev) => { if (dirty() && !readOnly()) { ev.preventDefault(); ev.returnValue = ''; } });

  function setType(t) {
    if (D.form.type === t) return;
    const p = (D.view.presets || {})[t];
    if (p) for (const k of PRESET_KEYS) D.form[k] = Array.isArray(p[k]) ? p[k].slice() : p[k];
    D.form.type = t;
    renderDirectory();
    const b = document.querySelector(`.u-dir-head [data-type="${t}"]`);
    if (b) b.focus();
    toast(`Filters and attributes are set for ${t === 'ad' ? 'Active Directory' : 'OpenLDAP'}. See More settings.`);
  }

  // focusSetting opens More settings if needed and puts focus on a setting.
  function focusSetting(key) {
    const c = D.inputs[key];
    if (!c) return;
    const more = c.closest('details');
    if (more) more.open = true;
    c.scrollIntoView({ block: 'center' });
    const target = c.matches('input, textarea, select') ? c : c.querySelector('input, textarea, select, button');
    if (target) target.focus({ preventScroll: true });
  }

  async function saveDirectory() {
    const save = $('ud-save');
    const restore = busy(save, 'Saving…');
    const wasOn = !!D.view.settings.enabled;
    let v;
    try {
      v = await api('api/auth/directory', D.form, 'PUT', ifMatch(D.view, D.view.shared));
    } catch (e) {
      restore();
      if (e.status === 412) {
        // Someone changed the settings since the page read them. The form
        // keeps these changes; saving again replaces theirs.
        toast(`${changedBy(e)} Your changes are still in the form: save again to replace theirs, or Discard changes to see them.`, null,
          { tone: 'warning', title: 'Someone else changed the directory settings' });
        loadDirectory();
      } else if (e.status === 400 && e.problems) {
        D.problems = e.problems;
        renderDirectory();
        const keys = Object.keys(e.fields || {});
        for (const k of keys) if (D.inputs[k]) markField(D.inputs[k], e.fields[k]);
        if (keys.some((k) => D.inputs[k] && D.inputs[k].closest('details'))) $('ud-more').open = true;
        const first = Object.keys(D.inputs).find((k) => keys.includes(k));
        if (first) focusSetting(first);
      } else if (e.code !== 'forbidden') {
        toastError(e.status === 503 ? 'The settings can’t be changed right now' : 'The settings were not saved', e);
      }
      return;
    }
    D.view = v;
    D.problems = null;
    D.form = formFromView(v);
    D.base = JSON.stringify(D.form);
    $('u-dir-on').classList.toggle('hidden', !v.settings.enabled);
    const remap = D.user && D.user.mapped && D.user.user ? D.user.user.username : '';
    renderDirectory();
    // A result read with an unsaved mapping is checked again, now saved.
    if (remap) lookupUser(remap, '');
    const on = !!v.settings.enabled;
    toast(on === wasOn ? 'Directory settings saved.' : on ? 'People in mapped groups can now sign in with their directory account.' : 'Directory users can no longer sign in.',
      null, { title: on === wasOn ? 'Saved' : on ? 'Directory sign-in is on' : 'Directory sign-in is off' });
    if (U.data) loadUsers({ quiet: true });
  }

  // ---- testing ----
  function testCard() {
    const ro = readOnly();
    const connBtn = el('button', { type: 'button', class: 'btn btn--secondary', id: 'ud-test' }, icon('network'), 'Test connection');
    const connOut = el('div', { class: 'u-test__out', id: 'ud-test-out', 'aria-live': 'polite' }, D.conn ? connResult(D.conn) : null);
    connBtn.addEventListener('click', async () => {
      const restore = busy(connBtn, 'Testing…');
      fill(connOut, el('p', { class: 'u-test__busy' }, 'Connecting…'));
      const snap = connSnapshot();
      try {
        D.conn = await api('api/auth/directory/test', ro ? {} : { settings: D.form });
      } catch (e) {
        D.conn = e.problems ? { ok: false, problems: e.problems, fields: e.fields } : { ok: false, message: sentence(e.message), servers: [] };
      }
      D.connSnap = snap;
      restore();
      fill(connOut, connResult(D.conn));
      syncStale();
    });

    const who = input('ud-test-user', { autocapitalize: 'none', placeholder: 'jane or jane@example.com' });
    who.value = D.testWho || '';
    who.addEventListener('input', () => { D.testWho = who.value; });
    const pw = input('ud-test-password', { type: 'password', autocomplete: 'new-password', placeholder: 'Optional' });
    const userBtn = el('button', { type: 'submit', class: 'btn btn--secondary' }, icon('search'), 'Look up');
    const userOut = el('div', { class: 'u-test__out', id: 'ud-test-user-out', 'aria-live': 'polite' }, D.user ? userResult(D.user) : null);
    const form = el('form', { class: 'u-test__form', novalidate: '' },
      field('Username', who),
      field('Password', pw, 'With a password, it is checked too.', { optional: true }),
      el('div', {}, userBtn));
    who.addEventListener('input', () => clearField(who));
    form.addEventListener('submit', async (ev) => {
      ev.preventDefault();
      if (!who.value.trim()) { markField(who, 'enter a username to look up'); who.focus(); return; }
      const restore = busy(userBtn, 'Looking up…');
      const password = pw.value;
      pw.value = '';
      await lookupUser(who.value.trim(), password);
      restore();
    });

    return el('div', { class: 'card u-test' },
      el('div', { class: 'card__head' }, el('div', {}, el('h3', { class: 'card__title' }, 'Test'),
        el('p', { class: 'card__sub' }, ro ? 'Uses the settings from signalith.yaml.' : 'Uses the form as it is, saved or not.'))),
      el('div', { class: 'card__body u-test__body' },
        el('div', { class: 'u-test__part' }, el('p', { class: 'u-test__lead' }, 'Connect and sign in as the service account.'), el('div', {}, connBtn), connOut),
        el('div', { class: 'u-test__part' }, el('h4', { class: 'u-test__title' }, 'Test a user'),
          el('p', { class: 'u-test__lead' }, 'Find someone as sign-in would, and see the role they would get.'), form, userOut)));
  }

  // lookupUser runs Test a user and shows the result.
  async function lookupUser(username, password) {
    const out = () => $('ud-test-user-out');
    if (out()) fill(out(), el('p', { class: 'u-test__busy' }, 'Looking up ' + username + '…'));
    const body = { username, password: password || '' };
    if (!readOnly()) body.settings = D.form;
    const snap = JSON.stringify(D.form);
    try {
      D.user = await api('api/auth/directory/test-user', body);
    } catch (e) {
      D.user = e.problems ? { ok: false, problems: e.problems, fields: e.fields } : { ok: false, message: sentence(e.message) };
    }
    D.userSnap = snap;
    if (out()) fill(out(), userResult(D.user));
    syncStale();
  }

  // staleNote shows (through CSS) when the settings changed since a test.
  const staleNote = () => el('p', { class: 'u-stale' }, icon('info'), 'The settings changed since this test. Test again to check them.');

  // settingLink goes to the setting a failed test points at.
  const settingLink = (key) => (key && D.inputs[key] && !readOnly()
    ? el('button', { type: 'button', class: 'link-btn u-goto', onclick: () => focusSetting(key) }, 'Show the setting', icon('arrow-right', 'icon--xs')) : null);
  const showSettingLink = (code) => settingLink(CODE_FIELD[code]);

  function problemsResult(r) {
    const first = Object.keys(D.inputs).find((k) => k in (r.fields || {}));
    return el('div', { class: 'u-result' }, staleNote(), dxAlert('danger', 'Fill in these settings first.', null, el('div', {},
      el('ul', { class: 'u-problems' }, ...r.problems.map((p) => el('li', {}, sentence(p)))), withLink(settingLink(first)))));
  }

  function connResult(r) {
    if (r.problems) return problemsResult(r);
    const servers = r.servers || [];
    const kids = [dxAlert(r.ok ? 'success' : 'danger', r.ok ? r.message : 'The test failed.', !r.ok && !servers.length ? r.message : null)];
    for (const s of servers) {
      kids.push(el('div', { class: 'u-steps' },
        servers.length > 1 || !r.ok ? el('div', { class: 'u-steps__server mono' }, s.url) : null,
        el('ul', { class: 'u-steps__list', role: 'list' }, ...(s.steps || []).map((st) => el('li', { 'data-ok': String(st.ok) },
          icon(st.ok ? 'circle-check' : 'circle-x'), el('span', {}, st.message)))),
        !s.ok ? withLink(showSettingLink(s.code)) : null,
        s.detail ? el('details', { class: 'u-detail' }, el('summary', {}, 'Technical detail'), el('code', {}, s.detail)) : null));
    }
    return el('div', { class: 'u-result' }, staleNote(), ...kids);
  }

  // Groups are compared the way the server does, roughly: case and the
  // spaces around separators do not matter.
  const normDN = (dn) => String(dn || '').toLowerCase().replace(/\s*([,=+])\s*/g, '$1').trim();
  function mappedRole(dn) {
    for (const r of ROLE_ORDER) if ((D.form[r + '_groups'] || []).some((g) => normDN(g) === normDN(dn))) return r;
    return '';
  }
  // formRole is the role groups give with the mappings in the form.
  function formRole(groups) {
    for (const r of ROLE_ORDER) if (groups.some((g) => mappedRole(g) === r)) return r;
    return D.form.default_role === 'viewer' ? 'viewer' : '';
  }
  const cnOf = (dn) => { const m = /^\s*[a-z]+=((?:\\.|[^,])+)/i.exec(dn || ''); return m ? m[1].replace(/\\(.)/g, '$1') : dn; };

  // splitMessage makes a server message's first sentence the title.
  function splitMessage(m) {
    const i = String(m || '').search(/\.\s+[A-Z]/);
    return i < 0 ? [m, null] : [m.slice(0, i + 1), m.slice(i + 1).trim()];
  }
  const withLink = (link) => (link ? el('div', { class: 'u-goto-row' }, link) : null);

  function userResult(r) {
    if (r.problems) return problemsResult(r);
    const u = r.user;
    // After "Add to <role>" here, the result shows what the unsaved
    // mapping gives rather than what the test found.
    const pending = r.mapped && u && (r.ok || r.code === 'no_role') ? formRole(u.groups || []) : null;
    const tone = r.ok ? 'success' : r.code === 'no_role' ? 'warning' : 'danger';
    const [title, rest] = splitMessage(r.message);
    const kids = [pending != null && pending !== (u.role || '')
      ? dxAlert(pending ? 'info' : 'warning', pending ? `${u.username} signs in as ${roleLabel(pending)} once you save.` : `${u.username} still can’t sign in.`,
        pending ? 'Save the settings, then test again to check.' : 'None of their groups is mapped to a role.')
      : dxAlert(tone, title, rest, r.ok ? null : withLink(showSettingLink(r.code)))];
    if (r.warning) kids.push(dxAlert('info', r.warning));
    if (u) {
      const groups = u.groups || [];
      const role = pending != null ? pending : u.role;
      const roleNode = role ? el('span', { class: 'badge u-role', 'data-role': role }, roleLabel(role)) : el('span', { class: 'muted' }, 'None');
      const rows = [
        ['Found', el('span', { class: 'mono u-dn' }, u.dn)],
        u.name ? ['Name', u.name] : null,
        u.email ? ['Email', u.email] : null,
        ['Role', pending != null && pending !== (u.role || '') ? el('span', {}, roleNode, el('span', { class: 'muted u-after-save' }, ' after you save')) : roleNode],
      ].filter(Boolean);
      kids.push(el('dl', { class: 'kv u-kv' }, ...rows.flatMap(([k, val]) => [el('dt', {}, k), el('dd', {}, val)])));
      kids.push(groupList(groups));
    }
    return el('div', { class: 'u-result' }, staleNote(), ...kids);
  }

  function groupList(groups) {
    const head = el('div', { class: 'u-glist__head' }, el('span', { class: 'section-title' }, 'Groups ', el('span', { class: 'count' }, String(groups.length))));
    if (!groups.length) return el('div', { class: 'u-glist' }, head, el('p', { class: 'muted' }, 'None found.'));
    const sorted = groups.slice().sort((a, b) => (mappedRole(a) ? 0 : 1) - (mappedRole(b) ? 0 : 1) || cnOf(a).localeCompare(cnOf(b)));
    const LIMIT = 8;
    const item = (dn) => {
      const role = mappedRole(dn);
      const addTo = !role && !readOnly() ? dxMenu('Map ' + cnOf(dn) + ' to a role', ROLE_ORDER.map((rr) => ({
        icon: 'plus', label: 'Add to ' + ROLE_LABEL[rr], run: () => {
          D.form[rr + '_groups'] = (D.form[rr + '_groups'] || []).filter((g) => g.trim()).concat(dn);
          // The result now reads with this mapping, so it is not out of date.
          if (D.user) { D.user.mapped = true; D.userSnap = JSON.stringify(D.form); }
          renderDirectory();
          const li = [...document.querySelectorAll('#ud-test-user-out li[data-dn]')].find((n) => n.dataset.dn === dn);
          if (li) li.focus();
          toast(`${cnOf(dn)} gives the ${ROLE_LABEL[rr]} role once you save.`);
        },
      }))) : null;
      if (addTo) addTo.classList.add('u-glist__menu');
      return el('li', { 'data-dn': dn, tabindex: '-1' }, el('div', { class: 'u-glist__text' }, el('b', {}, cnOf(dn)), el('span', { class: 'mono', title: dn }, dn)),
        role ? el('span', { class: 'badge u-role', 'data-role': role }, ROLE_LABEL[role]) : null, addTo);
    };
    const ul = el('ul', { class: 'u-glist__list', role: 'list' }, ...sorted.slice(0, LIMIT).map(item));
    const more = sorted.length > LIMIT ? el('button', { type: 'button', class: 'link-btn', onclick: (ev) => { ul.replaceChildren(...sorted.map(item)); ev.currentTarget.remove(); } }, `Show all ${sorted.length}`) : null;
    return el('div', { class: 'u-glist' }, head, ul, more);
  }

  // ---------- Change password (account menu) ----------
  $('change-password').addEventListener('click', () => {
    $('user-menu').removeAttribute('open');
    openChangePassword();
  });

  function openChangePassword() {
    const d = modalDialog('u-pw-dialog');
    const close = () => d.close();
    const err = formAlert();
    const cur = el('input', { id: 'u-pw-current', class: 'input', type: 'password', autocomplete: 'current-password' });
    const next = el('input', { id: 'u-pw-new', class: 'input', type: 'password', autocomplete: 'new-password' });
    const again = el('input', { id: 'u-pw-again', class: 'input', type: 'password', autocomplete: 'new-password' });
    [cur, next, again].forEach((n) => n.addEventListener('input', () => clearField(n)));
    const submit = el('button', { type: 'submit', class: 'btn btn--primary' }, 'Change password');
    const form = el('form', { novalidate: '' },
      modalHead('u-pw-dialog', 'Change your password', 'Other browsers signed in as you are signed out.', close),
      el('div', { class: 'modal__body' }, err,
        field('Current password', cur),
        field('New password', next, 'At least 8 characters.'),
        field('New password again', again)),
      footer(cancelButton(d), submit));
    form.addEventListener('submit', async (ev) => {
      ev.preventDefault();
      err.classList.add('hidden');
      clearFields(form);
      if (!cur.value) { markField(cur, 'enter your current password'); cur.focus(); return; }
      if (next.value.length < 8) { markField(next, 'enter at least 8 characters'); next.focus(); return; }
      if (again.value !== next.value) { markField(again, 'the two new passwords are not the same'); again.focus(); return; }
      const restore = busy(submit, 'Changing…');
      try {
        await api('api/me/password', { current_password: cur.value, new_password: next.value });
      } catch (e) {
        restore();
        const target = { current_password: cur, new_password: next }[e.field];
        if (target) { markField(target, e.message); target.focus(); target.select(); } else showAlert(err, 'Your password was not changed.', sentence(e.message));
        return;
      }
      close();
      toast('Other browsers signed in as you were signed out.', null, { title: 'Password changed' });
    });
    fill(d, form);
    d.showModal();
    cur.focus();
  }
}());
