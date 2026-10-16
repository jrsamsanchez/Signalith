// Ticketing page (admins): connections to Jira (Cloud or Data Center) and
// ServiceNow, which cases open tickets in and stay in step with. The server
// keeps them in one file and takes them whole (PUT api/ticketing): every
// change here sends the whole list back, with the secrets left empty, which
// keeps them. Secrets are never sent to the page; a connection only says
// whether each is set.
'use strict';

(function () {
  const TK = { data: null, seq: 0, tests: new Map() };
  const TYPES = {
    jira: { label: 'Jira', icon: 'layers', name: 'SOC project', hint: 'Jira Cloud or Data Center: one project, any issue type.' },
    servicenow: { label: 'ServiceNow', icon: 'inbox', name: 'Service desk', hint: 'Incidents, or another table with a state field.' },
  };
  const TYPE_ORDER = ['jira', 'servicenow'];
  const STATUS_TEXT = { new: 'New', in_progress: 'In progress', pending: 'Pending', resolved: 'Resolved', closed: 'Closed' };
  const SEV_TEXT = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', informational: 'Informational' };

  pageHooks.push((name) => { if (name === 'ticketing') load(); });
  $('tk-add').addEventListener('click', () => openConnection(null, 'jira'));

  const box = () => $('tk-page');
  const plural = (n, one, many) => `${n.toLocaleString()} ${n === 1 ? one : many || one + 's'}`;
  const typeOf = (t) => TYPES[t] || { label: t, icon: 'ticket' };
  const manage = () => !!(TK.data && TK.data.manage);
  const newID = () => {
    const b = new Uint8Array(6);
    crypto.getRandomValues(b);
    return [...b].map((x) => x.toString(16).padStart(2, '0')).join('');
  };
  const host = (u) => String(u || '').replace(/^https?:\/\//, '');

  async function load(quiet) {
    const seq = ++TK.seq;
    if (!TK.data && !quiet) {
      box().setAttribute('aria-busy', 'true');
      fill(box(), el('div', { class: 'card' }, el('div', { class: 'tk-skel' }, dxSkel('60%'), dxSkel('40%'), dxSkel('75%'))));
    }
    try {
      const d = await api('api/ticketing');
      if (seq !== TK.seq) return;
      TK.data = d;
      render();
    } catch (e) {
      if (seq !== TK.seq) return;
      box().removeAttribute('aria-busy');
      fill(box(), el('div', { class: 'card' }, dxEmpty({ tone: 'danger', icon: 'circle-alert', title: 'Couldn’t load ticketing', text: e.message, action: dxRetry(() => load()) })));
    }
  }

  // ---------- the page ----------
  function render() {
    const d = TK.data;
    box().removeAttribute('aria-busy');
    if (box().querySelector('details.menu[open]')) { TK.deferred = true; return; }
    TK.deferred = false;
    $('tk-add').classList.toggle('hidden', !manage() || !d.connections.length);
    fill(box(), notes(), connectionsCard(), d.problems && d.problems.length ? problemsCard() : null, d.connections.length ? howCard() : null);
  }

  function notes() {
    const d = TK.data;
    const list = [];
    if (d.file_error) list.push(dxAlert('danger', 'Nothing syncs until the ticketing file is fixed.', d.file_error));
    if (d.links_error) list.push(dxAlert('warning', 'Couldn’t read the tickets kept in step.', d.links_error));
    if (!d.manage && !d.file_error) {
      const servers = el('a', { href: '#servers', 'data-page': 'servers' }, 'Servers page');
      if (d.runs_on) {
        list.push(dxAlert('info', `Ticketing is set up on ${d.runs_on}.`, null,
          el('p', {}, `Only the server that runs the background jobs talks to Jira and ServiceNow, with its own connections. Change them on ${d.runs_on}; the `, servers, ' has its address.')));
      } else {
        list.push(dxAlert('info', 'Ticketing is set up on another server.', d.manage_why || ''));
      }
    }
    if (d.connections.length && !d.public_url) {
      list.push(dxAlert('info', 'Tickets have no link back to their case.', 'Set this server’s public address (server.public_url) on the Settings page, so each ticket links to its case in Signalith.'));
    }
    return list.length ? el('div', { class: 'tk-notes' }, ...list) : null;
  }

  function connectionsCard() {
    const d = TK.data;
    if (!d.connections.length) return el('div', { class: 'card' }, emptyState());
    const failing = d.connections.reduce((n, c) => n + (c.failing || 0) + (c.problem ? 1 : 0), 0);
    return el('section', { class: 'card', 'aria-labelledby': 'tk-conn-title' },
      el('div', { class: 'card__head' }, el('div', {},
        el('h3', { class: 'card__title', id: 'tk-conn-title' }, 'Connections'),
        el('p', { class: 'card__sub' }, 'Where cases open tickets · ' + plural(d.connections.length, 'connection') + (failing ? ` · ${failing} failing` : '')))),
      el('div', { class: 'tk-conns' }, ...d.connections.map(connectionCard)));
  }

  function emptyState() {
    const actions = el('div', { class: 'tk-starts' });
    if (manage()) {
      for (const t of TYPE_ORDER) {
        actions.append(el('button', { class: 'tk-start', type: 'button', onclick: () => openConnection(null, t) },
          el('span', { class: 'tk-type' }, icon(TYPES[t].icon)),
          el('span', { class: 'tk-start__text' }, el('b', {}, TYPES[t].label), el('span', {}, TYPES[t].hint))));
      }
    }
    return el('div', { class: 'empty tk-empty' },
      el('span', { class: 'empty__icon' }, icon('ticket')),
      el('div', { class: 'empty__title' }, 'No ticketing connections yet'),
      el('p', { class: 'empty__text' }, manage()
        ? 'Connect a Jira project or a ServiceNow table. Analysts then open a ticket from a case, and the two stay in step: status, notes and comments go both ways.'
        : 'Connections are set up on the server that runs the background jobs.'),
      actions.childElementCount ? actions : null);
  }

  function where(c) {
    return c.type === 'jira' ? `${host(c.url)} · ${c.project}` : `${host(c.url)} · ${c.table}`;
  }

  function connectionCard(c) {
    const t = typeOf(c.type);
    const test = TK.tests.get(c.id);
    let state = 'ok';
    let text = c.tickets ? `${plural(c.tickets, 'ticket')} kept in step` : 'No tickets yet';
    if (c.problem) { state = 'bad'; text = c.problem; } else if (c.failing) { state = 'bad'; text = `${plural(c.failing, 'ticket')} failing to sync`; } else if (!c.tickets) state = 'none';
    const items = manage() ? [{ icon: 'pencil', label: 'Edit', run: () => openConnection(c) }, 'sep', { icon: 'trash-2', label: 'Delete', danger: true, run: () => deleteConnection(c) }] : [];
    const menu = items.length ? dxMenu('Actions for ' + c.name, items) : null;
    if (menu) {
      menu.querySelector('summary').classList.add('btn--sm');
      menu.addEventListener('toggle', () => { if (!menu.open && TK.deferred) setTimeout(render); });
    }
    const testBtn = manage() ? el('button', { class: 'btn btn--secondary btn--sm', type: 'button', disabled: !!(test && test.busy) }, icon('plug-zap'), test && test.busy ? 'Testing…' : 'Test') : null;
    if (testBtn) testBtn.addEventListener('click', () => runTest(c));
    const flags = [];
    if (c.sync_status) flags.push('Status');
    if (c.sync_notes) flags.push('Notes');
    if (c.auto_create) flags.push(`Auto: ${SEV_TEXT[c.auto_min_severity] || c.auto_min_severity}${c.auto_min_severity === 'critical' ? '' : ' and up'}`);
    let result = null;
    if (test && !test.busy) {
      result = el('div', { class: 'tk-result', 'data-tone': test.ok ? 'success' : 'danger', role: test.ok ? 'status' : 'alert' },
        icon(test.ok ? 'circle-check' : 'circle-alert'), el('span', {}, test.text));
    }
    return el('article', { class: 'tk-conn', 'data-state': state, 'aria-label': `${c.label}: ${text}` },
      el('div', { class: 'tk-conn__top' },
        el('span', { class: 'tk-type', title: t.label }, icon(t.icon)),
        el('div', { class: 'tk-conn__text' },
          el('div', { class: 'tk-conn__name', title: c.name }, c.name),
          el('div', { class: 'tk-conn__dest', title: where(c) }, t.label, ' · ', where(c))),
        menu),
      el('div', { class: 'tk-conn__state' }, el('span', { class: 'tk-dot', 'data-state': state, 'aria-hidden': 'true' }), el('span', {}, text)),
      el('div', { class: 'tk-conn__foot' },
        el('span', { class: 'tk-flags' }, ...(flags.length ? flags : ['Opens tickets only']).map((f) => el('span', { class: 'badge badge--outline' }, f))),
        testBtn),
      el('div', { 'aria-live': 'polite' }, result));
  }

  async function runTest(c) {
    TK.tests.set(c.id, { busy: true });
    render();
    let r;
    try {
      r = await api('api/ticketing/test', { id: c.id });
    } catch (e) {
      r = { ok: false, error: e.message };
    }
    TK.tests.set(c.id, { ok: r.ok, text: r.ok ? r.message : r.error });
    load(true);
  }

  function problemsCard() {
    const d = TK.data;
    const conn = (id) => d.connections.find((c) => c.id === id);
    const rows = d.problems.map((p) => {
      const c = conn(p.connection);
      return el('li', { class: 'tk-problem' },
        el('div', { class: 'tk-problem__head' },
          el('a', { href: '#cases?id=' + encodeURIComponent(p.case_id), class: 'mono' }, p.case_id),
          el('span', {}, p.key ? `${c ? c.label : p.connection} ${p.key}` : (c ? c.label : p.connection)),
          el('span', { class: 'tk-problem__when', title: fmtTime(p.error_at) }, ago(p.error_at))),
        el('p', { class: 'tk-problem__err' }, p.error));
    });
    return el('section', { class: 'card', 'aria-labelledby': 'tk-prob-title' },
      el('div', { class: 'card__head' }, el('div', {},
        el('h3', { class: 'card__title', id: 'tk-prob-title' }, 'Tickets that need attention'),
        el('p', { class: 'card__sub' }, 'The latest problems keeping a case and its ticket in step; each is tried again by itself'))),
      el('ul', { class: 'tk-problems' }, ...rows));
  }

  function howCard() {
    const d = TK.data;
    return el('section', { class: 'card tk-how', 'aria-labelledby': 'tk-how-title' },
      el('div', { class: 'card__head' }, el('h3', { class: 'card__title', id: 'tk-how-title' }, 'How syncing works')),
      el('ul', { class: 'tk-how__list' },
        el('li', {}, 'Every minute, this server asks each system which tickets changed. New comments become case notes, and a new ticket status moves the case.'),
        el('li', {}, 'A case’s new notes become comments that start with ', el('span', { class: 'mono' }, d.marker), ', and a new case status, title or severity changes the ticket. When both change at once, the case wins.'),
        el('li', {}, 'A ticket gets only the case’s title, severity, status, description, notes and a link to the case: never events or search results.')));
  }

  // ---------- saving ----------
  function asInput(c) {
    return {
      id: c.id, name: c.name, type: c.type, url: c.url, auth: c.auth, email: c.email || '', username: c.username || '', client_id: c.client_id || '',
      project: c.project || '', issue_type: c.issue_type || '', set_priority: c.set_priority !== false, priorities: { ...(c.priorities || {}) },
      table: c.table || '', comment_field: c.comment_field || '', close_code: c.close_code || '', caller_id: c.caller_id || '', assignment_group: c.assignment_group || '',
      statuses: { ...(c.statuses || {}) }, sync_notes: !!c.sync_notes, sync_status: !!c.sync_status, auto_create: !!c.auto_create,
      auto_min_severity: c.auto_min_severity || 'high', allow_loopback: !!c.allow_loopback, ca_pem: c.ca_pem || '',
    };
  }

  async function save(change, done, opts = {}) {
    const d = TK.data;
    const input = { revision: d.revision, connections: d.connections.map(asInput) };
    change(input);
    try {
      TK.data = await api('api/ticketing', input, 'PUT');
    } catch (e) {
      if (opts.quiet) return e;
      toastError(e.status === 409 ? 'The settings changed elsewhere' : 'Couldn’t save', e);
      if (e.status === 409) load(true);
      return false;
    }
    render();
    if (done) toast(done);
    return true;
  }

  function confirmBox(o) {
    const dlg = $('tk-confirm');
    return new Promise((resolve) => {
      let result = false;
      const cancel = el('button', { class: 'btn btn--ghost', type: 'button', onclick: () => dlg.close() }, 'Cancel');
      const ok = el('button', { class: 'btn btn--danger', type: 'button' }, o.confirm);
      ok.addEventListener('click', () => { result = true; dlg.close(); });
      dlg.onclose = () => resolve(result);
      fill(dlg,
        el('div', { class: 'modal__head' }, el('div', {}, el('h2', { class: 'modal__title', id: 'tk-confirm-title' }, o.title), el('p', { class: 'modal__desc', id: 'tk-confirm-desc' }, o.text))),
        el('div', { class: 'modal__foot' }, cancel, ok));
      dlg.showModal();
      cancel.focus();
    });
  }

  async function deleteConnection(c) {
    const text = 'New tickets can’t be opened in it, and its tickets stop being kept in step. The tickets themselves stay in ' + typeOf(c.type).label + ', and cases keep their links. Its saved secrets are deleted.';
    if (!await confirmBox({ title: `Delete ${c.name}?`, text, confirm: 'Delete connection' })) return;
    TK.tests.delete(c.id);
    await save((inp) => { inp.connections = inp.connections.filter((x) => x.id !== c.id); }, `Deleted ${c.name}.`);
  }

  // ---------- form helpers ----------
  let fieldSeq = 0;
  const fid = (p) => `tk-f${++fieldSeq}-${p}`;
  const input = (p, attrs = {}) => el('input', { class: 'input', id: fid(p), type: 'text', autocomplete: 'off', spellcheck: 'false', 'data-field': p, ...attrs });
  function field(labelText, control, hint) {
    const hid = hint ? control.id + '-hint' : null;
    if (hid) control.setAttribute('aria-describedby', hid);
    return el('div', { class: 'field', 'data-field': control.dataset.field || '' }, el('label', { class: 'label', for: control.id }, labelText),
      control, hint ? el('p', { class: 'hint', id: hid }, hint) : null);
  }
  const check = (control, text, hint) => el('div', { class: 'field' }, el('label', { class: 'check' }, control, el('span', {}, text)), hint ? el('p', { class: 'hint' }, hint) : null);
  function markError(form, name, msg) {
    const f = form.querySelector(`[data-field="${CSS.escape(name)}"]`);
    if (!f) return false;
    const ctl = f.matches('input, select, textarea') ? f : f.querySelector('input, select, textarea');
    if (ctl) ctl.setAttribute('aria-invalid', 'true');
    (f.closest('.field') || f).append(el('p', { class: 'field-error', 'data-error': '' }, icon('circle-alert'), msg));
    return true;
  }
  function clearErrors(form) {
    form.querySelectorAll('[data-error]').forEach((n) => n.remove());
    form.querySelectorAll('[aria-invalid]').forEach((n) => n.removeAttribute('aria-invalid'));
  }
  function showProblems(form, msgBox, e, at, fallback) {
    const others = [];
    let first = null;
    for (const p of e.problems || []) {
      const msg = sentence(p.message.replace(/^[^:]*: /, ''));
      if (p.where === at && markError(form, p.field, msg)) {
        first = first || form.querySelector(`[aria-invalid="true"]`);
      } else {
        others.push(sentence(p.message));
      }
    }
    if (!(e.problems || []).length) others.push(e.message);
    fill(msgBox, others.length ? dxAlert('danger', fallback, others.join(' ')) : null);
    if (first) {
      const more = first.closest('details');
      if (more) more.open = true;
      first.focus();
    } else {
      msgBox.scrollIntoView({ block: 'nearest' });
    }
  }
  const select = (p, options, value) => {
    const s = el('select', { id: fid(p), class: 'select select--block', 'data-field': p }, ...options.map(([v, l]) => el('option', { value: v }, l)));
    s.value = value;
    return s;
  };

  // ---------- connection dialog ----------
  function openConnection(c, type) {
    const d = TK.data;
    const dlg = $('tk-dialog');
    const edit = !!c;
    let kind = edit ? c.type : type || 'jira';
    const id = edit ? c.id : newID();
    const at = 'connection:' + id;
    const msg = el('div', { class: 'nt-msg', 'aria-live': 'polite' });
    const form = el('form', { class: 'nt-form', novalidate: '', autocomplete: 'off' });
    const v = edit ? asInput(c) : { name: '', url: '', auth: '', sync_notes: true, sync_status: true, set_priority: true, auto_min_severity: 'high', statuses: {}, priorities: {} };

    const name = input('name', { maxlength: '80' });
    name.value = v.name;
    const url = input('url', { class: 'input mono', inputmode: 'url' });
    url.value = v.url;
    const email = input('email', { type: 'email', placeholder: 'signalith-bot@example.com' });
    email.value = v.email || '';
    const token = input('token', { type: 'password', autocomplete: 'new-password' });
    const username = input('username', { placeholder: 'signalith.integration' });
    username.value = v.username || '';
    const password = input('password', { type: 'password', autocomplete: 'new-password' });
    const clientID = input('client_id');
    clientID.value = v.client_id || '';
    const clientSecret = input('client_secret', { type: 'password', autocomplete: 'new-password' });
    const project = input('project', { class: 'input mono', placeholder: 'SEC', maxlength: '50' });
    project.value = v.project || '';
    const issueType = input('issue_type', { placeholder: 'Task' });
    issueType.value = v.issue_type || '';
    const setPriority = el('input', { type: 'checkbox' });
    setPriority.checked = v.set_priority !== false;
    const table = input('table', { class: 'input mono', placeholder: 'incident' });
    table.value = v.table || '';
    const commentField = select('comment_field', [['work_notes', 'Work notes (only the people working the ticket see them)'], ['comments', 'Additional comments (the caller sees them too)']], v.comment_field || 'work_notes');
    const closeCode = input('close_code', { placeholder: 'Solution provided' });
    closeCode.value = v.close_code || '';
    const caller = input('caller_id', { class: 'input mono', placeholder: 'Optional: a user’s sys_id' });
    caller.value = v.caller_id || '';
    const group = input('assignment_group', { class: 'input mono', placeholder: 'Optional: a group’s sys_id' });
    group.value = v.assignment_group || '';
    const syncNotes = el('input', { type: 'checkbox' });
    syncNotes.checked = v.sync_notes;
    const syncStatus = el('input', { type: 'checkbox' });
    syncStatus.checked = v.sync_status;
    const auto = el('input', { type: 'checkbox' });
    auto.checked = !!v.auto_create;
    const autoSev = select('auto_min_severity', (d.severities || []).slice().reverse().map((s) => [s, SEV_TEXT[s] + (s === 'critical' ? ' only' : ' and above')]), v.auto_min_severity || 'high');
    const loop = el('input', { type: 'checkbox' });
    loop.checked = !!v.allow_loopback;
    const ca = el('textarea', { class: 'textarea mono', id: fid('ca'), rows: '3', placeholder: '-----BEGIN CERTIFICATE-----', 'data-field': 'ca_pem', spellcheck: 'false' });
    ca.value = v.ca_pem || '';
    const statusInputs = {};
    const priorityInputs = {};
    let auth = v.auth;

    const typeSeg = el('div', { class: 'seg nt-type-seg', role: 'group', 'aria-label': 'System' });
    const authSeg = el('div', { class: 'seg nt-type-seg', role: 'group', 'aria-label': 'How Signalith signs in', 'data-field': 'auth' });
    const panel = el('div', { class: 'nt-form__panel' });
    const savedSecret = (field) => edit && c.type === kind && c.auth === auth && c[field + '_set'];
    const secretHint = (field, what) => (savedSecret(field) ? `Saved. Leave empty to keep it; type a new ${what} to replace it.` : null);
    const draw = () => {
      if (kind === 'jira' && !['cloud', 'bearer'].includes(auth)) auth = 'cloud';
      if (kind === 'servicenow' && !['basic', 'oauth'].includes(auth)) auth = 'basic';
      fill(typeSeg, ...TYPE_ORDER.map((k) => {
        const b = el('button', { type: 'button', 'aria-pressed': String(k === kind) }, icon(TYPES[k].icon), TYPES[k].label);
        b.addEventListener('click', () => { if (kind !== k) { kind = k; auth = ''; draw(); } });
        return b;
      }));
      const auths = kind === 'jira' ? [['cloud', 'Cloud: email and API token'], ['bearer', 'Data Center: access token']] : [['basic', 'User name and password'], ['oauth', 'OAuth client']];
      fill(authSeg, ...auths.map(([k, l]) => {
        const b = el('button', { type: 'button', 'aria-pressed': String(k === auth) }, l);
        b.addEventListener('click', () => { if (auth !== k) { auth = k; draw(); } });
        return b;
      }));
      name.placeholder = TYPES[kind].name;
      url.placeholder = kind === 'jira' ? (auth === 'bearer' ? 'https://jira.example.com' : 'https://example.atlassian.net') : 'https://example.service-now.com';
      for (const [ctl, f, what, ph] of [[token, 'token', 'token', auth === 'bearer' ? 'Personal access token' : 'API token'], [password, 'password', 'password', 'Password'], [clientSecret, 'client_secret', 'secret', 'Client secret']]) {
        ctl.placeholder = savedSecret(f) ? 'Saved · type to replace' : ph;
        ctl.dataset.what = what;
      }
      clearErrors(form);
      fill(msg);
      const parts = [field('Name', name, 'Shown on cases and in the audit log.'), field(kind === 'jira' ? 'Site address' : 'Instance address', url,
        kind === 'jira' ? 'The address you open Jira at. For Data Center, include its context path, such as /jira.' : 'The address you open ServiceNow at.'),
      el('div', { class: 'field' }, el('span', { class: 'label' }, 'Sign in with'), authSeg)];
      if (kind === 'jira' && auth === 'cloud') {
        parts.push(el('div', { class: 'nt-row' }, field('Account email', email), field('API token', token, secretHint('token', 'token'))));
        parts.push(el('p', { class: 'hint tk-hint' }, 'Create the token at id.atlassian.com › Security › API tokens, signed in as the account tickets come from. A dedicated account is best.'));
      } else if (kind === 'jira') {
        parts.push(field('Personal access token', token, secretHint('token', 'token') || 'In Jira: your profile › Personal Access Tokens › Create token.'));
      } else if (auth === 'basic') {
        parts.push(el('div', { class: 'nt-row' }, field('User name', username), field('Password', password, secretHint('password', 'password'))));
        parts.push(el('p', { class: 'hint tk-hint' }, 'A dedicated integration user with the itil role (and read access to sys_journal_field to bring comments back).'));
      } else {
        parts.push(el('div', { class: 'nt-row' }, field('Client ID', clientID), field('Client secret', clientSecret, secretHint('client_secret', 'secret'))));
        parts.push(el('p', { class: 'hint tk-hint' }, 'An OAuth application (System OAuth › Application Registry) with the client credentials grant allowed.'));
      }
      if (kind === 'jira') {
        parts.push(el('div', { class: 'nt-row' }, field('Project key', project), field('Issue type', issueType, 'Task when left empty.')));
      } else {
        parts.push(el('div', { class: 'nt-row' }, field('Table', table, 'incident when left empty.'), field('Case notes go to', commentField)));
      }
      parts.push(el('div', { class: 'field tk-sync' }, el('span', { class: 'label' }, 'Keep in step'),
        el('label', { class: 'check' }, syncStatus, el('span', {}, 'Status: a case’s status moves its ticket, and the ticket’s moves the case')),
        el('label', { class: 'check' }, syncNotes, el('span', {}, 'Notes and comments, both ways'))));
      const autoRow = el('div', { class: 'field', 'data-field': 'auto_create' }, el('label', { class: 'check' }, auto, el('span', {}, 'Open a ticket for every new case')),
        el('div', { class: 'tk-auto', hidden: !auto.checked }, autoSev),
        el('p', { class: 'hint' }, 'Only cases opened from when this is turned on, at this severity or above. Sample data never gets one.'));
      auto.onchange = () => { autoRow.querySelector('.tk-auto').hidden = !auto.checked; };
      parts.push(autoRow);

      // status mapping and the rest
      const mapRows = (d.statuses || []).map((s) => {
        const inp = statusInputs[s] || input('st-' + s, { class: 'input mono', 'aria-label': `${STATUS_TEXT[s] || s} in ${TYPES[kind].label}` });
        if (!statusInputs[s]) inp.value = (v.statuses || {})[s] || '';
        statusInputs[s] = inp;
        inp.dataset.field = 'statuses';
        inp.placeholder = kind === 'jira' ? { new: 'To Do', in_progress: 'In Progress', pending: 'Any “in progress” status', resolved: 'Done', closed: 'Done' }[s] : (d.default_states || {})[s] || '';
        return el('div', { class: 'tk-map__row' }, el('span', {}, STATUS_TEXT[s] || s), inp);
      });
      const mapHint = kind === 'jira'
        ? 'Jira status names, separated by commas, in order of preference. Empty goes by the status’s category: To Do, In Progress or Done.'
        : 'Incident state numbers: 1 New, 2 In Progress, 3 On Hold, 6 Resolved, 7 Closed. Canceled (8) closes the case.';
      const more = [el('div', { class: 'field', 'data-field': 'statuses' }, el('span', { class: 'label' }, 'Case status to ticket status'), el('div', { class: 'tk-map' }, ...mapRows), el('p', { class: 'hint' }, mapHint))];
      if (kind === 'jira') {
        more.push(check(setPriority, 'Set the issue’s priority from the case’s severity', 'Turned off by itself if the project’s screens don’t have the Priority field.'));
        more.push(el('div', { class: 'field', 'data-field': 'priorities' }, el('span', { class: 'label' }, 'Priority for each severity'),
          el('div', { class: 'tk-map' }, ...(d.severities || []).slice().reverse().map((s) => {
            const inp = priorityInputs[s] || input('pr-' + s, { 'aria-label': `Priority for ${SEV_TEXT[s]}` });
            if (!priorityInputs[s]) inp.value = (v.priorities || {})[s] || '';
            priorityInputs[s] = inp;
            inp.dataset.field = 'priorities';
            inp.placeholder = (d.default_priorities || {})[s] || '';
            return el('div', { class: 'tk-map__row' }, el('span', {}, SEV_TEXT[s]), inp);
          }))));
      } else {
        more.push(field('Close code', closeCode, 'Set with the close notes when a case is resolved or closed; it must be one your instance offers.'));
        more.push(el('div', { class: 'nt-row' }, field('Caller', caller), field('Assignment group', group)));
      }
      more.push(check(loop, 'Allow this server’s own addresses', 'For a test system on this machine (http://localhost too). Off, Signalith never connects to its own, cloud metadata or its OpenSearch addresses.'));
      more.push(field('Certificate authority', ca, 'PEM certificates of a private certificate authority the system’s certificate comes from. The system’s trusted ones always count.'));
      const details = el('details', { class: 'nt-more' }, el('summary', {}, icon('chevron-right', 'nt-chev'), 'Mapping and advanced'), el('div', { class: 'nt-more__body' }, ...more));
      fill(panel, ...parts, details);
    };

    const read = () => {
      const out = {
        id, name: name.value.trim() || TYPES[kind].name, type: kind, url: url.value.trim(), auth,
        sync_notes: syncNotes.checked, sync_status: syncStatus.checked, auto_create: auto.checked, auto_min_severity: autoSev.value,
        allow_loopback: loop.checked, ca_pem: ca.value.trim(), statuses: {},
      };
      for (const [s, inp] of Object.entries(statusInputs)) if (inp.value.trim()) out.statuses[s] = inp.value.trim();
      if (kind === 'jira') {
        Object.assign(out, { project: project.value.trim(), issue_type: issueType.value.trim(), set_priority: setPriority.checked, priorities: {} });
        for (const [s, inp] of Object.entries(priorityInputs)) if (inp.value.trim()) out.priorities[s] = inp.value.trim();
        if (auth === 'cloud') out.email = email.value.trim();
        out.token = token.value;
      } else {
        Object.assign(out, { table: table.value.trim(), comment_field: commentField.value, close_code: closeCode.value.trim(), caller_id: caller.value.trim(), assignment_group: group.value.trim() });
        if (auth === 'basic') { out.username = username.value.trim(); out.password = password.value; } else { out.client_id = clientID.value.trim(); out.client_secret = clientSecret.value; }
      }
      return out;
    };

    const testOut = el('span', { class: 'nt-test-out', 'aria-live': 'polite' });
    const testBtn = el('button', { class: 'btn btn--ghost', type: 'button' }, icon('plug-zap'), 'Test');
    const saveBtn = el('button', { class: 'btn btn--primary', type: 'submit' }, edit ? 'Save changes' : 'Add connection');
    testBtn.addEventListener('click', async () => {
      clearErrors(form);
      fill(msg);
      testBtn.disabled = true;
      fill(testOut, el('span', { class: 'nt-test-out__busy' }, 'Testing…'));
      let r;
      try {
        r = await api('api/ticketing/test', { connection: read() });
      } catch (e) {
        testBtn.disabled = false;
        if (e.problems) { fill(testOut); showProblems(form, msg, e, 'connection:' + id, 'Fix these settings first.'); return; }
        r = { ok: false, error: e.message };
      }
      testBtn.disabled = false;
      fill(testOut, el('span', { 'data-tone': r.ok ? 'success' : 'danger' }, icon(r.ok ? 'circle-check' : 'circle-alert'), r.ok ? 'Works' : 'Failed'));
      fill(msg, r.ok ? dxAlert('success', 'The connection works.', r.message) : dxAlert('danger', 'The connection doesn’t work yet.', r.error));
    });
    form.addEventListener('submit', async (ev) => {
      ev.preventDefault();
      clearErrors(form);
      fill(msg);
      saveBtn.disabled = true;
      const conn = read();
      const r = await save((inp) => {
        const i = inp.connections.findIndex((x) => x.id === id);
        if (i >= 0) inp.connections[i] = conn; else inp.connections.push(conn);
      }, null, { quiet: true });
      saveBtn.disabled = false;
      if (r !== true) {
        showProblems(form, msg, r, at, edit ? 'Couldn’t save the connection.' : 'Couldn’t add the connection.');
        return;
      }
      dlg.close();
      toast(edit ? `Saved ${conn.name}.` : `Added ${conn.name}. Analysts can now open tickets from a case.`);
    });
    fill(form,
      el('div', { class: 'modal__body' }, edit ? null : typeSeg, msg, panel),
      el('div', { class: 'modal__foot nt-foot' }, el('div', { class: 'nt-foot__test' }, testBtn, testOut), el('span', { class: 'spacer' }),
        el('button', { class: 'btn btn--ghost', type: 'button', onclick: () => dlg.close() }, 'Cancel'), saveBtn));
    fill(dlg,
      el('div', { class: 'modal__head' }, el('div', {},
        el('h2', { class: 'modal__title', id: 'tk-dialog-title' }, edit ? `Edit ${c.name}` : 'Add a ticketing connection'),
        el('p', { class: 'modal__desc' }, edit ? `${TYPES[kind].label} · secrets you leave empty stay as they are.` : 'A Jira project or ServiceNow table that cases open tickets in.')),
      el('button', { class: 'btn btn--ghost btn--icon btn--sm', type: 'button', 'aria-label': 'Close', onclick: () => dlg.close() }, icon('x'))),
      form);
    draw();
    dlg.showModal();
    (edit ? name : url).focus();
  }
})();
