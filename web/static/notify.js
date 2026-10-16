// Notifications page (admins): channels (where messages go: Slack, Teams,
// email or a webhook), rules (which findings go to which channels) and
// the latest deliveries. The server keeps channels and rules in one file
// and takes them whole (PUT api/notify): every change here sends the
// whole list back, with the secrets left empty, which keeps them. Secrets
// are never sent to the page; a channel only says whether each is set.
'use strict';

(function () {
  const NT = {
    data: null, deliveries: null, delivErr: '', seq: 0, busy: false,
    tests: new Map(), // channel id -> { busy, ok, text } of the latest Send test
    detections: null, // for the rule dialog's picker, loaded on first use
  };
  const TYPES = {
    slack: { label: 'Slack', icon: 'hash', name: '#soc', hint: 'An incoming webhook posts to one Slack channel.' },
    teams: { label: 'Teams', icon: 'users', name: 'SOC team', hint: 'A Teams workflow posts to one channel or chat.' },
    email: { label: 'Email', icon: 'mail', name: 'SOC email', hint: 'Signalith sends through your mail server.' },
    webhook: { label: 'Webhook', icon: 'webhook', name: 'SOAR', hint: 'A JSON POST to any address, such as a SOAR or ticketing system.' },
  };
  const TYPE_ORDER = ['slack', 'teams', 'email', 'webhook'];
  const LEAST = [['critical', 'Critical'], ['high', 'High'], ['medium', 'Medium'], ['low', 'Low'], ['informational', 'Any']];
  const LEAST_HINT = {
    critical: 'Only critical findings.', high: 'High and critical findings.', medium: 'Medium, high and critical findings.',
    low: 'Every finding but informational ones.', informational: 'Every finding.',
  };

  pageHooks.push((name) => { if (name === 'notify') load(); });
  $('nt-add-channel').addEventListener('click', () => openChannel(null, 'slack'));
  $('nt-add-rule').addEventListener('click', () => openRule(null));

  const box = () => $('nt-page');
  const plural = (n, one, many) => `${n.toLocaleString()} ${n === 1 ? one : many || one + 's'}`;
  const typeOf = (t) => TYPES[t] || { label: t, icon: 'send' };
  // label names a channel with its type, as the server's summaries do.
  const label = (c) => (c.name.toLowerCase().includes(typeOf(c.type).label.toLowerCase()) ? c.name : `${typeOf(c.type).label} ${c.name}`);
  const channelByID = (id) => ((NT.data && NT.data.channels) || []).find((c) => c.id === id);
  const manage = () => !!(NT.data && NT.data.manage);
  const newID = () => {
    const b = new Uint8Array(6);
    crypto.getRandomValues(b);
    return [...b].map((x) => x.toString(16).padStart(2, '0')).join('');
  };

  async function load(quiet) {
    const seq = ++NT.seq;
    if (!NT.data && !quiet) skeleton();
    try {
      const [d, del] = await Promise.all([
        api('api/notify'),
        api('api/notify/deliveries?limit=50').catch((e) => ({ error: e.message })),
      ]);
      if (seq !== NT.seq) return;
      NT.data = d;
      NT.deliveries = del.deliveries || null;
      NT.delivErr = del.error || '';
      render();
    } catch (e) {
      if (seq !== NT.seq) return;
      box().removeAttribute('aria-busy');
      fill(box(), el('div', { class: 'card' }, dxEmpty({ tone: 'danger', icon: 'circle-alert', title: 'Couldn’t load notifications', text: e.message, action: dxRetry(() => load()) })));
    }
  }

  function skeleton() {
    box().setAttribute('aria-busy', 'true');
    const bars = (n) => el('div', { class: 'nt-skel' }, ...Array.from({ length: n }, (_, i) => dxSkel(['60%', '40%', '75%'][i % 3])));
    fill(box(), el('div', { class: 'card' }, bars(3)), el('div', { class: 'card' }, bars(2)));
  }

  // ---------- the page ----------
  function render() {
    const d = NT.data;
    box().removeAttribute('aria-busy');
    // A redraw would close an open row menu; wait until it closes.
    if (box().querySelector('details.menu[open]')) { NT.deferred = true; return; }
    NT.deferred = false;
    const active = document.activeElement;
    const key = active && box().contains(active) ? (active.closest('[data-key]') || {}).dataset : null;
    const focusKey = key ? key.key : null;
    const hasChannels = d.channels.length > 0;
    $('nt-add-channel').classList.toggle('hidden', !manage() || !hasChannels);
    $('nt-add-rule').classList.toggle('hidden', !manage() || !hasChannels);
    fill(box(), notes(), channelsCard(), hasChannels ? rulesCard() : null, hasChannels || (NT.deliveries || []).length ? deliveriesCard() : null);
    if (focusKey) {
      const again = box().querySelector(`[data-key="${CSS.escape(focusKey)}"]`);
      if (again) (again.matches('details') ? again.querySelector('summary') : again).focus({ preventScroll: true });
    }
  }

  function notes() {
    const d = NT.data;
    const list = [];
    if (d.file_error) list.push(dxAlert('danger', 'Nothing is sent until the notifications file is fixed.', d.file_error));
    if (!d.manage && !d.file_error) {
      const servers = el('a', { href: '#servers', 'data-page': 'servers' }, 'Servers page');
      if (d.runs_on) {
        list.push(dxAlert('info', `Notifications are set up on ${d.runs_on}.`, null,
          el('p', {}, `Only the server that runs the background jobs sends them, with its own channels and rules. Change them on ${d.runs_on}; the `, servers, ' has its address.')));
      } else {
        list.push(dxAlert('info', 'Notifications are set up on another server.', d.manage_why || ''));
      }
    }
    if (d.channels.length && !d.link) {
      list.push(dxAlert('info', 'Messages have no link back to Signalith.', 'Set this server’s public address (server.public_url) on the Settings page, so each message links to the Findings page.'));
    }
    return list.length ? el('div', { class: 'nt-notes' }, ...list) : null;
  }

  // ---------- channels ----------
  function channelsCard() {
    const d = NT.data;
    if (!d.channels.length) return el('div', { class: 'card' }, channelsEmpty());
    const sub = [plural(d.channels.length, 'channel')];
    const failing = d.channels.filter((c) => c.problem || (c.last && c.last.status === 'failed')).length;
    if (failing) sub.push(`${failing} failing`);
    return el('section', { class: 'card nt-card', 'aria-labelledby': 'nt-ch-title' },
      el('div', { class: 'card__head' }, el('div', {},
        el('h3', { class: 'card__title', id: 'nt-ch-title' }, 'Channels'),
        el('p', { class: 'card__sub' }, 'Where messages go · ' + sub.join(' · ')))),
      el('div', { class: 'nt-channels' }, ...d.channels.map(channelCard)));
  }

  function channelsEmpty() {
    const actions = el('div', { class: 'nt-starts' });
    if (manage()) {
      for (const t of TYPE_ORDER) {
        actions.append(el('button', { class: 'nt-start', type: 'button', 'data-key': 'start:' + t, onclick: () => openChannel(null, t) },
          el('span', { class: 'nt-type', 'data-type': t }, icon(TYPES[t].icon)),
          el('span', { class: 'nt-start__text' }, el('b', {}, TYPES[t].label), el('span', {}, TYPES[t].hint))));
      }
    }
    return el('div', { class: 'empty nt-empty' },
      el('span', { class: 'empty__icon' }, icon('bell')),
      el('div', { class: 'empty__title' }, 'No notifications yet'),
      el('p', { class: 'empty__text' }, manage()
        ? 'Add a channel where messages should go, then a rule that says which findings go there. High and critical findings are a good start.'
        : 'Channels and rules are set up on the server that runs the background jobs.'),
      actions.childElementCount ? actions : null);
  }

  function destination(c) {
    if (c.type === 'email') {
      const to = c.to || [];
      return to.length ? to[0].replace(/^.*<|>$/g, '') + (to.length > 1 ? ` +${to.length - 1}` : '') : 'No recipients';
    }
    return c.url_server ? c.url_server.replace(/^https?:\/\//, '') : 'No URL';
  }

  function channelState(c) {
    if (c.problem) return ['bad', 'Needs attention', c.problem];
    const l = c.last;
    if (!l) return ['none', 'No messages yet', ''];
    const what = l.kind === 'test' ? 'Test' : 'Last message';
    if (l.status === 'sent') return ['ok', `${what} delivered ${ago(l.time)}`, ''];
    return ['bad', `${what} failed ${ago(l.time)}`, l.error || ''];
  }

  function channelCard(c) {
    const t = typeOf(c.type);
    const [state, text, detail] = channelState(c);
    const test = NT.tests.get(c.id);
    const items = [];
    if (manage()) {
      items.push({ icon: 'pencil', label: 'Edit', run: () => openChannel(c) });
      items.push('sep', { icon: 'trash-2', label: 'Delete', danger: true, run: () => deleteChannel(c) });
    }
    const menu = items.length ? dxMenu('Actions for ' + c.name, items) : null;
    if (menu) {
      menu.dataset.key = 'm:' + c.id;
      menu.querySelector('summary').classList.add('btn--sm');
      menu.addEventListener('toggle', () => { if (!menu.open && NT.deferred) setTimeout(render); });
    }
    const testBtn = manage() ? el('button', { class: 'btn btn--secondary btn--sm', type: 'button', 'data-key': 't:' + c.id }, icon('send'), test && test.busy ? 'Sending…' : 'Send test') : null;
    if (testBtn) {
      testBtn.disabled = !!(test && test.busy);
      testBtn.addEventListener('click', () => sendTest(c));
    }
    const used = c.rules.length ? `Used by ${c.rules.length === 1 ? c.rules[0] : plural(c.rules.length, 'rule')}` : 'Not used by a rule';
    let result = null;
    if (test && !test.busy) {
      result = el('div', { class: 'nt-result', 'data-tone': test.ok ? 'success' : 'danger', role: test.ok ? 'status' : 'alert' },
        icon(test.ok ? 'circle-check' : 'circle-alert'), el('span', {}, test.text));
    }
    return el('article', { class: 'nt-ch', 'data-state': state, 'aria-label': `${label(c)}: ${text}` },
      el('div', { class: 'nt-ch__top' },
        el('span', { class: 'nt-type', 'data-type': c.type, title: t.label }, icon(t.icon)),
        el('div', { class: 'nt-ch__text' },
          el('div', { class: 'nt-ch__name', title: c.name }, c.name),
          el('div', { class: 'nt-ch__dest', title: destination(c) }, t.label, ' · ', destination(c))),
        menu),
      el('div', { class: 'nt-ch__state' }, el('span', { class: 'nt-dot', 'data-state': state, 'aria-hidden': 'true' }),
        el('span', { title: c.last ? fmtTime(c.last.time) : '' }, text)),
      detail ? el('p', { class: 'nt-ch__err', title: detail }, detail) : null,
      el('div', { class: 'nt-ch__foot' }, el('span', { class: 'nt-ch__used' }, used), testBtn),
      el('div', { 'aria-live': 'polite' }, result));
  }

  async function sendTest(c) {
    NT.tests.set(c.id, { busy: true });
    render();
    let r;
    try {
      r = await api('api/notify/test', { id: c.id });
    } catch (e) {
      r = { ok: false, error: e.message };
    }
    NT.tests.set(c.id, { ok: r.ok, text: r.ok ? `Sent in ${fmtMS(r.duration_ms)}. Check that it arrived in ${label(c)}.` : r.error });
    load(true);
  }

  const fmtMS = (ms) => (ms < 1000 ? `${Math.max(1, ms || 0)} ms` : `${(ms / 1000).toFixed(1)} s`);

  // ---------- rules ----------
  function rulesCard() {
    const d = NT.data;
    const on = d.rules.filter((r) => r.enabled).length;
    const head = el('div', { class: 'card__head' }, el('div', {},
      el('h3', { class: 'card__title', id: 'nt-rule-title-list' }, 'Rules'),
      el('p', { class: 'card__sub' }, 'Which findings go where' + (d.rules.length ? ` · ${on} of ${d.rules.length} on` : ''))));
    if (!d.rules.length) {
      return el('section', { class: 'card nt-card', 'aria-labelledby': 'nt-rule-title-list' }, head,
        el('div', { class: 'empty empty--compact' },
          el('div', { class: 'empty__title' }, 'No rules yet'),
          el('p', { class: 'empty__text' }, 'Nothing is sent until a rule says which findings go to which channels.'),
          manage() ? el('div', { class: 'empty__actions' }, el('button', { class: 'btn btn--primary btn--sm', type: 'button', 'data-key': 'rule:add', onclick: () => openRule(null) }, icon('plus'), 'Add rule')) : null));
    }
    return el('section', { class: 'card nt-card', 'aria-labelledby': 'nt-rule-title-list' }, head,
      el('ul', { class: 'nt-rules' }, ...d.rules.map(ruleRow)));
  }

  function ruleRow(r) {
    const sw = el('input', { type: 'checkbox', role: 'switch', 'aria-label': `${r.name}: on`, 'data-key': 'sw:' + r.id });
    sw.checked = r.enabled;
    sw.disabled = !manage();
    sw.addEventListener('change', async () => {
      sw.disabled = true;
      const ok = await save((inp) => { inp.rules.find((x) => x.id === r.id).enabled = sw.checked; },
        sw.checked ? `${r.name} is on. Findings raised from now on are sent.` : `${r.name} is off.`);
      if (!ok) { sw.checked = !sw.checked; sw.disabled = false; }
    });
    const items = manage() ? [{ icon: 'pencil', label: 'Edit', run: () => openRule(r) }, 'sep', { icon: 'trash-2', label: 'Delete', danger: true, run: () => deleteRule(r) }] : [];
    const menu = items.length ? dxMenu('Actions for ' + r.name, items) : null;
    if (menu) {
      menu.dataset.key = 'rm:' + r.id;
      menu.querySelector('summary').classList.add('btn--sm');
      menu.addEventListener('toggle', () => { if (!menu.open && NT.deferred) setTimeout(render); });
    }
    return el('li', { class: 'nt-rule' + (r.enabled ? '' : ' is-off') },
      el('label', { class: 'switch nt-rule__switch' }, sw),
      el('div', { class: 'nt-rule__text' },
        el('div', { class: 'nt-rule__name' }, r.name, r.enabled ? null : el('span', { class: 'badge badge--outline' }, 'Off')),
        el('p', { class: 'nt-rule__sum' }, r.summary)),
      menu);
  }

  // ---------- deliveries ----------
  function deliveriesCard() {
    const list = NT.deliveries || [];
    const head = el('div', { class: 'card__head' }, el('div', {},
      el('h3', { class: 'card__title', id: 'nt-del-title' }, 'Recent deliveries'),
      el('p', { class: 'card__sub' }, 'The latest messages and tests, kept for 30 days')),
      el('div', { class: 'card__actions' }, el('button', { class: 'btn btn--ghost btn--sm btn--icon', type: 'button', title: 'Refresh', 'aria-label': 'Refresh deliveries', 'data-key': 'del:refresh', onclick: () => load(true) }, icon('refresh-cw'))));
    let bodyEl;
    if (NT.delivErr) {
      bodyEl = dxEmpty({ compact: true, tone: 'danger', icon: 'circle-alert', title: 'Couldn’t load deliveries', text: NT.delivErr, action: dxRetry(() => load(true)) });
    } else if (!list.length) {
      bodyEl = el('div', { class: 'empty empty--compact' },
        el('div', { class: 'empty__title' }, 'Nothing sent yet'),
        el('p', { class: 'empty__text' }, 'Messages show up here as findings match your rules. Send a test to see one now.'));
    } else {
      const rows = list.map((x) => {
        const ch = channelByID(x.channel);
        const t = typeOf(x.channel_type);
        const title = x.kind === 'test' ? 'Test message' : x.title || x.finding_id;
        const sub = [];
        if (x.summary > 1) sub.push(`in a summary of ${x.summary}`);
        if (x.rule_name) sub.push(`rule ${x.rule_name}`);
        if (x.playbook) sub.push(`playbook ${x.playbook}`);
        return el('tr', {},
          el('td', { class: 'nt-c-finding' },
            el('div', { class: 'nt-del__title' }, x.kind === 'test' ? el('span', { class: 'badge badge--outline' }, 'Test') : x.urgency ? sevBadge(x.urgency) : null,
              el('span', { class: 'cell-title', title }, title)),
            el('div', { class: 'nt-del__sub' }, el('span', { class: 'show-sm nt-inline' }, `${ch ? ch.name : x.channel_name} · ${ago(x.updated)}`), sub.length ? el('span', {}, sub.join(' · ')) : null)),
          el('td', { class: 'nt-c-channel hide-sm' }, el('span', { class: 'nt-del__ch' }, el('span', { class: 'nt-type nt-type--sm', 'data-type': x.channel_type }, icon(t.icon)), el('span', {}, ch ? ch.name : x.channel_name))),
          el('td', { class: 'nt-c-status' }, deliveryStatus(x)),
          el('td', { class: 'nt-c-when hide-sm' }, el('span', { class: 'age', title: fmtTime(x.updated) }, ago(x.updated))));
      });
      bodyEl = el('div', { class: 'table-wrap' }, el('table', { class: 'table nt-del-table' },
        el('thead', {}, el('tr', {}, el('th', { scope: 'col' }, 'Finding'), el('th', { scope: 'col', class: 'hide-sm' }, 'Channel'), el('th', { scope: 'col' }, 'Status'), el('th', { scope: 'col', class: 'hide-sm' }, 'When'))),
        el('tbody', {}, ...rows)));
    }
    return el('section', { class: 'card nt-card', 'aria-labelledby': 'nt-del-title' }, head, bodyEl);
  }

  function deliveryStatus(x) {
    let badge;
    let note = '';
    if (x.status === 'sent') {
      badge = el('span', { class: 'badge badge--success' }, 'Sent');
      if (x.attempts > 1) note = `on try ${x.attempts}`;
    } else if (x.status === 'sending') {
      badge = el('span', { class: 'badge' }, 'Sending');
    } else if (!x.final && x.next_try) {
      badge = el('span', { class: 'badge badge--warning', title: 'Next try ' + fmtTime(x.next_try) }, 'Retrying');
      note = `try ${x.attempts + 1} ${until(x.next_try)}`;
    } else {
      badge = el('span', { class: 'badge badge--danger' }, 'Failed');
    }
    return el('div', { class: 'nt-status' }, el('div', { class: 'nt-status__line' }, badge, note ? el('span', { class: 'nt-status__note' }, note) : null),
      x.error && x.status !== 'sent' ? el('p', { class: 'nt-status__err', title: x.error }, x.error) : null);
  }

  // until says when a time comes: "in 4m", or "soon" once it has passed.
  function until(t) {
    const s = (new Date(t).getTime() - Date.now()) / 1000;
    if (!isFinite(s) || s <= 30) return 'soon';
    if (s < 3600) return `in ${Math.ceil(s / 60)}m`;
    return `in ${Math.round(s / 3600)}h`;
  }

  // ---------- saving ----------
  // asInput is a saved channel as the server takes it back: the secrets
  // left empty keep their saved values, and listed headers keep theirs.
  function asInput(c) {
    return {
      id: c.id, name: c.name, type: c.type, host: c.host || '', port: c.port || 0, security: c.security || '', username: c.username || '',
      from: c.from || '', to: c.to || [], allow_loopback: !!c.allow_loopback, ca_pem: c.ca_pem || '',
      headers: (c.headers || []).map((h) => ({ name: h.name })),
    };
  }
  const ruleInput = (r) => ({
    id: r.id, name: r.name, enabled: r.enabled, channels: [...r.channels], min_urgency: r.min_urgency,
    detections: [...(r.detections || [])], min_risk_score: r.min_risk_score || 0, include_sample: !!r.include_sample,
  });

  // save changes the settings with change(input) and sends them; it
  // returns the problems on a refusal so a dialog can mark its fields, and
  // true on success.
  async function save(change, done, opts = {}) {
    const d = NT.data;
    const input = { revision: d.revision, channels: d.channels.map(asInput), rules: d.rules.map(ruleInput) };
    change(input);
    try {
      NT.data = await api('api/notify', input, 'PUT');
    } catch (e) {
      if (opts.quiet) return e;
      toastError(e.status === 409 ? 'The settings changed elsewhere' : 'Couldn’t save', e);
      if (e.status === 409) load(true);
      return false;
    }
    render();
    if (done) toast(done, opts.action || null);
    load(true);
    return true;
  }

  // ---------- confirm ----------
  function confirmBox(o) {
    const dlg = $('nt-confirm');
    return new Promise((resolve) => {
      let result = false;
      const cancel = el('button', { class: 'btn btn--ghost', type: 'button', onclick: () => dlg.close() }, 'Cancel');
      const ok = el('button', { class: 'btn btn--danger', type: 'button' }, o.confirm);
      ok.addEventListener('click', () => { result = true; dlg.close(); });
      dlg.onclose = () => resolve(result);
      fill(dlg,
        el('div', { class: 'modal__head' }, el('div', {}, el('h2', { class: 'modal__title', id: 'nt-confirm-title' }, o.title), el('p', { class: 'modal__desc', id: 'nt-confirm-desc' }, o.text))),
        el('div', { class: 'modal__foot' }, cancel, ok));
      dlg.showModal();
      cancel.focus();
    });
  }

  async function deleteChannel(c) {
    const off = NT.data.rules.filter((r) => r.channels.includes(c.id) && r.channels.length === 1).map((r) => r.name);
    let text = 'Messages stop going there at once. Its saved address and secrets are deleted.';
    if (c.rules.length) text += ` It’s taken out of ${c.rules.length === 1 ? 'the rule ' + c.rules[0] : plural(c.rules.length, 'rule')}`;
    if (off.length) text += `, and ${off.length === 1 ? off[0] + ', which sends nowhere else, is turned off' : off.length + ' rules that send nowhere else are turned off'}`;
    if (c.rules.length) text += '.';
    if (!await confirmBox({ title: `Delete ${c.name}?`, text, confirm: 'Delete channel' })) return;
    NT.tests.delete(c.id);
    await save((inp) => { inp.channels = inp.channels.filter((x) => x.id !== c.id); }, `Deleted ${c.name}.`);
  }

  async function deleteRule(r) {
    if (!await confirmBox({ title: `Delete the rule ${r.name}?`, text: r.summary.replace(/\.$/, '') + ' — this stops.', confirm: 'Delete rule' })) return;
    await save((inp) => { inp.rules = inp.rules.filter((x) => x.id !== r.id); }, `Deleted ${r.name}.`);
  }

  // ---------- form helpers ----------
  let fieldSeq = 0;
  const fid = (p) => `nt-f${++fieldSeq}-${p}`;
  function input(p, attrs = {}) {
    return el('input', { class: 'input', id: fid(p), type: 'text', autocomplete: 'off', spellcheck: 'false', ...attrs });
  }
  function field(labelText, control, hint, extra) {
    const hid = hint ? control.id + '-hint' : null;
    if (hid) control.setAttribute('aria-describedby', hid);
    return el('div', { class: 'field', 'data-field': control.dataset.field || '' }, el('label', { class: 'label', for: control.id }, labelText),
      extra || control, hint ? el('p', { class: 'hint', id: hid }, hint) : null);
  }
  function markError(form, name, msg) {
    const f = form.querySelector(`[data-field="${CSS.escape(name)}"]`);
    if (!f) return false;
    const ctl = f.querySelector('input, select, textarea');
    if (ctl) ctl.setAttribute('aria-invalid', 'true');
    f.append(el('p', { class: 'field-error', 'data-error': '' }, icon('circle-alert'), msg));
    return true;
  }
  function clearErrors(form) {
    form.querySelectorAll('[data-error]').forEach((n) => n.remove());
    form.querySelectorAll('[aria-invalid]').forEach((n) => n.removeAttribute('aria-invalid'));
  }
  // showProblems marks each problem of where on its field, and puts the
  // rest in the form's message box.
  function showProblems(form, msgBox, e, where, fallback) {
    const others = [];
    let first = null;
    for (const p of e.problems || []) {
      const msg = p.message.replace(/^[^:]*: /, '');
      if (p.where === where && markError(form, p.field, sentence(msg))) {
        first = first || form.querySelector(`[data-field="${CSS.escape(p.field)}"] input, [data-field="${CSS.escape(p.field)}"] select, [data-field="${CSS.escape(p.field)}"] textarea`);
      } else {
        others.push(sentence(p.message));
      }
    }
    if (!(e.problems || []).length) others.push(e.message);
    fill(msgBox, others.length ? dxAlert('danger', fallback, others.join(' ')) : null);
    if (first) first.focus();
    else msgBox.scrollIntoView({ block: 'nearest' });
  }

  // secretInput is a write-only setting: empty keeps the saved value.
  function secretInput(p, saved, placeholder, attrs = {}) {
    return input(p, { type: 'password', placeholder: saved ? 'Saved · type to replace' : placeholder, autocomplete: 'new-password', ...attrs });
  }

  // ---------- channel dialog ----------
  function openChannel(c, type) {
    const dlg = $('nt-channel-dialog');
    const edit = !!c;
    let kind = edit ? c.type : type || 'slack';
    const id = edit ? c.id : newID();
    const msg = el('div', { class: 'nt-msg', 'aria-live': 'polite' });
    const form = el('form', { class: 'nt-form', novalidate: '', autocomplete: 'off' });
    const name = input('name', { maxlength: '80', 'data-field': 'name' });
    name.value = edit ? c.name : '';
    let typed = edit; // the name was typed, not suggested
    name.addEventListener('input', () => { typed = true; });

    // URL channels
    const url = input('url', { class: 'input mono', 'data-field': 'url', inputmode: 'url' });
    // email
    const host = input('host', { class: 'input mono', placeholder: 'smtp.example.com', 'data-field': 'host' });
    const port = input('port', { type: 'number', min: '1', max: '65535', inputmode: 'numeric', 'data-field': 'port' });
    const security = el('select', { id: fid('security'), class: 'select select--block', 'data-field': 'security' },
      el('option', { value: 'starttls' }, 'STARTTLS (port 587)'), el('option', { value: 'tls' }, 'TLS (port 465)'), el('option', { value: 'none' }, 'None: a relay on this server'));
    const user = input('username', { 'data-field': 'username' });
    let clearPW = false;
    const pw = secretInput('password', edit && c.password_set, 'Only sent over TLS', { 'data-field': 'password' });
    const from = input('from', { type: 'email', placeholder: 'signalith@example.com', 'data-field': 'from' });
    const to = el('textarea', { class: 'textarea', id: fid('to'), rows: '2', placeholder: 'soc@example.com, oncall@example.com', 'data-field': 'to', spellcheck: 'false' });
    // webhook
    let clearSig = false;
    const sig = secretInput('signing_secret', edit && c.signing_secret_set, 'Optional', { 'data-field': 'signing_secret' });
    const headerRows = el('div', { class: 'nt-headers' });
    const headers = []; // { name, value, saved }
    // advanced
    const loop = el('input', { type: 'checkbox', id: fid('loop') });
    const ca = el('textarea', { class: 'textarea mono', id: fid('ca'), rows: '3', placeholder: '-----BEGIN CERTIFICATE-----', 'data-field': 'ca_pem', spellcheck: 'false' });
    if (edit) {
      host.value = c.host || '';
      port.value = c.port ? String(c.port) : '';
      security.value = c.security || 'starttls';
      user.value = c.username || '';
      from.value = c.from || '';
      to.value = (c.to || []).join(', ');
      loop.checked = !!c.allow_loopback;
      ca.value = c.ca_pem || '';
      for (const h of c.headers || []) headers.push({ name: h.name, value: '', saved: true });
    }
    security.addEventListener('change', () => {
      const ports = { starttls: '587', tls: '465', none: '25' };
      if (!port.value || Object.values(ports).includes(port.value)) port.value = ports[security.value];
    });
    if (!port.value) port.value = '587';

    const drawHeaders = () => {
      fill(headerRows, ...headers.map((h, i) => {
        const n = el('input', { class: 'input mono', type: 'text', 'aria-label': 'Header name', placeholder: 'Authorization', autocomplete: 'off', spellcheck: 'false' });
        n.value = h.name;
        n.readOnly = h.saved;
        n.addEventListener('input', () => { h.name = n.value; });
        const v = el('input', { class: 'input mono', type: 'password', 'aria-label': `Value of ${h.name || 'the header'}`, placeholder: h.saved ? 'Saved · type to replace' : 'Bearer …', autocomplete: 'new-password' });
        v.value = h.value;
        v.addEventListener('input', () => { h.value = v.value; });
        const rm = el('button', { class: 'btn btn--ghost btn--icon btn--sm', type: 'button', title: 'Remove header', 'aria-label': `Remove header ${h.name}` }, icon('x'));
        rm.addEventListener('click', () => { headers.splice(i, 1); drawHeaders(); });
        return el('div', { class: 'nt-header' }, n, v, rm);
      }), el('button', {
        class: 'link-btn nt-add-header', type: 'button',
        onclick: () => { headers.push({ name: '', value: '', saved: false }); drawHeaders(); headerRows.querySelector('.nt-header:last-of-type input').focus(); },
      }, icon('plus', 'icon--sm'), 'Add header'));
    };

    const clearable = (control, saved, onClear, what) => {
      if (!saved) return control;
      const btn = el('button', { class: 'link-btn', type: 'button' }, 'Remove');
      const wrap = el('div', { class: 'nt-secret' }, control, btn);
      btn.addEventListener('click', () => {
        onClear();
        control.value = '';
        control.placeholder = `Removed when you save · type a new ${what}`;
        btn.remove();
        control.focus();
      });
      return wrap;
    };

    const typeSeg = el('div', { class: 'seg nt-type-seg', role: 'group', 'aria-label': 'Kind of channel' });
    const panel = el('div', { class: 'nt-form__panel' });
    const draw = () => {
      const t = TYPES[kind];
      fill(typeSeg, ...TYPE_ORDER.map((k) => {
        const b = el('button', { type: 'button', 'aria-pressed': String(k === kind) }, icon(TYPES[k].icon), TYPES[k].label);
        b.addEventListener('click', () => { if (kind !== k) { kind = k; if (!typed) name.value = ''; draw(); } });
        return b;
      }));
      name.placeholder = t.name;
      clearErrors(form);
      fill(msg);
      const parts = [field('Name', name, kind === 'slack' ? 'Shown in messages and on this page, such as the Slack channel it posts to.' : null)];
      if (kind === 'email') {
        parts.push(el('div', { class: 'nt-row nt-row--host' }, field('Mail server', host), field('Port', port)));
        parts.push(field('Connection', security, 'STARTTLS and TLS protect the connection and the password. None is only for a mail relay on this server.'));
        parts.push(el('div', { class: 'nt-row' }, field('User name', user, null), field('Password', pw, null, clearable(pw, edit && c.password_set && c.type === 'email', () => { clearPW = true; }, 'password'))));
        parts.push(field('From', from, 'The address messages come from; your mail server must allow it.'));
        parts.push(field('To', to, 'One or more addresses, separated by commas.'));
      } else {
        const savedURL = edit && c.type === kind && c.url_set;
        url.placeholder = savedURL ? `Saved (${(c.url_server || '').replace(/^https?:\/\//, '')}) · paste a new URL to replace it`
          : { slack: 'https://hooks.slack.com/services/…', teams: 'https://…logic.azure.com/workflows/…', webhook: 'https://soar.example.com/hooks/signalith' }[kind];
        const how = {
          slack: 'In Slack, add the Incoming Webhooks app, pick the channel, and copy its Webhook URL.',
          teams: 'In Teams, open the channel’s ⋯ menu › Workflows › “Post to a channel when a webhook request is received”, then copy the URL it gives.',
          webhook: 'Signalith POSTs a JSON body to it. docs/notifications.md describes the body and how to check its signature.',
        }[kind];
        parts.push(field(kind === 'webhook' ? 'URL' : 'Webhook URL', url, how));
        if (kind === 'webhook') {
          parts.push(field('Signing secret', sig, 'Signs each body: the X-Signalith-Signature header is sha256= and its HMAC. Optional.',
            clearable(sig, edit && c.signing_secret_set, () => { clearSig = true; }, 'secret')));
          const hl = el('div', { class: 'field', 'data-field': 'headers' }, el('span', { class: 'label' }, 'Headers'), headerRows,
            el('p', { class: 'hint' }, 'Such as an API key the receiver asks for. Values are kept encrypted.'));
          parts.push(hl);
          drawHeaders();
        }
      }
      const more = el('details', { class: 'nt-more' }, el('summary', {}, icon('chevron-right', 'nt-chev'), 'Advanced'),
        el('div', { class: 'nt-more__body' },
          el('div', { class: 'field' }, el('label', { class: 'check' }, loop, el('span', {}, 'Allow this server’s own addresses')),
            el('p', { class: 'hint' }, 'For a receiver on this machine (localhost). Off, Signalith never sends to its own or cloud metadata addresses.')),
          field('Certificate authority', ca, 'PEM certificates of a private certificate authority the receiver’s certificate comes from. The system’s trusted ones always count.')));
      if (loop.checked || ca.value) more.open = true;
      fill(panel, ...parts, more);
    };

    const testOut = el('span', { class: 'nt-test-out', 'aria-live': 'polite' });
    const testBtn = el('button', { class: 'btn btn--ghost', type: 'button' }, icon('send'), 'Send test');
    const saveBtn = el('button', { class: 'btn btn--primary', type: 'submit' }, edit ? 'Save changes' : 'Add channel');
    const read = () => {
      const out = { id, name: name.value.trim(), type: kind, allow_loopback: loop.checked, ca_pem: ca.value.trim() };
      if (kind === 'email') {
        Object.assign(out, {
          host: host.value.trim(), port: parseInt(port.value, 10) || 0, security: security.value, username: user.value.trim(),
          password: pw.value, clear_password: clearPW || (!user.value.trim()), from: from.value.trim(), to: to.value.split(/[,;\n]/).map((s) => s.trim()).filter(Boolean),
        });
      } else {
        out.url = url.value.trim();
        if (kind === 'webhook') {
          out.signing_secret = sig.value;
          out.clear_signing_secret = clearSig;
          out.headers = headers.filter((h) => h.name.trim() || h.value).map((h) => ({ name: h.name.trim(), value: h.value }));
        }
      }
      if (!out.name) out.name = (TYPES[kind] || {}).name || kind;
      return out;
    };
    testBtn.addEventListener('click', async () => {
      clearErrors(form);
      fill(msg);
      testBtn.disabled = true;
      fill(testOut, el('span', { class: 'nt-test-out__busy' }, 'Sending…'));
      let r;
      try {
        r = await api('api/notify/test', { channel: read() });
      } catch (e) {
        testBtn.disabled = false;
        if (e.problems) { fill(testOut); showProblems(form, msg, e, 'channel:' + id, 'Fix these settings first.'); return; }
        r = { ok: false, error: e.message };
      }
      testBtn.disabled = false;
      fill(testOut, el('span', { 'data-tone': r.ok ? 'success' : 'danger', title: r.error || '' }, icon(r.ok ? 'circle-check' : 'circle-alert'), r.ok ? `Sent in ${fmtMS(r.duration_ms)}` : 'Failed'));
      if (!r.ok) fill(msg, dxAlert('danger', 'The test message wasn’t sent.', r.error));
    });
    form.addEventListener('submit', async (ev) => {
      ev.preventDefault();
      clearErrors(form);
      fill(msg);
      saveBtn.disabled = true;
      const ch = read();
      const first = !NT.data.rules.length && !edit;
      const r = await save((inp) => {
        const i = inp.channels.findIndex((x) => x.id === id);
        if (i >= 0) inp.channels[i] = ch; else inp.channels.push(ch);
      }, null, { quiet: true });
      saveBtn.disabled = false;
      if (r !== true) {
        showProblems(form, msg, r, 'channel:' + id, edit ? 'Couldn’t save the channel.' : 'Couldn’t add the channel.');
        return;
      }
      dlg.close();
      if (first) toast(`Added ${ch.name}. Now add a rule that sends findings to it.`, { label: 'Add rule', run: () => openRule(null, id) });
      else toast(edit ? `Saved ${ch.name}.` : `Added ${ch.name}.`);
    });
    fill(form,
      el('div', { class: 'modal__body' }, edit ? null : typeSeg, msg, panel),
      el('div', { class: 'modal__foot nt-foot' }, el('div', { class: 'nt-foot__test' }, testBtn, testOut), el('span', { class: 'spacer' }),
        el('button', { class: 'btn btn--ghost', type: 'button', onclick: () => dlg.close() }, 'Cancel'), saveBtn));
    fill(dlg,
      el('div', { class: 'modal__head' }, el('div', {},
        el('h2', { class: 'modal__title', id: 'nt-channel-title' }, edit ? `Edit ${c.name}` : 'Add a channel'),
        el('p', { class: 'modal__desc' }, edit ? `${TYPES[kind].label} · secrets you leave empty stay as they are.` : 'Where Signalith sends messages about findings.')),
      el('button', { class: 'btn btn--ghost btn--icon btn--sm', type: 'button', 'aria-label': 'Close', onclick: () => dlg.close() }, icon('x'))),
      form);
    draw();
    dlg.showModal();
    (edit ? name : (kind === 'email' ? host : url)).focus();
  }

  // ---------- rule dialog ----------
  async function loadDetections() {
    if (NT.detections) return NT.detections;
    try {
      const r = await api('api/detections');
      NT.detections = (r.detections || []).map((d) => ({ id: d.id, title: (d.title || d.id).replace(/\$[a-z0-9_.]+\$/gi, '…'), enabled: d.enabled }));
    } catch (_) {
      NT.detections = [];
    }
    return NT.detections;
  }

  // summary says what a rule does, as the server does once it is saved.
  function summary(r) {
    const what = { critical: 'Critical findings', high: 'High and critical findings', medium: 'Medium, high and critical findings', low: 'Findings of low urgency and above', informational: 'All findings' }[r.min_urgency] || 'Findings';
    const n = r.detections.length;
    const from = n === 0 ? 'from any detection' : n === 1 ? 'from ' + r.detections[0] : n <= 3 ? 'from ' + r.detections.slice(0, -1).join(', ') + ' and ' + r.detections[n - 1] : `from ${n} detections`;
    const parts = [what, from];
    if (r.min_risk_score > 0) parts.push(`with a risk score of ${r.min_risk_score} or more (when they have one)`);
    if (r.include_sample) parts.push('including sample data');
    const to = r.channels.map(channelByID).filter(Boolean).map(label);
    const list = to.length <= 1 ? to.join('') : to.slice(0, -1).join(', ') + ' and ' + to[to.length - 1];
    return parts.join(' ') + (to.length ? ' go to ' + list + '.' : ' go nowhere yet: pick a channel.');
  }

  async function openRule(r, channelID) {
    const dlg = $('nt-rule-dialog');
    const edit = !!r;
    const id = edit ? r.id : newID();
    const st = edit ? ruleInput(r) : { id, name: '', enabled: true, channels: channelID ? [channelID] : NT.data.channels.length === 1 ? [NT.data.channels[0].id] : [], min_urgency: 'high', detections: [], min_risk_score: 0, include_sample: false };
    const msg = el('div', { class: 'nt-msg', 'aria-live': 'polite' });
    const form = el('form', { class: 'nt-form', novalidate: '', autocomplete: 'off' });
    const preview = el('p', { class: 'nt-preview__text' });
    const sync = () => { preview.textContent = summary(st); };

    const name = input('rname', { maxlength: '80', placeholder: 'Urgent findings', 'data-field': 'name' });
    name.value = st.name;
    name.addEventListener('input', () => { st.name = name.value; });

    const chans = el('div', { class: 'nt-picks', role: 'group', 'aria-label': 'Channels' }, ...NT.data.channels.map((c) => {
      const cb = el('input', { type: 'checkbox' });
      cb.checked = st.channels.includes(c.id);
      cb.addEventListener('change', () => {
        st.channels = cb.checked ? [...st.channels, c.id] : st.channels.filter((x) => x !== c.id);
        sync();
      });
      return el('label', { class: 'check nt-pick' }, cb, el('span', { class: 'nt-type nt-type--sm', 'data-type': c.type }, icon(typeOf(c.type).icon)), el('span', {}, c.name));
    }));

    const urgHint = el('p', { class: 'hint', id: fid('urg-hint') });
    const urg = el('div', { class: 'seg nt-urg', role: 'group', 'aria-label': 'Least urgency', 'aria-describedby': urgHint.id });
    const drawUrg = () => {
      fill(urg, ...LEAST.map(([v, l]) => {
        const b = el('button', { type: 'button', 'aria-pressed': String(st.min_urgency === v) }, v === 'informational' ? null : el('span', { class: 'nt-sevdot', 'data-sev': v }), l);
        b.addEventListener('click', () => { st.min_urgency = v; drawUrg(); sync(); });
        return b;
      }));
      urgHint.textContent = LEAST_HINT[st.min_urgency];
    };
    drawUrg();

    const dets = await loadDetections();
    let some = st.detections.length > 0;
    const detSeg = el('div', { class: 'seg', role: 'group', 'aria-label': 'Detections' });
    const detFind = el('input', { class: 'input input--sm', type: 'search', placeholder: 'Find a detection', 'aria-label': 'Find a detection', autocomplete: 'off', spellcheck: 'false' });
    const detList = el('div', { class: 'nt-detlist' });
    const detBox = el('div', { class: 'nt-dets' }, detFind, detList);
    const drawDetList = () => {
      const q = detFind.value.trim().toLowerCase();
      const known = new Set(dets.map((d) => d.id));
      const all = [...dets, ...st.detections.filter((x) => !known.has(x)).map((x) => ({ id: x, title: x }))];
      const shown = all.filter((d) => !q || d.id.toLowerCase().includes(q) || d.title.toLowerCase().includes(q));
      fill(detList, ...shown.slice(0, 200).map((d) => {
        const cb = el('input', { type: 'checkbox' });
        cb.checked = st.detections.includes(d.id);
        cb.addEventListener('change', () => {
          st.detections = cb.checked ? [...st.detections, d.id] : st.detections.filter((x) => x !== d.id);
          sync();
        });
        return el('label', { class: 'check nt-det' }, cb, el('span', { class: 'nt-det__text' }, el('span', { class: 'nt-det__title' }, d.title), el('span', { class: 'nt-det__id mono' }, d.id)));
      }), shown.length ? null : el('p', { class: 'hint nt-det__none' }, q ? 'No detection matches.' : 'No detections yet.'));
    };
    detFind.addEventListener('input', drawDetList);
    const drawDetSeg = () => {
      fill(detSeg, ...[[false, 'Any detection'], [true, 'Only some']].map(([v, l]) => {
        const b = el('button', { type: 'button', 'aria-pressed': String(some === v) }, l);
        b.addEventListener('click', () => {
          some = v;
          if (!v) st.detections = [];
          drawDetSeg();
          drawDetList();
          sync();
          if (v) detFind.focus();
        });
        return b;
      }));
      detBox.hidden = !some;
    };
    drawDetSeg();
    drawDetList();

    const risk = input('risk', { type: 'number', min: '0', max: '100000', step: 'any', inputmode: 'decimal', placeholder: 'Any', 'data-field': 'min_risk_score' });
    risk.value = st.min_risk_score ? String(st.min_risk_score) : '';
    risk.addEventListener('input', () => { st.min_risk_score = parseFloat(risk.value) || 0; sync(); });
    const sample = el('input', { type: 'checkbox' });
    sample.checked = st.include_sample;
    sample.addEventListener('change', () => { st.include_sample = sample.checked; sync(); });
    const on = el('input', { type: 'checkbox', role: 'switch' });
    on.checked = st.enabled;
    on.addEventListener('change', () => { st.enabled = on.checked; });

    const saveBtn = el('button', { class: 'btn btn--primary', type: 'submit' }, edit ? 'Save changes' : 'Add rule');
    form.addEventListener('submit', async (ev) => {
      ev.preventDefault();
      clearErrors(form);
      fill(msg);
      if (!st.name.trim()) st.name = name.value.trim() || defaultName(st);
      saveBtn.disabled = true;
      const res = await save((inp) => {
        const i = inp.rules.findIndex((x) => x.id === id);
        const v = { ...st, name: st.name.trim() };
        if (i >= 0) inp.rules[i] = v; else inp.rules.push(v);
      }, null, { quiet: true });
      saveBtn.disabled = false;
      if (res !== true) {
        if (!edit && !name.value.trim()) st.name = '';
        showProblems(form, msg, res, 'rule:' + id, edit ? 'Couldn’t save the rule.' : 'Couldn’t add the rule.');
        return;
      }
      dlg.close();
      toast(edit ? `Saved ${st.name}.` : st.enabled ? `Added ${st.name}. Findings raised from now on are sent.` : `Added ${st.name}. It’s off for now.`);
    });

    const chanField = el('div', { class: 'field', 'data-field': 'channels' }, el('span', { class: 'label' }, 'Send to'), chans);
    const urgField = el('div', { class: 'field', 'data-field': 'min_urgency' }, el('span', { class: 'label' }, 'How urgent'), urg, urgHint);
    const detField = el('div', { class: 'field', 'data-field': 'detections' }, el('span', { class: 'label' }, 'From'), detSeg, detBox);
    const more = el('details', { class: 'nt-more' }, el('summary', {}, icon('chevron-right', 'nt-chev'), 'More options'),
      el('div', { class: 'nt-more__body' },
        field('Least risk score', risk, 'Only for findings of risk detections, which carry a risk score. Others are sent whatever this says.'),
        el('div', { class: 'field' }, el('label', { class: 'check' }, sample, el('span', {}, 'Include sample data')),
          el('p', { class: 'hint' }, 'Findings from the one-click sample data are skipped unless this is on. Turn it on to try a channel out.'))));
    if (st.min_risk_score || st.include_sample) more.open = true;
    fill(form,
      el('div', { class: 'modal__body' }, msg, field('Name', name), chanField, urgField, detField, more,
        el('div', { class: 'nt-preview' }, icon('bell'), el('div', {}, el('b', {}, 'This rule'), preview))),
      el('div', { class: 'modal__foot nt-foot' }, el('label', { class: 'switch' }, on, el('span', {}, 'On')), el('span', { class: 'spacer' }),
        el('button', { class: 'btn btn--ghost', type: 'button', onclick: () => dlg.close() }, 'Cancel'), saveBtn));
    fill(dlg,
      el('div', { class: 'modal__head' }, el('div', {},
        el('h2', { class: 'modal__title', id: 'nt-rule-title' }, edit ? `Edit ${r.name}` : 'Add a rule'),
        el('p', { class: 'modal__desc' }, 'Which new findings go to which channels. Each finding goes to a channel once, even when several rules match.')),
      el('button', { class: 'btn btn--ghost btn--icon btn--sm', type: 'button', 'aria-label': 'Close', onclick: () => dlg.close() }, icon('x'))),
      form);
    sync();
    dlg.showModal();
    name.focus();
  }

  // defaultName names a rule left unnamed after what it sends.
  function defaultName(st) {
    const base = { critical: 'Critical findings', high: 'Urgent findings', medium: 'Medium and above', low: 'Low and above', informational: 'All findings' }[st.min_urgency] || 'Findings';
    const taken = new Set(NT.data.rules.map((r) => r.name.toLowerCase()));
    if (!taken.has(base.toLowerCase())) return base;
    for (let i = 2; ; i++) if (!taken.has(`${base} ${i}`.toLowerCase())) return `${base} ${i}`;
  }
})();
