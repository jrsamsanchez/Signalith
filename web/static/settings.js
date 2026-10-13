// Settings page (admins): how the server runs. The sections, the settings
// in them and what each one does come from api/settings (the registry in
// internal/config/settings.go); this page only draws them. Changes wait in
// drafts until Save sends them together. Settings that apply at once do so
// when saved; the others wait for "Restart now", which restarts Signalith
// inside the same process and reloads the page when it is back.
'use strict';

(function () {
  // S.view is the last api/settings reply. S.drafts holds the unsaved
  // changes by setting: { kind: 'value', value, raw } for a new value,
  // 'clear' to remove a saved password or key, 'reset' to take a setting
  // off the page, 'retry' to use a change a restart set aside again.
  // S.replacing marks secrets whose Replace box is open. S.localOK is the
  // admin's yes, when saving, to a web address only the server reaches.
  const S = {
    view: null, seq: 0, drafts: {}, replacing: {}, fields: {}, sections: {}, controls: {},
    saveErr: null, tests: {}, restart: null, restartErr: '', pinned: '', pinnedY: 0, focusKey: '', localOK: false,
  };
  const DEFAULT_AI_URL = { anthropic: 'https://api.anthropic.com', openai: 'https://api.openai.com/v1' };
  const RESTART_NOTE = 'signalith.settingsRestarted';
  // Settings shown in a monospaced font: addresses, paths and names.
  const MONO = new Set(['url', 'address', 'list']);
  const MONO_KEYS = new Set(['server.tls_cert', 'server.tls_key', 'opensearch.index_prefix', 'assistant.model']);
  const SOURCE_FILE = 'signalith.yaml';

  // The connection tests: the settings each one reads, so only they make
  // its result out of date.
  const TESTS = {
    opensearch: {
      keys: ['opensearch.url', 'opensearch.username', 'opensearch.password', 'opensearch.ca_file', 'opensearch.cert_file',
        'opensearch.key_file', 'opensearch.proxy', 'opensearch.allow_insecure_http', 'opensearch.tls_skip_verify'],
      path: 'api/settings/test/opensearch', button: 'Test connection', icon: 'network', busy: 'Connecting…',
      lead: 'Connects with the settings above, saved or not.',
    },
    assistant: {
      keys: ['assistant.provider', 'assistant.url', 'assistant.model', 'assistant.api_key'],
      path: 'api/settings/test/assistant', button: 'Test', icon: 'sparkles', busy: 'Asking the model…',
      lead: 'Asks the model one sample question with the settings above, saved or not.',
    },
  };

  // ---------- small helpers ----------
  // How far Signalith's own certificate authority reaches (CAInfo.Scope).
  const CA_SCOPE = { standard: 'standard', strict: 'strict', unconstrained: 'older, unlimited' };
  const cap = (t) => t.charAt(0).toUpperCase() + t.slice(1);
  const securityLink = (text) => el('a', { href: '#security', 'data-page': 'security' }, text);
  const idOf = (key) => 'st-' + key.replace(/[^a-z0-9]+/gi, '-');
  const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);
  const dirtyKeys = () => Object.keys(S.drafts);
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  const sectionOf = (key) => S.sections[key];
  const isShown = () => $('page-settings').classList.contains('active');
  const editable = () => !!(S.view && S.view.editable);
  // While the settings file can't be read, nothing can be saved into it.
  const fileBroken = () => !!(S.view && (S.view.settings_file || {}).error);
  const readOnly = (f) => f.locked || !editable() || fileBroken();
  const narrow = () => window.matchMedia('(max-width: 720px)').matches;
  // Addresses that Docker publishes: a new port needs docker-compose.yml too.
  const PORTS = new Set(['server.listen', 'syslog.udp', 'syslog.tcp', 'syslog.tls']);

  // origin is scheme://host:port of an address, with the default port
  // filled in, as the server compares them; '' for anything else.
  function origin(raw) {
    try {
      const u = new URL(String(raw || '').trim());
      if (u.protocol !== 'http:' && u.protocol !== 'https:') return '';
      return u.protocol.slice(0, -1) + '://' + u.hostname.toLowerCase() + ':' + (u.port || (u.protocol === 'https:' ? '443' : '80'));
    } catch (_) {
      return '';
    }
  }

  // current is a setting's value as the form has it now.
  function current(key) {
    const f = S.fields[key];
    const d = S.drafts[key];
    if (!f) return undefined;
    if (d && d.kind === 'value') return d.value;
    if (d && d.kind === 'reset') return f.reset_to ? f.reset_to.value : f.value;
    if (d && d.kind === 'retry' && f.refused && f.type !== 'secret') return f.refused.value;
    return f.value;
  }

  // sentToNow is where a saved secret would be sent with the form as it
  // is: the only place the server lets it go is f.sent_to.
  function sentToNow(key) {
    if (key === 'opensearch.password') return origin(current('opensearch.url'));
    if (key === 'assistant.api_key') {
      const p = current('assistant.provider');
      return p ? origin(current('assistant.url') || DEFAULT_AI_URL[p]) : '';
    }
    return '';
  }

  // parse reads a control's raw value as the setting's type.
  function parse(f, raw) {
    switch (f.type) {
      case 'number': {
        const t = String(raw).trim();
        if (t === '') return f.empty_means ? 0 : '';
        const n = Number(t);
        return Number.isFinite(n) ? n : t;
      }
      case 'bool': return !!raw;
      case 'list': return String(raw).split(/[\n,]/).map((x) => x.trim()).filter(Boolean);
      case 'secret': return String(raw);
      default: return String(raw).trim();
    }
  }

  // show writes a value for people: On and Off, choice labels, and what
  // an empty value means.
  function show(f, v) {
    if (f.type === 'bool') return v ? 'On' : 'Off';
    if (f.type === 'list') return v && v.length ? v.join(', ') : (f.empty_means || 'none');
    if (f.type === 'choice') {
      const c = (f.choices || []).find((x) => x.value === v);
      if (c) return c.label;
    }
    if (v === '' || v == null || (f.type === 'number' && v === 0 && f.empty_means)) return f.empty_means || 'empty';
    return String(v);
  }

  // shortName names a setting outside its section, as in the restart
  // banner: "Listen address", "Syslog UDP address", "OpenSearch password".
  function shortName(key) {
    const f = S.fields[key];
    const sec = sectionOf(key);
    if (!f || !sec) return key;
    if (['general', 'web', 'https', 'search', 'detections', 'intel'].includes(sec.id)) return f.label;
    return sec.title + ' ' + noun(f.label);
  }
  // noun is a label inside a sentence: "Password" becomes "password",
  // while "API key" and "OpenSearch address" keep their capitals.
  const noun = (label) => (/^[A-Z][a-z]*(\s|$)/.test(label) ? label.charAt(0).toLowerCase() + label.slice(1) : label);
  function listWords(items) {
    if (items.length <= 1) return items.join('');
    return items.slice(0, -1).join(', ') + ' and ' + items[items.length - 1];
  }
  function uptime(s) {
    const d = Math.floor(s / 86400);
    const h = Math.floor((s % 86400) / 3600);
    const m = Math.floor((s % 3600) / 60);
    if (d) return `${d}d ${h}h`;
    if (h) return `${h}h ${m}m`;
    return m ? `${m}m` : 'less than a minute';
  }

  // ---------- loading ----------
  pageHooks.push((name) => {
    if (name === 'settings') load();
  });

  async function load() {
    const seq = ++S.seq;
    if (!S.view) renderLoading();
    let v;
    try {
      v = await api('api/settings');
    } catch (e) {
      if (seq === S.seq && !S.view) renderError(e);
      else if (seq === S.seq && e.code !== 'forbidden') toastError('Couldn’t refresh the settings', e);
      return;
    }
    if (seq !== S.seq) return;
    S.view = v;
    render();
    focusSetting();
    if (v.restart.in_progress && !S.restart) watchRestart({ before: lastAt(v), started: Date.now(), external: true });
    // The page that asked for the restart leaves a note: in this tab's
    // storage, or in the address when it followed Signalith to a new one
    // (another origin, with its own storage).
    let note = null;
    try { note = sessionStorage.getItem(RESTART_NOTE); sessionStorage.removeItem(RESTART_NOTE); } catch (_) { /* storage may be blocked */ }
    if (new URLSearchParams(location.search).has('restarted')) {
      note = '1';
      try { history.replaceState(null, '', location.pathname + location.hash); } catch (_) { /* sandboxed */ }
    }
    const last = v.restart.last;
    if (note && last && last.ok) toast('Signalith restarted with the saved settings.', null, { title: 'Restarted' });
  }
  const lastAt = (v) => (v.restart.last ? v.restart.last.at : '');

  function renderLoading() {
    fill($('st-alerts'));
    fill($('st-nav'));
    $('st-main').setAttribute('aria-busy', 'true');
    fill($('st-main'), ...[0, 1, 2].map(() => el('div', { class: 'card st-card st-skel' },
      el('div', { class: 'st-card__head' }, dxSkel('120px')),
      el('div', { class: 'st-card__body' }, ...[0, 1].map(() => el('div', { class: 'st-field' },
        el('div', { class: 'st-field__text' }, dxSkel('140px'), dxSkel('70%')), el('div', {}, dxSkel('100%'))))))));
  }
  function renderError(e) {
    fill($('st-nav'));
    $('st-main').setAttribute('aria-busy', 'false');
    fill($('st-main'), el('div', { class: 'card' }, dxEmpty({
      tone: 'danger', icon: 'circle-alert', title: 'Couldn’t load the settings', text: sentence(e.message), action: dxRetry(load),
    })));
  }

  // ---------- drawing ----------
  function render() {
    const v = S.view;
    S.fields = {};
    S.sections = {};
    S.controls = {};
    for (const sec of v.sections) {
      for (const f of sec.fields) { S.fields[f.key] = f; S.sections[f.key] = sec; }
    }
    // Drafts of settings that are now locked, or back to the value saved,
    // are no longer changes.
    for (const k of dirtyKeys()) {
      const f = S.fields[k];
      const d = S.drafts[k];
      if (!f || readOnly(f) || (d.kind === 'value' && f.type !== 'secret' && same(d.value, f.value)) || (d.kind === 'retry' && !f.refused)) delete S.drafts[k];
    }
    renderAlerts();
    renderNav();
    const main = $('st-main');
    main.setAttribute('aria-busy', 'false');
    fill(main, ...v.sections.map(sectionCard), aboutCard(), saveBar());
    for (const k of Object.keys(S.fields)) syncRow(k);
    syncAll();
    syncActive();
  }

  // openSetting opens the page at one setting, for links from other pages
  // (the syslog steps on Add data, turned-away senders on Health).
  window.openSetting = (key) => {
    S.focusKey = key;
    showPage('settings');
  };
  function focusSetting() {
    const key = S.focusKey;
    S.focusKey = '';
    const row = key && document.querySelector(`#st-main .st-field[data-key="${CSS.escape(key)}"]`);
    if (!row) return;
    const sec = sectionOf(key);
    row.scrollIntoView({ block: 'center' });
    S.pinned = sec.id;
    S.pinnedY = window.scrollY;
    markActive(sec.id);
    const ctl = S.controls[key];
    const target = ctl && !ctl.disabled ? ctl : $('st-sec-' + sec.id + '-title');
    if (target) target.focus({ preventScroll: true });
  }

  // ---- the list of sections ----
  function renderNav() {
    const items = S.view.sections.map((s) => [s.id, s.title]).concat([['about', 'About this server']]);
    fill($('st-nav'), el('ul', { class: 'st-nav__list', role: 'list' }, ...items.map(([id, title]) => el('li', {},
      el('button', { type: 'button', class: 'st-nav__item', 'data-sec': id, onclick: () => goToSection(id) },
        el('span', {}, title), el('span', { class: 'st-nav__mark', 'aria-hidden': 'true' }))))));
    syncActive();
  }

  function goToSection(id) {
    const card = $('st-sec-' + id);
    if (!card) return;
    card.scrollIntoView({ block: 'start' });
    S.pinned = id;
    S.pinnedY = window.scrollY;
    markActive(id);
    const t = $('st-sec-' + id + '-title');
    if (t) t.focus({ preventScroll: true });
  }
  function markActive(id) {
    const nav = $('st-nav');
    document.querySelectorAll('#st-nav .st-nav__item').forEach((b) => {
      if (b.dataset.sec !== id) { b.removeAttribute('aria-current'); return; }
      b.setAttribute('aria-current', 'true');
      // On a phone the sections are a row that scrolls sideways: keep the
      // one marked in view.
      if (nav && nav.scrollWidth > nav.clientWidth) {
        const left = b.offsetLeft - 16;
        const right = b.offsetLeft + b.offsetWidth + 16;
        if (left < nav.scrollLeft) nav.scrollLeft = left;
        else if (right > nav.scrollLeft + nav.clientWidth) nav.scrollLeft = right - nav.clientWidth;
      }
    });
  }
  // syncActive highlights the section at the top of the window, or the
  // last one at the end of the page; a section just picked in the list
  // stays highlighted until the page scrolls.
  let activeFrame = 0;
  function syncActive() {
    activeFrame = 0;
    if (!S.view || !isShown()) return;
    if (S.pinned && Math.abs(window.scrollY - S.pinnedY) < 4) { markActive(S.pinned); return; }
    S.pinned = '';
    const cards = [...document.querySelectorAll('#st-main > .st-card[id]')];
    if (!cards.length) return;
    let cur = cards[0];
    // Below the row of sections on a phone, below the top bar otherwise.
    const nav = $('st-nav');
    const edge = narrow() && nav ? nav.getBoundingClientRect().bottom + 24 : 140;
    for (const c of cards) if (c.getBoundingClientRect().top <= edge) cur = c;
    if (window.innerHeight + window.scrollY >= document.documentElement.scrollHeight - 4) cur = cards[cards.length - 1];
    markActive(cur.id.replace(/^st-sec-/, ''));
  }
  window.addEventListener('scroll', () => { if (!activeFrame) activeFrame = requestAnimationFrame(syncActive); }, { passive: true });

  // ---- the sections ----
  function sectionCard(sec) {
    const restart = sec.fields.filter((f) => f.apply === 'restart').length;
    const mixed = restart > 0 && restart < sec.fields.length;
    const tag = mixed ? null : restart
      ? el('span', { class: 'st-apply' }, icon('rotate-ccw', 'icon--sm'), 'Applies after a restart')
      : el('span', { class: 'st-apply' }, icon('zap', 'icon--sm'), 'Applies when saved');
    const titleId = 'st-sec-' + sec.id + '-title';
    return el('section', { class: 'card st-card', id: 'st-sec-' + sec.id, 'aria-labelledby': titleId },
      el('div', { class: 'st-card__head' },
        el('div', { class: 'st-card__heading' }, el('h3', { class: 'st-card__title', id: titleId, tabindex: '-1' }, sec.title),
          sec.help ? el('p', { class: 'st-card__desc' }, sec.help) : null),
        tag),
      el('div', { class: 'st-card__body' }, ...sec.fields.map((f) => fieldRow(f, mixed))),
      TESTS[sec.id] ? testBlock(sec.id) : null,
      sec.id === 'https' ? certificateBlock() : null);
  }

  // certificateBlock says how Signalith serves HTTPS now: the mode in use,
  // the names its certificate covers and, with its own certificate
  // authority, the CA to trust.
  function certificateBlock() {
    const t = S.view.tls || {};
    const f = S.fields['server.tls.mode'];
    const mode = f && (f.choices || []).find((c) => c.value === t.mode);
    const rows = [['HTTPS', mode ? mode.label : (t.mode || 'unknown')]];
    if (t.mode !== 'off' && (t.names || []).length) {
      rows.push(['Certificate covers', el('span', { class: 'mono' }, t.names.join(', '))]);
    }
    if (t.ca_sha256) rows.push([t.own_ca ? 'Signalith’s CA (SHA-256)' : 'Certificate authority (SHA-256)', el('span', { class: 'mono st-fp' }, t.ca_sha256)]);
    if (t.own_ca && t.ca_scope) {
      const made = t.ca_made ? ', made ' + new Date(t.ca_made).toLocaleDateString('en-GB', { day: 'numeric', month: 'short', year: 'numeric' }) : '';
      rows.push(['Certificate authority', el('span', {}, cap(CA_SCOPE[t.ca_scope] || t.ca_scope) + made + '. ', securityLink('Change it on the Security page'), '.')]);
    }
    const lead = t.mode === 'off'
      ? 'Signalith serves plain HTTP; the reverse proxy in front serves HTTPS.' + (t.names ? ' Syslog over TLS uses Signalith’s own certificate.' : '')
      : t.own_ca
        ? 'Browsers warn until this certificate authority is trusted. Agents and syslog devices get it with their setup on Add data.'
        : 'Your certificate is loaded again when its file changes.';
    return el('div', { class: 'st-test st-cert', id: 'st-cert' },
      el('h4', { class: 'section-title' }, 'In use now'),
      el('p', { class: 'st-test__lead' }, lead),
      el('dl', { class: 'kv st-kv' }, ...rows.flatMap(([k, val]) => [el('dt', {}, k), el('dd', {}, val)])),
      t.own_ca ? el('div', { class: 'btn-row' }, el('a', { class: 'btn btn--secondary btn--sm', href: 'api/tls/ca.pem', download: 'signalith-ca.pem' },
        icon('download'), 'Download the CA certificate')) : null);
  }

  // fieldRow draws one setting: its label, help and where its value comes
  // from on the left; the control and any problem with it on the right.
  function fieldRow(f, mixed) {
    const id = idOf(f.key);
    const ctl = control(f, id);
    const labelAttrs = { class: 'st-field__label', id: id + '-label' };
    // A secret's box comes and goes; its label names the whole group.
    const label = f.type === 'secret' ? el('span', labelAttrs, f.label) : el('label', Object.assign(labelAttrs, { for: id }), f.label);
    const row = el('div', { class: 'st-field', 'data-key': f.key, 'data-type': f.type },
      el('div', { class: 'st-field__text' }, label,
        el('p', { class: 'st-field__help', id: id + '-help' }, f.help),
        mixed && f.apply === 'restart' ? el('p', { class: 'st-field__note' }, icon('rotate-ccw', 'icon--xs'), 'Applies after a restart') : null,
        el('div', { class: 'st-field__meta', id: id + '-meta' })),
      el('div', { class: 'st-field__control' }, ctl,
        el('div', { class: 'st-field__notes', id: id + '-notes' })));
    return row;
  }

  // rerenderRow draws a setting again after Reset, Replace and the like,
  // and puts focus on what takes the place of the button pressed.
  function rerenderRow(key, focus) {
    const old = document.querySelector(`#st-main .st-field[data-key="${CSS.escape(key)}"]`);
    if (!old) return;
    const sec = sectionOf(key);
    const restart = sec.fields.filter((f) => f.apply === 'restart').length;
    const row = fieldRow(S.fields[key], restart > 0 && restart < sec.fields.length);
    old.replaceWith(row);
    syncRow(key);
    syncAll();
    if (focus) {
      const target = typeof focus === 'string' ? row.querySelector(focus) : S.controls[key];
      if (target) target.focus();
    }
  }

  function inputFor(f, id, value) {
    const attrs = { id, class: 'input' + (MONO.has(f.type) || MONO_KEYS.has(f.key) ? ' mono' : ''), type: 'text', autocomplete: 'off', spellcheck: 'false', autocapitalize: 'none' };
    // An example reads as one, unless it is also what empty means.
    if (f.placeholder) attrs.placeholder = f.placeholder === f.empty_means ? f.placeholder : 'e.g. ' + f.placeholder;
    if (f.type === 'url') attrs.inputmode = 'url';
    if (f.type === 'duration' || f.type === 'number') attrs.class += ' st-input--short';
    if (f.type === 'number') {
      Object.assign(attrs, { type: 'number', inputmode: 'numeric', step: '1' });
      if (f.min != null) attrs.min = String(f.min);
      if (f.max != null) attrs.max = String(f.max);
      if (f.empty_means) attrs.placeholder = f.empty_means;
    }
    const n = el('input', attrs);
    n.value = value;
    return n;
  }

  // rawOf is what a control shows for a value.
  function rawOf(f, v) {
    if (f.type === 'list') return (v || []).join('\n');
    if (f.type === 'number' && v === 0 && f.empty_means) return '';
    return v == null ? '' : String(v);
  }

  function control(f, id) {
    const d = S.drafts[f.key];
    const ro = readOnly(f);
    if (f.type === 'secret') return secretControl(f, id);
    const value = d && d.kind === 'value' && d.raw != null ? d.raw : rawOf(f, current(f.key));
    let n;
    if (f.type === 'bool') {
      const box = el('input', { type: 'checkbox', id, role: 'switch' });
      box.checked = !!current(f.key);
      const state = el('span', { class: 'st-switch__state', 'aria-hidden': 'true' }, box.checked ? 'On' : 'Off');
      box.addEventListener('change', () => { state.textContent = box.checked ? 'On' : 'Off'; edited(f, box.checked); });
      if (ro) box.disabled = true;
      S.controls[f.key] = box;
      describe(box, f);
      return el('label', { class: 'switch st-switch' }, box, state);
    }
    if (f.type === 'choice') {
      n = el('select', { id, class: 'select select--block' });
      const choices = (f.choices || []).slice();
      if (!choices.some((c) => c.value === value)) choices.push({ value, label: value });
      for (const c of choices) {
        const o = el('option', { value: c.value }, c.label);
        if (c.value === value) o.selected = true;
        n.append(o);
      }
      n.addEventListener('change', () => edited(f, n.value));
    } else if (f.type === 'list') {
      n = el('textarea', { id, class: 'textarea mono', rows: '3', spellcheck: 'false', autocomplete: 'off', placeholder: f.placeholder ? 'e.g. ' + f.placeholder : '' });
      n.value = value;
      n.addEventListener('input', () => edited(f, n.value));
    } else {
      n = inputFor(f, id, value);
      n.addEventListener('input', () => edited(f, n.value));
    }
    if (ro) n.disabled = true;
    S.controls[f.key] = n;
    describe(n, f);
    return n;
  }
  function describe(n, f) {
    const id = idOf(f.key);
    n.setAttribute('aria-describedby', [id + '-help', id + '-meta', id + '-notes'].join(' '));
  }

  // secretControl shows a saved password or key as "Saved, hidden" with
  // Replace and Remove; it is never sent back to the page.
  function secretControl(f, id) {
    const d = S.drafts[f.key];
    const ro = readOnly(f);
    const box = el('div', { class: 'st-secret', role: 'group', 'aria-labelledby': id + '-label', 'aria-describedby': [id + '-help', id + '-meta', id + '-notes'].join(' ') });
    const status = (text, ...kids) => el('div', { class: 'st-secret__saved' }, icon('key-round', 'icon--sm'), el('span', {}, text), ...kids);
    if (ro) {
      box.append(status(f.set ? 'Saved, hidden' : 'Not set'));
      return box;
    }
    const removing = d && (d.kind === 'clear' || (d.kind === 'reset' && f.reset_to && !f.reset_to.set));
    const undo = () => el('button', { type: 'button', class: 'link-btn st-secret__undo', onclick: () => { delete S.drafts[f.key]; rerenderRow(f.key, '.st-secret__btn'); } }, 'Undo');
    if (removing) {
      box.append(el('div', { class: 'st-secret__saved is-removing' }, icon('trash-2', 'icon--sm'), el('span', {}, 'Removed when you save'), undo()));
      return box;
    }
    if (d && d.kind === 'retry') {
      box.append(status('The one set aside is used again when you save', undo()));
      return box;
    }
    if (d && d.kind === 'reset' && f.refused && f.source.kind !== 'page') {
      box.append(status('The one set aside is removed when you save', undo()));
      return box;
    }
    if (d && d.kind === 'reset') {
      box.append(status('Back to the one in ' + SOURCE_FILE + ' when you save', undo()));
      return box;
    }
    if (f.set && !S.replacing[f.key] && !d) {
      const replace = el('button', { type: 'button', class: 'btn btn--secondary btn--sm st-secret__btn', 'aria-label': 'Replace the ' + noun(f.label) }, 'Replace');
      replace.addEventListener('click', () => { S.replacing[f.key] = true; rerenderRow(f.key, true); });
      const remove = el('button', { type: 'button', class: 'btn btn--ghost btn--sm st-secret__btn', 'aria-label': 'Remove the ' + noun(f.label) }, 'Remove');
      remove.addEventListener('click', () => {
        // Off the page entirely when nothing else sets one; otherwise an
        // empty one here overrides signalith.yaml.
        S.drafts[f.key] = f.source.kind === 'page' && f.reset_to && !f.reset_to.set ? { kind: 'reset' } : { kind: 'clear' };
        rerenderRow(f.key, '.st-secret__undo');
      });
      // One saved on this page is kept encrypted in the settings file.
      box.append(el('div', { class: 'st-secret__row' }, status(f.source.kind === 'page' ? 'Saved encrypted, hidden' : 'Saved, hidden'), replace, remove));
      S.controls[f.key] = replace;
      return box;
    }
    const n = el('input', { id, class: 'input', type: 'password', autocomplete: 'new-password', spellcheck: 'false', placeholder: f.set ? 'Type the new one' : 'Not set' });
    n.setAttribute('aria-labelledby', id + '-label');
    n.value = d && d.kind === 'value' ? d.raw : '';
    n.addEventListener('input', () => edited(f, n.value));
    S.controls[f.key] = n;
    const kids = [n];
    if (f.set) {
      kids.push(el('button', { type: 'button', class: 'btn btn--ghost btn--sm', onclick: () => {
        delete S.replacing[f.key];
        delete S.drafts[f.key];
        rerenderRow(f.key, '.st-secret__btn');
      } }, 'Keep saved'));
    }
    box.append(el('div', { class: 'st-secret__input' }, ...kids));
    return box;
  }

  // edited records a change typed or picked in a control.
  function edited(f, raw) {
    const v = parse(f, raw);
    if (f.type === 'secret') {
      if (raw === '') delete S.drafts[f.key]; else S.drafts[f.key] = { kind: 'value', value: raw, raw };
    } else if (same(v, f.value)) {
      delete S.drafts[f.key];
    } else {
      S.drafts[f.key] = { kind: 'value', value: v, raw };
    }
    if (S.saveErr && S.saveErr.fields[f.key]) delete S.saveErr.fields[f.key];
    syncRow(f.key);
    syncAll();
  }

  // syncRow fills in a setting's notes: where its value comes from when
  // that says something (changed here, set by the environment, set aside
  // by a restart), and under the control any problem, warning, or what an
  // empty value means. A value from signalith.yaml gets no note: the page
  // says so once, at the top.
  function syncRow(key) {
    const f = S.fields[key];
    const id = idOf(key);
    const meta = $(id + '-meta');
    const notes = $(id + '-notes');
    if (!f || !meta || !notes) return;
    const d = S.drafts[key];
    const ro = readOnly(f);
    const undo = (focus) => el('button', { type: 'button', class: 'link-btn', onclick: () => { delete S.drafts[key]; rerenderRow(key, focus); } }, 'Undo');
    const bits = [];
    if (f.locked) {
      const n = el('p', { class: 'st-source st-source--env', title: f.locked_reason || '' }, icon('lock', 'icon--xs'),
        el('span', {}, 'Set by ', el('code', {}, f.source.env), '. To change it, change Signalith’s environment and restart.'));
      bits.push(n);
    } else if (d && d.kind === 'retry') {
      // A secret's box says it already.
      if (f.type !== 'secret') {
        bits.push(el('p', { class: 'st-source st-source--reset' }, icon('rotate-ccw', 'icon--xs'),
          el('span', {}, `Back to ${show(f, f.refused.value)} when you save. `), undo('.st-retry')));
      }
    } else if (d && d.kind === 'reset' && f.refused && f.source.kind !== 'page') {
      if (f.type !== 'secret') {
        bits.push(el('p', { class: 'st-source st-source--reset' }, icon('trash-2', 'icon--xs'),
          el('span', {}, 'The change set aside is removed when you save. '), undo('.st-retry')));
      }
    } else if (d && d.kind === 'reset' && f.type !== 'secret') {
      const to = f.reset_to || {};
      bits.push(el('p', { class: 'st-source st-source--reset' }, icon('undo-2', 'icon--xs'),
        el('span', {}, to.source === 'file' ? `Back to ${show(f, to.value)} from ${SOURCE_FILE} when you save. ` : `Back to the default, ${show(f, to.value)}, when you save. `),
        undo('.st-reset')));
    } else if (f.refused && !d) {
      // A change a restart set aside: not used until it is tried again.
      const val = f.type === 'secret' ? 'The ' + noun(f.label) + ' saved here' : show(f, f.refused.value);
      const acts = ro ? [] : [
        el('button', { type: 'button', class: 'link-btn st-retry', onclick: () => { S.drafts[key] = { kind: 'retry' }; rerenderRow(key, '.link-btn'); } }, 'Try it again'),
        el('span', { class: 'st-dot', 'aria-hidden': 'true' }),
        el('button', { type: 'button', class: 'link-btn', 'aria-label': 'Remove the ' + noun(f.label) + ' set aside', onclick: () => { S.drafts[key] = { kind: 'reset' }; rerenderRow(key, '.link-btn'); } }, 'Remove'),
      ];
      bits.push(el('p', { class: 'st-source st-source--refused' }, icon('triangle-alert', 'icon--xs'),
        el('span', {}, 'Set aside: ', el('span', { class: f.type === 'secret' ? '' : 'mono' }, val), ' is not used.'), ...acts));
    } else if (f.source.kind === 'page') {
      const who = f.source.by ? `Changed here by ${f.source.by}` : 'Changed here';
      const when = f.source.at ? el('span', { class: 'age', title: new Date(f.source.at).toLocaleString() }, ago(f.source.at)) : null;
      const reset = ro || (d && d.kind === 'reset') ? null : el('button', {
        type: 'button', class: 'link-btn st-reset',
        'aria-label': `Reset ${noun(f.label)} to the ${f.reset_to && f.reset_to.source === 'file' ? SOURCE_FILE : 'default'} value`,
        onclick: () => { S.drafts[key] = { kind: 'reset' }; delete S.replacing[key]; if (S.saveErr) delete S.saveErr.fields[key]; rerenderRow(key, f.type === 'secret' ? '.st-secret__undo' : '.link-btn'); },
      }, 'Reset');
      bits.push(el('p', { class: 'st-source' }, el('span', {}, who, when ? ', ' : '', when), reset ? el('span', { class: 'st-dot', 'aria-hidden': 'true' }) : null, reset));
    }
    if (f.pending && !d) {
      bits.push(el('p', { class: 'st-source st-source--pending' }, icon('clock', 'icon--xs'), S.view.startup_problem && f.apply === 'live'
        ? 'Not in use, since Signalith started without the settings saved here.'
        : 'Saved. Waits for a restart.'));
    }
    fill(meta, ...bits);

    const out = [];
    const problem = (S.saveErr && S.saveErr.fields[key]) || (!d ? f.problem : '');
    if (problem) out.push(el('p', { class: 'field-error', role: S.saveErr && S.saveErr.fields[key] ? 'alert' : null }, icon('circle-alert'), el('span', {}, sentence(problem))));
    if (!problem && !d && startupBlame().includes(key)) {
      out.push(el('p', { class: 'field-error' }, icon('circle-alert'), el('span', {}, 'Signalith couldn’t start with this, so it started without the settings saved here. Change it or reset it, then restart.')));
    }
    if (f.refused && !d) out.push(el('p', { class: 'st-warn' }, icon('triangle-alert'), el('span', {}, sentence(f.refused.reason))));
    if (f.warning && !d) {
      const use = f.suggest && !ro ? el('button', { type: 'button', class: 'btn btn--secondary btn--sm st-use', onclick: () => {
        edited(f, f.suggest);
        rerenderRow(key, true);
      } }, 'Use ', el('span', { class: 'mono' }, f.suggest)) : null;
      out.push(el('div', { class: 'st-warn' }, icon('triangle-alert'), el('div', { class: 'st-warn__body' }, el('span', {}, f.warning), use)));
    }
    // A saved secret is only sent to the address it was entered for.
    if (f.type === 'secret' && f.set && !ro && !d && f.sent_to && !(S.saveErr && S.saveErr.fields[key])) {
      const now = sentToNow(key);
      if (!now) {
        // Turned off: kept for when the same address comes back.
        out.push(el('p', { class: 'st-hint' }, 'Not sent anywhere now. Kept for ', el('span', { class: 'mono' }, f.sent_to), '.'));
      } else if (now !== f.sent_to) {
        out.push(el('p', { class: 'st-warn' }, icon('triangle-alert'), el('span', {},
          `Enter the ${noun(f.label)} again, or remove it: the saved one is only sent to ${f.sent_to}.`)));
      } else {
        out.push(el('p', { class: 'st-hint' }, 'Only sent to ', el('span', { class: 'mono' }, f.sent_to), '.'));
      }
    }
    if (key === 'assistant.model' && !ro) {
      // Only Anthropic has a model to fall back on.
      const v = current(key);
      if (v === '' && current('assistant.provider') === 'anthropic') out.push(el('p', { class: 'st-hint' }, 'When empty: ' + f.empty_means + '.'));
    } else if (f.empty_means && !ro && f.type !== 'number' && f.type !== 'secret' && f.type !== 'choice') {
      const v = current(key);
      if (v === '' || (Array.isArray(v) && !v.length)) out.push(el('p', { class: 'st-hint' }, 'When empty: ' + f.empty_means + '.'));
    }
    // The certificate authority in use changes only on the Security page.
    const tls = S.view.tls || {};
    if (key === 'server.tls.ca_scope' && tls.own_ca && tls.ca_scope) {
      const chosen = current(key) || 'standard';
      let hint;
      if (tls.next_ca_sha256) hint = ['A new one is made. Switch to it on the ', securityLink('Security page'), '.'];
      else if (chosen === tls.ca_scope) hint = ['In use now. The ', securityLink('Security page'), ' makes a new certificate authority and switches to it.'];
      else hint = [`The one in use is ${CA_SCOPE[tls.ca_scope] || tls.ca_scope}. Nothing changes until you make the new one and switch to it on the `, securityLink('Security page'), '.'];
      out.push(el('p', { class: 'st-hint' }, ...hint));
    }
    if (PORTS.has(key) && (S.view.about || {}).container && (d || f.pending)) {
      out.push(el('p', { class: 'st-hint' }, 'In Docker, also publish the new port under ports: in docker-compose.yml.'));
    }
    fill(notes, ...out);
    const c = S.controls[key];
    if (c && c.matches('input, select, textarea')) {
      if (problem) c.setAttribute('aria-invalid', 'true'); else c.removeAttribute('aria-invalid');
    }
    const row = notes.closest('.st-field');
    if (row) row.classList.toggle('is-changed', !!d);
  }

  // startupBlame lists the settings Signalith could not start with, while
  // they are as they were then: changed since, they may work.
  function startupBlame() {
    const v = S.view;
    if (!v || !v.startup_problem) return [];
    const started = Date.parse((v.about || {}).started || '');
    return (v.startup_keys || []).filter((k) => {
      const f = S.fields[k];
      if (!f || f.refused) return false;
      return !(f.source.kind === 'page' && f.source.at && started && Date.parse(f.source.at) > started);
    });
  }

  // syncAll updates what depends on every draft: the save bar, the marks
  // in the section list, test results and the secrets' addresses.
  function syncAll() {
    const n = dirtyKeys().length;
    const bar = $('st-savebar');
    if (bar) {
      const problems = S.saveErr ? Object.keys(S.saveErr.fields).length + S.saveErr.problems.length : 0;
      bar.hidden = !n && !problems;
      const text = $('st-savebar-text');
      if (problems) {
        fill(text, el('span', { class: 'st-savebar__error' }, icon('circle-alert', 'icon--sm'),
          problems === 1 ? 'Nothing was saved. Fix the setting marked.' : `Nothing was saved. Fix the ${problems} settings marked.`), ' ',
        el('button', { type: 'button', class: 'link-btn', onclick: focusFirstProblem }, 'Show'));
      } else {
        fill(text, el('span', { class: 'st-savebar__dot', 'aria-hidden': 'true' }), n === 1 ? '1 unsaved change' : `${n} unsaved changes`);
      }
      $('st-save').disabled = !n;
      $('st-discard').hidden = !n;
      const general = $('st-savebar-general');
      fill(general, ...(S.saveErr && S.saveErr.problems.length ? [el('ul', { class: 'st-problems' }, ...S.saveErr.problems.map((p) => el('li', {}, sentence(p))))] : []));
      general.hidden = !general.firstChild;
    }
    // section marks: unsaved changes, problems
    document.querySelectorAll('#st-nav .st-nav__item').forEach((b) => {
      const sec = S.view.sections.find((s) => s.id === b.dataset.sec);
      const keys = sec ? sec.fields.map((f) => f.key) : [];
      const blame = startupBlame();
      const bad = keys.some((k) => (S.saveErr && S.saveErr.fields[k]) || (!S.drafts[k] && (S.fields[k].problem || S.fields[k].refused || blame.includes(k))));
      const changed = keys.some((k) => S.drafts[k]);
      const mark = b.querySelector('.st-nav__mark');
      mark.dataset.state = bad ? 'problem' : changed ? 'changed' : '';
      b.title = bad ? 'Needs fixing' : changed ? 'Unsaved changes' : '';
    });
    for (const k of ['opensearch.password', 'assistant.api_key', 'assistant.model']) if (S.fields[k]) syncRow(k);
    syncStale();
    syncRestartButton();
  }

  // ---- saving ----
  function saveBar() {
    const discard = el('button', { type: 'button', class: 'btn btn--ghost', id: 'st-discard' }, 'Discard');
    const save = el('button', { type: 'button', class: 'btn btn--primary', id: 'st-save' }, 'Save changes');
    discard.addEventListener('click', discardAll);
    save.addEventListener('click', saveAll);
    const bar = el('div', { class: 'st-savebar', id: 'st-savebar', role: 'region', 'aria-label': 'Unsaved changes' },
      el('div', { class: 'st-savebar__general', id: 'st-savebar-general' }),
      el('div', { class: 'st-savebar__row' }, el('span', { class: 'st-savebar__text', id: 'st-savebar-text', role: 'status' }),
        el('span', { class: 'spacer' }), discard, save));
    bar.hidden = true;
    return bar;
  }

  function discardAll() {
    S.drafts = {};
    S.replacing = {};
    S.saveErr = null;
    render();
    toast('Changes discarded.');
    const t = $('crumb-page');
    if (t) t.focus({ preventScroll: true });
  }

  // confirmChanges asks once about every change the server says needs a
  // yes, naming what each one does; some offer another change to make
  // with it. It resolves to null for Cancel, or to the changes to add.
  function confirmChanges(list) {
    const d = modalDialog('st-confirm');
    d.classList.add('st-dialog');
    return new Promise((resolve) => {
      let answer = null;
      const boxes = [];
      const one = list.length === 1 ? list[0] : null;
      let title = 'Save these changes?';
      if (one) {
        const f = S.fields[one.key];
        title = one.title || (f && f.type === 'bool' ? `Turn ${current(one.key) ? 'on' : 'off'} “${f.label}”?` : `Change the ${noun(shortName(one.key))}?`);
      }
      const cancel = el('button', { type: 'button', class: 'btn btn--ghost', onclick: () => d.close() }, 'Cancel');
      const ok = el('button', { type: 'button', class: 'btn btn--danger', onclick: () => {
        answer = {};
        for (const [box, also] of boxes) if (box.checked) answer[also.key] = also.value;
        d.close();
      } }, 'Save changes');
      const item = (c) => {
        const f = S.fields[c.key];
        const val = (v) => el('span', { class: 'mono' }, f ? show(f, v) : String(v));
        let change = null;
        // An empty old value is left out of the answer.
        if (c.new !== undefined) change = el('span', { class: 'st-confirm__change' }, val(c.old === undefined ? '' : c.old), icon('arrow-right', 'icon--xs'), val(c.new));
        else if (c.old !== undefined) change = el('span', { class: 'st-confirm__change' }, val(c.old));
        let also = null;
        if (c.also) {
          const box = el('input', { type: 'checkbox' });
          box.checked = true;
          boxes.push([box, c.also]);
          also = el('label', { class: 'check st-confirm__also' }, box, el('span', {}, c.also.label));
        }
        return el('li', { class: 'st-confirm__item' },
          el('div', { class: 'st-confirm__what' }, el('b', {}, c.name || shortName(c.key)), change),
          el('p', {}, c.text), also);
      };
      fill(d, modalHead('st-confirm', title, one ? null : 'Some of them change how Signalith works:', () => d.close()),
        el('div', { class: 'modal__body' }, el('ul', { class: 'st-confirm__list', role: 'list' }, ...list.map(item))),
        el('div', { class: 'modal__foot' }, cancel, ok));
      d.onclose = () => resolve(answer);
      d.showModal();
      cancel.focus();
    });
  }

  // showSaveProblems marks the settings a save or a check refused.
  function showSaveProblems(e) {
    const fields = {};
    const problems = (e.problems || []).slice();
    for (const [k, msg] of Object.entries(e.fields)) {
      if (S.fields[k] && !readOnly(S.fields[k])) fields[k] = msg; else problems.push((S.fields[k] ? S.fields[k].label + ': ' : '') + msg);
    }
    if (!Object.keys(fields).length && !problems.length) problems.push(e.message);
    S.saveErr = { fields, problems };
    for (const k of Object.keys(S.fields)) syncRow(k);
    syncAll();
    focusFirstProblem();
  }

  // saveAll checks the changes with the server first, so problems show
  // before anything is asked; then asks about the risky ones, and saves.
  async function saveAll() {
    const keys = dirtyKeys();
    if (!keys.length) return;
    const body = { values: {}, clear: [], reset: [], retry: [] };
    for (const k of keys) {
      const d = S.drafts[k];
      if (d.kind === 'value') body.values[k] = d.value;
      else if (d.kind === 'clear') body.clear.push(k);
      else if (d.kind === 'retry') body.retry.push(k);
      else body.reset.push(k);
    }
    let restore = busy($('st-save'), 'Saving…');
    let v;
    try {
      const check = await api('api/settings', Object.assign({ check_only: true }, body), 'PUT');
      const asks = check.confirm || [];
      if (asks.length) {
        restore();
        const also = await confirmChanges(asks);
        if (!also) { $('st-save').focus(); return; }
        Object.assign(body.values, also);
        if (asks.some((c) => c.code === 'local_only')) S.localOK = true;
        restore = busy($('st-save'), 'Saving…');
      }
      v = await api('api/settings', body, 'PUT');
    } catch (e) {
      restore();
      if (e.status === 400 && e.fields) {
        showSaveProblems(e);
      } else if (e.code === 'settings_file') {
        S.saveErr = null;
        load();
        toastError('The settings were not saved', e);
      } else if (e.code !== 'forbidden') {
        toastError('The settings were not saved', e);
      }
      return;
    }
    const focusKey = keys[0];
    S.view = v;
    S.drafts = {};
    S.replacing = {};
    S.saveErr = null;
    render();
    const later = v.after_restart || [];
    const now = v.applied || [];
    if (later.length) {
      toast(now.length ? 'Some apply now. The rest wait for a restart.' : 'They apply after a restart.', null, { title: 'Saved' });
      const banner = $('st-restart');
      if (banner) { window.scrollTo({ top: 0 }); banner.focus({ preventScroll: true }); }
    } else {
      toast(now.length ? 'Saved. The changes apply now.' : 'Saved.');
      const c = S.controls[focusKey];
      if (c && !c.disabled) c.focus({ preventScroll: true });
    }
  }

  // focusFirstProblem goes to the first setting marked, preferring one
  // that was changed: a problem can also mark the settings it depends on.
  function focusFirstProblem() {
    const keys = Object.keys(S.fields).filter((k) => S.saveErr && S.saveErr.fields[k]);
    const first = keys.find((k) => S.drafts[k]) || keys[0];
    if (!first) { const g = $('st-savebar-general'); if (g) g.scrollIntoView({ block: 'nearest' }); return; }
    const row = document.querySelector(`#st-main .st-field[data-key="${CSS.escape(first)}"]`);
    if (row) row.scrollIntoView({ block: 'center' });
    const c = S.controls[first];
    if (c) c.focus({ preventScroll: true });
  }

  // Leaving with unsaved changes asks first, inside the app and out.
  leaveGuards.push((from, to, opts) => {
    if (from !== 'settings' || !dirtyKeys().length) return true;
    const n = dirtyKeys().length;
    caseConfirm({
      title: 'Discard your changes?',
      text: `${n === 1 ? 'One setting was' : n + ' settings were'} changed but not saved. Leave this page without saving?`,
      confirm: 'Discard changes',
    }).then((ok) => {
      if (!ok) { $('st-save').focus(); return; }
      S.drafts = {};
      S.replacing = {};
      S.saveErr = null;
      showPage(to, Object.assign({}, opts, { force: true }));
    });
    return false;
  });
  window.addEventListener('beforeunload', (ev) => {
    if (dirtyKeys().length && !S.restart) { ev.preventDefault(); ev.returnValue = ''; }
  });

  // ---- testing ----
  function testPayload(id) {
    const body = { values: {}, clear: [] };
    for (const k of TESTS[id].keys) {
      const f = S.fields[k];
      const d = S.drafts[k];
      if (!f || f.locked) continue;
      if (f.type === 'secret') {
        if (d && d.kind === 'value') body.values[k] = d.value;
        else if (d && (d.kind === 'clear' || (d.kind === 'reset' && f.reset_to && !f.reset_to.set))) body.clear.push(k);
        continue;
      }
      body.values[k] = current(k);
    }
    return body;
  }

  function testBlock(id) {
    const t = TESTS[id];
    const btn = el('button', { type: 'button', class: 'btn btn--secondary', id: 'st-test-' + id }, icon(t.icon), t.button);
    const out = el('div', { class: 'st-test__out', id: 'st-test-' + id + '-out', 'aria-live': 'polite' }, S.tests[id] ? testResult(id, S.tests[id].result) : null);
    btn.addEventListener('click', () => runTest(id));
    return el('div', { class: 'st-test' },
      el('div', { class: 'st-test__row' }, btn, el('p', { class: 'st-test__lead' }, t.lead)), out);
  }

  async function runTest(id) {
    const t = TESTS[id];
    const btn = $('st-test-' + id);
    const out = $('st-test-' + id + '-out');
    const body = testPayload(id);
    const snap = JSON.stringify(body);
    const restore = busy(btn, t.busy);
    fill(out, el('p', { class: 'st-test__busy' }, t.busy));
    out.classList.remove('is-stale');
    let r;
    try {
      r = await api(t.path, body);
    } catch (e) {
      r = e.status === 400 && e.fields ? { ok: false, fields: e.fields, message: e.message } : { ok: false, failed: true, message: sentence(e.message) };
    }
    restore();
    S.tests[id] = { result: r, snap };
    fill(out, testResult(id, r));
    syncStale();
  }

  // A test result says when the settings it used changed since.
  function syncStale() {
    for (const id of Object.keys(TESTS)) {
      const out = $('st-test-' + id + '-out');
      const t = S.tests[id];
      if (out) out.classList.toggle('is-stale', !!t && t.snap !== JSON.stringify(testPayload(id)));
    }
  }
  const staleNote = () => el('p', { class: 'st-stale' }, icon('info', 'icon--sm'), 'The settings changed since this test. Test again to check them.');

  // Which setting a failed test points at.
  const OS_PROBLEM = {
    unreachable: ['Couldn’t reach OpenSearch', 'opensearch.url'], tls: ['Certificate problem', 'opensearch.url'],
    http: ['HTTP and HTTPS don’t match', 'opensearch.url'], auth: ['Sign-in refused', 'opensearch.password'],
    forbidden: ['Signed in, but not allowed', 'opensearch.username'], not_opensearch: ['That’s not OpenSearch', 'opensearch.url'],
    error: ['OpenSearch answered with an error', ''],
    // About OpenSearch itself: no setting here fixes them.
    not_initialized: ['OpenSearch’s security settings aren’t loaded', ''], busy: ['OpenSearch is too busy', ''],
    timeout: ['OpenSearch didn’t answer in time', ''],
  };
  function settingLink(key) {
    if (!key || !S.fields[key] || readOnly(S.fields[key])) return null;
    return el('button', { type: 'button', class: 'link-btn st-goto', onclick: () => {
      const row = document.querySelector(`#st-main .st-field[data-key="${CSS.escape(key)}"]`);
      if (row) row.scrollIntoView({ block: 'center' });
      const c = S.controls[key];
      if (c) c.focus({ preventScroll: true });
    } }, 'Show the setting', icon('arrow-right', 'icon--xs'));
  }

  function testResult(id, r) {
    const kids = [staleNote()];
    if (r.fields) {
      const keys = Object.keys(r.fields);
      kids.push(dxAlert('danger', 'Fix these settings first', null, el('div', {},
        el('ul', { class: 'st-problems' }, ...keys.map((k) => el('li', {}, el('b', {}, S.fields[k] ? S.fields[k].label + ': ' : ''), sentence(r.fields[k])))),
        settingLink(keys.find((k) => S.fields[k])))));
    } else if (r.failed) {
      kids.push(dxAlert('danger', 'Couldn’t run the test', r.message));
    } else if (id === 'opensearch') {
      if (r.ok) {
        const found = r.version && r.cluster_name ? `OpenSearch ${r.version}, cluster “${r.cluster_name}”. Health: ${r.health}.` : r.message;
        kids.push(dxAlert('success', 'Connected to OpenSearch', found, r.health && r.health !== 'green' ? el('p', {}, r.health === 'yellow'
          ? 'Yellow is normal with one OpenSearch node: there is nowhere to put the extra copies.'
          : 'Red means some data cannot be read. Check OpenSearch itself.') : null));
      } else {
        const [title, key] = OS_PROBLEM[r.problem] || ['Couldn’t connect', 'opensearch.url'];
        const field = r.problem === 'auth' && !current('opensearch.username') ? 'opensearch.username' : key;
        kids.push(dxAlert('danger', title, el('span', {}, ...withCode(r.message)), settingLink(field)));
      }
    } else if (r.ok) {
      const took = r.took_ms < 1000 ? 'in under a second' : `in ${(r.took_ms / 1000).toFixed(1)} seconds`;
      kids.push(dxAlert('success', 'The model answered ' + took, null, el('div', { class: 'st-test__qa' },
        el('p', {}, 'Asked: ', el('q', {}, r.question)),
        el('pre', { class: 'st-test__query mono' }, r.query))));
    } else {
      const key = /API key/i.test(r.message) ? 'assistant.api_key' : /not found/i.test(r.message) ? 'assistant.url' : '';
      kids.push(dxAlert('danger', 'The model didn’t answer', r.message, settingLink(key)));
    }
    return el('div', { class: 'st-result' }, ...kids);
  }

  // ---- about this server ----
  function aboutCard() {
    const v = S.view;
    const a = v.about || {};
    const file = v.settings_file || {};
    const facts = [
      ['Version', a.version || 'unknown'],
      ['Platform', (a.platform || '') + (a.container ? ', in a container' : '')],
    ];
    if (a.started) facts.push(['Running for', el('span', { title: 'Since ' + new Date(a.started).toLocaleString() }, uptime(a.uptime_seconds || 0))]);
    const kv = (rows) => el('dl', { class: 'kv st-kv' }, ...rows.flatMap(([k, val]) => [el('dt', {}, k), el('dd', {}, val)]));
    const pathRow = (p) => [p.label, el('span', { class: 'st-path' }, el('span', { class: 'mono' }, p.path || 'none'),
      p.source && p.source.kind === 'env' ? el('span', { class: 'st-path__note' }, icon('lock', 'icon--xs'), 'Set by ', el('code', {}, p.source.env)) : null)];
    const changed = (file.keys || []).length;
    const pages = (v.elsewhere || []).filter((x) => $('page-' + x.page));
    const exportLink = el('a', { class: 'btn btn--secondary', href: 'api/settings/export?download=1', download: 'signalith-settings.yaml' }, icon('download'), 'Download settings as YAML');
    const resetAll = changed && editable() && !fileBroken() ? el('button', { type: 'button', class: 'btn btn--ghost', id: 'st-reset-all', onclick: () => resetEverything() }, icon('undo-2'), 'Reset all') : null;
    let text = `Nothing is changed on this page yet. Every setting comes from ${SOURCE_FILE}, the environment or the defaults.`;
    if (fileBroken()) text = 'The settings file can’t be read, so the settings saved on this page aren’t shown. See the note at the top of the page.';
    else if (changed) text = `${changed === 1 ? '1 setting is' : changed + ' settings are'} changed on this page and kept in the settings file. Reset all puts back the values from ${SOURCE_FILE} or the defaults.`;
    return el('section', { class: 'card st-card st-about', id: 'st-sec-about', 'aria-labelledby': 'st-sec-about-title' },
      el('div', { class: 'st-card__head' }, el('div', { class: 'st-card__heading' },
        el('h3', { class: 'st-card__title', id: 'st-sec-about-title', tabindex: '-1' }, 'About this server'),
        el('p', { class: 'st-card__desc' }, 'Where Signalith keeps its files. These are set in ' + SOURCE_FILE + ' only, because pages save into them.'))),
      el('div', { class: 'st-card__body st-about__body' },
        kv(facts),
        el('div', { class: 'st-about__part' }, el('h4', { class: 'section-title' }, 'Files and folders'), kv((a.paths || []).map(pathRow))),
        el('div', { class: 'st-about__part' }, el('h4', { class: 'section-title' }, 'Changed on this page'),
          el('p', { class: 'st-about__text' }, text),
          el('div', { class: 'btn-row' }, exportLink, resetAll),
          el('p', { class: 'st-hint' }, 'The download has the settings in the format of ' + SOURCE_FILE + ', for another server. Passwords and keys are left out.')),
        pages.length ? el('div', { class: 'st-about__part' }, el('h4', { class: 'section-title' }, 'Set up on other pages'),
          el('ul', { class: 'st-links', role: 'list' }, ...pages.map((x) => el('li', {},
            el('a', { href: '#' + x.page, 'data-page': x.page }, el('span', {}, x.what), icon('arrow-right', 'icon--xs')),
            x.detail ? el('span', { class: 'st-links__detail' }, x.detail) : null)))) : null));
  }

  async function resetEverything() {
    const n = ((S.view.settings_file || {}).keys || []).length;
    const ok = await caseConfirm({
      title: n === 1 ? 'Reset the setting changed here?' : `Reset all ${n} settings changed here?`,
      text: `They go back to the values in ${SOURCE_FILE}, or the defaults. Settings that need a restart wait for one.`,
      confirm: 'Reset all',
    });
    if (!ok) { const b = $('st-reset-all'); if (b) b.focus(); return; }
    await resetAllNow('Nothing was reset');
  }

  // startNewFile replaces a settings file that can't be read with an
  // empty one; the server keeps the old one next to it.
  async function startNewFile(btn) {
    const file = S.view.settings_file || {};
    const ok = await caseConfirm({
      title: 'Start a new settings file?',
      text: `Every setting saved on this page is removed, including passwords. The current file is kept as ${file.backup || 'a copy next to it'}. To keep the settings, fix the file on the server instead.`,
      confirm: 'Start a new file',
    });
    if (!ok) { if (btn) btn.focus(); return; }
    await resetAllNow('No new file was started');
  }

  async function resetAllNow(failTitle) {
    let v;
    try {
      v = await api('api/settings', { reset_all: true }, 'PUT');
    } catch (e) {
      if (e.code !== 'forbidden') toastError(failTitle, e);
      return;
    }
    S.view = v;
    S.drafts = {};
    S.replacing = {};
    S.saveErr = null;
    render();
    if (v.backup) {
      toast('The old one is kept as ' + v.backup + '.', null, { title: 'New settings file' });
      return;
    }
    toast((v.after_restart || []).length ? 'Some changes wait for a restart.' : 'Every setting is back to ' + SOURCE_FILE + ' or its default.', null, { title: 'Reset' });
  }

  // ---------- the top of the page: problems and the restart ----------
  function renderAlerts() {
    const v = S.view;
    const out = [];
    const file = v.settings_file || {};
    if (file.error) {
      // One note with both ways out; the startup note would only repeat it.
      const btn = el('button', { type: 'button', class: 'btn btn--secondary btn--sm', onclick: () => startNewFile(btn) }, 'Start a new file');
      out.push(dxAlert('danger', 'The settings file can’t be read', file.error, el('div', { class: 'st-alert-more' },
        el('p', {}, 'Fix ', el('span', { class: 'mono' }, file.path), ' on the server and reload this page, or start a new file. Nothing can be changed here until then.'),
        el('div', { class: 'btn-row st-alert-actions' }, btn))));
    }
    // A file that couldn't be read at the start has its own note while it
    // still can't be; once fixed or new, the restart banner says the rest.
    if (v.startup_problem && !v.startup_file) {
      out.push(dxAlert('warning', 'Signalith started without the settings saved here', v.startup_problem, settingLink(startupBlame()[0])));
    }
    if (!v.editable) out.push(dxAlert('info', 'These settings can’t be changed here', 'This server was started without a configuration file. Start it with one (signalith serve -c signalith.yaml) to change settings on this page.'));
    if ((v.problems || []).length) {
      out.push(dxAlert('danger', SOURCE_FILE + ' has problems', 'Fix them in the file on the server, then restart Signalith.',
        el('ul', { class: 'st-problems' }, ...v.problems.map((p) => el('li', {}, sentence(p))))));
    }
    // Changes a restart set aside: each setting says why.
    const refused = (v.refused || []).filter((x) => S.fields[x.key]);
    if (refused.length && !S.restart) {
      const one = refused.length === 1 ? refused[0] : null;
      out.push(dxAlert('warning', one ? `${shortName(one.key)}: the change was set aside` : `Changes set aside: ${listWords(refused.map((x) => shortName(x.key)))}`,
        one ? sentence(one.reason) + ' Try it again, change it or remove it.'
          : 'A restart couldn’t use them, so Signalith uses the settings from before. Each one says why.',
        settingLink(refused[0].key)));
    }
    for (const w of v.warnings || []) out.push(dxAlert('warning', sentence(w)));
    const banner = restartBanner();
    if (banner) out.push(banner);
    fill($('st-alerts'), ...out);
    syncRestartButton();
  }

  // changedSince reports whether a setting was saved again after at.
  function changedSince(key, at) {
    const f = S.fields[key];
    return !!(f && f.source.kind === 'page' && f.source.at && Date.parse(f.source.at) > Date.parse(at));
  }
  const clock = (at) => new Date(at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  const pageAt = (addr) => String(addr).replace(/\/+$/, '') + '/#settings';

  function restartBanner() {
    const v = S.view;
    const r = v.restart || {};
    const pending = v.pending || [];
    const last = r.last;
    const st = S.restart;
    const box = (tone, ...kids) => el('div', { class: 'st-banner', 'data-tone': tone, id: 'st-restart', tabindex: '-1', role: 'region', 'aria-label': 'Restart' }, ...kids);
    const body = (...kids) => el('div', { class: 'st-banner__body' }, ...kids);
    const actions = (...kids) => el('div', { class: 'st-banner__actions' }, ...kids);
    if (st) return progressBanner(st, box, body, actions);
    // A move of the web page waits for someone to open it at the new address.
    if (r.awaiting) {
      const a = r.awaiting;
      return box('info', icon('globe'), body(
        el('b', {}, 'Open Signalith at its new address to keep it there'),
        el('p', {}, 'Signalith now answers at ', el('span', { class: 'mono' }, a.to), `. If nobody opens it there by ${clock(a.until)}, it goes back to `,
          el('span', { class: 'mono' }, a.from), '.')),
      actions(el('a', { class: 'btn btn--primary', href: pageAt(a.to) }, icon('external-link'), 'Open the new address')));
    }
    if (!pending.length) {
      if (S.restartErr) return box('danger', icon('circle-alert'), body(el('b', {}, 'Signalith didn’t restart'), el('p', {}, S.restartErr)));
      return null;
    }
    const keys = pending.map((p) => p.key);
    const names = keys.map(shortName);
    // The last restart failed on changes still waiting, unchanged since.
    const failed = !!(last && !last.ok && (last.keys || []).some((k) => keys.includes(k) && !changedSince(k, last.at)));
    // A restart refused for a setting it did not set aside fails the same
    // way again; one it set aside leaves the rest free to apply.
    const stuck = failed ? (last.problem_keys || []).filter((k) => keys.includes(k) && !changedSince(k, last.at)) : [];
    const retry = failed && (stuck.length > 0 || !(last.refused || []).length);
    const blame = startupBlame().filter((k) => keys.includes(k));
    const changes = el('details', { class: 'st-banner__details' }, el('summary', {}, pending.length === 1 ? 'What changes' : `What changes (${pending.length})`),
      el('ul', { class: 'st-changes', role: 'list' }, ...pending.map((p) => {
        const f = S.fields[p.key];
        return el('li', {}, el('span', { class: 'st-changes__name' }, shortName(p.key)), p.secret || !f
          ? el('span', { class: 'st-changes__val' }, 'changed')
          : el('span', { class: 'st-changes__val' }, el('span', { class: 'mono' }, show(f, p.old)), icon('arrow-right', 'icon--xs'), el('span', { class: 'mono' }, show(f, p.new))));
      })));
    const out = [];
    if (retry) {
      out.push(el('b', {}, last.rolled_back ? 'The restart went back to the previous settings' : 'The restart didn’t apply the changes'),
        el('p', {}, sentence(last.error)), el('p', { class: 'st-banner__meta' }, `Still waiting: ${listWords(names)}.`));
      const link = settingLink(stuck[0]);
      if (link) out.push(link);
    } else {
      out.push(el('b', {}, `Restart Signalith to apply: ${listWords(names)}`));
      // Browsers keep sign-ins over http:// and https:// apart.
      const flips = pending.some((p) => p.key === 'server.tls.mode' && (p.old === 'off') !== (p.new === 'off'));
      out.push(el('p', {}, r.available
        ? 'Saved changes wait for a restart. Signalith restarts in a few seconds' + (flips ? '; with HTTPS turned on or off, people sign in again.' : ' and everyone stays signed in.')
        : (r.unavailable || 'Restart Signalith on the server to apply them.')));
      // The note above links to it.
      if (blame.length) out.push(el('p', { class: 'st-banner__meta' }, `Change ${listWords(blame.map((k) => noun(shortName(k))))} first: Signalith couldn’t start with it.`));
    }
    if (S.restartErr) out.push(el('p', { class: 'st-banner__error' }, icon('circle-alert', 'icon--sm'), S.restartErr));
    if (r.blocked) out.push(el('p', { class: 'st-banner__error' }, icon('circle-alert', 'icon--sm'), r.blocked));
    if (r.available) out.push(el('p', { class: 'st-banner__error st-banner__dirty', id: 'st-restart-dirty', hidden: '' }, 'Save or discard the changes on this page first.'));
    out.push(changes);
    // The main button only when a restart can be expected to work.
    const weak = retry || blame.length > 0;
    const btn = r.available ? el('button', { type: 'button', class: 'btn ' + (weak ? 'btn--secondary' : 'btn--primary'), id: 'st-restart-now', 'data-weak': weak ? '1' : '' },
      icon('rotate-ccw'), retry ? 'Try again' : 'Restart now') : null;
    if (btn) btn.addEventListener('click', () => restartNow(btn));
    return box(retry ? 'warning' : 'info', icon(retry ? 'triangle-alert' : 'rotate-ccw'), body(...out), btn ? actions(btn) : null);
  }

  // progressBanner shows a restart under way, and what came of it when
  // the page cannot follow Signalith.
  function progressBanner(st, box, body, actions) {
    const away = st.goTo && origin(st.goTo) !== origin(location.href);
    if (st.down) {
      return box('danger', el('span', { class: 'st-spinner', 'aria-hidden': 'true' }), body(
        el('b', {}, 'Signalith couldn’t start'),
        el('p', {}, st.down + ' This page reloads when it is back.')));
    }
    if (st.timedOut) {
      const reload = el('button', { type: 'button', class: 'btn btn--secondary', onclick: () => location.reload() }, icon('refresh-cw'), 'Reload the page');
      if (away) {
        // HTTPS turned on or off, or a new port: this address may simply
        // not answer any more.
        return box('warning', icon('triangle-alert'), body(
          el('b', {}, 'Signalith doesn’t answer here'),
          el('p', {}, 'It may already be running at ', el('span', { class: 'mono' }, st.goTo), '. Open it there. If it doesn’t open, check Signalith on the server, for example with systemctl status signalith or docker compose logs signalith.')),
        actions(el('a', { class: 'btn btn--primary', href: pageAt(st.goTo) }, icon('external-link'), 'Open the new address'), reload));
      }
      return box('danger', icon('circle-alert'), body(
        el('b', {}, 'Signalith hasn’t come back yet'),
        el('p', {}, 'It has not answered for 90 seconds. Check it on the server, for example with systemctl status signalith or docker compose logs signalith. If a saved setting stops it from starting, run signalith settings reset there.')),
      actions(reload));
    }
    if (st.done && st.reachable === false) {
      return box('info', icon('circle-check'), body(
        el('b', {}, 'Signalith restarted'),
        el('p', {}, 'It now answers only on the server itself, at ', el('span', { class: 'mono' }, st.listen || st.goTo), '. This page stops working here in a few seconds.')));
    }
    let moving = null;
    if (st.goTo && st.reachable !== false) {
      // Browsers keep a sign-in made over http:// apart from https://.
      const signIn = new URL(st.goTo, location.href).protocol !== location.protocol ? ' You may need to sign in again there.' : '';
      moving = el('p', {}, 'Signalith moves to ', el('span', { class: 'mono' }, st.goTo), '. This page follows it there.' + signIn +
        ' If that address doesn’t open, come back here: Signalith goes back to this address after ' + Math.round((st.confirmIn || 120) / 60) + ' minutes.');
    }
    return box('progress', el('span', { class: 'st-spinner', 'aria-hidden': 'true' }), el('div', { class: 'st-banner__body', role: 'status' },
      el('b', {}, st.done ? (st.goTo ? 'Signalith is back. Opening the new address…' : 'Signalith is back. Reloading the page…') : st.external ? 'Signalith is restarting…' : 'Restarting Signalith…'),
      st.done ? null : el('p', {}, 'It checks the new settings first, and keeps the current ones if they can’t work. This usually takes a few seconds.'),
      moving, el('div', { class: 'st-progress', 'aria-hidden': 'true' }, el('span', {}))));
  }

  // The restart button waits for unsaved changes to be saved or discarded,
  // and is the page's main button only while there are none and a restart
  // can be expected to work.
  function syncRestartButton() {
    const btn = $('st-restart-now');
    if (!btn) return;
    const dirty = dirtyKeys().length > 0;
    const blocked = !!(S.view.restart && S.view.restart.blocked);
    btn.disabled = dirty || blocked;
    const main = !dirty && !btn.dataset.weak;
    btn.classList.toggle('btn--primary', main);
    btn.classList.toggle('btn--secondary', !main);
    const note = $('st-restart-dirty');
    if (note) note.hidden = !dirty;
  }

  async function restartNow(btn) {
    S.restartErr = '';
    const before = lastAt(S.view);
    let restore = busy(btn, 'Restarting…');
    let res;
    try {
      try {
        res = await api('api/settings/restart', S.localOK ? { local_only: true } : {});
      } catch (e) {
        if (e.code !== 'local_only') throw e;
        // The new address is one only the server itself reaches.
        restore();
        const ok = await caseConfirm({ title: 'Restart with an address only the server reaches?', text: sentence(e.message) + ' Use this only with a proxy on the same server.', confirm: 'Restart anyway' });
        if (!ok) { btn.focus(); return; }
        S.localOK = true;
        restore = busy(btn, 'Restarting…');
        res = await api('api/settings/restart', { local_only: true });
      }
    } catch (e) {
      restore();
      if (e.code === 'restarting') { watchRestart({ before, started: Date.now(), external: true }); return; }
      if (e.code === 'awaiting') { load(); return; }
      if (e.code !== 'forbidden') {
        S.restartErr = sentence(e.message);
        renderAlerts();
        const b = $('st-restart');
        if (b) b.focus();
      }
      return;
    }
    S.localOK = false;
    watchRestart({ before, started: Date.now(), goTo: res.go_to || '', reachable: res.reachable, listen: res.new_listen || '', confirmIn: res.confirm_within_s });
  }

  // follow opens the page at Signalith's new address, which tells
  // Signalith the move worked.
  function follow(st) {
    try { sessionStorage.setItem(RESTART_NOTE, '1'); } catch (_) { /* ignore */ }
    location.assign(st.goTo.replace(/[?#].*$/, '') + '?restarted=1#settings');
  }

  // watchRestart shows the restart under way and asks the server how it
  // went until it has finished: then the page reloads (at the new address
  // when the web address moved), or shows why the settings were kept.
  async function watchRestart(st) {
    S.restart = st;
    renderAlerts();
    const b = $('st-restart');
    if (b && !st.external) b.focus({ preventScroll: true });
    window.scrollTo({ top: 0 });
    let misses = 0;
    while (S.restart === st) {
      await sleep(1000);
      if (S.restart !== st) return;
      // While Signalith is down it keeps trying, and so does the page.
      if (!st.down && Date.now() - st.started > 90000) { st.timedOut = true; renderAlerts(); return; }
      let v;
      try {
        // Requests wait while the server switches; one that waits too
        // long is answered 503, which only means "ask again".
        v = await api('api/settings');
      } catch (e) {
        if (e.code === 'down') {
          if (!st.down) { st.down = sentence(e.message); renderAlerts(); }
          continue;
        }
        // 503 means a request waited too long while Signalith switched.
        if (e.status === 503) continue;
        // HTTPS turned on or off on the same port: this address stops
        // answering at once, so go to the new one and let it say how the
        // restart went.
        misses++;
        if (st.goTo && st.reachable !== false && origin(st.goTo) !== origin(location.href) && misses >= 5) {
          st.done = true;
          renderAlerts();
          follow(st);
          return;
        }
        continue;
      }
      misses = 0;
      if (st.down) { st.down = ''; st.external = true; }
      if (v.restart.in_progress || lastAt(v) === st.before) continue;
      const last = v.restart.last;
      if (last && last.ok && !st.external) {
        st.done = true;
        renderAlerts();
        if (st.reachable === false) return;
        // A move this very page confirmed (it asked through a reverse
        // proxy whose address stays the same) is already where it goes.
        if (st.goTo && !last.confirmed) follow(st);
        else {
          try { sessionStorage.setItem(RESTART_NOTE, '1'); } catch (_) { /* ignore */ }
          location.reload();
        }
        return;
      }
      S.restart = null;
      S.view = v;
      render();
      const banner = $('st-restart');
      if (banner && !st.external) banner.focus();
      if (last && last.ok && st.external) toast('Signalith restarted with the saved settings.', null, { title: 'Restarted' });
      return;
    }
  }
}());
