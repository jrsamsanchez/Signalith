// Settings > Network sensors (admins): each sensor that sends to
// Signalith, whether it is healthy and a checklist that says what to fix;
// the rule tuning every sensor with Suricata fetches (rules to turn off,
// limits and suppressions, and your own rules); and the sensor tokens.
// The sensor list follows the sensors every 30 seconds; the rule tuning
// is read once and again after a save, so drafts are never replaced.
'use strict';

(function () {
  const POLL_MS = 30000;
  const DAY = 86400000;
  const FIELDS = [
    {
      key: 'disable', label: 'Rules to turn off', file: 'disable.conf',
      hint: 'One per line: a rule’s SID (2013504), gid:sid, re:pattern, group:name or metadata:key value.',
      example: '# Noisy on our network\n2013504\nre:ET POLICY\ngroup:emerging-games.rules',
    },
    {
      key: 'threshold', label: 'Limits and suppressions', file: 'threshold.config',
      hint: 'One per line: suppress, threshold, event_filter or rate_filter, as in Suricata’s threshold.config.',
      example: '# The backup server scans on purpose\nsuppress gen_id 1, sig_id 2010935, track by_src, ip 10.0.5.20',
    },
    {
      key: 'local', label: 'Your own rules', file: 'local.rules',
      hint: 'One Suricata rule per line, each with a sid of its own, best from 1000000 to 1999999.',
      example: 'alert tls any any -> any any (msg:"Old TLS to the internet"; tls.version:1.0; sid:1000001; rev:1;)',
    },
  ];
  const NS = {
    data: null, loading: false, poll: null,
    tuning: null, tuningErr: '', drafts: {}, saving: false, saveErr: null, conflict: false,
    fieldEls: {}, built: false,
  };

  pageHooks.push((name) => {
    if (name !== 'sensors') {
      stopPoll();
      return;
    }
    if (!NS.built) build();
    load();
    if (!NS.tuning || !dirty()) loadTuning();
  });

  // ---------- loading ----------
  async function load() {
    if (NS.loading) return;
    NS.loading = true;
    stopPoll();
    try {
      NS.data = await api('api/sensors');
      $('ns-page').removeAttribute('aria-busy');
      renderSensors();
    } catch (e) {
      if (!NS.data) $('ns-list').replaceChildren(failed('Couldn’t load the sensors', e, load));
    } finally {
      NS.loading = false;
    }
    if (currentPage === 'sensors') NS.poll = setTimeout(load, POLL_MS);
  }

  function stopPoll() {
    clearTimeout(NS.poll);
    NS.poll = null;
  }

  async function loadTuning() {
    try {
      NS.tuning = await api('api/sensors/tuning');
      NS.tuningErr = '';
    } catch (e) {
      NS.tuningErr = e.message || 'The Signalith server did not respond.';
    }
    renderTuning(true);
  }

  // ---------- building ----------
  // build makes the page's three parts once: the sensors, the rule
  // tuning and the tokens. Polls redraw the first and the last only.
  function build() {
    NS.built = true;
    $('ns-page').replaceChildren(
      el('div', { id: 'ns-list', class: 'ns-list' }, skeleton()),
      tuningCard(),
      el('div', { id: 'ns-tokens' }));
  }

  function skeleton() {
    const bar = (w) => el('span', { class: 'skeleton', style: 'width:' + w });
    return el('div', { class: 'card ns-skel' }, ...['42%', '64%', '50%'].map((w) => el('div', { class: 'ns-skel__row' }, bar(w))));
  }

  function failed(title, e, retry) {
    return el('div', { class: 'card' }, el('div', { class: 'empty', 'data-tone': 'danger', role: 'alert' },
      el('span', { class: 'empty__icon' }, icon('circle-alert')),
      el('div', { class: 'empty__title' }, title),
      el('p', { class: 'empty__text' }, e.message || 'The Signalith server did not respond.'),
      el('div', { class: 'empty__actions' }, el('button', { class: 'btn btn--secondary btn--sm', type: 'button', onclick: retry }, icon('refresh-cw'), 'Try again'))));
  }

  // ---------- sensors ----------
  function renderSensors() {
    const d = NS.data;
    const sum = d.summary || {};
    const box = $('ns-list');
    if (!d.sensors.length) {
      box.replaceChildren(el('div', { class: 'card' }, el('div', { class: 'empty' },
        el('span', { class: 'empty__icon' }, icon('router')),
        el('div', { class: 'empty__title' }, 'No network sensors yet'),
        el('p', { class: 'empty__text' }, 'A sensor watches a mirror (SPAN) port with Zeek and Suricata and sends what it sees here. One install line sets it up, and it then shows here with a checklist.'),
        el('div', { class: 'empty__actions' }, el('a', { class: 'btn btn--primary btn--sm', href: '#data?source=sensor' }, icon('plus'), 'Add a sensor')))));
      renderTokens();
      return;
    }
    const kpis = el('div', { class: 'ns-kpis' },
      kpi('Sensors', sum.total, '', 'router', sum.with_suricata ? plural(sum.with_suricata, 'runs', 'run') + ' Suricata' : 'Zeek only'),
      kpi('Healthy', sum.healthy, sum.healthy ? 'success' : '', 'circle-check', 'Nothing to fix'),
      kpi('Need attention', sum.attention, sum.attention ? 'warning' : '', 'triangle-alert', 'Sending, with something to fix'),
      kpi('Silent', sum.silent, sum.silent ? 'danger' : '', 'circle-x', 'Nothing heard for ' + minutes(d.silent_after_sec)));
    box.replaceChildren(...[kpis,
      d.tuning_error ? el('div', { class: 'alert', 'data-tone': 'warning', role: 'status' }, icon('triangle-alert'),
        el('div', {}, 'Signalith could not compare the sensors’ rule tuning: ' + d.tuning_error + '.')) : null,
      el('h3', { class: 'sc-heading' }, plural(d.sensors.length, 'sensor', 'sensors'), el('span', { class: 'vs-muted' }, ' · worst first')),
      el('div', { class: 'ns-cards' }, ...d.sensors.map(sensorCard))].filter(Boolean));
    renderTokens();
    renderTuningMeta();
  }

  function kpi(label, value, tone, ic, foot) {
    const attrs = { class: 'card ns-kpi' };
    if (tone) attrs['data-tone'] = tone;
    if (!value) attrs['data-zero'] = '';
    return el('div', attrs,
      el('div', { class: 'ns-kpi__label' }, icon(ic), label),
      el('div', { class: 'ns-kpi__value num' }, (value || 0).toLocaleString()),
      el('div', { class: 'ns-kpi__foot' }, foot));
  }

  const plural = (n, one, many) => `${n.toLocaleString()} ${n === 1 ? one : many}`;
  const minutes = (sec) => plural(Math.round((sec || 900) / 60), 'minute', 'minutes');

  function silentSince(t) {
    const d = new Date(t);
    return Date.now() - d.getTime() < DAY ? d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : d.toLocaleDateString();
  }

  const STATE = {
    healthy: { label: 'Healthy', tone: 'success' },
    attention: { label: 'Needs attention', tone: 'warning' },
    silent: { label: 'Silent', tone: 'danger' },
  };

  function sensorCard(r) {
    const st = STATE[r.state] || STATE.attention;
    const label = r.state === 'silent' ? 'Silent since ' + silentSince(r.last_seen)
      : r.state === 'attention' ? (r.problems.length === 1 ? '1 thing to fix' : r.problems.length + ' things to fix') : st.label;
    const sub = ['Last heard ' + ago(r.last_seen), r.silent ? '' : plural(r.events_1h || 0, 'event', 'events') + ' in the last hour',
      (r.addresses || []).slice(0, 2).join(', ')].filter(Boolean).join(' · ');
    return el('article', { class: 'card sc-card ns-card', 'data-state': st.tone, 'data-key': r.key }, el('div', { class: 'card__body' },
      el('div', { class: 'sc-card__head' },
        el('span', { class: 'sc-card__icon' }, icon('router')),
        el('div', { class: 'sc-card__title' },
          el('div', { class: 'sc-card__name' }, el('h3', {}, r.name || 'Unnamed sensor')),
          el('p', { class: 'vs-muted' }, sub)),
        el('span', { class: 'badge badge--' + st.tone + ' sc-card__state' }, label)),
      facts(r),
      checklist(r)));
  }

  const gb = (b) => (b >= 1073741824 ? Math.round(b / 1073741824).toLocaleString() + ' GB' : Math.round(b / 1048576).toLocaleString() + ' MB');
  const toolText = (t) => (t ? [t.version, t.running ? 'running' : 'stopped'].filter(Boolean).join(', ') : '');

  function ageText(sec) {
    const h = Math.floor(sec / 3600);
    return h < 1 ? 'less than an hour' : h < 48 ? plural(h, 'hour', 'hours') : plural(Math.floor(h / 24), 'day', 'days');
  }

  function facts(r) {
    const s = r.status;
    const fact = (k, v) => (v ? [el('dt', {}, k), el('dd', {}, v)] : []);
    if (!s) {
      return el('dl', { class: 'ep-facts ns-facts' },
        ...fact('Sends', 'Zeek or Suricata logs, with no status line'),
        ...fact('Addresses', (r.addresses || []).join(', ')),
        ...fact('Agent token', r.token_name || 'Unknown'));
    }
    const rules = s.suricata ? [s.rules_count ? plural(s.rules_count, 'rule', 'rules') : 'No rules yet',
      r.rules_age_sec >= 0 ? 'updated ' + ageText(r.rules_age_sec) + ' ago' : '', s.rules_update === 'failed' ? 'the last update failed' : ''].filter(Boolean).join(', ') : '';
    const tc = (r.checks || []).find((c) => c.id === 'tuning');
    return el('dl', { class: 'ep-facts ns-facts' },
      ...fact('Zeek', toolText(s.zeek)),
      ...fact('Suricata', toolText(s.suricata)),
      ...fact('Capture port', [s.interface, s.link ? 'link ' + s.link : ''].filter(Boolean).join(', ')),
      ...fact('Packets', s.packets ? s.packets.toLocaleString() + ' received, ' + (s.drop_percent || 0) + '% dropped lately' : ''),
      ...fact('Disk free', (s.disk_free_percent || 0) + '%' + (s.disk_free_bytes ? ' (' + gb(s.disk_free_bytes) + ')' : '') + (s.disk_encrypted ? ', encrypted' : ', not encrypted')),
      ...fact('Suricata rules', rules),
      ...fact('Rule tuning', tc ? tuningFact(tc, s) : ''),
      ...fact('Installed with', [s.layout === 'docker' ? 'Docker' : s.layout === 'packages' ? 'Packages' : s.layout, s.version ? 'sensor script ' + s.version : ''].filter(Boolean).join(', ')),
      ...fact('Agent token', r.token_name || 'Unknown'));
  }

  function tuningFact(c, s) {
    const applied = Date.parse(s.tuning_applied || '');
    switch (c.state) {
      case 'current': return 'Up to date' + (isFinite(applied) ? ', applied ' + ago(applied) : '');
      case 'pending': return 'Fetching the tuning saved last';
      case 'failed': return 'The tuning saved last failed its test; it runs the one before';
      case 'stale': return 'Not the tuning saved last';
      case 'old_script': return 'Its install script cannot fetch tuning';
      case 'none': return 'None saved';
      default: return '';
    }
  }

  // ---------- the checklist ----------
  // Each check: [title when it passes, title when it fails, how bad a
  // failure is]. The fix text comes from sensorText (endpoints.js).
  const CHECK = {
    silent: ['Sending', 'Silent', 'fail'],
    no_status: ['', 'Sends no status line', 'info'],
    zeek_stopped: ['Zeek runs', 'Zeek is stopped', 'fail'],
    suricata_stopped: ['Suricata runs', 'Suricata is stopped', 'fail'],
    capture_link: ['The capture port’s link is up', 'The capture port’s link is down', 'fail'],
    capture_ip: ['The capture port only listens', 'The capture port has an IP address', 'warn'],
    no_traffic: ['Packets reach the capture port', 'No packets reach the capture port', 'warn'],
    drops: ['Drops few packets', 'Drops packets', 'warn'],
    disk_low: ['Enough free disk', 'The disk is almost full', 'fail'],
    rules_failed: ['Rules updates work', 'The rules update failed', 'fail'],
    rules_old: ['Rules are up to date', 'Rules are old', 'warn'],
    time_not_synced: ['The clock is synced', 'The clock is not synced', 'warn'],
  };
  const TUNING = {
    current: 'Runs the saved rule tuning',
    none: 'No rule tuning saved yet',
    unknown: 'Rule tuning not compared',
    pending: 'Fetching the new rule tuning',
    failed: 'The rule tuning failed its test',
    stale: 'Runs an old rule tuning',
    old_script: 'Can’t fetch rule tuning',
  };

  // checkView is a check as the list shows it: state (ok, info, warn or
  // fail), title and the plain fix.
  function checkView(c, r) {
    const s = r.status || {};
    if (c.id === 'tuning') {
      const title = TUNING[c.state] || 'Rule tuning';
      if (c.state === 'pending') return { state: 'info', title, text: 'Sensors fetch the tuning within 10 minutes of a save, and test it before they use it.' };
      if (c.ok) return { state: 'ok', title, text: '' };
      if (c.state === 'failed') return { state: 'fail', title, text: sensorText.warning('tuning_failed', { tuning_error: c.detail }) };
      if (c.state === 'old_script') {
        return { state: 'warn', title, text: 'It was installed before Signalith had rule tuning. Run the install line from Add data > Network sensor on it again: it keeps its settings and starts fetching the tuning.' };
      }
      return { state: 'warn', title, text: 'It has not fetched the tuning saved last' + (c.detail ? ' (' + c.detail + ')' : '') +
        '. On the sensor, see why with ' + sensorText.logsOf({}, 'signalith-sensor-tuning', 'suricata-update') + ', and check it reaches Signalith over HTTPS.' };
    }
    if (c.id === 'token') {
      if (c.ok) return { state: 'ok', title: 'Its agent token is active', text: '' };
      if (c.state === 'revoked') return { state: 'fail', title: 'Its agent token was revoked', text: 'Every server refuses what it sends. Make a new install line in Add data > Network sensor and run it on the sensor.' };
      return { state: 'warn', title: 'Its agent token is unknown', text: 'It sends with a token Signalith has no record of, such as the shared agent token. Make a new install line in Add data > Network sensor and run it on the sensor, so it has a sensor token of its own.' };
    }
    const k = CHECK[c.id] || [c.id, c.id, 'warn'];
    if (c.ok) return { state: 'ok', title: k[0] || c.id, text: '' };
    return { state: k[2], title: k[1], text: sensorText.warning(c.id, s) };
  }

  function checklist(r) {
    const views = (r.checks || []).map((c) => checkView(c, r));
    const shown = views.filter((v) => v.state !== 'ok');
    const passed = views.filter((v) => v.state === 'ok');
    return el('div', { class: 'ns-checks' },
      shown.length ? el('ul', { class: 'ns-checklist', role: 'list', 'aria-label': 'What to fix on ' + r.name }, ...shown.map(checkRow)) : null,
      passed.length ? el('details', { class: 'ns-pass' },
        el('summary', {}, icon('circle-check', 'icon--sm'), passed.length === 1 ? '1 check passes' : passed.length + ' checks pass', icon('chevron-down', 'icon--sm chev')),
        el('ul', { class: 'ns-checklist ns-checklist--ok', role: 'list' }, ...passed.map(checkRow))) : null);
  }

  const CHECK_ICON = { ok: 'check', info: 'info', warn: 'triangle-alert', fail: 'circle-alert' };
  function checkRow(v) {
    return el('li', { class: 'ns-check', 'data-state': v.state },
      el('span', { class: 'ns-check__icon' }, icon(CHECK_ICON[v.state])),
      el('div', { class: 'ns-check__text' }, el('b', {}, v.title), v.text ? el('p', {}, ...withCommands(v.text)) : null));
  }

  // withCommands sets the commands to run on the sensor ("sudo …") as
  // code, each with a copy button.
  function withCommands(text) {
    const out = [];
    let last = 0;
    for (const m of text.matchAll(/sudo [^,]+?(?=,|\.(?:\s|$)|$)/g)) {
      out.push(text.slice(last, m.index));
      const cmd = m[0];
      const btn = el('button', { class: 'btn btn--ghost btn--icon btn--sm ns-copy', type: 'button', 'aria-label': 'Copy ' + cmd, title: 'Copy' }, icon('copy', 'icon--xs'));
      btn.addEventListener('click', () => copy(cmd, btn));
      out.push(el('span', { class: 'ns-cmd' }, el('code', {}, cmd), btn));
      last = m.index + cmd.length;
    }
    out.push(text.slice(last));
    return out;
  }

  async function copy(text, btn) {
    let ok = false;
    try {
      await navigator.clipboard.writeText(text);
      ok = true;
    } catch (_) {
      const ta = el('textarea', { class: 'sr-only', readonly: '', 'aria-hidden': 'true' });
      ta.value = text;
      document.body.append(ta);
      ta.select();
      try { ok = document.execCommand('copy'); } catch (_) { ok = false; }
      ta.remove();
      btn.focus();
    }
    toast(ok ? 'Copied the command.' : 'Couldn’t copy. Select the command and press Ctrl+C.', null, ok ? {} : { tone: 'danger' });
  }

  // ---------- rule tuning ----------
  function tuningCard() {
    const fields = FIELDS.map((f) => {
      const id = 'ns-t-' + f.key;
      const ta = el('textarea', {
        id, class: 'textarea mono ns-tune__text', spellcheck: 'false', autocapitalize: 'off', autocomplete: 'off', wrap: 'off',
        rows: '8', placeholder: f.example, 'aria-describedby': id + '-hint ' + id + '-err',
      });
      const count = el('span', { class: 'ns-tune__count' });
      const err = el('div', { id: id + '-err', class: 'field-error hidden', role: 'alert' });
      ta.addEventListener('input', () => {
        const server = serverText(f.key);
        if (ta.value === server) delete NS.drafts[f.key];
        else NS.drafts[f.key] = ta.value;
        if (NS.saveErr && NS.saveErr.field === f.key) setSaveErr(null);
        syncTuning();
      });
      NS.fieldEls[f.key] = { ta, count, err };
      return el('div', { class: 'field ns-tune__field' },
        el('div', { class: 'label-row' }, el('label', { class: 'label', for: id }, f.label, ' ', el('span', { class: 'ns-tune__file mono' }, f.file)), count),
        el('p', { class: 'hint', id: id + '-hint' }, f.hint),
        ta, err);
    });
    const save = el('button', { id: 'ns-t-save', class: 'btn btn--primary', type: 'button', disabled: '' }, icon('save'), el('span', {}, 'Save rule tuning'));
    const discard = el('button', { id: 'ns-t-discard', class: 'btn btn--ghost', type: 'button', disabled: '' }, 'Discard changes');
    save.addEventListener('click', saveTuning);
    discard.addEventListener('click', () => {
      NS.drafts = {};
      setSaveErr(null);
      renderTuning(true);
    });
    return el('section', { class: 'card ns-tune', 'aria-labelledby': 'ns-t-title' },
      el('div', { class: 'card__head' }, el('div', {},
        el('h3', { class: 'card__title', id: 'ns-t-title' }, 'Rule tuning'),
        el('p', { class: 'card__sub' }, 'Every sensor with Suricata fetches this within 10 minutes, tests it with suricata-update and only then uses it. If the test fails, the sensor keeps the tuning it had and its card says why. Edits made by hand in /etc/suricata on a sensor still count.'))),
      el('div', { class: 'card__body ns-tune__body' },
        el('p', { id: 'ns-t-meta', class: 'ns-tune__meta' }),
        el('div', { id: 'ns-t-alert' }),
        ...fields,
        el('div', { id: 'ns-t-warn' }),
        el('div', { class: 'ns-tune__bar' }, el('span', { id: 'ns-t-state', class: 'ns-tune__state', role: 'status' }), discard, save)));
  }

  const serverText = (k) => (NS.tuning && NS.tuning.tuning ? NS.tuning.tuning[k] || '' : '');
  const dirty = () => Object.keys(NS.drafts).length > 0;
  const entries = (text) => text.split('\n').filter((l) => l.trim() && !l.trim().startsWith('#')).length;

  // renderTuning shows the tuning as last read. With reset, the boxes
  // take the server's text, except those with drafts.
  function renderTuning(reset) {
    if (!NS.built) return;
    const alert = $('ns-t-alert');
    if (NS.tuningErr && !NS.tuning) {
      alert.replaceChildren(el('div', { class: 'alert', 'data-tone': 'danger', role: 'alert' }, icon('circle-alert'),
        el('div', {}, el('b', {}, 'Couldn’t load the rule tuning. '), NS.tuningErr + ' ',
          el('button', { class: 'btn btn--secondary btn--sm', type: 'button', onclick: loadTuning }, 'Try again'))));
    } else if (NS.conflict) {
      const reload = el('button', { class: 'btn btn--secondary btn--sm', type: 'button' }, icon('refresh-cw'), 'Reload');
      reload.addEventListener('click', async () => {
        NS.conflict = false;
        await loadTuning();
      });
      alert.replaceChildren(el('div', { class: 'alert', 'data-tone': 'warning', role: 'alert' }, icon('triangle-alert'),
        el('div', { class: 'ns-tune__conflict' }, el('div', {}, el('b', {}, 'Someone else saved the rule tuning since you opened it. '),
          'Reload to see theirs: your changes stay in the boxes, so you can save them on top.'), reload)));
    } else {
      alert.replaceChildren();
    }
    for (const f of FIELDS) {
      const { ta } = NS.fieldEls[f.key];
      if (reset && !(f.key in NS.drafts)) ta.value = serverText(f.key);
      else if (f.key in NS.drafts && ta.value !== NS.drafts[f.key]) ta.value = NS.drafts[f.key];
      ta.disabled = !NS.tuning;
    }
    const warn = (NS.tuning && NS.tuning.warnings) || [];
    $('ns-t-warn').replaceChildren(...(warn.length ? [el('div', { class: 'alert', 'data-tone': 'info' }, icon('info'),
      el('div', {}, el('b', {}, 'Saved, with something to check:'), el('ul', { class: 'ns-tune__warn' }, ...warn.map((w) => el('li', {}, w)))))] : []));
    renderTuningMeta();
    syncTuning();
  }

  function renderTuningMeta() {
    const meta = $('ns-t-meta');
    if (!meta) return;
    const t = (NS.tuning && NS.tuning.saved !== undefined ? NS.tuning : NS.data && NS.data.tuning) || null;
    const sum = NS.data ? NS.data.summary : null;
    if (!t) {
      meta.replaceChildren();
      return;
    }
    const parts = [];
    if (t.saved) {
      parts.push(el('span', {}, 'Saved by ', el('b', {}, t.updated_by || 'an admin'), ', ' + ago(t.updated_at)));
      if (sum && sum.with_suricata) parts.push(el('span', {}, sum.running_tuning + ' of ' + plural(sum.with_suricata, 'sensor runs it', 'sensors run it')));
    } else {
      parts.push(el('span', {}, 'Nothing saved yet: sensors use their rules as they come.'));
    }
    meta.replaceChildren(icon('clock', 'icon--sm'), ...parts.flatMap((p, i) => (i ? [el('span', { class: 'ns-dot', 'aria-hidden': 'true' }, '·'), p] : [p])));
  }

  function syncTuning() {
    for (const f of FIELDS) {
      const { ta, count, err } = NS.fieldEls[f.key];
      const n = entries(ta.value);
      count.textContent = n === 1 ? '1 entry' : n.toLocaleString() + ' entries';
      const mine = NS.saveErr && NS.saveErr.field === f.key;
      ta.setAttribute('aria-invalid', mine ? 'true' : 'false');
      ta.classList.toggle('is-changed', f.key in NS.drafts);
      err.classList.toggle('hidden', !mine);
      err.replaceChildren(...(mine ? [icon('circle-alert'), el('span', {}, NS.saveErr.msg)] : []));
    }
    const d = dirty();
    $('ns-t-save').disabled = !d || NS.saving || !NS.tuning;
    $('ns-t-discard').disabled = !d || NS.saving;
    const st = $('ns-t-state');
    st.textContent = NS.saving ? 'Saving…' : d ? 'Not saved yet' : '';
  }

  function setSaveErr(e) {
    NS.saveErr = e;
    syncTuning();
  }

  async function saveTuning() {
    if (!dirty() || NS.saving) return;
    NS.saving = true;
    setSaveErr(null);
    const tuning = {};
    for (const f of FIELDS) tuning[f.key] = NS.fieldEls[f.key].ta.value;
    try {
      NS.tuning = await api('api/sensors/tuning', { tuning, version: NS.tuning.version }, 'PUT');
      NS.drafts = {};
      NS.conflict = false;
      NS.saving = false;
      renderTuning(true);
      toast('Sensors fetch it within 10 minutes and test it before they use it. Their cards say when they run it.', null, { title: 'Rule tuning saved' });
      load();
    } catch (e) {
      NS.saving = false;
      if (e.status === 409) {
        NS.conflict = true;
        renderTuning(false);
        $('ns-t-alert').scrollIntoView({ block: 'nearest' });
      } else if (e.status === 400 && e.field && NS.fieldEls[e.field]) {
        setSaveErr({ field: e.field, line: (e.data && e.data.line) || 0, msg: e.message });
        showLine(e.field, (e.data && e.data.line) || 0);
      } else {
        syncTuning();
        toast(e.message, null, { tone: 'danger', title: 'Couldn’t save the rule tuning' });
      }
    }
  }

  // showLine focuses a box and selects its line n (from 1).
  function showLine(key, n) {
    const ta = NS.fieldEls[key].ta;
    ta.scrollIntoView({ block: 'center' });
    ta.focus({ preventScroll: true });
    if (n < 1) return;
    const lines = ta.value.split('\n');
    let start = 0;
    for (let i = 0; i < n - 1 && i < lines.length; i++) start += lines[i].length + 1;
    const end = start + (lines[n - 1] || '').length;
    ta.setSelectionRange(start, end);
    const lh = parseFloat(getComputedStyle(ta).lineHeight) || 20;
    ta.scrollTop = Math.max(0, (n - 3) * lh);
  }

  // Leaving with unsaved tuning asks first, inside the app and out.
  leaveGuards.push((from, to, opts) => {
    if (from !== 'sensors' || !dirty()) return true;
    caseConfirm({
      title: 'Discard your rule tuning changes?',
      text: 'The rule tuning was changed but not saved. Leave this page without saving?',
      confirm: 'Discard changes',
    }).then((ok) => {
      if (!ok) { $('ns-t-save').focus(); return; }
      NS.drafts = {};
      NS.saveErr = null;
      renderTuning(true);
      showPage(to, Object.assign({}, opts, { force: true }));
    });
    return false;
  });
  window.addEventListener('beforeunload', (ev) => {
    if (dirty()) { ev.preventDefault(); ev.returnValue = ''; }
  });

  // ---------- sensor tokens ----------
  function renderTokens() {
    const d = NS.data;
    const box = $('ns-tokens');
    const list = (d.tokens || []).filter((t) => t.status !== 'revoked');
    const head = el('div', { class: 'card__head' }, el('div', {},
      el('h3', { class: 'card__title' }, 'Sensor tokens'),
      el('p', { class: 'card__sub' }, 'Each install line makes a token only a sensor can use: it sends events and its status, and fetches the rule tuning. Revoke the token of a sensor that is gone.')));
    let body;
    if (!d.tokens_loaded) {
      body = el('p', { class: 'ns-tokens__note vs-muted' }, 'The tokens could not be read yet. They show once this server has read them.');
    } else if (!list.length) {
      body = el('p', { class: 'ns-tokens__note vs-muted' }, 'No sensor tokens. Add data > Network sensor makes one with each install line.');
    } else {
      body = el('div', { class: 'table-wrap' }, el('table', { class: 'table ns-tokens__table' },
        el('thead', {}, el('tr', {}, el('th', {}, 'Token'), el('th', {}, 'Used by'), el('th', {}, 'Last used'), el('th', {}, 'Status'), el('th', {}, el('span', { class: 'sr-only' }, 'Actions')))),
        el('tbody', {}, ...list.map(tokenRow))));
    }
    box.replaceChildren(el('section', { class: 'card ns-tokens' }, head, body));
  }

  function tokenRow(t) {
    const used = Date.parse(t.last_used_at || '');
    const idle = !t.used_by.length && (!isFinite(used) || Date.now() - used > 30 * DAY);
    const revoke = el('button', { class: 'btn btn--ghost btn--sm', type: 'button' }, icon('ban'), 'Revoke');
    revoke.addEventListener('click', () => revokeToken(t));
    return el('tr', {},
      el('td', { 'data-label': 'Token' }, el('b', {}, t.name), t.hint ? el('div', { class: 'vs-muted mono ns-tokens__hint' }, '…' + t.hint) : null),
      el('td', { 'data-label': 'Used by' }, t.used_by.length ? t.used_by.join(', ') : el('span', { class: 'vs-muted' }, 'No sensor now')),
      el('td', { 'data-label': 'Last used' }, isFinite(used) ? ago(used) : 'Never'),
      el('td', { 'data-label': 'Status' }, idle ? el('span', { class: 'badge badge--warning', title: 'Not used for 30 days' }, 'Not used: revoke it if the sensor is gone')
        : el('span', { class: 'badge badge--success' }, 'Active')),
      el('td', { 'data-label': '', class: 'ns-tokens__act' }, revoke));
  }

  async function revokeToken(t) {
    const who = t.used_by.length ? t.used_by.join(', ') + (t.used_by.length === 1 ? ' stops' : ' stop') : 'Any sensor using it stops';
    const ok = await caseConfirm({
      title: `Revoke “${t.name}”?`,
      text: `${who} sending within seconds, on every server, and can no longer fetch the rule tuning. Events already stored stay. To bring a sensor back, run a new install line on it.`,
      confirm: 'Revoke token',
    });
    if (!ok) return;
    try {
      await api(`api/agent-tokens/${encodeURIComponent(t.id)}/revoke`, {});
      toast(`Revoked “${t.name}”.`);
    } catch (e) {
      toast(e.message, null, { tone: 'danger', title: 'Couldn’t revoke the token' });
    }
    load();
  }
}());
