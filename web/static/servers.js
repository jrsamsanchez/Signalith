// Servers page (admins): the Signalith servers that share this OpenSearch,
// and the one that runs the background jobs (detections, threat intel
// downloads and retention). It only shows; it is live while open, so a
// takeover shows up within seconds.
'use strict';

(function () {
  const REFRESH_MS = 5000;
  // The upgrade note, once dismissed, stays hidden in this browser.
  const NOTE_KEY = 'signalith.serversUpgradeNote';
  const S = { data: null, key: '', at: 0, tried: 0, busy: false, failed: false, ticker: null, seq: 0 };

  // [pulse state, label] for each server state from api/cluster.
  const STATE = {
    ready: ['', 'Running'],
    starting: ['idle', 'Starting'],
    stopping: ['idle', 'Stopping'],
    stopped: ['idle', 'Stopped'],
    offline: ['down', 'Not answering'],
    conflict: ['down', 'Identity in use'],
    // Or, when it was reached but didn't answer in time, osProblem's.
    unreachable: ['down', 'Can’t reach OpenSearch'],
    // Reached, but turned away: osProblem says how.
    refused: ['down', ''],
    down: ['down', 'Couldn’t start'],
  };
  const gone = (s) => s.state === 'offline' || s.state === 'stopped';
  const cap = (s) => (s ? s.charAt(0).toUpperCase() + s.slice(1) : s);

  pageHooks.push((name) => {
    // The banner on every other page says what this page says at length.
    meReady.then(renderClusterBanner);
    if (name !== 'servers') return;
    if (!S.ticker) S.ticker = setInterval(tick, 1000);
    load();
  });

  // tick updates the ages and the "updated Ns ago" line, and reloads
  // every few seconds; it stops when another page is open.
  function tick() {
    if (currentPage !== 'servers') {
      clearInterval(S.ticker);
      S.ticker = null;
      return;
    }
    if (document.hidden) return;
    ages();
    foot();
    if (S.data && Date.now() - S.tried >= REFRESH_MS) load(true);
  }

  async function load(quiet) {
    if (S.busy) return;
    if (!S.data && quiet !== true) skeleton();
    S.busy = true;
    S.tried = Date.now();
    const seq = ++S.seq;
    try {
      const d = await api('api/cluster');
      if (seq !== S.seq) return;
      S.data = d;
      S.at = Date.now();
      S.failed = false;
      render(d);
    } catch (e) {
      if (seq !== S.seq) return;
      S.failed = true;
      if (S.data) foot();
      else failed(e);
    } finally {
      S.busy = false;
    }
  }

  // ---------- small parts ----------
  function alertBox(tone, title, body) {
    const ic = { danger: 'circle-alert', warning: 'triangle-alert', info: 'info' }[tone];
    const attrs = { class: 'alert', 'data-tone': tone };
    if (tone === 'danger') attrs.role = 'alert';
    return el('div', attrs, icon(ic), el('div', {}, el('b', {}, title), body ? el('p', {}, ...linked(body)) : null));
  }

  // linked turns the names of pages into links, and sets commands as code.
  function linked(text) {
    const pages = { 'Data retention page': 'retention', 'Settings page': 'settings' };
    const parts = [];
    const re = new RegExp(Object.keys(pages).join('|'), 'g');
    let last = 0;
    let m;
    while ((m = re.exec(text))) {
      if (m.index > last) parts.push(...withCode(text.slice(last, m.index)));
      parts.push(el('a', { href: '#' + pages[m[0]], 'data-page': pages[m[0]] }, m[0]));
      last = re.lastIndex;
    }
    parts.push(...withCode(text.slice(last)));
    return parts;
  }

  // split makes a warning into a headline (its first sentence) and what it
  // means and what to do (the rest).
  function split(text) {
    const cut = text.indexOf('. ');
    return cut > 0 ? [text.slice(0, cut + 1), text.slice(cut + 2)] : [text, ''];
  }

  // Ages come from the server that answered, worked out by its own
  // clocks; they grow here until the next answer, so neither the other
  // servers' clocks nor this browser's need to be right.
  const age = (v) => v + Math.max(0, (Date.now() - S.at) / 1000);
  function agoText(sec) {
    if (sec < 60) return `${Math.max(1, Math.round(sec))}s ago`;
    if (sec < 3600) return Math.floor(sec / 60) + 'm ago';
    if (sec < 86400) return Math.floor(sec / 3600) + 'h ago';
    return Math.floor(sec / 86400) + 'd ago';
  }
  function upText(sec) {
    const n = (v, one, many) => `${v} ${v === 1 ? one : many}`;
    if (sec < 60) return 'Up less than a minute';
    if (sec < 3600) return 'Up ' + n(Math.floor(sec / 60), 'minute', 'minutes');
    if (sec < 86400) return 'Up ' + n(Math.floor(sec / 3600), 'hour', 'hours');
    return 'Up ' + n(Math.floor(sec / 86400), 'day', 'days');
  }
  const AGE = { seen: (sec) => 'Last seen ' + agoText(sec), stopped: agoText, up: upText };
  // ageSpan is a text that ages() keeps up to date in place.
  const ageSpan = (kind, sec) => el('span', { 'data-age': kind, 'data-sec': String(sec) }, AGE[kind](age(sec)));
  function ages() {
    for (const n of document.querySelectorAll('#servers [data-age]')) {
      const t = AGE[n.dataset.age](age(Number(n.dataset.sec)));
      if (n.textContent !== t) n.textContent = t;
    }
  }

  // clockOff says how far a server's clock is off OpenSearch's, only
  // when that matters: more than 2 seconds.
  function clockOff(s) {
    const ms = s.clock_offset_ms;
    if (ms == null || gone(s) || Math.abs(ms) <= 2000) return '';
    return `Clock ${(Math.abs(ms) / 1000).toFixed(1)} s ${ms > 0 ? 'behind' : 'ahead'}`;
  }

  const none = () => el('span', { class: 'sv-none' }, el('span', { 'aria-hidden': 'true' }, '–'), el('span', { class: 'sr-only' }, 'None'));

  // ---------- the list ----------
  function serverCell(s) {
    const addr = s.node_url || s.listen || '';
    return el('td', { 'data-col': 'server' },
      el('div', { class: 'sv-server' },
        el('span', { class: 'sv-server__icon' }, icon('server')),
        el('div', { class: 'sv-server__text' },
          el('div', { class: 'sv-server__name' }, el('span', { title: s.name }, s.name),
            s.self ? el('span', { class: 'badge badge--outline', title: 'The server that answered this page' }, 'This server') : null),
          addr ? el('div', { class: 'sv-server__addr mono', title: addr }, addr) : null)));
  }

  function statusCell(s) {
    const [state, named] = STATE[s.state] || ['idle', cap(s.state)];
    const problem = (s.opensearch || {}).problem;
    const label = s.state === 'refused' || (s.state === 'unreachable' && problem === 'timeout') ? osProblem(problem)[0] : named;
    const pulse = el('span', { class: 'pulse', 'aria-hidden': 'true' });
    if (state) pulse.dataset.state = state;
    const seenAgo = s.seen_seconds_ago;
    let head = el('span', { class: 'sv-state' }, pulse, label);
    let sub = null;
    if (s.state === 'stopped' && seenAgo != null) {
      // Stopped on purpose: no fault, so just when.
      head = el('span', { class: 'sv-state' }, pulse, 'Stopped ', ageSpan('stopped', seenAgo));
      sub = el('div', { class: 'sv-sub' }, 'Leaves this list 7 days after it stopped');
    } else if (s.state === 'offline' && seenAgo != null) {
      sub = el('div', { class: 'sv-sub', title: s.offline_since ? new Date(s.offline_since).toLocaleString() : '' }, ageSpan('seen', seenAgo));
    } else if (s.state === 'down') {
      sub = el('div', { class: 'sv-sub' }, 'Receives nothing and tries again every 30 seconds');
    } else if ((s.state === 'ready' || s.state === 'unreachable' || s.state === 'refused') && s.uptime_seconds != null) {
      sub = el('div', { class: 'sv-sub', title: s.started_at ? 'Started ' + new Date(s.started_at).toLocaleString() : '' }, ageSpan('up', s.uptime_seconds));
    }
    const clock = clockOff(s);
    return el('td', { 'data-col': 'status' }, head, sub,
      clock ? el('div', { class: 'sv-sub sv-warn', title: 'Keep every server’s clock in sync with NTP' }, icon('clock', 'icon--sm'), clock) : null);
  }

  function jobsCell(s, d) {
    const lease = d.lease || {};
    let body;
    if (s.jobs === 'runs' && lease.frozen) {
      body = [el('span', { class: 'badge badge--warning', title: 'OpenSearch’s disk is full: only the disk guard runs' }, icon('hard-drive', 'icon--sm'), 'Disk guard only')];
    } else if (s.jobs === 'runs') {
      body = [el('span', { class: 'badge badge--accent' }, icon('zap', 'icon--sm'), 'Runs jobs')];
    } else if (s.jobs === 'standby') {
      body = [el('span', { class: 'sv-standby' }, 'Standby')];
      const runner = (d.servers || []).find((x) => x.jobs === 'runs');
      if (s.cannot_take_over) {
        body.push(el('div', { class: 'sv-sub sv-warn' }, icon('triangle-alert', 'icon--sm'), el('span', {}, 'Won’t take over: ' + s.cannot_take_over)));
      } else if (runner) {
        body.push(el('div', { class: 'sv-sub' }, `Takes over if ${runner.name} stops`));
      } else if (s.state === 'ready') {
        body.push(el('div', { class: 'sv-sub' }, 'Takes them over within a minute'));
      }
    } else if (gone(s)) {
      body = [none()];
    } else {
      body = [el('span', { class: 'sv-standby' }, 'Doesn’t run them')];
      let why = s.not_eligible || '';
      if (/^detections\.scheduler is off/.test(why)) why = 'Run detections on schedule is off';
      if (why) body.push(el('div', { class: 'sv-sub' }, cap(why)));
    }
    return el('td', { 'data-col': 'jobs' }, ...body);
  }

  function row(s, d) {
    const attrs = { 'data-server': s.node_id || s.name };
    if (gone(s)) attrs.class = 'sv-gone';
    return el('tr', attrs, serverCell(s), statusCell(s), jobsCell(s, d),
      el('td', { 'data-col': 'version' }, s.version ? el('span', { class: 'mono' }, s.version) : none()));
  }

  function table(rows, busy) {
    return el('table', { class: 'table sv-table', 'aria-busy': String(!!busy) },
      el('thead', {}, el('tr', {},
        el('th', { scope: 'col', 'data-col': 'server' }, 'Server'),
        el('th', { scope: 'col', 'data-col': 'status' }, 'Status'),
        el('th', { scope: 'col', 'data-col': 'jobs' }, 'Background jobs'),
        el('th', { scope: 'col', 'data-col': 'version' }, 'Version'))),
      el('tbody', {}, ...rows));
  }

  // alerts says what needs a look, red for problems and amber for
  // attention: this server's warnings, which name the fix, then what the
  // other running servers report about themselves.
  function alerts(d, servers) {
    const out = [];
    const lease = d.lease || {};
    for (const w of d.warnings || []) {
      const [title, body] = split(w.text);
      out.push(alertBox(w.level === 'red' ? 'danger' : 'warning', title, body));
    }
    if (lease.frozen && !d.writes_refused) out.push(diskAlert(lease));
    for (const s of servers) {
      if (s.self || gone(s)) continue;
      for (const p of s.problems || []) {
        const [title, body] = split(p);
        out.push(alertBox('warning', `${s.name}: ${title}`, body));
      }
    }
    return out;
  }
  function diskAlert(lease) {
    const who = lease.holder_name;
    return alertBox('danger', 'OpenSearch’s disk is full, so it refuses new events.',
      (who ? `${who} keeps only the disk guard running: unless it was turned off on the Data retention page, it deletes the oldest days to make room. ` : '') +
      'New events are stored again by themselves once there is room. To make room sooner, give OpenSearch more disk.');
  }

  // summary is the line under the list's title: who runs the jobs, and
  // OpenSearch's state.
  function summary(d, servers) {
    const parts = [];
    const lease = d.lease || {};
    const full = d.writes_refused || lease.frozen;
    const runner = servers.find((s) => s.jobs === 'runs');
    if (runner && full) parts.push(`Only the disk guard runs, on ${runner.name}`);
    else if (runner) parts.push(`Jobs run on ${runner.name}`);
    else parts.push('No server runs the jobs right now');
    const down = servers.filter((s) => s.state === 'offline').length;
    if (down) parts.push(`${down} not answering`);
    const failed = servers.filter((s) => s.state === 'down').length;
    if (failed) parts.push(`${failed} couldn’t start`);
    const live = servers.filter((s) => !gone(s));
    const versions = [...new Set(live.filter((s) => s.version).map((s) => s.version))];
    if (live.length > 1 && versions.length === 1) parts.push('all on ' + versions[0]);
    const os = d.opensearch || {};
    if (full) parts.push('OpenSearch refuses writes (disk full)');
    else if (os.status === 'unreachable' && os.problem !== 'timeout') parts.push('OpenSearch can’t be reached');
    else if (os.status) parts.push(osTitle(os));
    return parts.join(' · ');
  }

  // Servers that stopped come last: they leave the list after a week.
  const ordered = (servers) => [...servers.filter((s) => s.state !== 'stopped'), ...servers.filter((s) => s.state === 'stopped')];

  function noteHidden() {
    try { return localStorage.getItem(NOTE_KEY) === 'hidden'; } catch (_) { return false; }
  }

  // upgradeNote is for servers set up by hand: an older version writes no
  // heartbeat, so it is not in the list, and does not take turns, so it
  // would run the jobs a second time. Shown until dismissed.
  function upgradeNote() {
    if (noteHidden()) return null;
    const close = el('button', { class: 'btn btn--ghost btn--icon btn--sm sv-note__close', type: 'button', 'aria-label': 'Dismiss this note', title: 'Dismiss' }, icon('x'));
    close.addEventListener('click', () => {
      try { localStorage.setItem(NOTE_KEY, 'hidden'); } catch (_) { /* storage may be blocked */ }
      const note = close.closest('.sv-note');
      if (note) note.remove();
      S.key = '';
    });
    return el('div', { class: 'callout sv-note' }, icon('info'), el('div', {},
      el('b', {}, 'Upgrading servers you set up by hand? '),
      'Servers that run an older version of Signalith aren’t listed here, and they don’t take turns: they would run detections, threat intel downloads and retention a second time. Upgrade them all together, or first turn off ',
      el('i', {}, 'Run detections on schedule'), ' (detections.scheduler: false) on the ones you haven’t upgraded yet.'), close);
  }

  // view is what the page shows, without the times that change on every
  // answer, so the page is rebuilt only when it changes, and focus and
  // selection survive the refresh. The ages change in place.
  function view(d, servers) {
    const lease = d.lease || {};
    return JSON.stringify([d.warnings, d.writes_refused, lease.frozen, lease.holder_name, (d.opensearch || {}).status, (d.opensearch || {}).problem, noteHidden(),
      servers.map((s) => [s.node_id, s.name, s.self, s.state, (s.opensearch || {}).problem, s.jobs, s.version, s.node_url, s.listen, s.cannot_take_over, s.not_eligible,
        clockOff(s), s.problems, s.seen_seconds_ago == null, s.uptime_seconds == null])]);
  }

  function render(d) {
    const servers = ordered(d.servers || []);
    const key = view(d, servers);
    if (key === S.key) {
      // The same page: only the ages move, from the new answer.
      for (const s of servers) {
        const n = document.querySelector(`#servers tr[data-server="${CSS.escape(s.node_id || s.name)}"] [data-age]`);
        if (n) n.dataset.sec = String(n.dataset.age === 'up' ? s.uptime_seconds : s.seen_seconds_ago);
      }
      ages();
      foot();
      return;
    }
    S.key = key;
    const box = $('servers');
    box.removeAttribute('aria-busy');
    const parts = [];
    const al = alerts(d, servers);
    if (al.length) parts.push(el('div', { class: 'sv-alerts' }, ...al));

    const n = servers.filter((s) => s.state !== 'stopped').length;
    const card = el('div', { class: 'card sv-card' },
      el('div', { class: 'card__head' }, el('div', {},
        el('h3', { class: 'card__title' }, n === 1 ? '1 server' : `${n} servers`),
        el('p', { class: 'card__sub' }, summary(d, servers)))),
      el('div', { class: 'table-wrap' }, table(servers.map((s) => row(s, d)))),
      el('div', { class: 'table-foot' }, el('span', { class: 'live', id: 'servers-live' })));
    parts.push(card);
    const note = upgradeNote();
    if (note) parts.push(note);
    box.replaceChildren(...parts);
    foot();
  }

  // foot says when the list was last read.
  function foot() {
    const live = $('servers-live');
    if (!live || !S.at) return;
    const s = Math.max(0, Math.round((Date.now() - S.at) / 1000));
    const when = s < 5 ? 'just now' : s < 60 ? s + 's ago' : ago(S.at);
    const text = S.failed ? `Couldn’t refresh, retrying · updated ${when}` : `Live · updated ${when}`;
    if (live.dataset.text === text) return;
    live.dataset.text = text;
    const pulse = el('span', { class: 'pulse', 'aria-hidden': 'true' });
    if (S.failed) pulse.dataset.state = 'warn';
    live.replaceChildren(pulse, text);
  }

  function skeleton() {
    const bar = (w) => el('span', { class: 'skeleton', style: 'width:' + w });
    const r = () => el('tr', {}, el('td', { 'data-col': 'server' }, bar('140px')), el('td', { 'data-col': 'status' }, bar('80px')),
      el('td', { 'data-col': 'jobs' }, bar('90px')), el('td', { 'data-col': 'version' }, bar('48px')));
    const box = $('servers');
    S.key = '';
    box.setAttribute('aria-busy', 'true');
    box.replaceChildren(el('div', { class: 'card sv-card' },
      el('div', { class: 'card__head' }, el('div', {}, el('h3', { class: 'card__title' }, 'Servers'))),
      el('div', { class: 'table-wrap' }, table([r(), r()], true))));
  }

  function failed(e) {
    const box = $('servers');
    S.key = '';
    box.removeAttribute('aria-busy');
    box.replaceChildren(el('div', { class: 'card' }, el('div', { class: 'empty', 'data-tone': 'danger', role: 'alert' },
      el('span', { class: 'empty__icon' }, icon('circle-alert')),
      el('div', { class: 'empty__title' }, 'Couldn’t load the servers'),
      el('p', { class: 'empty__text' }, e.message || 'The Signalith server did not respond.'),
      el('div', { class: 'empty__actions' }, el('button', { class: 'btn btn--secondary btn--sm', type: 'button', onclick: () => load() }, icon('refresh-cw'), 'Try again')))));
  }
})();
