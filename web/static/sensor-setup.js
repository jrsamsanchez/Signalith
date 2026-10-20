// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0
// Add data > Network sensor > Set up a new sensor.
//
// The Network sensor option has two tabs: "I already run Zeek or
// Suricata" (the Fluent Bit configuration app.js builds) and "Set up a new
// sensor", here. The new-sensor tab shows what a sensor needs, a few
// options, and one line to run on a fresh Linux machine
// (api/sensor/install): it downloads the sensor install script, checks its
// SHA-256 and runs it with the sensor's agent token on its standard input.
// The server address, the token name and the Zeek and Suricata switches
// are the other tab's, so both tabs agree. The line holds the token
// placeholder until Copy, which makes the token (agentTokEnsure, purpose
// sensor) and puts it in, as copying a configuration does. After a copy,
// the tab waits for the sensor: it reads api/agents every 10 seconds, for
// up to 30 minutes, until an agent with the new token sends.
'use strict';

(function () {
  const WAIT_EVERY = 10000;
  const WAIT_FOR = 30 * 60 * 1000;
  const TAB_KEY = 'signalith.sensorTab';
  const NEEDS = [
    ['router', 'A copy of the traffic', 'A switch port set to mirror (SPAN) your uplink, or a network tap.'],
    ['network', 'Two network ports', 'One plugged into the mirror port, with no IP address, and one to reach Signalith.'],
    ['server', 'A Linux machine', 'Ubuntu Server 24.04 LTS is best: 4 cores, 8 GB memory and 50 GB free for a small office.'],
    ['globe', 'Outbound HTTPS', 'To Signalith, the package sites and rules.emergingthreats.net. Nothing has to reach the sensor.'],
  ];
  // S.tab is the tab on screen (have or new), S.data the latest line as
  // the server sent it, S.wait the wait for the sensor after a copy.
  const S = { tab: 'have', layout: 'packages', data: null, seq: 0, error: null, wait: null };
  try { if (localStorage.getItem(TAB_KEY) === 'new') S.tab = 'new'; } catch (_) { /* storage may be blocked */ }

  const card = $('agent-setup');
  const tabs = { have: $('sensor-tab-have'), new: $('sensor-tab-new') };
  const box = $('sensor-new');
  const ifaceEl = $('sensor-iface');
  const netsEl = $('sensor-networks');

  $('sensor-needs').replaceChildren(...NEEDS.map(([ic, title, text]) => el('li', {}, icon(ic), el('span', {}, el('b', {}, title), text))));

  Object.entries(tabs).forEach(([k, t]) => t.addEventListener('click', () => pick(k, false)));
  $('sensor-tabs').addEventListener('keydown', (ev) => {
    if (ev.key !== 'ArrowRight' && ev.key !== 'ArrowLeft') return;
    ev.preventDefault();
    pick(S.tab === 'have' ? 'new' : 'have', true);
  });
  $('sensor-new-link').addEventListener('click', (ev) => {
    ev.preventDefault();
    pick('new', true);
  });
  $('sensor-layout').addEventListener('click', (ev) => {
    const b = ev.target.closest('button[data-layout]');
    if (!b || b.dataset.layout === S.layout) return;
    S.layout = b.dataset.layout;
    $('sensor-layout').querySelectorAll('button').forEach((x) => x.setAttribute('aria-pressed', String(x === b)));
    loadAgentConfig();
  });
  let typing = 0;
  [ifaceEl, netsEl].forEach((n) => n.addEventListener('input', () => {
    clearTimeout(typing);
    typing = setTimeout(loadAgentConfig, 400);
  }));
  pageHooks.push((name) => { if (name !== 'data') stopWait(); });

  function pick(tab, focus) {
    if (tab === S.tab) return;
    S.tab = tab;
    try { localStorage.setItem(TAB_KEY, tab); } catch (_) { /* storage may be blocked */ }
    stopWait();
    loadAgentConfig();
    if (focus) tabs[tab].focus();
  }

  // sensorSetupSync is called by app.js each time the setup card loads:
  // it shows the tabs for the Network sensor option, and is true when the
  // new-sensor tab is on screen, which then loads its line instead of a
  // configuration.
  window.sensorSetupSync = function (sensor) {
    $('sensor-tabs').classList.toggle('hidden', !sensor);
    for (const [k, t] of Object.entries(tabs)) {
      t.setAttribute('aria-selected', String(k === S.tab));
      t.tabIndex = k === S.tab ? 0 : -1;
    }
    const on = sensor && S.tab === 'new';
    const was = card.dataset.sensorTab === 'new';
    if (on) card.dataset.sensorTab = 'new';
    else delete card.dataset.sensorTab;
    // the token note says where the token is: the line or the configuration
    if (was !== on && agentTok.made && !agentTok.paste) agentTokMadeNote();
    if (!on) {
      stopWait();
      return false;
    }
    $('agent-title').textContent = 'Set up a new network sensor';
    $('agent-sub').textContent = S.layout === 'docker'
      ? 'One line runs Zeek, Suricata and the agent on a fresh Linux machine with Docker, from their publishers’ official images.'
      : 'One line installs Zeek, Suricata and the agent on a fresh Linux machine, from their publishers’ signed packages.';
    load();
    return true;
  };

  // sensorSetupActive is true while the new-sensor tab is on screen.
  window.sensorSetupActive = () => card.dataset.sensorTab === 'new';

  async function load() {
    const seq = ++S.seq;
    box.setAttribute('aria-busy', 'true');
    if (!S.data && !S.error) skeleton();
    // The address starts as the one agents send to: the first answer of
    // api/agents/config says it.
    if (!agentServerValue()) {
      try {
        agentServerFirst(await api('api/agents/config?os=linux&source=file'));
      } catch (_) { /* the line's own answer says what is wrong */ }
      if (seq !== S.seq) return;
    }
    const server = agentServerValue();
    agentServerSent = server;
    const q = new URLSearchParams({
      zeek: $('sensor-zeek').checked, suricata: $('sensor-suricata').checked, protocols: $('sensor-protocols').checked,
      interface: ifaceEl.value.trim(), networks: netsEl.value.trim(), docker: S.layout === 'docker',
    });
    if (server) q.set('server', server);
    try {
      const d = await api('api/sensor/install?' + q);
      if (seq !== S.seq) return;
      S.data = d;
      S.error = null;
      agentNameAdd = d.add_name || '';
      agentServerError('');
      fieldError('');
      try {
        if (server && server !== agentServerGuess) localStorage.setItem(agentServerKey, server);
        else localStorage.removeItem(agentServerKey);
      } catch (_) { /* storage may be blocked */ }
    } catch (e) {
      if (seq !== S.seq) return;
      S.data = null;
      S.error = null;
      if (e.field === 'server') agentServerError(e.message);
      else if (['tools', 'interface', 'networks'].includes(e.field)) fieldError(e.field, e.message);
      else S.error = e;
    } finally {
      if (seq === S.seq) box.removeAttribute('aria-busy');
    }
    if (seq === S.seq) render();
  }

  // fieldError shows an option's error under it, or clears them all.
  function fieldError(field, msg) {
    sensorFieldError(field === 'tools' ? field : '', field === 'tools' ? msg : '');
    for (const [f, input] of [['interface', ifaceEl], ['networks', netsEl]]) {
      const on = f === field && msg;
      const err = $(input.id + '-error');
      err.replaceChildren(...(on ? [icon('circle-alert'), sentence(msg)] : []));
      err.classList.toggle('hidden', !on);
      if (on) input.setAttribute('aria-invalid', 'true');
      else input.removeAttribute('aria-invalid');
    }
  }

  function skeleton() {
    const bar = (w) => el('span', { class: 'skeleton', style: 'width:' + w });
    box.replaceChildren(el('p', { class: 'sr-only' }, 'Making the line…'), bar('70%'), bar('90%'));
  }

  // sensorSetupRender draws the line again, with the token once there is
  // one (app.js calls it when the token is made or dropped).
  window.sensorSetupRender = render;

  function render() {
    if (!sensorSetupActive()) return;
    if (S.error) {
      box.replaceChildren(el('div', { class: 'alert', 'data-tone': 'danger', role: 'alert' }, icon('circle-alert'),
        el('div', {}, el('b', {}, 'Couldn’t make the line.'), el('p', {}, sentence(S.error.message)))));
      return;
    }
    const d = S.data;
    if (!d) {
      box.replaceChildren();
      return;
    }
    const copyBtn = el('button', { class: 'btn btn--ghost btn--sm', type: 'button', id: 'sensor-copy' }, icon('copy'), el('span', {}, 'Copy'));
    copyBtn.addEventListener('click', () => copyLine(copyBtn));
    const ca = d.ca_sha256
      ? el('p', { class: 'hint' }, icon('fingerprint'), el('span', {}, 'The sensor trusts Signalith’s certificate authority only if its fingerprint is ',
        el('span', { class: 'mono', title: d.ca_sha256 }, d.ca_sha256.slice(0, 16) + '…'), d.next_ca_sha256 ? ', or the next one’s while it is being switched.' : '.'))
      : null;
    box.replaceChildren(
      el('div', { class: 'agent-file sensor-line' },
        el('div', { class: 'agent-file__bar' }, icon('terminal'), el('span', { class: 'agent-file__name' }, 'Run on the sensor, as a user who can use sudo'),
          el('span', { class: 'spacer' }), copyBtn),
        el('pre', { class: 'sensor-line__text', id: 'sensor-line', tabindex: '0', 'aria-label': 'The line to run on the sensor' }, ...agentTokShown(d.linux, true))),
      el('p', { class: 'hint' }, icon('info'), el('span', {}, d.note)),
      ca,
      el('p', { class: 'hint' }, icon('list-checks'), el('span', {}, 'It checks the machine first and lists what it found. Add ', el('code', {}, '--check-only'),
        ' to the end to only check, or ', el('code', {}, '--dry-run /tmp/sensor'), ' to see what it would change (it writes the files under that folder). ',
        el('a', { href: 'https://github.com/jrsamsanchez/Signalith/blob/main/docs/network-sensor.md', target: '_blank', rel: 'noopener' }, 'Network sensor guide', icon('external-link', 'icon--xs')))),
      el('div', { id: 'sensor-wait', role: 'status', 'aria-live': 'polite' }));
    drawWait();
  }

  async function copyLine(btn) {
    if (agentServerValue() !== agentServerSent || box.hasAttribute('aria-busy')) await load();
    if (!S.data || agentServerEl.getAttribute('aria-invalid') === 'true') {
      agentServerEl.focus();
      return;
    }
    if (!(await agentEnsureName())) return;
    if (agentTokNeeded(S.data.linux) && !(await agentTokEnsure())) return;
    const line = agentTokFill(S.data.linux);
    // agentTokEnsure drew the line again: copy with the new button
    const b = $('sensor-copy') || btn;
    agentSetupCopy(line, b);
    startWait();
  }

  // ---------- waiting for the sensor ----------
  // The wait ends when an agent with the token just made (or, for a
  // pasted token, any sensor first heard after the copy) sends its first
  // batch, after 30 minutes, or when the tab or page changes.
  function startWait() {
    stopWait();
    const w = { from: Date.now(), tokenID: agentTok.paste ? '' : (agentTok.made && agentTok.made.id) || '', found: null, timer: 0, ended: false };
    S.wait = w;
    w.timer = setInterval(() => poll(w), WAIT_EVERY);
    drawWait();
  }

  function stopWait() {
    if (S.wait) clearInterval(S.wait.timer);
    S.wait = null;
  }

  async function poll(w) {
    if (S.wait !== w || document.hidden) return;
    if (Date.now() - w.from > WAIT_FOR) {
      clearInterval(w.timer);
      w.ended = true;
      drawWait();
      return;
    }
    let list;
    try {
      list = ((await api('api/agents')) || {}).agents || [];
    } catch (_) {
      return; // asked again in 10 seconds
    }
    if (S.wait !== w) return;
    const a = list.find((x) => !x.refusing && (w.tokenID ? x.token_id === w.tokenID
      : (x.sensor || /^(zeek|suricata|sensor)(\.|$)/.test(x.tag || '')) && new Date(x.first_seen).getTime() >= w.from - 60000));
    if (!a) return;
    clearInterval(w.timer);
    w.found = a;
    drawWait();
  }

  function drawWait() {
    const slot = $('sensor-wait');
    if (!slot) return;
    const w = S.wait;
    if (!w) return slot.replaceChildren();
    if (w.found) {
      const name = w.found.name || w.found.addresses[0] || 'The sensor';
      return slot.replaceChildren(el('div', { class: 'sj-live', 'data-state': 'ok' }, icon('circle-check'),
        el('div', {}, el('b', {}, name + ' is sending.'), ' ',
          el('a', { href: '#endpoints', 'data-page': 'endpoints' }, 'Open Endpoints', icon('arrow-right', 'icon--xs')))));
    }
    if (w.ended) {
      return slot.replaceChildren(el('div', { class: 'sj-live', 'data-state': 'warn' }, icon('triangle-alert'),
        el('div', {}, el('b', {}, 'No word from the sensor in 30 minutes.'),
          ' The script says on the sensor what stopped it. Fix that and run the line again: running it twice is safe.')));
    }
    slot.replaceChildren(el('div', { class: 'sj-live' }, el('span', { class: 'pulse', 'aria-hidden': 'true' }),
      el('div', {}, el('b', {}, 'Waiting for the sensor…'), ' Run the line on it. Installing takes a few minutes; this updates when it sends.')));
  }
})();
