// Add data > Signalith Agent.
//
// One line per computer installs the Signalith Agent (api/agent/install):
// it downloads the agent install script from this server, checks its
// SHA-256 and runs it with an agent token on its standard input. The
// agent then fetches what to collect from Signalith, writes Fluent Bit's
// configuration and keeps Fluent Bit running, so nothing is configured by
// hand. The server address and the token field are the page's own (one
// token, purpose agent, for every computer installed from the line). The
// line holds the token placeholder until Copy, which makes the token
// (agentTokEnsure) and puts it in. After a copy, the card waits for the
// agent: it reads api/agents every 10 seconds, for up to 30 minutes, until
// an agent with the new token reports.
'use strict';

(function () {
  const WAIT_EVERY = 10000;
  const WAIT_FOR = 30 * 60 * 1000;
  const NEEDS = [
    ['server', 'A Linux computer', 'Ubuntu 22.04 or 24.04, Debian 12 or 13, RHEL, Rocky, Alma or Oracle Linux 8 or 9, or Amazon Linux 2023.'],
    ['globe', 'Outbound HTTPS', 'To Signalith, and to packages.fluentbit.io for Fluent Bit. Nothing has to reach the computer.'],
    ['refresh-cw', 'Nothing to edit later', 'The agent asks Signalith what to collect every few minutes and keeps Fluent Bit running.'],
  ];
  // S.data is the latest line as the server sent it, S.wait the wait for
  // the agent after a copy.
  const S = { data: null, seq: 0, error: null, wait: null };

  const card = $('agent-setup');
  const box = $('agent-install');
  $('agent-install-needs').replaceChildren(...NEEDS.map(([ic, title, text]) => el('li', {}, icon(ic), el('span', {}, el('b', {}, title), text))));
  pageHooks.push((name) => { if (name !== 'data') stopWait(); });

  // agentInstallSync is called by app.js each time the setup card loads:
  // it is true when the Signalith Agent is the source on screen, which
  // then loads its line instead of a configuration.
  window.agentInstallSync = function (on) {
    const was = card.dataset.agentInstall === 'on';
    if (on) card.dataset.agentInstall = 'on';
    else delete card.dataset.agentInstall;
    if (was !== on && agentTok.made && !agentTok.paste) agentTokMadeNote();
    if (!on) {
      stopWait();
      return false;
    }
    $('agent-title').textContent = 'Install the Signalith Agent';
    $('agent-sub').textContent = 'One line per computer installs the agent and Fluent Bit. Signalith then tells the agent what to collect, so there is no configuration file to edit.';
    load();
    return true;
  };

  // agentInstallActive is true while the Signalith Agent is on screen.
  window.agentInstallActive = () => card.dataset.agentInstall === 'on';

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
    const q = new URLSearchParams();
    if (server) q.set('server', server);
    try {
      const d = await api('api/agent/install?' + q);
      if (seq !== S.seq) return;
      S.data = d;
      S.error = null;
      agentNameAdd = d.add_name || '';
      agentServerError('');
      try {
        if (server && server !== agentServerGuess) localStorage.setItem(agentServerKey, server);
        else localStorage.removeItem(agentServerKey);
      } catch (_) { /* storage may be blocked */ }
    } catch (e) {
      if (seq !== S.seq) return;
      S.data = null;
      S.error = null;
      if (e.field === 'server') agentServerError(e.message);
      else S.error = e;
    } finally {
      if (seq === S.seq) box.removeAttribute('aria-busy');
    }
    if (seq === S.seq) render();
  }

  function skeleton() {
    const bar = (w) => el('span', { class: 'skeleton', style: 'width:' + w });
    box.replaceChildren(el('p', { class: 'sr-only' }, 'Making the line…'), bar('70%'), bar('90%'));
  }

  // agentInstallRender draws the line again, with the token once there is
  // one (app.js calls it when the token is made or dropped).
  window.agentInstallRender = render;

  function render() {
    if (!agentInstallActive()) return;
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
    const copyBtn = el('button', { class: 'btn btn--ghost btn--sm', type: 'button', id: 'agent-install-copy' }, icon('copy'), el('span', {}, 'Copy'));
    copyBtn.addEventListener('click', () => copyLine(copyBtn));
    const programs = d.programs || [];
    const missing = ['linux-amd64', 'linux-arm64'].filter((p) => !programs.includes(p));
    const noProgram = missing.length
      ? el('div', { class: 'alert', 'data-tone': 'warning', role: 'status' }, icon('triangle-alert'),
        el('div', {}, el('b', {}, missing.length === 2 ? 'This server has no agent program to hand out.' : 'This server has no agent program for ' + (missing[0] === 'linux-arm64' ? 'ARM' : 'x86') + ' computers.'),
          el('p', {}, 'Released versions of Signalith (packages, Docker image) carry them; a build from source does not. Until then, set up Fluent Bit by hand with the Linux option.')))
      : null;
    const ca = d.ca_sha256
      ? el('p', { class: 'hint' }, icon('fingerprint'), el('span', {}, 'The computer trusts Signalith’s certificate authority only if its fingerprint is ',
        el('span', { class: 'mono', title: d.ca_sha256 }, d.ca_sha256.slice(0, 16) + '…'), d.next_ca_sha256 ? ', or the next one’s while it is being switched.' : '.'))
      : null;
    // replaceChildren, unlike el, would show a null as the text "null".
    box.replaceChildren(...[
      noProgram,
      el('div', { class: 'agent-file sensor-line' },
        el('div', { class: 'agent-file__bar' }, icon('terminal'), el('span', { class: 'agent-file__name' }, 'Run on each computer, as a user who can use sudo'),
          el('span', { class: 'spacer' }), copyBtn),
        el('pre', { class: 'sensor-line__text', id: 'agent-install-line', tabindex: '0', 'aria-label': 'The line to run on each computer' }, ...agentTokShown(d.linux, true))),
      el('p', { class: 'hint' }, icon('info'), el('span', {}, d.note)),
      ca,
      el('p', { class: 'hint' }, icon('list-checks'), el('span', {}, 'It checks the computer and the token before it installs anything, and says what stopped it. Add ',
        el('code', {}, '--dry-run /tmp/agent'), ' to the end to see what it would change (it writes the files under that folder). Running it again is safe. ',
        el('a', { href: 'https://github.com/jrsamsanchez/Signalith/blob/main/docs/signalith-agent.md', target: '_blank', rel: 'noopener' }, 'Signalith Agent guide', icon('external-link', 'icon--xs')))),
      el('p', { class: 'hint' }, icon('monitor'), el('span', {}, 'Windows and macOS: the agent is coming to them next. Until then, use the Windows option to set up Fluent Bit.')),
      el('div', { id: 'agent-install-wait', role: 'status', 'aria-live': 'polite' })].filter(Boolean));
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
    const b = $('agent-install-copy') || btn;
    agentSetupCopy(line, b);
    startWait();
  }

  // ---------- waiting for the agent ----------
  // The wait ends when an agent with the token just made (or, for a pasted
  // token, any Signalith Agent first heard after the copy) reports, after
  // 30 minutes, or when the source or page changes.
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
    const a = list.find((x) => x.managed && (w.tokenID ? x.managed.token === w.tokenID
      : new Date(x.managed.received).getTime() >= w.from - 60000));
    if (!a) return;
    clearInterval(w.timer);
    w.found = a;
    drawWait();
  }

  function drawWait() {
    const slot = $('agent-install-wait');
    if (!slot) return;
    const w = S.wait;
    if (!w) return slot.replaceChildren();
    if (w.found) {
      const name = w.found.name || w.found.addresses[0] || 'The computer';
      const fb = (w.found.managed.components || []).find((c) => c.name === 'fluentbit');
      const ok = fb && fb.state === 'running';
      return slot.replaceChildren(el('div', { class: 'sj-live', 'data-state': ok ? 'ok' : 'warn' }, icon(ok ? 'circle-check' : 'triangle-alert'),
        el('div', {}, el('b', {}, ok ? name + ' is set up and sending.' : name + ' has the agent, but Fluent Bit is ' + (fb ? fb.state : 'not running') + '.'), ' ',
          el('a', { href: '#endpoints', 'data-page': 'endpoints' }, 'Open Endpoints', icon('arrow-right', 'icon--xs')))));
    }
    if (w.ended) {
      return slot.replaceChildren(el('div', { class: 'sj-live', 'data-state': 'warn' }, icon('triangle-alert'),
        el('div', {}, el('b', {}, 'No word from the agent in 30 minutes.'),
          ' The script says on the computer what stopped it. Fix that and run the line again: running it twice is safe.')));
    }
    slot.replaceChildren(el('div', { class: 'sj-live' }, el('span', { class: 'pulse', 'aria-hidden': 'true' }),
      el('div', {}, el('b', {}, 'Waiting for the agent…'), ' Run the line on the computer. Installing takes a minute or two; this updates when the agent reports.')));
  }
})();
