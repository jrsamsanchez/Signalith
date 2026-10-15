// Servers page: Add a server, and servers waiting for approval.
//
// Add a server opens a dialog that first asks what is being added: a
// cluster server, which shares the work; a vulnerability scanner, a
// server that joins the same way but only scans the networks picked for
// it (its join token gives it cluster.role scanner); or a network sensor,
// which is not a Signalith server and is set up on Add data instead.
// For a server, it then checks what the new one needs
// from this one (api/cluster/join/prepare): an OpenSearch it can reach
// with TLS and a sign-in, the ports, the version. When OpenSearch isn't
// ready, Prepare OpenSearch says what to change and why, for Docker, Linux
// and Windows, and saves the address new servers are given. Then it makes
// a join token (api/cluster/tokens) and shows the one line to run on the
// new computer, and follows it live: the token used, the new server
// started, and this server reaching it (api/cluster/servers/{id}/check).
//
// Servers that wait for approval (started with OpenSearch's settings but
// no token) show in a card under the list, each with its fingerprint and
// Approve.
'use strict';

(function () {
  const PENDING_MS = 10000;
  const WATCH_MS = 3000;
  const PLATFORMS = [
    { id: 'linux', label: 'Linux', icon: 'terminal' },
    { id: 'windows', label: 'Windows', icon: 'monitor' },
    { id: 'docker', label: 'Docker', icon: 'box' },
  ];
  // KINDS are what Add a server can add. A scanner joins like a cluster
  // server, with the role in its token; a sensor is set up on Add data.
  const KINDS = [
    { id: 'server', icon: 'server', title: 'Cluster server',
      text: 'Shares the work: takes events from agents, answers searches and takes over the background jobs if another server stops.',
      desc: 'Install Signalith on another computer and join it to these servers. It shares this OpenSearch and every setting, user and detection.',
      guide: 'https://signalith.io/docs/multi-server/' },
    { id: 'scanner', icon: 'radar', title: 'Vulnerability scanner',
      text: 'Sits inside a network zone, such as a plant floor or a lab, and scans it with Nmap. Never runs the background jobs.',
      desc: 'Install Signalith on a computer inside the network zone to scan. It joins these servers as a scanner: it scans only the networks you pick for it, and its results land here.',
      guide: 'https://signalith.io/docs/vulnerabilities/#scanning-each-network-zone-from-inside-it' },
    { id: 'sensor', icon: 'activity', title: 'Network sensor',
      text: 'Watches traffic on a mirror or SPAN port with Zeek and Suricata, and sends what it sees. Not a Signalith server.',
      desc: 'A network sensor sends what it sees on your network to Signalith. It is set up on Add data, with one line to run on the sensor.',
      guide: 'https://signalith.io/docs/network-sensor/' },
  ];
  const kindOf = (id) => KINDS.find((k) => k.id === id);
  // S.pending is the last api/cluster's pending servers; D is the open
  // dialog's state, and D.kind what it adds ('' until picked).
  const S = { pending: [], at: 0, busy: false, ticker: null, seq: 0, prepOK: null };
  const D = { kind: '', prep: null, failed: null, platform: '', prepTab: '', addr: '', token: null, made: null, used: null, check: null, watch: null, making: false };

  // h is el without the attributes that are null or false, so an
  // attribute such as disabled can be left out by its value.
  const h = (tag, attrs = {}, ...kids) => el(tag, Object.fromEntries(Object.entries(attrs).filter(([, v]) => v != null && v !== false)), ...kids);
  const plural = (n, one, many) => `${n} ${n === 1 ? one : many}`;
  const timeText = (t) => new Date(t).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

  pageHooks.push((name) => {
    if (name !== 'servers') return;
    addButton();
    if (!S.ticker) S.ticker = setInterval(tick, 1000);
    loadPending();
  });

  function tick() {
    if (currentPage !== 'servers') {
      clearInterval(S.ticker);
      S.ticker = null;
      return;
    }
    if (document.hidden) return;
    if (Date.now() - S.at >= PENDING_MS) loadPending();
  }

  // ---------- the button ----------
  // It shows once this server answers api/cluster/join/prepare, so a
  // server too old to add servers shows none.
  async function addButton() {
    const btn = $('sv-add');
    if (!btn || btn.dataset.wired) return;
    btn.dataset.wired = '1';
    btn.addEventListener('click', () => openDialog(''));
    try {
      D.prep = await api('api/cluster/join/prepare');
      btn.hidden = false;
    } catch (e) {
      if (e.status !== 404) btn.hidden = false;
    }
  }

  // ---------- waiting for approval ----------
  async function loadPending() {
    if (S.busy) return;
    S.busy = true;
    S.at = Date.now();
    const seq = ++S.seq;
    try {
      const d = await api('api/cluster');
      if (seq !== S.seq) return;
      S.pending = d.pending || [];
      if (D.token) follow(d);
    } catch (_) {
      // The list of servers says what is wrong.
    } finally {
      S.busy = false;
    }
    renderPending();
  }

  function renderPending() {
    const box = $('servers-join');
    if (!box) return;
    if (!S.pending.length) {
      box.replaceChildren();
      return;
    }
    const rows = S.pending.map((p) => h('li', { class: 'sj-pending__row' },
      h('span', { class: 'sj-pending__icon' }, icon('server')),
      h('div', { class: 'sj-pending__text' },
        h('div', { class: 'sj-pending__name' }, h('b', {}, p.name || p.node_id), p.version ? h('span', { class: 'badge badge--outline badge--mono' }, p.version) : null,
          p.os ? h('span', { class: 'sj-muted' }, [p.os, p.arch].filter(Boolean).join(' ')) : null),
        h('div', { class: 'sj-muted' }, 'Fingerprint ', h('span', { class: 'mono sj-fp' }, p.fingerprint || 'unknown'),
          p.requested_at ? ' · asked ' + ago(p.requested_at) : '', p.node_url ? ' · ' + p.node_url : '')),
      h('button', { type: 'button', class: 'btn btn--secondary btn--sm', onclick: () => approve(p) }, icon('user-check'), 'Approve…')));
    fill(box, h('div', { class: 'card sj-card' },
      h('div', { class: 'card__head' }, h('div', {},
        h('h3', { class: 'card__title' }, plural(S.pending.length, 'server waits', 'servers wait') + ' to join'),
        h('p', { class: 'card__sub' }, 'Each one reaches this OpenSearch but has no cluster key yet. Approve only a server you set up: compare its fingerprint first.'))),
      h('ul', { class: 'sj-pending', role: 'list' }, ...rows)));
  }

  // approve asks the admin to compare the fingerprint the new server
  // shows (on its sign-in page and in its log) before it gets the key.
  function approve(p) {
    const d = modalDialog('sj-approve');
    const match = h('input', { type: 'checkbox', id: 'sj-approve-match' });
    const err = formAlert();
    const ok = h('button', { type: 'button', class: 'btn btn--primary', disabled: '' }, icon('user-check'), 'Approve');
    match.addEventListener('change', () => { ok.disabled = !match.checked; });
    ok.addEventListener('click', async () => {
      const restore = busy(ok, 'Approving…');
      try {
        await api('api/cluster/servers/' + encodeURIComponent(p.node_id) + '/approve', { fingerprint: p.fingerprint }, 'POST');
        d.close();
        toast(`${p.name || 'The server'} was approved. It joins within a minute.`, null, { tone: 'success' });
        loadPending();
      } catch (e) {
        restore();
        showAlert(err, 'It was not approved', sentence(e.message));
      }
    });
    fill(d, modalHead('sj-approve', `Approve ${p.name || 'this server'}?`, 'It gets the cluster key: it can read and change every shared setting, user and detection.', () => d.close()),
      h('div', { class: 'modal__body' },
        h('p', {}, 'On the new server, its sign-in page and its log show a fingerprint. Approve it only if it is this one:'),
        h('div', { class: 'sj-fp-big mono' }, p.fingerprint || 'unknown'),
        h('label', { class: 'switch sj-match', for: 'sj-approve-match' }, match, h('span', {}, 'The new server shows the same fingerprint')),
        err),
      h('div', { class: 'modal__foot' }, h('button', { type: 'button', class: 'btn btn--ghost', onclick: () => d.close() }, 'Cancel'), ok));
    d.showModal();
    match.focus();
  }

  // openAddServer opens Add a server from another page, such as Settings
  // > Scanners, with what to add already picked (server or scanner).
  window.openAddServer = (kind) => {
    showPage('servers');
    if (currentPage === 'servers') openDialog(kind || '');
  };

  // ---------- the dialog ----------
  async function openDialog(kind) {
    Object.assign(D, { kind: kindOf(kind) ? kind : '', failed: null, token: null, made: null, used: null, check: null, making: false, tokenErr: '' });
    stopWatch();
    const d = modalDialog('sj-dialog');
    d.classList.add('sj-dialog');
    d.onclose = () => {
      stopWatch();
      // The line holds a secret: it is not kept once the dialog closes.
      D.token = null;
      D.made = null;
      const btn = $('sv-add');
      if (btn) btn.focus();
    };
    draw();
    if (!d.open) d.showModal();
    try {
      D.prep = await api('api/cluster/join/prepare');
    } catch (e) {
      D.failed = e;
    }
    if (!D.platform) D.platform = defaultPlatform(D.prep);
    if (!D.prepTab) D.prepTab = defaultPlatform(D.prep);
    if (!D.addr) D.addr = guessAddress(D.prep);
    draw();
  }

  function defaultPlatform(prep) {
    const dep = (prep && prep.deployment) || '';
    if (dep === 'docker') return 'docker';
    if (dep === 'windows-service' || (prep && prep.os === 'windows')) return 'windows';
    return 'linux';
  }

  // guessAddress is this computer's address on the network, from the
  // address agents use, unless that is this computer only.
  function guessAddress(prep) {
    for (const u of [prep && prep.node_url, prep && prep.public_url]) {
      try {
        const h = new URL(u).hostname;
        if (h && h !== 'localhost' && !h.startsWith('127.') && h !== '[::1]') return h;
      } catch (_) { /* not set */ }
    }
    return '';
  }

  function draw() {
    const d = $('sj-dialog');
    if (!d) return;
    const keep = d.contains(document.activeElement) ? document.activeElement.dataset.focus : '';
    const body = h('div', { class: 'modal__body sj-body' });
    const prep = D.prep;
    if (!prep && !D.failed) {
      const bar = (w) => h('span', { class: 'skeleton', style: 'width:' + w });
      body.setAttribute('aria-busy', 'true');
      body.append(h('p', { class: 'sr-only' }, 'Checking what a new server needs…'), bar('60%'), bar('90%'), bar('75%'));
    } else if (!prep) {
      body.append(alertBox('danger', 'Couldn’t check this server', sentence(D.failed.message)));
    } else if (D.kind === 'sensor') {
      body.append(h('ol', { class: 'sj-steps', role: 'list' },
        step(1, 'What are you adding?', kindPicker()),
        step(2, 'Set it up on Add data', sensorPanel())));
    } else if (!D.kind) {
      body.append(h('ol', { class: 'sj-steps', role: 'list' }, step(1, 'What are you adding?', kindPicker())));
    } else {
      const problems = (prep.opensearch && prep.opensearch.problems) || [];
      const what = D.kind === 'scanner' ? 'scanner' : 'server';
      body.append(h('ol', { class: 'sj-steps', role: 'list' },
        step(1, 'What are you adding?', kindPicker()),
        step(2, `Check what the new ${what} needs`, checks(prep, problems)),
        step(3, 'Choose where it runs', platformPicker(problems, prep)),
        D.made ? step(4, 'Run this on the new computer', line(prep)) : null,
        D.made ? step(5, 'Watch it join', watchLine()) : null));
    }
    const kind = kindOf(D.kind) || KINDS[0];
    fill(d, modalHead('sj-dialog', 'Add a server', D.kind ? kind.desc : 'Add another computer to Signalith: a server that shares the work, a scanner for a network zone, or a network sensor.', () => d.close()),
      body,
      h('div', { class: 'modal__foot' },
        h('a', { class: 'btn btn--ghost sj-docs', href: kind.guide, target: '_blank', rel: 'noopener' }, icon('book-open'), 'Guide'),
        h('span', { class: 'spacer' }),
        h('button', { type: 'button', class: 'btn ' + (D.used && D.check && D.check.result === 'ready' ? 'btn--primary' : 'btn--ghost'), 'data-focus': 'close', onclick: () => d.close() }, D.used ? 'Done' : 'Close')));
    const f = keep && d.querySelector(`[data-focus="${keep}"]`);
    if (f) f.focus();
  }

  function step(n, title, ...kids) {
    return h('li', { class: 'sj-step' }, h('span', { class: 'sj-step__num' }, n),
      h('div', { class: 'sj-step__body' }, h('h3', { class: 'sj-step__title' }, title), ...kids.flat().filter(Boolean)));
  }

  // ---------- step 1: what is being added ----------
  // Cards with real radios, as on Add data. Once the line is made, the
  // token holds the role, so the choice is locked.
  function kindPicker() {
    const locked = !!D.made;
    const cards = KINDS.map((k) => {
      const radio = h('input', { type: 'radio', name: 'sj-kind', value: k.id, 'data-focus': 'kind-' + k.id,
        checked: D.kind === k.id ? '' : null, disabled: locked && D.kind !== k.id ? '' : null });
      radio.addEventListener('change', () => {
        if (!radio.checked) return;
        D.kind = k.id;
        D.tokenErr = '';
        draw();
      });
      return h('label', { class: 'sj-kind', 'data-kind': k.id },
        h('span', { class: 'sj-kind__icon' }, icon(k.icon)),
        h('span', { class: 'sj-kind__text' }, h('b', {}, k.title), h('span', {}, k.text)),
        radio);
    });
    return [h('fieldset', { class: 'sj-kinds' }, h('legend', { class: 'sr-only' }, 'What are you adding?'), ...cards),
      locked ? h('p', { class: 'sj-muted' }, 'The line below adds a ' + (D.kind === 'scanner' ? 'scanner' : 'cluster server') + '. To add something else, close this and start again.') : null];
  }

  // sensorPanel says what a sensor is and takes the admin to its setup on
  // Add data > Network sensor > Set up a new sensor.
  function sensorPanel() {
    const go = h('button', { type: 'button', class: 'btn btn--primary', 'data-focus': 'sensor-go' }, icon('activity'), h('span', {}, 'Set up a sensor'));
    go.addEventListener('click', () => {
      const d = $('sj-dialog');
      if (d) d.close();
      if (typeof openSensorSetup === 'function') openSensorSetup();
      else showPage('data');
      const tab = $('sensor-tab-new');
      if (tab && tab.getAttribute('aria-selected') !== 'true') tab.click();
      const card = $('agent-setup');
      if (card) requestAnimationFrame(() => card.scrollIntoView({ block: 'start' }));
    });
    const item = (ic, title, why) => h('li', { class: 'sj-check', 'data-ok': 'info' }, icon(ic), h('div', {}, h('b', {}, title), h('p', {}, why)));
    return [
      h('p', {}, 'A sensor doesn’t join these servers and isn’t listed here: it sends events, like an agent. Add data makes the one line that installs it.'),
      h('ul', { class: 'sj-checks', role: 'list' },
        item('server', 'A small Linux computer or VM', 'Ubuntu, Debian, Rocky Linux or AlmaLinux, near the network to watch.'),
        item('network', 'A port that sees the traffic', 'A second network port connected to a switch’s mirror (SPAN) port or a network tap.'),
        item('globe', 'HTTPS to this server', 'It sends to Signalith over HTTPS, so nothing has to reach the sensor.')),
      h('div', { class: 'sj-make' }, go)];
  }

  function alertBox(tone, title, text) {
    const icons = { danger: 'circle-alert', warning: 'triangle-alert', success: 'circle-check', info: 'info' };
    return h('div', { class: 'alert', 'data-tone': tone, role: tone === 'danger' ? 'alert' : null }, icon(icons[tone] || 'info'),
      h('div', {}, h('b', {}, title), text ? h('p', {}, text) : null));
  }

  // ---------- step 1: the checks ----------
  function checks(prep, problems) {
    const os = prep.opensearch || {};
    const items = [];
    // ok is true, false, or 'info' for something to know.
    const item = (ok, title, why) => h('li', { class: 'sj-check', 'data-ok': ok === 'info' ? 'info' : ok ? 'yes' : 'no' },
      icon(ok === 'info' ? 'info' : ok ? 'circle-check' : 'circle-alert'), h('div', {}, h('b', {}, title), why ? h('p', {}, why) : null));
    if (problems.length) {
      items.push(item(false, 'OpenSearch isn’t ready for a second server', 'Every server keeps its events in this OpenSearch, so the new one must reach it over the network, over TLS, and sign in. ' + problems.map((p) => p.text).join(' ')));
    } else {
      items.push(item(true, 'OpenSearch is ready', `New servers use ${os.address}${os.auth === 'certificate' ? ' and sign in with a certificate' : os.auth === 'password' ? ' and sign in with a password' : ''}.`));
    }
    const ports = prep.ports || [];
    const toOS = ports.filter((p) => p.where === 'opensearch');
    const onNew = ports.filter((p) => p.where === 'new');
    const portText = (p) => `${p.proto.toUpperCase()} ${p.port} (${p.what})`;
    const scanner = D.kind === 'scanner';
    // A scanner takes no events: only its web port must be open, for the
    // other servers to check it.
    const web = onNew[0];
    items.push(item('info', 'Ports',
      (toOS.length ? `The new ${scanner ? 'scanner' : 'server'} connects to OpenSearch on TCP ${toOS[0].port}. ` : '') +
      (scanner ? (web ? `On the scanner, allow TCP ${web.port} from the other servers: they check it on its web port. Agents and devices don’t send to it.` : '')
        : onNew.length ? `On the new server, allow ${onNew.map(portText).join(', ')}: the other servers check it on its web port, and agents and devices send to it.` : '')));
    if (scanner) {
      items.push(item('info', 'Nmap', 'The scanner runs Nmap 7.80 or later. The Docker image has it, and the Linux packages install it when they can. On Windows, install it from nmap.org. Settings > Scanners checks it once the scanner joins.'));
    }
    items.push(item('info', `Signalith ${prep.version}`, 'Every server runs the same version. The line installs it, or checks the one already installed.'));
    if (!prep.pinnable) items.push(item(false, 'A token can’t name this server’s certificate', prep.pin_problem || ''));
    const list = h('ul', { class: 'sj-checks', role: 'list' }, ...items);
    return problems.length ? [list, prepare(prep, problems)] : [list];
  }

  // ---------- Prepare OpenSearch ----------
  function prepare(prep, problems) {
    const os = prep.opensearch || {};
    const codes = new Set(problems.map((p) => p.code));
    const addrInput = h('input', { class: 'input input--sm mono', type: 'text', id: 'sj-addr', 'data-focus': 'addr', value: D.addr, placeholder: '192.168.1.20',
      autocomplete: 'off', autocapitalize: 'off', spellcheck: 'false', inputmode: 'url', 'aria-describedby': 'sj-addr-hint' });
    addrInput.addEventListener('input', () => { D.addr = addrInput.value.trim(); redrawPrepare(); });
    const tabs = h('div', { class: 'tabs sj-tabs', role: 'tablist', 'aria-label': 'Where OpenSearch runs' },
      ...PLATFORMS.map((p) => h('button', { type: 'button', role: 'tab', class: 'tab', 'aria-selected': String(D.prepTab === p.id), 'data-focus': 'prep-' + p.id,
        onclick: () => { D.prepTab = p.id; draw(); } }, icon(p.icon), p.label)));
    const box = h('div', { class: 'sj-prep', id: 'sj-prep' },
      h('div', { class: 'sj-prep__head' }, icon('wand-sparkles'), h('div', {}, h('h4', {}, 'Prepare OpenSearch'),
        h('p', { class: 'sj-muted' }, 'Do this once, on the computer OpenSearch runs on. Nothing is reindexed, and this server keeps running.'))),
      h('div', { class: 'sj-field' }, h('label', { class: 'label', for: 'sj-addr' }, 'That computer’s address on the network'), addrInput,
        h('p', { class: 'sj-muted', id: 'sj-addr-hint' }, 'The address the new servers reach it at, such as its IP address or DNS name. It fills in the commands below.')),
      tabs,
      h('div', { id: 'sj-prep-steps' }, prepSteps(prep, codes)),
      saveAddress(os));
    return box;
  }

  function redrawPrepare() {
    const box = $('sj-prep-steps');
    if (!box || !D.prep) return;
    const codes = new Set(((D.prep.opensearch || {}).problems || []).map((p) => p.code));
    box.replaceChildren(prepSteps(D.prep, codes));
    const save = $('sj-os-url');
    if (save && !save.dataset.touched) save.value = osAddress(D.prep);
  }

  function osAddress(prep) {
    const os = prep.opensearch || {};
    let port = '9200';
    try { port = new URL(os.address).port || port; } catch (_) { /* default */ }
    return D.addr ? `https://${D.addr.includes(':') && !D.addr.startsWith('[') ? '[' + D.addr + ']' : D.addr}:${port}` : (os.address_set ? os.address : '');
  }

  function cmd(text, focus) {
    const btn = h('button', { type: 'button', class: 'btn btn--ghost btn--sm', 'data-focus': focus || '', 'aria-label': 'Copy' }, icon('copy'), h('span', {}, 'Copy'));
    btn.addEventListener('click', () => copy(text, btn));
    return h('div', { class: 'sj-cmd' }, h('code', {}, text), btn);
  }

  function prepSteps(prep, codes) {
    const a = D.addr || '<address>';
    const list = [];
    const s = (text, ...kids) => list.push(h('li', {}, h('p', {}, text), ...kids));
    const secure = codes.has('http') || codes.has('no_auth') || codes.has('skip_verify');
    const docs = (text) => h('a', { href: 'https://signalith.io/docs/opensearch-security/', target: '_blank', rel: 'noopener' }, text, icon('external-link', 'icon--xs'));
    if (D.prepTab === 'docker') {
      if (secure) s('Signalith’s Docker quick start turns OpenSearch’s security on by itself. This OpenSearch has it off, so turn it on first, as ', docs('Securing OpenSearch'), ' explains.');
      s('Add the address to OpenSearch’s certificate, so new servers can check it is this OpenSearch they reach. In the Signalith folder:',
        cmd(`docker compose -f deploy/docker/docker-compose.yml run --rm setup bootstrap-docker -opensearch-name ${a}`, 'p1'));
      s('Open OpenSearch’s port to other computers. Add this line to deploy/docker/.env (make the file if there is none), so every later “up” keeps it open:',
        cmd('COMPOSE_PROFILES=cluster', 'p2'));
      s('Start it, and restart OpenSearch to use its new certificate:',
        cmd('docker compose -f deploy/docker/docker-compose.yml up -d', 'p3'), cmd('docker compose -f deploy/docker/docker-compose.yml restart opensearch', 'p4'));
      s('In this computer’s firewall, allow TCP 9200 from the new servers only. OpenSearch still asks each of them for its certificate.');
    } else {
      const linux = D.prepTab === 'linux';
      const conf = linux ? '/etc/opensearch/opensearch.yml' : 'C:\\opensearch\\config\\opensearch.yml';
      if (secure) s('Turn on OpenSearch’s security plugin (TLS and sign-in), as ', docs('Securing OpenSearch'), ' explains step by step. Then come back here.');
      s(`If OpenSearch uses certificates Signalith made (signalith opensearch-certs), make it a certificate for the new address under the same CA, and put the new node files in place of the old:`,
        cmd(`signalith opensearch-certs -ca-dir <first output folder> -san ${a} -out <new folder>`, 'p1'));
      s(`Let OpenSearch listen on the network as well as on this computer: in ${conf} set`, cmd(`network.host: ["_local_", "${a}"]`, 'p2'));
      if (linux) {
        s('OpenSearch checks the system’s memory map limit once it listens on the network. Raise it, keep it after a reboot, and restart OpenSearch:',
          cmd('sudo sysctl -w vm.max_map_count=262144 && echo vm.max_map_count=262144 | sudo tee /etc/sysctl.d/90-opensearch.conf', 'p3'),
          cmd('sudo systemctl restart opensearch', 'p4'));
        s('Allow TCP 9200 from the new servers only (one line per server):',
          cmd('sudo ufw allow from <new server> to any port 9200 proto tcp', 'p5'),
          h('p', { class: 'sj-muted' }, 'Or with firewalld:'),
          cmd(`sudo firewall-cmd --permanent --add-rich-rule='rule family=ipv4 source address=<new server> port port=9200 protocol=tcp accept' && sudo firewall-cmd --reload`, 'p6'));
      } else {
        s('Restart the OpenSearch service, then allow TCP 9200 from the new servers only:',
          cmd('New-NetFirewallRule -DisplayName "OpenSearch from Signalith" -Direction Inbound -LocalPort 9200 -Protocol TCP -RemoteAddress <new server> -Action Allow', 'p3'));
      }
    }
    return h('ol', { class: 'sj-prep__steps', role: 'list' }, ...list);
  }

  // saveAddress sets cluster.opensearch_url, the address new servers are
  // given, on the Settings page's store.
  function saveAddress(os) {
    const input = h('input', { class: 'input input--sm mono', type: 'url', id: 'sj-os-url', 'data-focus': 'os-url', value: osAddress(D.prep) || os.address || '',
      autocomplete: 'off', spellcheck: 'false', placeholder: 'https://192.168.1.20:9200' });
    input.addEventListener('input', () => { input.dataset.touched = '1'; });
    const err = formAlert();
    const save = h('button', { type: 'button', class: 'btn btn--primary btn--sm', 'data-focus': 'os-save' }, icon('save'), h('span', {}, 'Save and check again'));
    save.addEventListener('click', async () => {
      const v = input.value.trim();
      if (!/^https:\/\/[^\s/]+(:\d+)?\/?$/.test(v)) {
        showAlert(err, 'That isn’t an address', 'Give it as https://host:9200.');
        return;
      }
      err.classList.add('hidden');
      const restore = busy(save, 'Saving…');
      try {
        await api('api/settings', { values: { 'cluster.opensearch_url': v } }, 'PUT');
        D.prep = await api('api/cluster/join/prepare');
        toast('New servers are given ' + v + '.', null, { tone: 'success' });
        draw();
      } catch (e) {
        restore();
        showAlert(err, 'It was not saved', sentence(e.message));
      }
    });
    return h('div', { class: 'sj-field sj-save' },
      h('label', { class: 'label', for: 'sj-os-url' }, 'Address for new servers'),
      h('p', { class: 'sj-muted' }, 'When the steps above are done, save the address new servers reach OpenSearch at (Settings: cluster.opensearch_url).'),
      h('div', { class: 'sj-save__row' }, input, save), err);
  }

  // ---------- step 2: where it runs, and the token ----------
  function platformPicker(problems, prep) {
    const tabs = h('div', { class: 'tabs sj-tabs', role: 'tablist', 'aria-label': 'Where the new server runs' },
      ...PLATFORMS.map((p) => h('button', { type: 'button', role: 'tab', class: 'tab', 'aria-selected': String(D.platform === p.id), 'data-focus': 'pf-' + p.id,
        disabled: D.made ? '' : null,
        onclick: () => { D.platform = p.id; draw(); } }, icon(p.icon), p.label)));
    const why = {
      linux: 'A Linux computer with systemd (Debian, Ubuntu, RHEL, Rocky, Alma, Fedora, SUSE). The line installs Signalith as a service.',
      windows: 'Windows Server 2019 or later, or Windows 10 or 11, in PowerShell opened with Run as administrator. The line installs Signalith as a service.',
      docker: 'Any computer with Docker and a copy of the Signalith folder (git clone https://github.com/jrsamsanchez/Signalith).',
    }[D.platform];
    const blocked = problems.length > 0 || !prep.pinnable;
    const make = h('button', { type: 'button', class: 'btn btn--primary', 'data-focus': 'make', disabled: blocked || D.made || D.making ? '' : null },
      icon('key-round'), h('span', {}, D.making ? 'Making the line…' : 'Make the line'));
    make.addEventListener('click', makeToken);
    return [tabs, h('p', { class: 'sj-muted' }, why),
      D.made ? null : h('div', { class: 'sj-make' }, make,
        h('span', { class: 'sj-muted' }, problems.length ? 'Prepare OpenSearch first.' : !prep.pinnable ? 'A token can’t be used here: approve the new server instead.' : 'It holds a token that works once, for 60 minutes.')),
      D.tokenErr ? alertBox('danger', 'Couldn’t make the line', D.tokenErr) : null];
  }

  async function makeToken() {
    D.making = true;
    D.tokenErr = '';
    draw();
    try {
      const r = await api('api/cluster/tokens', { platform: D.platform, ttl_minutes: 60, role: D.kind === 'scanner' ? 'scanner' : '' }, 'POST');
      D.made = r;
      D.token = r.id;
      D.used = null;
      D.check = null;
      startWatch();
    } catch (e) {
      D.tokenErr = e.status === 404 ? 'This server can’t make join tokens. Upgrade it, or add the server with a cluster key file (see the guide).' : sentence(e.message);
    } finally {
      D.making = false;
      draw();
    }
  }

  // ---------- step 3: the line ----------
  function line(prep) {
    const r = D.made;
    const c = r.commands || {};
    const until = r.expires_at ? timeText(r.expires_at) : '';
    const once = h('p', { class: 'sj-muted sj-once' }, icon('clock', 'icon--xs'), `Works once, until ${until || 'it expires in 60 minutes'}. Anyone with it can join a server, so don’t share it.`);
    if (D.platform === 'docker') {
      const env = c.docker || `SIGNALITH_JOIN=${r.token}\nSIGNALITH_NODE_NAME=signalith-2\nSIGNALITH_NODE_URL=https://<this computer's address>:8080\n`;
      return [
        h('p', {}, 'In the Signalith folder on the new computer, save this as ', h('code', {}, 'deploy/docker/join.env'), '. Change SIGNALITH_NODE_URL to that computer’s address, so the other servers can reach it:'),
        fileBlock('deploy/docker/join.env', env),
        h('p', {}, 'Then start it:'),
        cmd(c.docker_run || 'docker compose -f deploy/docker/docker-compose.server.yml --env-file deploy/docker/join.env up -d', 'run'),
        once];
    }
    const text = c[D.platform] || `signalith join '${r.token}'`;
    const note = c[D.platform + '_note'];
    return [
      h('p', {}, D.platform === 'windows' ? 'In PowerShell opened with Run as administrator on the new computer:' : 'In a terminal on the new computer (it asks for your sudo password):'),
      note ? alertBox('warning', 'Install Signalith there first', note) : null,
      cmd(text, 'line'),
      h('p', { class: 'sj-muted' }, 'It downloads the install script from this server and checks it, installs Signalith ' + prep.version + ', checks the new computer reaches OpenSearch, then joins and starts the service. It stops with a plain message, changing nothing, if something is missing.'),
      once];
  }

  function fileBlock(name, text) {
    const btn = h('button', { type: 'button', class: 'btn btn--ghost btn--sm', 'data-focus': 'env' }, icon('copy'), h('span', {}, 'Copy'));
    btn.addEventListener('click', () => copy(text, btn));
    return h('div', { class: 'sj-file' }, h('div', { class: 'sj-file__bar' }, icon('file-code'), h('span', { class: 'mono' }, name), h('span', { class: 'spacer' }), btn),
      h('pre', { class: 'sj-file__text' }, text));
  }

  // ---------- step 4: following it ----------
  function startWatch() {
    stopWatch();
    D.watch = setInterval(() => {
      if (!$('sj-dialog') || !$('sj-dialog').open) { stopWatch(); return; }
      if (D.used) checkServer(); else loadPending();
    }, WATCH_MS);
  }

  function stopWatch() {
    if (D.watch) clearInterval(D.watch);
    D.watch = null;
  }

  // follow notes when the token was used, from api/cluster's tokens.
  function follow(d) {
    if (D.used) return;
    const t = (d.tokens || []).find((x) => x.id === D.token);
    if (t && t.used_by && t.used_by.node_id) {
      D.used = t.used_by;
      checkServer();
      draw();
    }
  }

  async function checkServer() {
    if (!D.used || D.checking) return;
    D.checking = true;
    try {
      const c = await api('api/cluster/servers/' + encodeURIComponent(D.used.node_id) + '/check');
      const changed = !D.check || D.check.result !== c.result;
      D.check = c;
      if (c.result === 'ready') stopWatch();
      if (changed) draw();
    } catch (e) {
      // 404: it hasn't sent its first heartbeat yet.
      if (e.status !== 404) {
        D.check = { result: 'error', detail: sentence(e.message) };
        draw();
      }
    } finally {
      D.checking = false;
    }
  }

  function watchLine() {
    const live = (state, title, text) => h('div', { class: 'sj-live', 'data-state': state, role: 'status' },
      state === 'wait' ? h('span', { class: 'pulse', 'aria-hidden': 'true' }) : icon(state === 'ok' ? 'circle-check' : 'triangle-alert'),
      h('div', {}, h('b', {}, title), text ? h('p', {}, ...[].concat(text)) : null));
    if (!D.used) return live('wait', `Waiting for the new ${D.kind === 'scanner' ? 'scanner' : 'server'} to use the line…`, 'This updates by itself once it has.');
    const name = D.used.name || 'The new server';
    const c = D.check;
    if (!c) return live('wait', `${name} used the token`, 'Waiting for it to start…');
    switch (c.result) {
      case 'ready':
        if (D.kind === 'scanner') {
          return live('ok', `${name} joined as a scanner${c.version ? ' (' + c.version + ')' : ''} and is ready`,
            ['Next, pick it for the zone’s networks: on ', h('a', { href: '#vulns', 'data-page': 'vulns', onclick: () => $('sj-dialog').close() }, 'Vulnerabilities'),
              ' > Networks, edit a network and choose it under Scanned by. ', h('a', { href: '#scanners', 'data-page': 'scanners', onclick: () => $('sj-dialog').close() }, 'Settings > Scanners'),
              ' shows whether it has what scanning needs.']);
        }
        return live('ok', `${name} joined${c.version ? ' (' + c.version + ')' : ''} and is ready`, 'It is in the list of servers. Add it to your load balancer, or point agents at it.');
      case 'not_ready': return live('wait', `${name} is starting`, c.detail);
      case 'no_address': return live('warn', `${name} joined, but the other servers can’t check it`, c.detail + ' Set its address on its Settings page (Server > Address for other servers).');
      case 'certificate': return live('warn', `${name} answers with another certificate`, c.detail);
      case 'unreachable': return live('warn', `${name} is running, but this server can’t reach it`, c.detail);
    }
    return live('warn', `Couldn’t check ${name}`, c.detail || '');
  }

  // copy copies text. navigator.clipboard needs HTTPS or localhost, so a
  // plain-HTTP page falls back to a hidden textarea.
  async function copy(text, btn) {
    let ok = false;
    try {
      await navigator.clipboard.writeText(text);
      ok = true;
    } catch (_) {
      const ta = h('textarea', { class: 'sr-only', readonly: '', 'aria-hidden': 'true' });
      ta.value = text;
      document.body.append(ta);
      ta.select();
      try { ok = document.execCommand('copy'); } catch (_) { ok = false; }
      ta.remove();
      btn.focus();
    }
    const use = btn.querySelector('use');
    const label = btn.querySelector('span');
    if (use) use.setAttribute('href', ok ? '#i-check' : '#i-circle-alert');
    if (label) label.textContent = ok ? 'Copied' : 'Copy failed';
    btn.classList.toggle('is-copied', ok);
    clearTimeout(btn.copyTimer);
    btn.copyTimer = setTimeout(() => {
      if (use) use.setAttribute('href', '#i-copy');
      if (label) label.textContent = 'Copy';
      btn.classList.remove('is-copied');
    }, 1800);
  }
})();
