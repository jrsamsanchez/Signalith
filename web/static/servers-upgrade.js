// Servers page: the upgrade checklist (multi-server design 4.9). A card
// under the list of servers says whether the next server may be upgraded
// now, as signalith cluster upgrade-check does, and gives each server its
// steps, in the order to follow (the server running the background jobs
// last): Drain, Upgrade (the command for how it runs), Wait for Ready,
// Resume. Everything comes from api/cluster/upgrade, read every 15
// seconds while the page shows; Drain and Resume are the requests of the
// Maintenance part of a server's panel. Nothing is kept beyond the page's
// life: a version that changed since the page opened counts as upgraded.
'use strict';

(function () {
  const REFRESH_MS = 15000;
  const README = 'https://github.com/jrsamsanchez/Signalith/blob/main/README.md#linux';
  const S = { v: null, off: false, at: 0, busy: false, seq: 0, ticker: null, failed: null, first: {}, open: null, acting: {} };

  pageHooks.push((name) => {
    if (name !== 'servers' || !can('admin')) return;
    if (!S.ticker) S.ticker = setInterval(tick, 1000);
    load();
  });

  function tick() {
    if (currentPage !== 'servers') {
      clearInterval(S.ticker);
      S.ticker = null;
      return;
    }
    if (document.hidden) return;
    if (Date.now() - S.at >= REFRESH_MS) load();
  }

  async function load() {
    if (S.busy) return;
    S.busy = true;
    S.at = Date.now();
    const seq = ++S.seq;
    try {
      const v = await api('api/cluster/upgrade');
      if (seq !== S.seq) return;
      S.v = v;
      S.off = false;
      S.failed = null;
      for (const s of v.servers || []) if (s.node_id && !(s.node_id in S.first)) S.first[s.node_id] = s.version;
    } catch (e) {
      if (seq !== S.seq) return;
      // A server without a cluster, or of a version without the route,
      // shows no checklist.
      if (e.status === 503 || e.status === 404) S.off = true;
      else S.failed = e;
    } finally {
      S.busy = false;
    }
    render();
  }

  async function act(s, what) {
    const doing = (what === 'drain' ? 'drain ' : 'resume ') + s.name;
    S.acting[s.node_id] = what;
    render();
    try {
      const res = await api(`api/cluster/servers/${encodeURIComponent(s.node_id)}/${what}`, null, 'POST');
      if (res && res.request_id) {
        const rq = await followRequest(res.request_id);
        if (rq && rq.state === 'failed') toast(rq.error || 'No reason given.', null, { tone: 'danger', title: 'Couldn’t ' + doing });
      }
    } catch (e) {
      toast(e.message || 'The server did not answer.', null, { tone: 'danger', title: 'Couldn’t ' + doing });
    }
    delete S.acting[s.node_id];
    load();
  }

  // ---------- what each server has left to do ----------
  const mixed = (v) => (v.versions || []).length > 1;
  // upgraded: the server runs the newest version, or a version other than
  // the one it ran when the page opened.
  function upgraded(v, s) {
    if (S.first[s.node_id] && S.first[s.node_id] !== s.version) return true;
    return mixed(v) && !!v.newest && s.version === v.newest;
  }

  // order puts the servers upgraded first, then the others by name, the
  // one running the background jobs last.
  function order(v) {
    return (v.servers || []).slice().sort((a, b) => {
      const ua = upgraded(v, a), ub = upgraded(v, b);
      if (ua !== ub) return ua ? -1 : 1;
      if (a.jobs !== b.jobs) return a.jobs ? 1 : -1;
      return a.name.localeCompare(b.name);
    });
  }

  function commands(dep) {
    const linux = el('li', {}, 'Linux: ', el('code', {}, 'sudo apt upgrade signalith'), ' or ', el('code', {}, 'sudo dnf upgrade signalith'),
      ', or replace the program as the ',
      el('a', { href: README, target: '_blank', rel: 'noopener noreferrer' }, 'README says', icon('arrow-up-right', 'icon--xs'),
        el('span', { class: 'sr-only' }, ' (opens in a new tab)')), '.');
    const win = el('li', {}, 'Windows: run the new release’s MSI, or ', el('code', {}, 'install.ps1'), ' from the new release’s folder.');
    const docker = el('li', {}, 'Docker: ', el('code', {}, 'git pull && docker compose up -d'), ' in the Signalith folder.');
    const pick = { systemd: [linux], 'windows-service': [win], docker: [docker] }[dep] || [linux, win, docker];
    return el('ul', { class: 'sv-upgrade__cmds', role: 'list' }, ...pick);
  }

  // steps are the four steps of a server, each done, now or later.
  function steps(v, s, single, isNext) {
    const up = upgraded(v, s);
    const ready = s.live && s.state === 'ready';
    const drained = !!s.drained;
    const acting = S.acting[s.node_id];
    const st = { drain: 'later', upgrade: 'later', wait: 'later', resume: 'later' };
    if (up) {
      st.drain = st.upgrade = 'done';
      st.wait = ready || drained ? 'done' : 'now';
      st.resume = drained ? (s.live ? 'now' : 'later') : 'done';
      if (!drained && ready) st.wait = 'done';
    } else if (isNext) {
      st.drain = single || drained ? 'done' : 'now';
      st.upgrade = single || drained ? 'now' : 'later';
    }
    const row = (key, title, ...body) => el('li', { class: 'sv-upgrade__step', 'data-state': st[key] },
      el('span', { class: 'sv-upgrade__mark', 'aria-hidden': 'true' }, icon(st[key] === 'done' ? 'circle-check' : st[key] === 'now' ? 'circle-dot' : 'clock', 'icon--sm')),
      el('div', {}, el('b', {}, title), el('span', { class: 'sr-only' }, ` (${st[key] === 'done' ? 'done' : st[key] === 'now' ? 'do this now' : 'later'})`), ...body));
    const out = [];
    if (!single) {
      out.push(row('drain', 'Drain', el('p', { class: 'sv-upgrade__text' },
        'It stops taking traffic from load balancers and hands the background jobs over.'),
      st.drain === 'now' && !drained ? el('button', { type: 'button', class: 'btn btn--secondary btn--sm', disabled: !!acting || !s.live,
        onclick: () => act(s, 'drain') }, icon('power'), acting === 'drain' ? 'Draining…' : 'Drain ' + s.name) : null));
    }
    out.push(row('upgrade', 'Upgrade', el('p', { class: 'sv-upgrade__text' }, `Stop ${s.name}, install the new version and start it.`), commands(s.deployment)));
    out.push(row('wait', 'Wait for Ready', el('p', { class: 'sv-upgrade__text' },
      up && !ready ? `${s.name} is ${s.state}: this list updates by itself.` : 'Its state turns ready on the new version.')));
    if (!single) {
      out.push(row('resume', 'Resume', el('p', { class: 'sv-upgrade__text' }, 'A drained server stays drained after the restart until it is resumed.'),
        drained && st.resume === 'now' ? el('button', { type: 'button', class: 'btn btn--secondary btn--sm', disabled: !!acting,
          onclick: () => act(s, 'resume') }, icon('play'), acting === 'resume' ? 'Resuming…' : 'Resume ' + s.name) : null));
    }
    return el('ol', { class: 'sv-upgrade__steps', role: 'list' }, ...out);
  }

  // ---------- the card ----------
  function summary(v) {
    const vs = v.versions || [];
    if (v.single) return 'This server is the only one using this OpenSearch.';
    if (vs.length <= 1) return vs.length ? `Every server runs ${vs[0]}.` : 'No server has said which version it runs.';
    const servers = v.servers || [];
    const done = servers.filter((s) => upgraded(v, s)).length;
    return `The servers run ${vs.join(' and ')}: ${done} of ${servers.length} on ${v.newest || 'the newest'}.`;
  }

  function notes(title, list, tone) {
    if (!list || !list.length) return null;
    return el('div', { class: 'alert', 'data-tone': tone, role: tone === 'danger' ? 'alert' : 'status' }, icon(tone === 'danger' ? 'circle-alert' : 'triangle-alert'),
      el('div', {}, el('b', {}, title), el('ul', { class: 'sv-upgrade__notes', role: 'list' }, ...list.map((n) => el('li', {}, n.text)))));
  }

  function details(v) {
    const facts = [];
    if (v.cluster_level) facts.push(['Cluster level', String(v.cluster_level)]);
    const lv = Object.entries(v.level_versions || {}).sort((a, b) => Number(a[0]) - Number(b[0]));
    for (const [level, ver] of lv) facts.push([`Level ${level} since`, ver]);
    const mig = Object.entries(v.migrations || {}).sort((a, b) => a[0].localeCompare(b[0]));
    if (!facts.length && !mig.length) return null;
    return el('details', { class: 'sv-upgrade__details' }, el('summary', {}, 'Details'),
      facts.length ? el('dl', { class: 'ca-facts' }, ...facts.map(([k, val]) => el('div', { class: 'ca-fact' }, el('dt', {}, k), el('dd', {}, val)))) : null,
      mig.length ? el('div', {}, el('h4', { class: 'section-title' }, 'Migrations run once for the cluster'),
        el('ul', { class: 'sv-upgrade__notes', role: 'list' }, ...mig.map(([name, at]) => el('li', {}, el('span', { class: 'mono' }, name), ' ',
          el('span', { class: 'sv-panel__key', title: new Date(at).toLocaleString() }, ago(at)))))) : null);
  }

  function render() {
    const box = $('servers-upgrade');
    if (!box) return;
    const v = S.v;
    if (S.off || !v) {
      box.replaceChildren();
      return;
    }
    const a = document.activeElement;
    const focus = a && box.contains(a) && a.dataset ? a.dataset.focus : '';
    const servers = order(v);
    const single = !!v.single || servers.length < 2;
    const nextUp = servers.find((s) => !upgraded(v, s) && s.live);
    const urgent = mixed(v) || (v.blockers || []).length > 0;
    const open = S.open == null ? urgent : S.open;
    const body = [];
    body.push(el('div', { class: 'alert', 'data-tone': v.safe ? 'success' : 'warning', role: 'status' }, icon(v.safe ? 'circle-check' : 'hourglass'),
      el('div', {}, el('b', {}, v.safe ? 'Safe to upgrade the next server' : 'Not safe yet'), v.next ? el('p', {}, v.next) : null)));
    body.push(notes('Wait for this first', v.blockers, 'danger'), notes('Good to know', v.warnings, 'warning'));
    if (S.failed) body.push(el('p', { class: 'sv-panel__text sv-warn' }, 'Couldn’t read the checklist: ' + (S.failed.message || 'no answer') + '. Trying again.'));
    body.push(el('ol', { class: 'sv-upgrade__servers', role: 'list' }, ...servers.map((s, i) => {
      const up = upgraded(v, s);
      const tag = up ? 'upgraded' : s.jobs ? 'runs the jobs: last' : nextUp && nextUp.node_id === s.node_id ? 'next' : '';
      return el('li', { class: 'sv-upgrade__server', 'data-upgraded': up ? 'true' : 'false' },
        el('div', { class: 'sv-upgrade__head' }, el('span', { class: 'sv-upgrade__n' }, String(i + 1)), el('b', {}, s.name),
          el('span', { class: 'mono sv-panel__key' }, s.version || 'unknown'), el('span', { class: 'sv-panel__key' }, s.state),
          tag ? el('span', { class: 'badge' }, tag) : null),
        steps(v, s, single, !!nextUp && nextUp.node_id === s.node_id));
    })));
    body.push(details(v));
    // Only the admin's own click decides whether it stays open; until
    // then it opens while versions are mixed or something blocks.
    let card = null;
    card = el('details', { class: 'card ca-card sv-upgrade', 'aria-labelledby': 'sv-upgrade-title' },
      el('summary', { class: 'card__head', 'data-focus': 'upgrade-summary', onclick: () => { S.open = !card.open; } }, el('div', { class: 'ca-head' }, el('span', { class: 'ca-head__icon' }, icon('arrow-big-up-dash')),
        el('div', {}, el('h3', { class: 'card__title', id: 'sv-upgrade-title' }, 'Upgrade the servers'),
          el('p', { class: 'card__sub' }, summary(v))))),
      el('div', { class: 'ca-body' }, ...body.filter(Boolean)));
    card.open = open;
    box.replaceChildren(card);
    if (focus) {
      const n = box.querySelector(`[data-focus="${CSS.escape(focus)}"]`);
      if (n) n.focus({ preventScroll: true });
    }
  }
})();
