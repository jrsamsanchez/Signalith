// Servers page: who each server signs in to OpenSearch as. Once the
// cluster keeps OpenSearch's certificate authority, each server signs in
// with a certificate of its own (CN=signalith-server-<name>) that it
// renews itself; until then they share one credential. A card under the
// list says which, and what to do next; each server's side panel
// (serverPanels) says how that server signs in. Everything comes from
// api/cluster/opensearch-identity.
'use strict';

(function () {
  const REFRESH_MS = 15000;
  // Within this many days of expiry, a certificate that should have been
  // renewed is worth a warning.
  const SOON_DAYS = 30;
  const S = { rep: null, at: 0, busy: false, seq: 0, ticker: null, failed: null };
  const DAY = { day: 'numeric', month: 'short', year: 'numeric' };
  const dayText = (t) => new Date(t).toLocaleDateString('en-GB', DAY);
  const daysLeft = (t) => (new Date(t).getTime() - Date.now()) / 86400000;
  const short = (fp) => (fp || '').split(':').slice(0, 8).join(':') + '…';
  const live = (s) => s.state !== 'offline' && s.state !== 'stopped';
  const listWords = (items) => (items.length <= 1 ? items.join('') : items.slice(0, -1).join(', ') + ' and ' + items[items.length - 1]);
  const COMPOSE = 'docker compose -f deploy/docker/docker-compose.yml';

  pageHooks.push((name) => {
    if (name !== 'servers') return;
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
      const rep = await api('api/cluster/opensearch-identity');
      if (seq !== S.seq) return;
      S.rep = rep;
      S.failed = null;
    } catch (e) {
      if (seq !== S.seq) return;
      S.failed = e;
    } finally {
      S.busy = false;
    }
    render();
  }

  // who is how a server signs in, in words.
  function who(id) {
    if (!id) return 'Not reported by its version';
    if (id.managed) return 'Its own certificate, ' + id.cn;
    if (id.cn === 'signalith') return 'The shared certificate, signalith';
    if (id.cn) return 'Certificate ' + id.cn;
    if (id.user) return 'User name and password (' + id.user + ')';
    return 'Nothing it can report';
  }

  function alertBox(tone, title, ...body) {
    const ic = { danger: 'circle-alert', warning: 'triangle-alert', info: 'info' }[tone];
    const attrs = { class: 'alert', 'data-tone': tone };
    if (tone === 'danger') attrs.role = 'alert';
    return el('div', attrs, icon(ic), el('div', {}, el('b', {}, title), ...body.filter(Boolean)));
  }

  function cmd(text) {
    return el('pre', { class: 'osid-cmd', tabindex: '0', 'aria-label': 'Command' }, text);
  }

  function render() {
    const box = $('servers-osid');
    if (!box) return;
    const rep = S.rep;
    if (!rep && S.failed) {
      fill(box, card('OpenSearch sign-in', 'Couldn’t read it now; this page tries again.', null));
      return;
    }
    const servers = (rep && rep.servers) || [];
    // A server of its own, with nothing handed over, has nothing to show.
    if (!rep || rep.alone || (!rep.ca && servers.length < 2)) {
      box.replaceChildren();
      return;
    }
    if (!rep.ca) {
      fill(box, card('OpenSearch sign-in', 'These servers share one OpenSearch credential.', [
        el('p', { class: 'ca-text' }, 'Removing a server means changing that credential on every other one. When Signalith made OpenSearch’s certificates, hand their certificate authority to the cluster, and each server gets a certificate of its own that it renews itself:'),
        cmd(COMPOSE + ' run --rm setup bootstrap-docker -export-ca-key'),
        el('p', { class: 'ca-muted' }, 'Without Docker: signalith cluster opensearch-ca import /path/to/ca/root-ca-key.pem on any server.'),
      ]));
      return;
    }
    const ca = rep.ca;
    const up = servers.filter(live);
    const sharedLeft = up.filter((s) => s.identity && s.identity.shared);
    const own = up.filter((s) => s.identity && s.identity.managed);
    const alerts = [];
    for (const s of up) {
      const id = s.identity;
      if (id && id.problem) alerts.push(alertBox('warning', s.name + ' keeps its current OpenSearch sign-in for now', el('p', {}, id.problem)));
      else if (id && id.managed && id.not_after && daysLeft(id.not_after) < SOON_DAYS - 1) {
        alerts.push(alertBox('warning', s.name + '’s OpenSearch certificate expires on ' + dayText(id.not_after), el('p', {}, 'It should have renewed it by now. Its log says why not.')));
      }
    }
    if (sharedLeft.length && !alerts.length) {
      alerts.push(alertBox('info', listWords(sharedLeft.map((s) => s.name)) + (sharedLeft.length === 1 ? ' still signs' : ' still sign') + ' in with a shared credential',
        el('p', {}, 'A server that signs in with the shared certificate switches to its own within a minute. One that signs in with a password, or a certificate from another certificate authority, keeps it.')));
    }
    if (up.length && own.length === up.length) {
      alerts.push(alertBox('info', 'Every server has its own OpenSearch certificate',
        el('p', {}, 'The shared certificate, signalith, opens nothing Signalith needs any more. To make removing a server end its access for good, delete the line - "signalith" under signalith_server in roles_mapping.yml (deploy/docker/opensearch/security/roles_mapping.yml in Docker), then load the security settings again:'),
        cmd(COMPOSE + ' run --rm setup bootstrap-docker -apply-security\n' + COMPOSE + ' up -d'),
        el('p', {}, 'Without Docker, run OpenSearch’s securityadmin.sh (or .bat) instead.')));
    }
    const rows = servers.map((s) => {
      const id = s.identity;
      const until = id && id.not_after ? dayText(id.not_after) : '';
      return el('li', {}, el('b', {}, s.name + (s.self ? ' (this server)' : '')),
        el('span', {}, who(id)),
        until ? el('span', { class: 'ca-muted' }, (id.managed ? 'renews itself; valid until ' : 'valid until ') + until) : null,
        live(s) ? null : el('span', { class: 'ca-muted' }, 'not running'));
    });
    fill(box, card('OpenSearch sign-in', `${own.length} of ${up.length} running ${up.length === 1 ? 'server signs' : 'servers sign'} in with a certificate of ${up.length === 1 ? 'its' : 'their'} own.`, [
      el('dl', { class: 'ca-facts' },
        el('div', { class: 'ca-fact' }, el('dt', {}, 'Certificate authority'), el('dd', {}, el('span', { class: 'mono ca-fp', title: ca.ca_sha256 }, short(ca.ca_sha256)), ' · OpenSearch’s, kept by the cluster')),
        el('div', { class: 'ca-fact' }, el('dt', {}, 'Handed over'), el('dd', {}, `by ${ca.imported_by}${ca.imported_on ? ' on ' + ca.imported_on : ''}, ${dayText(ca.imported_at)}`))),
      alerts.length ? el('div', { class: 'ca-alerts' }, ...alerts) : null,
      el('ul', { class: 'ca-list osid-list', role: 'list' }, ...rows),
    ]));
  }

  function card(title, sub, body) {
    return el('section', { class: 'card ca-card', 'aria-labelledby': 'osid-title' },
      el('div', { class: 'card__head' },
        el('div', { class: 'ca-head' },
          el('span', { class: 'ca-head__icon' }, icon('key-round')),
          el('div', {},
            el('h3', { class: 'card__title', id: 'osid-title' }, title),
            el('p', { class: 'card__sub' }, sub)))),
      body ? el('div', { class: 'ca-body' }, ...[].concat(body).filter(Boolean)) : null);
  }

  // Each server's side panel says how it signs in.
  serverPanels.push(({ s, part }) => {
    const rep = S.rep;
    if (!rep || rep.alone) return null;
    const v = (rep.servers || []).find((x) => x.node_id === s.node_id);
    if (!v || !v.identity) return null;
    const id = v.identity;
    const kids = [el('p', { class: 'sv-panel__text' }, who(id) + '.')];
    if (id.not_after) kids.push(el('p', { class: 'sv-panel__text' }, (id.managed ? 'It renews it itself; this one is valid until ' : 'Valid until ') + dayText(id.not_after) + '.'));
    if (id.problem) kids.push(el('p', { class: 'sv-panel__text sv-warn' }, id.problem));
    return part('OpenSearch sign-in', ...kids);
  });
})();
