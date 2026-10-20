// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0
// Servers page: the cluster's one certificate authority. Once the cluster
// has one, every server's HTTPS certificate comes from it, so a single CA
// file works for agents and browsers on every server; a card under the
// list of servers says which it is. While servers set up separately each
// keep their own, the card asks an admin which to keep, with the one most
// agents use preselected and the agents each choice would break. Each
// server's side panel (serverPanels) says which certificate authority it
// uses. Once one is shared, the card replaces it in three steps (prepare,
// switch, retire; api/cluster/tls/rotate-ca). Everything comes from
// api/cluster/tls.
'use strict';

(function () {
  const REFRESH_MS = 15000;
  // touched is set once the admin picks a radio: until then the choice
  // follows the suggestion, which may change as the counts come in.
  const S = { rep: null, at: 0, busy: false, seq: 0, ticker: null, failed: null, choice: '', touched: false, asking: null };
  const SCOPE = { standard: 'standard', strict: 'strict', unconstrained: 'older, unlimited' };
  const DAY = { day: 'numeric', month: 'short', year: 'numeric' };
  const dayText = (t) => new Date(t).toLocaleDateString('en-GB', DAY);
  const plural = (n, one, many) => `${n.toLocaleString()} ${n === 1 ? one : many}`;
  // short is the first eight bytes of a fingerprint; the whole one is
  // its tooltip.
  const short = (fp) => (fp || '').split(':').slice(0, 8).join(':') + '…';
  const fpEl = (fp) => el('span', { class: 'mono ca-fp', title: fp }, short(fp));
  const listWords = (items) => (items.length <= 1 ? items.join('') : items.slice(0, -1).join(', ') + ' and ' + items[items.length - 1]);

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
    if (document.hidden || S.asking) return;
    if (Date.now() - S.at >= REFRESH_MS) load();
  }

  async function load() {
    if (S.busy) return;
    S.busy = true;
    S.at = Date.now();
    const seq = ++S.seq;
    try {
      const rep = await api('api/cluster/tls');
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

  // ---------- the card ----------
  function render() {
    const box = $('servers-ca');
    if (!box) return;
    const rep = S.rep;
    if (!rep && S.failed) {
      fill(box, card('Certificate authority', 'Couldn’t read it now; this page tries again.', null));
      return;
    }
    if (!rep || rep.alone) {
      box.replaceChildren();
      return;
    }
    // Keep the radio that has focus, and what was open, across a refresh.
    const a = document.activeElement;
    const focus = a && box.contains(a) && a.dataset ? a.dataset.focus : '';
    const open = new Set([...box.querySelectorAll('details[open][data-key]')].map((d) => d.dataset.key));
    let body;
    if (!rep.on) body = [el('p', { class: 'ca-text' }, rep.off)];
    else if (rep.published) body = published(rep);
    else body = choice(rep);
    fill(box, card('Certificate authority', subline(rep), body));
    for (const d of box.querySelectorAll('details[data-key]')) if (open.has(d.dataset.key)) d.open = true;
    if (focus) {
      const n = box.querySelector(`[data-focus="${CSS.escape(focus)}"]`);
      if (n) n.focus({ preventScroll: true });
    }
  }

  function subline(rep) {
    if (!rep.on) return 'Each server keeps its own for now.';
    if (rep.published) return 'Every server’s HTTPS certificate comes from the cluster’s certificate authority, so one CA file works for agents and browsers on every server.';
    const cands = rep.candidates || [];
    if (!cands.length) return 'No server has a certificate authority of its own to share yet.';
    if (cands.length === 1) {
      const files = (rep.servers || []).filter((s) => s.mode === 'files').map((s) => s.name);
      const why = files.length ? `${listWords(files)} ${files.length === 1 ? 'uses' : 'use'} your own certificate files, so ` : '';
      return cap(`${why}Signalith didn’t share ${cands[0].servers[0]}’s certificate authority by itself. Keep it to use it on every server.`);
    }
    return 'The servers were set up separately, so each has its own certificate authority. Choose the one every server should use.';
  }

  function card(title, sub, body) {
    const icn = S.rep && S.rep.published ? 'shield-check' : 'shield';
    return el('section', { class: 'card ca-card', 'aria-labelledby': 'ca-title' },
      el('div', { class: 'card__head' },
        el('div', { class: 'ca-head' },
          el('span', { class: 'ca-head__icon' }, icon(icn)),
          el('div', {},
            el('h3', { class: 'card__title', id: 'ca-title' }, title),
            el('p', { class: 'card__sub' }, sub)))),
      body ? el('div', { class: 'ca-body' }, ...[].concat(body).filter(Boolean)) : null);
  }

  // facts is a definition list of label and value pairs; empty values
  // are left out.
  function facts(pairs) {
    const kids = [];
    for (const [k, v] of pairs) if (v) kids.push(el('div', { class: 'ca-fact' }, el('dt', {}, k), el('dd', {}, v)));
    return el('dl', { class: 'ca-facts' }, ...kids);
  }

  function alertBox(tone, title, text) {
    const ic = { danger: 'circle-alert', warning: 'triangle-alert', info: 'info' }[tone];
    const attrs = { class: 'alert', 'data-tone': tone };
    if (tone === 'danger') attrs.role = 'alert';
    return el('div', attrs, icon(ic), el('div', {}, el('b', {}, title), text ? el('p', {}, text) : null));
  }

  // serverAlerts are the problems of each server's certificate: red when
  // it cannot take the cluster's, amber for the rest.
  function serverAlerts(rep) {
    const out = [];
    for (const s of rep.servers || []) {
      if (s.problem) out.push(alertBox('danger', `${s.name} keeps its own certificate authority`, cap(s.problem) + '.'));
      for (const w of s.warnings || []) out.push(alertBox('warning', s.name, w));
    }
    return out.length ? el('div', { class: 'ca-alerts' }, ...out) : null;
  }
  const cap = (t) => (t ? t.charAt(0).toUpperCase() + t.slice(1) : t);

  function published(rep) {
    const ca = rep.ca;
    const using = (rep.servers || []).filter((s) => s.cluster).length;
    const reported = (rep.servers || []).filter((s) => s.reported).length;
    const names = ca.names || [];
    const made = [ca.subject, ca.scope ? SCOPE[ca.scope] || ca.scope : '', ca.not_after ? 'valid until ' + dayText(ca.not_after) : ''].filter(Boolean).join(' · ');
    const retired = rep.retired || [];
    return [
      facts([
        ['Fingerprint', el('span', { class: 'mono ca-fp--full' }, ca.ca_sha256)],
        ['Certificate authority', made],
        ['Published', `by ${ca.published_by} on ${dayText(ca.published_at)}`],
        ['In use', `${using} of ${plural(reported, 'server', 'servers')}`],
        ['Names on every server', names.length ? names.join(', ') : 'None added yet. A name an agent is set up with on Add data is added here.'],
      ]),
      serverAlerts(rep),
      retired.length ? el('details', { class: 'disclosure ca-retired', 'data-key': 'retired' },
        el('summary', { 'data-focus': 'retired' }, icon('archive'), `Retired certificate authorities (${retired.length})`, icon('chevron-down', 'chev')),
        el('div', { class: 'disclosure__body' },
          el('p', { class: 'ca-text' }, 'The certificate authorities servers used before the cluster’s. They never sign again. Agents whose configuration trusts only one of them are marked “Needs a new configuration” on the ', el('a', { href: '#endpoints', 'data-page': 'endpoints' }, 'Endpoints page'), '.'),
          el('ul', { class: 'ca-list', role: 'list' }, ...retired.map((r) => el('li', {}, fpEl(r.ca_sha256),
            el('span', { class: 'ca-muted' }, `${r.server ? r.server + '’s, ' : ''}retired ${dayText(r.retired_at)}`)))))) : null,
      rotation(rep),
    ];
  }

  // ---------- replacing it ----------
  const STEPS = {
    prepare: {
      button: 'Replace it…', title: 'Make a new certificate authority for every server?', ok: 'Make it',
      text: 'Every server hands it out with the one in use from now on. Nothing changes for agents and browsers until you switch. Managed agents take it by themselves; give other agents, browsers and syslog devices the CA file again before the switch.',
      done: 'Every server now hands out the new certificate authority with the one in use.',
    },
    switch: {
      button: 'Switch to it…', title: 'Switch every server to the new certificate authority?', ok: 'Switch',
      text: 'Each server issues itself a certificate from the new one within seconds. The old one is still trusted until you retire it. An agent, browser or device that doesn’t trust the new one by then refuses the servers.',
      done: 'Every server now issues its certificate from the new certificate authority.',
    },
    retire: {
      button: 'Retire the old one…', title: 'Retire the old certificate authority?', ok: 'Retire it',
      text: 'No server hands it out any more, and its key is deleted from the shared settings. Agents that trust only it need a new configuration.',
      done: 'The old certificate authority is retired.',
    },
  };

  function rotation(rep) {
    const r = rep.rotation || { state: 'none', blockers: [] };
    const blockers = r.blockers || [];
    const download = el('a', { class: 'btn btn--secondary btn--sm', href: r.state === 'none' ? 'api/tls/ca.pem' : 'api/tls/ca.pem?which=both', download: 'signalith-ca.pem' },
      icon('download'), r.state === 'none' ? 'Download the certificate authority' : 'Download both certificate authorities');
    let step = 'prepare';
    let info = null;
    if (r.state === 'prepared' && r.next) {
      step = 'switch';
      info = [facts([
        ['New certificate authority', el('span', { class: 'mono ca-fp--full' }, r.next.ca_sha256)],
        ['Prepared', `${r.next.by ? 'by ' + r.next.by + ' ' : ''}on ${dayText(r.next.at)}, valid until ${dayText(r.next.not_after)}`],
      ]), el('p', { class: 'ca-text' }, 'Every server hands out both. Managed agents take the new one by themselves. Give other agents, browsers and syslog devices the file with both before you switch.')];
    } else if (r.state === 'switched' && r.previous) {
      step = 'retire';
      info = [facts([
        ['Old certificate authority', el('span', { class: 'mono ca-fp--full' }, r.previous.ca_sha256)],
        ['Switched', `${r.previous.by ? 'by ' + r.previous.by + ' ' : ''}on ${dayText(r.previous.at)}`],
      ]), el('p', { class: 'ca-text' }, 'Every server issues its certificate from the new one and still hands out the old one. Retire it once every server’s certificate comes from the new one.')];
    }
    const go = el('button', { type: 'button', class: 'btn btn--' + (step === 'prepare' ? 'secondary' : 'primary') + ' btn--sm', 'data-focus': 'ca-rotate', onclick: () => confirmStep(step) }, STEPS[step].button);
    go.disabled = !!S.asking || (step !== 'prepare' && blockers.length > 0);
    return [
      info,
      step !== 'prepare' && blockers.length ? el('div', { class: 'ca-alerts' }, ...blockers.map((b) => alertBox('warning', 'Waiting for a server', cap(b) + '.'))) : null,
      S.asking ? el('p', { class: 'ca-progress', role: 'status' }, icon('clock', 'icon--sm'), S.asking) : null,
      el('div', { class: 'ca-actions' }, download, go,
        step === 'prepare' ? el('span', { class: 'ca-muted' }, 'Replace it when its key may have leaked, or a server you removed may still hold it.') : null),
    ];
  }

  function confirmStep(step) {
    const st = STEPS[step];
    const d = modalDialog('ca-rotate');
    const ok = el('button', { type: 'button', class: 'btn btn--primary', 'data-focus': 'ca-rotate-ok' }, st.ok);
    const err = el('div', { class: 'alert hidden', 'data-tone': 'danger', role: 'alert' });
    ok.addEventListener('click', async () => {
      const back = busy(ok, 'Asking…');
      try {
        const r = await api('api/cluster/tls/rotate-ca', { step });
        d.close();
        followStep(r, st);
      } catch (e) {
        fill(err, icon('circle-alert'), el('div', {}, el('b', {}, 'Nothing changed'), el('p', {}, e.message)));
        err.classList.remove('hidden');
      } finally {
        back();
      }
    });
    fill(d, modalHead('ca-rotate', st.title, st.text, () => d.close()),
      el('div', { class: 'modal__body' }, err),
      el('div', { class: 'modal__foot' }, el('button', { type: 'button', class: 'btn btn--ghost', onclick: () => d.close() }, 'Cancel'), ok));
    d.showModal();
    ok.focus();
  }

  // followStep shows the request's progress on the card until the server
  // that runs the background jobs has taken the step.
  async function followStep(r, st) {
    S.asking = 'Asking the server that runs the background jobs…';
    render();
    const req = await followRequest(r.request_id, () => {
      S.asking = 'The server that runs the background jobs is on it…';
      render();
    });
    S.asking = null;
    if (req && req.state === 'done') toast(st.done);
    else if (req && req.state === 'failed') toastError('Nothing changed', new Error(req.error || 'no reason given'));
    else toast('It hasn’t answered yet; this page shows it once it has.');
    load();
  }

  // ---------- the choice ----------
  function choice(rep) {
    const cands = rep.candidates || [];
    if (!cands.length) return [serverAlerts(rep), el('p', { class: 'ca-text' }, 'Servers that use your own certificate files never share a certificate authority. A server that makes its own offers it here.')];
    if (!S.touched || !cands.some((c) => c.ca_sha256 === S.choice)) {
      S.choice = (cands.find((c) => c.preselected) || cands[0]).ca_sha256;
      S.touched = false;
    }
    const radios = cands.map((c, i) => candidate(c, i));
    const chosen = cands.find((c) => c.ca_sha256 === S.choice);
    const go = el('button', { type: 'button', class: 'btn btn--primary btn--sm', 'data-focus': 'ca-keep', 'data-feature': 'shared_tls', onclick: () => confirmChoice(chosen) }, 'Keep this one…');
    // Only a server that runs can publish its certificate authority.
    go.disabled = !!S.asking || !chosen || !chosen.up;
    return [
      rep.agents_unread ? alertBox('warning', 'The agent counts may be short', rep.agents_unread) : null,
      el('fieldset', { class: 'ca-choice' },
        el('legend', { class: 'ca-legend' }, 'Which certificate authority should every server use?'),
        ...radios),
      serverAlerts(rep),
      S.asking ? el('p', { class: 'ca-progress', role: 'status' }, icon('clock', 'icon--sm'), S.asking) : null,
      el('div', { class: 'ca-actions' }, go,
        el('span', { class: 'ca-muted' }, 'The other servers take it within seconds and retire their own.')),
    ];
  }

  function candidate(c, i) {
    const id = 'ca-cand-' + i;
    const owner = c.servers[0];
    const more = c.servers.slice(1);
    const radio = el('input', { type: 'radio', name: 'ca-cand', id, value: c.ca_sha256, 'data-focus': 'cand:' + c.ca_sha256 });
    radio.checked = c.ca_sha256 === S.choice;
    radio.addEventListener('change', () => { S.choice = c.ca_sha256; S.touched = true; render(); });
    const breaks = c.breaks || [];
    const lines = [
      el('span', { class: 'ca-cand__counts' },
        `Used by ${plural(c.agent_count, 'agent', 'agents')}`,
        c.break_count ? el('span', { class: 'ca-warn' }, ` · ${plural(c.break_count, 'agent', 'agents')} would need a new configuration`) : ' · no agent would need a new configuration'),
      el('span', { class: 'ca-muted' }, [more.length ? `Also used by ${listWords(more)}` : '', `${more.length ? 'made' : 'Made'} ${dayText(c.not_before)}`, c.scope ? SCOPE[c.scope] || c.scope : ''].filter(Boolean).join(' · '), ' · ', fpEl(c.ca_sha256)),
    ];
    if (!c.up) {
      lines.push(el('span', { class: 'ca-bad' }, icon('circle-alert', 'icon--sm'),
        `${listWords(c.servers)} ${c.servers.length === 1 ? 'is' : 'are'} offline. Start ${c.servers.length === 1 ? 'it' : 'one of them'} to keep this certificate authority.`));
    }
    for (const u of c.cannot_cover || []) {
      lines.push(el('span', { class: 'ca-bad' }, icon('circle-alert', 'icon--sm'),
        `It can’t vouch for ${u.server}’s ${u.names.length === 1 ? 'name' : 'names'} ${listWords(u.names)}, so ${u.server}’s certificate would leave ${u.names.length === 1 ? 'it' : 'them'} out.`));
    }
    if (breaks.length) {
      const left = c.break_count - breaks.length;
      lines.push(el('details', { class: 'ca-breaks', 'data-key': 'breaks:' + c.ca_sha256 },
        el('summary', { 'data-focus': 'breaks:' + c.ca_sha256 }, icon('chevron-right', 'icon--sm ca-chev'), 'Agents that would need a new configuration'),
        el('ul', { class: 'ca-list', role: 'list' }, ...breaks.map((b) => el('li', {}, b.name || b.address || b.key)),
          left > 0 ? el('li', { class: 'ca-muted' }, `and ${plural(left, 'more', 'more')}`) : null)));
    }
    return el('div', { class: 'ca-cand' + (radio.checked ? ' is-checked' : '') },
      radio,
      el('div', { class: 'ca-cand__text' },
        el('label', { for: id, class: 'ca-cand__label' }, `Keep ${owner}’s certificate authority`,
          c.preselected ? el('span', { class: 'badge badge--accent' }, 'Suggested') : null),
        ...lines));
  }

  function confirmChoice(c) {
    if (!c || !c.up) return;
    const owner = c.servers[0];
    const d = modalDialog('ca-confirm');
    const text = c.break_count
      ? `Every server takes it within seconds. ${plural(c.break_count, 'agent', 'agents')} set up for another server ${c.break_count === 1 ? 'needs' : 'need'} a new configuration from Add data. The other certificate authorities are retired and never sign again.`
      : 'Every server takes it within seconds, and no agent needs a new configuration. The other certificate authorities are retired and never sign again.';
    const ok = el('button', { type: 'button', class: 'btn btn--primary', 'data-focus': 'ca-ok' }, 'Keep it');
    const err = el('div', { class: 'alert hidden', 'data-tone': 'danger', role: 'alert' });
    ok.addEventListener('click', async () => {
      const back = busy(ok, 'Asking…');
      try {
        const r = await api('api/cluster/tls/choose', { ca_sha256: c.ca_sha256 });
        d.close();
        follow(r, owner);
      } catch (e) {
        fill(err, icon('circle-alert'), el('div', {}, el('b', {}, 'Nothing changed'), el('p', {}, e.message)));
        err.classList.remove('hidden');
      } finally {
        back();
      }
    });
    fill(d, modalHead('ca-confirm', `Keep ${owner}’s certificate authority for every server?`, text, () => d.close()),
      el('div', { class: 'modal__body' }, facts([['Fingerprint', el('span', { class: 'mono ca-fp--full' }, c.ca_sha256)]]), err),
      el('div', { class: 'modal__foot' }, el('button', { type: 'button', class: 'btn btn--ghost', onclick: () => d.close() }, 'Cancel'), ok));
    d.showModal();
    ok.focus();
  }

  // follow shows the request's progress on the card until the server
  // holding the certificate authority has published it.
  async function follow(r, owner) {
    S.asking = `Asking ${owner} to publish it…`;
    render();
    const req = await followRequest(r.request_id, (q) => {
      S.asking = q.state === 'running' ? `${owner} is publishing it…` : `Waiting for ${owner}…`;
      render();
    });
    S.asking = null;
    if (req && req.state === 'done') toast(`Every server now uses ${owner}’s certificate authority.`);
    else if (req && req.state === 'failed') toastError('The certificate authority wasn’t published', new Error(req.error || 'no reason given'));
    else toast(`${owner} hasn’t answered yet; this page shows it once it has.`);
    load();
  }

  // ---------- each server's side panel ----------
  serverPanels.push(({ s, part }) => {
    const rep = S.rep;
    if (!rep || !rep.on) return null;
    const v = (rep.servers || []).find((x) => x.node_id === s.node_id);
    if (!v) return null;
    const kids = [];
    if (!v.reported) {
      kids.push(el('p', { class: 'sv-panel__text' }, 'Its version doesn’t report its certificate.'));
    } else {
      let what;
      if (v.mode === 'off') what = ['It doesn’t serve HTTPS itself.'];
      else if (v.mode === 'files') what = v.ca_sha256 ? ['Your own certificate files, from ', fpEl(v.ca_sha256), '.'] : ['Your own certificate files, from a public certificate authority.'];
      else if (v.cluster) what = ['The cluster’s, ', fpEl(v.ca_sha256), '.'];
      else what = ['Its own, ', fpEl(v.ca_sha256), rep.published ? '. It takes the cluster’s within seconds.' : '.'];
      kids.push(el('p', { class: 'sv-panel__text' }, ...what));
      if (v.leaf_expires) kids.push(el('p', { class: 'sv-panel__text' }, 'Its certificate renews itself; this one is valid until ' + dayText(v.leaf_expires) + '.'));
      if (v.next_ca_sha256) kids.push(el('p', { class: 'sv-panel__text' }, 'It hands out the new certificate authority, ', fpEl(v.next_ca_sha256), ', with the one in use.'));
      if (v.problem) kids.push(el('p', { class: 'sv-panel__text sv-bad' }, cap(v.problem) + '.'));
      for (const w of v.warnings || []) kids.push(el('p', { class: 'sv-panel__text sv-warn' }, w));
    }
    return part('Certificate authority', ...kids);
  });
})();
