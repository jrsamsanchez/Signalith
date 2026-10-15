// Servers page: draining, removing and moving work between servers, and
// rotating the cluster key. Each server's side panel (serverPanels) gets
// a part with Drain or Resume, Move the background jobs here, and Remove
// from the cluster; a card under the list of servers shows the cluster
// key and the servers removed, with Rotate cluster key. Everything comes
// from api/cluster/lifecycle; each change is a request another server
// runs, followed with followRequest.
'use strict';

(function () {
  const REFRESH_MS = 15000;
  const S = { lc: null, off: '', at: 0, busy: false, seq: 0, ticker: null, failed: null, rotating: null };
  // REMOVE_AFTER_MIN matches api.RemoveAfter.
  const REMOVE_AFTER_MIN = 10;
  const plural = (n, one, many) => `${n.toLocaleString()} ${n === 1 ? one : many}`;
  const short = (fp) => (fp || '').split(':').slice(0, 8).join(':') + (fp ? '…' : '');

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
      const d = await api('api/cluster/lifecycle');
      if (seq !== S.seq) return;
      S.lc = d.on ? d.lifecycle : null;
      S.off = d.on ? '' : d.off || '';
      S.failed = null;
    } catch (e) {
      if (seq !== S.seq) return;
      S.failed = e;
    } finally {
      S.busy = false;
    }
    render();
  }

  // run asks for a change and follows the request it makes, with a
  // toast for how it went.
  async function run(path, method, body, doing, done) {
    let res;
    try {
      res = await api(path, body, method);
    } catch (e) {
      toast(e.message || 'The server did not answer.', null, { tone: 'danger', title: 'Couldn’t ' + doing });
      return null;
    }
    if (res && res.request_id) {
      const rq = await followRequest(res.request_id);
      if (rq && rq.state === 'failed') {
        toast(rq.error || 'No reason given.', null, { tone: 'danger', title: 'Couldn’t ' + doing });
        load();
        return res;
      }
    }
    if (done) toast(typeof done === 'function' ? done(res) : done);
    load();
    return res;
  }

  // ---------- the side panel ----------
  serverPanels.push(({ s, part }) => {
    if (!S.lc || !s.node_id) return null;
    const feats = s.features || [];
    const gone = s.state === 'offline' || s.state === 'stopped';
    const draining = s.state === 'draining';
    const kids = [];
    const buttons = [];
    const canDrain = feats.includes('drain');
    if (!gone) {
      if (draining) {
        kids.push(el('p', { class: 'sv-panel__text' }, `${s.name} is drained: it tells load balancers it doesn’t want traffic and doesn’t run the background jobs. It can be stopped or removed safely.`));
        buttons.push(el('button', { type: 'button', class: 'btn btn--secondary btn--sm', 'data-focus': 'resume', disabled: !canDrain,
          onclick: () => run(`api/cluster/servers/${encodeURIComponent(s.node_id)}/resume`, null, 'POST', 'resume ' + s.name, `${s.name} takes traffic again.`) },
        icon('play'), 'Resume'));
      } else {
        kids.push(el('p', { class: 'sv-panel__text' }, canDrain
          ? `Drain ${s.name} before you stop it for maintenance or remove it: it stops taking traffic from load balancers and hands the background jobs to another server.`
          : `${s.name} runs a version that can’t be drained. Upgrade it first.`));
        buttons.push(el('button', { type: 'button', class: 'btn btn--secondary btn--sm', 'data-focus': 'drain', disabled: !canDrain,
          onclick: () => run(`api/cluster/servers/${encodeURIComponent(s.node_id)}/drain`, null, 'POST', 'drain ' + s.name, `${s.name} is drained.`) },
        icon('power'), 'Drain'));
      }
      if (s.jobs === 'standby' && s.state === 'ready') {
        buttons.push(el('button', { type: 'button', class: 'btn btn--secondary btn--sm', 'data-focus': 'move',
          onclick: () => run('api/cluster/jobs/move', { to: s.node_id }, 'POST', 'move the background jobs', `The background jobs move to ${s.name}.`) },
        icon('arrow-right'), 'Run the background jobs here'));
      }
    }
    if (!s.self) {
      const ago = s.seen_seconds_ago;
      const removable = draining || s.state === 'stopped' || (s.state === 'offline' && ago != null && ago >= REMOVE_AFTER_MIN * 60);
      buttons.push(el('button', { type: 'button', class: 'btn btn--danger btn--sm', 'data-focus': 'remove', disabled: !removable,
        title: removable ? '' : `Drain it or stop it first, or wait until it has been offline for ${REMOVE_AFTER_MIN} minutes.`,
        onclick: () => askRemove(s) }, icon('trash-2'), 'Remove from the cluster'));
    }
    if (!buttons.length) return null;
    kids.push(el('div', { class: 'sv-life__actions' }, ...buttons));
    return part('Maintenance', ...kids);
  });

  // askRemove confirms a removal, with the key rotation on by default.
  function askRemove(s) {
    const d = modalDialog('sv-life-remove');
    const rotate = el('input', { type: 'checkbox', id: 'sv-life-rotate' });
    rotate.checked = !!(S.lc && S.lc.rotation && S.lc.rotation.on);
    rotate.disabled = !rotate.checked;
    const close = () => d.close();
    const ok = el('button', { type: 'button', class: 'btn btn--danger', onclick: async () => {
      ok.disabled = true;
      close();
      const res = await run(`api/cluster/servers/${encodeURIComponent(s.node_id)}?rotate=${rotate.checked}`, null, 'DELETE', 'remove ' + s.name,
        (r) => (r && r.rotate_skipped ? `${s.name} was removed. ${r.rotate_skipped}` : `${s.name} was removed and the cluster key rotated.`));
      if (res && $('sv-panel') && $('sv-panel').open) $('sv-panel').close();
    } }, 'Remove ' + s.name);
    const why = rotate.disabled
      ? 'Rotating the cluster key needs every server on a version that supports it.'
      : `A new key goes to every other server; ${s.name}’s copy of the old one then opens nothing.`;
    fill(d, modalHead('sv-life-remove', `Remove ${s.name} from the cluster?`,
      'It leaves the list of servers and the keyring. To bring it back, give it the cluster key again.', close),
    el('div', { class: 'modal__body' },
      el('div', { class: 'field' }, el('label', { class: 'check' }, rotate, 'Rotate the cluster key (recommended)'),
        el('p', { class: 'hint' }, why))),
    el('div', { class: 'modal__foot' }, el('button', { type: 'button', class: 'btn btn--ghost', onclick: close }, 'Cancel'), ok));
    d.showModal();
    ok.focus();
  }

  // ---------- the card: cluster key and removed servers ----------
  function render() {
    const box = $('servers-life');
    if (!box) return;
    const lc = S.lc;
    if (!lc) {
      box.replaceChildren();
      return;
    }
    const a = document.activeElement;
    const focus = a && box.contains(a) && a.dataset ? a.dataset.focus : '';
    const rot = lc.rotation || {};
    const body = [];
    const facts = [['Active key', rot.active ? el('span', { class: 'mono' }, rot.active) : null],
      ['Servers holding it', plural((lc.members || []).length, 'server', 'servers')]];
    if (rot.catch_up_until) facts.push(['Offline servers catch up until', new Date(rot.catch_up_until).toLocaleString()]);
    body.push(el('dl', { class: 'ca-facts' }, ...facts.filter(([, v]) => v).map(([k, v]) => el('div', { class: 'ca-fact' }, el('dt', {}, k), el('dd', {}, v)))));
    if (rot.in_progress) {
      body.push(el('div', { class: 'alert', 'data-tone': 'info', role: 'status' }, icon('refresh-cw'),
        el('div', {}, el('b', {}, 'Rotating the cluster key'), el('p', {}, `Step: ${rot.in_progress.phase}. Started by ${rot.in_progress.started_by || 'an admin'}. Asked again, it goes on from here.`))));
    }
    const removed = (lc.removed || []).slice().reverse();
    if (removed.length) {
      body.push(el('h4', { class: 'section-title' }, 'Removed servers'),
        el('ul', { class: 'sv-panel__list', role: 'list' }, ...removed.slice(0, 10).map((r) => el('li', {},
          el('span', {}, r.name),
          el('span', { class: 'sv-panel__key' }, `${ago(r.at)} by ${r.by || 'an admin'}`),
          r.rotated ? null : el('span', { class: 'sv-panel__text sv-warn' }, 'its copy of the cluster key still works until the key is rotated'),
          r.fingerprint ? el('span', { class: 'mono sv-panel__key', title: r.fingerprint }, short(r.fingerprint)) : null))));
    }
    const busy = !!S.rotating || !!rot.in_progress;
    const btn = el('button', { type: 'button', class: 'btn btn--secondary btn--sm', 'data-focus': 'rotate', disabled: !rot.on || !!S.rotating,
      title: rot.on ? '' : 'Every server must run a version that supports it.', onclick: askRotate }, icon('key-round'),
    rot.in_progress ? 'Finish the rotation' : 'Rotate cluster key');
    body.push(el('div', { class: 'sv-life__actions' }, btn, busy && S.rotating ? el('span', { class: 'sv-panel__key' }, S.rotating) : null));
    fill(box, el('section', { class: 'card ca-card', 'aria-labelledby': 'sv-life-title' },
      el('div', { class: 'card__head' }, el('div', { class: 'ca-head' }, el('span', { class: 'ca-head__icon' }, icon('key-round')),
        el('div', {}, el('h3', { class: 'card__title', id: 'sv-life-title' }, 'Cluster key'),
          el('p', { class: 'card__sub' }, 'Every server signs and seals the shared settings with it. Rotate it after a server is removed or when a copy of it may have leaked.')))),
      el('div', { class: 'ca-body' }, ...body)));
    if (focus) {
      const n = box.querySelector(`[data-focus="${CSS.escape(focus)}"]`);
      if (n) n.focus({ preventScroll: true });
    }
  }

  async function askRotate() {
    if (!await caseConfirm({ title: 'Rotate the cluster key?',
      text: 'Every server gets a new key and signs everything again with it. Servers offline now catch up within 7 days of coming back; later than that, they need the key again.',
      confirm: 'Rotate key' })) return;
    S.rotating = 'Rotating…';
    render();
    try {
      let res;
      try {
        res = await api('api/cluster/rotate-key', null, 'POST');
      } catch (e) {
        toast(e.message || 'The server did not answer.', null, { tone: 'danger', title: 'Couldn’t rotate the cluster key' });
        return;
      }
      const rq = await followRequest(res.request_id, (r) => {
        const p = r.progress;
        S.rotating = p && p.total ? `Rotating: step ${Math.min(p.done + 1, p.total)} of ${p.total}…` : 'Rotating…';
        render();
      });
      if (rq && rq.state === 'failed') toast(rq.error || 'No reason given.', null, { tone: 'danger', title: 'Couldn’t rotate the cluster key' });
      else if (rq && rq.state === 'done') toast('The cluster key was rotated.');
    } finally {
      S.rotating = null;
      load();
    }
  }
})();
