// Chat accounts: linking a Slack or Teams account to the signed-in user,
// so that their clicks on the buttons in Signalith's messages count as
// theirs. Slack sends an unlinked user a link to #chat-link/<token>,
// which this page confirms; Teams users make a code here and send it to
// the Signalith app. The account menu's Chat accounts lists and removes
// the user's links. docs/notifications.md describes the whole flow.
'use strict';

(function () {
  const LINK_HASH = /^#chat-link\/([0-9a-fA-F]{64})$/;
  // Read before the app picks the first page, which replaces the address.
  let pending = (location.hash.match(LINK_HASH) || [])[1] || '';

  const item = $('chat-open');
  item.addEventListener('click', () => {
    $('user-menu').removeAttribute('open');
    openAccounts();
  });
  meReady.then((m) => {
    if (!m) return;
    // An API token is not a person who clicks buttons.
    item.classList.toggle('hidden', m.auth === 'token');
    if (pending) confirmLink(takePending());
  });
  window.addEventListener('hashchange', () => {
    const t = (location.hash.match(LINK_HASH) || [])[1];
    if (!t) return;
    pending = t;
    meReady.then((m) => { if (m) confirmLink(takePending()); });
  });

  // takePending returns the link's token and takes it out of the address,
  // so it is not kept in the history or shown again on reload.
  function takePending() {
    const t = pending;
    pending = '';
    if (LINK_HASH.test(location.hash)) {
      try { history.replaceState(null, '', '#' + (currentPage || 'dashboards')); } catch (_) { /* sandboxed */ }
    }
    return t;
  }

  const fmtDay = (t) => new Date(t).toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
  const footer = (...kids) => el('div', { class: 'modal__foot' }, ...kids);
  const closeBtn = (d, text) => el('button', { type: 'button', class: 'btn btn--ghost', onclick: () => d.close() }, text || 'Cancel');

  // ---------- #chat-link/<token> ----------
  async function confirmLink(token) {
    const d = modalDialog('chat-link-dialog');
    d.classList.add('chat-dialog');
    const close = () => d.close();
    const head = (desc) => modalHead('chat-link-dialog', 'Link your chat account', desc, close);
    fill(d, head(''), el('div', { class: 'modal__body' }, dxSkel('80%'), el('div', { class: 'u-skel-gap' }), dxSkel('50%')));
    if (!d.open) d.showModal();
    let info;
    try {
      info = await api('api/chat/link/check', { token });
    } catch (e) {
      fill(d, head(''), el('div', { class: 'modal__body' }, dxEmpty({ tone: 'danger', icon: 'circle-alert', title: 'This link doesn’t work', text: sentence(e.message) })),
        footer(closeBtn(d, 'Close')));
      return;
    }
    const who = (me && (me.name || me.username)) || 'you';
    const err = formAlert();
    const ok = el('button', { type: 'button', class: 'btn btn--primary' }, icon('link'), 'Link account');
    const warn = info.linked_to && info.linked_to !== (me && me.username)
      ? dxAlert('warning', `It is linked to ${info.linked_to} now.`, `Linking it to you replaces that link: its clicks count as yours from then on.`) : null;
    fill(d, head(`Your clicks in ${info.system_label} will count as ${who}.`),
      el('div', { class: 'modal__body chat-body' }, err,
        el('div', { class: 'chat-who' },
          el('span', { class: 'chat-mark', 'aria-hidden': 'true' }, icon(info.system === 'slack' ? 'hash' : 'message-square-text')),
          el('div', {}, el('b', {}, info.account), el('span', {}, `will act as the Signalith user ${me ? me.username : ''}`))),
        warn,
        el('p', { class: 'hint' }, 'Only link an account that is yours. If you didn’t just click a button in chat, close this page. ',
          'Buttons only do what your Signalith role allows, and each click is in the audit log.')),
      footer(closeBtn(d), ok));
    ok.focus();
    ok.addEventListener('click', async () => {
      err.classList.add('hidden');
      const restore = busy(ok, 'Linking…');
      try {
        await api('api/chat/link', { token });
      } catch (e) {
        restore();
        showAlert(err, 'Your account was not linked.', sentence(e.message));
        return;
      }
      close();
      toast(`Go back to ${info.system_label} and click the button again.`, null, { title: `Linked ${info.account}` });
    });
  }

  // ---------- account menu: Chat accounts ----------
  async function openAccounts() {
    const d = modalDialog('chat-accounts-dialog');
    d.classList.add('chat-dialog');
    const close = () => d.close();
    const head = modalHead('chat-accounts-dialog', 'Chat accounts', 'Slack and Teams accounts whose button clicks count as yours.', close);
    fill(d, head, el('div', { class: 'modal__body' }, dxSkel('100%'), el('div', { class: 'u-skel-gap' }), dxSkel('60%')));
    if (!d.open) d.showModal();
    let list;
    try {
      list = (await api('api/chat/accounts')).accounts || [];
    } catch (e) {
      fill(d, head, el('div', { class: 'modal__body' }, dxEmpty({ tone: 'danger', icon: 'circle-alert', title: 'Couldn’t load your chat accounts', text: sentence(e.message), action: dxRetry(openAccounts) })));
      return;
    }
    const rows = list.map((l) => {
      const rm = el('button', { type: 'button', class: 'btn btn--ghost btn--sm' }, icon('unlink'), 'Unlink');
      rm.addEventListener('click', async () => {
        const restore = busy(rm, 'Unlinking…');
        try {
          await api('api/chat/accounts/' + encodeURIComponent(l.id), undefined, 'DELETE');
        } catch (e) {
          restore();
          toastError('Couldn’t unlink', e);
          return;
        }
        toast(`Unlinked ${l.account}.`);
        openAccounts();
      });
      return el('li', { class: 'chat-acct' },
        el('span', { class: 'chat-mark chat-mark--sm', 'aria-hidden': 'true' }, icon(l.system === 'slack' ? 'hash' : 'message-square-text')),
        el('div', { class: 'chat-acct__text' }, el('b', {}, l.account), el('span', {}, 'Linked ' + fmtDay(l.created))), rm);
    });
    const code = el('div', { class: 'chat-code', 'aria-live': 'polite' });
    const make = el('button', { type: 'button', class: 'btn btn--secondary' }, icon('message-square-text'), 'Link a Teams account');
    make.addEventListener('click', async () => {
      const restore = busy(make, 'Making a code…');
      let r;
      try {
        r = await api('api/chat/code', {});
      } catch (e) {
        restore();
        fill(code, dxAlert('danger', 'No code was made.', sentence(e.message)));
        return;
      }
      restore();
      fill(code, el('p', {}, 'In the Teams channel the Signalith app posts to, send this message:'),
        el('div', { class: 'chat-code__msg' }, el('code', {}, `@Signalith link ${r.code}`)),
        el('p', { class: 'hint' }, `The code works once, for ${r.minutes} minutes. Then refresh this list.`));
    });
    fill(d, head,
      el('div', { class: 'modal__body chat-body' },
        rows.length ? el('ul', { class: 'chat-accts' }, ...rows)
          : el('p', { class: 'chat-none' }, 'None yet. The first time you click a button in a Slack message, Signalith sends you a link to connect your account.'),
        el('div', { class: 'chat-teams' }, make, code)),
      footer(closeBtn(d, 'Done')));
  }
})();
