// Add data: Okta. Signalith reads the organization's System Log itself,
// from Okta's System Log API, once an API service app is entered in
// Settings > Okta. Nothing is installed. The steps add that app; below
// them, how far the System Log has been read (api/health's okta).
// oktaOpen is the way in.
(() => {
  'use strict';

  const o = { h: null, ticker: null, busy: false, tried: 0, failed: '' };
  const body = () => $('okta-body');
  const shown = () => currentPage === 'data' && !$('okta-setup').classList.contains('hidden');
  const code = (t) => el('code', {}, t);
  const b = (t) => el('b', {}, t);
  const text = (...parts) => el('p', { class: 'agent-step__text' }, ...parts);
  const step = (n, ...parts) => el('li', { class: 'agent-step' }, el('span', { class: 'agent-step__num' }, n),
    el('div', { class: 'agent-step__body' }, ...parts.filter(Boolean)));

  async function oktaOpen() {
    if (!o.ticker) o.ticker = setInterval(tick, 1000);
    await poll();
  }
  window.oktaOpen = oktaOpen;

  function tick() {
    if (!shown()) {
      clearInterval(o.ticker);
      o.ticker = null;
      return;
    }
    if (!document.hidden && Date.now() - o.tried >= 15000) poll();
  }

  async function poll() {
    if (o.busy) return;
    o.busy = true;
    o.tried = Date.now();
    try {
      o.h = await api('api/health');
      o.failed = '';
    } catch (e) {
      if (!o.h) o.failed = e.message || 'The Signalith server did not respond.';
    } finally {
      o.busy = false;
    }
    render();
  }

  // openSettings shows Settings at its Okta section.
  function openSettings() {
    showPage('settings');
    const until = Date.now() + 8000;
    const find = () => {
      const sec = document.querySelector('#st-main .st-card[id$="okta"]');
      if (sec) {
        sec.scrollIntoView({ block: 'start' });
        const title = sec.querySelector('.st-card__title');
        if (title) title.focus({ preventScroll: true });
      } else if (Date.now() < until) setTimeout(find, 150);
    };
    find();
  }

  function status() {
    const s = o.h && o.h.okta;
    if (o.failed) return dxAlert('danger', 'Couldn’t check the System Log', o.failed);
    if (!o.h) return null;
    if (!s) return dxAlert('info', 'Not set up yet', 'Once the Okta domain, the app and its key are saved in Settings, Signalith starts reading within a minute.');
    if (s.error) return dxAlert('warning', 'Couldn’t check the System Log', s.error);
    if (!s.last_run) return dxAlert('info', 'Starting', 'The settings are saved. The first read starts within a minute and goes back 24 hours.');
    const read = s.until ? el('span', { title: new Date(s.until).toLocaleString() }, ago(s.until)) : 'nothing yet';
    const facts = el('ul', { class: 'st-problems' },
      el('li', {}, b(s.domain), ': read up to ', read),
      el('li', {}, 'Last look ', el('span', { title: new Date(s.last_run).toLocaleString() }, ago(s.last_run)), ', with ',
        String(s.last_records || 0), s.last_records === 1 ? ' new event' : ' new events'),
      s.last_error ? el('li', { class: 'field-error' }, s.last_error) : null);
    return dxAlert(s.last_error ? 'warning' : 'success', s.last_error ? 'Reading, with problems' : 'Reading the System Log', null, facts);
  }

  function render() {
    const box = body();
    box.removeAttribute('aria-busy');
    const steps = el('ol', { class: 'agent-steps', role: 'list' },
      step(1, text('In the ', b('Okta Admin Console'), ', open ', b('Applications > Applications'), ' and choose ', b('Create App Integration'),
        '. Pick ', b('API Services'), ' and name it ', code('Signalith'), '.')),
      step(2, text('On the app’s ', b('General'), ' tab, edit ', b('Client Credentials'), ': choose ', b('Public key / Private key'),
        ', then ', b('Add key'), ' > ', b('Generate new key'), '. Copy the private key (', b('PEM'), ' or the JSON shown) before you close the box: Okta shows it only once.')),
      step(3, text('On the ', b('Okta API Scopes'), ' tab, grant ', code('okta.logs.read'), '. On the ', b('Admin roles'), ' tab, give the app ',
        b('Read-only Administrator'), '.')),
      step(4, text('In Signalith’s ', b('Settings > Okta'), ', enter your Okta domain (such as ', code('example.okta.com'), '), the app’s ',
        b('Client ID'), ' and the private key, choose ', b('Test'), ', then save.'),
        el('div', {}, el('button', { class: 'btn btn--secondary btn--sm', type: 'button', onclick: openSettings }, icon('settings'), 'Open Settings'))));
    box.replaceChildren(steps, status(),
      el('p', { class: 'hint' }, icon('info'), el('span', {}, 'Events arrive within a minute or two of happening. The ',
        el('a', { href: 'https://github.com/jrsamsanchez/Signalith/blob/main/docs/okta.md', target: '_blank', rel: 'noopener' }, 'Okta guide'),
        ' has the details, and how to use an API token instead.')));
  }
})();
