// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0
// Add data: Microsoft 365. Signalith reads the tenant's audit log itself,
// from Microsoft's Office 365 Management Activity API, once an app
// registered in Entra ID is entered in Settings > Microsoft 365. Nothing
// is installed. The steps register that app; below them, how far the
// audit log has been read (api/health's m365). m365Open is the way in.
(() => {
  'use strict';

  const m = { h: null, ticker: null, busy: false, tried: 0, failed: '' };
  const body = () => $('m365-body');
  const shown = () => currentPage === 'data' && !$('m365-setup').classList.contains('hidden');
  const code = (t) => el('code', {}, t);
  const b = (t) => el('b', {}, t);
  const text = (...parts) => el('p', { class: 'agent-step__text' }, ...parts);
  const step = (n, ...parts) => el('li', { class: 'agent-step' }, el('span', { class: 'agent-step__num' }, n),
    el('div', { class: 'agent-step__body' }, ...parts.filter(Boolean)));
  const NAMES = { 'Audit.AzureActiveDirectory': 'Sign-ins', 'Audit.Exchange': 'Exchange', 'Audit.SharePoint': 'SharePoint and OneDrive', 'Audit.General': 'Teams, Power Platform and the rest' };

  async function m365Open() {
    if (!m.ticker) m.ticker = setInterval(tick, 1000);
    await poll();
  }
  window.m365Open = m365Open;

  function tick() {
    if (!shown()) {
      clearInterval(m.ticker);
      m.ticker = null;
      return;
    }
    if (!document.hidden && Date.now() - m.tried >= 15000) poll();
  }

  async function poll() {
    if (m.busy) return;
    m.busy = true;
    m.tried = Date.now();
    try {
      m.h = await api('api/health');
      m.failed = '';
    } catch (e) {
      if (!m.h) m.failed = e.message || 'The Signalith server did not respond.';
    } finally {
      m.busy = false;
    }
    render();
  }

  // openSettings shows Settings at its Microsoft 365 section.
  function openSettings() {
    showPage('settings');
    const until = Date.now() + 8000;
    const find = () => {
      const sec = document.querySelector('#st-main .st-card[id$="m365"]');
      if (sec) {
        sec.scrollIntoView({ block: 'start' });
        const title = sec.querySelector('.st-card__title');
        if (title) title.focus({ preventScroll: true });
      } else if (Date.now() < until) setTimeout(find, 150);
    };
    find();
  }

  function status() {
    const s = m.h && m.h.m365;
    if (m.failed) return dxAlert('danger', 'Couldn’t check the audit log', m.failed);
    if (!m.h) return null;
    if (!s) return dxAlert('info', 'Not set up yet', 'Once the tenant, app and secret are saved in Settings, Signalith starts reading within a few minutes.');
    if (s.error) return dxAlert('warning', 'Couldn’t check the audit log', s.error);
    const types = s.content_types || [];
    if (!types.length) return dxAlert('info', 'Starting', 'The settings are saved. The first read starts within five minutes, and Microsoft can take up to 12 hours to make a new subscription’s first records available.');
    const errs = types.filter((t) => t.last_error);
    const rows = types.map((t) => el('li', {}, b(NAMES[t.content_type] || t.content_type), ': read up to ',
      el('span', { title: new Date(t.until).toLocaleString() }, ago(t.until)),
      t.last_error ? el('span', { class: 'field-error' }, ' (', t.last_error, ')') : null));
    return dxAlert(errs.length ? 'warning' : 'success', errs.length ? 'Reading, with problems' : 'Reading the audit log',
      null, el('ul', { class: 'st-problems' }, ...rows));
  }

  function render() {
    const box = body();
    box.removeAttribute('aria-busy');
    const steps = el('ol', { class: 'agent-steps', role: 'list' },
      step(1, text('In the ', b('Microsoft Entra admin center'), ', open ', b('App registrations'), ' and choose ', b('New registration'),
        '. Name it ', code('Signalith'), ' and keep ', b('Accounts in this organizational directory only'), '.')),
      step(2, text('On the app’s ', b('API permissions'), ': ', b('Add a permission'), ' > ', b('Office 365 Management APIs'), ' > ',
        b('Application permissions'), ' > ', code('ActivityFeed.Read'), '. Then choose ', b('Grant admin consent'), '.')),
      step(3, text('On ', b('Certificates & secrets'), ', make a ', b('New client secret'), ' and copy its ', b('Value'), '.')),
      step(4, text('Check auditing is on: in ', b('Microsoft Purview'), ' > ', b('Audit'), ', there is no ', b('Start recording'), ' button.')),
      step(5, text('In Signalith’s ', b('Settings > Microsoft 365'), ', enter the ', b('Directory (tenant) ID'), ' and ', b('Application (client) ID'),
        ' from the app’s Overview page and the secret, choose ', b('Test'), ', then save.'),
        el('div', {}, el('button', { class: 'btn btn--secondary btn--sm', type: 'button', onclick: openSettings }, icon('settings'), 'Open Settings'))));
    box.replaceChildren(steps, status(),
      el('p', { class: 'hint' }, icon('info'), el('span', {}, 'Records arrive 30 minutes to a few hours after they happen: Microsoft’s own delay. The ',
        el('a', { href: 'https://github.com/jrsamsanchez/Signalith/blob/main/docs/microsoft-365.md', target: '_blank', rel: 'noopener' }, 'Microsoft 365 guide'),
        ' has the details.')));
  }
})();
