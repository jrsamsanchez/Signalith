// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0
// Settings > Metrics (admins): the scrape endpoint GET /metrics for
// Prometheus. Its settings (metrics.enabled, metrics.token_sha256 and
// metrics.allow in the registry, internal/config/settings.go) are saved
// with PUT api/settings like the Server tab's, and every server of a
// cluster shares them. The scrape token is made by the server and shown
// once, here; only its SHA-256 is saved. See docs/metrics.md.
'use strict';

(function () {
  const M = { view: null, seq: 0, token: '', sha: '' };
  const body = $('mt-body');
  const DOCS = 'https://github.com/jrsamsanchez/signalith/blob/main/docs/metrics.md';

  pageHooks.push((name) => {
    if (name === 'metrics' && can('admin')) load();
  });

  async function load() {
    const seq = ++M.seq;
    body.setAttribute('aria-busy', 'true');
    try {
      const v = await api('api/metrics');
      if (seq !== M.seq) return;
      M.view = v;
      render();
    } catch (e) {
      if (seq !== M.seq) return;
      body.replaceChildren(el('p', { class: 'mt-warn' }, icon('triangle-alert'), el('span', {}, sentence(e.message))));
    } finally {
      if (seq === M.seq) body.removeAttribute('aria-busy');
    }
  }

  function copyRow(id, value, label) {
    const box = el('input', { id, class: 'input mono', type: 'text', readonly: '', value, 'aria-label': label });
    box.addEventListener('focus', () => box.select());
    const copy = el('button', { type: 'button', class: 'btn btn--secondary btn--sm', 'aria-label': 'Copy ' + label.toLowerCase() }, icon('copy'), 'Copy');
    copy.addEventListener('click', async () => {
      try {
        await navigator.clipboard.writeText(value);
        toast('Copied.');
      } catch (_) {
        box.focus();
        box.select();
        toast('Press Ctrl+C (or ⌘C) to copy it.', null, { tone: 'info' });
      }
    });
    return el('div', { class: 'mt-copy' }, box, copy);
  }

  function snippet(url) {
    let host = url;
    let scheme = 'https';
    try {
      const u = new URL(url);
      host = u.host;
      scheme = u.protocol.replace(':', '');
    } catch (_) { /* shown as it is */ }
    return [
      'scrape_configs:',
      '  - job_name: signalith',
      '    scheme: ' + scheme,
      '    authorization:',
      '      credentials_file: /etc/prometheus/signalith-scrape-token',
      '    tls_config:',
      '      ca_file: /etc/prometheus/signalith-ca.pem',
      '    static_configs:',
      '      - targets: [\'' + host + '\']',
    ].join('\n');
  }

  function render() {
    const v = M.view;
    const editable = v.editable && !v.demo;
    const on = el('input', { type: 'checkbox', id: 'mt-enabled', checked: v.enabled, disabled: !editable });
    const allow = el('textarea', { id: 'mt-allow', class: 'textarea input mono', rows: '3', placeholder: '10.0.5.20\n10.0.5.0/24', disabled: !editable });
    allow.value = (v.allow || []).join('\n');
    const status = v.on ? 'On: GET /metrics answers scrapers that send the scrape token.'
      : v.demo ? 'Off: a public demo never answers scrapes.'
        : v.enabled && !v.token_set ? 'Off until a scrape token is saved.' : 'Off: GET /metrics answers 404.';

    const tokenRow = el('div', { class: 'mt-row' }, el('span', { class: 'label' }, 'Scrape token'));
    if (M.token) {
      tokenRow.append(copyRow('mt-token', M.token, 'The new scrape token'),
        el('p', { class: 'mt-warn' }, icon('triangle-alert'), el('span', {}, 'Copy it to the scraper now: it is shown only this once. Save to start using it' +
          (v.token_set ? '; the old token stops working then.' : '.'))));
    } else {
      const make = el('button', { type: 'button', class: 'btn btn--secondary btn--sm', id: 'mt-make', disabled: !editable }, icon('key-round'), v.token_set ? 'Replace token' : 'Create token');
      make.addEventListener('click', async () => {
        const restore = busy(make, 'Creating…');
        try {
          const r = await api('api/metrics/token', {});
          M.token = r.token;
          M.sha = r.sha256;
          render();
          const n = $('mt-token');
          if (n) n.focus();
        } catch (e) {
          restore();
          toast(sentence(e.message), null, { tone: 'danger' });
        }
      });
      tokenRow.append(el('div', { class: 'mt-actions' }, el('span', { class: 'mt-help' }, v.token_set ? 'A token is saved.' : 'No token yet.'), make));
    }
    tokenRow.append(el('p', { class: 'mt-help' }, 'Prometheus sends it as Authorization: Bearer. Signalith keeps only its SHA-256 fingerprint.'));

    const save = el('button', { type: 'button', class: 'btn btn--primary btn--sm', id: 'mt-save', disabled: !editable }, icon('check'), 'Save');
    save.addEventListener('click', async () => {
      const values = {
        'metrics.enabled': on.checked,
        'metrics.allow': allow.value.split(/[\s,]+/).map((x) => x.trim()).filter(Boolean),
      };
      if (M.sha) values['metrics.token_sha256'] = M.sha;
      const restore = busy(save, 'Saving…');
      try {
        await api('api/settings', { values }, 'PUT');
        M.token = '';
        M.sha = '';
        restore();
        toast('Saved.');
        await load();
      } catch (e) {
        restore();
        const fields = e.fields || {};
        const msg = Object.values(fields)[0] || (e.problems && e.problems[0]) || e.message;
        toast(sentence(msg), null, { tone: 'danger' });
      }
    });

    body.replaceChildren(
      el('p', { class: 'mt-help', id: 'mt-status' }, status),
      el('div', { class: 'mt-row' }, el('span', { class: 'label' }, 'Scrape address'), copyRow('mt-url', v.scrape_url, 'Scrape address'),
        v.warning ? el('p', { class: 'mt-warn' }, icon('triangle-alert'), el('span', {}, v.warning)) : null),
      el('label', { class: 'switch' }, on, el('span', {}, 'Answer scrapes')),
      tokenRow,
      el('div', { class: 'mt-row' }, el('label', { class: 'label', for: 'mt-allow' }, 'Scrapers’ addresses'), allow,
        el('p', { class: 'mt-help' }, 'One IP address or range per line. Empty: any address with the token.')),
      el('div', { class: 'mt-row' }, el('span', { class: 'label' }, 'Prometheus'),
        el('pre', { class: 'mt-snippet mono' }, snippet(v.scrape_url)),
        el('p', { class: 'mt-help' }, 'Put the token in the credentials file, and Signalith’s CA certificate, from /api/tls/ca.pem, in the ca_file (not needed with a certificate the scraper already trusts). ',
          el('a', { href: DOCS, target: '_blank', rel: 'noopener' }, 'The metrics guide'), ' lists every metric.')),
      v.editable ? el('div', { class: 'mt-actions' }, save) : el('p', { class: 'mt-help' }, 'This server has no settings file, so these settings can only be changed in signalith.yaml (metrics).'));
  }
}());
