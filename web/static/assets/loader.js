// Reloads the page when one of its scripts or stylesheets fails to load.
// The server names them under v/<version>/, which only a server of that
// version serves: behind a load balancer during an upgrade, a page from
// one version may ask a server of another for them, and get a 404. A
// reload gets a page and files from one server again. After 5 tries in a
// row the page says why it may not work. This file is loaded by its plain
// path, so a server of any version serves it.
'use strict';
(function () {
  const KEY = 'signalith.loadRetries';
  const MAX = 5;
  let failed = false;
  const count = () => {
    try { return Number(sessionStorage.getItem(KEY)) || 0; } catch (_) { return -1; }
  };
  const note = () => {
    const show = () => {
      if (document.getElementById('upgrade-note')) return;
      const meta = document.querySelector('meta[name="signalith-version"]');
      const v = meta ? meta.content : '';
      const div = document.createElement('div');
      div.id = 'upgrade-note';
      div.setAttribute('role', 'alert');
      div.textContent = 'Signalith is being upgraded; some pages may not work until every server runs the same version as this page' +
        (v ? ' (' + v + ')' : '') + '. Reload the page in a minute.';
      // Styled here: the stylesheet may be what failed to load.
      Object.assign(div.style, {
        position: 'fixed', left: '16px', right: '16px', top: '16px', zIndex: '1000', padding: '12px 14px',
        borderRadius: '8px', background: '#7a1d1d', color: '#fff', font: '14px/1.4 system-ui, sans-serif',
      });
      document.body.append(div);
    };
    if (document.body) show();
    else document.addEventListener('DOMContentLoaded', show);
  };
  addEventListener('error', (ev) => {
    const t = ev.target;
    if (failed || !t || (t.tagName !== 'SCRIPT' && t.tagName !== 'LINK')) return;
    if (t.tagName === 'LINK' && t.rel !== 'stylesheet') return;
    failed = true;
    const n = count();
    if (n < 0 || n >= MAX) { note(); return; } // without storage, no loop guard: never reload
    try { sessionStorage.setItem(KEY, String(n + 1)); } catch (_) { note(); return; }
    setTimeout(() => location.reload(), 1000 * (n + 1));
  }, true);
  addEventListener('load', () => {
    if (!failed) try { sessionStorage.removeItem(KEY); } catch (_) { /* storage may be blocked */ }
  });
}());
