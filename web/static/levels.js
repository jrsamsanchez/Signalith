// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0
// Features that wait for older servers. While servers run mixed versions
// during a rolling upgrade, a feature that comes with a newer cluster
// level stays off until every server runs a version that supports it.
// A control for such a feature carries data-feature="<name>" (the names
// of GET /api/cluster/features); this greys it out with "Available when
// every server runs 1.6.0 or later". The list is read at most once a
// minute. A failed read, or a server too old to have the route, leaves
// every control as it is: nothing is greyed out on doubt.
'use strict';

(function () {
  const EVERY = 60000;
  let cache = null; // { at, byName }
  let pending = null;

  async function load() {
    if (cache && Date.now() - cache.at < EVERY) return cache.byName;
    if (pending) return pending;
    pending = (async () => {
      try {
        const d = await api('api/cluster/features');
        const byName = {};
        for (const f of (d && d.features) || []) byName[f.name] = f;
        cache = { at: Date.now(), byName };
      } catch (_) {
        // Keep what was known; with nothing known, nothing is greyed.
        if (!cache) cache = { at: Date.now(), byName: {} };
        else cache.at = Date.now();
      }
      pending = null;
      return cache.byName;
    })();
    return pending;
  }

  // text is what a control says while its feature waits.
  function text(f) {
    let t = f.why || 'Available when every server runs a version that supports it';
    if (f.waiting && f.waiting.length) {
      t += ' (waiting for ' + f.waiting.map((w) => w.version ? `${w.name} on ${w.version}` : w.name).join(', ') + ')';
    }
    return t;
  }

  // get resolves to { on, text } for a feature; an unknown feature is on.
  async function get(name) {
    const f = (await load())[name];
    if (!f || f.on) return { on: true, text: '' };
    return { on: false, text: text(f) };
  }

  function mark(node, byName) {
    const f = byName[node.dataset.feature];
    const hint = node.nextElementSibling && node.nextElementSibling.classList.contains('feature-wait') ? node.nextElementSibling : null;
    if (!f || f.on) {
      if (node.dataset.featureWait) {
        // It waited before and is on now: give the control back as it
        // was, disabled if its page had it disabled.
        const wasDisabled = node.dataset.featurePrevDisabled === '1';
        const wasTitle = node.dataset.featurePrevTitle;
        delete node.dataset.featureWait;
        delete node.dataset.featurePrevDisabled;
        delete node.dataset.featurePrevTitle;
        node.disabled = wasDisabled;
        if (wasDisabled) node.setAttribute('aria-disabled', 'true');
        else node.removeAttribute('aria-disabled');
        if (wasTitle) node.title = wasTitle;
        else node.removeAttribute('title');
        if (hint) hint.remove();
      }
      return;
    }
    const t = text(f);
    if (!node.dataset.featureWait) {
      // What the page set, to give back once the feature is on.
      node.dataset.featurePrevDisabled = node.disabled ? '1' : '';
      if (node.title) node.dataset.featurePrevTitle = node.title;
    }
    node.dataset.featureWait = '1';
    node.disabled = true;
    node.setAttribute('aria-disabled', 'true');
    node.title = t;
    if (hint) hint.textContent = t;
    else node.after(el('span', { class: 'feature-wait' }, t));
  }

  // apply greys out the controls under root (the document by default)
  // whose feature waits.
  async function apply(root) {
    root = root || document;
    const nodes = [];
    if (root.matches && root.matches('[data-feature]')) nodes.push(root);
    if (root.querySelectorAll) nodes.push(...root.querySelectorAll('[data-feature]'));
    if (!nodes.length) return;
    const byName = await load();
    for (const n of nodes) mark(n, byName);
  }

  window.featureGate = { get, apply };

  // Pages redraw their cards: controls added later are marked too.
  const watch = new MutationObserver((records) => {
    for (const r of records) {
      for (const n of r.addedNodes) {
        if (n.nodeType === 1 && (n.matches('[data-feature]') || n.querySelector('[data-feature]'))) apply(n);
      }
    }
  });
  function start() {
    watch.observe(document.body, { childList: true, subtree: true });
    if (typeof pageHooks !== 'undefined') pageHooks.push(() => { apply(); });
    apply();
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start);
  else start();
})();
