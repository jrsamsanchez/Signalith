// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0
//
// Checks the web app's scripts the way a browser loads them: for each page
// (web/static/index.html, login.html), every <script src> is read in page
// order and run, as a classic script, in one shared global scope with a
// stand-in for the browser. It fails when a script is missing, does not
// parse, declares a top-level name another script of the page declares
// too (the browser then skips the whole second script), or uses a name
// nothing defines while it loads. Run by internal/repocheck's tests:
//   node .github/scripts/check-web-scripts.js
'use strict';
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const root = path.resolve(__dirname, '..', '..');
const staticDir = path.join(root, 'web', 'static');

// anything is a stand-in for every browser object: each property, call
// and new gives another stand-in, and it reads as an empty string or 0.
function anything() {
  const target = function () {};
  return new Proxy(target, {
    get(_, key) {
      if (key === Symbol.toPrimitive) return (hint) => (hint === 'number' ? 0 : '');
      if (key === Symbol.iterator) return function* () {};
      if (key === 'then') return undefined; // not a promise
      return anything();
    },
    set() { return true; },
    has() { return true; },
    apply() { return anything(); },
    construct() { return anything(); },
  });
}

// The globals a page's scripts may use without defining them: the
// browser's own. Everything else must come from the page's scripts.
const browserGlobals = [
  'window', 'self', 'globalThis', 'document', 'navigator', 'location', 'history', 'localStorage',
  'sessionStorage', 'fetch', 'Headers', 'Request', 'Response', 'FormData', 'URLSearchParams', 'Blob',
  'File', 'FileReader', 'AbortController', 'EventSource', 'WebSocket', 'MutationObserver',
  'ResizeObserver', 'IntersectionObserver', 'CustomEvent', 'Event', 'KeyboardEvent', 'MouseEvent',
  'HTMLElement', 'Element', 'Node', 'DOMParser', 'XMLSerializer', 'Image', 'Option', 'CSS',
  'getComputedStyle', 'matchMedia', 'requestAnimationFrame', 'cancelAnimationFrame', 'alert',
  'confirm', 'prompt', 'open', 'close', 'print', 'scrollTo', 'scrollBy', 'crypto', 'performance',
  'screen', 'devicePixelRatio', 'innerWidth', 'innerHeight', 'PublicKeyCredential',
  'CredentialsContainer', 'Notification', 'BroadcastChannel', 'Worker', 'indexedDB', 'caches',
  'queueMicrotask', 'structuredClone', 'btoa', 'atob', 'TextEncoder', 'TextDecoder', 'URL',
  'customElements', 'ClipboardItem', 'DOMRect', 'Range', 'Selection', 'getSelection', 'NodeFilter',
  'HTMLInputElement', 'HTMLSelectElement', 'HTMLTextAreaElement', 'HTMLFormElement', 'SVGElement',
  'ShadowRoot', 'DocumentFragment', 'Text', 'CanvasRenderingContext2D', 'Path2D', 'visualViewport',
  'origin', 'isSecureContext', 'onload', 'onerror', 'addEventListener', 'removeEventListener',
  'dispatchEvent', 'setTimeout', 'clearTimeout', 'setInterval', 'clearInterval',
];

function scriptsOf(page) {
  const html = fs.readFileSync(path.join(staticDir, page), 'utf8');
  const out = [];
  const re = /<script\b[^>]*\bsrc="([^"]+)"[^>]*>/g;
  let m;
  while ((m = re.exec(html)) !== null) {
    const src = m[1].split('?')[0];
    if (/^(https?:)?\/\//.test(src)) {
      throw new Error(`${page}: loads ${src} from another site; the app serves every script itself`);
    }
    out.push(src.replace(/^\//, ''));
  }
  return out;
}

function checkPage(page) {
  const problems = [];
  const sandbox = {};
  for (const name of browserGlobals) sandbox[name] = anything();
  // Timers never fire, so only what runs while a script loads is checked.
  for (const name of ['setTimeout', 'setInterval', 'requestAnimationFrame', 'queueMicrotask']) sandbox[name] = () => 0;
  // Real values where a page computes with them while it loads.
  Object.assign(sandbox, { console, JSON, Math, Date, Promise, URL, URLSearchParams, TextEncoder, TextDecoder, Intl });
  const ctx = vm.createContext(sandbox);
  for (const name of ['window', 'self', 'globalThis']) {
    vm.runInContext(`var ${name} = this;`, ctx);
  }
  const scripts = scriptsOf(page);
  if (scripts.length === 0) problems.push(`${page}: no scripts found`);
  for (const src of scripts) {
    const file = path.join(staticDir, src);
    if (!fs.existsSync(file)) {
      problems.push(`${page}: ${src} does not exist`);
      continue;
    }
    const code = fs.readFileSync(file, 'utf8');
    let script;
    try {
      script = new vm.Script(code, { filename: `web/static/${src}` });
    } catch (e) {
      problems.push(`${page}: web/static/${src}: ${e.name}: ${e.message}\n${firstFrame(e)}`);
      continue;
    }
    try {
      script.runInContext(ctx, { timeout: 5000 });
    } catch (e) {
      // A stand-in can make code that is fine in a browser throw (a
      // TypeError, say); only names that do not exist, and names declared
      // twice, are mistakes in the scripts themselves.
      const name = e && e.constructor && e.constructor.name;
      if (name === 'ReferenceError' || name === 'SyntaxError') {
        problems.push(`${page}: web/static/${src}: ${name}: ${e.message}\n${firstFrame(e)}`);
      }
    }
  }
  return { scripts: scripts.length, problems };
}

function firstFrame(e) {
  const line = String(e && e.stack || '').split('\n').find((l) => l.includes('web/static/'));
  return line ? '    ' + line.trim() : '';
}

let failed = false;
for (const page of ['index.html', 'login.html']) {
  const { scripts, problems } = checkPage(page);
  console.log(`${page}: ${scripts} scripts loaded`);
  for (const p of problems) {
    console.error(p);
    failed = true;
  }
}
process.exit(failed ? 1 : 0);
