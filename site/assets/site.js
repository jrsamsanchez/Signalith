// Signalith website: theme switch, nav, product tour, install tabs, copy buttons,
// the hero's event floor and reveal-on-scroll. No dependencies.
'use strict';

const root = document.documentElement;
const reduced = matchMedia('(prefers-reduced-motion: reduce)').matches;

// Theme -----------------------------------------------------------------------
function currentTheme() {
  return root.dataset.theme || (matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
}
document.querySelectorAll('[data-theme-toggle]').forEach((b) => b.addEventListener('click', () => {
  const next = currentTheme() === 'dark' ? 'light' : 'dark';
  root.dataset.theme = next;
  try { localStorage.setItem('signalith.theme', next); } catch (_) { /* ignore */ }
}));

// Nav: solid once scrolled past the top, menu on phones ----------------------
const nav = document.querySelector('[data-nav]');
const menuBtn = document.querySelector('[data-menu]');
const mobile = document.getElementById('mobile-nav');
const onScroll = () => nav.classList.toggle('is-scrolled', scrollY > 24);
addEventListener('scroll', onScroll, { passive: true });
onScroll();
function setMenu(open) {
  mobile.hidden = !open;
  menuBtn.setAttribute('aria-expanded', String(open));
  nav.classList.toggle('is-open', open);
}
menuBtn.addEventListener('click', () => setMenu(mobile.hidden));
mobile.addEventListener('click', (e) => { if (e.target.closest('a')) setMenu(false); });
addEventListener('keydown', (e) => { if (e.key === 'Escape' && !mobile.hidden) { setMenu(false); menuBtn.focus(); } });

// Tabs (shared by the tour and the install steps) -----------------------------
function tabs(list, onSelect) {
  const items = [...list.querySelectorAll('[role="tab"]')];
  const select = (tab, focus) => {
    items.forEach((t) => {
      const on = t === tab;
      t.setAttribute('aria-selected', String(on));
      t.tabIndex = on ? 0 : -1;
    });
    if (focus) tab.focus();
    onSelect(tab);
  };
  items.forEach((t, i) => {
    t.addEventListener('click', () => select(t));
    t.addEventListener('keydown', (e) => {
      const d = { ArrowRight: 1, ArrowLeft: -1 }[e.key];
      if (d) { e.preventDefault(); select(items[(i + d + items.length) % items.length], true); }
      if (e.key === 'Home') { e.preventDefault(); select(items[0], true); }
      if (e.key === 'End') { e.preventDefault(); select(items[items.length - 1], true); }
    });
  });
}

const tourList = document.querySelector('.tour__tabs');
const tourImg = document.querySelector('[data-tour-img]');
const tourCap = document.querySelector('[data-tour-cap]');
const tourPanel = document.getElementById('p-tour');
const alts = {
  findings: 'The Signalith Findings page: a queue of findings with severity, status and owner, and an inspector panel for the selected finding.',
  search: 'The Signalith Search page: a plain-English question box, a query, a timeline and a table of results.',
  dashboard: 'The Signalith Security posture dashboard: key numbers, findings by hour, top detections and top risk objects.',
  investigation: 'A Signalith investigation case with its timeline of notes and findings, and its details.',
  intel: 'The Signalith threat intel feed catalog with free feeds to add.',
  security: 'The Signalith Security page listing what to fix first and whether data is encrypted in transit.',
};
// warm the cache so switching is instant
addEventListener('load', () => Object.keys(alts).forEach((k) => { const i = new Image(); i.src = `assets/shots/${k}.webp`; }));
tabs(tourList, (tab) => {
  const k = tab.dataset.shot;
  tourPanel.setAttribute('aria-labelledby', tab.id);
  tourCap.textContent = tab.dataset.cap;
  tourImg.classList.add('is-loading');
  const done = () => tourImg.classList.remove('is-loading');
  tourImg.addEventListener('load', done, { once: true });
  tourImg.srcset = `assets/shots/${k}-720.webp 720w, assets/shots/${k}.webp 1440w`;
  tourImg.src = `assets/shots/${k}.webp`;
  tourImg.alt = alts[k];
  if (tourImg.complete) done();
});

const startList = document.querySelector('.start__tabs');
tabs(startList, (tab) => {
  document.querySelectorAll('.start__panel').forEach((p) => { p.hidden = p.id !== tab.getAttribute('aria-controls'); });
});

// Copy buttons ------------------------------------------------------------------
document.querySelectorAll('.copy').forEach((b) => b.addEventListener('click', async () => {
  const text = b.parentElement.querySelector('code').innerText;
  try {
    await navigator.clipboard.writeText(text);
  } catch (_) {
    const r = document.createRange(); r.selectNodeContents(b.parentElement.querySelector('code'));
    const s = getSelection(); s.removeAllRanges(); s.addRange(r); return;
  }
  const use = b.querySelector('use');
  b.classList.add('is-done'); use.setAttribute('href', '#i-check'); b.setAttribute('aria-label', 'Copied');
  setTimeout(() => { b.classList.remove('is-done'); use.setAttribute('href', '#i-copy'); b.setAttribute('aria-label', 'Copy'); }, 1600);
}));

// Hero floor: a field of event noise with one lit bar, the signal ----------------
const floor = document.querySelector('[data-floor]');
if (floor) {
  const n = 56, lit = 28;
  const bars = [];
  for (let i = 0; i < n; i++) {
    const b = document.createElement('i');
    if (i === lit) b.className = 'lit';
    b.style.setProperty('--h', i === lit ? '100%' : `${18 + Math.round(Math.random() * 38)}%`);
    floor.appendChild(b); bars.push(b);
  }
  if (!reduced) {
    setInterval(() => {
      if (document.hidden) return;
      for (let k = 0; k < 6; k++) {
        const i = Math.floor(Math.random() * n);
        if (i !== lit) bars[i].style.setProperty('--h', `${18 + Math.round(Math.random() * 38)}%`);
      }
    }, 900);
  }
}

// Reveal on scroll ------------------------------------------------------------
const revealables = document.querySelectorAll('.section__head, .card, .split > *, .flow, .built, .start, .facts__in > div');
if ('IntersectionObserver' in window && !reduced) {
  const io = new IntersectionObserver((entries) => entries.forEach((e) => {
    if (e.isIntersecting) { e.target.classList.add('is-in'); io.unobserve(e.target); }
  }), { rootMargin: '0px 0px -8% 0px' });
  revealables.forEach((el, i) => {
    el.setAttribute('data-reveal', '');
    if (el.classList.contains('card')) el.style.transitionDelay = `${(i % 3) * 70}ms`;
    io.observe(el);
  });
}
