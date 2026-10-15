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
  search: 'The Signalith Search page: a plain-English question turned into a query, with a timeline and a table of results.',
  dashboard: 'The Signalith Security posture dashboard: key numbers, new findings by urgency, top detections and top risk objects.',
  detections: 'The Signalith Detections page with the SigmaHQ and Splunk Security Content rule packs and the list of detections.',
  investigation: 'A Signalith investigation case with its timeline of notes and findings, and its details.',
  endpoints: 'The Signalith Endpoints page listing osquery hosts with their status, failing configuration checks and log agent.',
  vulnerabilities: 'The Signalith Vulnerabilities dashboard: hosts with known exploited and critical CVEs, and what to patch first.',
  malware: 'The Signalith Malware dashboard: hosts with malware, what the antivirus did, and the top threats.',
  intel: 'The Signalith threat intel feed catalog with free feeds to add.',
  network: 'The Signalith Network dashboard: IDS alerts, connections, data sent to the internet and alerts over time from Zeek and Suricata.',
  servers: 'The Signalith Servers page: three servers sharing one OpenSearch, one running the background jobs and two on standby, and the shared certificate authority.',
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

// Demo video: a big play button over the poster, native controls once playing.
const demo = document.querySelector('[data-demo]');
if (demo) {
  const video = demo.querySelector('video');
  const play = demo.querySelector('[data-demo-play]');
  video.controls = false;
  play.hidden = false;
  play.addEventListener('click', () => { video.controls = true; video.play(); });
  video.addEventListener('play', () => { play.hidden = true; video.controls = true; });
}

// Feature tiles: a tile with data-clip turns over to a short demo clip. The clip
// loads only when asked for, plays muted with a sound switch, and opens larger
// in a dialog. Escape or the back button turns the tile over again.
const svg = (id) => `<svg class="icon" aria-hidden="true"><use href="#${id}"/></svg>`;
let clipbox = null;
function openClipbox(sources, poster, title, muted, at) {
  if (!clipbox) {
    clipbox = document.createElement('dialog');
    clipbox.className = 'clipbox';
    clipbox.innerHTML = `<video controls playsinline loop></video><div class="clipbox__bar"><span class="clipbox__title"></span><button class="flip__btn" type="button" data-close aria-label="Close">${svg('i-x')}</button></div>`;
    document.body.appendChild(clipbox);
    clipbox.querySelector('[data-close]').addEventListener('click', () => clipbox.close());
    clipbox.addEventListener('click', (e) => { if (e.target === clipbox) clipbox.close(); });
    clipbox.addEventListener('close', () => clipbox.querySelector('video').pause());
  }
  const v = clipbox.querySelector('video');
  clipbox.querySelector('.clipbox__title').textContent = title;
  clipbox.setAttribute('aria-label', `Demo: ${title}`);
  v.poster = poster; v.innerHTML = sources; v.muted = muted; v.load();
  v.addEventListener('loadedmetadata', () => { v.currentTime = at || 0; }, { once: true });
  clipbox.showModal();
  v.play().catch(() => {});
}
document.querySelectorAll('.card[data-clip]').forEach((card) => {
  const name = card.dataset.clip;
  const title = card.querySelector('h3').textContent;
  const base = `assets/clips/${name}`, poster = `${base}.webp`;
  const sources = `<source src="${base}.webm" type="video/webm"><source src="${base}.mp4" type="video/mp4">`;
  const front = document.createElement('div');
  front.className = 'flip__face flip__front';
  front.append(...card.childNodes);
  const go = document.createElement('button');
  go.type = 'button'; go.className = 'flip__go';
  go.setAttribute('aria-label', `Watch a demo: ${title}`);
  go.innerHTML = `${svg('i-play')}Watch demo${card.dataset.len ? `<span class="flip__len">${card.dataset.len}</span>` : ''}`;
  front.appendChild(go);
  const back = document.createElement('div');
  back.className = 'flip__face flip__back';
  back.inert = true;
  back.innerHTML = `<video class="flip__video" muted playsinline loop preload="none" poster="${poster}" aria-label="Demo: ${title}"></video>
    <div class="flip__bar"><span class="flip__title">${title}</span>
    <button class="flip__btn" type="button" data-sound aria-pressed="false" aria-label="Sound">${svg('i-volume-x')}</button>
    <button class="flip__btn" type="button" data-big aria-label="Watch larger">${svg('i-maximize')}</button>
    <button class="flip__btn" type="button" data-back aria-label="Turn back">${svg('i-undo')}</button></div>`;
  const flip = document.createElement('div');
  flip.className = 'flip';
  flip.append(front, back);
  card.appendChild(flip);
  card.classList.add('card--clip');
  const video = back.querySelector('video');
  const sound = back.querySelector('[data-sound]');
  const turn = (on) => {
    card.classList.toggle('is-flipped', on);
    front.inert = on; back.inert = !on;
    if (on) {
      if (!video.firstChild) { video.innerHTML = sources; video.load(); }
      video.currentTime = 0;
      video.play().catch(() => {});
      sound.focus({ preventScroll: true });
    } else {
      video.pause();
      go.focus({ preventScroll: true });
    }
  };
  front.addEventListener('click', () => turn(true));
  back.querySelector('[data-back]').addEventListener('click', () => turn(false));
  back.addEventListener('keydown', (e) => { if (e.key === 'Escape') turn(false); });
  sound.addEventListener('click', () => {
    video.muted = !video.muted;
    sound.setAttribute('aria-pressed', String(!video.muted));
    sound.querySelector('use').setAttribute('href', video.muted ? '#i-volume-x' : '#i-volume');
  });
  const big = () => { video.pause(); openClipbox(sources, poster, title, video.muted, video.currentTime); };
  back.querySelector('[data-big]').addEventListener('click', big);
  video.addEventListener('click', big);
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
const revealables = document.querySelectorAll('.section__head, .card, .soon__item, .split > *, .flow, .built, .start, .facts__in > div');
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
