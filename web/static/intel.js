// Threat intel: feeds (added on this page or in signalith.yaml), the
// indicators they bring, manual add and CSV upload.
// Uses the ri* helpers (states, inspectors, alerts) from risk.js and the
// menu helper dxMenu from detections.js.
'use strict';

const tiState = {
  offset: 0, limit: 100, type: '', overview: null, list: [], total: 0, lookup: null, open: null, seq: 0, listSeq: 0, loaded: false, poll: null,
  // feeds
  feeds: [], downloads: true, manage: true, fileError: '',
  allFeeds: false, // show every feed, not only the first few
  expanded: new Set(), // feeds whose details are open
  pending: new Map(), // feeds changed here, polled until their download is done
  deferred: false, // a redraw waits for an open row menu to close
};

// until describes a future time, like ago does a past one.
function until(t) {
  const s = (new Date(t).getTime() - Date.now()) / 1000;
  if (!isFinite(s)) return '';
  if (s <= 60) return 'now';
  if (s < 3600) return 'in ' + Math.round(s / 60) + 'm';
  if (s < 86400) return 'in ' + Math.round(s / 3600) + 'h';
  return 'in ' + Math.round(s / 86400) + 'd';
}

// huntQuery is a search for the events an indicator would match.
function huntQuery(ind) {
  const v = quoteValue(ind.value);
  if (ind.type === 'ip' || ind.type === 'cidr') return `src=${v} OR dest=${v}`;
  if (ind.type === 'domain') return `dest_host=${v} OR dest=${v} OR query=${v} OR url="*${ind.value}*"`;
  if (['md5', 'sha1', 'sha256'].includes(ind.type)) return `process_${ind.type}=${v} OR process_hash="*${ind.value}*"`;
  return '"' + ind.value.replace(/"/g, '\\"') + '"';
}

// Types group into the classes the API filters by (?type=ip covers cidr).
const TI_CLASS = { ip: 'ip', cidr: 'ip', domain: 'domain', url: 'url', md5: 'hash', sha1: 'hash', sha256: 'hash', email: 'email' };
const TI_CLASSES = [['ip', 'IPs', 'globe'], ['domain', 'Domains', 'link'], ['url', 'URLs', 'external-link'], ['hash', 'Hashes', 'hash'], ['email', 'Emails', 'mail']];
const TI_TYPE_LABEL = { ip: 'IP address', cidr: 'Network', domain: 'Domain', url: 'URL', md5: 'MD5 hash', sha1: 'SHA-1 hash', sha256: 'SHA-256 hash', email: 'Email address' };
const TI_TYPE_SHORT = { ip: 'IP', cidr: 'Network', domain: 'Domain', url: 'URL', md5: 'MD5', sha1: 'SHA-1', sha256: 'SHA-256', email: 'Email' };
const TI_TYPE_ICON = { ip: 'globe', cidr: 'network', domain: 'link', url: 'external-link', md5: 'hash', sha1: 'hash', sha256: 'hash', email: 'mail' };
const TI_HUNT = '* | threatmatch\n| table _time, threat_match_field, threat_match_value, threat_source, threat_target, user, sourcetype';
const tiSourceLabel = (s) => (s === 'manual' ? 'Manual' : s);
// TI_SAMPLE is the source of the indicators the sample data adds; they go
// when it is removed.
const TI_SAMPLE = 'Sample data';
const tiChip = (ind) => el('span', { class: 'chip', 'data-kind': TI_CLASS[ind.type] || 'hash', title: ind.value }, el('span', {}, ind.value));
const tiPlural = (n, one, many) => `${n.toLocaleString()} ${n === 1 ? one : many || one + 's'}`;
// Weights may be set in quarters (the Tor exit list is 0.25).
const tiWeight = (v) => (typeof v === 'number' ? v.toLocaleString(undefined, { maximumFractionDigits: 2 }) : riNum(v));
// tiBusy is busy() that keeps keyboard focus on the button: a focused
// button that is disabled sends focus to the page body.
function tiBusy(btn, label) {
  const had = document.activeElement === btn;
  const done = busy(btn, label);
  return () => {
    done();
    const a = document.activeElement;
    if (had && btn.isConnected && (!a || a === document.body)) btn.focus({ preventScroll: true });
  };
}

// Feed settings in words. A feed's type is auto, hash or an indicator
// type; TI_NOUN has the [one, many] nouns for counts.
const TI_FEED_TYPE = { auto: 'Any type', ip: 'IP addresses', cidr: 'Networks', domain: 'Domains', url: 'URLs', md5: 'MD5 hashes', sha1: 'SHA-1 hashes', sha256: 'SHA-256 hashes', hash: 'File hashes', email: 'Email addresses' };
const TI_FEED_TYPE_SHORT = { auto: 'Mixed', ip: 'IPs', cidr: 'Networks', domain: 'Domains', url: 'URLs', md5: 'MD5', sha1: 'SHA-1', sha256: 'SHA-256', hash: 'Hashes', email: 'Emails' };
const TI_NOUN = { ip: ['IP address', 'IP addresses'], cidr: ['network', 'networks'], domain: ['domain', 'domains'], url: ['URL', 'URLs'], md5: ['MD5 hash', 'MD5 hashes'],
  sha1: ['SHA-1 hash', 'SHA-1 hashes'], sha256: ['SHA-256 hash', 'SHA-256 hashes'], email: ['email address', 'email addresses'] };
const TI_FORMAT = { auto: 'Detect automatically', lines: 'Plain list', csv: 'CSV', stix: 'STIX 2.1' };
const TI_INTERVALS = ['15m', '30m', '1h', '3h', '6h', '12h', '1d'];
const TI_KEEP = ['1d', '3d', '7d', '14d', '30d'];
const TI_NUMBER_WORD = ['no', 'one', 'two', 'three', 'four', 'five', 'six', 'seven', 'eight', 'nine', 'ten'];

// tiDur says a duration setting (30m, 1h, 7d) in words.
function tiDur(d) {
  const m = /^(\d+)([mhd])$/.exec(d || '');
  if (!m) return d || '';
  const n = +m[1];
  return `${n} ${{ m: 'minute', h: 'hour', d: 'day' }[m[2]]}${n === 1 ? '' : 's'}`;
}
const tiEvery = (d) => { const s = tiDur(d); return 'every ' + (s.startsWith('1 ') ? s.slice(2) : s); };
const tiFormatText = (format, column) => (format === 'csv' && column ? `CSV, column ${column}` : TI_FORMAT[format] || format);
const tiBytes = (n) => (n >= 1 << 20 ? (n / (1 << 20)).toFixed(1) + ' MB' : n >= 1024 ? Math.round(n / 1024) + ' KB' : n + ' bytes');
const tiListWords = (a) => (a.length < 2 ? a.join('') : a.slice(0, -1).join(', ') + ' and ' + a[a.length - 1]);
const tiSlug = (s) => String(s).toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+/, '').slice(0, 48).replace(/-+$/, '');
function tiHost(u) { try { return new URL(u).host; } catch (_) { return ''; } }
// tiServer is what saved secrets are tied to: scheme, host and port.
function tiServer(u) { try { const x = new URL(String(u).trim()); return x.protocol + '//' + x.host; } catch (_) { return ''; } }

// tiUniqueName makes a feed name no other feed has.
function tiUniqueName(base) {
  const taken = new Set(tiState.feeds.map((f) => f.name));
  if (base.length < 2) base = 'feed' + (base ? '-' + base : '');
  if (!taken.has(base)) return base;
  for (let i = 2; ; i++) if (!taken.has(`${base}-${i}`)) return `${base}-${i}`;
}
// tiNameFor suggests a feed name from its URL: the host without its
// top-level domain, and the file name unless it says nothing.
function tiNameFor(u) {
  let x;
  try { x = new URL(u); } catch (_) { return ''; }
  const host = x.hostname.replace(/^www\./, '').replace(/^\[|\]$/g, '');
  let parts = /^[\d.]+$/.test(host) || host.includes(':') ? [host] : host.split('.');
  if (parts.length > 1) parts = parts.slice(0, -1);
  let base = parts.slice(0, 2).join('-');
  const file = (x.pathname.split('/').filter(Boolean).pop() || '').replace(/\.[a-z0-9]{1,5}$/i, '');
  if (file && !/^(index|feeds?|downloads?|exports?|lists?|txt|csv|json|recent|latest|all)$/i.test(file)) base += '-' + file;
  return tiUniqueName(tiSlug(base));
}

// ---------- catalog of free feeds ----------
const tiCat = { list: null, promise: null };
function loadCatalog(force) {
  if (force || !tiCat.promise) {
    tiCat.promise = api('api/intel/catalog').then((r) => (tiCat.list = r.entries || []));
    tiCat.promise.catch(() => { tiCat.promise = null; });
  }
  return tiCat.promise;
}
const tiCatalogFor = (f) => (tiCat.list || []).find((e) => (f.catalog && e.id === f.catalog) || e.feed === f.name) || null;

// ---------- overview: errors, type pills, feeds ----------
// loadIntel loads the page. While feeds download it checks again every
// few seconds in the background: a background check redraws the feeds
// and counts only, so keyboard focus stays put, and reloads the
// indicators only when the counts changed.
async function loadIntel(opts = {}) {
  const bg = !!opts.background;
  const seq = ++tiState.seq;
  clearTimeout(tiState.poll);
  if (!tiState.overview) {
    const sk = riSkeleton(TI_FEED_COLS, 3);
    sk.classList.add('ti-feed-table');
    $('ti-feeds').replaceChildren(sk);
    $('ti-list').replaceChildren(riSkeleton(TI_IND_COLS));
  }
  const refresh = $('ti-refresh');
  const hadFocus = document.activeElement === refresh;
  if (!bg) refresh.disabled = true;
  const enable = () => {
    refresh.disabled = false;
    if (hadFocus && document.activeElement === document.body) refresh.focus({ preventScroll: true });
  };
  // The catalog names each catalog feed's provider and fills the empty
  // state's offer, so it loads alongside.
  const cat = tiCat.list ? null : loadCatalog().catch(() => null);
  let res;
  try {
    res = await api('api/intel');
    // With no feeds, wait for the catalog so the empty state shows its
    // offer at once instead of changing under the pointer.
    if (cat && !(res.feeds || []).length) await cat;
  } catch (e) {
    if (seq !== tiState.seq) return;
    enable();
    if (bg) tiState.poll = setTimeout(() => { if (currentPage === 'intel') loadIntel({ background: true }); }, 5000);
    else showIntelError(e);
    return;
  }
  if (seq !== tiState.seq) return;
  enable();
  const counts = (o) => JSON.stringify(o && o.summary);
  const changed = counts(tiState.overview) !== counts(res);
  tiState.overview = res;
  tiState.feeds = res.feeds || [];
  tiState.downloads = !!res.downloads;
  tiState.downloadsWhy = res.downloads_why || '';
  // The server that downloads feeds, '' when none does, null when this
  // one does or its scheduler is off.
  tiState.runsOn = typeof res.runs_on === 'string' ? res.runs_on : null;
  // Only admins add and change feeds.
  tiState.manage = res.manage !== false && can('admin');
  tiState.fileError = res.file_error || '';
  // Where the servers share their settings, every server changes the one
  // feed list, and the server that runs the background jobs downloads.
  tiState.shared = !!res.shared;
  // Each feed's version, so a change applies only to the feed as shown.
  tiState.etags = res.etags || {};
  $('ti-error').classList.add('hidden');
  $('ti-main').classList.remove('hidden');
  $('ti-add-open').disabled = false;
  $('ti-hunt').disabled = false;
  // Feeds are added on the server that downloads them; here the note says so.
  $('ti-feed-add').hidden = !tiState.manage;
  $('ti-feed-add').disabled = !tiState.manage || !!tiState.fileError;
  if (!bg || changed) renderTypePills();
  settlePending();
  renderFeeds();
  if (cat && tiState.feeds.length) cat.then(() => { if (seq === tiState.seq && currentPage === 'intel' && tiCat.list) renderFeeds(); });
  const sources = Object.keys((res.summary || {}).by_source || {}).sort();
  const sel = $('ti-source');
  const cur = sel.value;
  if (!bg || changed) {
    const keep = document.activeElement === sel;
    sel.replaceChildren(el('option', { value: '' }, 'Any source'), ...sources.map((s) => el('option', { value: s }, tiSourceLabel(s))));
    if (sources.includes(cur)) sel.value = cur;
    else if (cur) { sel.value = ''; tiState.offset = 0; }
    if (keep) sel.focus({ preventScroll: true });
  }
  // While a feed downloads, check again so its status settles by itself.
  if (tiState.feeds.some((f) => f.status && f.status.running) || tiState.pending.size) {
    tiState.poll = setTimeout(() => { if (currentPage === 'intel') loadIntel({ background: true }); }, 2500);
  }
  if (!bg || changed) loadIndicators();
}

// showIntelError replaces the page with what failed (threat intel may be
// off on this server); the buttons that need it are disabled meanwhile.
function showIntelError(e) {
  tiState.overview = null;
  closeIndicator();
  $('ti-main').classList.add('hidden');
  $('ti-add-open').disabled = true;
  $('ti-hunt').disabled = true;
  $('ti-feed-add').disabled = true;
  $('ti-error').replaceChildren(riEmpty({ icon: 'circle-alert', tone: 'danger', title: 'Couldn’t load threat intel', text: riCap(e.message) + '.', action: riRetry(loadIntel) }));
  $('ti-error').classList.remove('hidden');
}

function renderTypePills() {
  const sum = (tiState.overview && tiState.overview.summary) || { total: 0, by_type: {} };
  const counts = {};
  for (const [t, n] of Object.entries(sum.by_type || {})) counts[TI_CLASS[t] || t] = (counts[TI_CLASS[t] || t] || 0) + n;
  const pill = (cls, label, name, n) => {
    const b = el('button', { class: 'pill', type: 'button', 'aria-pressed': String(tiState.type === cls), 'data-cls': cls }, icon(name), label, el('span', { class: 'num' }, n.toLocaleString()));
    b.addEventListener('click', () => {
      if (tiState.type === cls) return;
      tiState.type = cls;
      tiState.offset = 0;
      renderTypePills();
      loadIndicators();
    });
    return b;
  };
  const box = $('ti-type');
  const focused = box.contains(document.activeElement) ? document.activeElement.dataset.cls : null;
  box.replaceChildren(pill('', 'All', 'layers', sum.total || 0),
    ...TI_CLASSES.filter(([cls]) => counts[cls] || tiState.type === cls).map(([cls, label, name]) => pill(cls, label, name, counts[cls] || 0)));
  if (focused !== null && focused !== undefined) {
    const again = box.querySelector(`[data-cls="${CSS.escape(focused)}"]`) || box.firstElementChild;
    if (again) again.focus({ preventScroll: true });
  }
}

// ---------- feeds list ----------
const TI_FEED_COLS = [['Feed', 'ti-c-feed'], ['Type', 'ti-c-type hide-sm'], ['Indicators', 'num ti-c-count'], ['Updated', 'ti-c-upd hide-sm'], ['', 'ti-c-act']];

// A feed added or changed here downloads at once on the server that runs
// the schedule; the page checks back until that download is done.
function tiWatch(view) {
  if (!tiState.downloads || !view || !view.enabled) return;
  tiState.pending.set(view.name, { before: (view.status && view.status.last_attempt) || '', since: Date.now() });
}
function settlePending() {
  for (const [name, p] of tiState.pending) {
    const f = tiState.feeds.find((x) => x.name === name);
    const at = f && f.status ? f.status.last_attempt || '' : '';
    if (!f || !f.enabled || (at && at !== p.before && !f.status.running) || Date.now() - p.since > 90000) tiState.pending.delete(name);
  }
}

function feedState(f) {
  const st = f.status || {};
  if (f.problem) return ['bad', 'Not used'];
  if (!f.enabled) return ['off', 'Off'];
  if (st.running || tiState.pending.has(f.name)) return ['run', 'Downloading'];
  if (st.last_error) return ['bad', 'Failing'];
  if (st.last_success) return ['ok', 'OK'];
  return ['wait', 'Waiting for its first download'];
}

// TI_FEEDS_SHOWN is how many feeds the card lists before "Show all", so
// the indicators stay in view; failing feeds are always listed.
const TI_FEEDS_SHOWN = 6;

function renderFeeds() {
  const box = $('ti-feeds');
  // Redrawing would close an open row menu; wait until it closes.
  if (box.querySelector('details.menu[open]')) { tiState.deferred = true; return; }
  tiState.deferred = false;
  const feeds = tiState.feeds;
  const active = document.activeElement;
  const keyed = active && box.contains(active) ? active.closest('[data-key]') : null;
  const focusKey = keyed ? keyed.dataset.key : null;
  const hasFeeds = feeds.length > 0;
  // One primary button: the empty state's while there are no feeds.
  $('ti-feed-add').classList.toggle('btn--primary', hasFeeds || !tiState.manage);
  $('ti-feed-add').classList.toggle('btn--secondary', !hasFeeds && tiState.manage);
  const notes = [];
  if (tiState.fileError && can('admin')) notes.push(riAlert('danger', 'Feeds can’t be changed on this page right now.', el('p', {}, tiState.fileError)));
  const servers = el('a', { href: '#servers', 'data-page': 'servers' }, 'Servers page');
  if (tiState.shared && !tiState.downloads && can('admin') && tiState.runsOn) {
    notes.push(riAlert('info', `${tiState.runsOn} downloads the feeds.`,
      el('p', {}, 'Every server shares this list of feeds: a feed added or changed here is downloaded there, and its status shows on every server.')));
  } else if (!tiState.downloads && can('admin') && tiState.runsOn === '') {
    notes.push(riAlert('danger', 'No server downloads feeds right now.',
      el('p', {}, 'Feeds don’t update until a server runs the background jobs again. The ', servers, ' says why.')));
  } else if (!tiState.downloads && can('admin') && tiState.runsOn) {
    notes.push(riAlert('info', `Feeds are managed on ${tiState.runsOn}.`,
      el('p', {}, `This server doesn’t download feeds: add and change them on ${tiState.runsOn}. The `, servers, ' has its address.')));
  } else if (!tiState.downloads && can('admin')) {
    notes.push(riAlert('info', 'Feeds are managed on another server.',
      el('p', {}, tiState.downloadsWhy || 'This server doesn’t download feeds. Add and change feeds on the Signalith server that runs the background jobs.')));
  }
  const noteBox = notes.length ? el('div', { class: 'ti-feeds__notes' }, ...notes) : null;
  if (!hasFeeds) {
    $('ti-feeds-sub').textContent = 'Lists of known-bad indicators, downloaded on a schedule';
    // With a note, it says all there is to say.
    fill(box, noteBox, notes.length ? null : feedsEmpty());
  } else {
    const failing = feeds.filter((f) => feedState(f)[0] === 'bad').length;
    const off = feeds.filter((f) => !f.enabled).length;
    const total = feeds.reduce((n, f) => n + (f.indicators || 0), 0);
    const sub = [tiPlural(feeds.length, 'feed'), tiPlural(total, 'indicator')];
    if (failing) sub.push(`${failing} failing`);
    if (off) sub.push(`${off} off`);
    $('ti-feeds-sub').textContent = sub.join(' · ');
    let shown = feeds;
    const many = feeds.length > TI_FEEDS_SHOWN + 1;
    if (many && !tiState.allFeeds) {
      // Failing, open and downloading feeds always show; others fill up the rest.
      const must = (f) => feedState(f)[0] === 'bad' || tiState.expanded.has(f.name) || tiState.pending.has(f.name);
      let room = TI_FEEDS_SHOWN - feeds.filter(must).length;
      shown = feeds.filter((f) => must(f) || room-- > 0);
    }
    const rows = [];
    for (const f of shown) rows.push(...feedRows(f));
    let more = null;
    if (many) {
      const btn = el('button', { class: 'link-btn', type: 'button', 'data-key': 'feeds:more', 'aria-expanded': String(tiState.allFeeds) },
        icon(tiState.allFeeds ? 'chevron-up' : 'chevron-down', 'icon--sm'), tiState.allFeeds ? 'Show fewer feeds' : `Show all ${feeds.length} feeds`);
      btn.addEventListener('click', () => { tiState.allFeeds = !tiState.allFeeds; renderFeeds(); });
      more = el('div', { class: 'ti-feeds__more' }, btn);
    }
    fill(box, noteBox, el('table', { class: 'table ti-feed-table' }, riHead(TI_FEED_COLS), el('tbody', {}, ...rows)), more);
  }
  if (focusKey) {
    // Keep keyboard focus on the same control after a redraw.
    const again = box.querySelector(`[data-key="${CSS.escape(focusKey)}"]`) || box.querySelector('.ti-feed__toggle');
    if (again) (again.matches('details') ? again.querySelector('summary') : again).focus({ preventScroll: true });
  }
}

// feedsEmpty offers the recommended catalog feeds in one click.
function feedsEmpty() {
  const rec = tiState.manage ? (tiCat.list || []).filter((e) => e.recommended && !e.added && !e.needs_key) : [];
  const providers = [...new Set(rec.map((e) => e.provider))];
  const text = rec.length
    ? `Start with ${TI_NUMBER_WORD[rec.length] || rec.length} free, low-noise feeds from ${tiListWords(providers)}, or pick your own.`
    : 'Feeds keep lists of known-bad IPs, URLs and file hashes up to date by downloading them on a schedule.' + (can('admin') ? '' : ' An admin sets them up.');
  const actions = el('div', { class: 'empty__actions' });
  if (tiState.manage && !tiState.fileError) {
    if (rec.length) {
      const on = el('button', { class: 'btn btn--primary', type: 'button', 'data-key': 'empty:rec' }, icon('zap'), 'Turn on recommended feeds');
      on.addEventListener('click', () => addRecommended(rec.map((e) => e.id), on));
      actions.append(on);
    }
    actions.append(el('button', { class: 'btn btn--secondary', type: 'button', 'data-key': 'empty:browse', onclick: () => openFeedDialog({ tab: 'catalog' }) },
      rec.length ? 'Browse all feeds' : 'Add a feed'));
  }
  return el('div', { class: 'empty ti-feeds__empty' }, el('span', { class: 'empty__icon' }, icon('rss')),
    el('div', { class: 'empty__title' }, 'No feeds yet'), el('p', { class: 'empty__text' }, text), actions.childElementCount ? actions : null);
}

// addRecommended adds catalog feeds by ID and starts their downloads.
async function addRecommended(ids, btn) {
  const fromEmpty = !!btn.closest('.ti-feeds__empty');
  const done = tiBusy(btn, 'Turning on…');
  let r;
  try {
    r = await api('api/intel/catalog', { ids });
  } catch (e) {
    done();
    toastError('Couldn’t turn on the feeds', e);
    return null;
  }
  done();
  const added = r.added || [];
  for (const v of added) tiWatch(v);
  for (const e of tiCat.list || []) {
    const v = added.find((x) => x.catalog === e.id);
    if (v) { e.added = true; e.feed = v.name; }
  }
  if (added.length) toast(`Turned on ${tiPlural(added.length, 'feed')}. They’re downloading now.`);
  else if ((r.skipped || []).length) toast(r.skipped[0].reason, null, { tone: 'danger', title: 'No feeds were added' });
  await loadIntel();
  // The empty state's button is gone; go on to the first new feed.
  if (fromEmpty && added.length && currentPage === 'intel') {
    const row = $('ti-feeds').querySelector(`[data-key="${CSS.escape('t:' + added[0].name)}"]`) || $('ti-feeds').querySelector('.ti-feed__toggle');
    if (row) row.focus();
  }
  return r;
}

// feedRows is a feed's row and the details it opens.
function feedRows(f) {
  const st = f.status || {};
  const [state, label] = feedState(f);
  const open = tiState.expanded.has(f.name);
  const cat = tiCatalogFor(f);
  const detailId = 'ti-fd-' + f.name.replace(/[^a-z0-9_-]/gi, '_');
  const toggle = el('button', { class: 'ti-feed__toggle', type: 'button', 'aria-expanded': String(open), 'aria-controls': detailId, 'data-key': 't:' + f.name },
    icon('chevron-right', 'ti-chev'), el('span', { class: 'ti-dot', 'data-state': state, title: label }),
    el('span', { class: 'ti-feed__name', title: f.name }, f.name), el('span', { class: 'sr-only' }, `, ${label}`));
  const line = el('div', { class: 'ti-feed__line' }, toggle,
    f.source === 'config' ? el('span', { class: 'badge badge--outline', title: 'Change it in signalith.yaml' }, 'From signalith.yaml')
      : f.from ? el('span', { class: 'badge badge--outline', title: tiCap(f.from) }, /signalith\.yaml/.test(f.from) ? 'signalith.yaml' : 'Imported') : null);
  const origin = cat ? cat.provider : tiHost(f.url) + (f.kind === 'taxii' ? ' · TAXII' : '');
  let sub;
  if (f.problem) sub = el('span', { class: 'ti-feed__sub ti-feed__sub--bad', title: f.problem }, sentence(f.problem));
  else if (state === 'bad') sub = el('span', { class: 'ti-feed__sub ti-feed__sub--bad', title: st.last_error }, st.last_error);
  else {
    sub = el('span', { class: 'ti-feed__sub' }, origin, f.enabled ? ` · ${tiEvery(f.interval)}` : '',
      el('span', { class: 'ti-only-sm' }, ` · ${TI_FEED_TYPE_SHORT[f.type] || f.type}`));
  }
  const tr = el('tr', { class: 'ti-feed' + (open ? ' is-open' : '') + (f.enabled ? '' : ' is-off'), 'data-state': state },
    el('td', { class: 'ti-c-feed' }, line, sub),
    el('td', { class: 'ti-c-type hide-sm' }, TI_FEED_TYPE[f.type] || f.type),
    el('td', { class: 'num ti-c-count' }, el('span', { class: 'ti-count' }, (f.indicators || 0).toLocaleString()),
      el('span', { class: 'ti-only-sm ti-count__upd' }, feedUpdatedText(f, state))),
    el('td', { class: 'ti-c-upd hide-sm' }, feedUpdated(f, state)),
    el('td', { class: 'ti-c-act' }, feedMenu(f)));
  const detail = el('tr', { class: 'ti-feed-detail', id: detailId }, el('td', { colspan: String(TI_FEED_COLS.length) }, feedDetails(f, cat)));
  detail.hidden = !open;
  tr.addEventListener('click', (ev) => {
    if (ev.target.closest('details.menu, a') || String(getSelection()).trim()) return;
    const now = !tiState.expanded.has(f.name);
    if (now) tiState.expanded.add(f.name); else tiState.expanded.delete(f.name);
    toggle.setAttribute('aria-expanded', String(now));
    tr.classList.toggle('is-open', now);
    detail.hidden = !now;
  });
  return [tr, detail];
}

function feedUpdatedText(f, state) {
  const st = f.status || {};
  if (state === 'run') return 'Downloading…';
  if (!f.enabled) return 'Off';
  if (st.last_success) return ago(st.last_success);
  if (!tiState.downloads && !st.last_attempt) return '—'; // downloaded by another server
  return st.last_attempt ? 'Never' : 'Not yet';
}
function feedUpdated(f, state) {
  const st = f.status || {};
  const title = st.last_success ? 'Last downloaded ' + fmtTime(st.last_success) : !tiState.downloads ? 'Downloaded by the server that runs the background jobs' : '';
  return el('span', { class: 'ti-upd' + (state === 'run' ? ' ti-upd--run' : ''), title }, feedUpdatedText(f, state));
}

// feedMenu: feeds from signalith.yaml can only be refreshed here. On a
// server that doesn't download feeds, only those can be (they are the
// same on every server).
function feedMenu(f) {
  const mine = f.source === 'ui' && tiState.manage && !tiState.fileError;
  const items = [];
  if (can('admin') && f.enabled && !f.problem && (tiState.downloads || tiState.shared || f.source === 'config')) items.push({ icon: 'refresh-cw', label: 'Refresh now', run: () => refreshFeed(f) });
  if (mine) {
    items.push({ icon: 'pencil', label: 'Edit', run: () => openFeedDialog({ feed: f }) });
    if (!f.problem) items.push({ icon: 'power', label: f.enabled ? 'Turn off' : 'Turn on', run: () => setFeedEnabled(f, !f.enabled) });
    items.push('sep', { icon: 'trash-2', label: 'Delete', danger: true, run: () => confirmFeedDelete(f) });
  }
  if (!items.length) return null;
  const m = dxMenu('Actions for ' + f.name, items);
  m.classList.add('ti-menu');
  m.dataset.key = 'm:' + f.name;
  m.querySelector('summary').classList.add('btn--sm');
  m.addEventListener('toggle', () => { if (!m.open && tiState.deferred) setTimeout(renderFeeds); });
  return m;
}

// feedDetails is what a row shows when opened: where the feed comes
// from, how it is read and kept, and what its last download found.
function feedDetails(f, cat) {
  const st = f.status || {};
  const items = [];
  const add = (k, v, cls) => items.push(el('div', { class: 'ti-kv__item' + (cls ? ' ti-kv__item--' + cls : '') }, el('dt', {}, k), el('dd', {}, ...[].concat(v))));
  // On a phone the row cuts a long name short.
  add('Name', el('span', { class: 'mono ti-break' }, f.name), 'sm');
  if (f.kind === 'taxii') {
    add('TAXII server', el('span', { class: 'mono ti-break' }, f.url), 'wide');
    add('Collection', el('span', { class: 'mono ti-break' }, f.collection));
  } else {
    add('Address', el('span', { class: 'mono ti-break' }, f.url), 'wide');
    // For auto, what the last download was read as.
    add('Format', f.format === 'auto' && st.format ? `${tiFormatText(st.format, st.column)} (detected)` : tiFormatText(f.format, f.column));
  }
  add('Type', TI_FEED_TYPE[f.type] || f.type);
  const next = f.enabled && tiState.downloads && st.next_run && !st.running ? `, next ${until(st.next_run)}` : '';
  add('Downloads', riCap(tiEvery(f.interval)) + next);
  add('If downloads stop', `Indicators stay ${tiDur(f.max_age)}`);
  add('Weight', `${tiWeight(f.weight)} (multiplies the risk a match adds)`);
  if (st.last_success) {
    add('Last download', [el('span', { title: fmtTime(st.last_success) }, ago(st.last_success)),
      ` · ${tiPlural(st.count || 0, 'indicator')}, ${(st.added || 0).toLocaleString()} new, ${(st.removed || 0).toLocaleString()} gone`]);
  }
  if (st.last_attempt && st.last_attempt !== st.last_success) add('Last try', el('span', { title: fmtTime(st.last_attempt) }, ago(st.last_attempt)));
  if ((f.headers || []).length) add('API key', f.headers.map((h) => h.name).join(', ') + ' (saved, hidden)');
  if (f.username) add('Sign-in', f.username + (f.password && f.password.set ? ', password saved' : ''));
  if (cat) {
    add('From the catalog', cat.homepage ? el('a', { href: cat.homepage, target: '_blank', rel: 'noopener noreferrer' }, `${cat.title}, ${cat.provider}`, icon('external-link', 'icon--xs'))
      : `${cat.title}, ${cat.provider}`);
  }
  const notes = [];
  if (st.skipped) notes.push(`${tiPlural(st.skipped, 'line')} skipped as not valid indicators` + (st.skipped_example ? `, such as “${st.skipped_example}”.` : '.'));
  if (st.reserved) notes.push(`${tiPlural(st.reserved, 'private or reserved network')} skipped, so they never match your own network.`);
  if (st.note) notes.push(st.note);
  let alert = null;
  if (f.problem) alert = riAlert('warning', 'This feed is not used.', el('p', {}, sentence(f.problem)));
  else if (st.last_error && f.enabled) {
    const keyHint = cat && cat.key_header && !(f.headers || []).length && /API key/.test(st.last_error)
      ? el('p', {}, `${cat.key_help || ''} Add it with Edit.`.trim()) : null;
    alert = riAlert('danger', st.last_success ? 'The last download failed. The indicators from before are kept.' : 'The download failed.', el('p', {}, st.last_error), keyHint);
  }
  return el('div', { class: 'ti-detail' },
    alert,
    f.description ? el('p', { class: 'ti-detail__desc' }, f.description) : null,
    el('dl', { class: 'ti-kv' }, ...items),
    notes.length ? el('ul', { class: 'ti-detail__notes' }, ...notes.map((n) => el('li', {}, icon('info', 'icon--sm'), el('span', {}, n)))) : null,
    f.source === 'config' ? el('p', { class: 'ti-detail__src' }, icon('file-code', 'icon--sm'), 'Set in signalith.yaml. Change it there and restart Signalith.')
      : f.from ? el('p', { class: 'ti-detail__src' }, icon('file-code', 'icon--sm'), `${tiCap(f.from)}. A change here applies on every server.`) : null);
}

const tiCap = (t) => (t ? t[0].toUpperCase() + t.slice(1) : '');
// tiIfMatch makes a change apply only to the feed as the page shows it.
const tiIfMatch = (name) => (tiState.etags && tiState.etags[name] ? { 'If-Match': tiState.etags[name] } : undefined);
// tiStale says that someone changed a feed meanwhile, and shows theirs.
function tiStale(e, name) {
  if (e.status !== 412) return false;
  // The server's message says to reload; the page does that itself.
  toast(`Someone changed ${name} since you opened the page. The page now shows their change; make yours again if it is still needed.`, null,
    { tone: 'warning', title: 'Someone else changed this feed' });
  loadIntel();
  return true;
}

async function refreshFeed(f) {
  const t = $('ti-feeds').querySelector(`[data-key="${CSS.escape('t:' + f.name)}"]`);
  const tr = t && t.closest('tr');
  if (tr) {
    tr.querySelector('.ti-dot').dataset.state = 'run';
    tr.querySelectorAll('.ti-upd, .ti-count__upd').forEach((n) => { n.textContent = 'Downloading…'; n.classList.add('ti-upd--run'); });
  }
  const say = (text) => tr && tr.querySelectorAll('.ti-upd, .ti-count__upd').forEach((n) => { n.textContent = text; });
  try {
    const r = await api(`api/intel/feeds/${encodeURIComponent(f.name)}/refresh`, {}, 'POST');
    if (r.request_id) {
      // The server that runs the background jobs downloads it: follow
      // the request, queued there, then downloading, then the result.
      const on = r.queued_on || 'the server that runs the background jobs';
      say(`Queued on ${on}`);
      const req = await followRequest(r.request_id, (q) => say(q.state === 'running' ? 'Downloading…' : q.state === 'queued' ? `Queued on ${on}` : ''));
      if (!req) toastError(`Couldn’t follow the download of ${f.name}`, new Error('The request is gone. The feed’s status shows how it went.'));
      else if (req.state === 'failed') toastError(`Couldn’t download ${f.name}`, new Error(req.error || 'The download failed.'));
      else if (req.state === 'done') {
        const st = req.result || {};
        if (st.already_running) toast(`${f.name} is already downloading on ${on}; its status shows here when it is done.`);
        else if (st.last_error) toastError(`Couldn’t download ${f.name}`, new Error(st.last_error));
        else toast(`Downloaded ${f.name} on ${on}: ${tiPlural(st.count || 0, 'indicator')}.`);
      } else toast(`The download of ${f.name} is still waiting on ${on}. Its status shows here when it is done.`);
    } else {
      toast(`Downloaded ${f.name}: ${tiPlural((r.status || {}).count || 0, 'indicator')}.`);
    }
  } catch (e) {
    toastError(`Couldn’t download ${f.name}`, e);
  }
  loadIntel();
}

async function setFeedEnabled(f, on) {
  let v;
  try {
    v = await api('api/intel/feeds/' + encodeURIComponent(f.name), { enabled: on }, 'PUT', tiIfMatch(f.name));
  } catch (e) {
    if (tiStale(e, f.name)) return;
    toastError(`Couldn’t turn ${on ? 'on' : 'off'} ${f.name}`, e);
    return;
  }
  if (on) {
    tiWatch(v);
    toast(`Turned on ${f.name}.` + (tiState.downloads ? ' It’s downloading now.' : ''));
  } else {
    const n = f.indicators || 0;
    toast(`Turned off ${f.name}.` + (n ? ` Its ${tiPlural(n, 'indicator')} no longer match.` : ''), { label: 'Undo', run: () => setFeedEnabled(v, true) });
  }
  loadIntel();
}

// ---------- delete a feed ----------
function confirmFeedDelete(f) {
  const d = $('ti-feed-delete');
  d.dataset.feed = f.name;
  const n = f.indicators || 0;
  const remove = el('input', { type: 'checkbox', id: 'ti-feed-delete-ind' });
  remove.checked = true;
  const msg = el('div', { class: 'ti-msg' });
  const ok = el('button', { class: 'btn btn--danger', type: 'button' }, 'Delete feed');
  // The body holds the choice about indicators, and any error.
  const body = el('div', { class: 'modal__body' }, msg,
    n ? el('div', { class: 'ti-del' },
      el('label', { class: 'check' }, remove, `Also remove its ${tiPlural(n, 'indicator')} now`),
      el('p', { class: 'hint ti-del__hint' }, `Otherwise they keep matching for up to ${tiDur(f.max_age)}, then expire.`)) : null);
  body.hidden = !n;
  fill(d,
    el('div', { class: 'modal__head' }, el('div', {},
      el('h3', { class: 'modal__title', id: 'ti-feed-delete-title' }, 'Delete ', el('span', { class: 'mono' }, f.name), '?'),
      el('p', { class: 'modal__desc', id: 'ti-feed-delete-desc' }, 'It stops downloading. You can add it again later.'))),
    body,
    el('div', { class: 'modal__foot' }, el('button', { class: 'btn btn--ghost', type: 'button', onclick: () => d.close() }, 'Cancel'), ok));
  ok.addEventListener('click', async () => {
    const drop = !n || remove.checked;
    const done = tiBusy(ok, 'Deleting…');
    let r;
    try {
      r = await api(`api/intel/feeds/${encodeURIComponent(f.name)}?indicators=${drop ? 'remove' : 'keep'}`, undefined, 'DELETE', tiIfMatch(f.name));
    } catch (e) {
      done();
      if (e.status === 412) { d.close(); tiStale(e, f.name); return; }
      body.hidden = false;
      msg.replaceChildren(riAlert('danger', 'Couldn’t delete the feed.', el('p', {}, sentence(e.message))));
      return;
    }
    d.close();
    tiState.expanded.delete(f.name);
    tiState.pending.delete(f.name);
    const gone = r.indicators_removed || 0;
    toast(drop ? `Deleted ${f.name}` + (gone ? ` and its ${tiPlural(gone, 'indicator')}.` : '.') : `Deleted ${f.name}. Its indicators expire within ${tiDur(f.max_age)}.`);
    for (const e of tiCat.list || []) if (e.feed === f.name) { e.added = false; e.feed = ''; }
    loadIntel();
  });
  d.showModal();
}
// A dialog opened from a row menu closes with focus nowhere (the menu item
// is hidden by then, so the browser can't return to it): go to the row.
const tiFocusLost = (d) => { const a = document.activeElement; return !a || a === document.body || d.contains(a); };
$('ti-feed-delete').addEventListener('close', () => {
  const d = $('ti-feed-delete');
  if (!tiFocusLost(d)) return;
  const row = $('ti-feeds').querySelector(`[data-key="${CSS.escape('t:' + d.dataset.feed)}"]`);
  (row || $('ti-feeds').querySelector('.ti-feed__toggle') || $('ti-feed-add')).focus();
});

// ---------- add and edit a feed ----------
// Adding offers three ways in (the catalog, a URL, a TAXII 2.1 server);
// editing shows the feed's own form. tf.seq drops answers that arrive
// after the dialog closed or opened again.
const tf = { seq: 0, feed: null };
const TF_TABS = [['catalog', 'Catalog'], ['url', 'From a URL'], ['taxii', 'TAXII 2.1']];

function openFeedDialog({ tab = 'catalog', feed = null } = {}) {
  const d = $('ti-feed-dialog');
  tf.seq++;
  tf.feed = feed;
  d.classList.toggle('is-add', !feed);
  const head = el('div', { class: 'modal__head' },
    el('div', {}, el('h3', { class: 'modal__title', id: 'ti-feed-title' }, feed ? 'Edit feed' : 'Add a feed'),
      el('p', { class: 'modal__desc' }, feed ? el('span', { class: 'mono' }, feed.name) : 'Signalith downloads it on a schedule and matches its indicators against your events.')),
    el('button', { class: 'btn btn--ghost btn--icon btn--sm modal__close', type: 'button', 'aria-label': 'Close', onclick: () => d.close() }, icon('x')));
  if (feed) {
    const form = feedForm(feed.kind === 'taxii' ? 'taxii' : 'url', feed);
    fill(d, head, form.node);
    d.showModal();
    form.focus();
    return;
  }
  const bar = el('div', { class: 'tabs ti-feed-tabs', role: 'tablist', 'aria-label': 'Where the feed comes from' });
  const tabs = {};
  const panels = {};
  const built = {};
  const select = (id, focusTab) => {
    for (const [k] of TF_TABS) {
      tabs[k].setAttribute('aria-selected', String(k === id));
      tabs[k].tabIndex = k === id ? 0 : -1;
      panels[k].hidden = k !== id;
    }
    if (!built[id]) {
      built[id] = id === 'catalog' ? catalogPanel() : feedForm(id, null);
      panels[id].append(built[id].node);
    }
    if (focusTab) tabs[id].focus();
    else built[id].focus();
  };
  for (const [id, label] of TF_TABS) {
    tabs[id] = el('button', { class: 'tab', type: 'button', role: 'tab', id: 'tf-tab-' + id, 'aria-controls': 'tf-panel-' + id }, label);
    tabs[id].addEventListener('click', () => select(id));
    bar.append(tabs[id]);
    panels[id] = el('div', { class: 'ti-panel', role: 'tabpanel', id: 'tf-panel-' + id, 'aria-labelledby': 'tf-tab-' + id });
  }
  bar.addEventListener('keydown', (ev) => {
    const ids = TF_TABS.map(([k]) => k);
    const i = ids.indexOf(ev.target.id.replace('tf-tab-', ''));
    let j = { ArrowRight: i + 1, ArrowLeft: i - 1, Home: 0, End: ids.length - 1 }[ev.key];
    if (i < 0 || j === undefined) return;
    ev.preventDefault();
    j = (j + ids.length) % ids.length;
    select(ids[j], true);
  });
  fill(d, head, bar, ...TF_TABS.map(([k]) => panels[k]));
  d.showModal();
  select(tab);
}
$('ti-feed-dialog').addEventListener('close', () => {
  tf.seq++;
  if (tiFocusLost($('ti-feed-dialog'))) {
    const row = tf.feed && $('ti-feeds').querySelector(`[data-key="${CSS.escape('t:' + tf.feed.name)}"]`);
    (row || $('ti-feed-add')).focus();
  }
});

// catalogPanel lists the built-in free feeds, recommended ones first.
function catalogPanel() {
  const seq = tf.seq;
  const body = el('div', { class: 'modal__body ti-cat' }, el('div', { class: 'ti-cat-grid' },
    ...Array.from({ length: 4 }, () => el('div', { class: 'ti-cat-card' }, el('span', { class: 'skeleton', style: 'width:60%' }),
      el('span', { class: 'skeleton', style: 'width:35%' }), el('span', { class: 'skeleton', style: 'width:90%' })))));
  const foot = el('div', { class: 'modal__foot' });
  const node = el('div', { class: 'ti-panel__inner' }, body, foot);
  const closeBtn = el('button', { class: 'btn btn--ghost', type: 'button', onclick: () => $('ti-feed-dialog').close() }, 'Close');
  const render = () => {
    const list = tiCat.list || [];
    const section = (title, text, entries) => (entries.length ? el('section', { class: 'ti-cat-sec', 'aria-label': title },
      el('div', { class: 'ti-cat-sec__head' }, el('h4', { class: 'section-title' }, title), el('p', {}, text)),
      el('div', { class: 'ti-cat-grid' }, ...entries.map((e) => catalogCard(e, render)))) : null);
    fill(body,
      section('Recommended', 'High signal, few false positives', list.filter((e) => e.recommended)),
      section('More free feeds', 'Broader lists; some flag activity that is not always malicious', list.filter((e) => !e.recommended)));
    const rec = list.filter((e) => e.recommended && !e.added && !e.needs_key);
    let all = null;
    if (rec.length > 1 && tiState.manage) {
      all = el('button', { class: 'btn btn--primary', type: 'button' }, icon('zap'), `Add all ${rec.length} recommended`);
      all.addEventListener('click', async () => {
        const r = await addRecommended(rec.map((e) => e.id), all);
        if (r && seq === tf.seq) {
          render();
          (body.querySelector('.ti-added') || closeBtn).focus();
        }
      });
    }
    fill(foot, closeBtn, all);
  };
  const load = () => loadCatalog(true).then(() => { if (seq === tf.seq) render(); }, (e) => {
    if (seq !== tf.seq) return;
    fill(body, riEmpty({ icon: 'circle-alert', tone: 'danger', title: 'Couldn’t load the catalog', text: riCap(e.message) + '.', action: riRetry(load) }));
  });
  fill(foot, closeBtn);
  load();
  return { node, focus: () => (body.querySelector('.ti-cat-card button') || $('tf-tab-catalog')).focus() };
}

function catalogCard(e, rerender) {
  const titleId = 'tf-cat-' + e.id;
  const act = el('div', { class: 'ti-cat-card__act' });
  const msg = el('div', { class: 'ti-msg' });
  const keyBox = el('div', { class: 'ti-cat-key' });
  keyBox.hidden = true;
  const card = el('article', { class: 'ti-cat-card', 'aria-labelledby': titleId },
    el('div', { class: 'ti-cat-card__head' }, el('h5', { class: 'ti-cat-card__title', id: titleId }, e.title), act),
    el('div', { class: 'ti-cat-card__meta' },
      e.homepage ? el('a', { href: e.homepage, target: '_blank', rel: 'noopener noreferrer', title: `${e.provider} website (opens in a new tab)` }, e.provider) : el('span', {}, e.provider),
      el('span', { class: 'badge' }, TI_FEED_TYPE_SHORT[e.type] || e.type),
      e.needs_key ? el('span', { class: 'badge badge--warning' }, icon('key-round', 'icon--xs'), 'Needs free key') : null),
    el('p', { class: 'ti-cat-card__desc' }, e.description), keyBox, msg);
  const doAdd = async (btn, key) => {
    msg.replaceChildren();
    const done = tiBusy(btn, 'Adding…');
    let v;
    try {
      v = await api('api/intel/feeds', { catalog: e.id, headers: key ? [{ name: e.key_header, value: key }] : [] });
    } catch (err) {
      done();
      msg.replaceChildren(el('p', { class: 'field-error' }, icon('circle-alert'), sentence(Object.values(err.fields || {})[0] || err.message)));
      return;
    }
    e.added = true;
    e.feed = v.name;
    tiWatch(v);
    toast(`Added ${e.title}.` + (tiState.downloads ? ' It’s downloading now.' : ''));
    loadIntel();
    rerender();
    // Keep keyboard focus where the Add button was.
    const t = document.getElementById(titleId);
    const mark = t && t.closest('.ti-cat-card').querySelector('.ti-added');
    if (mark) mark.focus();
  };
  if (e.added) act.append(el('span', { class: 'ti-added', tabindex: '-1' }, icon('check', 'icon--sm'), 'Added'));
  else if (tiState.manage) {
    const add = el('button', { class: 'btn btn--secondary btn--sm', type: 'button', 'aria-label': `Add ${e.title}` }, icon('plus'), 'Add');
    act.append(add);
    if (e.needs_key) {
      const keyId = 'tf-cat-key-' + e.id;
      const input = el('input', { id: keyId, class: 'input mono', type: 'password', autocomplete: 'off', spellcheck: 'false' });
      const go = el('button', { class: 'btn btn--secondary', type: 'button' }, 'Add feed');
      fill(keyBox,
        el('label', { class: 'label', for: keyId }, `API key (${e.key_header})`),
        el('div', { class: 'ti-cat-key__row' }, input, go),
        el('p', { class: 'hint' }, e.key_help || '', e.key_url ? el('a', { href: e.key_url, target: '_blank', rel: 'noopener noreferrer' }, 'Get a free key') : null));
      add.addEventListener('click', () => { keyBox.hidden = false; add.hidden = true; input.focus(); });
      const submit = () => {
        if (!input.value.trim()) {
          msg.replaceChildren(el('p', { class: 'field-error' }, icon('circle-alert'), `Enter your ${e.provider} API key first.`));
          input.focus();
          return;
        }
        doAdd(go, input.value.trim());
      };
      go.addEventListener('click', submit);
      input.addEventListener('keydown', (ev) => { if (ev.key === 'Enter') { ev.preventDefault(); submit(); } });
    } else add.addEventListener('click', () => doAdd(add));
  }
  return card;
}

// feedForm is the form for a feed from a URL or a TAXII 2.1 collection:
// empty to add one, filled in to edit one. Secrets are write-only: saved
// ones show as "Saved, hidden" and can be replaced or removed.
function feedForm(kind, feed) {
  const seq = tf.seq;
  const alive = () => seq === tf.seq;
  const edit = !!feed;
  const taxii = kind === 'taxii';
  const p = 'tf-' + kind;
  const cat = feed ? tiCatalogFor(feed) : null;
  const msg = el('div', { class: 'ti-msg' });
  const field = (label, input, ...rest) => el('div', { class: 'field' }, el('label', { class: 'label', for: input.id }, label), ...(rest.length ? rest : [input]));
  const select = (id, options, value) => {
    const s = el('select', { id, class: 'select select--block' }, ...options.map(([v, l]) => el('option', { value: v }, l)));
    if (value && !options.some(([v]) => v === value)) s.append(el('option', { value }, value));
    s.value = value || options[0][0];
    return s;
  };

  // where it comes from
  const url = el('input', { id: p + '-url', class: 'input mono', type: 'url', inputmode: 'url', autocomplete: 'off', spellcheck: 'false',
    placeholder: taxii ? 'https://cti.example.com/api1/' : 'https://example.com/blocklist.txt' });
  url.value = feed ? feed.url : '';
  const testBtn = el('button', { class: 'btn btn--secondary', type: 'button' }, icon('play'), 'Test');
  const findBtn = el('button', { class: 'btn btn--secondary', type: 'button' }, icon('list'), 'Find collections');
  const result = el('div', { class: 'ti-result', 'aria-live': 'polite' });

  // more settings
  const name = el('input', { id: p + '-name', class: 'input mono', type: 'text', autocomplete: 'off', spellcheck: 'false', placeholder: 'my-feed' });
  const desc = el('input', { id: p + '-desc', class: 'input', type: 'text', autocomplete: 'off', placeholder: 'What it lists, or who runs it' });
  desc.value = feed ? feed.description || '' : '';
  const format = select(p + '-format', Object.entries(TI_FORMAT), feed ? feed.format : 'auto');
  const column = el('input', { id: p + '-column', class: 'input mono', type: 'text', autocomplete: 'off', spellcheck: 'false', placeholder: 'url or 3' });
  column.value = feed ? feed.column || '' : '';
  const type = select(p + '-type', Object.entries(TI_FEED_TYPE).map(([v, l]) => [v, v === 'auto' ? 'Detect each value' : l]), feed ? feed.type : 'auto');
  const interval = select(p + '-interval', TI_INTERVALS.map((v) => [v, riCap(tiEvery(v))]), feed ? feed.interval : '1h');
  const keep = select(p + '-keep', TI_KEEP.map((v) => [v, tiDur(v)]), feed ? feed.max_age : '7d');
  const weight = el('input', { id: p + '-weight', class: 'input', type: 'number', inputmode: 'decimal', min: '0.1', max: '10', step: '0.25' });
  weight.value = feed ? String(feed.weight) : '1';
  const columnField = field('CSV column', column, column, el('p', { class: 'hint' }, 'Header name, or number from 1'));
  const moreSum = el('span', { class: 'ti-more__sum' });
  const more = el('details', { class: 'ti-more' },
    el('summary', {}, icon('chevron-right', 'ti-chev'), el('span', { class: 'ti-more__title' }, 'More settings'), moreSum),
    el('div', { class: 'ti-more__grid' },
      edit ? null : field('Name', name, name, el('p', { class: 'hint' }, 'Indicators show it as their source')),
      field('Description', desc),
      taxii ? null : field('Format', format),
      taxii ? null : field('Indicator type', type),
      taxii ? null : columnField,
      field('Check for updates', interval),
      field('If downloads stop, keep indicators', keep),
      field('Weight', weight, weight, el('p', { class: 'hint' }, '1 is normal; 2 doubles the risk a match adds'))));
  const syncMore = () => {
    columnField.hidden = format.value !== 'csv';
    const bits = [edit ? null : name.value.trim() || null, tiEvery(interval.value), `kept ${tiDur(keep.value)}`, `weight ${weight.value || 1}`];
    moreSum.textContent = bits.filter(Boolean).join(' · ');
  };
  // Settings a test fills in go back to automatic when the URL changes,
  // unless they were set by hand.
  const own = new Set(edit ? ['name', 'format', 'type', 'column'] : []);
  name.addEventListener('input', () => own.add('name'));
  for (const [k, n] of [['format', format], ['type', type], ['column', column]]) n.addEventListener('change', () => own.add(k));
  for (const n of [name, interval, keep, weight, format]) n.addEventListener(n.tagName === 'SELECT' ? 'change' : 'input', syncMore);

  // secrets: saved headers and password, a new API key header, a user name
  const savedHeaders = (feed ? feed.headers || [] : []).map((h, i) => ({ name: h.name, state: 'keep',
    input: el('input', { id: `${p}-saved-${i}`, class: 'input mono', type: 'password', autocomplete: 'new-password', spellcheck: 'false', 'aria-label': `New value for ${h.name}` }) }));
  const keys = el('div', { class: 'ti-keys', id: p + '-keys' });
  const keyName = el('input', { id: p + '-key-name', class: 'input mono', type: 'text', autocomplete: 'off', spellcheck: 'false', placeholder: taxii ? 'Authorization' : 'X-Api-Key' });
  const keyValue = el('input', { id: p + '-key-value', class: 'input mono', type: 'password', autocomplete: 'new-password', spellcheck: 'false' });
  let keyShown = false;
  const user = el('input', { id: p + '-user', class: 'input', type: 'text', autocomplete: 'off', spellcheck: 'false' });
  user.value = feed ? feed.username || '' : '';
  const pass = el('input', { id: p + '-pass', class: 'input', type: 'password', autocomplete: 'new-password' });
  const pw = { saved: !!(feed && feed.password && feed.password.set), state: 'keep' };
  let auth = feed && feed.username ? 'basic' : feed && savedHeaders.length ? 'key' : 'none';
  let chosen = feed && taxii ? { api_root: feed.url, id: feed.collection, title: '' } : null;
  // collsFor is the address the collections were found at. A Test or Find
  // collections answer counts only while the address it was asked for is
  // still the one in the field (req changes with every request and every
  // edit of the address).
  const addr = (u) => String(u || '').trim().replace(/\/+$/, '').toLowerCase();
  let collsFor = chosen ? addr(feed.url) : '';
  let req = 0;
  let running = null; // re-enables the button of the request in flight
  // failedFor is the request a failed Test was for; saving it then says "anyway".
  let failedFor = null;
  const currentURL = () => (taxii && chosen ? chosen.api_root : url.value.trim());
  const moved = () => edit && tiServer(currentURL()) !== tiServer(feed.url);
  const newKeyRow = () => keyShown || (taxii && !savedHeaders.length);

  // savedRow is a stored secret: "Saved, hidden" with Replace and Remove.
  // When the URL moves to another server it must be entered again.
  const savedRow = (label, s, input, redraw, key) => {
    if (moved() && s.state === 'keep') { s.state = 'replace'; s.auto = true; }
    // Back on the saved server, a key that was only asked for again is kept.
    if (!moved() && s.auto && s.state === 'replace' && !input.value) s.state = 'keep';
    if (s.state !== 'replace') s.auto = false;
    const row = el('div', { class: 'ti-key-saved' + (s.state === 'remove' ? ' is-removed' : ''), 'data-sk': key });
    const btn = (text, run) => el('button', { class: 'btn btn--ghost btn--sm', type: 'button', onclick: () => {
      run();
      redraw();
      const r = node.querySelector(`[data-sk="${key}"]`);
      ((r && (r.querySelector('input') || r.querySelector('button'))) || url).focus();
    } }, text);
    if (s.state === 'replace') {
      input.placeholder = moved() ? 'Enter it again for the new server' : 'New value';
      row.append(el('span', { class: 'mono ti-key-saved__name' }, label), input,
        moved() ? btn('Remove', () => { s.state = 'remove'; input.value = ''; }) : btn('Cancel', () => { s.state = 'keep'; input.value = ''; }));
    } else if (s.state === 'remove') {
      row.append(el('span', { class: 'mono ti-key-saved__name' }, label), el('span', { class: 'ti-key-saved__state' }, 'Removed when you save'),
        btn('Undo', () => { s.state = 'keep'; }));
    } else {
      row.append(el('span', { class: 'mono ti-key-saved__name' }, label), el('span', { class: 'ti-key-saved__state' }, icon('lock', 'icon--xs'), 'Saved, hidden'),
        btn('Replace', () => { s.state = 'replace'; }), btn('Remove', () => { s.state = 'remove'; }));
    }
    return row;
  };
  const keyHint = () => (cat && cat.key_header
    ? el('p', { class: 'hint ti-hint-wrap' }, cat.key_help || '', cat.key_url ? el('a', { href: cat.key_url, target: '_blank', rel: 'noopener noreferrer' }, 'Get a free key') : null)
    : el('p', { class: 'hint ti-hint-wrap' }, taxii ? 'Sent as a request header. For a token, include its scheme, such as Bearer.' : 'Sent as a request header with each download. It is saved on the server and never shown again.'));
  const drawKeys = () => {
    const rows = savedHeaders.map((h, i) => savedRow(h.name, h, h.input, drawKeys, 'h' + i));
    if (newKeyRow()) {
      if (!keyName.value && cat && cat.key_header) keyName.value = cat.key_header;
      if (!keyName.value && taxii && !savedHeaders.length) keyName.value = 'Authorization';
      rows.push(el('div', { class: 'ti-key-new' },
        el('div', { class: 'field' }, el('label', { class: 'label', for: keyName.id }, 'Header name'), keyName),
        el('div', { class: 'field' }, el('label', { class: 'label', for: keyValue.id }, 'API key'), keyValue),
        taxii && !savedHeaders.length ? null : el('button', { class: 'btn btn--ghost btn--icon ti-key-new__x', type: 'button', 'aria-label': 'Don’t add this header', title: 'Don’t add this header',
          onclick: () => { keyShown = false; keyName.value = ''; keyValue.value = ''; drawKeys(); (keys.querySelector('.link-btn') || url).focus(); } }, icon('x'))));
    } else {
      rows.push(el('button', { class: 'link-btn', type: 'button', onclick: () => { keyShown = true; drawKeys(); (keyName.value ? keyValue : keyName).focus(); } },
        icon('plus', 'icon--sm'), savedHeaders.length ? 'Add another header' : cat && cat.key_header ? `Add your ${cat.provider} key` : 'Add an API key'));
    }
    if (newKeyRow()) rows.push(keyHint());
    fill(keys, ...rows);
  };
  const pwBox = el('div', { class: 'field', id: p + '-pw' });
  const drawPassword = () => {
    if (pw.saved) fill(pwBox, el('span', { class: 'label' }, 'Password'), savedRow('Password', pw, pass, drawPassword, 'pw'));
    else fill(pwBox, el('label', { class: 'label', for: pass.id }, 'Password'), pass);
    pass.setAttribute('aria-label', 'Password');
  };

  // TAXII: how to sign in, and the collection to read
  const seg = el('div', { class: 'seg ti-seg', role: 'group', 'aria-labelledby': p + '-auth-label' });
  const authPanel = el('div', { class: 'ti-auth' });
  const drawAuth = () => {
    fill(seg, ...[['none', 'None'], ['basic', 'User name and password'], ['key', 'API key']].map(([v, l]) =>
      el('button', { type: 'button', 'aria-pressed': String(auth === v), onclick: () => { auth = v; drawAuth(); seg.querySelector('[aria-pressed="true"]').focus(); } }, l)));
    if (auth === 'basic') {
      drawPassword();
      fill(authPanel, el('div', { class: 'form-grid' }, field('User name', user), pwBox));
    } else if (auth === 'key') {
      drawKeys();
      fill(authPanel, keys);
    } else {
      fill(authPanel, savedHeaders.length || pw.saved ? el('p', { class: 'hint' }, icon('info'), 'The saved sign-in details are removed when you save.') : null);
    }
  };
  const colls = el('div', { class: 'ti-colls-box', id: p + '-colls' });
  const testRow = el('div', { class: 'ti-test-row' }, testBtn);
  const drawCollections = (list, info) => {
    const items = list.map((c, i) => {
      const r = el('input', { type: 'radio', name: p + '-coll', id: `${p}-coll-${i}`, value: c.id });
      r.checked = !!chosen && chosen.id === c.id;
      r.addEventListener('change', () => {
        chosen = c;
        if (!own.has('name') && !edit && c.title) { name.value = tiUniqueName(tiSlug(c.title)); syncMore(); }
        result.replaceChildren();
        testRow.hidden = false;
      });
      return el('label', { class: 'ti-coll', for: r.id }, r, el('span', { class: 'ti-coll__text' },
        el('span', { class: 'ti-coll__title' }, c.title || 'Saved collection'),
        c.description ? el('span', { class: 'ti-coll__desc' }, c.description) : null,
        el('span', { class: 'mono ti-coll__id' }, c.id)));
    });
    fill(colls, items.length ? el('fieldset', { class: 'ti-colls' }, el('legend', { class: 'label' }, info.title ? `Collections on ${info.title}` : 'Collection'), ...items) : null,
      info.note ? el('p', { class: 'hint' }, info.note) : null);
    testRow.hidden = !chosen;
  };

  // body is the request: the form's settings, with each secret set, kept
  // or cleared.
  const body = (forTest) => {
    const b = { kind, url: currentURL() };
    if (!edit && !forTest) b.name = name.value.trim();
    if (!forTest) {
      b.description = desc.value.trim();
      b.interval = interval.value;
      b.max_age = keep.value;
      const w = parseFloat(weight.value);
      if (isFinite(w)) b.weight = w;
    }
    if (taxii) b.collection = chosen ? chosen.id : '';
    else {
      b.format = format.value;
      b.type = type.value;
      b.column = format.value === 'csv' || format.value === 'auto' ? column.value.trim() : '';
    }
    const useKeys = !taxii || auth === 'key';
    b.headers = savedHeaders.map((h) => {
      if (!useKeys || h.state === 'remove') return { name: h.name, clear: true };
      if (h.state === 'replace' && h.input.value.trim()) return { name: h.name, value: h.input.value.trim() };
      return { name: h.name };
    });
    if (useKeys && newKeyRow() && (keyName.value.trim() || keyValue.value.trim())) b.headers.push({ name: keyName.value.trim(), value: keyValue.value.trim() });
    if (taxii) {
      if (auth === 'basic') {
        b.username = user.value.trim();
        if (pw.saved && pw.state === 'remove') b.clear_password = true;
        else if (!pw.saved || pw.state === 'replace') b.password = pass.value;
      } else {
        b.username = '';
        if (pw.saved) b.clear_password = true;
      }
    }
    if (edit && forTest) b.feed = feed.name; // the test uses the saved secrets
    return b;
  };

  // errors: next to their settings, the rest at the top
  const targets = { name, url, collection: colls, format, type, column, interval, max_age: keep, weight, description: desc, headers: keys, username: user, password: pwBox, kind: url, catalog: url };
  const clearErrors = () => {
    msg.replaceChildren();
    node.querySelectorAll('.ti-ferr').forEach((n) => n.remove());
    node.querySelectorAll('[aria-invalid]').forEach((n) => { n.removeAttribute('aria-invalid'); n.removeAttribute('aria-describedby'); });
  };
  const markField = (t, text) => {
    const isInput = t.matches('input, select');
    const box = isInput ? t.closest('.field') : t;
    if (!box || box.querySelector(':scope > .ti-ferr')) return;
    const id = (t.id || p) + '-error';
    box.append(el('p', { class: 'field-error ti-ferr', id }, icon('circle-alert'), sentence(text)));
    const input = isInput ? t : t.querySelector('input:not([type=radio]), select');
    if (input) { input.setAttribute('aria-invalid', 'true'); input.setAttribute('aria-describedby', id); }
    if (more.contains(box)) more.open = true;
  };
  const showErrors = (e, what) => {
    const shown = [];
    for (const [k, text] of Object.entries(e.fields || {})) {
      const t = targets[k];
      if (t && t.isConnected) { markField(t, text); shown.push(text); }
    }
    const rest = (e.problems || []).filter((x) => !shown.includes(x));
    if (shown.length && !rest.length) msg.replaceChildren(riAlert('danger', 'Please fix the marked settings.'));
    else if (rest.length) msg.replaceChildren(riAlert('danger', 'Please fix these settings.', el('ul', { class: 'ti-problems' }, ...rest.map((x) => el('li', {}, sentence(x))))));
    else msg.replaceChildren(riAlert('danger', what, el('p', {}, sentence(e.message))));
    const first = node.querySelector('[aria-invalid="true"]');
    if (first) first.focus();
    else msg.scrollIntoView({ block: 'nearest' });
  };
  const needURL = () => {
    const v = url.value.trim();
    let why = '';
    if (!v) why = taxii ? 'Enter the server’s address.' : 'Enter the feed’s address.';
    else if (!/^https?:\/\/[^\s/?#]+/i.test(v)) why = 'Use an address that starts with https:// or http://.';
    else if (/^https?:\/\/[^/?#]*@/i.test(v)) why = taxii ? 'Leave the user name and password out of the address; choose User name and password under Sign in.' : 'Leave the user name and password out of the address.';
    if (!why) return true;
    markField(url, why);
    url.focus();
    return false;
  };
  const needAuth = () => {
    if (taxii && auth === 'basic') {
      if (!user.value.trim()) { markField(user, 'Enter the user name.'); user.focus(); return false; }
      if (!pw.saved && !pass.value) { markField(pass, 'Enter the password.'); pass.focus(); return false; }
      if (pw.saved && pw.state === 'replace' && moved() && !pass.value) {
        markField(pwBox, 'Enter the password again for the new server, or remove it.');
        pass.focus();
        return false;
      }
    }
    // Saved keys are only sent to the server they were entered for.
    const again = moved() && (!taxii || auth === 'key') ? savedHeaders.find((h) => h.state === 'replace' && !h.input.value.trim()) : null;
    if (again) { markField(keys, `Enter ${again.name} again for the new server, or remove it.`); again.input.focus(); return false; }
    if (!newKeyRow() || (taxii && auth !== 'key')) return true;
    const n = keyName.value.trim();
    const v = keyValue.value.trim();
    if (v && !n) { markField(keys, 'Enter the header name, such as X-Api-Key.'); keyName.focus(); return false; }
    if (!v && (n || (taxii && !savedHeaders.length))) { markField(keys, taxii ? 'Enter the API key, or choose None.' : `Enter the key for ${n}, or remove the header.`); keyValue.focus(); return false; }
    return true;
  };

  // Test downloads the feed without saving it and shows what it found.
  const runTest = async () => {
    clearErrors();
    if (!needURL() || !needAuth()) return;
    if (taxii && !chosen) { markField(colls, 'Find the server’s collections and choose one first.'); findBtn.focus(); return; }
    const my = ++req;
    const b = body(true);
    const done = tiBusy(testBtn, 'Testing…');
    running = done;
    result.replaceChildren(el('div', { class: 'ti-test', 'data-tone': 'busy' }, icon('cloud-download'),
      el('div', { class: 'ti-test__body' }, el('b', {}, `Downloading from ${tiHost(currentURL()) || 'the server'}…`), el('span', { class: 'skeleton' }))));
    let r;
    try {
      r = await api('api/intel/feeds/test', b);
    } catch (e) {
      if (!alive() || my !== req) return;
      done();
      running = null;
      result.replaceChildren();
      showErrors(e, 'Couldn’t test the feed.');
      return;
    }
    // The address changed meanwhile: this answer is for another feed.
    if (!alive() || my !== req) return;
    done();
    running = null;
    if (r.ok && !taxii) {
      // Fill in what was detected, unless set by hand.
      if (!own.has('format') && format.value === 'auto' && r.format) format.value = r.format;
      if (!own.has('column') && r.column) column.value = r.column;
      if (!own.has('type') && type.value === 'auto' && r.type) type.value = r.type;
      syncMore();
    }
    failedFor = r.ok ? null : JSON.stringify(body(true));
    syncSave();
    result.replaceChildren(testResult(r));
    result.scrollIntoView({ block: 'nearest' });
  };
  const testResult = (r) => {
    // The way to add a key or sign in is right above the result.
    if (!r.ok) return riAlert('danger', 'The test failed.', el('p', {}, r.error || 'The feed could not be read.'));
    const types = Object.entries(r.by_type || {}).sort((a, b) => b[1] - a[1]);
    const typeText = types.length === 1 ? TI_FEED_TYPE[types[0][0]] || types[0][0]
      : types.map(([t, n]) => `${n.toLocaleString()} ${(TI_NOUN[t] || [t, t])[n === 1 ? 0 : 1]}`).join(', ');
    const notes = [];
    if (r.note) notes.push(r.note);
    if (r.skipped) notes.push(`${tiPlural(r.skipped, 'line')} skipped as not valid indicators` + (r.skipped_example ? `, such as “${r.skipped_example}”.` : '.'));
    if (r.reserved) notes.push(`${tiPlural(r.reserved, 'private or reserved network')} skipped, so they never match your own network.`);
    const samples = (r.samples || []).slice(0, 5);
    return el('div', { class: 'ti-test', 'data-tone': 'ok' }, icon('circle-check'),
      el('div', { class: 'ti-test__body' },
        el('b', {}, `Found ${tiPlural(r.total, 'indicator')}`),
        el('p', { class: 'ti-test__meta' }, [taxii ? 'STIX 2.1' : tiFormatText(r.format, r.column), typeText, r.bytes ? tiBytes(r.bytes) : ''].filter(Boolean).join(' · ')),
        samples.length ? el('ul', { class: 'ti-samples', 'aria-label': 'Examples' }, ...samples.map((s) => el('li', {},
          el('span', { class: 'mono' }, s.value), s.description ? el('span', { class: 'ti-samples__desc' }, s.description) : null)),
        r.total > samples.length ? el('li', { class: 'ti-samples__more' }, `and ${(r.total - samples.length).toLocaleString()} more`) : null) : null,
        ...notes.map((n) => el('p', { class: 'ti-test__note' }, icon('info', 'icon--sm'), el('span', {}, n)))));
  };

  // Find collections lists the TAXII server's readable collections.
  const findCollections = async () => {
    clearErrors();
    if (!needURL() || !needAuth()) return;
    const my = ++req;
    const asked = url.value.trim();
    const done = tiBusy(findBtn, 'Looking…');
    running = done;
    fill(colls, el('div', { class: 'ti-test', 'data-tone': 'busy' }, icon('server'),
      el('div', { class: 'ti-test__body' }, el('b', {}, `Asking ${tiHost(asked)}…`), el('span', { class: 'skeleton' }))));
    const b = body(true);
    b.url = asked;
    if (edit) b.feed = feed.name;
    let r;
    try {
      r = await api('api/intel/taxii/collections', b);
    } catch (e) {
      if (!alive() || my !== req) return;
      done();
      running = null;
      colls.replaceChildren();
      showErrors(e, 'Couldn’t list the collections.');
      return;
    }
    // The address changed meanwhile: these are another server's collections.
    if (!alive() || my !== req) return;
    done();
    running = null;
    result.replaceChildren();
    failedFor = null;
    syncSave();
    if (!r.ok) {
      chosen = null;
      collsFor = '';
      testRow.hidden = true;
      fill(colls, riAlert('danger', 'Couldn’t list the collections.', el('p', {}, r.error)));
      return;
    }
    const readable = (r.collections || []).filter((c) => c.can_read);
    const hidden = (r.collections || []).length - readable.length;
    chosen = (chosen && readable.find((c) => c.id === chosen.id && addr(c.api_root) === addr(chosen.api_root))) || (readable.length === 1 ? readable[0] : null);
    collsFor = addr(asked);
    if (chosen && !own.has('name') && !edit) { name.value = tiUniqueName(tiSlug(chosen.title || chosen.id)); syncMore(); }
    if (!readable.length) {
      testRow.hidden = true;
      fill(colls, riAlert('warning', hidden ? `None of the ${hidden} collections can be read with these sign-in details.` : 'This server has no collections.',
        el('p', {}, hidden ? 'Check the user name, password or API key, or ask the server’s administrator for read access.' : 'Check the address: it should be the API root that holds the collections.')));
      return;
    }
    drawCollections(readable, { title: r.title, note: hidden ? `${tiPlural(hidden, 'more collection')} can’t be read with these sign-in details.` : '' });
    const pick = colls.querySelector('input:checked') || colls.querySelector('input');
    if (pick) pick.focus();
  };

  // syncSave says "anyway" on the main button after a failed Test of the
  // settings in the form.
  const syncSave = () => {
    const anyway = failedFor !== null && failedFor === JSON.stringify(body(true));
    saveBtn.textContent = anyway ? (edit ? 'Save anyway' : 'Add anyway') : (edit ? 'Save changes' : 'Add feed');
  };

  // Save adds the feed or saves the changes; it downloads at once.
  const save = async (ev) => {
    ev.preventDefault();
    clearErrors();
    if (!needURL() || !needAuth()) return;
    if (taxii && !chosen) { markField(colls, 'Find the server’s collections and choose one.'); findBtn.focus(); return; }
    if (!edit && !name.value.trim()) name.value = taxii ? tiUniqueName(tiSlug((chosen && chosen.title) || 'taxii')) : tiNameFor(url.value.trim()) || tiUniqueName('feed');
    const done = tiBusy(saveBtn, edit ? 'Saving…' : 'Adding…');
    let v;
    try {
      v = edit ? await api('api/intel/feeds/' + encodeURIComponent(feed.name), body(false), 'PUT', tiIfMatch(feed.name)) : await api('api/intel/feeds', body(false));
    } catch (e) {
      if (!alive()) return;
      done();
      if (edit && e.status === 412) {
        // Someone changed the feed since the page read it: read their
        // version (and its new ETag), so saving again replaces it.
        await loadIntel();
        if (!alive()) return;
        msg.replaceChildren(riAlert('warning', 'Someone else changed this feed meanwhile.',
          el('p', {}, 'The page now has their version. Save again to replace it with yours.')));
        msg.scrollIntoView({ block: 'nearest' });
        return;
      }
      showErrors(e, edit ? 'Couldn’t save the feed.' : 'Couldn’t add the feed.');
      return;
    }
    if (!alive()) return;
    done();
    $('ti-feed-dialog').close();
    tiWatch(v);
    toast((edit ? `Saved ${v.name}.` : `Added ${v.name}.`) + (v.enabled ? ' It’s downloading now.' : ''));
    for (const e of tiCat.list || []) if (e.id === v.catalog) { e.added = true; e.feed = v.name; }
    loadIntel();
  };

  const saveBtn = el('button', { class: 'btn btn--primary', type: 'submit' }, edit ? 'Save changes' : 'Add feed');
  const parts = [msg];
  if (taxii) {
    parts.push(field('Server address', url, url,
      el('p', { class: 'hint ti-hint-wrap' }, 'The API root, such as https://cti.example.com/api1/, or the discovery address ending in /taxii2/.')));
    parts.push(el('div', { class: 'field' }, el('span', { class: 'label', id: p + '-auth-label' }, 'Sign in'), seg, authPanel));
    parts.push(el('div', { class: 'ti-find-row' }, findBtn), colls, testRow);
  } else {
    parts.push(field('Feed URL', url, el('div', { class: 'ti-url-row' }, url, testBtn),
      el('p', { class: 'hint ti-hint-wrap' }, 'A plain list, CSV or STIX 2.1 file. Signalith works out the format.')));
    parts.push(keys);
  }
  parts.push(result, more);
  const node = el('form', { class: 'ti-feed-form', novalidate: '', autocomplete: 'off' },
    el('div', { class: 'modal__body' }, ...parts),
    el('div', { class: 'modal__foot' }, el('button', { class: 'btn btn--ghost', type: 'button', onclick: () => $('ti-feed-dialog').close() }, 'Cancel'), saveBtn));
  node.addEventListener('submit', save);
  for (const ev of ['input', 'change']) node.addEventListener(ev, () => { if (failedFor !== null) syncSave(); });
  testBtn.addEventListener('click', runTest);
  findBtn.addEventListener('click', findCollections);
  url.addEventListener('keydown', (ev) => {
    if (ev.key !== 'Enter') return;
    ev.preventDefault();
    (taxii ? findCollections : runTest)();
  });
  url.addEventListener('input', () => {
    // An answer still on its way belongs to the old address: drop it, and
    // let Test and Find collections run again at once.
    req++;
    const asking = !!colls.querySelector('[data-tone="busy"]');
    if (running) { running(); running = null; }
    result.replaceChildren();
    if (!edit && !own.has('name') && !taxii) name.value = tiNameFor(url.value.trim());
    if (!taxii) {
      // What a test filled in belongs to the old URL.
      if (!own.has('format')) format.value = 'auto';
      if (!own.has('type')) type.value = 'auto';
      if (!own.has('column')) column.value = '';
    } else if (asking || addr(url.value) !== collsFor) {
      // The collections, and the one chosen, are another address's.
      chosen = null;
      collsFor = '';
      colls.replaceChildren();
      testRow.hidden = true;
    }
    syncMore();
    if (savedHeaders.length) drawKeys();
    if (taxii && auth === 'basic' && pw.saved) drawPassword();
  });
  if (taxii) {
    drawAuth();
    if (chosen) drawCollections([chosen], {});
    else testRow.hidden = true;
  } else drawKeys();
  syncMore();
  return { node, focus: () => url.focus() };
}

// ---------- indicators ----------
const TI_IND_COLS = [['Indicator', 'ti-c-ind'], ['Type', 'hide-sm ti-c-type'], ['Source', 'hide-sm ti-c-source'], ['Weight', 'num hide-sm ti-c-weight', 'Multiplies the risk a match adds'],
  ['Last seen', 'hide-sm ti-c-seen'], ['Expires', 'hide-sm ti-c-exp']];

async function loadIndicators() {
  const seq = ++tiState.listSeq;
  const q = $('ti-q').value.trim();
  const p = new URLSearchParams({ limit: tiState.limit, offset: tiState.offset });
  if (q) p.set('q', q);
  if (tiState.type) p.set('type', tiState.type);
  if ($('ti-source').value) p.set('source', $('ti-source').value);
  if (!tiState.loaded) $('ti-list').replaceChildren(riSkeleton(TI_IND_COLS));
  else $('ti-list').querySelector('table')?.setAttribute('aria-busy', 'true');
  let res;
  try {
    res = await api('api/intel/indicators?' + p);
  } catch (e) {
    if (seq !== tiState.listSeq) return;
    tiState.loaded = false;
    tiState.list = [];
    $('ti-count').textContent = '';
    $('ti-prev').disabled = true;
    $('ti-next').disabled = true;
    $('ti-list').replaceChildren(riEmpty({ icon: 'circle-alert', tone: 'danger', title: 'Couldn’t load indicators', text: riCap(e.message) + '. Your filters are kept.', action: riRetry(loadIndicators) }));
    return;
  }
  let lookup = null;
  if (!(res.indicators || []).length && q) {
    // A value inside a listed network, or a URL on a listed domain, is not
    // a text match; ask the server the way a search would.
    try { lookup = (await api('api/intel/lookup?' + new URLSearchParams({ value: q }))).matches || []; } catch (_) { lookup = null; }
    if (lookup) lookup = lookup.filter((m) => (!tiState.type || TI_CLASS[m.type] === tiState.type) && (!$('ti-source').value || m.source === $('ti-source').value));
  }
  if (seq !== tiState.listSeq) return;
  tiState.loaded = true;
  tiState.list = res.indicators || [];
  tiState.total = res.total || 0;
  tiState.lookup = lookup && lookup.length ? lookup : null;
  renderIndicators();
}

const tiShown = () => tiState.lookup || tiState.list;
const tiFiltered = () => !!($('ti-q').value.trim() || tiState.type || $('ti-source').value);

function renderIndicators() {
  const box = $('ti-list');
  // A redraw keeps keyboard focus on the same row.
  const a = document.activeElement;
  const focusId = a && box.contains(a) ? (a.closest('tr[data-id]') || {}).dataset?.id : null;
  const list = tiState.list;
  const end = tiState.offset + list.length;
  $('ti-prev').disabled = tiState.offset === 0;
  $('ti-next').disabled = end >= tiState.total;
  $('ti-prev').classList.toggle('hidden', tiState.total <= tiState.limit);
  $('ti-next').classList.toggle('hidden', tiState.total <= tiState.limit);
  const shown = tiShown();
  if (tiState.lookup) {
    const n = tiState.lookup.length;
    $('ti-count').textContent = `${n} ${n === 1 ? 'indicator matches' : 'indicators match'} by network or host`;
  } else if (tiState.total) {
    $('ti-count').textContent = tiState.total > list.length || tiState.offset
      ? `${(tiState.offset + 1).toLocaleString()}–${end.toLocaleString()} of ${tiState.total.toLocaleString()}`
      : `${tiState.total.toLocaleString()} ${tiState.total === 1 ? 'indicator' : 'indicators'}`;
  } else $('ti-count').textContent = '';
  if (tiState.open && !shown.some((i) => i.id === tiState.open)) closeIndicator();
  if (!shown.length) {
    box.replaceChildren(tiFiltered()
      ? riEmpty({ icon: 'search', title: 'No indicators match', text: 'Nothing matches these filters. A value inside a listed network still counts as a match.', action: { label: 'Clear filters', run: clearIntelFilters } })
      : riEmpty({ icon: 'radar', title: 'No indicators yet', text: can('analyst') ? 'Indicators come from feeds. Add your own with Add indicators.' : 'Indicators come from feeds and from analysts.' }));
    return;
  }
  const rows = shown.map((ind) => {
    const open = () => showIndicator(ind.id);
    const tr = el('tr', { 'data-id': ind.id, onclick: open },
      el('td', { class: 'ti-c-ind' }, tiChip(ind), el('span', { class: 'ti-sub' }, ind.description || (ind.tags || []).join(', '))),
      el('td', { class: 'hide-sm ti-c-type muted' }, TI_TYPE_SHORT[ind.type] || ind.type),
      el('td', { class: 'hide-sm ti-c-source muted' }, tiSourceLabel(ind.source)),
      el('td', { class: 'num hide-sm ti-c-weight' }, tiWeight(ind.weight)),
      el('td', { class: 'hide-sm ti-c-seen' }, el('span', { class: 'age', title: ind.first_seen ? 'First seen ' + fmtTime(ind.first_seen) : '' }, ago(ind.last_seen))),
      el('td', { class: 'hide-sm ti-c-exp' }, el('span', { class: 'age', title: ind.expires ? fmtTime(ind.expires) : '' }, ind.expires ? until(ind.expires) : 'Never')));
    if (ind.id === tiState.open) tr.setAttribute('aria-selected', 'true');
    riRowKeys(tr, open, () => !!tiState.open);
    return tr;
  });
  fill(box,
    tiState.lookup ? el('div', { class: 'ti-note' }, el('div', { class: 'callout' }, icon('info'),
      el('div', {}, 'No indicator contains ', el('b', { class: 'mono' }, $('ti-q').value.trim()), ', but it matches these the way a search would.'))) : null,
    el('table', { class: 'table ti-ind-table' }, riHead(TI_IND_COLS), el('tbody', {}, ...rows)));
  if (focusId) {
    const row = box.querySelector(`tr[data-id="${CSS.escape(focusId)}"]`);
    if (row) row.focus({ preventScroll: true });
  }
}

function clearIntelFilters() {
  $('ti-q').value = '';
  $('ti-source').value = '';
  tiState.type = '';
  tiState.offset = 0;
  renderTypePills();
  loadIndicators();
}

function markIndicatorRow() {
  $('ti-list').querySelectorAll('tbody tr').forEach((tr) => {
    if (tr.dataset.id === tiState.open) tr.setAttribute('aria-selected', 'true');
    else tr.removeAttribute('aria-selected');
  });
}

function closeIndicator() {
  if (!tiState.open) return;
  const hadFocus = $('ti-detail').contains(document.activeElement);
  const row = $('ti-list').querySelector('tr[aria-selected="true"]');
  tiState.open = null;
  riHidePanel($('ti-detail'));
  markIndicatorRow();
  if (row && (hadFocus || document.activeElement === document.body)) row.focus();
}
riInspectors.push({ page: 'intel', panel: $('ti-detail'), close: closeIndicator });

function showIndicator(id) {
  const shown = tiShown();
  const idx = shown.findIndex((i) => i.id === id);
  if (idx < 0) return;
  const ind = shown[idx];
  tiState.open = id;
  markIndicatorRow();
  const box = $('ti-detail');
  const step = (d) => { const o = shown[idx + d]; if (o) showIndicator(o.id); };
  const bar = el('div', { class: 'inspector__bar' }, icon(TI_TYPE_ICON[ind.type] || 'hash', 'icon--sm'), el('span', {}, TI_TYPE_LABEL[ind.type] || ind.type),
    el('span', {}, `· ${idx + 1} of ${shown.length}`), el('span', { class: 'spacer' }),
    riIconBtn('chevron-up', 'Previous', () => step(-1), idx === 0),
    riIconBtn('chevron-down', 'Next', () => step(1), idx === shown.length - 1),
    riIconBtn('x', 'Close details', closeIndicator));
  const title = el('h2', { class: 'inspector__title mono ti-value', tabindex: '-1' }, ind.value);
  const meta = el('div', { class: 'inspector__meta' }, el('span', {}, tiSourceLabel(ind.source)), el('span', { class: 'dotsep' }),
    el('span', {}, `Weight ${tiWeight(ind.weight)}`), el('span', { class: 'dotsep' }), el('span', { title: fmtTime(ind.last_seen) }, 'seen ' + ago(ind.last_seen)));
  const kv = [];
  const add = (k, v) => { if (v) kv.push(el('dt', {}, k), el('dd', {}, v)); };
  add('Type', TI_TYPE_LABEL[ind.type] || ind.type);
  add('Source', ind.source === 'manual' ? 'Added by hand or uploaded' : ind.source === TI_SAMPLE ? 'The sample data' : ind.source);
  add('Weight', `${tiWeight(ind.weight)} (multiplies the risk a match adds)`);
  add('First seen', ind.first_seen ? fmtTime(ind.first_seen) : '');
  add('Last seen', ind.last_seen ? fmtTime(ind.last_seen) : '');
  add('Expires', ind.expires ? `${fmtTime(ind.expires)} (${until(ind.expires)})` : 'Never');
  add('ID', el('span', { class: 'mono' }, ind.id));
  // A feed's indicators return with its next download; those of a deleted
  // feed stay until they expire, and can be deleted one by one.
  const manual = ind.source === 'manual';
  const sample = ind.source === TI_SAMPLE;
  const feedGone = !manual && !sample && !tiState.feeds.some((f) => f.name === ind.source);
  const body = el('div', { class: 'inspector__body' },
    ind.description ? el('p', {}, ind.description) : null,
    (ind.tags || []).length ? el('section', { class: 'section', 'aria-label': 'Tags' }, el('h3', { class: 'section-title' }, 'Tags'),
      el('div', { class: 'chips' }, ...ind.tags.map((t) => el('span', { class: 'chip' }, el('span', {}, t))))) : null,
    el('section', { class: 'section', 'aria-label': 'Details' }, el('h3', { class: 'section-title' }, 'Details'), el('dl', { class: 'kv' }, ...kv)),
    manual ? null : sample ? el('div', { class: 'callout' }, icon('info'), el('div', {}, 'This comes with the sample data and goes when you remove it on the ', el('a', { href: '#data', 'data-page': 'data' }, 'Add data'), ' page.'))
      : el('div', { class: 'callout' }, icon('info'), feedGone
      ? el('div', {}, 'The feed ', el('b', {}, ind.source), ' was deleted. This stays until it expires, or you can delete it now.')
      : el('div', {}, 'This comes from the feed ', el('b', {}, ind.source), ' and returns with its next download. To stop using it, turn the feed off.')));
  const foot = el('div', { class: 'inspector__foot' },
    el('button', { class: 'btn btn--secondary', type: 'button', title: 'Search the last 7 days for this indicator', onclick: () => openSearch(huntQuery(ind), '-7d') }, icon('search'), 'Search events'));
  if ((manual || feedGone) && can('analyst')) {
    foot.append(el('span', { class: 'spacer' }), el('button', { class: 'btn btn--ghost', type: 'button', onclick: () => confirmDelete(ind) }, icon('trash-2'), 'Delete'));
  }
  box.replaceChildren(bar, el('div', { class: 'inspector__head' }, title, meta), body, foot);
  const wasOpen = !box.classList.contains('hidden');
  riShowPanel(box);
  if (riSlideOver.matches && !wasOpen) title.focus();
  if (!wasOpen) riReveal(box);
}

// ---------- delete an indicator ----------
let tiDeleting = null;
function confirmDelete(ind) {
  tiDeleting = ind;
  $('ti-confirm-desc').replaceChildren(el('span', { class: 'mono' }, ind.value), ' stops matching events right away.');
  $('ti-confirm-delete').disabled = false;
  $('ti-confirm').showModal();
}
$('ti-confirm-delete').addEventListener('click', async () => {
  const ind = tiDeleting;
  if (!ind) return;
  const btn = $('ti-confirm-delete');
  btn.disabled = true;
  try {
    await api('api/intel/indicators/' + encodeURIComponent(ind.id), undefined, 'DELETE');
  } catch (e) {
    btn.disabled = false;
    $('ti-confirm-desc').replaceChildren(riAlert('danger', 'Couldn’t delete it.', el('p', {}, riCap(e.message) + '.')));
    return;
  }
  $('ti-confirm').close();
  closeIndicator();
  toast(`Deleted ${ind.value}.`);
  loadIntel();
});

// ---------- add and upload indicators ----------
function selectAddTab(which, focus) {
  const one = which === 'one';
  $('ti-tab-one').setAttribute('aria-selected', String(one));
  $('ti-tab-upload').setAttribute('aria-selected', String(!one));
  $('ti-tab-one').tabIndex = one ? 0 : -1;
  $('ti-tab-upload').tabIndex = one ? -1 : 0;
  $('ti-add').hidden = !one;
  $('ti-upload-panel').hidden = one;
  if (focus) (one ? $('ti-tab-one') : $('ti-tab-upload')).focus();
}
for (const [id, which] of [['ti-tab-one', 'one'], ['ti-tab-upload', 'upload']]) {
  $(id).addEventListener('click', () => selectAddTab(which));
  $(id).addEventListener('keydown', (ev) => {
    if (ev.key !== 'ArrowLeft' && ev.key !== 'ArrowRight') return;
    ev.preventDefault();
    selectAddTab(which === 'one' ? 'upload' : 'one', true);
  });
}

function clearFieldError(input) {
  input.removeAttribute('aria-invalid');
  input.removeAttribute('aria-describedby');
  const err = input.parentElement.querySelector('.field-error');
  if (err) err.remove();
}
function setFieldError(input, text) {
  clearFieldError(input);
  input.setAttribute('aria-invalid', 'true');
  input.setAttribute('aria-describedby', input.id + '-error');
  input.parentElement.append(el('span', { class: 'field-error', id: input.id + '-error' }, icon('circle-alert'), text));
}

$('ti-add-open').addEventListener('click', () => {
  $('ti-add-msg').replaceChildren();
  $('ti-upload-msg').replaceChildren();
  clearFieldError($('ti-value'));
  clearFieldError($('ti-file'));
  selectAddTab('one');
  $('ti-add-dialog').showModal();
  $('ti-value').focus();
});
$('ti-value').addEventListener('input', () => clearFieldError($('ti-value')));
$('ti-file').addEventListener('change', () => { clearFieldError($('ti-file')); $('ti-upload-msg').replaceChildren(); });

$('ti-add').addEventListener('submit', async (ev) => {
  ev.preventDefault();
  const msg = $('ti-add-msg');
  msg.replaceChildren();
  if (!$('ti-value').value.trim()) {
    setFieldError($('ti-value'), 'Enter an IP address, network, domain, URL, hash or email address.');
    $('ti-value').focus();
    return;
  }
  const body = {
    value: $('ti-value').value, type: $('ti-add-type').value, description: $('ti-desc').value,
    weight: $('ti-weight').value, expires: $('ti-expires').value,
    tags: $('ti-tags').value.split(',').map((t) => t.trim()).filter(Boolean),
  };
  const btn = $('ti-add-submit');
  btn.disabled = true;
  try {
    const ind = await api('api/intel/indicators', body);
    $('ti-add-dialog').close();
    toast(`Added ${TI_TYPE_LABEL[ind.type] || ind.type} ${ind.value}. Searches and the threat detection use it right away.`);
    $('ti-value').value = '';
    $('ti-desc').value = '';
    loadIntel();
  } catch (e) {
    msg.replaceChildren(riAlert('danger', 'Couldn’t add it.', el('p', {}, riCap(e.message) + '.')));
  } finally {
    btn.disabled = false;
  }
});

$('ti-upload').addEventListener('click', async () => {
  const msg = $('ti-upload-msg');
  msg.replaceChildren();
  const file = $('ti-file').files[0];
  if (!file) {
    setFieldError($('ti-file'), 'Choose a CSV or text file first.');
    $('ti-file').focus();
    return;
  }
  const btn = $('ti-upload');
  btn.disabled = true;
  try {
    const text = await file.text();
    const resp = await apiRaw('api/intel/upload', { method: 'POST', headers: { 'Content-Type': 'text/csv' }, body: text });
    const data = await resp.json().catch(() => ({}));
    if (!resp.ok) {
      msg.replaceChildren(riAlert('danger', riCap(data.error || resp.statusText) + '.', riLineErrors(data.lines)));
      return;
    }
    $('ti-add-dialog').close();
    toast(`Added ${data.count.toLocaleString()} ${data.count === 1 ? 'indicator' : 'indicators'}.`);
    $('ti-file').value = '';
    loadIntel();
  } catch (e) {
    msg.replaceChildren(riAlert('danger', 'The upload failed.', el('p', {}, e.message)));
  } finally {
    btn.disabled = false;
  }
});

for (const d of ['ti-add-dialog', 'ti-confirm']) {
  $(d).querySelectorAll('[data-close]').forEach((b) => b.addEventListener('click', () => $(d).close()));
}

// ---------- filters and actions ----------
let tiTimer = null;
$('ti-q').addEventListener('input', () => {
  clearTimeout(tiTimer);
  tiTimer = setTimeout(() => { tiState.offset = 0; loadIndicators(); }, 250);
});
$('ti-source').addEventListener('change', () => { tiState.offset = 0; loadIndicators(); });
$('ti-prev').addEventListener('click', () => { tiState.offset = Math.max(0, tiState.offset - tiState.limit); loadIndicators(); });
$('ti-next').addEventListener('click', () => { tiState.offset += tiState.limit; loadIndicators(); });
$('ti-refresh').addEventListener('click', loadIntel);
$('ti-hunt').addEventListener('click', () => openSearch(TI_HUNT, '-24h'));
$('ti-feed-add').addEventListener('click', () => openFeedDialog({ tab: 'catalog' }));

pageHooks.push((name) => {
  if (name === 'intel') loadIntel();
});
