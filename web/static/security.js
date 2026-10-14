// Security page (admins): whether Signalith is set up safely, and what to
// fix first. The checks run on the server (internal/security), the same
// ones `signalith security` prints; this page only draws api/security: a
// summary with the three things to fix first, then one card per group of
// checks. A problem folds away how to fix it, and a good row that could be
// stronger folds away how; nothing opens by itself. While Signalith is
// changing its own certificate authority, a panel above the groups walks
// through the steps.
'use strict';

(function () {
  const S = { rep: null, seq: 0, tries: 0, ticker: null };

  // Each state has its own icon shape, so colour is never the only signal.
  const STATE = {
    risk: { icon: 'circle-alert', word: 'At risk' },
    attention: { icon: 'triangle-alert', word: 'Needs attention' },
    unknown: { icon: 'circle-help', word: 'Can’t tell' },
    good: { icon: 'circle-check', word: 'Good' },
  };
  const ORDER = { risk: 0, attention: 1, unknown: 2, good: 3 };
  const GROUP_ICON = { transit: 'network', rest: 'hard-drive', use: 'cpu', accounts: 'users', host: 'server' };
  const FAMILY = { linux: 'Linux', windows: 'Windows PowerShell', docker: 'Docker' };
  const SCOPE = { standard: 'standard', strict: 'strict', unconstrained: 'older, unlimited' };
  const DOCS = 'https://github.com/jrsamsanchez/signalith/blob/';

  // ---------- words ----------
  const plural = (n, one, many) => `${n} ${n === 1 ? one : many}`;
  const needs = (n) => (n === 1 ? '1 needs attention' : `${n} need attention`);
  const DAY = { day: 'numeric', month: 'short', year: 'numeric' };
  const dayText = (t) => new Date(t).toLocaleDateString('en-GB', DAY);
  const fullTime = (t) => new Date(t).toLocaleString('en-GB', { ...DAY, hour: '2-digit', minute: '2-digit' });
  function agoText(t) {
    const s = (Date.now() - new Date(t).getTime()) / 1000;
    if (!isFinite(s)) return '';
    if (s < 45) return 'just now';
    if (s < 3600) return plural(Math.max(1, Math.round(s / 60)), 'minute', 'minutes') + ' ago';
    if (s < 86400) return plural(Math.floor(s / 3600), 'hour', 'hours') + ' ago';
    return plural(Math.floor(s / 86400), 'day', 'days') + ' ago';
  }
  // timeEl is a relative time that the ticker keeps current, with the
  // full time as its tooltip.
  const timeEl = (t) => el('time', { datetime: new Date(t).toISOString(), title: fullTime(t), 'data-ago': String(t) }, agoText(t));
  function listWords(items) {
    if (items.length <= 1) return items.join('');
    return items.slice(0, -1).join(', ') + ' and ' + items[items.length - 1];
  }
  // docsURL links to the docs of this version: its release tag, else main.
  function docsURL(file, anchor) {
    const v = (S.rep && S.rep.server.version) || '';
    const ref = /^v\d+\.\d+\.\d+$/.test(v) ? v : 'main';
    return DOCS + ref + '/' + (file === 'README.md' ? '' : 'docs/') + file + (anchor ? '#' + anchor : '');
  }
  // family is the key of a fix's commands for a deployment.
  function family(dep) {
    dep = dep || '';
    if (dep === 'docker' || dep === 'container') return 'docker';
    if (dep.startsWith('linux')) return 'linux';
    if (dep.startsWith('windows')) return 'windows';
    return '';
  }
  const rowId = (id) => 'sc-' + id.replace(/[^a-z0-9]+/gi, '-');
  const byState = (a, b) => (ORDER[a.state] - ORDER[b.state]) || (a.rank - b.rank);

  // ---------- small parts ----------
  const stateIcon = (state, cls) => el('span', { class: cls, 'data-state': state }, icon(STATE[state].icon));
  const srWord = (state) => el('span', { class: 'sr-only' }, STATE[state].word + ': ');
  function btn(kind, label, onclick, attrs = {}) {
    const b = el('button', { type: 'button', class: `btn btn--${kind} btn--sm`, ...attrs }, label);
    b.addEventListener('click', onclick);
    return b;
  }
  function docLink(url, label = 'How it works') {
    return el('a', { class: 'sc-doc', href: url, target: '_blank', rel: 'noopener noreferrer' },
      label, icon('arrow-up-right', 'icon--xs'), el('span', { class: 'sr-only' }, ' (opens in a new tab)'));
  }
  const say = (text) => { const s = $('sc-status'); if (s) s.textContent = text; };

  // copyText copies to the clipboard; plain-HTTP pages, where the browser
  // has no clipboard API, copy a selected hidden text box instead.
  async function copyText(text) {
    try {
      await navigator.clipboard.writeText(text);
      return true;
    } catch (_) {
      const ta = el('textarea', { class: 'sr-only', readonly: '', 'aria-hidden': 'true' });
      ta.value = text;
      document.body.append(ta);
      ta.select();
      let ok = false;
      try { ok = document.execCommand('copy'); } catch (_) { ok = false; }
      ta.remove();
      return ok;
    }
  }
  // copyButton is the Copy button of a command block.
  function copyButton(text, label, focusKey) {
    const b = el('button', { type: 'button', class: 'btn btn--ghost btn--icon btn--sm sc-copy', 'aria-label': label, title: 'Copy', 'data-focus': focusKey }, icon('copy'));
    b.addEventListener('click', async () => {
      const ok = await copyText(text);
      b.querySelector('use').setAttribute('href', ok ? '#i-check' : '#i-circle-alert');
      b.classList.toggle('is-copied', ok);
      say(ok ? 'Copied.' : 'Couldn’t copy. Select the text and press Ctrl+C.');
      clearTimeout(b.copyTimer);
      b.copyTimer = setTimeout(() => {
        b.querySelector('use').setAttribute('href', '#i-copy');
        b.classList.remove('is-copied');
      }, 1800);
    });
    return b;
  }
  // cmdBlock is a command with its Copy button. The box scrolls sideways
  // by itself, so a long command never widens the page.
  function cmdBlock(label, text, focusKey) {
    return el('div', { class: 'sc-cmd' },
      el('div', { class: 'sc-cmd__head' }, el('span', { class: 'sc-cmd__label' }, label), copyButton(text, 'Copy the ' + label + ' command', focusKey)),
      el('pre', { class: 'sc-cmd__pre', tabindex: '0', 'aria-label': label + ' command' }, text));
  }

  // ---------- loading ----------
  pageHooks.push((name) => {
    if (name !== 'security') return;
    if (!S.ticker) S.ticker = setInterval(tick, 30000);
    load();
  });

  // tick keeps "Checked 3 minutes ago" current; it stops when another
  // page is open.
  function tick() {
    if (currentPage !== 'security') {
      clearInterval(S.ticker);
      S.ticker = null;
      return;
    }
    if (document.hidden) return;
    for (const t of document.querySelectorAll('#sc-root time[data-ago]')) {
      const v = agoText(t.dataset.ago);
      if (t.textContent !== v) t.textContent = v;
    }
  }

  // load fetches the last report. With retried (Try again on the error
  // box, which loading replaces), focus goes to the result or to the new
  // Try again button, rather than being lost.
  async function load(retried) {
    const seq = ++S.seq;
    if (!S.rep) skeleton();
    let rep;
    try {
      rep = await api('api/security');
    } catch (e) {
      if (seq !== S.seq) return;
      // The first check after a start is still running: try again soon.
      if (e.status === 503 && S.tries++ < 5) {
        setTimeout(() => { if (currentPage === 'security' && seq === S.seq) load(); }, 3000);
        return;
      }
      S.tries = 0;
      if (S.rep) toastError('Couldn’t refresh the security report', e);
      else failed(e, retried);
      return;
    }
    if (seq !== S.seq) return;
    S.tries = 0;
    show(rep);
    if (retried) focusHeadline();
  }

  // focusHeadline puts focus on the overall result.
  function focusHeadline() {
    const h = $('sc-headline');
    if (!h) return;
    h.setAttribute('tabindex', '-1');
    h.focus();
  }

  function show(rep) {
    S.rep = rep;
    render();
    renderSecurityCount({ risk: rep.summary.risk });
  }

  // recheck runs the checks now; the server runs them at most every ten
  // seconds, and callers who ask at once share one run.
  async function recheck() {
    const b = $('sc-recheck');
    if (b.disabled) return;
    const before = S.rep;
    const back = busy(b, 'Checking…');
    b.setAttribute('aria-busy', 'true');
    S.seq++;
    try {
      const rep = await api('api/security?recheck=1');
      show(rep);
      const n = changes(before, rep);
      if (n) toast(`Checked. ${plural(n, 'thing', 'things')} changed.`);
      else say('Checked. Nothing changed.');
    } catch (e) {
      if (S.rep) toastError('Couldn’t run the checks', e);
      else failed(e);
    } finally {
      back();
      b.removeAttribute('aria-busy');
    }
  }
  $('sc-recheck').addEventListener('click', recheck);

  // changes counts the checks whose state changed. Lines are left out:
  // some hold a time ("since Signalith started 2 minutes ago").
  function changes(a, b) {
    if (!a) return 0;
    const was = new Map(a.checks.map((c) => [c.id, c.state]));
    const now = new Map(b.checks.map((c) => [c.id, c.state]));
    let n = 0;
    for (const [id, v] of now) if (was.get(id) !== v) n++;
    for (const id of was.keys()) if (!now.has(id)) n++;
    return n;
  }

  // ---------- export ----------
  // Copy asks for the text report inside the click, so the browser lets
  // it reach the clipboard once it arrives.
  async function copyReport() {
    $('sc-export').removeAttribute('open');
    const fetchText = async () => {
      const resp = await apiRaw('api/security?format=text');
      if (resp.status === 401) { toSignIn(); throw new Error('Your session ended. Sign in again.'); }
      if (!resp.ok) {
        const d = await resp.json().catch(() => ({}));
        throw new Error(d.error || resp.statusText);
      }
      return resp.text();
    };
    try {
      if (typeof ClipboardItem === 'function' && navigator.clipboard && navigator.clipboard.write) {
        const text = fetchText();
        await navigator.clipboard.write([new ClipboardItem({ 'text/plain': text.then((t) => new Blob([t], { type: 'text/plain' })) })]);
      } else if (!(await copyText(await fetchText()))) {
        throw new Error('This browser didn’t allow it. Use Download as text instead.');
      }
      toast('Report copied');
    } catch (e) {
      toastError('Couldn’t copy the report', e);
    }
  }
  $('sc-copy').addEventListener('click', copyReport);
  $('sc-download').addEventListener('click', () => $('sc-export').removeAttribute('open'));

  // ---------- drawing ----------
  // render draws the whole report. Disclosures that were open stay open,
  // and the control that had focus gets it back, so a re-check or a
  // certificate authority step doesn't lose your place.
  function render() {
    const rep = S.rep;
    const box = $('sc-root');
    const open = new Set([...box.querySelectorAll('details[open][data-key]')].map((d) => d.dataset.key));
    const a = document.activeElement;
    const focus = a && box.contains(a) && a.dataset ? a.dataset.focus : '';
    box.removeAttribute('aria-busy');
    fill(box,
      renderSummary(rep),
      renderOthers(rep),
      rep.ca_owner === 'cluster' ? renderClusterCA(rep) : renderCAPanel(rep),
      ...rep.groups.map((g) => renderGroup(rep, g)),
      renderAlways(rep),
      renderNotChecked(rep),
      el('p', { class: 'sc-foot' }, `Checked ${fullTime(rep.checked_at)} on ${rep.server.name} · Signalith ${rep.server.version}`));
    for (const d of box.querySelectorAll('details[data-key]')) if (open.has(d.dataset.key)) d.open = true;
    if (focus) {
      const n = box.querySelector(`[data-focus="${CSS.escape(focus)}"]`);
      if (n) n.focus({ preventScroll: true });
    }
  }

  // renderSummary is the card at the top: the worst state, the counts,
  // and the first three things to fix.
  function renderSummary(rep) {
    const sum = rep.summary;
    const worst = sum.risk ? 'risk' : sum.attention ? 'attention' : 'good';
    const tileIcon = { risk: 'shield-alert', attention: 'shield', good: 'shield-check' }[worst];
    let head;
    if (sum.risk) head = `${sum.risk} at risk` + (sum.attention ? ` · ${needs(sum.attention)}` : '');
    else if (sum.attention) head = sum.attention === 1 ? '1 thing needs attention' : `${sum.attention} things need attention`;
    else head = 'Nothing needs attention';
    const sub = ['Checked ', timeEl(rep.checked_at), ` on ${rep.server.name} · ${sum.good} good`];
    if (sum.unknown) sub.push(` · ${sum.unknown} Signalith can’t check from here`);
    const first = (rep.fix_first || []).slice(0, 3).map((id) => rep.checks.find((c) => c.id === id)).filter(Boolean);
    return el('section', { class: 'card sc-summary', 'aria-labelledby': 'sc-headline' },
      el('div', { class: 'sc-summary__main' },
        el('span', { class: 'sc-tile', 'data-state': worst }, icon(tileIcon)),
        el('div', { class: 'sc-head' },
          el('h2', { class: 'sc-headline', id: 'sc-headline' }, head),
          el('p', { class: 'sc-sub' }, ...sub))),
      first.length ? el('div', { class: 'sc-fixfirst' },
        el('h3', { class: 'section-title' }, 'Fix first'),
        el('ul', { class: 'sc-fixfirst__list', role: 'list' }, ...first.map((c) => el('li', {}, fixFirstRow(c))))) : null);
  }

  function fixFirstRow(c) {
    return el('button', { type: 'button', class: 'sc-ff', 'data-state': c.state, 'data-focus': 'ff:' + c.id, onclick: () => goToCheck(c.id) },
      stateIcon(c.state, 'sc-ff__icon'), srWord(c.state),
      el('span', { class: 'sc-ff__title' }, c.title),
      el('span', { class: 'sc-ff__line' }, c.line),
      icon('chevron-right', 'sc-ff__chev'));
  }

  // goToCheck brings a check's row into view with how to fix it open.
  function goToCheck(id) {
    const row = $(rowId(id));
    if (!row) return;
    const d = row.querySelector('details.sc-fix');
    if (d) d.open = true;
    row.scrollIntoView({ block: 'center' });
    const target = d ? d.querySelector('summary') : row.querySelector('.sc-row__title');
    target.focus({ preventScroll: true });
  }

  // renderOthers is one quiet line about the other servers that share
  // this OpenSearch, each a link to its own Security page.
  function renderOthers(rep) {
    const list = rep.others || [];
    if (!list.length) return null;
    const text = (o) => {
      if (o.not_checked) return 'not checked (older version)';
      if (o.risk) return `${o.risk} at risk` + (o.attention ? ` · ${needs(o.attention)}` : '');
      return o.attention ? needs(o.attention) : 'nothing needs attention';
    };
    const link = (o) => {
      try {
        const u = new URL(o.url);
        if (u.protocol === 'https:' || u.protocol === 'http:') return el('a', { href: new URL('/#security', u).href }, o.name);
      } catch (_) { /* no address: the name alone */ }
      return el('span', { class: 'sc-others__name' }, o.name);
    };
    return el('p', { class: 'sc-others' }, el('span', { class: 'sc-others__label' }, 'Other servers'),
      ...list.map((o) => {
        const ca = o.ca_scope ? `${SCOPE[o.ca_scope] || o.ca_scope} certificate authority` : '';
        return el('span', { class: 'sc-others__item', title: o.checked_at ? 'Checked ' + agoText(o.checked_at) : '' },
          link(o), el('span', { 'aria-hidden': 'true' }, ' · '), el('span', { class: 'sr-only' }, ': '), text(o),
          ca ? el('span', { class: 'sc-others__ca' }, ', ', ca) : null);
      }));
  }

  // tally sums up a group's rows: "All good", "1 at risk · 2 need attention".
  function tally(list) {
    const n = (s) => list.filter((c) => c.state === s).length;
    const parts = [];
    if (n('risk')) parts.push(`${n('risk')} at risk`);
    if (n('attention')) parts.push(needs(n('attention')));
    if (n('unknown')) parts.push(`${n('unknown')} Signalith can’t check`);
    return parts.length ? parts.join(' · ') : 'All good';
  }

  function renderGroup(rep, g) {
    const list = rep.checks.filter((c) => c.group === g.id).sort(byState);
    if (!list.length) return null;
    const titleId = 'sc-g-' + g.id;
    return el('section', { class: 'card sc-group', 'aria-labelledby': titleId },
      el('div', { class: 'sc-group__head' },
        el('span', { class: 'sc-group__icon' }, icon(GROUP_ICON[g.id] || 'shield')),
        el('div', { class: 'sc-group__heading' },
          el('h2', { class: 'sc-group__title', id: titleId }, g.title),
          el('p', { class: 'sc-group__desc' }, g.description)),
        el('span', { class: 'sc-tally' }, tally(list))),
      el('ul', { class: 'sc-rows', role: 'list' }, ...list.map(renderRow)));
  }

  // renderRow is one check: its state icon, title and line, any details,
  // and folded away, how to fix it or make it stronger.
  function renderRow(c) {
    return el('li', { class: 'sc-row', id: rowId(c.id), 'data-state': c.state },
      stateIcon(c.state, 'sc-row__icon'),
      el('h3', { class: 'sc-row__title', tabindex: '-1' }, srWord(c.state), c.title),
      el('div', { class: 'sc-row__body' },
        el('p', { class: 'sc-row__line' }, c.line),
        c.details && c.details.length ? el('ul', { class: 'sc-row__details', role: 'list' }, ...c.details.map((d) => el('li', {}, d))) : null,
        c.fix ? renderFix(c, c.fix, 'fix') : null,
        c.tip ? renderFix(c, c.tip, 'tip') : null));
  }

  // renderFix is a closed disclosure: the steps, the buttons that go
  // there, a link to the docs and the commands for this server's setup.
  function renderFix(c, fix, kind) {
    const key = kind + ':' + c.id;
    const scopeTip = kind === 'tip' && c.id === 'transit.ca_scope';
    return el('details', { class: 'sc-fix', 'data-key': key, 'data-kind': kind },
      el('summary', { class: 'sc-fix__summary', 'data-focus': 'sum:' + key },
        icon('chevron-right', 'icon--sm sc-chev'), fix.label, el('span', { class: 'sr-only' }, ` (${c.title})`)),
      el('div', { class: 'sc-fix__body' },
        scopeTip ? scopeSteps(fix.steps) : steps(fix.steps),
        actions(c, fix, kind),
        renderCommands(c, fix, kind)));
  }

  function steps(list) {
    if (!list || !list.length) return null;
    if (list.length === 1) return el('p', { class: 'sc-steps-text' }, list[0]);
    return el('ol', { class: 'sc-steplist' }, ...list.map((s) => el('li', {}, s)));
  }
  // scopeSteps explains standard and strict: paragraphs, each choice's
  // name in bold.
  function scopeSteps(list) {
    return el('div', { class: 'sc-scope' }, ...list.map((s) => {
      const m = s.match(/^(Standard|Strict)( \(in use\))?\. (.*)$/);
      if (!m) return el('p', {}, s);
      return el('p', {}, el('b', {}, m[1]), (m[2] || '') + '. ' + m[3]);
    }));
  }

  function actions(c, fix, kind) {
    const acts = [];
    if (fix.setting) {
      acts.push(fix.locked_by
        ? el('span', { class: 'sc-locked' }, icon('lock', 'icon--xs'), el('span', {}, 'Set by ', el('code', {}, fix.locked_by), ' where Signalith is started'))
        : btn('secondary', 'Open setting', () => openSetting(fix.setting), { 'data-focus': 'set:' + kind + ':' + c.id }));
    }
    if (fix.page) {
      const p = fix.page;
      acts.push(btn('secondary', p.label, () => {
        if (p.id === 'users' && p.tab && window.showUsersTab) window.showUsersTab(p.tab);
        else showPage(p.id);
      }, { 'data-focus': 'page:' + kind + ':' + c.id }));
    }
    const act = caButton(c, fix, kind);
    if (act) acts.push(act);
    if (fix.docs && fix.docs.url) acts.push(docLink(fix.docs.url, fix.docs.label || undefined));
    return acts.length ? el('div', { class: 'sc-actions' }, ...acts) : null;
  }

  // caButton is the in-page action of a fix: making a new certificate
  // authority, or going up to the panel of the change in progress.
  function caButton(c, fix, kind) {
    const ca = S.rep.ca;
    if (!fix.action || !ca || !ca.current) return null;
    const focus = { 'data-focus': 'act:' + kind + ':' + c.id };
    // The cluster's certificate authority is not changed here.
    if (S.rep.ca_owner === 'cluster') return btn('secondary', 'Open Servers', () => showPage('servers'), focus);
    if (fix.action === 'ca.panel' || ca.next || ca.previous) return btn('secondary', 'Continue above', goToPanel, focus);
    if (fix.action !== 'ca.prepare') return null;
    if (kind === 'tip' && c.id === 'transit.ca_scope') {
      const other = ca.current.scope === 'strict' ? 'standard' : 'strict';
      return btn('secondary', `Switch to ${other}…`, () => prepareDialog(other), focus);
    }
    return btn('secondary', 'Make a new certificate authority…', () => prepareDialog(ca.scope_setting || 'standard'), focus);
  }

  // renderCommands shows the commands for the setup this server runs in,
  // and folds away the others.
  function renderCommands(c, fix, kind) {
    const cmds = fix.commands || {};
    const mine = family(S.rep.server.deployment);
    const others = ['linux', 'windows', 'docker'].filter((k) => cmds[k] && k !== mine);
    const key = kind + ':' + c.id;
    if (!cmds[mine] && !others.length) return null;
    return el('div', { class: 'sc-cmds' },
      cmds[mine] ? cmdBlock(FAMILY[mine], cmds[mine], 'copy:' + key + ':' + mine) : null,
      others.length ? el('details', { class: 'sc-other', 'data-key': 'other:' + key },
        el('summary', { 'data-focus': 'other:' + key }, icon('chevron-right', 'icon--sm sc-chev'), cmds[mine] ? 'Other setups' : 'Commands'),
        el('div', { class: 'sc-other__body' }, ...others.map((k) => cmdBlock(FAMILY[k], cmds[k], 'copy:' + key + ':' + k)))) : null);
  }

  function renderAlways(rep) {
    const list = rep.always_on || [];
    return el('details', { class: 'disclosure sc-more sc-always', 'data-key': 'always' },
      el('summary', { 'data-focus': 'sum:always' }, icon('shield-check'), `Always on (${list.length})`, icon('chevron-down', 'chev')),
      el('div', { class: 'disclosure__body' },
        el('p', { class: 'sc-more__lead' }, 'Built in, with nothing to set up.'),
        el('ul', { class: 'sc-list', role: 'list' }, ...list.map((t) => el('li', {}, icon('check', 'icon--sm'), el('span', {}, t))))));
  }

  function renderNotChecked(rep) {
    return el('details', { class: 'disclosure sc-more sc-notchecked', 'data-key': 'notchecked' },
      el('summary', { 'data-focus': 'sum:notchecked' }, icon('eye-off'), 'Not checked here', icon('chevron-down', 'chev')),
      el('div', { class: 'disclosure__body' },
        el('p', { class: 'sc-more__lead' }, 'Signalith can’t see these from where it runs, so they’re worth checking yourself.'),
        el('ul', { class: 'sc-list sc-list--plain', role: 'list' }, ...(rep.not_checked || []).map((t) => el('li', {}, el('span', {}, t)))),
        el('p', { class: 'sc-more__link' }, docLink(docsURL('security.md', 'not-checked-here'), 'How to check these yourself'))));
  }

  // ---------- the cluster's certificate authority ----------
  // renderClusterCA replaces the change panel on a server whose
  // certificate authority is the cluster's: every server shares it, so it
  // is not prepared or switched here, and the Servers page says more.
  function renderClusterCA(rep) {
    const cur = rep.ca && rep.ca.current;
    return el('section', { class: 'card sc-group sc-cluster-ca', id: 'sc-cluster-ca', 'aria-labelledby': 'sc-cluster-ca-title' },
      el('div', { class: 'sc-group__head' },
        el('span', { class: 'sc-group__icon' }, icon('shield-check')),
        el('div', { class: 'sc-group__heading' },
          el('h2', { class: 'sc-group__title', id: 'sc-cluster-ca-title' }, 'Cluster certificate authority'),
          el('p', { class: 'sc-group__desc' }, 'This server’s HTTPS certificate comes from the certificate authority every server of the cluster shares, so agents and browsers trust one file for all of them. It isn’t changed here: changing it comes in a later version.'))),
      el('div', { class: 'sc-cluster-ca__body' },
        cur ? el('p', { class: 'sc-cluster-ca__fp' }, el('span', { class: 'sc-others__label' }, 'Fingerprint'), el('span', { class: 'mono' }, cur.fingerprint)) : null,
        el('div', { class: 'sc-actions' },
          btn('secondary', 'Open Servers', () => showPage('servers'), { 'data-focus': 'cluster-ca:servers' }),
          el('a', { class: 'btn btn--ghost btn--sm', href: 'api/tls/ca.pem', download: 'signalith-ca.pem', 'data-focus': 'cluster-ca:download' }, icon('download'), 'Download it'))));
  }

  // ---------- the certificate authority panel ----------
  // Shown only while a change is in progress: a new certificate
  // authority is ready (next), or Signalith switched and keeps the old
  // one (previous) until it is removed.
  function renderCAPanel(rep) {
    const ca = rep.ca;
    if (!ca || !ca.current || (!ca.next && !ca.previous)) return null;
    const switched = !!ca.previous;
    const made = switched ? ca.current : ca.next;
    const fp = (made.fingerprint || '').replace(/:/g, '').slice(0, 8);
    const madeAt = made.at || made.not_before;

    const step1 = [el('p', {}, `Made ${dayText(madeAt)}: ${SCOPE[made.scope] || made.scope}, fingerprint `, el('code', {}, fp + '…'))];
    if (!switched) step1.push(el('p', {}, el('button', { type: 'button', class: 'link-btn', 'data-focus': 'ca:discard', onclick: confirmDiscard }, 'Cancel this change')));

    const step2 = switched
      ? [el('p', { class: 'sc-muted' }, 'A computer that refuses the new certificate needs it too: ',
        el('a', { href: 'api/tls/ca.pem', download: 'signalith-ca.pem' }, 'download it'), ', then trust it like the first one.')]
      : shareSteps();

    const step3 = switched ? [] : [
      el('p', {}, 'Once browsers and agents trust it, switch. Signalith starts using it right away, with no restart.'),
      el('div', { class: 'sc-actions' }, el('button', { type: 'button', class: 'btn btn--primary btn--sm', 'data-focus': 'ca:switch', onclick: confirmSwitch }, 'Switch now…'))];

    let step4;
    if (switched) {
      const refused = ca.refusals || [];
      step4 = [el('p', {}, 'Switched ', timeEl(ca.previous.at || rep.checked_at), '.')];
      if (refused.length) {
        const computers = new Set(refused.map((r) => r.address)).size;
        step4.push(el('p', {}, `${plural(computers, 'computer', 'computers')} refused the new certificate since:`),
          el('ul', { class: 'sc-refused', role: 'list' }, ...refused.map((r) => el('li', {},
            el('code', {}, r.address), ` · ${r.via === 'syslog' ? 'syslog over TLS' : 'HTTPS'} · ${plural(r.count, 'time', 'times')} · last `, timeEl(r.last_seen)))));
      } else {
        step4.push(el('p', {}, 'Nothing has refused the new certificate since.'));
      }
      step4.push(el('div', { class: 'sc-actions' },
        btn('secondary', 'Switch back…', confirmRollback, { 'data-focus': 'ca:rollback' }),
        btn('secondary', 'Remove the old one…', confirmPrune, { 'data-focus': 'ca:prune' })));
    } else {
      step4 = [el('p', { class: 'sc-muted' }, 'After the switch, this lists any computer that refuses the new certificate. Then you remove the old one.')];
    }

    const step = (n, title, state, body) => {
      const attrs = { class: 'sc-step', 'data-step': state };
      if (state === 'current') attrs['aria-current'] = 'step';
      return el('li', attrs,
        el('span', { class: 'sc-step__mark', 'aria-hidden': 'true' }, state === 'done' ? icon('check', 'icon--sm') : String(n)),
        el('div', { class: 'sc-step__body' },
          el('h3', { class: 'sc-step__title' }, state === 'done' ? el('span', { class: 'sr-only' }, 'Done: ') : null, title),
          ...body));
    };
    return el('section', { class: 'card sc-ca', id: 'sc-ca', 'aria-labelledby': 'sc-ca-title' },
      el('div', { class: 'sc-group__head' },
        el('span', { class: 'sc-group__icon' }, icon('shield')),
        el('div', { class: 'sc-group__heading' },
          el('h2', { class: 'sc-group__title', id: 'sc-ca-title', tabindex: '-1' }, 'Switching certificate authority'),
          el('p', { class: 'sc-group__desc' }, 'Both are trusted while you switch, so nothing has to stop.'))),
      el('ol', { class: 'sc-steps', role: 'list' },
        step(1, 'Made', 'done', step1),
        step(2, 'Share it', switched ? 'done' : 'current', step2),
        step(3, 'Switch', switched ? 'done' : 'todo', step3),
        step(4, 'Tidy up', switched ? 'current' : 'todo', step4)));
  }

  // shareSteps says how to give the new certificate authority to
  // browsers, agents and syslog devices before the switch.
  function shareSteps() {
    const host = agentAddress();
    // A private temporary file: another account can't swap what's
    // installed.
    const linux = `t=$(mktemp) && curl -fsS --cacert /etc/fluent-bit/signalith-ca.pem -o "$t" "https://${host}/api/tls/ca.pem?which=both" && sudo install -m 644 "$t" /etc/fluent-bit/signalith-ca.pem && rm -f "$t" && sudo systemctl restart fluent-bit`;
    const windows = 'Copy-Item "$env:USERPROFILE\\Downloads\\signalith-ca.pem" \'C:\\Program Files\\fluent-bit\\conf\\signalith-ca.pem\' -Force; Restart-Service fluent-bit';
    const dl = (href, name, label) => el('a', { class: 'btn btn--secondary btn--sm', href, download: name }, icon('download'), label);
    return [
      el('p', {}, 'Give it to browsers and agents. They keep trusting the current one too.'),
      el('div', { class: 'sc-share' },
        el('div', { class: 'sc-share__part' },
          el('h4', { class: 'sc-share__title' }, 'Browsers'),
          el('div', { class: 'sc-actions' }, dl('api/tls/ca.pem?which=next', 'signalith-ca-new.crt', 'Download the new certificate'),
            docLink(docsURL('https.md', 'trust-the-certificate'), 'How to trust it')),
          el('p', { class: 'sc-muted' }, 'Trust it the same way as the first one. The sign-in page also offers it.')),
        el('div', { class: 'sc-share__part' },
          el('h4', { class: 'sc-share__title' }, 'Agents'),
          el('p', {}, 'New agents from Add data already get both. For the others, replace their CA file and restart them.'),
          el('p', { class: 'sc-muted' }, 'On each Linux agent:'),
          cmdBlock('Linux agents', linux, 'copy:ca:linux'),
          el('p', { class: 'sc-muted' }, `The download is checked against the certificate authority the agent already trusts. Change ${host} if agents reach Signalith at another address.`),
          el('p', { class: 'sc-muted' }, 'On each Windows agent, download the file with both, then in PowerShell as Administrator:'),
          el('div', { class: 'sc-actions' }, dl('api/tls/ca.pem?which=both', 'signalith-ca.pem', 'Download both')),
          cmdBlock('Windows agents', windows, 'copy:ca:windows')),
        el('div', { class: 'sc-share__part' },
          el('h4', { class: 'sc-share__title' }, 'Syslog over TLS devices'),
          el('p', {}, 'Give them the same file (rsyslog: ', el('code', {}, '/etc/rsyslog.d/signalith-ca.pem'), '; syslog-ng: ', el('code', {}, '/etc/syslog-ng/signalith-ca.pem'), ').'))),
      el('p', { class: 'sc-muted' }, 'Signalith can’t see which computers trust it yet. After the switch, it lists any that refuse.'),
    ];
  }

  // agentAddress is where agents reach Signalith: the address saved on
  // Add data, else the one this page uses.
  function agentAddress() {
    let v = '';
    try { v = localStorage.getItem('signalith.agentServer') || ''; } catch (_) { /* storage may be blocked */ }
    if (v) {
      try {
        const u = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(v) ? v : 'https://' + v);
        return u.port || !location.port ? u.host : u.host + ':' + location.port;
      } catch (_) { /* not an address: use this page's */ }
    }
    return location.host;
  }

  // focusRow brings a check's row into view and puts focus on its title,
  // for when the control that was used is gone.
  function focusRow(id) {
    const row = $(rowId(id));
    if (!row) return;
    row.scrollIntoView({ block: 'center' });
    row.querySelector('.sc-row__title').focus({ preventScroll: true });
  }

  function goToPanel() {
    const p = $('sc-ca');
    if (!p) return;
    p.scrollIntoView({ block: 'start' });
    $('sc-ca-title').focus({ preventScroll: true });
  }

  // ---------- certificate authority steps ----------
  async function caAction(action, scope) {
    const body = { action };
    if (scope) body.scope = scope;
    const rep = await api('api/security/ca', body);
    if (rep && rep.checks) show(rep);
    else await load();
  }

  // dialog fills the page's one dialog: a title, what happens, anything
  // extra, and the button that does it. run throws to keep it open with
  // the error shown.
  function dialog({ title, text, extra, confirm, tone, busyLabel, run }) {
    const d = modalDialog('sc-dialog');
    d.classList.add('sc-dialog');
    const err = formAlert();
    const ok = el('button', { type: 'button', class: 'btn ' + (tone === 'danger' ? 'btn--danger' : 'btn--primary') }, confirm);
    ok.addEventListener('click', async () => {
      const back = busy(ok, busyLabel);
      try {
        await run();
        d.close();
      } catch (e) {
        back();
        // Refused before anything was done; otherwise something may have
        // changed, so the page shows what is true now.
        const refused = e.status === 400 || e.status === 404 || e.status === 409;
        showAlert(err, refused ? 'Nothing changed' : 'That didn’t work', sentence(e.message));
        ok.focus();
        if (e.status !== 400) load();
      }
    });
    fill(d, modalHead('sc-dialog', title, null, () => d.close()),
      el('div', { class: 'modal__body' }, err, ...[].concat(text).map((t) => (typeof t === 'string' ? el('p', { class: 'sc-dialog__text' }, t) : t)), ...(extra || [])),
      el('div', { class: 'modal__foot' }, el('button', { type: 'button', class: 'btn btn--ghost', onclick: () => d.close() }, 'Cancel'), ok));
    d.showModal();
    ok.focus();
    return d;
  }

  // prepareDialog makes a new certificate authority next to the one in
  // use; the scope chosen is saved as the setting first.
  function prepareDialog(scope) {
    const ca = S.rep.ca;
    const names = (ca.would_cover || {})[scope] || [];
    // Names used in the last day that a strict one wouldn't cover:
    // Signalith's own (private, or leading to this computer), and others
    // it can't tell apart from a name someone made up.
    const notCovered = scope === 'strict' ? (ca.seen_names || []).filter((s) => !s.covered_strict) : [];
    const missed = notCovered.filter((s) => s.own).map((s) => s.name);
    const unknown = notCovered.filter((s) => !s.own).map((s) => s.name);
    const toNames = (d) => () => { d.close(); openSetting('server.tls.names'); };
    const extra = [el('div', { class: 'sc-cover' },
      el('p', { class: 'label' }, 'It will cover:'),
      el('ul', { class: 'sc-names', role: 'list' }, ...names.map((n) => el('li', {}, el('code', {}, n))),
        scope === 'standard' ? el('li', { class: 'sc-names__more' }, 'and any private network name or address') : null))];
    let d;
    if (ca.container) {
      extra.push(el('div', { class: 'callout' }, icon('info'), el('div', { class: 'sc-callout__body' },
        el('p', {}, 'Signalith runs in a container and can’t see this computer’s own addresses. Add the address people and agents use, such as 192.168.1.20, under Extra certificate names first.'),
        btn('secondary', 'Open setting', () => toNames(d)()))));
    }
    if (missed.length) {
      extra.push(el('div', { class: 'alert', 'data-tone': 'warning' }, icon('triangle-alert'), el('div', { class: 'sc-callout__body' },
        el('p', {}, `Also used to reach this server in the last day: ${listWords(missed)}. Add them under Extra certificate names first, or they won’t work after the switch.`),
        btn('secondary', 'Open setting', () => toNames(d)()))));
    }
    if (unknown.length) {
      extra.push(el('div', { class: 'callout' }, icon('info'), el('div', { class: 'sc-callout__body' },
        el('p', {}, `Also seen in the last day, but Signalith can’t tell they belong to this server: ${listWords(unknown)}. Add them only if people or agents use them to reach it.`))));
    }
    d = dialog({
      title: `Make a ${scope} certificate authority`,
      text: 'Signalith makes it now, next to the one in use. Nothing changes for browsers or agents until you switch.',
      extra, confirm: 'Make it', busyLabel: 'Making…',
      run: async () => {
        await caAction('prepare', scope);
        toast('Give it to browsers and agents, then switch.', null, { title: 'New certificate authority made' });
        requestAnimationFrame(goToPanel);
      },
    });
  }

  function confirmDiscard() {
    dialog({
      title: 'Cancel this change?',
      text: 'Signalith deletes the new certificate authority. The one in use stays as it is. Computers you already gave the new one to can forget it.',
      confirm: 'Cancel the change', tone: 'danger', busyLabel: 'Cancelling…',
      run: async () => {
        await caAction('discard');
        toast('The new certificate authority was deleted.', null, { title: 'Change cancelled' });
        requestAnimationFrame(() => focusRow('transit.ca_scope'));
      },
    });
  }

  function confirmSwitch() {
    dialog({
      title: 'Switch to the new certificate authority?',
      text: ['Signalith starts using it right away. Browsers and agents that don’t trust it yet can’t connect until they do, or until you switch back. Agents keep their events meanwhile.',
        'Trust it in this browser first. After the switch, a browser that doesn’t trust it can’t open this page, so you couldn’t switch back from here.',
        el('p', {}, docLink(docsURL('https.md', 'switching-to-a-new-certificate-authority'), 'How to switch back without this page'))],
      confirm: 'Switch now', busyLabel: 'Switching…',
      run: async () => {
        await caAction('switch');
        toast('Switched. This page lists any computer that refuses the new certificate.');
        requestAnimationFrame(goToPanel);
      },
    });
  }

  function confirmRollback() {
    dialog({
      title: 'Switch back?',
      text: 'Signalith goes back to the previous certificate authority right away. The new one is kept, so you can switch again without sharing it again.',
      confirm: 'Switch back', busyLabel: 'Switching back…',
      run: async () => {
        await caAction('rollback');
        toast('Signalith uses the previous certificate authority again.', null, { title: 'Switched back' });
        requestAnimationFrame(goToPanel);
      },
    });
  }

  function confirmPrune() {
    dialog({
      title: 'Remove the old certificate authority?',
      text: ['You can’t switch back after this. Remove the old certificate authority from the computers that trusted it, too.',
        el('p', {}, docLink(docsURL('https.md', 'switching-to-a-new-certificate-authority'), 'How to remove it from a computer'))],
      confirm: 'Remove it', tone: 'danger', busyLabel: 'Removing…',
      run: async () => {
        await caAction('prune');
        toast('The old certificate authority was removed.', null, { title: 'Done' });
        requestAnimationFrame(() => focusRow('transit.ca_scope'));
      },
    });
  }

  // ---------- loading and error states ----------
  function skeleton() {
    const box = $('sc-root');
    box.setAttribute('aria-busy', 'true');
    const bar = (w) => el('span', { class: 'skeleton sc-skel sc-skel--' + w });
    const row = (w) => el('li', { class: 'sc-row' }, el('span', { class: 'sc-row__icon' }), el('div', { class: 'sc-row__title' }, bar('title')), el('div', { class: 'sc-row__body' }, bar(w)));
    fill(box,
      el('div', { class: 'card sc-summary' }, el('div', { class: 'sc-summary__main' }, el('span', { class: 'sc-tile sc-tile--skel' }),
        el('div', { class: 'sc-head' }, bar('40'), bar('60')))),
      ...['70', '55', '65'].map((w) => el('div', { class: 'card sc-group' },
        el('div', { class: 'sc-group__head' }, el('span', { class: 'sc-group__icon' }), el('div', { class: 'sc-group__heading' }, bar('20'), bar('45'))),
        el('ul', { class: 'sc-rows', role: 'list' }, row(w), row('60'), row('45')))));
  }

  function failed(e, retried) {
    const box = $('sc-root');
    box.removeAttribute('aria-busy');
    const again = el('button', { type: 'button', class: 'btn btn--secondary btn--sm', onclick: () => load(true) }, icon('refresh-cw'), 'Try again');
    fill(box, el('div', { class: 'alert', 'data-tone': 'danger', role: 'alert' }, icon('circle-alert'),
      el('div', { class: 'sc-error' },
        el('p', {}, el('b', {}, 'Couldn’t load the security report: '), sentence(e.message)),
        el('div', {}, again))));
    if (retried) again.focus();
  }
})();
