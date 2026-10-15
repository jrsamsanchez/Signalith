// Compliance page (every role): for each framework, the controls Signalith
// gives evidence for and how well, with what to fix; a CSV export and a
// printable report for auditors; and, for admins, a note on a control that
// is handled outside Signalith or does not apply. Evidence sources lists
// the capabilities behind every control, the ones that would help most
// first.
'use strict';

(function () {
  const FW_KEY = 'signalith.compliance.framework';
  const STATUS = {
    met: { label: 'Evidence', tone: 'success', icon: 'circle-check' },
    partial: { label: 'Partial', tone: 'warning', icon: 'circle-dot' },
    missing: { label: 'Gap', tone: 'danger', icon: 'circle-x' },
    external: { label: 'Handled outside', tone: 'accent', icon: 'notebook-pen' },
    na: { label: 'Not applicable', tone: 'outline', icon: 'minus' },
  };
  const FILTERS = [['all', 'All'], ['met', 'Evidence'], ['partial', 'Partial'], ['missing', 'Gaps'], ['noted', 'Noted']];
  const PAGES = {
    data: 'Add data', detections: 'Detections', endpoints: 'Endpoints', vulns: 'Vulnerabilities', findings: 'Findings', cases: 'Investigations',
    notify: 'Notifications', respond: 'Response actions', intel: 'Threat intel', retention: 'Data retention', users: 'Users',
    security: 'Security', assets: 'Assets & identities', health: 'Health', search: 'Search',
  };
  const S = { data: null, fw: '', tab: 'controls', find: '', show: 'all', open: new Set(), loading: false, seq: 0 };
  try { S.fw = localStorage.getItem(FW_KEY) || ''; } catch (_) { /* storage may be blocked */ }

  pageHooks.push((name) => { if (name === 'compliance') load(false); });
  $('cp-refresh').addEventListener('click', () => load(true));

  async function load(fresh) {
    if (S.loading) return;
    S.loading = true;
    const seq = ++S.seq;
    const btn = $('cp-refresh');
    btn.disabled = true;
    if (!S.data) skeleton();
    try {
      const d = await api('api/compliance' + (fresh ? '?fresh=1' : ''));
      if (seq !== S.seq) return;
      S.data = d;
      if (!d.frameworks.some((f) => f.id === S.fw)) S.fw = d.frameworks[0].id;
      render();
      if (fresh) dxNotify('Checked again just now.');
    } catch (e) {
      if (!S.data) {
        $('cp-frameworks').replaceChildren();
        fill($('cp-body'), el('div', { class: 'card' },
          dxEmpty({ tone: 'danger', icon: 'circle-alert', title: 'Couldn’t load compliance', text: sentence(e.message), action: dxRetry(() => load(false)) })));
      } else toastError('Couldn’t check again', e);
    } finally {
      S.loading = false;
      btn.disabled = false;
    }
  }

  function skeleton() {
    fill($('cp-frameworks'), ...Array.from({ length: 6 }, () => el('div', { class: 'card cp-fw', 'aria-busy': 'true' },
      dxSkel('60%'), el('div', { class: 'dx-skel-gap' }), dxSkel('40px'), el('div', { class: 'dx-skel-gap' }), dxSkel('90%'))));
    fill($('cp-body'), el('div', { class: 'card cp-panel', 'aria-busy': 'true' },
      ...Array.from({ length: 6 }, () => el('div', { class: 'cp-skel' }, dxSkel('70%')))));
  }

  const fw = () => S.data.frameworks.find((f) => f.id === S.fw);
  const exportURL = (format) => `api/compliance/export?framework=${encodeURIComponent(S.fw)}&format=${format}`;

  function render() {
    renderFrameworks();
    renderBody();
  }

  // ---------- framework cards ----------
  function bar(counts, total) {
    const b = el('div', { class: 'cp-bar', 'aria-hidden': 'true' });
    for (const k of ['met', 'external', 'partial', 'missing', 'na']) {
      if (counts[k]) b.append(el('i', { 'data-st': k, style: `flex-grow:${counts[k]}` }));
    }
    if (!total) b.append(el('i', { style: 'flex-grow:1' }));
    return b;
  }

  function renderFrameworks() {
    const box = $('cp-frameworks');
    const cards = S.data.frameworks.map((f) => {
      const c = f.counts;
      const total = f.controls.length;
      const sel = f.id === S.fw;
      const b = el('button', {
        class: 'card cp-fw', type: 'button', role: 'tab', id: 'cp-fw-' + f.id, 'aria-selected': String(sel), tabindex: sel ? '0' : '-1',
        'aria-controls': 'cp-body', 'aria-label': `${f.name} ${f.version}: ${f.score}% coverage, ${c.met + c.external} of ${total} controls with evidence`,
      },
      el('span', { class: 'cp-fw__name' }, f.name),
      el('span', { class: 'cp-fw__ver' }, f.version),
      el('span', { class: 'cp-fw__score num' }, String(f.score), el('small', {}, '%')),
      bar(c, total),
      el('span', { class: 'cp-fw__foot' }, `${c.met + c.external} of ${total} with evidence`),
      el('span', { class: 'cp-fw__gaps', ...(c.missing ? {} : { 'data-none': '' }) }, c.missing ? `${c.missing} ${c.missing === 1 ? 'gap' : 'gaps'}` : 'No gaps'));
      b.addEventListener('click', () => selectFramework(f.id));
      return b;
    });
    fill(box, ...cards);
    if (!box.dataset.keys) {
      box.dataset.keys = '1';
      box.addEventListener('keydown', (ev) => {
        if (ev.key !== 'ArrowRight' && ev.key !== 'ArrowLeft') return;
        const ids = S.data.frameworks.map((f) => f.id);
        const i = ids.indexOf(S.fw) + (ev.key === 'ArrowRight' ? 1 : -1);
        selectFramework(ids[(i + ids.length) % ids.length]);
        $('cp-fw-' + S.fw).focus();
        ev.preventDefault();
      });
    }
  }

  function selectFramework(id) {
    if (id === S.fw) return;
    S.fw = id;
    S.open.clear();
    try { localStorage.setItem(FW_KEY, id); } catch (_) { /* storage may be blocked */ }
    render();
    const card = $('cp-fw-' + id);
    if (card) card.scrollIntoView({ block: 'nearest', inline: 'nearest' });
  }

  // ---------- the selected framework ----------
  function renderBody() {
    const f = fw();
    const c = f.counts;
    const exportMenu = el('div', { class: 'cp-export' },
      el('a', { class: 'btn btn--secondary btn--sm', href: exportURL('csv'), download: '' }, icon('file-spreadsheet'), 'CSV'),
      el('a', { class: 'btn btn--secondary btn--sm', href: exportURL('html'), target: '_blank', rel: 'noopener' }, icon('file-text'), 'Report (PDF)'));
    const head = el('div', { class: 'cp-head' },
      el('div', { class: 'cp-head__text' },
        el('h3', { class: 'cp-head__title' }, `${f.name} ${f.version}`),
        el('p', { class: 'cp-head__meta' }, f.publisher, el('span', { class: 'dotsep', 'aria-hidden': 'true' }),
          el('a', { href: f.url, target: '_blank', rel: 'noopener noreferrer' }, 'About the framework', icon('external-link', 'icon--sm')))),
      exportMenu);
    const legend = el('div', { class: 'legend cp-legend' },
      ...['met', 'partial', 'missing', 'external', 'na'].map((k) => el('span', {}, el('i', { 'data-st': k }), `${STATUS[k].label} `, el('b', { class: 'num' }, String(c[k] || 0)))));
    const summary = el('div', { class: 'cp-summary' },
      el('div', { class: 'cp-summary__score' }, el('span', { class: 'num' }, f.score + '%'), el('small', {}, 'coverage score')),
      el('div', { class: 'cp-summary__bar' }, bar(c, f.controls.length), legend));
    const notes = (S.data.notes || []).map((n) => dxAlert('warning', 'Some evidence could not be read', n));

    const noted = c.external + c.na;
    const tabs = dxTabs('cp', [['controls', 'Controls', f.controls.length], ['sources', 'Evidence sources', S.data.capabilities.length]], S.tab, (t) => {
      S.tab = t;
      renderBody();
      $('cp-tab-' + t).focus();
    });
    fill($('cp-body'),
      el('div', { class: 'card cp-panel' }, head, summary, ...notes,
        el('p', { class: 'cp-scope' }, `Only the ${f.controls.length} controls a SIEM can give evidence for are listed. Controls with partial evidence count half toward the score${noted ? '; controls noted as not applicable are left out of it' : ''}.`),
        tabs,
        dxPanel('cp', 'controls', S.tab, S.tab === 'controls' ? controlsPanel(f) : null),
        dxPanel('cp', 'sources', S.tab, S.tab === 'sources' ? sourcesPanel() : null),
        el('p', { class: 'cp-notice' }, f.notice, ' The mapping shows where Signalith gives evidence; it does not by itself make a system compliant.')));
  }

  // ---------- controls ----------
  function controlsPanel(f) {
    const find = el('input', { class: 'input', id: 'cp-find', type: 'search', placeholder: 'Find a control', 'aria-label': 'Find a control by number or title', autocomplete: 'off', spellcheck: 'false' });
    find.value = S.find;
    const counts = { all: f.controls.length, met: f.counts.met, partial: f.counts.partial, missing: f.counts.missing, noted: f.counts.external + f.counts.na };
    const pills = el('div', { class: 'pills', role: 'group', 'aria-label': 'Show' }, ...FILTERS.map(([k, label]) => {
      const p = el('button', { class: 'pill', type: 'button', 'aria-pressed': String(S.show === k) }, label, ' ', el('span', { class: 'num' }, String(counts[k])));
      p.addEventListener('click', () => { S.show = k; drawList(); syncPills(); });
      return p;
    }));
    const syncPills = () => pills.querySelectorAll('.pill').forEach((p, i) => p.setAttribute('aria-pressed', String(FILTERS[i][0] === S.show)));
    const list = el('div', { class: 'cp-list' });
    find.addEventListener('input', () => { S.find = find.value; drawList(); });

    function drawList() {
      const term = S.find.trim().toLowerCase();
      const shown = f.controls.filter((c) => {
        if (S.show === 'noted' ? !c.attestation : S.show !== 'all' && c.status !== S.show) return false;
        return !term || `${c.id} ${c.title} ${c.group} ${(c.nist || []).join(' ')}`.toLowerCase().includes(term);
      });
      if (!shown.length) {
        fill(list, dxEmpty({ compact: true, icon: 'search', title: 'No control matches', text: 'Try another word or show all controls.' }));
        return;
      }
      const groups = [];
      for (const c of shown) {
        if (!groups.length || groups[groups.length - 1].name !== c.group) groups.push({ name: c.group, items: [] });
        groups[groups.length - 1].items.push(c);
      }
      fill(list, ...groups.map((g) => el('section', { class: 'cp-group' },
        el('h4', { class: 'section-title' }, g.name, el('span', { class: 'count' }, String(g.items.length))),
        el('ul', { class: 'cp-ctls' }, ...g.items.map((c) => el('li', {}, controlRow(f, c)))))));
    }
    drawList();
    return el('div', {}, el('div', { class: 'toolbar cp-toolbar' },
      el('div', { class: 'input-wrap' }, icon('search'), find), pills), list);
  }

  function statusBadge(st) {
    const s = STATUS[st] || STATUS.missing;
    return el('span', { class: `badge badge--${s.tone} cp-badge` }, s.label);
  }

  function controlRow(f, c) {
    const key = f.id + '/' + c.id;
    const open = S.open.has(key);
    const bodyId = 'cp-c-' + key.replace(/[^a-z0-9]/gi, '-');
    const dots = el('span', { class: 'cp-dots', 'aria-hidden': 'true' },
      ...c.evidence.map((e) => el('i', { 'data-st': e.status, title: `${e.name}: ${STATUS[e.status].label}` })));
    const head = el('button', { class: 'cp-ctl__head', type: 'button', 'aria-expanded': String(open), 'aria-controls': bodyId },
      el('span', { class: 'cp-ctl__id mono' }, c.id),
      el('span', { class: 'cp-ctl__title' }, c.title),
      dots, statusBadge(c.status), icon('chevron-down', 'cp-ctl__chev'));
    const wrap = el('div', { class: 'cp-ctl' + (open ? ' is-open' : ''), 'data-st': c.status }, head);
    const body = el('div', { class: 'cp-ctl__body', id: bodyId });
    body.hidden = !open;
    if (open) fill(body, ...controlDetail(f, c));
    head.addEventListener('click', () => {
      const now = !S.open.has(key);
      if (now) S.open.add(key); else S.open.delete(key);
      head.setAttribute('aria-expanded', String(now));
      wrap.classList.toggle('is-open', now);
      body.hidden = !now;
      fill(body, ...(now ? controlDetail(f, c) : []));
    });
    wrap.append(body);
    return wrap;
  }

  function goTo(page) {
    return () => { if (typeof pageAllowed === 'function' && !pageAllowed(page)) return; showPage(page); };
  }

  function evidenceItem(e) {
    const s = STATUS[e.status];
    const canOpen = e.fix && e.page && PAGES[e.page] && pageAllowed(e.page);
    return el('li', { class: 'cp-ev', 'data-st': e.status },
      el('span', { class: 'cp-ev__icon', title: s.label }, icon(s.icon)),
      el('div', { class: 'cp-ev__text' },
        el('div', { class: 'cp-ev__name' }, e.name, el('span', { class: 'sr-only' }, ` (${s.label})`)),
        el('p', { class: 'cp-ev__detail' }, e.detail),
        e.fix ? el('p', { class: 'cp-ev__fix' }, e.fix, canOpen ? ' ' : null,
          canOpen ? el('button', { class: 'link-btn', type: 'button', onclick: goTo(e.page) }, `Open ${PAGES[e.page]}`, icon('arrow-right', 'icon--sm')) : null) : null));
  }

  function controlDetail(f, c) {
    const out = [el('ul', { class: 'cp-evs' }, ...c.evidence.map(evidenceItem))];
    const ch = c.checks;
    if (ch && ch.failing.length) {
      out.push(el('div', { class: 'cp-sub' }, el('h5', { class: 'section-title' }, 'Failing checks', el('span', { class: 'count' }, String(ch.failing.length))),
        el('ul', { class: 'cp-fails' }, ...ch.failing.slice(0, 8).map((x) => el('li', {},
          el('span', {}, x.title), el('span', { class: 'cp-fails__n' }, `${x.platform} · ${x.hosts} ${x.hosts === 1 ? 'host' : 'hosts'}`)))),
        ch.failing.length > 8 ? el('p', { class: 'hint' }, `And ${ch.failing.length - 8} more on the Endpoints page.`) : null));
    }
    if (c.detections.length) {
      const shown = c.detections.slice(0, 10);
      out.push(el('div', { class: 'cp-sub' }, el('h5', { class: 'section-title' }, 'Detections on', el('span', { class: 'count' }, String(c.detections.length))),
        el('ul', { class: 'cp-dets' }, ...shown.map((d) => el('li', { class: 'badge badge--outline' + (d.data ? '' : ' cp-det--nodata'), title: d.data ? (d.tagged ? 'Tagged for this control' : '') : 'The data it reads does not arrive' }, d.name))),
        c.detections.length > shown.length ? el('p', { class: 'hint' }, `And ${c.detections.length - shown.length} more.`) : null));
    }
    const meta = [];
    if (c.nist && c.nist.length && f.id !== 'nist-800-53') meta.push(`Lines up with NIST SP 800-53 ${c.nist.join(', ')}.`);
    if (meta.length) out.push(el('p', { class: 'cp-meta' }, ...meta));
    out.push(noteBlock(f, c));
    return out;
  }

  // ---------- notes on controls (admins) ----------
  function noteBlock(f, c) {
    const a = c.attestation;
    if (a) {
      return el('div', { class: 'cp-note', 'data-st': a.status },
        el('div', { class: 'cp-note__head' }, icon(STATUS[a.status].icon), el('b', {}, a.status === 'external' ? 'Handled outside Signalith' : 'Not applicable'),
          el('span', { class: 'cp-note__by' }, `${a.by || 'an admin'} · ${dxClock(a.at)}`),
          el('span', { class: 'spacer' }),
          can('admin') ? dxBtn('ghost', 'Edit', () => editNote(f, c), { sm: true, icon: 'pencil' }) : null,
          can('admin') ? dxBtn('ghost', 'Remove', () => saveNote(f, c, '', ''), { sm: true, icon: 'trash-2' }) : null),
        el('p', { class: 'cp-note__text' }, a.note),
        c.computed !== a.status ? el('p', { class: 'hint' }, `From Signalith’s own evidence alone: ${STATUS[c.computed].label.toLowerCase()}.`) : null);
    }
    if (!can('admin') || c.status === 'met') return null;
    return el('div', { class: 'cp-note-actions' },
      el('span', { class: 'hint' }, 'Covered some other way?'),
      dxBtn('secondary', 'Handled outside Signalith', () => editNote(f, c, 'external'), { sm: true, icon: 'notebook-pen' }),
      dxBtn('ghost', 'Not applicable', () => editNote(f, c, 'na'), { sm: true }));
  }

  function editNote(f, c, status) {
    const id = 'cp-note-dialog';
    const d = modalDialog(id);
    const cur = c.attestation || {};
    const pick = status || cur.status || 'external';
    const radio = (value, label, desc) => el('label', { class: 'cp-radio' },
      el('input', { type: 'radio', name: 'cp-note-status', value, ...(pick === value ? { checked: '' } : {}) }),
      el('span', {}, el('b', {}, label), el('small', {}, desc)));
    const text = el('textarea', { class: 'input textarea', id: 'cp-note-text', rows: '4', maxlength: '2000', placeholder: 'For example: chrony keeps every server’s clock in sync; the platform team checks it monthly.' });
    text.value = cur.note || '';
    const alert = formAlert();
    const save = dxBtn('primary', 'Save note', null, { type: 'submit' });
    const close = () => d.close();
    const form = el('form', { method: 'dialog' },
      modalHead(id, `${f.name} ${c.id}`, c.title, close),
      el('div', { class: 'modal__body' }, alert,
        el('fieldset', { class: 'cp-radios' }, el('legend', { class: 'label' }, 'This control is'),
          radio('external', 'Handled outside Signalith', 'Another tool or process covers it; it counts as covered.'),
          radio('na', 'Not applicable', 'It does not apply to your systems; it is left out of the score.')),
        dxField('Note for the auditor', text, 'Say how it is handled or why it does not apply. The report shows it with your name and the date.')),
      el('div', { class: 'modal__foot' }, dxBtn('ghost', 'Cancel', close), save));
    form.addEventListener('submit', async (ev) => {
      ev.preventDefault();
      const st = form.querySelector('input[name="cp-note-status"]:checked').value;
      save.disabled = true;
      const ok = await saveNote(f, c, st, text.value, alert);
      save.disabled = false;
      if (ok) d.close();
    });
    fill(d, form);
    d.showModal();
    text.focus();
  }

  async function saveNote(f, c, status, note, alertBox) {
    try {
      await api('api/compliance/notes', { framework: f.id, control: c.id, status, note }, 'PUT');
      S.open.add(f.id + '/' + c.id);
      const d = await api('api/compliance');
      S.data = d;
      render();
      dxNotify(status ? 'Note saved.' : 'Note removed.');
      return true;
    } catch (e) {
      if (alertBox) showAlert(alertBox, 'Couldn’t save the note', sentence(e.message));
      else toastError('Couldn’t remove the note', e);
      return false;
    }
  }

  // ---------- evidence sources ----------
  function sourcesPanel() {
    const used = {};
    for (const f of S.data.frameworks) for (const c of f.controls) for (const id of c.caps) used[id] = (used[id] || 0) + 1;
    const rank = { missing: 0, partial: 1, met: 2 };
    const caps = [...S.data.capabilities].sort((a, b) => rank[a.status] - rank[b.status] || (used[b.id] || 0) - (used[a.id] || 0) || a.name.localeCompare(b.name));
    const todo = caps.filter((c) => c.status !== 'met').length;
    return el('div', {},
      el('p', { class: 'cp-intro' }, todo
        ? `${todo} of ${caps.length} evidence sources are missing or partial. Those used by the most controls come first, so fixing them raises coverage most.`
        : 'Every evidence source is in place.'),
      el('ul', { class: 'cp-evs cp-sources' }, ...caps.map((c) => {
        const li = evidenceItem({ ...c, name: c.name });
        li.querySelector('.cp-ev__name').append(el('span', { class: 'cp-used' }, `${used[c.id] || 0} ${used[c.id] === 1 ? 'control' : 'controls'}`));
        li.querySelector('.cp-ev__detail').before(el('p', { class: 'cp-ev__desc' }, c.description));
        return li;
      })));
  }
})();
