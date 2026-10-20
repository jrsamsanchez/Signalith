// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0
// Add data: Any other log. An admin pastes or uploads a sample of a log
// Signalith has no parser for; the server suggests how to read it
// (api/parsers/analyze), previews the events and the detections that
// could use them, and the admin adjusts it, asks the AI model to improve
// it (api/parsers/refine) and saves it (PUT api/parsers/{name}). Agents
// then send the log under the parser's tag, and syslog from the programs
// it names is read with it. See docs/custom-logs.md. customLogsOpen is
// the way in.
(() => {
  'use strict';

  const C = {
    info: null, failed: '', loading: false,
    sample: '', ans: null, parser: null, err: '',
    seq: 0, timer: null, busy: false, ai: false, aiNote: '',
    editing: '', saved: '', send: 'linux', paths: '', input: null, inputErr: '',
  };
  const body = () => $('custom-body');
  const code = (t) => el('code', {}, t);
  const b = (t) => el('b', {}, t);
  const plural = (n, w, ws) => `${Number(n).toLocaleString()} ${n === 1 ? w : (ws || w + 's')}`;
  const FORMAT_NAMES = { json: 'JSON', kv: 'key=value', csv: 'CSV', cef: 'CEF', leef: 'LEEF', regex: 'Regular expression', text: 'Text only' };
  const MODEL_NAMES = (m) => m.replace(/_/g, ' ');
  const DELIMS = { csv: [[',', 'Comma'], [';', 'Semicolon'], ['|', 'Pipe |'], ['\t', 'Tab']], kv: [['', 'Spaces'], [',', 'Comma'], [';', 'Semicolon'], ['|', 'Pipe |']] };

  async function customLogsOpen() {
    if (!C.info && !C.loading) await load();
    else render();
  }
  window.customLogsOpen = customLogsOpen;

  async function load() {
    C.loading = true;
    body().setAttribute('aria-busy', 'true');
    if (!C.info) fill(body(), el('div', { class: 'cl-skel' }, dxSkel('40%'), dxSkel('100%'), dxSkel('70%')));
    try {
      C.info = await api('api/parsers');
      C.failed = '';
    } catch (e) {
      C.failed = e.message || 'The Signalith server did not respond.';
    } finally {
      C.loading = false;
    }
    render();
  }

  // ---------- drawing ----------

  // keepFocus redraws a part of the card and puts the focus back on the
  // control that had it (by data-k), so typing and picking carry on.
  function keepFocus(box, draw) {
    const a = document.activeElement;
    const k = a && box.contains(a) ? a.dataset.k : '';
    const pos = k && 'selectionStart' in a ? [a.selectionStart, a.selectionEnd] : null;
    draw();
    if (!k) return;
    const n = box.querySelector(`[data-k="${CSS.escape(k)}"]`);
    if (!n) return;
    n.focus({ preventScroll: true });
    if (pos && n.setSelectionRange) try { n.setSelectionRange(pos[0], pos[1]); } catch (_) { /* not a text field */ }
  }

  function render() {
    const box = body();
    box.setAttribute('aria-busy', 'false');
    if (C.failed && !C.info) {
      fill(box, dxEmpty({ tone: 'danger', icon: 'circle-alert', compact: true, title: 'Couldn’t load the custom parsers', text: sentence(C.failed), action: dxRetry(load) }));
      return;
    }
    keepFocus(box, () => fill(box,
      C.info.error ? dxAlert('danger', 'The saved parsers couldn’t be read', C.info.error) : null,
      savedList(),
      el('ol', { class: 'agent-steps cl-steps' },
        sampleStep(),
        C.parser ? readStep() : null,
        C.parser ? previewStep() : null,
        C.parser ? detectionsStep() : null,
        C.parser ? saveStep() : null)));
  }

  const step = (n, title, ...parts) => el('li', { class: 'agent-step' }, el('span', { class: 'agent-step__num' }, n),
    el('div', { class: 'agent-step__body' }, el('p', { class: 'agent-step__text' }, b(title)), ...parts.filter(Boolean)));

  // ---------- saved parsers ----------
  function savedList() {
    const ps = (C.info && C.info.parsers) || [];
    if (!ps.length) return null;
    const rows = ps.map((p) => el('tr', { 'data-parser': p.name },
      el('td', {}, el('div', { class: 'mono cl-name' }, p.name), el('div', { class: 'cl-sub mono' }, 'sourcetype=' + p.sourcetype)),
      el('td', {}, MODEL_NAMES(p.model)),
      el('td', {}, FORMAT_NAMES[p.format] || p.format, p.header === 'syslog' ? el('span', { class: 'cl-sub' }, ' with syslog header') : null),
      el('td', { class: 'cl-when' }, p.updated_at ? el('span', { title: new Date(p.updated_at).toLocaleString() }, ago(p.updated_at)) : ''),
      el('td', { class: 'cl-act' }, dxMenu('Actions for ' + p.name, [
        { icon: 'pencil', label: 'Edit', run: () => edit(p) },
        { icon: 'send', label: 'Send logs to it', run: () => { edit(p); C.saved = p.name; render(); focusSend(); } },
        { icon: 'search', label: 'Search its events', run: () => { setQuery(`sourcetype="${p.sourcetype}"`); showPage('search'); } },
        'sep',
        { icon: 'trash-2', label: 'Delete', danger: true, run: () => remove(p) },
      ]))));
    return el('div', { class: 'cl-saved' },
      el('div', { class: 'cl-saved__head' }, b('Your parsers'), el('span', { class: 'cl-sub' }, plural(ps.length, 'parser'))),
      el('div', { class: 'table-wrap' }, el('table', { class: 'table table--compact cl-table cl-table--saved' },
        el('thead', {}, el('tr', {}, ...['Parser', 'Data model', 'Format', 'Changed'].map((h) => el('th', { scope: 'col' }, h)), el('th', { scope: 'col' }, el('span', { class: 'sr-only' }, 'Actions')))),
        el('tbody', {}, ...rows))));
  }

  function edit(p) {
    C.parser = JSON.parse(JSON.stringify(p));
    C.editing = p.name;
    C.saved = '';
    C.input = null;
    C.aiNote = '';
    C.err = '';
    if (C.sample.trim()) preview(true);
    else {
      C.ans = null;
      render();
      $('cl-sample').focus();
    }
  }

  async function remove(p) {
    const ok = await caseConfirm({ title: `Delete “${p.name}”?`, text: 'Events already stored keep their fields. Lines agents send under its tag afterwards are stored as plain text, and syslog from its programs is read as before.', confirm: 'Delete parser' });
    if (!ok) return;
    try {
      const resp = await apiRaw('api/parsers/' + encodeURIComponent(p.name), { method: 'DELETE' });
      if (!resp.ok) {
        const data = await resp.json().catch(() => ({}));
        throw new Error(data.error || resp.statusText);
      }
      toast(`Deleted “${p.name}”.`);
      if (C.editing === p.name) C.editing = '';
      if (C.saved === p.name) C.saved = '';
    } catch (e) {
      toastError('Couldn’t delete the parser', e);
    }
    await load();
  }

  // ---------- 1. the sample ----------
  function sampleStep() {
    const lim = (C.info && C.info.limits) || {};
    const ta = el('textarea', { class: 'input textarea mono cl-sample', id: 'cl-sample', 'data-k': 'sample', rows: '7', spellcheck: 'false', autocomplete: 'off', autocapitalize: 'off',
      placeholder: 'date=2026-10-16 time=14:05:09 devname="fw01" srcip=10.0.1.15 dstip=203.0.113.9 dstport=443 action="accept"', 'aria-describedby': 'cl-sample-hint' });
    ta.value = C.sample;
    ta.addEventListener('input', () => { C.sample = ta.value; });
    const file = el('input', { type: 'file', class: 'sr-only', id: 'cl-file', accept: '.log,.txt,.csv,.json,.jsonl,.ndjson,.tsv,text/*,application/json' });
    file.addEventListener('change', async () => {
      const f = file.files[0];
      if (!f) return;
      const max = lim.sample_bytes || 524288;
      C.sample = await f.slice(0, max).text();
      file.value = '';
      render();
      analyze();
    });
    const go = dxBtn('primary', C.parser && !C.editing ? 'Read it again' : 'Read the sample', () => analyze(), { sm: true, icon: 'scan-search', id: 'cl-read' });
    if (C.busy && !C.parser) { go.disabled = true; go.setAttribute('aria-busy', 'true'); }
    return step(1, 'Paste a few lines of the log, or upload a file',
      ta,
      el('div', { class: 'cl-row' }, go,
        el('label', { class: 'btn btn--secondary btn--sm', for: 'cl-file' }, icon('upload'), 'Upload a file'),
        C.editing && C.parser && !C.sample.trim() ? el('span', { class: 'cl-sub' }, 'Editing ', el('span', { class: 'mono' }, C.editing), '. Paste a sample to preview it.') : null),
      el('p', { class: 'hint', id: 'cl-sample-hint' }, `Ten to fifty lines is plenty. Signalith reads the first ${(lim.sample_lines || 500).toLocaleString()} lines, up to ${Math.round((lim.sample_bytes || 524288) / 1024)} KB. The sample stays on this server unless you ask the AI model for help.`),
      C.err && !C.parser ? dxAlert('danger', 'Couldn’t read the sample', sentence(C.err)) : null);
  }

  async function analyze() {
    if (!C.sample.trim()) {
      C.err = 'Paste a few lines of the log first.';
      render();
      return $('cl-sample').focus();
    }
    C.busy = true;
    C.err = '';
    C.editing = '';
    C.saved = '';
    C.input = null;
    C.aiNote = '';
    C.parser = null;
    render();
    const seq = ++C.seq;
    try {
      const ans = await api('api/parsers/analyze', { sample: C.sample });
      if (seq !== C.seq) return;
      C.ans = ans;
      C.parser = ans.parser;
    } catch (e) {
      if (seq !== C.seq) return;
      C.err = e.message;
    } finally {
      if (seq === C.seq) C.busy = false;
    }
    render();
    const head = document.querySelector('#custom-body .cl-read-head');
    if (head) head.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
  }

  // preview runs the edited parser on the sample, a moment after the last
  // change; now skips the wait.
  function preview(now) {
    clearTimeout(C.timer);
    if (!now) {
      C.timer = setTimeout(() => preview(true), 350);
      return;
    }
    if (!C.sample.trim()) {
      render();
      return;
    }
    const seq = ++C.seq;
    C.busy = true;
    markBusy(true);
    api('api/parsers/analyze', { sample: C.sample, parser: C.parser }).then((ans) => {
      if (seq !== C.seq) return;
      C.ans = ans;
      C.err = '';
      const keepName = C.parser.name;
      C.parser = { ...ans.parser, name: keepName };
    }).catch((e) => {
      if (seq !== C.seq) return;
      C.err = e.message;
    }).finally(() => {
      if (seq !== C.seq) return;
      C.busy = false;
      render();
    });
  }

  function markBusy(on) {
    document.querySelectorAll('#custom-body .cl-live').forEach((n) => n.classList.toggle('is-stale', on));
  }

  // change updates the parser from the form and previews it.
  function change(fn, redraw) {
    fn(C.parser);
    if (redraw) render();
    preview();
  }

  // ---------- 2. how it is read ----------
  function readStep() {
    const p = C.parser;
    const info = C.info || {};
    const ans = C.ans || {};
    const models = info.models || [];
    const text = (k, label, value, set, attrs = {}) => {
      const id = 'cl-f-' + k;
      const n = el('input', { class: 'input input--sm' + (attrs.mono ? ' mono' : ''), id, 'data-k': k, type: 'text', autocomplete: 'off', spellcheck: 'false', autocapitalize: 'off', ...(attrs.placeholder ? { placeholder: attrs.placeholder } : {}), ...(attrs.maxlength ? { maxlength: attrs.maxlength } : {}) });
      n.value = value || '';
      n.addEventListener('input', () => change((q) => set(q, n.value)));
      return dxField(label, n, attrs.hint);
    };
    const select = (k, label, value, options, set, hint, redraw) => {
      const id = 'cl-f-' + k;
      const n = el('select', { class: 'select select--sm', id, 'data-k': k },
        ...options.map(([v, t]) => el('option', { value: v, selected: v === value }, t)));
      n.addEventListener('change', () => change((q) => set(q, n.value), redraw));
      return dxField(label, n, hint);
    };
    const fmt = p.format;
    const fields = [
      text('name', 'Name', p.name, (q, v) => { q.name = v.trim().toLowerCase(); }, { mono: true, maxlength: 48, hint: 'Agents send under the tag custom.' + (p.name || 'name') + '.' }),
      text('sourcetype', 'Sourcetype', p.sourcetype, (q, v) => { q.sourcetype = v.trim(); }, { mono: true, maxlength: 64, hint: 'What searches filter on, such as acme:firewall.' }),
      select('model', 'Data model', p.model, models.map((m) => [m, MODEL_NAMES(m)]), (q, v) => { q.model = v; }, 'Detections read events by data model.', true),
      select('format', 'Format', fmt, (info.formats || []).map((f) => [f, FORMAT_NAMES[f] || f]), (q, v) => {
        q.format = v;
        if (v === 'csv' && !q.delimiter) q.delimiter = ',';
        if (v === 'kv' && !q.kv_separator) q.kv_separator = '=';
      }, null, true),
    ];
    const opts = [];
    if (fmt === 'csv' || fmt === 'kv') {
      opts.push(select('delim', fmt === 'csv' ? 'Columns separated by' : 'Pairs separated by', p.delimiter || '', DELIMS[fmt], (q, v) => { q.delimiter = v; }));
    }
    if (fmt === 'kv') {
      opts.push(select('kvsep', 'Key and value joined by', p.kv_separator || '=', [['=', 'key=value'], [':', 'key: value']], (q, v) => { q.kv_separator = v; }));
    }
    if (fmt === 'csv') {
      opts.push(text('columns', 'Column names', (p.columns || []).join(', '), (q, v) => { q.columns = v.split(',').map((s) => s.trim()); }, { mono: true, hint: 'In order, separated by commas. Leave one empty to skip that column.' }));
    }
    if (fmt === 'regex') {
      const ta = el('textarea', { class: 'input textarea mono cl-pattern', id: 'cl-f-pattern', 'data-k': 'pattern', rows: '3', spellcheck: 'false', autocomplete: 'off' });
      ta.value = p.pattern || '';
      ta.addEventListener('input', () => change((q) => { q.pattern = ta.value; }));
      opts.push(dxField('Regular expression', ta, el('span', {}, 'RE2 syntax. Each named group ', code('(?P<user>\\S+)'), ' becomes a field. Name groups after data model fields where you can.')));
    }
    // The time: a field the preview found, or the one chosen (it leaves
    // the fields once read).
    const names = new Set(((ans.preview && ans.preview.fields) || []).map((f) => f.name));
    if (p.time_field) names.add(p.time_field);
    const timeOpts = [['', 'None: the time it arrives'], ...[...names].sort().map((n) => [n, n.replace('+', ' + ')])];
    const tf = (info.time_formats || []);
    opts.push(select('timefield', 'Event time', p.time_field || '', timeOpts, (q, v) => { q.time_field = v; if (!v) q.time_format = ''; }, null, true));
    if (p.time_field) {
      opts.push(select('timeformat', 'Written as', p.time_format || '', [['', 'Any format Signalith knows'], ...tf.map((f) => [f.name, f.example])], (q, v) => { q.time_format = v; }));
    }
    const hdr = el('input', { type: 'checkbox', id: 'cl-f-header', 'data-k': 'header', checked: p.header === 'syslog' });
    hdr.addEventListener('change', () => change((q) => { q.header = hdr.checked ? 'syslog' : ''; }));
    const keep = el('input', { type: 'checkbox', id: 'cl-f-keep', 'data-k': 'keep', checked: !p.keep_action });
    keep.addEventListener('change', () => change((q) => { q.keep_action = !keep.checked; }));
    const switches = el('div', { class: 'cl-switches' },
      fmt === 'cef' || fmt === 'leef' ? null : el('label', { class: 'switch', title: 'Read the time, host and program from a syslog header before the message' }, hdr, ' Lines start with a syslog header'),
      el('label', { class: 'switch', title: 'accept, deny, failed and the like become allowed, blocked, success or failure; the original stays in vendor_action' }, keep, ' Use the data model’s action words'));
    const more = [
      text('product', 'Product', p.vendor_product, (q, v) => { q.vendor_product = v; }, { placeholder: 'Acme Firewall', hint: 'Fills vendor_product.' }),
    ];
    if (info.syslog) {
      more.push(text('apps', 'Also read syslog from', (p.syslog_apps || []).join(', '), (q, v) => { q.syslog_apps = v.split(',').map((s) => s.trim()).filter(Boolean); },
        { mono: true, placeholder: 'acmefw', hint: 'Program names in the syslog header, separated by commas. Their messages are read with this parser.' }));
    }
    const conf = ans.confidence && !C.editing ? el('span', { class: 'badge ' + ({ high: 'badge--success', medium: 'badge--accent', low: 'badge--warning' }[ans.confidence] || '') },
      { high: 'Sure of the format', medium: 'Fairly sure', low: 'Check the fields' }[ans.confidence]) : null;
    return step(2, 'Check how Signalith reads it',
      el('div', { class: 'cl-read-head' }, conf, aiBlock()),
      ...((ans.notes && !C.editing ? ans.notes : []).map((n) => el('p', { class: 'hint', 'data-tone': 'warning' }, icon('info'), el('span', {}, n)))),
      C.aiNote ? dxAlert('info', 'What the AI model changed', C.aiNote) : null,
      el('div', { class: 'cl-grid' }, ...fields),
      el('div', { class: 'cl-grid' }, ...opts),
      switches,
      el('div', { class: 'cl-grid' }, ...more),
      C.err && C.parser ? dxAlert('danger', 'This doesn’t work yet', sentence(C.err)) : null);
  }

  function aiBlock() {
    const ai = C.info && C.info.ai;
    if (!ai) {
      return el('span', { class: 'cl-sub' }, icon('wand-sparkles'), ' An AI model can help with free text: set one up in ',
        el('button', { class: 'link-btn', type: 'button', onclick: () => showPage('settings') }, 'Settings'), '.');
    }
    const lines = (C.info.limits && C.info.limits.ai_lines) || 20;
    const btn = dxBtn('secondary', C.ai ? 'Asking the AI model…' : 'Improve with AI', refine, { sm: true, icon: 'wand-sparkles', id: 'cl-ai' });
    if (C.ai) { btn.disabled = true; btn.setAttribute('aria-busy', 'true'); }
    if (!C.sample.trim()) btn.disabled = true;
    return el('div', { class: 'cl-ai' }, btn,
      el('span', { class: 'cl-sub' }, `Sends the first ${lines} lines of the sample to ${ai.model} at `, el('span', { class: 'mono' }, ai.sent_to), ai.local ? ', on your network.' : '.'));
  }

  async function refine() {
    if (C.ai) return;
    C.ai = true;
    render();
    const seq = ++C.seq;
    try {
      const ans = await api('api/parsers/refine', { sample: C.sample, parser: C.parser });
      if (seq !== C.seq) return;
      C.ans = ans;
      C.parser = { ...ans.parser, name: C.parser.name };
      C.aiNote = ans.explanation || 'The AI model suggested a parser; the preview below shows what it reads.';
      C.err = '';
    } catch (e) {
      if (seq === C.seq) toastError('The AI model couldn’t improve the parser', e);
    } finally {
      C.ai = false;
      C.busy = false;
      render();
    }
  }

  // ---------- 3. the preview ----------
  function previewStep() {
    const pv = C.ans && C.ans.preview;
    if (!pv) {
      return step(3, 'Preview', el('p', { class: 'hint' }, 'Paste a sample above to see the events this parser makes.'));
    }
    const parts = [];
    const of = pv.lines - (pv.skipped || 0);
    const tone = pv.parsed === of ? 'success' : pv.parsed * 2 >= of ? 'warning' : 'danger';
    parts.push(el('div', { class: 'cl-stats' },
      el('span', { class: 'cl-stat', 'data-tone': tone }, icon(tone === 'success' ? 'circle-check' : 'triangle-alert'), `Fields found in ${pv.parsed.toLocaleString()} of ${plural(of, 'line')}`),
      el('span', { class: 'cl-stat' }, icon('clock'), pv.timed === of ? 'Every event has its own time' : `${pv.timed.toLocaleString()} with their own time`),
      pv.skipped ? el('span', { class: 'cl-stat' }, icon('minus'), plural(pv.skipped, 'header line') + ' skipped') : null));
    parts.push(fieldsTable(pv));
    parts.push(eventsList(pv));
    return el('li', { class: 'agent-step' }, el('span', { class: 'agent-step__num' }, 3),
      el('div', { class: 'agent-step__body cl-live' }, el('p', { class: 'agent-step__text' }, b('Map the fields and check the events')), ...parts));
  }

  function fieldsTable(pv) {
    const p = C.parser;
    const targets = ((C.info && C.info.targets) || {})[p.model] || [];
    const rows = (pv.fields || []).map((f) => {
      const raw = f.from || f.name;
      const sel = el('select', { class: 'select select--sm cl-map', 'data-k': 'map:' + raw, 'aria-label': 'Data model field for ' + raw },
        el('option', { value: '' }, 'Keep as ' + raw),
        ...targets.filter((t) => t !== raw).map((t) => el('option', { value: t, selected: f.from ? t === f.name : false }, t)));
      sel.addEventListener('change', () => change((q) => {
        q.mappings = (q.mappings || []).filter((m) => m.from !== raw);
        if (sel.value) q.mappings.push({ from: raw, to: sel.value });
      }));
      const sug = !f.from && f.suggest && f.suggest !== f.name ? el('button', { class: 'link-btn cl-sug', type: 'button', onclick: () => change((q) => {
        q.mappings = (q.mappings || []).filter((m) => m.from !== raw);
        q.mappings.push({ from: raw, to: f.suggest });
      }) }, 'Map to ' + f.suggest) : null;
      return el('tr', { 'data-in': f.in_model ? 'yes' : 'no' },
        el('td', {}, el('div', { class: 'cl-fname' },
          f.in_model ? el('span', { class: 'cl-dot', title: 'A ' + MODEL_NAMES(p.model) + ' field' }) : el('span', { class: 'cl-dot cl-dot--off' }),
          el('span', { class: 'mono' }, f.from ? f.from : f.name)),
          f.count < (pv.parsed || 0) ? el('div', { class: 'cl-sub' }, `in ${f.count} of ${pv.parsed}`) : null),
        el('td', { class: 'cl-ex' }, ...(f.examples || []).slice(0, 2).map((x) => el('span', { class: 'cl-val mono', title: x }, x))),
        el('td', { class: 'cl-to' }, sel, sug));
    });
    if (!rows.length) {
      return el('p', { class: 'hint', 'data-tone': 'warning' }, icon('triangle-alert'), el('span', {}, 'No fields yet: the lines are kept as text only. Try another format, or a regular expression.'));
    }
    const inModel = (pv.fields || []).filter((f) => f.in_model).length;
    return el('div', { class: 'cl-fields' },
      el('p', { class: 'cl-sub' }, `${plural((pv.fields || []).length, 'field')}, ${inModel} of them ${MODEL_NAMES(p.model)} fields. Map the others that mean the same, so searches and detections find them.`),
      el('div', { class: 'table-wrap' }, el('table', { class: 'table table--compact cl-table cl-table--fields' },
        el('thead', {}, el('tr', {}, el('th', { scope: 'col' }, 'Field'), el('th', { scope: 'col' }, 'Example'), el('th', { scope: 'col' }, 'Stored as'))),
        el('tbody', {}, ...rows))));
  }

  function eventsList(pv) {
    const p = C.parser;
    const evs = (pv.events || []).slice(0, 6);
    const skip = new Set(['@timestamp', 'datamodel', 'message', 'sourcetype']);
    const items = evs.map((e) => {
      const f = e.fields || {};
      const keys = Object.keys(f).filter((k) => !skip.has(k)).sort((a, z) => {
        const ia = (((C.info && C.info.targets) || {})[p.model] || []).indexOf(a);
        const iz = (((C.info && C.info.targets) || {})[p.model] || []).indexOf(z);
        return (ia < 0 ? 999 : ia) - (iz < 0 ? 999 : iz) || a.localeCompare(z);
      });
      return el('li', { class: 'cl-event' },
        el('div', { class: 'cl-event__head' }, el('span', { class: 'cl-event__time mono' }, new Date(e.time).toLocaleString()),
          el('span', { class: 'cl-event__raw mono', title: f.message || '' }, f.message || '')),
        el('div', { class: 'cl-event__fields' }, ...keys.slice(0, 14).map((k) => el('span', { class: 'cl-kv' }, el('span', { class: 'cl-kv__k' }, k), el('span', { class: 'cl-kv__v', title: String(f[k]) }, String(f[k])))),
          keys.length > 14 ? el('span', { class: 'cl-sub' }, `+${keys.length - 14} more`) : null));
    });
    return el('div', { class: 'cl-events' },
      el('p', { class: 'cl-sub' }, `The first ${plural(evs.length, 'event')} as they would be stored, under datamodel=${p.model}.`),
      el('ul', { class: 'cl-event-list' }, ...items));
  }

  // ---------- 4. detections ----------
  function detectionsStep() {
    const cov = C.ans && C.ans.coverage;
    const p = C.parser;
    if (!cov) return null;
    const parts = [];
    if (!cov.in_model) {
      parts.push(el('p', { class: 'agent-step__text' }, p.model === 'Other'
        ? 'Events in Other are searchable, but no detection reads them. Choose a data model in step 2 if one fits.'
        : `No detection reads ${MODEL_NAMES(p.model)} events yet. You can write one on the Detections page.`));
    } else {
      parts.push(el('div', { class: 'cl-cov' },
        el('div', { class: 'cl-cov__num' }, el('span', { class: 'cl-cov__big' }, cov.ready.toLocaleString()), el('span', {}, `of ${plural(cov.in_model, MODEL_NAMES(p.model) + ' detection')} can run on these events`)),
        el('div', { class: 'cl-bar', role: 'img', 'aria-label': `${cov.ready} of ${cov.in_model}` }, el('span', { style: `width:${Math.round(100 * cov.ready / cov.in_model)}%` }))));
      if (cov.list && cov.list.length) {
        parts.push(el('ul', { class: 'cl-dets' }, ...cov.list.slice(0, 8).map((d) => el('li', {},
          el('span', { class: 'sev sev--glyph', 'data-sev': d.severity, role: 'img', 'aria-label': d.severity + ' severity' }), el('span', { class: 'cl-det__title' }, d.title),
          d.fires ? el('span', { class: 'badge badge--warning' }, `Matches ${plural(d.fires, 'sample event')}`) : null,
          d.enabled ? null : el('span', { class: 'badge badge--outline' }, 'Off')))));
        if (cov.ready > 8) parts.push(el('p', { class: 'cl-sub' }, `And ${(cov.ready - 8).toLocaleString()} more.`));
      }
      if (cov.unlock && cov.unlock.length) {
        parts.push(el('p', { class: 'cl-sub' }, 'Map a field to one of these and more detections can run:'),
          el('div', { class: 'cl-unlock' }, ...cov.unlock.map((u) => el('span', { class: 'badge badge--outline badge--mono' }, `${u.field} · +${u.count}`))));
      }
    }
    return el('li', { class: 'agent-step' }, el('span', { class: 'agent-step__num' }, 4),
      el('div', { class: 'agent-step__body cl-live' }, el('p', { class: 'agent-step__text' }, b('Detections that can use it')), ...parts));
  }

  // ---------- 5. save and send ----------
  function saveStep() {
    const p = C.parser;
    const save = dxBtn('primary', C.editing === p.name ? 'Save changes' : 'Save parser', doSave, { sm: true, icon: 'save', id: 'cl-save' });
    const parts = [el('div', { class: 'cl-row' }, save,
      el('span', { class: 'cl-sub' }, 'Every server reads with it at once. Events already stored stay as they are.'))];
    if (C.saved) parts.push(sendBlock());
    return step(5, C.saved ? 'Send the logs' : 'Save it', ...parts);
  }

  async function doSave() {
    const p = C.parser;
    const exists = ((C.info && C.info.parsers) || []).some((x) => x.name === p.name);
    if (exists && C.editing !== p.name) {
      const ok = await caseConfirm({ title: `Replace “${p.name}”?`, text: 'A parser by that name exists. Saving replaces how its tag and syslog programs are read.', confirm: 'Replace parser' });
      if (!ok) return;
    }
    const btn = $('cl-save');
    btn.disabled = true;
    btn.setAttribute('aria-busy', 'true');
    try {
      const saved = await api('api/parsers/' + encodeURIComponent(p.name), p, 'PUT');
      toast(`Saved “${saved.name}”. Lines sent under custom.${saved.name} are read with it now.`);
      C.editing = saved.name;
      C.saved = saved.name;
      C.parser = { ...saved };
      C.err = '';
      await load();
      focusSend();
    } catch (e) {
      C.err = e.message;
      render();
      const a = document.querySelector('#custom-body .cl-steps .alert[data-tone="danger"]');
      if (a) a.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
    }
  }

  function focusSend() {
    const n = $('cl-send');
    if (n) n.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
  }

  function sendBlock() {
    const p = C.parser;
    const tag = 'custom.' + C.saved;
    const tabs = [['linux', 'Files on Linux'], ['windows', 'Files on Windows'], ['syslog', 'Syslog'], ['script', 'A script']];
    const seg = el('div', { class: 'seg seg--sm cl-seg', role: 'group', 'aria-label': 'How the log arrives' }, ...tabs.map(([k, t]) => {
      const bt = el('button', { type: 'button', 'aria-pressed': String(C.send === k), 'data-k': 'send:' + k }, t);
      bt.addEventListener('click', () => { C.send = k; C.input = null; C.inputErr = ''; render(); });
      return bt;
    }));
    const parts = [seg];
    if (C.send === 'linux' || C.send === 'windows') {
      const win = C.send === 'windows';
      const ta = el('textarea', { class: 'input textarea mono cl-paths', id: 'cl-paths', 'data-k': 'paths', rows: '2', spellcheck: 'false', autocomplete: 'off',
        placeholder: win ? 'C:\\ProgramData\\Acme\\logs\\*.log' : '/var/log/acme/*.log' });
      ta.value = C.paths;
      ta.addEventListener('input', () => { C.paths = ta.value; });
      parts.push(dxField('Log files on the host', ta, 'One per line; * matches any part of a name. Files that hold secrets, such as the agent’s own configuration or password and key files, are refused: they would become searchable.'),
        el('div', { class: 'cl-row' }, dxBtn('secondary', 'Make the agent input', makeInput, { sm: true, icon: 'file-code' })),
        C.inputErr ? el('p', { class: 'field-error', role: 'alert' }, icon('circle-alert'), sentence(C.inputErr)) : null);
      if (C.input) {
        const btn = el('button', { class: 'btn btn--ghost btn--sm', type: 'button' }, icon('copy'), el('span', {}, 'Copy'));
        btn.addEventListener('click', () => agentSetupCopy(C.input, btn));
        parts.push(el('div', { class: 'agent-file cl-file' },
          el('div', { class: 'agent-file__bar' }, el('span', { class: 'agent-file__name mono' }, win ? 'C:\\Program Files\\fluent-bit\\conf\\fluent-bit.conf' : '/etc/fluent-bit/fluent-bit.conf'), el('span', { class: 'cl-grow' }), btn),
          el('pre', { class: 'cl-conf mono' }, C.input)),
        el('ol', { class: 'sl-ui-steps' },
          el('li', {}, 'Set up the agent on the host first, from the ', el('button', { class: 'link-btn', type: 'button', onclick: () => { pickDataSource(win ? 'windows' : 'linux'); loadDataSource(); } }, win ? 'Windows' : 'Linux'), ' card, if it isn’t yet.'),
          el('li', {}, 'Add the input above to the agent’s ', code('fluent-bit.conf'), ', next to its other ', code('[INPUT]'), ' sections.'),
          el('li', {}, 'Restart Fluent Bit: ', code(win ? 'Restart-Service fluent-bit' : 'sudo systemctl restart fluent-bit'), '. New lines arrive within seconds.')));
      }
    } else if (C.send === 'syslog') {
      const apps = p.syslog_apps || [];
      parts.push(apps.length
        ? el('p', { class: 'agent-step__text' }, 'Syslog messages whose program is ', ...apps.flatMap((a, i) => [i ? ', ' : '', code(a)]), ' are read with this parser. Point the device at Signalith from the ',
          el('button', { class: 'link-btn', type: 'button', onclick: () => { pickDataSource('syslog'); loadDataSource(); } }, 'Syslog'), ' card.')
        : el('p', { class: 'agent-step__text' }, 'Name the program the device puts in its syslog header under ', b('Also read syslog from'), ' in step 2, then save again.'));
    } else {
      parts.push(el('p', { class: 'agent-step__text' }, 'Send JSON lines, one ', code('{"log": "<the line>"}'), ' per line (or the JSON objects themselves for a JSON parser), with an ', el('button', { class: 'link-btn', type: 'button', onclick: () => showPage('tokens') }, 'agent token'), ':'),
        el('div', { class: 'agent-cmd' }, el('code', {}, `curl -sS --cacert signalith-ca.pem -H "Authorization: Bearer $SIGNALITH_TOKEN" -H "X-Signalith-Tag: ${tag}" --data-binary @lines.json https://<signalith address>/api/ingest`)));
    }
    return el('div', { class: 'cl-send', id: 'cl-send' }, ...parts);
  }

  async function makeInput() {
    const paths = C.paths.split('\n').map((s) => s.trim()).filter(Boolean);
    if (!paths.length) {
      C.inputErr = 'Name the log files to read.';
      render();
      return $('cl-paths').focus();
    }
    try {
      const r = await api(`api/parsers/${encodeURIComponent(C.saved)}/input?os=${C.send}&paths=${encodeURIComponent(paths.join('\n'))}`);
      C.input = r.input;
      C.inputErr = '';
    } catch (e) {
      C.input = null;
      C.inputErr = e.message;
    }
    render();
  }
})();
