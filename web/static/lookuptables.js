// Settings > Lookups (admins): the CSV tables the lookup command reads.
// Each table is uploaded whole; the first line names its columns. A
// search adds columns from the rows whose key column matches a field:
//   | lookup owners host OUTPUT owner, team
// See docs/query-language.md and docs/settings.md.
'use strict';

(function () {
  const L = { data: null, seq: 0 };
  const body = $('lt-body');
  const newBtn = $('lt-new');
  newBtn.addEventListener('click', () => openUpload(null));

  pageHooks.push((name) => {
    if (name === 'lookuptables' && can('admin')) load();
  });

  async function load(quiet) {
    if (!L.data && !quiet) skeleton();
    const seq = ++L.seq;
    try {
      const d = await api('api/lookuptables');
      if (seq !== L.seq) return;
      L.data = d;
      render();
    } catch (e) {
      if (seq !== L.seq) return;
      if (!L.data || !quiet) failed(e);
    }
  }

  // ---------- small parts ----------
  const full = (t) => new Date(t).toLocaleString();
  function day(t) {
    const d = new Date(t);
    if (!isFinite(d)) return '';
    const opts = d.getFullYear() === new Date().getFullYear() ? { day: 'numeric', month: 'short' } : { day: 'numeric', month: 'short', year: 'numeric' };
    return d.toLocaleDateString(undefined, opts);
  }
  function size(n) {
    if (n < 1024) return n + ' B';
    if (n < 1 << 20) return Math.round(n / 1024) + ' KB';
    return (n / (1 << 20)).toFixed(1) + ' MB';
  }
  const NAME_RE = /^[a-z0-9][a-z0-9_-]{0,63}$/;
  // A name from a file name: report Owners (2).csv becomes owners-2.
  const nameFrom = (file) => file.replace(/\.csv$/i, '').toLowerCase().replace(/[^a-z0-9_-]+/g, '-').replace(/^[-_]+|[-_]+$/g, '').slice(0, 64);
  // example is the lookup command for a table, matching its first column.
  function example(t) {
    const cols = t.columns || [];
    const out = cols.slice(1, 3).join(', ');
    return `| lookup ${t.name} ${cols[0] || 'field'}` + (out ? ` OUTPUT ${out}` : '');
  }

  function skeleton() {
    body.setAttribute('aria-busy', 'true');
    const rows = Array.from({ length: 2 }, () => el('tr', {},
      el('td', { 'data-col': 'name' }, dxSkel('140px'), el('div', { class: 'tk-skel-gap' }), dxSkel('200px')),
      el('td', { 'data-col': 'rows' }, dxSkel('56px')),
      el('td', { 'data-col': 'size' }, dxSkel('48px')),
      el('td', { 'data-col': 'updated' }, dxSkel('80px')),
      el('td', { 'data-col': 'act' })));
    fill(body, table(rows));
  }

  function failed(e) {
    body.setAttribute('aria-busy', 'false');
    fill(body, dxEmpty({ tone: 'danger', icon: 'circle-alert', compact: true, title: 'Couldn’t load the lookup tables', text: sentence(e.message), action: dxRetry(() => load()) }));
  }

  const COLS = [['name', 'Table'], ['rows', 'Rows'], ['size', 'Size'], ['updated', 'Updated'], ['act', '']];
  function table(rows) {
    return el('div', { class: 'table-wrap' }, el('table', { class: 'table tk-table' },
      el('thead', {}, el('tr', {}, ...COLS.map(([k, label]) => el('th', { 'data-col': k, scope: 'col' },
        label || el('span', { class: 'sr-only' }, 'Actions'))))),
      el('tbody', {}, ...rows)));
  }

  // ---------- the list ----------
  function render() {
    const d = L.data;
    body.setAttribute('aria-busy', 'false');
    const multi = !!d.multi_server;
    newBtn.disabled = multi;
    const tables = d.tables || [];
    const parts = [];
    if (multi) {
      parts.push(el('div', { class: 'alert tk-alert', 'data-tone': 'warning', role: 'status' }, icon('triangle-alert'),
        el('div', { class: 'tk-alert__body' }, el('b', {}, 'Lookup tables can’t be changed while there are several servers.'),
          el('p', {}, 'Each server keeps its own tables, and sharing them between servers is still to come.'))));
    }
    if (tables.length) {
      parts.push(table(tables.map((t) => row(t, multi))));
    } else {
      parts.push(el('div', { class: 'empty empty--compact tk-empty' },
        el('span', { class: 'empty__icon' }, icon('file-spreadsheet')),
        el('div', { class: 'empty__title' }, 'No lookup tables yet'),
        el('p', { class: 'empty__text' }, 'Upload a CSV file whose first line names its columns, such as host,owner,team. Then add its columns to events with the lookup command.'),
        multi ? null : el('div', { class: 'empty__actions' }, dxBtn('secondary', 'Add a table', () => openUpload(null), { sm: true, icon: 'upload' }))));
    }
    fill(body, ...parts);
  }

  function row(t, multi) {
    const items = [
      { icon: 'eye', label: 'View', run: () => openView(t) },
      { icon: 'search', label: 'Use in Search', run: () => useInSearch(t) },
      { icon: 'download', label: 'Download CSV', run: () => { location.href = 'api/lookuptables/' + encodeURIComponent(t.name) + '.csv'; } },
    ];
    if (!multi) {
      items.push({ icon: 'upload', label: 'Replace…', run: () => openUpload(t) });
      items.push({ icon: 'trash-2', label: 'Delete', danger: true, run: () => remove(t) });
    }
    const m = dxMenu('Actions for ' + t.name, items);
    m.classList.add('tk-menu');
    let cols = (t.columns || []).join(', ');
    const how = [(t.wildcard || []).length ? 'wildcards in ' + t.wildcard.join(', ') : '', t.ignore_case ? 'ignores case' : ''].filter(Boolean);
    if (how.length) cols += ' · ' + how.join(', ');
    return el('tr', { 'data-table': t.name },
      el('td', { 'data-col': 'name' },
        el('div', { class: 'tk-name mono' }, t.name),
        el('div', { class: 'tk-hint', title: cols }, cols)),
      el('td', { 'data-col': 'rows' }, el('span', { class: 'tk-num' }, t.rows.toLocaleString())),
      el('td', { 'data-col': 'size' }, el('span', { class: 'tk-num' }, size(t.bytes))),
      el('td', { 'data-col': 'updated' }, el('span', { title: full(t.updated) }, day(t.updated))),
      el('td', { 'data-col': 'act' }, m));
  }

  function focusRow(name) {
    const r = name ? body.querySelector(`[data-table="${CSS.escape(name)}"] summary`) : null;
    (r || newBtn).focus();
  }

  function useInSearch(t) {
    setQuery('* ' + example(t) + '\n| table ' + (t.columns || []).slice(0, 4).join(', '));
    showPage('search');
  }

  // ---------- dialogs ----------
  function setFieldError(input, err, msg) {
    if (msg) {
      input.setAttribute('aria-invalid', 'true');
      err.replaceChildren(icon('circle-alert'), sentence(msg));
    } else {
      input.removeAttribute('aria-invalid');
      err.replaceChildren();
    }
    err.classList.toggle('hidden', !msg);
  }

  // openUpload adds a table, or replaces t's rows when t is given.
  function openUpload(t) {
    const d = modalDialog('lt-dialog');
    const close = () => d.close();
    d.onclose = () => { fill(d); focusRow(t && t.name); };
    const file = el('input', { class: 'input', id: 'lt-f-file', type: 'file', accept: '.csv,text/csv', required: '', 'aria-describedby': 'lt-f-file-hint lt-f-file-error' });
    const fileErr = el('p', { class: 'field-error hidden', id: 'lt-f-file-error', role: 'alert' });
    const name = el('input', { class: 'input mono', id: 'lt-f-name', type: 'text', maxlength: '64', autocomplete: 'off', spellcheck: 'false', required: '',
      placeholder: 'owners', 'aria-describedby': 'lt-f-name-hint lt-f-name-error' });
    const nameErr = el('p', { class: 'field-error hidden', id: 'lt-f-name-error', role: 'alert' });
    // How keys match, as Splunk's match_type = WILDCARD(col) and
    // case_sensitive_match = false: kept from the table being replaced.
    const wild = el('input', { class: 'input mono', id: 'lt-f-wild', type: 'text', autocomplete: 'off', spellcheck: 'false',
      placeholder: 'process_path', 'aria-describedby': 'lt-f-wild-hint' });
    wild.value = ((t && t.wildcard) || []).join(', ');
    const fold = el('input', { type: 'checkbox', id: 'lt-f-fold' });
    fold.checked = !!(t && t.ignore_case);
    if (t) {
      name.value = t.name;
      name.readOnly = true;
    }
    name.addEventListener('input', () => setFieldError(name, nameErr, ''));
    file.addEventListener('change', () => {
      setFieldError(file, fileErr, '');
      if (!t && !name.value && file.files[0]) name.value = nameFrom(file.files[0].name);
    });
    const alertBox = formAlert();
    const label = t ? 'Replace table' : 'Add table';
    const submit = el('button', { type: 'submit', class: 'btn btn--primary' }, el('span', {}, label));
    const form = el('form', { novalidate: '' },
      modalHead('lt-dialog', t ? `Replace “${t.name}”` : 'Add a lookup table',
        t ? 'The new file replaces every row. Searches use it right away.' : 'A CSV file whose first line names the columns, up to 16 MB.', close),
      el('div', { class: 'modal__body' }, alertBox,
        el('div', { class: 'field' }, el('label', { class: 'label', for: 'lt-f-file' }, 'CSV file'), file,
          el('p', { class: 'hint', id: 'lt-f-file-hint' }, 'For example host,owner,team on the first line, then one row per host. Values match exactly, including case, unless you choose otherwise below.'), fileErr),
        el('div', { class: 'field' }, el('label', { class: 'label', for: 'lt-f-name' }, 'Name'), name,
          el('p', { class: 'hint', id: 'lt-f-name-hint' }, 'What searches call it: lower-case letters, digits, - and _.'), nameErr),
        el('fieldset', { class: 'field rp-fieldset' }, el('legend', { class: 'label' }, 'Matching'),
          el('label', { class: 'label', for: 'lt-f-wild' }, 'Wildcard columns (optional)'), wild,
          el('p', { class: 'hint', id: 'lt-f-wild-hint' }, 'Columns, separated by commas, whose cells can hold * to match any text, such as C:\\Windows\\*.exe.'),
          el('label', { class: 'check' }, fold, el('span', {}, 'Ignore case when matching')))),
      el('div', { class: 'modal__foot' }, el('button', { type: 'button', class: 'btn btn--ghost', onclick: close }, 'Cancel'), submit));
    form.addEventListener('submit', async (ev) => {
      ev.preventDefault();
      alertBox.classList.add('hidden');
      const f = file.files[0];
      if (!f) {
        setFieldError(file, fileErr, 'Pick a CSV file.');
        return file.focus();
      }
      const n = name.value.trim();
      if (!NAME_RE.test(n)) {
        setFieldError(name, nameErr, 'Use lower-case letters, digits, - and _, starting with a letter or digit.');
        return name.focus();
      }
      if (!t && (L.data && (L.data.tables || []).some((x) => x.name === n))) {
        const ok = await caseConfirm({ title: `Replace “${n}”?`, text: 'A table by that name exists. The new file replaces all its rows.', confirm: 'Replace table' });
        if (!ok) return name.focus();
      }
      submit.disabled = true;
      submit.setAttribute('aria-busy', 'true');
      try {
        const q = new URLSearchParams();
        const cols = wild.value.split(',').map((c) => c.trim()).filter(Boolean);
        if (cols.length) q.set('wildcard', cols.join(','));
        if (fold.checked) q.set('case_sensitive', 'false');
        const qs = q.toString() ? '?' + q.toString() : '';
        const resp = await apiRaw('api/lookuptables/' + encodeURIComponent(n) + qs, { method: 'PUT', headers: { 'Content-Type': 'text/csv' }, body: await f.text() });
        const data = await resp.json().catch(() => ({}));
        if (!resp.ok) {
          showAlert(alertBox, 'The table wasn’t saved', sentence(data.error || resp.statusText));
          return;
        }
        t = data;
        d.close();
        toast(`Saved “${data.name}” with ${data.rows.toLocaleString()} ${data.rows === 1 ? 'row' : 'rows'}. Searches use it right away.`);
        load(true);
      } catch (e) {
        showAlert(alertBox, 'The upload failed', sentence(e.message));
      } finally {
        submit.disabled = false;
        submit.setAttribute('aria-busy', 'false');
      }
    });
    fill(d, form);
    d.showModal();
    file.focus();
  }

  // openView shows a table's first rows and how to use it.
  async function openView(t) {
    const d = modalDialog('lt-view');
    const close = () => d.close();
    d.onclose = () => { fill(d); focusRow(t.name); };
    const box = el('div', { class: 'modal__body', 'aria-busy': 'true' }, dxSkel('100%'));
    fill(d, modalHead('lt-view', t.name, `${t.rows.toLocaleString()} ${t.rows === 1 ? 'row' : 'rows'} · ${(t.columns || []).length} columns`, close), box,
      el('div', { class: 'modal__foot' }, el('button', { type: 'button', class: 'btn btn--primary', onclick: close }, 'Done')));
    d.showModal();
    try {
      const r = await api('api/lookuptables/' + encodeURIComponent(t.name));
      const shown = (r.rows || []).slice(0, 200);
      const cols = r.table.columns || [];
      box.removeAttribute('aria-busy');
      fill(box,
        el('div', { class: 'lt-preview' }, el('table', { class: 'table' },
          el('thead', {}, el('tr', {}, ...cols.map((c) => el('th', { scope: 'col' }, c)))),
          el('tbody', {}, ...shown.map((row) => el('tr', {}, ...row.map((v) => el('td', {}, v))))))),
        r.table.rows > shown.length ? el('p', { class: 'hint' }, `The first ${shown.length.toLocaleString()} rows. Download the CSV for all of them.`) : null,
        el('div', { class: 'lt-usage' }, el('span', { class: 'label' }, 'Use it in a search'), el('code', {}, example(r.table))));
    } catch (e) {
      box.removeAttribute('aria-busy');
      fill(box, dxEmpty({ tone: 'danger', icon: 'circle-alert', compact: true, title: 'Couldn’t load the table', text: sentence(e.message) }));
    }
  }

  async function remove(t) {
    const ok = await caseConfirm({
      title: `Delete “${t.name}”?`,
      text: 'Searches and detections that look it up will fail until a table by that name is added again.',
      confirm: 'Delete table',
    });
    if (!ok) return focusRow(t.name);
    try {
      const resp = await apiRaw('api/lookuptables/' + encodeURIComponent(t.name), { method: 'DELETE' });
      if (!resp.ok) {
        const data = await resp.json().catch(() => ({}));
        throw new Error(data.error || resp.statusText);
      }
      toast(`Deleted “${t.name}”.`);
    } catch (e) {
      toastError('Couldn’t delete the table', e);
    }
    await load(true);
    focusRow(null);
  }
}());
