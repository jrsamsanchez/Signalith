// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0
// Settings > Sign-in notice (admins): the notice on the sign-in page
// (auth.notice.title, auth.notice.text and auth.notice.agree in the
// registry, internal/config/settings.go), read with GET api/auth/notice
// and saved with PUT api/settings like the Server tab's, so the save is in
// the audit log and every server of a cluster shares it. The notice is
// plain text everywhere: the preview here and the sign-in page set it as
// text, never as HTML. See docs/sign-in-notice.md.
'use strict';

(function () {
  const N = { view: null, seq: 0 };
  const body = $('nt-body');
  const DOCS = 'https://github.com/jrsamsanchez/signalith/blob/main/docs/sign-in-notice.md';

  pageHooks.push((name) => {
    if (name === 'notice' && can('admin')) load();
  });

  // Leaving with unsaved changes asks first.
  leaveGuards.push((from, to, opts) => {
    if (from !== 'notice' || !N.view || !dirty()) return true;
    caseConfirm({
      title: 'Discard your changes?',
      text: 'The sign-in notice was changed but not saved. Leave this page without saving?',
      confirm: 'Discard changes',
    }).then((ok) => {
      if (!ok) { const b = $('nt-save'); if (b) b.focus(); return; }
      N.view = null;
      showPage(to, Object.assign({}, opts, { force: true }));
    });
    return false;
  });

  async function load() {
    const seq = ++N.seq;
    body.setAttribute('aria-busy', 'true');
    try {
      const v = await api('api/auth/notice');
      if (seq !== N.seq) return;
      N.view = v;
      render();
    } catch (e) {
      if (seq !== N.seq) return;
      body.replaceChildren(el('p', { class: 'nt-warn' }, icon('triangle-alert'), el('span', {}, sentence(e.message))));
    } finally {
      if (seq === N.seq) body.removeAttribute('aria-busy');
    }
  }

  // draft is what the fields hold now, as the server keeps it: Windows line
  // breaks made plain ones and the ends trimmed.
  function draft() {
    const t = $('nt-title-in');
    const x = $('nt-text');
    const a = $('nt-agree');
    if (!t || !x || !a) return null;
    return { title: t.value.trim(), text: x.value.replace(/\r\n?/g, '\n').trim(), agree: a.checked };
  }
  function dirty() {
    const d = draft();
    const v = N.view;
    return !!d && (d.title !== (v.title || '') || d.text !== (v.text || '') || d.agree !== !!v.agree);
  }
  const chars = (s) => [...s].length;

  function render() {
    const v = N.view;
    const editable = !!v.editable;
    const title = el('input', { id: 'nt-title-in', class: 'input', type: 'text', maxlength: String(v.title_max), placeholder: 'Notice', autocomplete: 'off', disabled: !editable, 'aria-describedby': 'nt-title-help' });
    title.value = v.title || '';
    const text = el('textarea', { id: 'nt-text', class: 'textarea input', rows: '8', disabled: !editable, 'aria-describedby': 'nt-text-help nt-count',
      placeholder: 'This system is for authorized use only. Activity on it is monitored and recorded. By signing in you agree to these terms.' });
    text.value = v.text || '';
    const count = el('span', { class: 'nt-count', id: 'nt-count', 'aria-live': 'polite' });
    const agree = el('input', { type: 'checkbox', id: 'nt-agree', checked: !!v.agree, disabled: !editable });
    const agreeState = el('span', { class: 'st-switch__state', 'aria-hidden': 'true' }, v.agree ? 'On' : 'Off');

    // The preview is the sign-in page's box, filled as text.
    const pvTitle = el('b', { class: 'auth__notice-title' });
    const pvText = el('div', { class: 'auth__notice-text' });
    const pvAgree = el('label', { class: 'check auth__notice-agree' }, el('input', { type: 'checkbox', disabled: true, tabindex: '-1' }), 'I have read this notice and agree to it');
    const preview = el('div', { class: 'auth__notice nt-preview', 'aria-hidden': 'true' }, pvTitle, pvText, pvAgree);
    const pvEmpty = el('p', { class: 'nt-help' }, 'The notice is off: the sign-in page shows none while it is empty.');

    const status = el('p', { class: 'nt-help', id: 'nt-status' });
    const save = el('button', { type: 'button', class: 'btn btn--primary btn--sm', id: 'nt-save', disabled: true }, icon('check'), 'Save');
    const revert = el('button', { type: 'button', class: 'btn btn--ghost btn--sm', id: 'nt-revert', disabled: true }, 'Undo changes');

    function update() {
      const d = draft();
      const n = chars(d.text);
      const over = n > v.text_max;
      count.textContent = `${n.toLocaleString()} of ${v.text_max.toLocaleString()} characters`;
      count.classList.toggle('nt-count--over', over);
      if (over) text.setAttribute('aria-invalid', 'true');
      else text.removeAttribute('aria-invalid');
      agreeState.textContent = d.agree ? 'On' : 'Off';
      pvTitle.textContent = d.title || 'Notice';
      pvText.textContent = d.text;
      pvAgree.hidden = !d.agree;
      preview.hidden = !d.text;
      pvEmpty.hidden = !!d.text;
      const changed = dirty();
      save.disabled = !editable || !changed || over || (d.agree && !d.text);
      revert.disabled = !changed;
      status.textContent = d.agree && !d.text ? 'Write the notice people agree to first.'
        : v.on ? (v.agree ? 'On: the sign-in page shows the notice, and nobody signs in there without ticking I agree.' : 'On: the sign-in page shows the notice.')
          : 'Off: the sign-in page shows no notice.';
    }
    [title, text].forEach((n) => n.addEventListener('input', update));
    agree.addEventListener('change', update);
    revert.addEventListener('click', () => render());

    save.addEventListener('click', async () => {
      const d = draft();
      const values = { 'auth.notice.title': d.title, 'auth.notice.text': d.text, 'auth.notice.agree': d.agree };
      const restore = busy(save, 'Saving…');
      try {
        await api('api/settings', { values }, 'PUT');
        restore();
        toast(d.text ? 'Saved. The sign-in page shows the new notice now.' : 'Saved. The sign-in page shows no notice now.');
        await load();
      } catch (e) {
        restore();
        if (e.code === 'forbidden') return;
        const fields = e.fields || {};
        const msg = Object.values(fields)[0] || (e.problems && e.problems[0]) || e.message;
        toast(sentence(msg), null, { tone: 'danger' });
      }
    });

    body.replaceChildren(
      status,
      el('div', { class: 'nt-row' }, el('label', { class: 'label', for: 'nt-title-in' }, 'Title'), title,
        el('p', { class: 'nt-help', id: 'nt-title-help' }, 'The notice’s heading. Empty: Notice.')),
      el('div', { class: 'nt-row' }, el('label', { class: 'label', for: 'nt-text' }, 'Notice'), text,
        el('div', { class: 'nt-meta' }, el('p', { class: 'nt-help', id: 'nt-text-help' }, 'Plain text: line breaks are kept, and nothing is read as HTML or a link. Empty turns the notice off.'), count)),
      el('div', { class: 'nt-row' },
        el('div', { class: 'nt-switch-row' }, el('span', { class: 'label', id: 'nt-agree-label' }, 'Ask people to agree'),
          el('label', { class: 'switch st-switch', 'aria-labelledby': 'nt-agree-label' }, agree, agreeState)),
        el('p', { class: 'nt-help' }, 'Nobody can sign in on the sign-in page, with a password, a passkey or single sign-on, until they tick I agree. Each sign-in is logged with notice=agreed. API tokens are for scripts and are not asked.')),
      el('div', { class: 'nt-row' }, el('span', { class: 'label' }, 'Preview'), preview, pvEmpty),
      editable ? el('div', { class: 'nt-actions' }, save, revert,
        el('a', { class: 'nt-docs', href: DOCS, target: '_blank', rel: 'noopener' }, 'The sign-in notice guide'))
        : el('p', { class: 'nt-help' }, 'This server has no settings file, so the notice can only be changed in signalith.yaml (auth.notice).'));
    update();
  }
}());
