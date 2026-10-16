// Sign-in page. Posts the form as JSON and, on success, returns to the page
// the user first asked for.
'use strict';

(function () {
  const $ = (id) => document.getElementById(id);
  const root = document.documentElement;
  const auth = document.querySelector('.auth');
  const form = $('login-form');
  const user = $('username');
  const pass = $('password');
  const remember = $('remember');
  const submit = $('login-submit');
  const submitLabel = $('login-submit-label');
  const reveal = $('reveal');
  const caps = $('caps-hint');
  const forgot = $('forgot');
  const forgotNote = $('forgot-note');
  const params = new URLSearchParams(location.search);
  let lockTimer = null;
  const REFUSED_DISABLED = ['This account is disabled.', 'Ask a Signalith admin to enable it.'];

  // send is fetch with the headers of api() in app.js: it sends back how
  // far the servers had read the shared settings when this browser last
  // saw them, and keeps the newest such token, so behind a load balancer
  // a password just changed is known to the next server too.
  const CONFIG_KEY = 'signalith.config';
  async function send(path, opts) {
    let seen = {};
    try { seen = JSON.parse(sessionStorage.getItem(CONFIG_KEY)) || {}; } catch (_) { /* storage may be blocked */ }
    const headers = new Headers((opts && opts.headers) || {});
    if (seen.id) headers.set('X-Signalith-Config-Min', seen.id + '.' + seen.seq);
    const resp = await fetch(path, { ...(opts || {}), headers });
    const t = resp.headers.get('X-Signalith-Config') || '';
    const i = t.lastIndexOf('.');
    const seq = Number(t.slice(i + 1));
    if (i > 0 && Number.isFinite(seq) && (t.slice(0, i) !== seen.id || seq > seen.seq)) {
      try { sessionStorage.setItem(CONFIG_KEY, JSON.stringify({ id: t.slice(0, i), seq })); } catch (_) { /* storage may be blocked */ }
    }
    return resp;
  }

  // Only a path on this site is allowed as the return address, so a crafted
  // link cannot send someone to another site after signing in. The check
  // compares the resolved origin, because browsers drop tabs and newlines
  // and read \ as /, which turns "/<tab>/evil.example" into another site.
  // Without ?next, a #page the browser kept through the redirect applies.
  // With no page named at all, signing in opens the home page, Dashboards
  // (HOME_PAGE in app.js), rather than whatever page was used last.
  const HOME = '#dashboards';
  function nextPath() {
    const home = new URL('./', location.href).pathname + (location.hash || HOME);
    const next = params.get('next');
    if (!next || !next.startsWith('/')) return home;
    try {
      const u = new URL(next, location.href);
      // The full URL, not the path: "/.//evil.example" resolves to the
      // path "//evil.example", which on its own would leave the site.
      if (u.origin !== location.origin) return home;
      // A server redirect cannot see the #page; the browser kept it here.
      if (!u.hash) u.hash = location.hash || (u.pathname === new URL('./', location.href).pathname ? HOME : '');
      return u.href;
    } catch (_) {
      return home;
    }
  }

  // setView shows one of the messages above the form: error, locked,
  // signedout, or none. invalid is the field the error is about, if any:
  // only a wrong or missing value marks a field, so a refusal for another
  // reason (a disabled account, say) does not look like a wrong password.
  function setView(view, invalid) {
    auth.dataset.view = view || '';
    for (const f of [user, pass]) {
      if (f === invalid) f.setAttribute('aria-invalid', 'true');
      else f.removeAttribute('aria-invalid');
    }
  }

  function showError(title, text, invalid) {
    $('login-error-title').textContent = title;
    $('login-error-text').textContent = text || '';
    $('login-error-text').hidden = !text;
    setView('error', invalid);
  }

  function sentence(s) {
    s = String(s || '').trim();
    if (!s) return '';
    s = s.charAt(0).toUpperCase() + s.slice(1);
    return /[.!?]$/.test(s) ? s : s + '.';
  }

  function setBusy(busy) {
    submit.disabled = busy;
    submitLabel.textContent = busy ? 'Signing in…' : 'Sign in';
  }

  // locked pauses the form until the server's Retry-After has passed.
  function locked(message, seconds) {
    $('login-locked-text').textContent = sentence(message) || 'Too many failed sign-ins. Try again later.';
    setView('locked');
    submit.disabled = true;
    clearTimeout(lockTimer);
    const wait = Number(seconds);
    if (wait > 0) {
      lockTimer = setTimeout(() => {
        submit.disabled = false;
        if (auth.dataset.view === 'locked') setView('');
      }, wait * 1000);
    }
  }

  if (params.has('signedout')) setView('signedout');

  // ---- Single sign-on --------------------------------------------------
  // The button (shown by the server when single sign-on is on) returns to
  // the same page as a password sign-in; the server checks the path again.
  const ssoLink = $('sso-link');
  if (ssoLink) {
    const u = new URL(nextPath(), location.href);
    ssoLink.href = 'api/auth/oidc/start?next=' + encodeURIComponent(u.pathname + u.search + u.hash);
  }
  // A single sign-on that failed comes back here with a code; the reason
  // is in the server log.
  const SSO_REFUSED = {
    off: ['Single sign-on is turned off.', 'Sign in with your Signalith account, or ask a Signalith admin.'],
    provider: ['Signalith can’t reach your identity provider right now.', 'Try again in a minute. If it keeps happening, tell a Signalith admin.'],
    expired: ['That sign-in took too long or started in another browser.', 'Try again.'],
    denied: ['Your identity provider didn’t sign you in.', 'Try again, or ask your identity provider’s admin about your access.'],
    failed: ['Signalith couldn’t confirm your sign-in with your identity provider.', 'Try again. If it keeps happening, tell a Signalith admin: the server log says why.'],
    username: ['Your identity provider didn’t send a username Signalith can use.', 'Ask a Signalith admin to check the username claim under Settings, Single sign-on.'],
    domain: ['Your email address isn’t in a domain that can use Signalith.', 'Sign in with your work account, or ask a Signalith admin.'],
    role: ['Your account can’t use Signalith yet.', 'It isn’t in a group that Signalith lets in. Ask a Signalith admin to add you to one.'],
    new: ['You haven’t used Signalith before, and new users aren’t added.', 'Ask a Signalith admin to let you in.'],
    taken: ['Another Signalith user already has your username.', 'Ask a Signalith admin to sort it out.'],
    unconfirmed: ['Signalith couldn’t confirm this is the account your organization set up for you.', 'Ask a Signalith admin to check provisioning under Settings, Single sign-on.'],
    disabled: REFUSED_DISABLED,
    busy: ['Only admins can sign in right now.', 'Signalith can’t reach its storage. Try again later.'],
    store: ['Signalith couldn’t save your sign-in.', 'Try again. If it keeps happening, tell a Signalith admin.'],
  };
  const ssoError = params.get('sso_error');
  if (ssoError) {
    const m = SSO_REFUSED[ssoError] || SSO_REFUSED.failed;
    showError(m[0], m[1]);
    // A reload should not show it again.
    const clean = new URL(location.href);
    clean.searchParams.delete('sso_error');
    history.replaceState(null, '', clean.pathname + clean.search + clean.hash);
  }

  reveal.addEventListener('click', () => {
    const show = pass.type === 'password';
    pass.type = show ? 'text' : 'password';
    reveal.setAttribute('aria-pressed', String(show));
    reveal.setAttribute('aria-label', show ? 'Hide password' : 'Show password');
    reveal.title = show ? 'Hide password' : 'Show password';
    reveal.querySelector('use').setAttribute('href', show ? '#i-eye-off' : '#i-eye');
    pass.focus();
  });

  forgot.addEventListener('click', () => {
    const open = forgotNote.hidden;
    forgotNote.hidden = !open;
    forgot.setAttribute('aria-expanded', String(open));
  });

  // Caps Lock hint while typing the password.
  const capsCheck = (ev) => {
    if (ev.getModifierState) caps.toggleAttribute('data-on', ev.getModifierState('CapsLock'));
  };
  pass.addEventListener('keydown', capsCheck);
  pass.addEventListener('keyup', capsCheck);
  pass.addEventListener('blur', () => caps.removeAttribute('data-on'));

  // The theme toggle saves the choice under the same key as the app.
  document.querySelectorAll('[data-theme-toggle]').forEach((b) => b.addEventListener('click', () => {
    const dark = root.dataset.theme ? root.dataset.theme === 'dark' : matchMedia('(prefers-color-scheme: dark)').matches;
    root.dataset.theme = dark ? 'light' : 'dark';
    try { localStorage.setItem('signalith.theme', root.dataset.theme); } catch (_) { /* storage may be blocked */ }
  }));

  // Messages for the sign-in refusals the server names with a code.
  const REFUSED = {
    wrong_credentials: ['That username and password don’t match.', 'After 10 failed attempts, sign-in pauses for 15 minutes.'],
    disabled: REFUSED_DISABLED,
    not_in_group: ['Your account can’t use Signalith yet.', 'It isn’t in a directory group that Signalith lets in. Ask a Signalith admin to add you to one.'],
    password_expired: ['Your directory password has expired.', 'Change it the way you usually do, for example by signing in to Windows, then sign in here again.'],
    directory_unavailable: ['Signalith can’t reach your directory right now.', 'Try again in a minute. If it keeps happening, tell a Signalith admin.'],
  };

  form.addEventListener('submit', async (ev) => {
    ev.preventDefault();
    if (submit.disabled) return;
    if (!user.value.trim() || !pass.value) {
      const missing = user.value.trim() ? pass : user;
      showError('Enter your username and password.', '', missing);
      missing.focus();
      return;
    }
    setBusy(true);
    let resp;
    try {
      resp = await send('api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: user.value.trim(), password: pass.value, remember: remember.checked }),
      });
    } catch (_) {
      setBusy(false);
      showError('Could not reach the Signalith server.', 'Check your connection and try again.');
      return;
    }
    const data = await resp.json().catch(() => ({}));
    if (resp.ok) {
      if (data.must_change_password) {
        setBusy(false);
        showChange(data, pass.value);
        return;
      }
      location.replace(nextPath());
      return;
    }
    setBusy(false);
    if (resp.status === 429) {
      locked(data.error, resp.headers.get('Retry-After'));
      return;
    }
    const wrong = resp.status === 401 || data.code === 'wrong_credentials';
    const known = REFUSED[data.code] || (wrong ? REFUSED.wrong_credentials : null);
    if (known) showError(known[0], known[1], wrong ? pass : null);
    else showError('Sign-in failed.', sentence(data.error) || 'Try again.');
    // Only a wrong password is worth retyping; the other refusals would be
    // refused again (and retries count toward the lockout). Focus stays on
    // the button, which was disabled while signing in.
    if (wrong) pass.select();
    else submit.focus();
  });

  // ---- Choose a new password -------------------------------------------
  // After signing in with a temporary password the only way on is to
  // choose a new one. The server refuses everything else until then.
  const change = $('change-form');
  const cCurrent = $('change-current');
  const cNew = $('change-new');
  const cAgain = $('change-again');
  const cSubmit = $('change-submit');
  const cLabel = $('change-submit-label');
  let temporary = '';

  function changeError(title, text, input) {
    $('change-error-title').textContent = title;
    $('change-error-text').textContent = text || '';
    $('change-error-text').hidden = !text;
    $('change-error').hidden = false;
    [cCurrent, cNew, cAgain].forEach((el) => el.removeAttribute('aria-invalid'));
    if (input) {
      input.setAttribute('aria-invalid', 'true');
      input.focus();
      input.select();
    }
  }

  function showChange(me, typed) {
    temporary = typed || '';
    const who = me && (me.name || me.username);
    $('change-sub').textContent = (who ? who + ', you' : 'You') + ' signed in with a temporary password. Choose your own to continue.';
    $('change-current-field').hidden = !!temporary;
    $('change-error').hidden = true;
    form.hidden = true;
    change.hidden = false;
    setView('');
    document.title = 'Choose a new password · Signalith';
    (temporary ? cNew : cCurrent).focus();
  }

  function showSignIn() {
    change.hidden = true;
    form.hidden = false;
    temporary = '';
    [cCurrent, cNew, cAgain].forEach((el) => { el.value = ''; });
    pass.value = '';
    document.title = 'Sign in · Signalith';
    setView('signedout');
    user.focus();
  }

  change.addEventListener('submit', async (ev) => {
    ev.preventDefault();
    if (cSubmit.disabled) return;
    const current = temporary || cCurrent.value;
    if (!current) { changeError('Enter your temporary password.', '', cCurrent); return; }
    if (cNew.value.length < 8) { changeError('Use at least 8 characters.', '', cNew); return; }
    if (cNew.value !== cAgain.value) { changeError('The two new passwords don’t match.', 'Type the same password in both boxes.', cAgain); return; }
    if (cNew.value === current) { changeError('Choose a password that is different from the temporary one.', '', cNew); return; }
    cSubmit.disabled = true;
    cLabel.textContent = 'Saving…';
    let resp;
    try {
      resp = await send('api/me/password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ current_password: current, new_password: cNew.value }),
      });
    } catch (_) {
      resp = null;
    }
    cSubmit.disabled = false;
    cLabel.textContent = 'Save and continue';
    if (!resp) { changeError('Could not reach the Signalith server.', 'Check your connection and try again.'); return; }
    if (resp.ok) { location.replace(nextPath()); return; }
    const data = await resp.json().catch(() => ({}));
    if (resp.status === 401) { showSignIn(); showError('Your session ended.', 'Sign in again with your temporary password.'); return; }
    if (resp.status === 429) { changeError('Too many tries.', sentence(data.error)); return; }
    if (data.field === 'current_password') {
      // The typed temporary password was replaced in the meantime: ask for it.
      temporary = '';
      $('change-current-field').hidden = false;
      changeError('Your temporary password is not right.', 'An admin may have reset it again. Ask them for the newest one.', cCurrent);
      return;
    }
    changeError(sentence(data.error) || 'Your password could not be changed.', '', data.field === 'new_password' ? cNew : null);
  });

  $('change-signout').addEventListener('click', async () => {
    try { await send('api/logout', { method: 'POST' }); } catch (_) { /* signing out locally is enough */ }
    showSignIn();
  });

  // A session that still needs a new password is sent here from the app
  // with ?change=1. Asking api/me without a session would log a 401.
  if (params.has('change')) send('api/me', { headers: { Accept: 'application/json' } })
    .then((r) => (r.ok ? r.json() : null))
    .then((me) => { if (me && me.must_change_password && change.hidden) showChange(me, ''); })
    .catch(() => { /* not signed in */ });

  (user.value ? pass : user).focus();
}());
