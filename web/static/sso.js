// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0
// Settings > Single sign-on (admins): signing in with an identity provider
// over OpenID Connect (Microsoft Entra ID, Okta, Google, Keycloak) or SAML
// 2.0 (AD FS, Okta, Entra ID), each on its own tab of the page.
// The settings are ordinary settings (auth.oidc.* and auth.saml.* in the registry,
// internal/config/settings.go), saved with PUT api/settings like those of
// the Server tab: every server of a cluster shares them, and the client
// secret is kept encrypted and only sent to the issuer it was entered
// for. This page lays them out for the task, with the redirect URI to
// register and a test of the provider. See docs/sso.md.
'use strict';

(function () {
  // O.view is the last api/auth/oidc reply; O.drafts the unsaved changes
  // by setting ({ value } or { clear: true } for the secret); O.replacing
  // whether the secret's box is open; O.errors the problems by setting
  // from the last save or test.
  // O.proto is the protocol shown, oidc or saml; O.tests the last test
  // of each, with O.snaps the settings it ran with.
  const O = { view: null, seq: 0, drafts: {}, replacing: false, errors: {}, general: [], tests: {}, snaps: {}, saving: false, token: '', proto: '' };
  const page = $('sso-page');
  const DOCS = 'https://github.com/jrsamsanchez/signalith/blob/main/docs/sso.md';
  const SECRET = 'auth.oidc.client_secret';
  const SCIM_ON = 'auth.scim.enabled';
  const SCIM_TOKEN = 'auth.scim.token_sha256';
  // Each provider's section of the guide.
  const DOCS_AT = { entra: 'microsoft-entra-id', okta: 'okta', google: 'google', keycloak: 'keycloak', other: 'other-providers' };
  const SAML_DOCS_AT = { adfs: 'ad-fs', entra: 'microsoft-entra-id-saml', okta: 'okta-saml', other: 'other-saml-providers' };
  const PROTO_KEY = 'signalith.sso.protocol';
  const SAML_XML = 'auth.saml.metadata_xml';

  // The cards, and the settings in each.
  const CARDS = [
    { id: 'provider', proto: 'oidc', title: 'Identity provider', desc: 'Register Signalith with your identity provider as a web application, then enter what it gives you here.',
      keys: ['auth.oidc.enabled', 'auth.oidc.provider', 'auth.oidc.issuer', 'auth.oidc.client_id', SECRET], redirect: true, test: 'oidc' },
    { id: 'access', proto: 'oidc', title: 'Who gets in', desc: 'Roles come from the groups the provider sends, at every sign-in. Someone in several lists gets the highest role.',
      keys: ['auth.oidc.admin_groups', 'auth.oidc.analyst_groups', 'auth.oidc.viewer_groups', 'auth.oidc.default_role', 'auth.oidc.allowed_domains', 'auth.oidc.create_users'] },
    { id: 'claims', proto: 'oidc', title: 'Claims and button', desc: 'The provider’s usual values are filled in. Change them only if your provider sends something else.',
      keys: ['auth.oidc.scopes', 'auth.oidc.username_claim', 'auth.oidc.groups_claim', 'auth.oidc.button_label'] },
    { id: 'saml-provider', proto: 'saml', title: 'Identity provider', desc: 'Add Signalith to your identity provider as a SAML application with the entity ID and ACS URL below, then give Signalith the provider’s metadata.',
      keys: ['auth.saml.enabled', 'auth.saml.provider', 'auth.saml.metadata_url', SAML_XML], samlAddrs: true, test: 'saml' },
    { id: 'saml-access', proto: 'saml', title: 'Who gets in', desc: 'Roles come from the groups the provider sends, at every sign-in. Someone in several lists gets the highest role.',
      keys: ['auth.saml.admin_groups', 'auth.saml.analyst_groups', 'auth.saml.viewer_groups', 'auth.saml.default_role', 'auth.saml.create_users'] },
    { id: 'saml-attrs', proto: 'saml', title: 'Attributes and button', desc: 'The provider’s usual attributes are filled in. Change them only if your provider sends something else.',
      keys: ['auth.saml.username_attribute', 'auth.saml.groups_attribute', 'auth.saml.button_label'] },
    { id: 'scim', title: 'Provisioning (SCIM)', desc: 'Optional. Lets the identity provider add people before they first sign in, keep their names up to date, and disable or remove them, which signs them out at once. Roles still come from their groups at each sign-in.',
      keys: [SCIM_ON, SCIM_TOKEN], scim: true },
  ];
  // What to look for in each provider's console, under the issuer.
  const ISSUER_HINT = {
    entra: 'In Entra ID: App registrations, your app, Endpoints. Use the tenant ID, not “common”.',
    okta: 'In Okta: Security, API, Authorization Servers. The default server’s issuer ends in /oauth2/default.',
    google: 'Google’s issuer is always https://accounts.google.com; leave this empty.',
    keycloak: 'In Keycloak: Realm settings, OpenID Endpoint Configuration. It ends in /realms/ and your realm’s name.',
    other: 'Your provider’s discovery document is at this address plus /.well-known/openid-configuration.',
  };
  // Where each SAML provider publishes its metadata, and what its groups
  // look like.
  const METADATA_HINT = {
    adfs: 'In AD FS it is /FederationMetadata/2007-06/FederationMetadata.xml on your AD FS server.',
    entra: 'In Entra ID: Enterprise applications, your app, Single sign-on, SAML Certificates: the App Federation Metadata Url.',
    okta: 'In Okta: Applications, your app, Sign On: the Metadata URL.',
    other: 'Your provider lists it with its SAML settings, often as IdP metadata.',
  };
  const SAML_GROUPS_HINT = {
    adfs: 'AD FS sends group names once a claim rule sends Token-Groups as Group.',
    entra: 'Entra ID sends group object IDs (GUIDs) once a group claim is added.',
    okta: 'Okta sends group names once a group attribute statement named groups is added.',
    other: 'As the groups attribute names them.',
  };
  const GROUPS_HINT = {
    entra: 'Entra ID sends group object IDs (GUIDs), or app role values when the groups claim is roles.',
    okta: 'Okta sends group names once the groups claim is added to the authorization server.',
    google: 'Google sends no groups: list people’s email addresses here instead.',
    keycloak: 'Keycloak sends group paths such as /soc-analysts once a group membership mapper is added.',
    other: 'As the groups claim names them.',
  };

  pageHooks.push((name) => {
    if (name === 'sso' && can('admin')) load();
  });

  // Leaving with unsaved changes asks first, inside the app and out.
  leaveGuards.push((from, to, opts) => {
    if (from !== 'sso' || !O.view || !dirty()) return true;
    const n = dirty();
    caseConfirm({
      title: 'Discard your changes?',
      text: `${n === 1 ? 'One setting was' : n + ' settings were'} changed but not saved. Leave this page without saving?`,
      confirm: 'Discard changes',
    }).then((ok) => {
      if (!ok) { const b = $('sso-save'); if (b) b.focus(); return; }
      O.drafts = {};
      O.errors = {};
      O.general = [];
      O.replacing = false;
      O.token = '';
      showPage(to, Object.assign({}, opts, { force: true }));
    });
    return false;
  });
  window.addEventListener('beforeunload', (ev) => {
    if (O.view && dirty()) { ev.preventDefault(); ev.returnValue = ''; }
  });

  async function load() {
    if (!O.view) skeleton();
    const seq = ++O.seq;
    try {
      const v = await api('api/auth/oidc');
      if (seq !== O.seq) return;
      O.view = v;
      render();
    } catch (e) {
      if (seq !== O.seq) return;
      page.setAttribute('aria-busy', 'false');
      fill(page, el('div', { class: 'card' }, dxEmpty({ tone: 'danger', icon: 'circle-alert', compact: true, title: 'Couldn’t load single sign-on', text: sentence(e.message), action: dxRetry(() => load()) })));
    }
  }

  function skeleton() {
    page.setAttribute('aria-busy', 'true');
    fill(page, ...CARDS.slice(0, 2).map(() => el('section', { class: 'card st-card st-skel' },
      el('div', { class: 'st-card__head' }, el('div', { class: 'st-card__heading' }, dxSkel('160px'))),
      el('div', { class: 'st-card__body' }, ...[1, 2, 3].map(() => el('div', { class: 'st-field' },
        el('div', { class: 'st-field__text' }, dxSkel('120px'), dxSkel('70%')), el('div', { class: 'st-field__control' }, dxSkel('100%'))))))));
  }

  // ---------- values ----------
  const field = (key) => (O.view.fields || []).find((f) => f.key === key);
  const editable = () => !!O.view.editable;
  const readOnly = (f) => !f || f.locked || !editable() || O.saving;
  const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);
  function current(key) {
    const d = O.drafts[key];
    if (d && 'value' in d) return d.value;
    const f = field(key);
    return f ? f.value : undefined;
  }
  // isSAML tells the SAML settings from the OpenID Connect ones.
  const isSAML = (key) => key.startsWith('auth.saml.');
  const provider = (key) => current(key && isSAML(key) ? 'auth.saml.provider' : 'auth.oidc.provider') || '';
  const preset = (key) => ((key && isSAML(key) ? O.view.saml_presets : O.view.presets) || []).find((p) => p.id === provider(key)) || null;
  const dirty = () => Object.keys(O.drafts).length;

  function setDraft(f, value) {
    if (f.type === 'secret') {
      if (value === '') delete O.drafts[f.key]; else O.drafts[f.key] = { value };
    } else if (same(value, f.value)) {
      delete O.drafts[f.key];
    } else {
      O.drafts[f.key] = { value };
    }
    delete O.errors[f.key];
  }

  function parse(f, raw) {
    if (f.type === 'list') return String(raw).split(/[\n,]/).map((s) => s.trim()).filter(Boolean);
    if (f.type === 'bool') return !!raw;
    return String(raw).trim();
  }

  // payload is a change as PUT api/settings and the test take it.
  function payload() {
    const values = {};
    const clear = [];
    for (const [k, d] of Object.entries(O.drafts)) {
      if (d.clear) clear.push(k); else values[k] = d.value;
    }
    return { values, clear };
  }

  // ---------- drawing ----------
  function render() {
    const v = O.view;
    page.setAttribute('aria-busy', 'false');
    const parts = [];
    if (!v.editable) {
      parts.push(dxAlert('info', 'These settings can’t be changed here', 'This server was started without a configuration file. Start it with one (signalith serve -c signalith.yaml) to set up single sign-on on this page.'));
    }
    parts.push(statusCard());
    parts.push(protoTabs());
    const panel = el('div', { class: 'sso-panel', role: 'tabpanel', id: 'sso-panel', 'aria-labelledby': 'sso-tab-' + proto() });
    for (const c of CARDS) if (!c.proto || c.proto === proto()) panel.append(card(c));
    parts.push(panel);
    if (O.general.length) {
      parts.push(dxAlert('danger', 'Nothing was saved', '', el('ul', { class: 'st-problems' }, ...O.general.map((p) => el('li', {}, sentence(p))))));
    }
    parts.push(saveBar());
    const focusId = document.activeElement && page.contains(document.activeElement) ? document.activeElement.id : '';
    fill(page, ...parts);
    if (focusId && $(focusId)) $(focusId).focus();
  }

  // statusCard says whether single sign-on is on now, with what, and for
  // whom.
  function statusCard() {
    const v = O.view;
    const label = (list, key) => { const p = (list || []).find((x) => x.id === (field(key) || {}).value); return p ? p.label : ''; };
    const using = [];
    if (v.on) using.push('OpenID Connect' + (label(v.presets, 'auth.oidc.provider') ? ' with ' + label(v.presets, 'auth.oidc.provider') : ''));
    if (v.saml_on) using.push('SAML' + (label(v.saml_presets, 'auth.saml.provider') ? ' with ' + label(v.saml_presets, 'auth.saml.provider') : ''));
    const on = using.length > 0;
    const n = v.sso_users || 0;
    const who = n === 1 ? '1 person has signed in with it.' : n + ' people have signed in with it.';
    return el('div', { class: 'card sso-status', 'data-on': on ? 'true' : 'false' },
      el('span', { class: 'sso-status__icon' }, icon(on ? 'circle-check' : 'circle-dashed')),
      el('div', { class: 'sso-status__text' },
        el('b', {}, on ? 'Single sign-on is on: ' + using.join(' and ') : 'Single sign-on is off'),
        el('p', {}, on ? 'The sign-in page shows a button for it. Local users, directory sign-in and the built-in admin still work. ' + who
          : 'Set up your identity provider below, with OpenID Connect or SAML, test it, then turn single sign-on on.')),
      el('a', { class: 'btn btn--ghost btn--sm sso-status__docs', href: DOCS, target: '_blank', rel: 'noopener noreferrer' },
        icon('book-open'), 'Setup guide', el('span', { class: 'sr-only' }, ' (opens in a new tab)')));
  }

  // proto is the protocol shown: the one picked last, or the one on.
  function proto() {
    if (!O.proto) {
      let saved = '';
      try { saved = localStorage.getItem(PROTO_KEY) || ''; } catch (_) { /* storage may be blocked */ }
      O.proto = saved === 'saml' || saved === 'oidc' ? saved : (O.view.saml_on && !O.view.on ? 'saml' : 'oidc');
    }
    return O.proto;
  }

  // protoTabs switches between OpenID Connect and SAML. Unsaved changes
  // on either stay until saved or discarded.
  function protoTabs() {
    const tabs = el('div', { class: 'tabs sso-tabs', role: 'tablist', 'aria-label': 'Protocol' });
    const pick = (id, focus) => {
      O.proto = id;
      try { localStorage.setItem(PROTO_KEY, id); } catch (_) { /* storage may be blocked */ }
      render();
      if (focus && $('sso-tab-' + id)) $('sso-tab-' + id).focus();
    };
    for (const [id, label, on] of [['oidc', 'OpenID Connect', O.view.on], ['saml', 'SAML 2.0', O.view.saml_on]]) {
      const t = el('button', { class: 'tab', type: 'button', role: 'tab', id: 'sso-tab-' + id, 'aria-controls': 'sso-panel',
        'aria-selected': String(proto() === id), tabindex: proto() === id ? '0' : '-1' }, label,
      on ? el('span', { class: 'badge badge--success sso-tab__on' }, 'On') : null);
      t.addEventListener('click', () => { if (proto() !== id) pick(id); });
      tabs.append(t);
    }
    tabs.addEventListener('keydown', (e) => {
      if (!['ArrowRight', 'ArrowLeft', 'Home', 'End'].includes(e.key)) return;
      e.preventDefault();
      pick(proto() === 'oidc' ? 'saml' : 'oidc', true);
    });
    return tabs;
  }

  function card(c) {
    const titleId = 'sso-' + c.id + '-title';
    const rows = [];
    for (const key of c.keys) {
      const f = field(key);
      if (f) rows.push(row(f));
      if (key === SECRET && c.redirect) rows.push(redirectRow());
      if (key === SAML_XML && c.samlAddrs) {
        rows.push(copyRow('sso-saml-entity', 'Entity ID', O.view.saml_entity_id,
          'Give the identity provider this identifier (AD FS: relying party identifier; Entra ID: Identifier; Okta: Audience URI). Signalith’s own SAML metadata is at this address too, for providers that read it.',
          'Copy the entity ID', O.view.saml_warning));
        rows.push(copyRow('sso-saml-acs', 'ACS URL', O.view.saml_acs_url,
          'Where the provider posts its signed answer (AD FS: SAML assertion consumer endpoint; Entra ID: Reply URL; Okta: Single sign-on URL). Both come from the web address on the Server tab.',
          'Copy the ACS URL', ''));
      }
      if (key === SCIM_ON && c.scim) rows.push(copyRow('sso-scim-url', 'SCIM base URL', O.view.scim_url,
        'Enter this address in the identity provider as the tenant URL (Entra ID) or base URL (Okta). It comes from the web address on the Server tab.',
        'Copy the SCIM base URL', O.view.scim_warning));
    }
    return el('section', { class: 'card st-card', id: 'sso-' + c.id, 'aria-labelledby': titleId },
      el('div', { class: 'st-card__head' }, el('div', { class: 'st-card__heading' },
        el('h3', { class: 'st-card__title', id: titleId }, c.title), el('p', { class: 'st-card__desc' }, c.desc))),
      el('div', { class: 'st-card__body' }, ...rows),
      c.test ? testBlock(c.test) : null);
  }

  const idOf = (key) => 'sso-' + key.replace(/[^a-z0-9]+/gi, '-');

  // help is a setting's help, with what fits the provider chosen.
  function help(f) {
    const p = provider(f.key);
    if (f.key === 'auth.oidc.issuer' && ISSUER_HINT[p]) return f.help + ' ' + ISSUER_HINT[p];
    if (f.key === 'auth.oidc.admin_groups' && GROUPS_HINT[p]) return f.help + ' ' + GROUPS_HINT[p];
    if (f.key === 'auth.saml.metadata_url' && METADATA_HINT[p]) return f.help + ' ' + METADATA_HINT[p];
    if (f.key === 'auth.saml.admin_groups' && SAML_GROUPS_HINT[p]) return f.help + ' ' + SAML_GROUPS_HINT[p];
    return f.help;
  }

  function row(f) {
    const id = idOf(f.key);
    const label = f.type === 'secret' || f.key === SCIM_TOKEN ? el('span', { class: 'st-field__label', id: id + '-label' }, f.label)
      : el('label', { class: 'st-field__label', id: id + '-label', for: id }, f.label);
    const notes = [];
    if (f.locked) notes.push(el('p', { class: 'st-source st-source--env' }, icon('lock', 'icon--xs'), el('span', {}, 'Set by ' + f.env + ' where Signalith is started.')));
    const problem = O.errors[f.key] || (!O.drafts[f.key] && f.problem);
    if (problem) notes.push(el('p', { class: 'field-error', role: O.errors[f.key] ? 'alert' : null }, icon('circle-alert'), el('span', {}, sentence(problem))));
    if (f.warning) notes.push(el('p', { class: 'st-warn' }, icon('triangle-alert'), el('span', {}, sentence(f.warning))));
    if ((f.key === 'auth.oidc.provider' || f.key === 'auth.saml.provider') && provider(f.key)) {
      const at = isSAML(f.key) ? SAML_DOCS_AT[provider(f.key)] || 'saml-20' : DOCS_AT[provider(f.key)] || 'set-it-up';
      notes.push(el('p', { class: 'st-hint' }, el('a', { href: DOCS + '#' + at, target: '_blank', rel: 'noopener noreferrer' },
        'How to set up ' + (preset(f.key) ? preset(f.key).label : 'your provider'), icon('arrow-up-right', 'icon--xs'))));
    }
    return el('div', { class: 'st-field', 'data-key': f.key, 'data-type': f.type },
      el('div', { class: 'st-field__text' }, label, el('p', { class: 'st-field__help', id: id + '-help' }, help(f))),
      el('div', { class: 'st-field__control' }, control(f, id), el('div', { class: 'st-field__notes', id: id + '-notes' }, ...notes)));
  }

  // placeholder is an example for an empty box, from the provider's preset.
  function placeholder(f) {
    const p = preset(f.key);
    const prov = provider(f.key);
    if (p && isSAML(f.key)) {
      if (f.key === 'auth.saml.metadata_url') return p.metadata_example;
      if (f.key === 'auth.saml.username_attribute') return p.username_attribute;
      if (f.key === 'auth.saml.groups_attribute') return p.groups_attribute;
      if (f.key === 'auth.saml.button_label') return prov === 'other' ? 'Sign in with SAML single sign-on' : 'Sign in with ' + p.label.replace(/^Microsoft /, '');
    } else if (p) {
      if (f.key === 'auth.oidc.issuer') return p.issuer || p.issuer_example;
      if (f.key === 'auth.oidc.username_claim') return p.username_claim;
      if (f.key === 'auth.oidc.groups_claim') return p.groups_claim || 'none';
      if (f.key === 'auth.oidc.scopes') return (p.scopes || []).filter((s) => s !== 'openid').join('\n');
      if (f.key === 'auth.oidc.button_label') return prov === 'other' ? 'Sign in with single sign-on' : 'Sign in with ' + p.label.replace(/^Microsoft /, '');
    }
    if (f.key === SAML_XML) return '<EntityDescriptor …>';
    if (/\.admin_groups$/.test(f.key)) return prov === 'google' ? 'soc-lead@example.com' : prov === 'entra' ? '6f1c4a3e-…' : 'soc-admins';
    if (/\.analyst_groups$/.test(f.key)) return prov === 'google' ? 'analyst@example.com' : 'soc-analysts';
    if (/\.viewer_groups$/.test(f.key)) return 'it-auditors';
    return f.placeholder || '';
  }

  function control(f, id) {
    const ro = readOnly(f);
    const describe = (n) => { n.setAttribute('aria-describedby', id + '-help ' + id + '-notes'); if (O.errors[f.key]) n.setAttribute('aria-invalid', 'true'); return n; };
    const value = current(f.key);
    if (f.type === 'secret') return secretControl(f, id);
    if (f.key === SCIM_TOKEN) return tokenControl(f, id);
    if (f.type === 'bool') {
      // create_users is on when it was never set.
      const on = value == null ? /\.create_users$/.test(f.key) : !!value;
      const box = describe(el('input', { type: 'checkbox', id, role: 'switch' }));
      box.checked = on;
      if (ro) box.disabled = true;
      box.addEventListener('change', () => { setDraft(f, box.checked); render(); });
      return el('label', { class: 'switch st-switch' }, box, el('span', { class: 'st-switch__state', 'aria-hidden': 'true' }, on ? 'On' : 'Off'));
    }
    if (f.type === 'choice') {
      const n = describe(el('select', { id, class: 'select select--block' }));
      const v = value == null ? '' : value;
      for (const c of f.choices || []) {
        const o = el('option', { value: c.value }, c.label);
        if (c.value === v || (v === '' && c.value === 'none' && /\.default_role$/.test(f.key))) o.selected = true;
        n.append(o);
      }
      if (ro) n.disabled = true;
      n.addEventListener('change', () => { setDraft(f, n.value); render(); });
      return n;
    }
    const ph = placeholder(f);
    if (f.key === SAML_XML) {
      // Pasted metadata, kept on one line: line breaks between XML tags
      // and inside the certificates mean nothing.
      const n = describe(el('textarea', { id, class: 'textarea mono', rows: '4', spellcheck: 'false', autocomplete: 'off', placeholder: ph }));
      n.value = value || '';
      if (ro) n.disabled = true;
      n.addEventListener('input', () => { setDraft(f, String(n.value).replace(/\s+/g, ' ').trim()); syncBar(); });
      return n;
    }
    if (f.type === 'list') {
      const n = describe(el('textarea', { id, class: 'textarea mono', rows: '3', spellcheck: 'false', autocomplete: 'off', placeholder: ph ? 'e.g. ' + ph.split('\n').join(', ') : '' }));
      n.value = (value || []).join('\n');
      if (ro) n.disabled = true;
      n.addEventListener('input', () => { setDraft(f, parse(f, n.value)); syncBar(); });
      return n;
    }
    const mono = f.type === 'url' || /claim|client_id|attribute/.test(f.key);
    const n = describe(el('input', { id, class: 'input' + (mono ? ' mono' : ''), type: 'text', autocomplete: 'off', spellcheck: 'false', autocapitalize: 'none',
      placeholder: ph ? (f.empty_means && f.key !== 'auth.oidc.issuer' ? ph : 'e.g. ' + ph) : '' }));
    if (f.type === 'url') n.inputMode = 'url';
    n.value = value == null ? '' : value;
    if (ro) n.disabled = true;
    n.addEventListener('input', () => { setDraft(f, parse(f, n.value)); syncBar(); });
    // Issuer and provider change what the test checks and the hints say.
    n.addEventListener('change', () => { if (f.key === 'auth.oidc.issuer' || f.key === 'auth.saml.metadata_url') syncTest(); });
    return n;
  }

  // secretControl shows a saved client secret as saved, with Replace and
  // Remove; it is never sent to the page.
  function secretControl(f, id) {
    const box = el('div', { class: 'st-secret', role: 'group', 'aria-labelledby': id + '-label', 'aria-describedby': id + '-help ' + id + '-notes' });
    const status = (text, ...kids) => el('div', { class: 'st-secret__saved' }, icon('key-round', 'icon--sm'), el('span', {}, text), ...kids);
    const d = O.drafts[f.key];
    if (readOnly(f)) {
      box.append(status(f.set ? 'Saved, hidden' : 'Not set'));
      return box;
    }
    if (d && d.clear) {
      box.append(el('div', { class: 'st-secret__saved is-removing' }, icon('trash-2', 'icon--sm'), el('span', {}, 'Removed when you save'),
        el('button', { type: 'button', class: 'link-btn st-secret__undo', onclick: () => { delete O.drafts[f.key]; render(); } }, 'Undo')));
      return box;
    }
    if (f.set && !O.replacing && !d) {
      const replace = el('button', { type: 'button', class: 'btn btn--secondary btn--sm st-secret__btn', id, 'aria-label': 'Replace the client secret' }, 'Replace');
      replace.addEventListener('click', () => { O.replacing = true; render(); const n = $(id); if (n) n.focus(); });
      const remove = el('button', { type: 'button', class: 'btn btn--ghost btn--sm st-secret__btn', 'aria-label': 'Remove the client secret' }, 'Remove');
      remove.addEventListener('click', () => { O.drafts[f.key] = { clear: true }; render(); });
      box.append(el('div', { class: 'st-secret__row' }, status('Saved encrypted, hidden'), replace, remove));
      if (f.sent_to) box.append(el('p', { class: 'st-source' }, icon('send', 'icon--xs'), el('span', {}, 'Only sent to ', el('span', { class: 'mono' }, f.sent_to))));
      return box;
    }
    const n = el('input', { id, class: 'input', type: 'password', autocomplete: 'new-password', spellcheck: 'false', placeholder: f.set ? 'Type the new one' : 'Not set' });
    n.setAttribute('aria-labelledby', id + '-label');
    n.value = d && 'value' in d ? d.value : '';
    n.addEventListener('input', () => { setDraft(f, n.value); syncBar(); });
    const kids = [n];
    if (f.set) kids.push(el('button', { type: 'button', class: 'btn btn--ghost btn--sm', onclick: () => { O.replacing = false; delete O.drafts[f.key]; render(); } }, 'Keep saved'));
    box.append(el('div', { class: 'st-secret__input' }, ...kids));
    return box;
  }

  // redirectRow is the address to register with the provider.
  function redirectRow() {
    return copyRow('sso-redirect', 'Redirect URI', O.view.redirect_uri,
      'Register this address with the identity provider as the sign-in redirect (callback) URI, exactly as it is. It comes from the web address on the Server tab.',
      'Copy the redirect URI', O.view.redirect_warning);
  }

  // copyRow is an address to give the identity provider, with Copy.
  function copyRow(id, label, value, helpText, copyLabel, warning) {
    const box = el('input', { id, class: 'input mono', type: 'text', readonly: '', value: value || '', 'aria-describedby': id + '-help' });
    box.addEventListener('focus', () => box.select());
    return el('div', { class: 'st-field sso-redirect', 'data-key': id },
      el('div', { class: 'st-field__text' }, el('label', { class: 'st-field__label', for: id }, label),
        el('p', { class: 'st-field__help', id: id + '-help' }, helpText)),
      el('div', { class: 'st-field__control' }, el('div', { class: 'sso-copy' }, box, copyButton(box, value, copyLabel)),
        warning ? el('p', { class: 'st-warn' }, icon('triangle-alert'), el('span', {}, warning)) : null));
  }

  function copyButton(box, value, label) {
    const copy = el('button', { type: 'button', class: 'btn btn--secondary btn--sm', 'aria-label': label }, icon('copy'), 'Copy');
    copy.addEventListener('click', async () => {
      try {
        await navigator.clipboard.writeText(value);
        toast('Copied.');
      } catch (_) {
        box.focus();
        box.select();
        toast('Press Ctrl+C (or ⌘C) to copy it.', null, { tone: 'info' });
      }
    });
    return copy;
  }

  // tokenControl shows whether a SCIM token is saved, makes a new one
  // (shown once, here), and removes it. Only the token's SHA-256 is saved.
  function tokenControl(f, id) {
    const box = el('div', { class: 'st-secret', role: 'group', 'aria-labelledby': id + '-label', 'aria-describedby': id + '-help ' + id + '-notes' });
    const status = (text, ...kids) => el('div', { class: 'st-secret__saved' }, icon('key-round', 'icon--sm'), el('span', {}, text), ...kids);
    const d = O.drafts[f.key];
    const saved = !!f.value;
    if (readOnly(f)) {
      box.append(status(saved ? 'Saved' : 'Not set'));
      return box;
    }
    if (d && d.clear) {
      box.append(el('div', { class: 'st-secret__saved is-removing' }, icon('trash-2', 'icon--sm'), el('span', {}, 'Removed when you save'),
        el('button', { type: 'button', class: 'link-btn st-secret__undo', onclick: () => { delete O.drafts[f.key]; render(); } }, 'Undo')));
      return box;
    }
    if (d && O.token) {
      const tok = el('input', { id, class: 'input mono', type: 'text', readonly: '', value: O.token, 'aria-label': 'The new SCIM token' });
      tok.addEventListener('focus', () => tok.select());
      box.append(el('div', { class: 'sso-copy' }, tok, copyButton(tok, O.token, 'Copy the new SCIM token')),
        el('p', { class: 'st-warn' }, icon('triangle-alert'), el('span', {}, 'Copy it into the identity provider now: it is shown only this once. Save to start using it' +
          (saved ? '; the old token stops working then.' : '.'))),
        el('button', { type: 'button', class: 'link-btn st-secret__undo', onclick: () => { O.token = ''; delete O.drafts[f.key]; render(); } }, 'Cancel'));
      return box;
    }
    const make = el('button', { type: 'button', class: 'btn btn--secondary btn--sm st-secret__btn', id }, icon('key-round'), saved ? 'Replace token' : 'Create token');
    make.addEventListener('click', async () => {
      const restore = busy(make, 'Creating…');
      try {
        const r = await api('api/auth/scim/token', {});
        O.token = r.token;
        O.drafts[f.key] = { value: r.sha256 };
        delete O.errors[f.key];
        render();
        const n = $(id);
        if (n) n.focus();
      } catch (e) {
        restore();
        toast(sentence(e.message), null, { tone: 'danger' });
      }
    });
    const kids = [status(saved ? 'Saved' : 'Not set'), make];
    if (saved) {
      kids.push(el('button', { type: 'button', class: 'btn btn--ghost btn--sm st-secret__btn', 'aria-label': 'Remove the SCIM token',
        onclick: () => { O.drafts[f.key] = { clear: true }; render(); } }, 'Remove'));
    }
    box.append(el('div', { class: 'st-secret__row' }, ...kids));
    return box;
  }

  // ---------- the test ----------
  // kind is oidc or saml; each has its own test and result.
  const TEST = {
    oidc: { path: 'api/auth/oidc/test', lead: 'Reads the provider’s discovery document and signing keys with the settings above, saved or not.' },
    saml: { path: 'api/auth/saml/test', lead: 'Reads the provider’s metadata and signing certificates with the settings above, saved or not.' },
  };
  const testId = (kind) => kind === 'saml' ? 'saml-test' : 'sso-test';

  function testBlock(kind) {
    const id = testId(kind);
    const btn = el('button', { type: 'button', class: 'btn btn--secondary', id }, icon('plug-zap'), 'Test');
    btn.addEventListener('click', () => runTest(kind));
    if (!editable() && !(kind === 'saml' ? O.view.saml_on : O.view.on)) btn.disabled = true;
    const out = el('div', { class: 'st-test__out', id: id + '-out', 'aria-live': 'polite' }, O.tests[kind] ? testResult(kind) : null);
    return el('div', { class: 'st-test' },
      el('div', { class: 'st-test__row' }, btn, el('p', { class: 'st-test__lead' }, TEST[kind].lead)), out);
  }

  async function runTest(kind) {
    const btn = $(testId(kind));
    const out = $(testId(kind) + '-out');
    const body = payload();
    const snap = JSON.stringify(body);
    const restore = busy(btn, 'Testing…');
    fill(out, el('p', { class: 'st-test__busy' }, 'Asking the identity provider…'));
    let r;
    try {
      r = await api(TEST[kind].path, body);
    } catch (e) {
      r = e.status === 400 && e.fields ? { ok: false, fields: e.fields, message: e.message } : { ok: false, message: sentence(e.message), steps: [] };
    }
    restore();
    O.tests[kind] = r;
    O.snaps[kind] = snap;
    if (r.fields) for (const [k, m] of Object.entries(r.fields)) O.errors[k] = m;
    if (r.fields) render(); else fill(out, testResult(kind));
  }

  function testResult(kind) {
    const r = O.tests[kind];
    const stale = O.snaps[kind] !== JSON.stringify(payload());
    if (r.fields) {
      return dxAlert('warning', 'Fix the settings marked above, then test again.', '');
    }
    const steps = (r.steps || []).map((s) => el('li', { class: 'sso-step', 'data-ok': s.ok ? 'true' : 'false' },
      icon(s.ok ? 'circle-check' : 'circle-x', 'icon--sm'), el('div', {}, el('b', {}, s.name), el('span', {}, ' ' + s.detail))));
    return el('div', { class: 'sso-result' + (stale ? ' is-stale' : '') },
      dxAlert(r.ok ? 'success' : 'danger', r.ok ? 'The identity provider is ready' : 'The test failed', sentence(r.message)),
      steps.length ? el('ul', { class: 'sso-steps' }, ...steps) : null,
      stale ? el('p', { class: 'st-stale' }, icon('info', 'icon--sm'), 'The settings changed since this test. Test again to check them.') : null);
  }

  function syncTest() {
    for (const kind of Object.keys(TEST)) {
      const out = $(testId(kind) + '-out');
      if (out && O.tests[kind]) fill(out, testResult(kind));
    }
  }

  // ---------- saving ----------
  function saveBar() {
    const n = dirty();
    const save = el('button', { type: 'button', class: 'btn btn--primary btn--sm', id: 'sso-save' }, icon('check'), 'Save');
    save.addEventListener('click', saveAll);
    const discard = el('button', { type: 'button', class: 'btn btn--ghost btn--sm', id: 'sso-discard' }, 'Discard');
    discard.addEventListener('click', () => { O.drafts = {}; O.errors = {}; O.general = []; O.replacing = false; O.token = ''; render(); });
    return el('div', { class: 'st-savebar', id: 'sso-savebar', hidden: n ? null : '' },
      el('div', { class: 'st-savebar__row' },
        el('span', { class: 'st-savebar__text', id: 'sso-savebar-text' }, el('span', { class: 'st-savebar__dot', 'aria-hidden': 'true' }), n === 1 ? '1 unsaved change' : n + ' unsaved changes'),
        el('span', { class: 'sso-grow' }), discard, save));
  }

  function syncBar() {
    const bar = $('sso-savebar');
    if (!bar) return;
    const n = dirty();
    bar.hidden = !n;
    const text = $('sso-savebar-text');
    if (text) fill(text, el('span', { class: 'st-savebar__dot', 'aria-hidden': 'true' }), n === 1 ? '1 unsaved change' : n + ' unsaved changes');
    syncTest();
  }

  async function saveAll() {
    if (O.saving || !dirty()) return;
    const turnsOn = ['auth.oidc.enabled', 'auth.saml.enabled'].some((k) => O.drafts[k] && O.drafts[k].value === true);
    O.saving = true;
    const btn = $('sso-save');
    const restore = busy(btn, 'Saving…');
    try {
      const body = payload();
      if (O.view.shared) {
        // Each setting as this page read it: one changed since by someone
        // else is refused (412) rather than overwritten.
        body.if_version = {};
        for (const k of Object.keys(O.drafts)) if (field(k) && field(k).version != null) body.if_version[k] = field(k).version;
      }
      await api('api/settings', body, 'PUT');
      O.drafts = {};
      O.errors = {};
      O.general = [];
      O.replacing = false;
      O.saving = false;
      O.token = '';
      restore();
      await load();
      toast(turnsOn ? 'Saved. Single sign-on is on: try it in a private window before you sign out.' : 'Saved.');
    } catch (e) {
      O.saving = false;
      restore();
      O.errors = e.fields || {};
      // Problems with settings not on this page (signalith.yaml).
      O.general = Object.keys(O.errors).length ? [] : (e.problems && e.problems.length ? e.problems : [e.message]);
      if (e.status === 412) O.general = ['Someone else changed these settings since you opened this page. Reload it to see their changes, then make yours again.'];
      render();
      const first = Object.keys(O.errors)[0];
      if (first && $(idOf(first))) $(idOf(first)).focus();
    }
  }
}());
