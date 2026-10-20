// Copyright 2026 The Signalith authors
// SPDX-License-Identifier: Apache-2.0
// Passkeys (WebAuthn) in the browser, for the sign-in page and the app.
// The server sends its options as JSON, with binary values in base64url;
// navigator.credentials wants them as bytes, and its answer goes back as
// JSON the same way.
'use strict';

(function () {
  function decode(s) {
    const b = atob(String(s).replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((String(s).length + 3) % 4));
    const out = new Uint8Array(b.length);
    for (let i = 0; i < b.length; i++) out[i] = b.charCodeAt(i);
    return out.buffer;
  }
  function encode(buf) {
    const bytes = new Uint8Array(buf);
    let s = '';
    for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }
  const withIDs = (list) => (list || []).map((c) => ({ ...c, id: decode(c.id) }));

  // supported reports whether this browser can use passkeys here: they
  // need HTTPS (or localhost) and a host name, not an IP address.
  function supported() {
    return !!(window.PublicKeyCredential && navigator.credentials && window.isSecureContext
      && !/^[\d.]+$|^\[|:/.test(location.hostname));
  }

  function answer(cred) {
    const r = cred.response;
    const out = {
      id: cred.id, rawId: encode(cred.rawId), type: cred.type,
      authenticatorAttachment: cred.authenticatorAttachment || undefined,
      clientExtensionResults: cred.getClientExtensionResults ? cred.getClientExtensionResults() : {},
      response: { clientDataJSON: encode(r.clientDataJSON) },
    };
    if (r.attestationObject) {
      out.response.attestationObject = encode(r.attestationObject);
      if (r.getTransports) out.response.transports = r.getTransports();
    } else {
      out.response.authenticatorData = encode(r.authenticatorData);
      out.response.signature = encode(r.signature);
      if (r.userHandle) out.response.userHandle = encode(r.userHandle);
    }
    return out;
  }

  // create makes a passkey from the server's options ({ publicKey, token })
  // and returns the answer to send back.
  async function create(opts) {
    const pk = opts.publicKey;
    const cred = await navigator.credentials.create({
      publicKey: {
        ...pk,
        challenge: decode(pk.challenge),
        user: { ...pk.user, id: decode(pk.user.id) },
        excludeCredentials: withIDs(pk.excludeCredentials),
      },
    });
    return { token: opts.token, credential: answer(cred) };
  }

  // get asks for a passkey with the server's options ({ publicKey, token })
  // and returns the answer to send back.
  async function get(opts, signal) {
    const pk = opts.publicKey;
    const cred = await navigator.credentials.get({
      publicKey: { ...pk, challenge: decode(pk.challenge), allowCredentials: withIDs(pk.allowCredentials) },
      signal,
    });
    return { token: opts.token, credential: answer(cred) };
  }

  // problem says, in words, why the browser made or used no passkey; ''
  // when the user just closed its window.
  function problem(err, making) {
    switch (err && err.name) {
      case 'NotAllowedError': case 'AbortError': return '';
      case 'InvalidStateError': return making ? 'This device already has a passkey for your account.' : 'That passkey can’t be used here.';
      case 'SecurityError': return 'This browser allows passkeys only when Signalith is opened by its name over HTTPS.';
      case 'NotSupportedError': return 'This device can’t make a passkey that Signalith accepts.';
    }
    return (err && err.message) || 'The browser couldn’t use a passkey.';
  }

  // guessName suggests a name for a new passkey: the kind of device.
  function guessName() {
    const ua = navigator.userAgent || '';
    if (/iPhone/.test(ua)) return 'iPhone';
    if (/iPad/.test(ua)) return 'iPad';
    if (/Android/.test(ua)) return 'Android phone';
    if (/Macintosh|Mac OS X/.test(ua)) return 'Mac';
    if (/Windows/.test(ua)) return 'Windows PC';
    if (/CrOS/.test(ua)) return 'Chromebook';
    if (/Linux/.test(ua)) return 'Linux computer';
    return 'Passkey';
  }

  window.SignalithPasskey = { supported, create, get, problem, guessName };
}());
