/**
 * VaultSync client — end-to-end encrypted sync for the single-file journal apps.
 *
 * Everything secret is derived on the device from one sync code. The server stores
 * ciphertext and a version number and nothing else; it cannot read a journal even if
 * the database leaks, because it never receives the code or any key derived from it.
 *
 * The trade that buys: lose the code and the data is unrecoverable. There is no reset.
 *
 * Merge is per-entry, not last-write-wins on the whole journal, so writing on your phone
 * and your Mac while offline doesn't cost you one of the two.
 *
 * Usage:
 *   VaultSync.init({ appId: 'rem', adapter });
 *   adapter = { exportItems() -> {id: {u, d, x}}, importItems(items) }
 *      u = updatedAt ms, d = deletedAt ms (0 if live), x = the entry itself
 */
(function (global) {
  'use strict';

  var ENDPOINT = 'https://vaultsync.defy-gravity-24-sda.workers.dev';
  var ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ'; // Crockford base32: no I, L, O, U
  var CODE_BYTES = 15;                               // 120 bits -> exactly 24 chars
  var DEBOUNCE_MS = 4000;

  var state = { appId: null, adapter: null, keys: null, status: 'idle', lastSync: 0, lastError: null };
  var listeners = [];
  var timer = null;
  var running = null;

  /* ---------------- code encoding ---------------- */

  function generateCode() {
    var raw = new Uint8Array(CODE_BYTES);
    crypto.getRandomValues(raw);
    return format(encode(raw));
  }

  function encode(bytes) {
    var bits = 0, value = 0, out = '';
    for (var i = 0; i < bytes.length; i++) {
      value = (value << 8) | bytes[i];
      bits += 8;
      while (bits >= 5) { out += ALPHABET[(value >>> (bits - 5)) & 31]; bits -= 5; }
    }
    if (bits > 0) out += ALPHABET[(value << (5 - bits)) & 31];
    return out;
  }

  function decode(text) {
    var clean = normalize(text);
    var bits = 0, value = 0, out = [];
    for (var i = 0; i < clean.length; i++) {
      var idx = ALPHABET.indexOf(clean[i]);
      if (idx < 0) throw new Error('That code has a character that is not part of a sync code.');
      value = (value << 5) | idx;
      bits += 5;
      if (bits >= 8) { out.push((value >>> (bits - 8)) & 255); bits -= 8; }
    }
    return new Uint8Array(out);
  }

  /** Uppercase, drop separators, and fold the characters people reliably mistype. */
  function normalize(text) {
    return String(text).toUpperCase().replace(/[\s-]/g, '')
      .replace(/[IL]/g, '1').replace(/O/g, '0').replace(/U/g, 'V');
  }

  function format(code) {
    return (code.match(/.{1,4}/g) || []).join('-');
  }

  function isValidCode(text) {
    try {
      var clean = normalize(text);
      if (clean.length !== 24) return false;
      decode(clean);
      return true;
    } catch (e) { return false; }
  }

  /* ---------------- key derivation ---------------- */

  function bytesToHex(buf) {
    return Array.prototype.map.call(new Uint8Array(buf), function (b) {
      return b.toString(16).padStart(2, '0');
    }).join('');
  }

  function bytesToB64(buf) {
    var bin = '', arr = new Uint8Array(buf);
    for (var i = 0; i < arr.length; i++) bin += String.fromCharCode(arr[i]);
    return btoa(bin);
  }

  function b64ToBytes(text) {
    var bin = atob(text), arr = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
    return arr;
  }

  async function deriveKeys(code, appId) {
    var raw = decode(code);
    var base = await crypto.subtle.importKey('raw', raw, 'HKDF', false, ['deriveBits']);
    async function bits(label) {
      return crypto.subtle.deriveBits({
        name: 'HKDF', hash: 'SHA-256',
        salt: new Uint8Array(0),
        info: new TextEncoder().encode('vaultsync|' + label + '|' + appId),
      }, base, 256);
    }
    var idBits = await bits('id');
    var writeBits = await bits('write');
    var encBits = await bits('enc');
    return {
      syncId: bytesToHex(idBits),
      writeToken: bytesToB64(writeBits).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''),
      encKey: await crypto.subtle.importKey('raw', encBits, 'AES-GCM', false, ['encrypt', 'decrypt']),
    };
  }

  async function encrypt(keys, plainObject) {
    var iv = crypto.getRandomValues(new Uint8Array(12));
    var data = new TextEncoder().encode(JSON.stringify(plainObject));
    var ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv }, keys.encKey, data);
    return { blob: bytesToB64(ct), iv: bytesToB64(iv) };
  }

  async function decrypt(keys, blob, iv) {
    var pt = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: b64ToBytes(iv) }, keys.encKey, b64ToBytes(blob));
    return JSON.parse(new TextDecoder().decode(pt));
  }

  /* ---------------- merge ---------------- */

  function stampOf(item) { return Math.max((item && item.u) || 0, (item && item.d) || 0); }

  /** Union by id; for ids on both sides the more recently touched one wins. */
  function mergeItems(mine, theirs) {
    var out = {}, id;
    for (id in mine) if (Object.prototype.hasOwnProperty.call(mine, id)) out[id] = mine[id];
    for (id in theirs) {
      if (!Object.prototype.hasOwnProperty.call(theirs, id)) continue;
      if (!out[id] || stampOf(theirs[id]) > stampOf(out[id])) out[id] = theirs[id];
    }
    return out;
  }

  /* ---------------- storage of the code ---------------- */

  function codeKey() { return 'vaultsync.code.' + state.appId; }
  function metaKey() { return 'vaultsync.meta.' + state.appId; }

  function getCode() { try { return localStorage.getItem(codeKey()); } catch (e) { return null; } }
  function isLinked() { return !!getCode(); }

  function readMeta() {
    try { return JSON.parse(localStorage.getItem(metaKey())) || {}; } catch (e) { return {}; }
  }
  function writeMeta(patch) {
    var meta = Object.assign(readMeta(), patch);
    try { localStorage.setItem(metaKey(), JSON.stringify(meta)); } catch (e) {}
    return meta;
  }

  /* ---------------- status ---------------- */

  function setStatus(status, error) {
    state.status = status;
    state.lastError = error || null;
    listeners.forEach(function (fn) { try { fn(getStatus()); } catch (e) {} });
  }

  function getStatus() {
    return {
      linked: isLinked(), status: state.status,
      lastSync: readMeta().lastSync || 0, error: state.lastError,
    };
  }

  /* ---------------- network ---------------- */

  async function api(path, options) {
    var res = await fetch(ENDPOINT + path, options);
    return res;
  }

  /* ---------------- the sync itself ---------------- */

  async function syncNow() {
    if (running) return running;          // collapse overlapping calls
    running = doSync().finally(function () { running = null; });
    return running;
  }

  async function doSync() {
    if (!isLinked()) return { status: 'not_linked' };
    if (!state.adapter) return { status: 'no_adapter' };

    setStatus('syncing');
    try {
      if (!state.keys) state.keys = await deriveKeys(getCode(), state.appId);
      var keys = state.keys;

      var remote = {}, version = 0;
      var res = await api('/v1/vault/' + keys.syncId, { method: 'GET' });
      if (res.status === 200) {
        var body = await res.json();
        version = body.version;
        try {
          var env = await decrypt(keys, body.blob, body.iv);
          remote = (env && env.items) || {};
        } catch (e) {
          // Ciphertext we cannot open means a different code owns this vault.
          setStatus('error', 'This code does not match the data on the server.');
          return { status: 'bad_key' };
        }
      } else if (res.status !== 404) {
        throw new Error('Server said ' + res.status);
      }

      var merged = mergeItems(state.adapter.exportItems(), remote);
      state.adapter.importItems(merged);

      if (JSON.stringify(merged) === JSON.stringify(remote)) {
        writeMeta({ lastSync: Date.now() });
        setStatus('idle');
        return { status: 'up_to_date' };
      }

      for (var attempt = 0; attempt < 3; attempt++) {
        var payload = await encrypt(keys, { v: 1, app: state.appId, items: merged });
        var put = await api('/v1/vault/' + keys.syncId, {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + keys.writeToken },
          body: JSON.stringify({ blob: payload.blob, iv: payload.iv, baseVersion: version }),
        });

        if (put.status === 200) {
          writeMeta({ lastSync: Date.now() });
          setStatus('idle');
          return { status: 'pushed' };
        }

        if (put.status === 409) {
          // Another device wrote first. Fold their copy in and try again.
          var conflict = await put.json();
          version = conflict.version;
          if (conflict.blob) {
            try {
              var theirs = await decrypt(keys, conflict.blob, conflict.iv);
              merged = mergeItems(merged, (theirs && theirs.items) || {});
              state.adapter.importItems(merged);
            } catch (e) { /* unreadable: our merge still wins the retry */ }
          }
          continue;
        }

        if (put.status === 403) {
          setStatus('error', 'Another journal already owns this code.');
          return { status: 'forbidden' };
        }
        if (put.status === 413) {
          setStatus('error', 'This journal is too big to sync as one piece.');
          return { status: 'too_large' };
        }
        throw new Error('Server said ' + put.status);
      }

      setStatus('error', 'Kept colliding with another device. Try again.');
      return { status: 'conflict' };
    } catch (e) {
      var offline = (typeof navigator !== 'undefined' && navigator.onLine === false);
      setStatus(offline ? 'offline' : 'error', offline ? null : (e && e.message) || String(e));
      return { status: offline ? 'offline' : 'error' };
    }
  }

  function schedule() {
    if (!isLinked()) return;
    clearTimeout(timer);
    timer = setTimeout(function () { syncNow(); }, DEBOUNCE_MS);
  }

  /* ---------------- linking ---------------- */

  async function link(code) {
    if (!isValidCode(code)) throw new Error('That does not look like a sync code.');
    var normalized = format(normalize(code));
    localStorage.setItem(codeKey(), normalized);
    state.keys = null;
    var result = await syncNow();
    if (result.status === 'bad_key' || result.status === 'forbidden') {
      localStorage.removeItem(codeKey());
      state.keys = null;
      throw new Error('That code belongs to a different journal.');
    }
    return result;
  }

  /** Stop syncing here. The journal stays on this device and on the server. */
  function unlink() {
    try { localStorage.removeItem(codeKey()); localStorage.removeItem(metaKey()); } catch (e) {}
    state.keys = null;
    setStatus('idle');
  }

  /** Stop syncing AND erase the server copy. Other linked devices keep their local data. */
  async function forget() {
    if (!isLinked()) return;
    try {
      if (!state.keys) state.keys = await deriveKeys(getCode(), state.appId);
      await api('/v1/vault/' + state.keys.syncId, {
        method: 'DELETE',
        headers: { 'Authorization': 'Bearer ' + state.keys.writeToken },
      });
    } catch (e) { /* unlink locally regardless */ }
    unlink();
  }

  function init(options) {
    state.appId = options.appId;
    state.adapter = options.adapter;
    if (options.endpoint) ENDPOINT = options.endpoint;

    if (isLinked()) {
      syncNow();
      global.addEventListener('online', function () { syncNow(); });
      document.addEventListener('visibilitychange', function () {
        if (!document.hidden) syncNow();
      });
    }
  }

  function supported() {
    return typeof crypto !== 'undefined' && !!crypto.subtle && !!global.isSecureContext;
  }

  global.VaultSync = {
    init: init, supported: supported,
    generateCode: generateCode, isValidCode: isValidCode, format: format,
    isLinked: isLinked, getCode: getCode,
    link: link, unlink: unlink, forget: forget,
    syncNow: syncNow, schedule: schedule,
    getStatus: getStatus,
    onStatus: function (fn) { listeners.push(fn); },
    _internals: { mergeItems: mergeItems, encode: encode, decode: decode, normalize: normalize },
  };
})(window);
