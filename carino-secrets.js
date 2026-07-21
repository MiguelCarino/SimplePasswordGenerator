/* carino-secrets.js — Carino Systems shared secret-splitting engine
 *
 * Shamir's Secret Sharing over GF(256). Split a secret into n shares such that
 * any k of them rebuild it and any k-1 reveal nothing whatsoever — not the
 * secret, not its length, not a single character. That is information-theoretic,
 * so shares stay safe against an attacker with unlimited computing power.
 *
 * Vendored deliberately: every site that handles secrets carries its own copy
 * rather than fetching this from a shared origin, so no single compromise can
 * reach across the fleet and each page stays provably self-contained.
 *
 * Keep this file byte-identical across repos — shares written by one Carino
 * site must always be recoverable on another.
 *
 * Copyright (c) 2026 Miguel Carino. See LICENSE.
 */
(function (global) {
  'use strict';

  /* ─── GF(256), poly x^8+x^4+x^3+x^2+1 ──────────────────────────────── */
  const EXP = new Uint8Array(512), LOG = new Uint8Array(256);
  (function () {
    let x = 1;
    for (let i = 0; i < 255; i++) { EXP[i] = x; LOG[x] = i; x <<= 1; if (x & 0x100) x ^= 0x11d; }
    for (let i = 255; i < 512; i++) EXP[i] = EXP[i - 255];
  })();

  const mul = (a, b) => (a === 0 || b === 0) ? 0 : EXP[LOG[a] + LOG[b]];
  const div = (a, b) => (a === 0) ? 0 : EXP[LOG[a] + 255 - LOG[b]];

  /* Each byte gets its own random polynomial with the byte as constant term. */
  function splitBytes(bytes, n, k) {
    const shares = [];
    for (let i = 1; i <= n; i++) shares.push({ x: i, y: new Uint8Array(bytes.length) });
    const coeffs = new Uint8Array(k - 1);
    for (let b = 0; b < bytes.length; b++) {
      crypto.getRandomValues(coeffs);
      for (const s of shares) {
        let acc = 0;                                  // Horner, highest term first
        for (let j = k - 2; j >= 0; j--) acc = mul(acc, s.x) ^ coeffs[j];
        s.y[b] = mul(acc, s.x) ^ bytes[b];
      }
    }
    return shares;
  }

  /* Lagrange interpolation evaluated at x=0. */
  function combineBytes(shares, len) {
    const out = new Uint8Array(len);
    for (let b = 0; b < len; b++) {
      let acc = 0;
      for (let i = 0; i < shares.length; i++) {
        let num = 1, den = 1;
        for (let j = 0; j < shares.length; j++) {
          if (i === j) continue;
          num = mul(num, shares[j].x);
          den = mul(den, shares[i].x ^ shares[j].x);
        }
        acc ^= mul(shares[i].y[b], div(num, den));
      }
      out[b] = acc;
    }
    return out;
  }

  /* ─── Crockford base32 ─────────────────────────────────────────────────
     No I, L, O or U, so a share survives being read aloud or copied by hand;
     decoding folds the look-alikes back in.                                */
  const B32 = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

  function b32enc(bytes) {
    let bits = 0, val = 0, out = '';
    for (const b of bytes) {
      val = (val << 8) | b; bits += 8;
      while (bits >= 5) { out += B32[(val >>> (bits - 5)) & 31]; bits -= 5; }
    }
    if (bits > 0) out += B32[(val << (5 - bits)) & 31];
    return out;
  }

  function b32dec(str) {
    const s = str.toUpperCase().replace(/[^0-9A-Z]/g, '')
                 .replace(/O/g, '0').replace(/[IL]/g, '1');
    let bits = 0, val = 0; const out = [];
    for (const c of s) {
      const idx = B32.indexOf(c);
      if (idx < 0) throw new Error(`one of the parts contains an invalid character`);
      val = (val << 5) | idx; bits += 5;
      if (bits >= 8) { out.push((val >>> (bits - 8)) & 255); bits -= 8; }
    }
    return new Uint8Array(out);
  }

  function crc16(bytes) {
    let crc = 0xffff;
    for (const b of bytes) {
      crc ^= b << 8;
      for (let i = 0; i < 8; i++)
        crc = (crc & 0x8000) ? ((crc << 1) ^ 0x1021) & 0xffff : (crc << 1) & 0xffff;
    }
    return crc;
  }

  /* ─── Wire format: CS1-<base32 of [ver, k, x, ...y, crc16]> ──────────── */
  const VERSION = 1, TAG_LEN = 3, MAX_BYTES = 512, MAX_SHARES = 10;

  function encodeShare(k, x, y) {
    const p = new Uint8Array(3 + y.length);
    p[0] = VERSION; p[1] = k; p[2] = x; p.set(y, 3);
    const c = crc16(p);
    const full = new Uint8Array(p.length + 2);
    full.set(p); full[p.length] = c >> 8; full[p.length + 1] = c & 0xff;
    return 'CS1-' + (b32enc(full).match(/.{1,5}/g) || []).join('-');
  }

  function parseShare(str) {
    const t = String(str).trim().toUpperCase();
    if (!/^CS[1IL]-/.test(t)) throw new Error('every part must start with CS1-');
    const full = b32dec(t.slice(4));                 // tolerates a hand-copied "CSI-"
    if (full.length < 6) throw new Error('one of the parts is incomplete');
    const p = full.slice(0, -2);
    const c = (full[full.length - 2] << 8) | full[full.length - 1];
    if (crc16(p) !== c) throw new Error('one of the parts was mistyped — check it character by character');
    if (p[0] !== VERSION) throw new Error(`one of the parts uses an unknown format (v${p[0]})`);
    if (p[2] === 0) throw new Error('one of the parts is damaged');
    return { k: p[1], x: p[2], y: p.slice(3) };
  }

  const tagOf = async bytes =>
    new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)).slice(0, TAG_LEN);

  /* ─── Public API ───────────────────────────────────────────────────────
     Throws Error with a message written for a reader, not a developer, so
     every Carino site reports the same wording for the same failure.       */

  async function split(secret, n, k) {
    if (!secret) throw new Error('there is nothing to split yet');
    n = Number(n); k = Number(k);
    if (!(n >= 2 && n <= MAX_SHARES)) throw new Error(`pick between 2 and ${MAX_SHARES} parts`);
    if (!(k >= 2 && k <= n)) throw new Error('the number needed cannot exceed the number of parts');

    const body = new TextEncoder().encode(secret);
    if (body.length > MAX_BYTES)
      throw new Error(`keep it under ${MAX_BYTES} bytes — this is built for keys and passwords, not documents`);

    // The checksum rides inside the split payload, so it leaks nothing on its own.
    const blob = new Uint8Array(body.length + TAG_LEN);
    blob.set(body); blob.set(await tagOf(body), body.length);

    return splitBytes(blob, n, k).map(s => ({ index: s.x, total: n, needed: k,
                                              text: encodeShare(k, s.x, s.y) }));
  }

  async function recover(input) {
    // Accepts a blob of pasted text, or an array of either bare shares or whole
    // wrapped messages — so flatten to lines first, then keep only the shares.
    const lines = (Array.isArray(input) ? input.join('\n') : String(input))
      .split('\n').map(l => l.trim()).filter(Boolean)
      .filter(l => /^CS[1IL]-/i.test(l));              // ignore surrounding instructions
    if (!lines.length) throw new Error('paste the parts first — each one starts with CS1-');

    const parsed = lines.map(parseShare);
    const len = parsed[0].y.length;
    if (parsed.some(s => s.y.length !== len))
      throw new Error('these parts are different sizes — they come from different secrets');

    const seen = new Set();
    for (const s of parsed) {
      if (seen.has(s.x)) throw new Error(`part ${s.x} was pasted twice — each part must be different`);
      seen.add(s.x);
    }

    const k = parsed[0].k;
    if (parsed.length < k)
      throw new Error(`this needs ${k} parts and you have ${parsed.length} — the missing ones cannot be guessed`);

    const blob = combineBytes(parsed.slice(0, k), len);
    const body = blob.slice(0, -TAG_LEN), tag = blob.slice(-TAG_LEN);
    const want = await tagOf(body);
    if (!tag.every((b, i) => b === want[i]))
      throw new Error('these parts do not belong together — each is well-formed, but they are from different secrets');

    return { secret: new TextDecoder().decode(body), needed: k, used: parsed.length };
  }

  /* A bare CS1- string tells a recipient nothing. Wrap it so the message can
     be forwarded as-is and still make sense to someone who has never seen it. */
  function message(share, url) {
    return `Part ${share.index} of ${share.total} — you need ` +
           (share.needed === share.total ? 'all ' + share.total : `${share.needed} of the ${share.total}`) +
           ` parts, sent separately.\n${share.text}\nOpen them together at: ${url}`;
  }

  global.CarinoSecrets = { split, recover, message, parseShare,
                           MAX_SHARES, MAX_BYTES, VERSION };
})(window);
