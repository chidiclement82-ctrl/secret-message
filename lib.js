/* Shared code for the send page and the inbox: encoding, encryption and the
 * database calls. Everything is done with the browser's Web Crypto API.
 *
 * How a message is protected
 * --------------------------
 * The owner has an ECDH P-256 key pair. For each message the sender's browser
 * makes a fresh key pair, combines it with the owner's public key (ECDH), and
 * turns the result into an AES-256-GCM key with HKDF. Only the owner's private
 * key can recreate that AES key. The database stores:
 *
 *   blob = base64url( 0x01 | sender public key (65) | iv (12) | ciphertext )
 *
 * The owner's private key is kept in the database too, but only encrypted
 * ("wrapped") with a key made from the owner's passphrase by PBKDF2. The same
 * PBKDF2 run also gives an access token; the database stores just its SHA-256
 * and only hands out messages to someone who knows the token.
 */
(function () {
  "use strict";

  const cfg = window.SM_CONFIG;
  const enc = new TextEncoder();
  const dec = new TextDecoder();
  const subtle = crypto.subtle;

  const PBKDF2_ROUNDS = 600000;
  const VERSION = 1;
  const HKDF_INFO = enc.encode("secret-message v1");
  const WRAP_AAD = enc.encode("secret-message key v1");
  const PAD_TO = 256; // hide exact message length
  const MAX_BLOB = 16000; // the database refuses anything longer

  // ---- encoding ----------------------------------------------------------
  function toB64(bytes) {
    let s = "";
    for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }
  function fromB64(str) {
    if (typeof str !== "string" || !/^[A-Za-z0-9_-]*$/.test(str)) throw new Error("bad encoding");
    const s = atob(str.replace(/-/g, "+").replace(/_/g, "/"));
    const out = new Uint8Array(s.length);
    for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
    return out;
  }
  const toHex = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
  function concat(...parts) {
    const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
    let o = 0;
    for (const p of parts) { out.set(p, o); o += p.length; }
    return out;
  }
  const random = (n) => crypto.getRandomValues(new Uint8Array(n));

  // ---- owner keys --------------------------------------------------------
  const ECDH = { name: "ECDH", namedCurve: "P-256" };
  const importPublic = (b64) => subtle.importKey("raw", fromB64(b64), ECDH, true, []);

  // One slow PBKDF2 run gives both the access token and the key-wrapping key.
  async function fromPassphrase(passphrase, saltB64) {
    const base = await subtle.importKey("raw", enc.encode(passphrase.normalize("NFC")), "PBKDF2", false, ["deriveBits"]);
    const bits = new Uint8Array(await subtle.deriveBits(
      { name: "PBKDF2", hash: "SHA-256", salt: fromB64(saltB64), iterations: PBKDF2_ROUNDS }, base, 512));
    const token = bits.slice(0, 32);
    const wrapKey = await subtle.importKey("raw", bits.slice(32), "AES-GCM", false, ["encrypt", "decrypt"]);
    const authHash = toHex(new Uint8Array(await subtle.digest("SHA-256", token)));
    return { token: toHex(token), authHash, wrapKey };
  }

  async function wrapPrivateKey(privateKey, wrapKey) {
    const pkcs8 = new Uint8Array(await subtle.exportKey("pkcs8", privateKey));
    const iv = random(12);
    const ct = await subtle.encrypt({ name: "AES-GCM", iv, additionalData: WRAP_AAD }, wrapKey, pkcs8);
    return toB64(concat(iv, new Uint8Array(ct)));
  }
  async function unwrapPrivateKey(wrappedB64, wrapKey) {
    const all = fromB64(wrappedB64);
    const pkcs8 = await subtle.decrypt({ name: "AES-GCM", iv: all.slice(0, 12), additionalData: WRAP_AAD }, wrapKey, all.slice(12));
    // Extractable so the key can be re-wrapped when the passphrase changes.
    return subtle.importKey("pkcs8", pkcs8, ECDH, true, ["deriveBits"]);
  }

  // Everything the database needs for a new inbox (or a new passphrase).
  async function newCredentials(passphrase, privateKey) {
    const salt = toB64(random(16));
    const { authHash, wrapKey, token } = await fromPassphrase(passphrase, salt);
    return { salt, auth_hash: authHash, wrapped_key: await wrapPrivateKey(privateKey, wrapKey), token };
  }
  async function newInbox(passphrase) {
    const pair = await subtle.generateKey(ECDH, true, ["deriveBits"]);
    const publicKey = toB64(new Uint8Array(await subtle.exportKey("raw", pair.publicKey)));
    return { public_key: publicKey, ...(await newCredentials(passphrase, pair.privateKey)) };
  }

  // A short fingerprint of a public key, to compare by eye.
  async function fingerprint(publicKeyB64) {
    const h = toHex(new Uint8Array(await subtle.digest("SHA-256", fromB64(publicKeyB64)))).slice(0, 20).toUpperCase();
    return h.match(/.{4}/g).join(" ");
  }

  // ---- messages ----------------------------------------------------------
  async function messageKey(privateKey, publicKey, ephPubRaw, ownerPubRaw) {
    const shared = await subtle.deriveBits({ name: "ECDH", public: publicKey }, privateKey, 256);
    const hk = await subtle.importKey("raw", shared, "HKDF", false, ["deriveKey"]);
    return subtle.deriveKey(
      { name: "HKDF", hash: "SHA-256", salt: concat(ephPubRaw, ownerPubRaw), info: HKDF_INFO },
      hk, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
  }

  // Encrypt { text, from } to the owner's public key. Returns the blob, or
  // throws Error("too long").
  async function sealMessage(ownerPubB64, text, from) {
    const ownerPub = await importPublic(ownerPubB64);
    const ownerPubRaw = fromB64(ownerPubB64);
    const eph = await subtle.generateKey(ECDH, true, ["deriveBits"]);
    const ephPubRaw = new Uint8Array(await subtle.exportKey("raw", eph.publicKey));
    const key = await messageKey(eph.privateKey, ownerPub, ephPubRaw, ownerPubRaw);

    let body = enc.encode(JSON.stringify({ m: text, f: from || "" }));
    // Pad with spaces (valid trailing JSON whitespace) to a multiple of PAD_TO.
    const padded = new Uint8Array(Math.ceil((body.length + 1) / PAD_TO) * PAD_TO).fill(0x20);
    padded.set(body);
    body = padded;

    const iv = random(12);
    const ct = new Uint8Array(await subtle.encrypt({ name: "AES-GCM", iv, additionalData: ownerPubRaw }, key, body));
    const blob = toB64(concat(new Uint8Array([VERSION]), ephPubRaw, iv, ct));
    if (blob.length > MAX_BLOB) throw new Error("too long");
    return blob;
  }

  async function openMessage(privateKey, ownerPubB64, blob) {
    const all = fromB64(blob);
    if (all[0] !== VERSION) throw new Error("unknown version");
    const ephPubRaw = all.slice(1, 66);
    const iv = all.slice(66, 78);
    const ownerPubRaw = fromB64(ownerPubB64);
    const ephPub = await subtle.importKey("raw", ephPubRaw, ECDH, false, []);
    const key = await messageKey(privateKey, ephPub, ephPubRaw, ownerPubRaw);
    const pt = await subtle.decrypt({ name: "AES-GCM", iv, additionalData: ownerPubRaw }, key, all.slice(78));
    const data = JSON.parse(dec.decode(pt));
    return { text: String(data.m || ""), from: String(data.f || "") };
  }

  // ---- database ----------------------------------------------------------
  class ApiError extends Error {
    constructor(code, message) { super(message); this.code = code; }
  }
  async function rpc(fn, args) {
    let res;
    try {
      res = await fetch(`${cfg.supabaseUrl}/rest/v1/rpc/${fn}`, {
        method: "POST",
        headers: { apikey: cfg.supabaseKey, "content-type": "application/json" },
        body: JSON.stringify(args || {}),
        referrerPolicy: "no-referrer",
        credentials: "omit",
      });
    } catch (_) {
      throw new ApiError("offline", "Can't reach the server. Check your internet connection and try again.");
    }
    const text = await res.text();
    const data = text ? JSON.parse(text) : null;
    if (!res.ok) throw new ApiError((data && data.code) || String(res.status), (data && data.message) || res.statusText);
    return data;
  }

  // The owner's public key: the pinned one if set, else the database's. If
  // both exist they must match.
  async function ownerPublicKey() {
    const inbox = await rpc("get_inbox");
    const live = inbox && inbox.public_key;
    if (cfg.pinnedPublicKey) {
      if (live && live !== cfg.pinnedPublicKey) throw new ApiError("key-mismatch", "The inbox key doesn't match this site's pinned key.");
      return { publicKey: cfg.pinnedPublicKey, salt: inbox && inbox.salt };
    }
    return { publicKey: live || null, salt: inbox && inbox.salt };
  }

  window.SM = {
    ApiError, rpc, ownerPublicKey, fingerprint,
    newInbox, newCredentials, fromPassphrase, unwrapPrivateKey,
    sealMessage, openMessage,
    supported: !!(window.crypto && crypto.subtle && window.fetch),
  };
})();
