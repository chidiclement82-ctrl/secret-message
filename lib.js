/* Shared code for all pages: encoding, encryption and the database calls.
 * Everything is done with the browser's Web Crypto API.
 *
 * How conversations are protected
 * -------------------------------
 * Each conversation starts with a random 32-byte secret made on the
 * visitor's device. Their private conversation link carries it after the
 * "#", which browsers never send to any server. From the secret, HKDF gives:
 *   - the conversation key: AES-256-GCM, encrypts every message both ways
 *   - the conversation token: lets the visitor add to and read the thread;
 *     the database only stores its SHA-256 (the thread id)
 *
 * The owner gets the conversation key in an "envelope": the visitor's
 * browser makes a one-off ECDH P-256 key pair, combines it with the owner's
 * public key, and turns that into an AES key with HKDF. Only the owner's
 * private key can open it.
 *
 *   envelope = base64url( 0x01 | sender public key (65) | iv (12) | sealed key )
 *   message  = base64url( 0x02 | iv (12) | ciphertext )
 *
 * Messages are padded so their length doesn't give away what's in them, and
 * each one is bound to its direction, so the database can't make it look
 * like the owner said something the visitor wrote, or the other way round.
 *
 * The owner's private key is stored in the database encrypted ("wrapped")
 * with a key made from the owner's passphrase by PBKDF2. The same PBKDF2 run
 * gives an access token; the database stores just its SHA-256 and only opens
 * the inbox for someone who knows the token.
 */
(function () {
  "use strict";

  const cfg = window.SM_CONFIG;
  const enc = new TextEncoder();
  const dec = new TextDecoder();
  const subtle = crypto.subtle;

  const PBKDF2_ROUNDS = 600000;
  const WRAP_AAD = enc.encode("secret-message key v1");
  const PAD_TO = 256;
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
  const sha256 = async (bytes) => new Uint8Array(await subtle.digest("SHA-256", bytes));

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
    return { token: toHex(token), authHash: toHex(await sha256(token)), wrapKey };
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
    const h = toHex(await sha256(fromB64(publicKeyB64))).slice(0, 20).toUpperCase();
    return h.match(/.{4}/g).join(" ");
  }

  // ---- envelopes: the conversation key, sealed to the owner --------------
  async function envelopeKey(privateKey, publicKey, ephPubRaw, ownerPubRaw) {
    const shared = await subtle.deriveBits({ name: "ECDH", public: publicKey }, privateKey, 256);
    const hk = await subtle.importKey("raw", shared, "HKDF", false, ["deriveKey"]);
    return subtle.deriveKey(
      { name: "HKDF", hash: "SHA-256", salt: concat(ephPubRaw, ownerPubRaw), info: enc.encode("secret-message envelope v1") },
      hk, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
  }
  // The thread id is bound in, so an envelope can't be moved to another thread.
  const envelopeAad = (ownerPubRaw, threadId) => concat(ownerPubRaw, enc.encode(threadId));

  async function sealEnvelope(ownerPubB64, threadId, keyBytes) {
    const ownerPubRaw = fromB64(ownerPubB64);
    const eph = await subtle.generateKey(ECDH, true, ["deriveBits"]);
    const ephPubRaw = new Uint8Array(await subtle.exportKey("raw", eph.publicKey));
    const key = await envelopeKey(eph.privateKey, await importPublic(ownerPubB64), ephPubRaw, ownerPubRaw);
    const iv = random(12);
    const ct = await subtle.encrypt({ name: "AES-GCM", iv, additionalData: envelopeAad(ownerPubRaw, threadId) }, key, keyBytes);
    return toB64(concat(new Uint8Array([1]), ephPubRaw, iv, new Uint8Array(ct)));
  }

  async function openEnvelope(privateKey, ownerPubB64, threadId, envelope) {
    const all = fromB64(envelope);
    if (all[0] !== 1) throw new Error("unknown version");
    const ephPubRaw = all.slice(1, 66);
    const ownerPubRaw = fromB64(ownerPubB64);
    const ephPub = await subtle.importKey("raw", ephPubRaw, ECDH, false, []);
    const key = await envelopeKey(privateKey, ephPub, ephPubRaw, ownerPubRaw);
    const raw = await subtle.decrypt(
      { name: "AES-GCM", iv: all.slice(66, 78), additionalData: envelopeAad(ownerPubRaw, threadId) }, key, all.slice(78));
    return subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt", "decrypt"]);
  }

  // ---- conversations -----------------------------------------------------
  // Everything a visitor's device needs, from the secret in their link.
  async function threadFromSecret(secretB64) {
    const secret = fromB64(secretB64);
    if (secret.length !== 32) throw new Error("bad link");
    const hk = await subtle.importKey("raw", secret, "HKDF", false, ["deriveBits"]);
    const bits = async (info) => new Uint8Array(await subtle.deriveBits(
      { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info: enc.encode(info) }, hk, 256));
    const keyBytes = await bits("secret-message thread key v1");
    const tokenBytes = await bits("secret-message thread token v1");
    return {
      secret: secretB64,
      keyBytes,
      key: await subtle.importKey("raw", keyBytes, "AES-GCM", false, ["encrypt", "decrypt"]),
      token: toHex(tokenBytes),
      id: toHex(await sha256(tokenBytes)),
    };
  }
  const newThread = () => threadFromSecret(toB64(random(32)));

  const messageAad = (fromOwner) => enc.encode(fromOwner ? "secret-message owner v1" : "secret-message visitor v1");

  // Encrypt { text, from } for a conversation. Throws Error("too long").
  async function sealMessage(key, fromOwner, text, from) {
    const body = enc.encode(JSON.stringify(from ? { m: text, f: from } : { m: text }));
    // Pad with spaces (valid trailing JSON whitespace) to a multiple of PAD_TO.
    const padded = new Uint8Array(Math.ceil((body.length + 1) / PAD_TO) * PAD_TO).fill(0x20);
    padded.set(body);
    const iv = random(12);
    const ct = new Uint8Array(await subtle.encrypt({ name: "AES-GCM", iv, additionalData: messageAad(fromOwner) }, key, padded));
    const blob = toB64(concat(new Uint8Array([2]), iv, ct));
    if (blob.length > MAX_BLOB) throw new Error("too long");
    return blob;
  }

  async function openMessage(key, fromOwner, blob) {
    const all = fromB64(blob);
    if (all[0] !== 2) throw new Error("unknown version");
    const pt = await subtle.decrypt({ name: "AES-GCM", iv: all.slice(1, 13), additionalData: messageAad(fromOwner) }, key, all.slice(13));
    const data = JSON.parse(dec.decode(pt));
    return { text: String(data.m || ""), from: String(data.f || "") };
  }

  // Decrypt a list of { from_owner, blob, ... } rows; a row that fails is
  // marked broken rather than dropped.
  function openAll(key, rows) {
    return Promise.all((rows || []).map(async (r) => {
      try {
        return { ...r, ...(await openMessage(key, r.from_owner, r.blob)) };
      } catch (_) {
        return { ...r, broken: true };
      }
    }));
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
        cache: "no-store",
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

  // ---- conversations saved on this device (visitor side) -----------------
  // Only a convenience so visitors can find their chats again; the link is
  // what matters. Storage can be unavailable (private mode), so never rely on it.
  const SAVED = "sm-conversations";
  function savedConversations() {
    try { return JSON.parse(localStorage.getItem(SAVED)) || []; } catch (_) { return []; }
  }
  function saveConversation(secret, preview) {
    try {
      const list = savedConversations().filter((c) => c.secret !== secret);
      list.unshift({ secret, preview: preview.slice(0, 60), at: Date.now() });
      localStorage.setItem(SAVED, JSON.stringify(list.slice(0, 20)));
    } catch (_) { /* not saved; the link still works */ }
  }
  function forgetConversation(secret) {
    try { localStorage.setItem(SAVED, JSON.stringify(savedConversations().filter((c) => c.secret !== secret))); } catch (_) {}
  }
  const chatLink = (secret) => new URL("chat.html#" + secret, location.href).href;

  // ---- notifications -----------------------------------------------------
  // Push notifications only say "something arrived"; the text stays encrypted.
  const pushSupported = () => "serviceWorker" in navigator && "PushManager" in window && "Notification" in window;
  const isIos = () => /iP(hone|ad|od)/.test(navigator.userAgent) || (navigator.platform === "MacIntel" && navigator.maxTouchPoints > 1);
  const installed = () => window.matchMedia("(display-mode: standalone)").matches || navigator.standalone === true;

  // Why notifications can't be turned on here, or "" if they can.
  function pushBlocker() {
    if (pushSupported()) return Notification.permission === "denied" ? "denied" : "";
    return isIos() && !installed() ? "ios-install" : "unsupported";
  }

  // Ask permission, subscribe this browser, and return { endpoint, p256dh,
  // auth } for the database. Throws Error("denied") if the person says no.
  async function pushSubscribe() {
    const key = await rpc("get_push_key");
    if (!key) throw new ApiError("no-key", "Notifications aren't set up on the server yet.");
    if ((await Notification.requestPermission()) !== "granted") throw new Error("denied");
    const reg = await navigator.serviceWorker.register("sw.js");
    await navigator.serviceWorker.ready;
    let sub = await reg.pushManager.getSubscription();
    const want = toB64(fromB64(key));
    if (sub && sub.options.applicationServerKey && toB64(new Uint8Array(sub.options.applicationServerKey)) !== want) {
      await sub.unsubscribe();
      sub = null;
    }
    sub = sub || await reg.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: fromB64(key) });
    const json = sub.toJSON();
    return { endpoint: json.endpoint, p256dh: json.keys.p256dh, auth: json.keys.auth };
  }

  // Wire up a "turn on notifications" button. `register(sub)` saves the
  // subscription in the database; `doneKey` remembers success on this device.
  function setupNotifyButton(btn, note, doneKey, register) {
    const blocker = pushBlocker();
    const setNote = (msg) => { note.textContent = msg; note.hidden = !msg; };
    let done = false;
    try { done = localStorage.getItem(doneKey) === "1" && Notification.permission === "granted"; } catch (_) {}
    if (blocker === "ios-install") {
      btn.hidden = true;
      setNote("To get notifications on iPhone, tap Share, then Add to Home Screen, and open this page from there.");
      return;
    }
    if (blocker === "unsupported") { btn.hidden = true; return; }
    if (blocker === "denied") {
      btn.hidden = true;
      setNote("Notifications are blocked for this site. You can allow them in your browser's settings.");
      return;
    }
    const markDone = () => { btn.textContent = "🔔 Notifications on"; btn.disabled = true; };
    if (done) markDone();
    btn.hidden = false;
    btn.addEventListener("click", async () => {
      btn.disabled = true;
      setNote("");
      try {
        await register(await pushSubscribe());
        try { localStorage.setItem(doneKey, "1"); } catch (_) {}
        markDone();
      } catch (e) {
        btn.disabled = false;
        setNote(e.message === "denied" ? "Notifications weren't allowed."
          : e.code === "offline" ? e.message
          : "Couldn't turn on notifications on this device. Please try again.");
      }
    });
  }

  // ---- small page helpers ------------------------------------------------
  const timeFmt = new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" });
  const formatTime = (iso) => timeFmt.format(new Date(iso));

  window.SM = {
    ApiError, rpc, ownerPublicKey, fingerprint,
    newInbox, newCredentials, fromPassphrase, unwrapPrivateKey,
    sealEnvelope, openEnvelope, newThread, threadFromSecret,
    sealMessage, openMessage, openAll,
    savedConversations, saveConversation, forgetConversation, chatLink, formatTime,
    setupNotifyButton,
    supported: !!(window.crypto && crypto.subtle && window.fetch),
  };
})();
