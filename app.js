/* Secret message: end-to-end encrypted notes shared by link.
 *
 * Everything happens in the browser with the Web Crypto API. The encrypted
 * message (and, without a password, its key) travels in the link's #fragment,
 * which browsers never send to the server.
 *
 * Link formats (all parts base64url):
 *   #k1.<iv+ciphertext>.<key>          key in the link
 *   #p1.<salt+iv+ciphertext>           key derived from a password
 */
(function () {
  "use strict";

  const PBKDF2_ROUNDS = 600000;
  const enc = new TextEncoder();
  const dec = new TextDecoder();
  const $ = (id) => document.getElementById(id);

  // ---- base64url ---------------------------------------------------------
  function toB64(bytes) {
    let s = "";
    for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }
  function fromB64(str) {
    if (!/^[A-Za-z0-9_-]*$/.test(str)) throw new Error("bad link");
    const s = atob(str.replace(/-/g, "+").replace(/_/g, "/"));
    const out = new Uint8Array(s.length);
    for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
    return out;
  }
  function concat(...parts) {
    const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
    let o = 0;
    for (const p of parts) { out.set(p, o); o += p.length; }
    return out;
  }
  const random = (n) => crypto.getRandomValues(new Uint8Array(n));

  // ---- crypto ------------------------------------------------------------
  async function keyFromPassword(password, salt) {
    const base = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveKey"]);
    return crypto.subtle.deriveKey(
      { name: "PBKDF2", hash: "SHA-256", salt, iterations: PBKDF2_ROUNDS },
      base, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
  }
  const importRaw = (raw) => crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt", "decrypt"]);

  // The format tag is bound to the ciphertext, so a link can't be switched
  // from one format to the other without failing to decrypt.
  async function seal(key, tag, text) {
    const iv = random(12);
    const ct = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv, additionalData: enc.encode(tag) }, key, enc.encode(text));
    return concat(iv, new Uint8Array(ct));
  }
  async function open(key, tag, blob) {
    const pt = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: blob.slice(0, 12), additionalData: enc.encode(tag) }, key, blob.slice(12));
    return dec.decode(pt);
  }

  async function encryptToFragment(text, password) {
    if (password) {
      const salt = random(16);
      const sealed = await seal(await keyFromPassword(password, salt), "p1", text);
      return "p1." + toB64(concat(salt, sealed));
    }
    const raw = random(32);
    const sealed = await seal(await importRaw(raw), "k1", text);
    return "k1." + toB64(sealed) + "." + toB64(raw);
  }

  function parseFragment(frag) {
    const parts = frag.split(".");
    if (parts[0] === "k1" && parts.length === 3) {
      const raw = fromB64(parts[2]);
      if (raw.length !== 32) throw new Error("bad link");
      return { kind: "k1", blob: fromB64(parts[1]), raw };
    }
    if (parts[0] === "p1" && parts.length === 2) {
      const all = fromB64(parts[1]);
      return { kind: "p1", salt: all.slice(0, 16), blob: all.slice(16) };
    }
    throw new Error("bad link");
  }

  async function decryptParsed(p, password) {
    if (p.kind === "k1") return open(await importRaw(p.raw), "k1", p.blob);
    return open(await keyFromPassword(password, p.salt), "p1", p.blob);
  }

  // ---- UI helpers --------------------------------------------------------
  function show(el, on) { el.hidden = !on; }
  function say(el, msg) { el.textContent = msg || ""; show(el, !!msg); }
  async function copy(text, btn) {
    try {
      await navigator.clipboard.writeText(text);
    } catch (_) {
      return; // Clipboard blocked: the text is still selectable on the page.
    }
    const old = btn.textContent;
    btn.textContent = "Copied ✓";
    setTimeout(() => { btn.textContent = old; }, 1500);
  }

  if (!window.crypto || !crypto.subtle) {
    say($("compose-error"), "This browser can't encrypt. Open the page over https in an up-to-date browser.");
    $("encrypt").disabled = true;
    return;
  }

  // ---- compose -----------------------------------------------------------
  const message = $("message");
  message.addEventListener("input", () => { $("count").textContent = message.value.length; });

  $("encrypt").addEventListener("click", async () => {
    const text = message.value;
    const password = $("password").value;
    if (!text.trim()) { say($("compose-error"), "Write a message first."); return; }
    say($("compose-error"), "");
    const btn = $("encrypt");
    btn.disabled = true;
    btn.textContent = "Encrypting…";
    try {
      const frag = await encryptToFragment(text, password);
      const link = location.origin + location.pathname + "#" + frag;
      $("link").value = link;
      $("share-wa").href = "https://wa.me/?text=" + encodeURIComponent(link);
      show($("pw-note"), !!password);
      show($("result"), true);
      // Don't leave the plaintext or password sitting on the page.
      message.value = "";
      $("password").value = "";
      $("count").textContent = "0";
      $("link").select();
    } catch (_) {
      say($("compose-error"), "Couldn't encrypt that message. Please try again.");
    } finally {
      btn.disabled = false;
      btn.textContent = "Encrypt & make link";
    }
  });

  $("copy").addEventListener("click", () => copy($("link").value, $("copy")));

  // Phones offer their own share sheet (WhatsApp, Telegram, Signal, SMS…).
  if (navigator.share) {
    show($("share"), true);
    $("share").addEventListener("click", () => {
      navigator.share({ title: "Secret message", url: $("link").value }).catch(() => {});
    });
  }
  $("again").addEventListener("click", () => {
    show($("result"), false);
    $("link").value = "";
    message.focus();
  });

  // ---- reveal ------------------------------------------------------------
  const frag = location.hash.slice(1);
  if (!frag) return;

  // Take the secret out of the address bar right away, so it isn't left in
  // this tab's history or shown over someone's shoulder.
  history.replaceState(null, "", location.pathname + location.search);
  show($("compose"), false);
  show($("reveal"), true);

  let parsed;
  try {
    parsed = parseFragment(frag);
  } catch (_) {
    say($("reveal-error"), "This link is broken or incomplete. Ask the sender to copy it again.");
    show($("decrypt"), false);
    return;
  }
  const needsPassword = parsed.kind === "p1";
  show($("pw-wrap"), needsPassword);
  if (needsPassword) $("unlock-password").focus();

  async function reveal() {
    const btn = $("decrypt");
    const password = $("unlock-password").value;
    if (needsPassword && !password) { say($("reveal-error"), "Enter the password."); return; }
    btn.disabled = true;
    btn.textContent = "Unlocking…";
    try {
      $("plain").textContent = await decryptParsed(parsed, password);
      say($("reveal-error"), "");
      show($("plain-wrap"), true);
      show($("pw-wrap"), false);
      show(btn, false);
    } catch (_) {
      say($("reveal-error"), needsPassword
        ? "Wrong password, or the link was changed."
        : "This link was changed or is incomplete, so it can't be opened.");
    } finally {
      btn.disabled = false;
      btn.textContent = "Show message";
    }
  }
  $("decrypt").addEventListener("click", reveal);
  $("unlock-password").addEventListener("keydown", (e) => { if (e.key === "Enter") reveal(); });
  $("copy-plain").addEventListener("click", () => copy($("plain").textContent, $("copy-plain")));
})();
