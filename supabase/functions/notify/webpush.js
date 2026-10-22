// Web Push sending with nothing but WebCrypto, so it runs the same in the
// Supabase Edge Runtime (Deno) and in Node for tests.
//   - Payload encryption: RFC 8291 (aes128gcm content coding, RFC 8188)
//   - Sender identification: VAPID, RFC 8292 (ES256 JWT)

const enc = new TextEncoder();
const subtle = crypto.subtle;

export function toB64(bytes) {
  let s = "";
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
export function fromB64(str) {
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
async function hkdf(salt, ikm, info, length) {
  const key = await subtle.importKey("raw", ikm, "HKDF", false, ["deriveBits"]);
  return new Uint8Array(await subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt, info }, key, length * 8));
}

// A new VAPID key pair: the public key as raw base64url (what browsers
// want) and the private key as a JWK (what we keep).
export async function newVapidKeys() {
  const pair = await subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  return {
    publicKey: toB64(new Uint8Array(await subtle.exportKey("raw", pair.publicKey))),
    privateJwk: await subtle.exportKey("jwk", pair.privateKey),
  };
}

// Encrypt `payload` (bytes) for one subscription. Returns the request body.
export async function encryptPayload(payload, p256dhB64, authB64, { salt, asKeys } = {}) {
  const uaPublic = fromB64(p256dhB64);
  const authSecret = fromB64(authB64);
  salt = salt || crypto.getRandomValues(new Uint8Array(16));
  asKeys = asKeys || await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
  const asPublic = new Uint8Array(await subtle.exportKey("raw", asKeys.publicKey));
  const uaKey = await subtle.importKey("raw", uaPublic, { name: "ECDH", namedCurve: "P-256" }, false, []);
  const ecdhSecret = new Uint8Array(await subtle.deriveBits({ name: "ECDH", public: uaKey }, asKeys.privateKey, 256));

  const ikm = await hkdf(authSecret, ecdhSecret, concat(enc.encode("WebPush: info\0"), uaPublic, asPublic), 32);
  const cek = await hkdf(salt, ikm, enc.encode("Content-Encoding: aes128gcm\0"), 16);
  const nonce = await hkdf(salt, ikm, enc.encode("Content-Encoding: nonce\0"), 12);

  // One record: the payload, then the 0x02 "last record" delimiter.
  const plaintext = concat(payload, new Uint8Array([2]));
  const key = await subtle.importKey("raw", cek, "AES-GCM", false, ["encrypt"]);
  const ciphertext = new Uint8Array(await subtle.encrypt({ name: "AES-GCM", iv: nonce }, key, plaintext));

  const rs = new Uint8Array(4);
  new DataView(rs.buffer).setUint32(0, 4096);
  return concat(salt, rs, new Uint8Array([asPublic.length]), asPublic, ciphertext);
}

// The VAPID Authorization header value for one push service.
export async function vapidAuth(endpoint, vapid, subject) {
  const header = toB64(enc.encode(JSON.stringify({ typ: "JWT", alg: "ES256" })));
  const claims = toB64(enc.encode(JSON.stringify({
    aud: new URL(endpoint).origin,
    exp: Math.floor(Date.now() / 1000) + 12 * 3600,
    sub: subject,
  })));
  const key = await subtle.importKey("jwk", vapid.privateJwk, { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
  // WebCrypto gives the raw r||s signature that ES256 JWTs use.
  const sig = new Uint8Array(await subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, enc.encode(`${header}.${claims}`)));
  return `vapid t=${header}.${claims}.${toB64(sig)}, k=${vapid.publicKey}`;
}

// Send one notification. Resolves to the push service's HTTP status.
export async function sendPush(sub, message, vapid, subject) {
  const body = await encryptPayload(enc.encode(JSON.stringify(message)), sub.p256dh, sub.auth);
  const res = await fetch(sub.endpoint, {
    method: "POST",
    headers: {
      Authorization: await vapidAuth(sub.endpoint, vapid, subject),
      "Content-Encoding": "aes128gcm",
      "Content-Type": "application/octet-stream",
      TTL: "86400",
      Urgency: "high",
    },
    body,
  });
  await res.body?.cancel();
  return res.status;
}
